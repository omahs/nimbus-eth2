# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import
  std/[deques, options, strformat, strutils, sequtils, tables,
       typetraits, uri, json],
  # Nimble packages:
  chronos, metrics, chronicles/timings, stint/endians2,
  json_rpc/client,
  web3, web3/ethtypes as web3Types, web3/ethhexstrings, web3/engine_api,
  eth/common/eth_types,
  eth/async_utils, stew/[byteutils, objects, results, shims/hashes],
  # Local modules:
  ../spec/[deposit_snapshots, eth2_merkleization, forks, helpers],
  ../spec/datatypes/[base, phase0, bellatrix],
  ../networking/network_metadata,
  ../consensus_object_pools/block_pools_types,
  ".."/[beacon_chain_db, beacon_node_status, beacon_clock],
  "."/[merkle_minimal, el_conf]

from std/times import getTime, inSeconds, initTime, `-`
from ../spec/engine_authentication import getSignedIatToken

export
  web3Types, deques, base, DepositTreeSnapshot

logScope:
  topics = "eth1"

type
  PubKeyBytes = DynamicBytes[48, 48]
  WithdrawalCredentialsBytes = DynamicBytes[32, 32]
  SignatureBytes = DynamicBytes[96, 96]
  Int64LeBytes = DynamicBytes[8, 8]

contract(DepositContract):
  proc deposit(pubkey: PubKeyBytes,
               withdrawalCredentials: WithdrawalCredentialsBytes,
               signature: SignatureBytes,
               deposit_data_root: FixedBytes[32])

  proc get_deposit_root(): FixedBytes[32]
  proc get_deposit_count(): Int64LeBytes

  proc DepositEvent(pubkey: PubKeyBytes,
                    withdrawalCredentials: WithdrawalCredentialsBytes,
                    amount: Int64LeBytes,
                    signature: SignatureBytes,
                    index: Int64LeBytes) {.event.}

const
  hasDepositRootChecks = defined(has_deposit_root_checks)
  hasGenesisDetection* = defined(has_genesis_detection)

  targetBlocksPerLogsRequest = 5000'u64  # This is roughly a day of Eth1 blocks

  # Engine API timeouts
  engineApiConnectionTimeout = 5.seconds  # How much we wait before giving up connecting to the Engine API
  web3RequestsTimeout* = 8.seconds # How much we wait for eth_* requests (e.g. eth_getBlockByHash)

  # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.1/src/engine/specification.md#request-2
  GETPAYLOAD_TIMEOUT = 1.seconds

type
  Eth1BlockNumber* = uint64
  Eth1BlockTimestamp* = uint64
  Eth1BlockHeader = web3Types.BlockHeader

  GenesisStateRef = ref phase0.BeaconState

  Eth1Block* = ref object
    hash*: Eth2Digest
    number*: Eth1BlockNumber
    timestamp*: Eth1BlockTimestamp
      ## Basic properties of the block
      ## These must be initialized in the constructor

    deposits*: seq[DepositData]
      ## Deposits inside this particular block

    depositRoot*: Eth2Digest
    depositCount*: uint64
      ## Global deposits count and hash tree root of the entire sequence
      ## These are computed when the block is added to the chain (see `addBlock`)

    when hasGenesisDetection:
      activeValidatorsCount*: uint64

  Eth1Chain* = object
    db: BeaconChainDB
    cfg: RuntimeConfig
    finalizedBlockHash: Eth2Digest
    finalizedDepositsMerkleizer: DepositsMerkleizer
      ## The latest block that reached a 50% majority vote from
      ## the Eth2 validators according to the follow distance and
      ## the ETH1_VOTING_PERIOD

    blocks*: Deque[Eth1Block]
      ## A non-forkable chain of blocks ending at the block with
      ## ETH1_FOLLOW_DISTANCE offset from the head.

    blocksByHash: Table[BlockHash, Eth1Block]

    headMerkleizer: DepositsMerkleizer
      ## Merkleizer state after applying all `blocks`

    hasConsensusViolation: bool
      ## The local chain contradicts the observed consensus on the network

  NextExpectedPayloadParams* = object
    headBlockRoot*: Eth2Digest
    safeBlockRoot*: Eth2Digest
    finalizedBlockRoot*: Eth2Digest
    payloadAttributes: PayloadAttributesV1

  ELManager* = ref object
    eth1Network: Option[Eth1Network]

    depositContractAddress*: Eth1Address
    blocksPerLogsRequest: uint64

    elConnections: seq[ELConnection]

    depositsChain: Eth1Chain

    exchangedConfiguration*: bool
    terminalBlockHash*: Option[BlockHash]

    depositSyncConnectionIdx: int
    depositSyncLoopFut: Future[void]

    exchangeTransitionConfigurationLoopFut: Future[void]

    stopFut: Future[void]
    getBeaconTime: GetBeaconTimeFn

    ttdReachedField: bool

    nextExpectedPayloadParams*: Option[NextExpectedPayloadParams]

    when hasGenesisDetection:
      genesisValidators: seq[ImmutableValidatorData]
      genesisValidatorKeyToIndex: Table[ValidatorPubKey, ValidatorIndex]
      genesisState: GenesisStateRef
      genesisStateFut: Future[void]

  EtcStatus {.pure.} = enum
    notExchangedYet
    exchangeError
    mismatch
    # TODO This should go away
    localConfigurationUpdated
    match

  ELConnection* = ref object
    engineUrl: EngineApiUrl

    web3: Option[Web3]
      ## This will be `none` before connecting and while we are
      ## reconnecting after a lost connetion. You can wait on
      ## the future below for the moment the connection is active.

    connectingFut: Future[Web3]
      ## This future will be replaced when the connection is lost.

    depositContract: Option[Sender[DepositContract]]
      ## This will be `none` in networks lacking a deposit contract

    delaySyncRestart: Duration
      ## Back-off time before we restart syncing through this connection.
      ## Useful while we wait the EL client to sync.

    etcStatus: EtcStatus
    lastPayloadId: Option[engine_api.PayloadID]

  FullBlockId* = object
    number: Eth1BlockNumber
    hash: BlockHash

  DataProviderFailure* = object of CatchableError
  CorruptDataProvider* = object of DataProviderFailure
  DataProviderTimeout* = object of DataProviderFailure

  DisconnectHandler* = proc () {.gcsafe, raises: [Defect].}

  DepositEventHandler* = proc (
    pubkey: PubKeyBytes,
    withdrawalCredentials: WithdrawalCredentialsBytes,
    amount: Int64LeBytes,
    signature: SignatureBytes,
    merkleTreeIndex: Int64LeBytes,
    j: JsonNode) {.gcsafe, raises: [Defect].}

  BlockProposalEth1Data* = object
    vote*: Eth1Data
    deposits*: seq[Deposit]
    hasMissingDeposits*: bool

declareCounter failed_web3_requests,
  "Failed web3 requests"

declareGauge eth1_latest_head,
  "The highest Eth1 block number observed on the network"

declareGauge eth1_synced_head,
  "Block number of the highest synchronized block according to follow distance"

declareGauge eth1_finalized_head,
  "Block number of the highest Eth1 block finalized by Eth2 consensus"

declareGauge eth1_finalized_deposits,
  "Number of deposits that were finalized by the Eth2 consensus"

declareGauge eth1_chain_len,
  "The length of the in-memory chain of Eth1 blocks"

declareCounter engine_newPayload_failures,
  "Number of failed requests to the newPayload Engine API end-point", labels = ["url"]

declareCounter engine_newPayload_sent,
  "Number of successful requests to the newPayload Engine API end-point",
  labels = ["url", "status"]

declareCounter engine_forkchoiceUpdated_failures,
  "Number of failed requests to the forkchoiceUpdated Engine API end-point", labels = ["url"]

declareCounter engine_forkchoiceUpdated_sent,
  "Number of successful requests to the forkchoiceUpdated Engine API end-point",
  labels = ["url", "status"]

func ttdReached*(m: ELManager): bool =
  m.ttdReachedField

template cfg(m: ELManager): auto =
  m.depositsChain.cfg

when hasGenesisDetection:
  import ../spec/[beaconstate, signatures]

  template hasEnoughValidators(m: ELManager, blk: Eth1Block): bool =
    blk.activeValidatorsCount >= m.cfg.MIN_GENESIS_ACTIVE_VALIDATOR_COUNT

  func chainHasEnoughValidators(m: ELManager): bool =
    m.depositsChain.blocks.len > 0 and m.hasEnoughValidators(m.depositsChain.blocks[^1])

  func isAfterMinGenesisTime(m: ELManager, blk: Eth1Block): bool =
    doAssert blk.timestamp != 0
    let t = genesis_time_from_eth1_timestamp(m.cfg, uint64 blk.timestamp)
    t >= m.cfg.MIN_GENESIS_TIME

  func isGenesisCandidate(m: ELManager, blk: Eth1Block): bool =
    m.hasEnoughValidators(blk) and m.isAfterMinGenesisTime(blk)

  proc findGenesisBlockInRange(m: ELManager, startBlock, endBlock: Eth1Block):
                               Future[Eth1Block] {.gcsafe.}

  proc signalGenesis(m: ELManager, genesisState: GenesisStateRef) =
    m.genesisState = genesisState

    if not m.genesisStateFut.isNil:
      m.genesisStateFut.complete()
      m.genesisStateFut = nil

  func allGenesisDepositsUpTo(m: ELManager, totalDeposits: uint64): seq[DepositData] =
    for i in 0 ..< int64(totalDeposits):
      result.add m.depositsChain.db.genesisDeposits.get(i)

  proc createGenesisState(m: ELManager, eth1Block: Eth1Block): GenesisStateRef =
    notice "Generating genesis state",
      blockNum = eth1Block.number,
      blockHash = eth1Block.hash,
      blockTimestamp = eth1Block.timestamp,
      totalDeposits = eth1Block.depositCount,
      activeValidators = eth1Block.activeValidatorsCount

    var deposits = m.allGenesisDepositsUpTo(eth1Block.depositCount)

    result = newClone(initialize_beacon_state_from_eth1(
      m.cfg,
      eth1Block.hash,
      eth1Block.timestamp.uint64,
      deposits, {}))

    if eth1Block.activeValidatorsCount != 0:
      doAssert result.validators.lenu64 == eth1Block.activeValidatorsCount

  proc produceDerivedData(m: ELManager, deposit: DepositData) =
    let htr = hash_tree_root(deposit)

    if verify_deposit_signature(m.cfg, deposit):
      let pubkey = deposit.pubkey
      if pubkey notin m.genesisValidatorKeyToIndex:
        let idx = ValidatorIndex m.genesisValidators.len
        m.genesisValidators.add ImmutableValidatorData(
          pubkey: pubkey,
          withdrawal_credentials: deposit.withdrawal_credentials)
        m.genesisValidatorKeyToIndex[pubkey] = idx

  proc processGenesisDeposit*(m: ELManager, newDeposit: DepositData) =
    m.depositsChain.db.genesisDeposits.add newDeposit
    m.produceDerivedData(newDeposit)

template depositChainBlocks*(m: ELManager): Deque[Eth1Block] =
  m.depositsChain.blocks

template finalizedDepositsMerkleizer(m: ELManager): auto =
  m.depositsChain.finalizedDepositsMerkleizer

template headMerkleizer(m: ELManager): auto =
  m.depositsChain.headMerkleizer

template toGaugeValue(x: Quantity): int64 =
  toGaugeValue(distinctBase x)

# TODO: Add cfg validation
# MIN_GENESIS_ACTIVE_VALIDATOR_COUNT should be larger than SLOTS_PER_EPOCH
#  doAssert SECONDS_PER_ETH1_BLOCK * cfg.ETH1_FOLLOW_DISTANCE < GENESIS_DELAY,
#             "Invalid configuration: GENESIS_DELAY is set too low"

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-alpha.0/specs/phase0/validator.md#get_eth1_data
func compute_time_at_slot(genesis_time: uint64, slot: Slot): uint64 =
  genesis_time + slot * SECONDS_PER_SLOT

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-alpha.0/specs/phase0/validator.md#get_eth1_data
func voting_period_start_time(state: ForkedHashedBeaconState): uint64 =
  let eth1_voting_period_start_slot =
    getStateField(state, slot) - getStateField(state, slot) mod
      SLOTS_PER_ETH1_VOTING_PERIOD.uint64
  compute_time_at_slot(
    getStateField(state, genesis_time), eth1_voting_period_start_slot)

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-alpha.0/specs/phase0/validator.md#get_eth1_data
func is_candidate_block(cfg: RuntimeConfig,
                        blk: Eth1Block,
                        period_start: uint64): bool =
  (blk.timestamp + cfg.SECONDS_PER_ETH1_BLOCK * cfg.ETH1_FOLLOW_DISTANCE <= period_start) and
  (blk.timestamp + cfg.SECONDS_PER_ETH1_BLOCK * cfg.ETH1_FOLLOW_DISTANCE * 2 >= period_start)

func asEth2Digest*(x: BlockHash): Eth2Digest =
  Eth2Digest(data: array[32, byte](x))

template asBlockHash*(x: Eth2Digest): BlockHash =
  BlockHash(x.data)

func asConsensusExecutionPayload*(rpcExecutionPayload: ExecutionPayloadV1):
    bellatrix.ExecutionPayload =
  template getTransaction(tt: TypedTransaction): bellatrix.Transaction =
    bellatrix.Transaction.init(tt.distinctBase)

  bellatrix.ExecutionPayload(
    parent_hash: rpcExecutionPayload.parentHash.asEth2Digest,
    feeRecipient:
      ExecutionAddress(data: rpcExecutionPayload.feeRecipient.distinctBase),
    state_root: rpcExecutionPayload.stateRoot.asEth2Digest,
    receipts_root: rpcExecutionPayload.receiptsRoot.asEth2Digest,
    logs_bloom: BloomLogs(data: rpcExecutionPayload.logsBloom.distinctBase),
    prev_randao: rpcExecutionPayload.prevRandao.asEth2Digest,
    block_number: rpcExecutionPayload.blockNumber.uint64,
    gas_limit: rpcExecutionPayload.gasLimit.uint64,
    gas_used: rpcExecutionPayload.gasUsed.uint64,
    timestamp: rpcExecutionPayload.timestamp.uint64,
    extra_data:
      List[byte, MAX_EXTRA_DATA_BYTES].init(
        rpcExecutionPayload.extraData.distinctBase),
    base_fee_per_gas: rpcExecutionPayload.baseFeePerGas,
    block_hash: rpcExecutionPayload.blockHash.asEth2Digest,
    transactions: List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(
      mapIt(rpcExecutionPayload.transactions, it.getTransaction)))

func asEngineExecutionPayload*(executionPayload: bellatrix.ExecutionPayload):
    ExecutionPayloadV1 =
  template getTypedTransaction(tt: bellatrix.Transaction): TypedTransaction =
    TypedTransaction(tt.distinctBase)

  engine_api.ExecutionPayloadV1(
    parentHash: executionPayload.parent_hash.asBlockHash,
    feeRecipient: Address(executionPayload.fee_recipient.data),
    stateRoot: executionPayload.state_root.asBlockHash,
    receiptsRoot: executionPayload.receipts_root.asBlockHash,
    logsBloom:
      FixedBytes[BYTES_PER_LOGS_BLOOM](executionPayload.logs_bloom.data),
    prevRandao: executionPayload.prev_randao.asBlockHash,
    blockNumber: Quantity(executionPayload.block_number),
    gasLimit: Quantity(executionPayload.gas_limit),
    gasUsed: Quantity(executionPayload.gas_used),
    timestamp: Quantity(executionPayload.timestamp),
    extraData:
      DynamicBytes[0, MAX_EXTRA_DATA_BYTES](executionPayload.extra_data),
    baseFeePerGas: executionPayload.base_fee_per_gas,
    blockHash: executionPayload.block_hash.asBlockHash,
    transactions: mapIt(executionPayload.transactions, it.getTypedTransaction))

func shortLog*(b: Eth1Block): string =
  try:
    &"{b.number}:{shortLog b.hash}(deposits = {b.depositCount})"
  except ValueError as exc: raiseAssert exc.msg

template findBlock(chain: Eth1Chain, eth1Data: Eth1Data): Eth1Block =
  getOrDefault(chain.blocksByHash, asBlockHash(eth1Data.block_hash), nil)

func makeSuccessorWithoutDeposits(existingBlock: Eth1Block,
                                  successor: BlockObject): Eth1Block =
  result = Eth1Block(
    hash: successor.hash.asEth2Digest,
    number: Eth1BlockNumber successor.number,
    timestamp: Eth1BlockTimestamp successor.timestamp)

  when hasGenesisDetection:
    result.activeValidatorsCount = existingBlock.activeValidatorsCount

func latestCandidateBlock(chain: Eth1Chain, periodStart: uint64): Eth1Block =
  for i in countdown(chain.blocks.len - 1, 0):
    let blk = chain.blocks[i]
    if is_candidate_block(chain.cfg, blk, periodStart):
      return blk

proc popFirst(chain: var Eth1Chain) =
  let removed = chain.blocks.popFirst
  chain.blocksByHash.del removed.hash.asBlockHash
  eth1_chain_len.set chain.blocks.len.int64

func getDepositsRoot*(m: DepositsMerkleizer): Eth2Digest =
  mixInLength(m.getFinalHash, int m.totalChunks)

proc addBlock*(chain: var Eth1Chain, newBlock: Eth1Block) =
  for deposit in newBlock.deposits:
    chain.headMerkleizer.addChunk hash_tree_root(deposit).data

  newBlock.depositCount = chain.headMerkleizer.getChunkCount
  newBlock.depositRoot = chain.headMerkleizer.getDepositsRoot

  chain.blocks.addLast newBlock
  chain.blocksByHash[newBlock.hash.asBlockHash] = newBlock

  eth1_chain_len.set chain.blocks.len.int64

func toVoteData(blk: Eth1Block): Eth1Data =
  Eth1Data(
    deposit_root: blk.depositRoot,
    deposit_count: blk.depositCount,
    block_hash: blk.hash)

func hash*(x: Eth1Data): Hash =
  hash(x.block_hash)

template awaitWithRetries*[T](lazyFutExpr: Future[T],
                              timeout: Duration,
                              retries = 3,
                              onFailure: untyped): untyped =
  block:
    const
      reqType = astToStr(lazyFutExpr)

    var
      retryDelay = 16000
      retryDelayValue = retryDelay
      f: Future[T]
      attempts = 0
      errors {.inject.}: array[retries, ref CatchableError]

    while true:
      f = lazyFutExpr
      yield f or sleepAsync(timeout)
      if not f.finished:
        await cancelAndWait(f)
      elif f.failed:
        if f.error[] of CancelledError:
          raise f.error
        errors[attempts] = f.error
        debug "Web3 request failed", req = reqType, err = f.error.msg
        inc failed_web3_requests
      else:
        break

      inc attempts
      if attempts >= retries:
        template lastError(): ref CatchableError =
          errors[retries - 1]

        onFailure
      else:
        await sleepAsync(milliseconds(retryDelayValue))
        retryDelayValue *= 2

    read(f)

template awaitWithRetries*[T](lazyFutExpr: Future[T],
                              timeout: Duration,
                              retries = 3): untyped =
  awaitWithRetries(lazyFutExpr, timeout, retries,
                   onFailure = block: raise lastError())

proc close(connection: ELConnection): Future[void] {.async.} =
  if connection.web3.isSome:
    awaitWithTimeout(connection.web3.get.close(), 30.seconds):
      debug "Failed to close data provider in time"

proc isConnected(connection: ELConnection): bool =
  connection.web3.isNone

proc getJsonRpcRequestHeaders(jwtSecret: Option[seq[byte]]):
    auto =
  if jwtSecret.isSome:
    let secret = jwtSecret.get
    (proc(): seq[(string, string)] =
      # https://www.rfc-editor.org/rfc/rfc6750#section-6.1.1
      @[("Authorization", "Bearer " & getSignedIatToken(
        secret, (getTime() - initTime(0, 0)).inSeconds))])
  else:
    (proc(): seq[(string, string)] = @[])

proc newWeb3*(engineUrl: EngineApiUrl): Future[Web3] =
  newWeb3(engineUrl.url, getJsonRpcRequestHeaders(engineUrl.jwtSecret))

proc reconnect(connection: ELConnection) {.async.} =
  if connection.isConnected:
    return

  if connection.connectingFut == nil:
    connection.connectingFut = connection.engineUrl.newWeb3()

  connection.web3 = some(await connection.connectingFut)

proc connectedRpcClient(connection: ELConnection): Future[RpcClient] {.async.} =
  if not connection.isConnected:
    await connection.reconnect()

  return connection.web3.get.provider

proc getBlockByHash(rpcClient: RpcClient, hash: BlockHash): Future[BlockObject] =
  rpcClient.eth_getBlockByHash(hash, false)

proc getBlockByNumber*(rpcClient: RpcClient,
                       number: Eth1BlockNumber): Future[BlockObject] =
  let hexNumber = try:
    &"0x{number:X}" # No leading 0's!
  except ValueError as exc:
    # Since the format above is valid, failing here should not be possible
    raiseAssert exc.msg

  rpcClient.eth_getBlockByNumber(hexNumber, false)

func areSameAs(expectedParams: Option[NextExpectedPayloadParams],
               latestHead, latestSafe, latestFinalized: Eth2Digest,
               timestamp: uint64, feeRecipient: Eth1Address): bool =
  expectedParams.isSome and
  expectedParams.get.headBlockRoot == latestHead and
  expectedParams.get.safeBlockRoot == latestSafe and
  expectedParams.get.finalizedBlockRoot == latestFinalized and
  expectedParams.get.payloadAttributes.timestamp.uint64 == timestamp and
  expectedParams.get.payloadAttributes.suggestedFeeRecipient == feeRecipient

proc getPayloadFromSingleEL(
    connection: ELConnection,
    isForkChoiceUpToDate: bool,
    headBlock, safeBlock, finalizedBlock: Eth2Digest,
    timestamp: uint64,
    randomData: Eth2Digest,
    suggestedFeeRecipient: Eth1Address): Future[engine_api.ExecutionPayloadV1] {.async.} =

  let
    rpcClient = await connection.connectedRpcClient()
    payloadId = if isForkChoiceUpToDate and connection.lastPayloadId.isSome:
      connection.lastPayloadid.get
    else:
      # TODO Add metric
      let response = await rpcClient.engine_forkchoiceUpdatedV1(
        ForkchoiceStateV1(
          headBlockHash: headBlock.asBlockHash,
          safeBlockHash: safeBlock.asBlockHash,
          finalizedBlockHash: finalizedBlock.asBlockHash),
        some engine_api.PayloadAttributesV1(
          timestamp: Quantity timestamp,
          prevRandao: FixedBytes[32] randomData.data,
          suggestedFeeRecipient: suggestedFeeRecipient))

      if response.payloadStatus.status != PayloadExecutionStatus.valid or
         response.payloadId.isNone:
        raise newException(CatchableError, "Head block is not a valid payload")

      response.payloadId.get

  return await rpcClient.engine_getPayloadV1(FixedBytes[8] payloadId)

proc cmpPayloads(lhs, rhs: engine_api.ExecutionPayloadV1): int =
  # TODO
  1

proc getPayload*(m: ELManager,
                 headBlock, safeBlock, finalizedBlock: Eth2Digest,
                 timestamp: uint64,
                 randomData: Eth2Digest,
                 suggestedFeeRecipient: Eth1Address):
                 Future[Opt[engine_api.ExecutionPayloadV1]] {.async.} =
  # TODO Pre-merge, deliver empty payload
  # default(bellatrix.ExecutionPayload)

  let isFcUpToDate = m.nextExpectedPayloadParams.areSameAs(
    headBlock, safeBlock, finalizedBlock,
    timestamp, suggestedFeeRecipient)

  let
    deadline = sleepAsync(GETPAYLOAD_TIMEOUT)
    requests = m.elConnections.mapIt(it.getPayloadFromSingleEL(
      isFcUpToDate, headBlock, safeBlock, finalizedBlock,
      timestamp, randomData, suggestedFeeRecipient
    ))
    requestsCompleted = allFutures(requests)

  await requestsCompleted or deadline

  var bestPayloadIdx = none int
  for idx, req in requests:
    if not req.finished:
      req.cancel()
    elif req.failed:
      # TODO log, fix connection, etc
      discard
    elif bestPayloadIdx.isNone:
      bestPayloadIdx = some idx
    else:
      if cmpPayloads(req.read, requests[bestPayloadIdx.get].read) > 0:
        bestPayloadIdx = some idx

  if bestPayloadIdx.isSome:
    return ok requests[bestPayloadIdx.get].read
  else:
    return err()

proc sendNewPayloadToSingleEL(connection: ELConnection,
                              payload: engine_api.ExecutionPayloadV1):
                              Future[PayloadStatusV1] {.async.} =
  let rpcClient = await connection.connectedRpcClient()
  return await rpcClient.engine_newPayloadV1(payload)

type
  StatusRelation = enum
    newStatusIsPreferable
    oldStatusIsOk
    disagreement

proc compareStatuses(prevStatus, newStatus: PayloadExecutionStatus): StatusRelation =
  case prevStatus
  of PayloadExecutionStatus.syncing:
    if newStatus == PayloadExecutionStatus.syncing:
      oldStatusIsOk
    else:
      newStatusIsPreferable

  of PayloadExecutionStatus.valid:
    case newStatus
    of PayloadExecutionStatus.syncing,
       PayloadExecutionStatus.accepted,
       PayloadExecutionStatus.valid:
      oldStatusIsOk
    of PayloadExecutionStatus.invalid_block_hash,
       PayloadExecutionStatus.invalid:
      disagreement

  of PayloadExecutionStatus.invalid:
    case newStatus
    of PayloadExecutionStatus.syncing,
       PayloadExecutionStatus.invalid:
      oldStatusIsOk
    of PayloadExecutionStatus.valid,
       PayloadExecutionStatus.accepted,
       PayloadExecutionStatus.invalid_block_hash:
      disagreement

  of PayloadExecutionStatus.accepted:
    case newStatus
    of PayloadExecutionStatus.accepted,
       PayloadExecutionStatus.syncing:
      oldStatusIsOk
    of PayloadExecutionStatus.valid:
      newStatusIsPreferable
    of PayloadExecutionStatus.invalid_block_hash,
       PayloadExecutionStatus.invalid:
      disagreement

  of PayloadExecutionStatus.invalid_block_hash:
    if newStatus == PayloadExecutionStatus.invalid_block_hash:
      oldStatusIsOk
    else:
      disagreement

proc sendNewPayload*(m: ELManager, payload: engine_api.ExecutionPayloadV1):
                     Future[PayloadExecutionStatus] {.async.} =
  let
    deadline = sleepAsync(NEWPAYLOAD_TIMEOUT)
    requests = m.elConnections.mapIt(sendNewPayloadToSingleEL(it, payload))
    requestsCompleted = allFutures(requests)

  await requestsCompleted or deadline

  var
    selectedResponse = none int
    disagreementAlreadyDetected = false

  for idx, req in requests:
    if not req.finished:
      req.cancel()
    else:
      let url = m.elConnections[idx].engineUrl.url
      if req.failed:
        engine_newPayload_failures.inc(1, [url])
        error "Sending payload to the EL failed",
               url, err = req.error.msg
      else:
        let status = req.read.status
        engine_newPayload_sent.inc(1, [url, $status])

        if selectedResponse.isNone:
          selectedResponse = some idx
        elif not disagreementAlreadyDetected:
          let prevStatus = requests[selectedResponse.get].read.status
          case compareStatuses(status, prevStatus)
          of newStatusIsPreferable:
            selectedResponse = some idx
          of oldStatusIsOk:
            discard
          of disagreement:
            disagreementAlreadyDetected = true
            error "ELs disagree regarding newPayload status",
                  url1 = m.elConnections[selectedResponse.get].engineUrl,
                  status1 = prevStatus,
                  url2 = url,
                  status2 = status

  return if disagreementAlreadyDetected:
    PayloadExecutionStatus.invalid
  elif selectedResponse.isSome:
    requests[selectedResponse.get].read.status
  else:
    PayloadExecutionStatus.syncing

proc forkchoiceUpdatedForSingleEL(
    connection: ELConnection,
    state: ref ForkchoiceStateV1,
    payloadAttrs: ref Option[engine_api.PayloadAttributesV1]):
    Future[PayloadStatusV1] {.async.} =
  let rpcClient = await connection.connectedRpcClient()
  let response = await rpcClient.engine_forkchoiceUpdatedV1(
    state[], payloadAttrs[])

  if response.payloadStatus.status notin {syncing, valid, invalid}:
    debug "Invalid fork-choice updated response from the EL",
          payloadStatus = response.payloadStatus
    return

  if response.payloadStatus.status == PayloadExecutionStatus.valid and
     response.payloadId.isSome:
    connection.lastPayloadId = response.payloadId

  return response.payloadStatus

proc forkchoiceUpdated*(m: ELManager,
                        headBlock, safeBlock, finalizedBlock: Eth2Digest,
                        payloadAttributes = none PayloadAttributesV1):
                        Future[PayloadExecutionStatus] {.async.} =
  doAssert not headBlock.isZero

  # Allow finalizedBlockRoot to be 0 to avoid sync deadlocks.
  #
  # https://github.com/ethereum/EIPs/blob/master/EIPS/eip-3675.md#pos-events
  # has "Before the first finalized block occurs in the system the finalized
  # block hash provided by this event is stubbed with
  # `0x0000000000000000000000000000000000000000000000000000000000000000`."
  # and
  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.3/specs/bellatrix/validator.md#executionpayload
  # notes "`finalized_block_hash` is the hash of the latest finalized execution
  # payload (`Hash32()` if none yet finalized)"

  if payloadAttributes.isSome:
    m.nextExpectedPayloadParams = some NextExpectedPayloadParams(
      headBlockRoot: headBlock,
      safeBlockRoot: safeBlock,
      finalizedBlockRoot: finalizedBlock,
      payloadAttributes: payloadAttributes.get)

  let
    state = newClone ForkchoiceStateV1(
      headBlockHash: headBlock.asBlockHash,
      safeBlockHash: safeBlock.asBlockHash,
      finalizedBlockHash: finalizedBlock.asBlockHash)
    payloadAttrs = newClone payloadAttributes
    deadline = sleepAsync(FORKCHOICEUPDATED_TIMEOUT)
    requests = m.elConnections.mapIt(
      it.forkchoiceUpdatedForSingleEL(state, payloadAttrs))
    requestsCompleted = allFutures(requests)

  await requestsCompleted or deadline

  var
    selectedResponse = none int
    disagreementAlreadyDetected = false

  for idx, req in requests:
    if not req.finished:
      req.cancel()
    else:
      let url = m.elConnections[idx].engineUrl.url
      if req.failed:
        engine_forkchoiceUpdated_failures.inc(1, [url])
        error "Sending fork-choice update to the EL failed",
               url, err = req.error.msg
      else:
        let status = req.read.status
        engine_newPayload_sent.inc(1, [url, $status])

        if selectedResponse.isNone:
          selectedResponse = some idx
        elif not disagreementAlreadyDetected:
          let prevStatus = requests[selectedResponse.get].read.status
          case compareStatuses(status, prevStatus)
          of newStatusIsPreferable:
            selectedResponse = some idx
          of oldStatusIsOk:
            discard
          of disagreement:
            disagreementAlreadyDetected = true
            error "ELs disagree regarding fork-choice update status",
                  url1 = m.elConnections[selectedResponse.get].engineUrl,
                  status1 = prevStatus,
                  url2 = url,
                  status2 = status

  return if disagreementAlreadyDetected:
    PayloadExecutionStatus.invalid
  elif selectedResponse.isSome:
    requests[selectedResponse.get].read.status
  else:
    PayloadExecutionStatus.syncing

proc forkchoiceUpdatedNoResult*(m: ELManager,
                                headBlock, safeBlock, finalizedBlock: Eth2Digest,
                                payloadAttributes = none PayloadAttributesV1) {.async.} =
  discard await m.forkchoiceUpdated(
    headBlock, safeBlock, finalizedBlock, payloadAttributes)

# TODO can't be defined within exchangeConfigWithSingleEL
proc `==`(x, y: Quantity): bool {.borrow, noSideEffect.}

proc exchangeConfigWithSingleEL(m: ELManager, connection: ELConnection) {.async.} =
  let rpcClient = await connection.connectedRpcClient()

  if m.eth1Network.isSome and
     connection.etcStatus == EtcStatus.notExchangedYet:
    try:
      let
        providerChain =
          awaitWithRetries(rpcClient.eth_chainId(), web3RequestsTimeout,
                           onFailure = block: raise lastError())

        # https://eips.ethereum.org/EIPS/eip-155#list-of-chain-ids
        expectedChain = case m.eth1Network.get
          of mainnet: 1.Quantity
          of ropsten: 3.Quantity
          of rinkeby: 4.Quantity
          of goerli:  5.Quantity
          of sepolia: 11155111.Quantity   # https://chainid.network/
      if expectedChain != providerChain:
        warn "The specified EL client is connected to a different chain",
              url = connection.engineUrl,
              expectedChain = distinctBase(expectedChain),
              actualChain = distinctBase(providerChain)
        connection.etcStatus = EtcStatus.mismatch
        return
    except CatchableError as exc:
      # Typically because it's not synced through EIP-155, assuming this Web3
      # endpoint has been otherwise working.
      debug "Failed to obtain eth_chainId",
             error = exc.msg

  let
    ourConfiguration = TransitionConfigurationV1(
      terminalTotalDifficulty: m.depositsChain.cfg.TERMINAL_TOTAL_DIFFICULTY,
      terminalBlockHash:
        if m.terminalBlockHash.isSome:
          m.terminalBlockHash.get
        else:
          (static default BlockHash),
      terminalBlockNumber:
        if m.terminalBlockNumber.isSome:
          m.terminalBlockNumber.get
        else:
          (static default Quantity))
    elConfiguration = try:
      awaitWithRetries(
        rpcClient.engine_exchangeTransitionConfigurationV1(ourConfiguration),
        timeout = 1.seconds)
    except CatchableError as err:
      error "Failed to exchange transition configuration",
            url = connection.engineUrl, err = err.msg
      connection.etcStatus = EtcStatus.exchangeError
      return

  if ourConfiguration.terminalTotalDifficulty != elConfiguration.terminalTotalDifficulty:
    warn "Engine API configured with different terminal total difficulty",
         url = connection.engineUrl,
         engineAPI_value = elConfiguration.terminalTotalDifficulty,
         localValue = ourConfiguration.terminalTotalDifficulty
    connection.etcStatus = EtcStatus.mismatch
    return

  if m.terminalBlockNumber.isSome and m.terminalBlockHash.isSome:
    var status = EtcStatus.match
    if ourConfiguration.terminalBlockNumber != elConfiguration.terminalBlockNumber:
      warn "Engine API reporting different terminal block number",
            url = connection.engineUrl,
            engineAPI_value = elConfiguration.terminalBlockNumber.uint64,
            localValue = ourConfiguration.terminalBlockNumber.uint64
      status = EtcStatus.mismatch
    if ourConfiguration.terminalBlockHash != elConfiguration.terminalBlockHash:
      warn "Engine API reporting different terminal block hash",
            url = connection.engineUrl,
            engineAPI_value = elConfiguration.terminalBlockHash,
            localValue = ourConfiguration.terminalBlockHash
      status = EtcStatus.mismatch
    connection.etcStatus = status
  else:
    m.terminalBlockNumber = some elConfiguration.terminalBlockNumber
    m.terminalBlockHash = some elConfiguration.terminalBlockHash

    info "Obtained terminal block from Engine API",
       url = connection.engineUrl,
       terminalBlockNumber = m.terminalBlockNumber.get.uint64,
       terminalBlockHash = m.terminalBlockHash.get

    connection.etcStatus = EtcStatus.localConfigurationUpdated

proc exchangeTransitionConfiguration*(m: ELManager) {.async.} =
  let
    deadline = sleepAsync(3.seconds)
    requests = m.elConnections.mapIt(m.exchangeConfigWithSingleEL(it))
    requestsCompleted = allFutures(requests)

  await requestsCompleted or deadline

  for idx, req in requests:
    if not req.finished:
      m.elConnections[idx].etcStatus = EtcStatus.exchangeError
      req.cancel()

template readJsonField(j: JsonNode, fieldName: string, ValueType: type): untyped =
  var res: ValueType
  fromJson(j[fieldName], fieldName, res)
  res

template init[N: static int](T: type DynamicBytes[N, N]): T =
  T newSeq[byte](N)

proc fetchTimestampWithRetries(rpcClient: RpcClient,
                               blk: Eth1Block) {.async.} =
  let web3block = awaitWithRetries(
    rpcClient.getBlockByHash(blk.hash.asBlockHash),
    web3RequestsTimeout)
  blk.timestamp = Eth1BlockTimestamp web3block.timestamp

func depositEventsToBlocks(depositsList: JsonNode): seq[Eth1Block] {.
    raises: [Defect, CatchableError].} =
  if depositsList.kind != JArray:
    raise newException(CatchableError,
      "Web3 provider didn't return a list of deposit events")

  var lastEth1Block: Eth1Block

  for logEvent in depositsList:
    let
      blockNumber = Eth1BlockNumber readJsonField(logEvent, "blockNumber", Quantity)
      blockHash = readJsonField(logEvent, "blockHash", BlockHash)
      logData = strip0xPrefix(logEvent["data"].getStr)

    if lastEth1Block == nil or lastEth1Block.number != blockNumber:
      lastEth1Block = Eth1Block(
        hash: blockHash.asEth2Digest,
        number: blockNumber
        # The `timestamp` is set in `syncBlockRange` immediately
        # after calling this function, because we don't want to
        # make this function `async`
      )

      result.add lastEth1Block

    var
      pubkey = init PubKeyBytes
      withdrawalCredentials = init WithdrawalCredentialsBytes
      amount = init Int64LeBytes
      signature = init SignatureBytes
      index = init Int64LeBytes

    var offset = 0
    offset += decode(logData, offset, pubkey)
    offset += decode(logData, offset, withdrawalCredentials)
    offset += decode(logData, offset, amount)
    offset += decode(logData, offset, signature)
    offset += decode(logData, offset, index)

    if pubkey.len != 48 or
       withdrawalCredentials.len != 32 or
       amount.len != 8 or
       signature.len != 96 or
       index.len != 8:
      raise newException(CorruptDataProvider, "Web3 provider supplied invalid deposit logs")

    lastEth1Block.deposits.add DepositData(
      pubkey: ValidatorPubKey.init(pubkey.toArray),
      withdrawal_credentials: Eth2Digest(data: withdrawalCredentials.toArray),
      amount: bytes_to_uint64(amount.toArray),
      signature: ValidatorSig.init(signature.toArray))

type
  DepositContractDataStatus = enum
    Fetched
    VerifiedCorrect
    DepositRootIncorrect
    DepositRootUnavailable
    DepositCountIncorrect
    DepositCountUnavailable

template awaitOrRaiseOnTimeout[T](fut: Future[T],
                                  timeout: Duration): T =
  awaitWithTimeout(fut, timeout):
    raise newException(DataProviderTimeout, "Timeout")

when hasDepositRootChecks:
  const
    contractCallTimeout = 60.seconds

  proc fetchDepositContractData(rpcClient: RpcClient,
                                depositContact: Sender[DepositContract],
                                blk: Eth1Block): Future[DepositContractDataStatus] {.async.} =
    let
      depositRoot = depositContract.get_deposit_root.call(blockNumber = blk.number)
      rawCount = depositContract.get_deposit_count.call(blockNumber = blk.number)

    try:
      let fetchedRoot = asEth2Digest(
        awaitOrRaiseOnTimeout(depositRoot, contractCallTimeout))
      if blk.depositRoot.isZero:
        blk.depositRoot = fetchedRoot
        result = Fetched
      elif blk.depositRoot == fetchedRoot:
        result = VerifiedCorrect
      else:
        result = DepositRootIncorrect
    except CatchableError as err:
      debug "Failed to fetch deposits root",
        blockNumber = blk.number,
        err = err.msg
      result = DepositRootUnavailable

    try:
      let fetchedCount = bytes_to_uint64(
        awaitOrRaiseOnTimeout(rawCount, contractCallTimeout).toArray)
      if blk.depositCount == 0:
        blk.depositCount = fetchedCount
      elif blk.depositCount != fetchedCount:
        result = DepositCountIncorrect
    except CatchableError as err:
      debug "Failed to fetch deposits count",
            blockNumber = blk.number,
            err = err.msg
      result = DepositCountUnavailable

proc pruneOldBlocks(chain: var Eth1Chain, depositIndex: uint64) =
  ## Called on block finalization to delete old and now redundant data.
  let initialChunks = chain.finalizedDepositsMerkleizer.getChunkCount
  var lastBlock: Eth1Block

  while chain.blocks.len > 0:
    let blk = chain.blocks.peekFirst
    if blk.depositCount >= depositIndex:
      break
    else:
      for deposit in blk.deposits:
        chain.finalizedDepositsMerkleizer.addChunk hash_tree_root(deposit).data
    chain.popFirst()
    lastBlock = blk

  if chain.finalizedDepositsMerkleizer.getChunkCount > initialChunks:
    chain.finalizedBlockHash = lastBlock.hash
    chain.db.putDepositTreeSnapshot DepositTreeSnapshot(
      eth1Block: lastBlock.hash,
      depositContractState: chain.finalizedDepositsMerkleizer.toDepositContractState,
      blockHeight: lastBlock.number,
    )

    eth1_finalized_head.set lastBlock.number.toGaugeValue
    eth1_finalized_deposits.set lastBlock.depositCount.toGaugeValue

    debug "Eth1 blocks pruned",
           newTailBlock = lastBlock.hash,
           depositsCount = lastBlock.depositCount

func advanceMerkleizer(chain: Eth1Chain,
                       merkleizer: var DepositsMerkleizer,
                       depositIndex: uint64): bool =
  if chain.blocks.len == 0:
    return depositIndex == merkleizer.getChunkCount

  if chain.blocks.peekLast.depositCount < depositIndex:
    return false

  let
    firstBlock = chain.blocks[0]
    depositsInLastPrunedBlock = firstBlock.depositCount -
                                firstBlock.deposits.lenu64

  # advanceMerkleizer should always be called shortly after prunning the chain
  doAssert depositsInLastPrunedBlock == merkleizer.getChunkCount

  for blk in chain.blocks:
    for deposit in blk.deposits:
      if merkleizer.getChunkCount < depositIndex:
        merkleizer.addChunk hash_tree_root(deposit).data
      else:
        return true

  return merkleizer.getChunkCount == depositIndex

iterator getDepositsRange*(chain: Eth1Chain, first, last: uint64): DepositData =
  # TODO It's possible to make this faster by performing binary search that
  #      will locate the blocks holding the `first` and `last` indices.
  # TODO There is an assumption here that the requested range will be present
  #      in the Eth1Chain. This should hold true at the call sites right now,
  #      but we need to guard the pre-conditions better.
  for blk in chain.blocks:
    if blk.depositCount <= first:
      continue

    let firstDepositIdxInBlk = blk.depositCount - blk.deposits.lenu64
    if firstDepositIdxInBlk >= last:
      break

    for i in 0 ..< blk.deposits.lenu64:
      let globalIdx = firstDepositIdxInBlk + i
      if globalIdx >= first and globalIdx < last:
        yield blk.deposits[i]

func lowerBound(chain: Eth1Chain, depositCount: uint64): Eth1Block =
  # TODO: This can be replaced with a proper binary search in the
  #       future, but the `algorithm` module currently requires an
  #       `openArray`, which the `deques` module can't provide yet.
  for eth1Block in chain.blocks:
    if eth1Block.depositCount > depositCount:
      return
    result = eth1Block

proc trackFinalizedState(chain: var Eth1Chain,
                         finalizedEth1Data: Eth1Data,
                         finalizedStateDepositIndex: uint64,
                         blockProposalExpected = false): bool =
  ## This function will return true if the ELManager is synced
  ## to the finalization point.

  if chain.blocks.len == 0:
    debug "Eth1 chain not initialized"
    return false

  let latest = chain.blocks.peekLast
  if latest.depositCount < finalizedEth1Data.deposit_count:
    if blockProposalExpected:
      error "The Eth1 chain is not synced",
            ourDepositsCount = latest.depositCount,
            targetDepositsCount = finalizedEth1Data.deposit_count
    return false

  let matchingBlock = chain.lowerBound(finalizedEth1Data.deposit_count)
  result = if matchingBlock != nil:
    if matchingBlock.depositRoot == finalizedEth1Data.deposit_root:
      true
    else:
      error "Corrupted deposits history detected",
            ourDepositsCount = matchingBlock.depositCount,
            taretDepositsCount = finalizedEth1Data.deposit_count,
            ourDepositsRoot = matchingBlock.depositRoot,
            targetDepositsRoot = finalizedEth1Data.deposit_root
      chain.hasConsensusViolation = true
      false
  else:
    error "The Eth1 chain is in inconsistent state",
          checkpointHash = finalizedEth1Data.block_hash,
          checkpointDeposits = finalizedEth1Data.deposit_count,
          localChainStart = shortLog(chain.blocks.peekFirst),
          localChainEnd = shortLog(chain.blocks.peekLast)
    chain.hasConsensusViolation = true
    false

  if result:
    chain.pruneOldBlocks(finalizedStateDepositIndex)

template trackFinalizedState*(m: ELManager,
                              finalizedEth1Data: Eth1Data,
                              finalizedStateDepositIndex: uint64): bool =
  trackFinalizedState(m.depositsChain, finalizedEth1Data, finalizedStateDepositIndex)

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-alpha.0/specs/phase0/validator.md#get_eth1_data
proc getBlockProposalData*(chain: var Eth1Chain,
                           state: ForkedHashedBeaconState,
                           finalizedEth1Data: Eth1Data,
                           finalizedStateDepositIndex: uint64): BlockProposalEth1Data =
  let
    periodStart = voting_period_start_time(state)
    hasLatestDeposits = chain.trackFinalizedState(finalizedEth1Data,
                                                  finalizedStateDepositIndex,
                                                  blockProposalExpected = true)

  var otherVotesCountTable = initCountTable[Eth1Data]()
  for vote in getStateField(state, eth1_data_votes):
    let eth1Block = chain.findBlock(vote)
    if eth1Block != nil and
       eth1Block.depositRoot == vote.deposit_root and
       vote.deposit_count >= getStateField(state, eth1_data).deposit_count and
       is_candidate_block(chain.cfg, eth1Block, periodStart):
      otherVotesCountTable.inc vote
    else:
      debug "Ignoring eth1 vote",
            root = vote.block_hash,
            deposits = vote.deposit_count,
            depositsRoot = vote.deposit_root,
            localDeposits = getStateField(state, eth1_data).deposit_count

  let
    stateDepositIdx = getStateField(state, eth1_deposit_index)
    stateDepositsCount = getStateField(state, eth1_data).deposit_count

  # A valid state should never have this condition, but it doesn't hurt
  # to be extra defensive here because we are working with uint types
  var pendingDepositsCount = if stateDepositsCount > stateDepositIdx:
    stateDepositsCount - stateDepositIdx
  else:
    0

  if otherVotesCountTable.len > 0:
    let (winningVote, votes) = otherVotesCountTable.largest
    debug "Voting on eth1 head with majority", votes
    result.vote = winningVote
    if uint64((votes + 1) * 2) > SLOTS_PER_ETH1_VOTING_PERIOD:
      pendingDepositsCount = winningVote.deposit_count - stateDepositIdx

  else:
    let latestBlock = chain.latestCandidateBlock(periodStart)
    if latestBlock == nil:
      debug "No acceptable eth1 votes and no recent candidates. Voting no change"
      result.vote = getStateField(state, eth1_data)
    else:
      debug "No acceptable eth1 votes. Voting for latest candidate"
      result.vote = latestBlock.toVoteData

  if pendingDepositsCount > 0:
    if hasLatestDeposits:
      let
        totalDepositsInNewBlock = min(MAX_DEPOSITS, pendingDepositsCount)
        postStateDepositIdx = stateDepositIdx + pendingDepositsCount
      var
        deposits = newSeqOfCap[DepositData](totalDepositsInNewBlock)
        depositRoots = newSeqOfCap[Eth2Digest](pendingDepositsCount)
      for data in chain.getDepositsRange(stateDepositIdx, postStateDepositIdx):
        if deposits.lenu64 < totalDepositsInNewBlock:
          deposits.add data
        depositRoots.add hash_tree_root(data)

      var scratchMerkleizer = copy chain.finalizedDepositsMerkleizer
      if chain.advanceMerkleizer(scratchMerkleizer, stateDepositIdx):
        let proofs = scratchMerkleizer.addChunksAndGenMerkleProofs(depositRoots)
        for i in 0 ..< totalDepositsInNewBlock:
          var proof: array[33, Eth2Digest]
          proof[0..31] = proofs.getProof(i.int)
          proof[32] = default(Eth2Digest)
          proof[32].data[0..7] = toBytesLE uint64(postStateDepositIdx)
          result.deposits.add Deposit(data: deposits[i], proof: proof)
      else:
        error "The Eth1 chain is in inconsistent state" # This should not really happen
        result.hasMissingDeposits = true
    else:
      result.hasMissingDeposits = true

template getBlockProposalData*(m: ELManager,
                               state: ForkedHashedBeaconState,
                               finalizedEth1Data: Eth1Data,
                               finalizedStateDepositIndex: uint64):
                               BlockProposalEth1Data =
  getBlockProposalData(
    m.depositsChain, state, finalizedEth1Data, finalizedStateDepositIndex)

proc new*(T: type ELConnection, engineUrl: EngineApiUrl): T =
  ELConnection(
    engineUrl: engineUrl,
    delaySyncRestart: ZeroDuration)

proc connect(connection: ELConnection,
             depositContractAddress: Option[Eth1Address]):
             Future[Result[void, string]] {.async.} =
  let web3Fut = connection.engineUrl.newWeb3()
  yield web3Fut or sleepAsync(engineApiConnectionTimeout)

  if (not web3Fut.finished) or web3Fut.failed:
    await cancelAndWait(web3Fut)
    if web3Fut.failed:
      return err "Failed to setup web3 connection: " & web3Fut.readError.msg
    else:
      return err "Failed to setup web3 connection"

  let web3 = web3Fut.read
  connection.web3 = some web3

  if depositContractAddress.isSome:
    connection.depositContract = some web3.contractSender(
      DepositContract, depositContractAddress.get)

  return ok()

proc resetConnection(provider: var ELConnection,
                     depositContractAddress: Option[Eth1Address]) {.async.} =
  discard

template getOrDefault[T, E](r: Result[T, E]): T =
  type TT = T
  get(r, default(TT))

proc init*(T: type Eth1Chain, cfg: RuntimeConfig, db: BeaconChainDB): T =
  let
    finalizedDeposits =
      if db != nil:
        db.getDepositTreeSnapshot().getOrDefault()
      else:
        default(DepositTreeSnapshot)
    m = DepositsMerkleizer.init(finalizedDeposits.depositContractState)

  T(db: db,
    cfg: cfg,
    finalizedBlockHash: finalizedDeposits.eth1Block,
    finalizedDepositsMerkleizer: m,
    headMerkleizer: copy m)

proc getBlock(provider: Web3DataProviderRef, id: BlockHashOrNumber):
             Future[BlockObject] =
  if id.isHash:
    let hash = id.hash.asBlockHash()
    return provider.getBlockByHash(hash)
  else:
    return provider.getBlockByNumber(id.number)

proc currentEpoch(m: ELManager): Epoch =
  if m.getBeaconTime != nil:
    m.getBeaconTime().slotOrZero.epoch
  else:
    Epoch 0

proc new*(T: type ELManager,
          cfg: RuntimeConfig,
          db: BeaconChainDB,
          getBeaconTime: GetBeaconTimeFn,
          web3Urls: seq[EngineApiUrl],
          eth1Network: Option[Eth1Network],
          ttdReached: bool): T =
  if depositContractSnapshot.isSome:
    putInitialDepositContractSnapshot(db, depositContractSnapshot.get)

  T(depositsChain: Eth1Chain.init(cfg, db),
    depositContractAddress: cfg.DEPOSIT_CONTRACT_ADDRESS,
    getBeaconTime: getBeaconTime,
    elConnections: mapIt(web3Urls, ELConnection.new(it)),
    eth1Network: eth1Network,
    blocksPerLogsRequest: targetBlocksPerLogsRequest,
    ttdReachedField: ttdReached)

proc runDbMigrations*(T: type Eth1Monitor,
                      db: BeaconChainDB,
                      web3Url: string,
                      jwtSecret: Option[seq[byte]],
                      depositContractAddress: Eth1Address,
                      depositContractDeployedAt: BlockHashOrNumber) {.async.} =
  if db.hasDepositTreeSnapshot():
    return

  let providerRes = await Web3DataProvider.new(depositContractAddress, web3Url, jwtSecret)
  if providerRes.isErr:
    fatal "Failed to initialize web3 provider",
          depositContract = depositContractAddress,
          web3Url, err = providerRes.error
    quit 1
  let provider = providerRes.get()
  doAssert provider != nil

  # There might be an old deposit snapshot in the database that needs upgrade.
  let oldSnapshot = db.getUpgradableDepositSnapshot()
  if oldSnapshot.isSome:
    let
      hash = oldSnapshot.get.eth1Block.asBlockHash()
      blk = awaitWithRetries provider.getBlockByHash(hash)
      blockNumber = uint64(blk.number)

    db.putDepositTreeSnapshot oldSnapshot.get.toDepositTreeSnapshot(blockNumber)
  else:
    # If there is no DCS record at all, create one pointing to the deployment block
    # of the deposit contract and insert it as a starting point.
    let blk = try:
      awaitWithRetries getBlock(provider, depositContractDeployedAt)
    except CatchableError as e:
      fatal "Failed to fetch deployment block",
            depositContract = depositContractAddress,
            deploymentBlock = $depositContractDeployedAt,
            err = e.msg
      quit 1
    doAssert blk != nil, "getBlock should not return nil"
    db.putDepositTreeSnapshot DepositTreeSnapshot(
      eth1Block: blk.hash.asEth2Digest,
      blockHeight: uint64 blk.number)

proc safeCancel(fut: var Future[void]) =
  if not fut.isNil and not fut.finished:
    fut.cancel()
  fut = nil

func clear(chain: var Eth1Chain) =
  chain.blocks.clear()
  chain.blocksByHash.clear()
  chain.headMerkleizer = copy chain.finalizedDepositsMerkleizer
  chain.hasConsensusViolation = false

proc doStop(m: ELManager) {.async.} =
  safeCancel m.depositSyncLoopFut
  safeCancel m.exchangeTransitionConfigurationLoopFut

  let closeConnectionFutures = mapIt(m.elConnections, close(it))
  await allFutures(closeConnectionFutures)

proc stop(m: ELManager) {.async.} =
  if not m.stopFut.isNil:
    await m.stopFut
  else:
    m.stopFut = m.doStop()
    await m.stopFut
    m.stopFut = nil

const
  votedBlocksSafetyMargin = 50

func earliestBlockOfInterest(m: ELManager, latestEth1BlockNumber: Eth1BlockNumber): Eth1BlockNumber =
  latestEth1BlockNumber - (2 * m.cfg.ETH1_FOLLOW_DISTANCE) - votedBlocksSafetyMargin

proc syncBlockRange(m: ELManager,
                    rpcClient: RpcClient,
                    depositContract: Sender[DepositContract],
                    fromBlock, toBlock,
                    fullSyncFromBlock: Eth1BlockNumber) {.gcsafe, async.} =
  doAssert m.dataProvider != nil, "close not called concurrently"
  doAssert m.depositsChain.blocks.len > 0

  var currentBlock = fromBlock
  while currentBlock <= toBlock:
    var
      depositLogs: JsonNode = nil
      maxBlockNumberRequested: Eth1BlockNumber
      backoff = 100

    while true:
      maxBlockNumberRequested =
        min(toBlock, currentBlock + m.blocksPerLogsRequest - 1)

      debug "Obtaining deposit log events",
            fromBlock = currentBlock,
            toBlock = maxBlockNumberRequested,
            backoff

      debug.logTime "Deposit logs obtained":
        # Reduce all request rate until we have a more general solution
        # for dealing with Infura's rate limits
        await sleepAsync(milliseconds(backoff))
        let jsonLogsFut = depositContract.getJsonLogs(
          DepositEvent,
          fromBlock = some blockId(currentBlock),
          toBlock = some blockId(maxBlockNumberRequested))

        depositLogs = try:
          # Downloading large amounts of deposits may take several minutes
          awaitWithTimeout(jsonLogsFut, 60.seconds):
            raise newException(DataProviderTimeout,
              "Request time out while obtaining json logs")
        except CatchableError as err:
          debug "Request for deposit logs failed", err = err.msg
          inc failed_web3_requests
          backoff = (backoff * 3) div 2
          m.blocksPerLogsRequest = m.blocksPerLogsRequest div 2
          if m.blocksPerLogsRequest == 0:
            m.blocksPerLogsRequest = 1
            raise err
          continue
        m.blocksPerLogsRequest = min(
          (m.blocksPerLogsRequest * 3 + 1) div 2,
          targetBlocksPerLogsRequest)

      currentBlock = maxBlockNumberRequested + 1
      break

    let blocksWithDeposits = depositEventsToBlocks(depositLogs)

    for i in 0 ..< blocksWithDeposits.len:
      let blk = blocksWithDeposits[i]
      await rpcClient.fetchTimestampWithRetries(blk)

      if blk.number > fullSyncFromBlock:
        let lastBlock = m.depositsChain.blocks.peekLast
        for n in max(lastBlock.number + 1, fullSyncFromBlock) ..< blk.number:
          debug "Obtaining block without deposits", blockNum = n
          let blockWithoutDeposits = awaitWithRetries(
            rpcClient.getBlockByNumber(n),
            web3RequestsTimeout)

          m.depositsChain.addBlock(
            lastBlock.makeSuccessorWithoutDeposits(blockWithoutDeposits))
          eth1_synced_head.set blockWithoutDeposits.number.toGaugeValue

      m.depositsChain.addBlock blk
      eth1_synced_head.set blk.number.toGaugeValue

    if blocksWithDeposits.len > 0:
      let lastIdx = blocksWithDeposits.len - 1
      template lastBlock: auto = blocksWithDeposits[lastIdx]

      let status = when hasDepositRootChecks:
        awaitWithRetries(
          rpcClient.fetchDepositContractData(depositContract, lastBlock),
          web3RequestsTimeout)
      else:
        DepositRootUnavailable

      when hasDepositRootChecks:
        debug "Deposit contract state verified",
              status = $status,
              ourCount = lastBlock.depositCount,
              ourRoot = lastBlock.depositRoot

      case status
      of DepositRootIncorrect, DepositCountIncorrect:
        raise newException(CorruptDataProvider,
          "The deposit log events disagree with the deposit contract state")
      else:
        discard

      info "Eth1 sync progress",
        blockNumber = lastBlock.number,
        depositsProcessed = lastBlock.depositCount

    when hasGenesisDetection:
      if blocksWithDeposits.len > 0:
        for blk in blocksWithDeposits:
          for deposit in blk.deposits:
            m.processGenesisDeposit(deposit)
          blk.activeValidatorsCount = m.genesisValidators.lenu64

        let
          lastBlock = blocksWithDeposits[^1]
          depositTreeSnapshot = DepositTreeSnapshot(
            eth1Block: lastBlock.hash,
            depositContractState: m.headMerkleizer.toDepositContractState,
            blockNumber: lastBlock.number)

        m.depositsChain.db.putDepositTreeSnapshot depositTreeSnapshot

      if m.genesisStateFut != nil and m.chainHasEnoughValidators:
        let lastIdx = m.depositsChain.blocks.len - 1
        template lastBlock: auto = m.depositsChain.blocks[lastIdx]

        if maxBlockNumberRequested == toBlock and
           (m.depositsChain.blocks.len == 0 or lastBlock.number != toBlock):
          let web3Block = awaitWithRetries(
            rpcClient.getBlockByNumber(toBlock),
            ethRequetsTimeout)

          debug "Latest block doesn't hold deposits. Obtaining it",
                 ts = web3Block.timestamp.uint64,
                 number = web3Block.number.uint64

          m.depositsChain.addBlock lastBlock.makeSuccessorWithoutDeposits(web3Block)
        else:
          await rpcClient.fetchTimestampWithRetries(lastBlock)

        var genesisBlockIdx = m.depositsChain.blocks.len - 1
        if m.isAfterMinGenesisTime(m.depositsChain.blocks[genesisBlockIdx]):
          for i in 1 ..< blocksWithDeposits.len:
            let idx = (m.depositsChain.blocks.len - 1) - i
            let blk = m.depositsChain.blocks[idx]
            await rpcClient.fetchTimestampWithRetries(blk)
            if m.isGenesisCandidate(blk):
              genesisBlockIdx = idx
            else:
              break
          # We have a candidate state on our hands, but our current Eth1Chain
          # may consist only of blocks that have deposits attached to them
          # while the real genesis may have happened in a block without any
          # deposits (triggered by MIN_GENESIS_TIME).
          #
          # This can happen when the beacon node is launched after the genesis
          # event. We take a short cut when constructing the initial Eth1Chain
          # by downloading only deposit log entries. Thus, we'll see all the
          # blocks with deposits, but not the regular blocks in between.
          #
          # We'll handle this special case below by examing whether we are in
          # this potential scenario and we'll use a fast guessing algorith to
          # discover the ETh1 block with minimal valid genesis time.
          var genesisBlock = m.depositsChain.blocks[genesisBlockIdx]
          if genesisBlockIdx > 0:
            let genesisParent = m.depositsChain.blocks[genesisBlockIdx - 1]
            if genesisParent.timestamp == 0:
              await rpcClient.fetchTimestampWithRetries(genesisParent)
            if m.hasEnoughValidators(genesisParent) and
               genesisBlock.number - genesisParent.number > 1:
              genesisBlock = awaitWithRetries(
                m.findGenesisBlockInRange(genesisParent, genesisBlock),
                web3RequestsTimeout)

          m.signalGenesis m.createGenesisState(genesisBlock)

func init(T: type FullBlockId, blk: Eth1BlockHeader|BlockObject): T =
  FullBlockId(number: Eth1BlockNumber blk.number, hash: blk.hash)

func isNewLastBlock(m: ELManager, blk: Eth1BlockHeader|BlockObject): bool =
  m.latestEth1Block.isNone or blk.number.uint64 > m.latestEth1BlockNumber

proc findTerminalBlock(provider: Web3DataProviderRef,
                       ttd: Uint256): Future[BlockObject] {.async.} =
  ## Find the first execution block with a difficulty higher than the
  ## specified `ttd`.
  var
    cache = initTable[uint64, BlockObject]()
    step = -0x4000'i64

  proc next(x: BlockObject): Future[BlockObject] {.async.} =
    ## Returns the next block that's `step` steps away.
    let key = uint64(max(int64(x.number) + step, 1))
    # Check if present in cache.
    if key in cache:
      return cache[key]
    # Not cached, fetch.
    let value = awaitWithRetries provider.getBlockByNumber(key)
    cache[key] = value
    return value

  # Block A follows, B leads.
  var
    a = awaitWithRetries(
      provider.web3.provider.eth_getBlockByNumber("latest", false))
    b = await next(a)

  while true:
    let one = a.totalDifficulty > ttd
    let two = b.totalDifficulty > ttd
    if one != two:
      step = step div -2i64
      if step == 0:
        # Since we can't know in advance from which side the block is
        # approached, one last check is needed to determine the proper
        # terminal block.
        if one: return a
        else  : return b
    a = b
    b = await next(b)

  # This is unreachable.
  doAssert(false)

func hasProperlyConfiguredConnection(m: ELManager): bool =
  for connection in m.elConnections:
    if connection.etcStatus in {EtcStatus.match, EtcStatus.localConfigurationUpdated}:
      return true

  return false

proc shouldExchangeTransitionConfiguration*(m: ELManager): bool =
  # We start exchanging the configuration roughly two weeks before the hard-fork
  m.currentEpoch + 14 * 256 >= m.cfg.BELLATRIX_FORK_EPOCH

proc startExchangeTransitionConfigurationLoop(m: ELManager) {.async.} =
  if m.shouldExchangeTransitionConfiguration and not m.hasProperlyConfiguredConnection:
    await m.exchangeTransitionConfiguration()
    if not m.hasProperlyConfiguredConnection:
      fatal "The Bellatrix hard fork requires the beacon node to be connected a properly configured Engine API end-point. " &
            "See https://nimbus.guide/merge.html for more details."
      quit 1

  while true:
    # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.1/src/engine/specification.md#engine_exchangetransitionconfigurationv1
    await sleepAsync(60.seconds)
    if m.shouldExchangeTransitionConfiguration:
      traceAsyncErrors m.exchangeTransitionConfiguration()

proc startDepositsSyncingLoop(m: ELManager) {.async.} =
  var
    isFirstRun = true
    activeConnectionIdx = -1
  let
    shouldProcessDeposits = not (
      m.depositContractAddress.isZeroMemory or
      m.depositsChain.finalizedBlockHash.data.isZeroMemory)
    establishConnectionsToELs = mapIt(m.elConnections, reconnect(it))
    connectionDeadline = sleepAsync(3.seconds)

  # TODO: This shouldn't be here potentially
  await allFutures(establishConnectionsToELs) or connectionDeadline
  for connectionAttempt in establishConnectionsToELs:
    if not connectionAttempt.finished:
      cancel connectionAttempt

  while true:
    try:
      activeConnectionIdx = (activeConnectionIdx + 1) mod m.elConnections.len
      let activeConnection = m.elConnections[activeConnectionIdx]

      if activeConnection.delaySyncRestart > ZeroDuration:
        await sleepAsync(activeConnection.delaySyncRestart)
        activeConnection.delaySyncRestart = ZeroDuration

      let rpcClient = await activeConnection.connectedRpcClient()

      logScope:
        url = activeConnection.engineUrl.url

      if isFirstRun:
        info "Starting Eth1 deposit contract monitoring",
              contract = $m.depositContractAddress
        isFirstRun = false

      # We might need to reset the chain if the new provider disagrees
      # with the previous one regarding the history of the chain or if
      # we have detected a conensus violation - our view disagreeing with
      # the majority of the validators in the network.
      #
      # Consensus violations happen in practice because the web3 providers
      # sometimes return incomplete or incorrect deposit log events even
      # when they don't indicate any errors in the response. When this
      # happens, we are usually able to download the data successfully
      # on the second attempt.
      if m.depositsChain.blocks.len > 0:
        let needsReset = m.depositsChain.hasConsensusViolation or (block:
          let
            lastKnownBlock = m.depositsChain.blocks.peekLast
            matchingBlockAtNewProvider = awaitWithRetries(
              rpcClient.getBlockByNumber(lastKnownBlock.number),
              web3RequestsTimeout)

          lastKnownBlock.hash.asBlockHash != matchingBlockAtNewProvider.hash)

        if needsReset:
          m.depositsChain.clear()

      var eth1SyncedTo: Eth1BlockNumber
      if shouldProcessDeposits:
        if m.depositsChain.blocks.len == 0:
          let finalizedBlockHash = m.depositsChain.finalizedBlockHash.asBlockHash
          let startBlock = try:
            awaitWithRetries(rpcClient.getBlockByHash(finalizedBlockHash),
                             web3RequestsTimeout)
          except CatchableError as err:
            warn "Failed to obtain latest finalized block details from EL. " &
                 "Please check whether the EL is still syncing",
                  finalizedBlockHash, err = err.msg
            activeConnection.delaySyncRestart = 1.minutes
            raise err

          m.depositsChain.addBlock Eth1Block(
            hash: m.depositsChain.finalizedBlockHash,
            number: Eth1BlockNumber startBlock.number,
            timestamp: Eth1BlockTimestamp startBlock.timestamp)

        eth1SyncedTo = Eth1BlockNumber m.depositsChain.blocks[^1].number

        eth1_synced_head.set eth1SyncedTo.toGaugeValue
        eth1_finalized_head.set eth1SyncedTo.toGaugeValue
        eth1_finalized_deposits.set(
          m.depositsChain.finalizedDepositsMerkleizer.getChunkCount.toGaugeValue)

        debug "Starting Eth1 syncing", `from` = shortLog(m.depositsChain.blocks[^1])

      let shouldCheckForMergeTransition = block:
        const FAR_FUTURE_TOTAL_DIFFICULTY =
          u256"115792089237316195423570985008687907853269984665640564039457584007913129638912"
        (not m.ttdReachedField) and
        (m.cfg.TERMINAL_TOTAL_DIFFICULTY != FAR_FUTURE_TOTAL_DIFFICULTY)

      while true:
        if bnStatus == BeaconNodeStatus.Stopping:
          when hasGenesisDetection:
            if not m.genesisStateFut.isNil:
              m.genesisStateFut.complete()
              m.genesisStateFut = nil
          await m.stop()
          return

        if m.depositsChain.hasConsensusViolation:
          raise newException(CorruptDataProvider, "Eth1 chain contradicts Eth2 consensus")

        let latestBlock = try:
          awaitWithRetries(
            rpcClient.eth_getBlockByNumber(blockId("latest"), false),
            web3RequestsTimeout)
        except CatchableError as err:
          error "Failed to obtain the latest block from the EL", err = err.msg
          raise err

        let syncTargetBlock = latestBlock.number.uint64 - m.cfg.ETH1_FOLLOW_DISTANCE
        if syncTargetBlock <= eth1SyncedTo:
          # The chain reorged to a lower height.
          # It's relatively safe to ignore that.
          await sleepAsync(m.cfg.SECONDS_PER_ETH1_BLOCK.int.seconds)
          continue

        eth1_latest_head.set latestBlock.number.toGaugeValue

        if m.currentEpoch >= m.cfg.BELLATRIX_FORK_EPOCH and m.terminalBlockHash.isNone:
          var terminalBlockCandidate = latestBlock

          info "startDepositsSyncingLoop: checking for merge terminal block",
            currentEpoch = m.currentEpoch,
            BELLATRIX_FORK_EPOCH = m.cfg.BELLATRIX_FORK_EPOCH,
            totalDifficulty = $latestBlock.totalDifficulty,
            ttd = $m.cfg.TERMINAL_TOTAL_DIFFICULTY,
            terminalBlockHash = m.terminalBlockHash

          # TODO when a terminal block hash is configured in cfg.TERMINAL_BLOCK_HASH,
          #      we should try to fetch that block from the EL - this facility is not
          #      in use on any current network, but should be implemented for full
          #      compliance
          if m.terminalBlockHash.isNone and shouldCheckForMergeTransition:
            let terminalBlock = await findTerminalBlock(
              m.dataProvider,
              m.cfg.TERMINAL_TOTAL_DIFFICULTY)
            m.terminalBlockHash = some(terminalBlock.hash)
            m.ttdReachedField = true
            debug "startEth1Syncing: found merge terminal block",
              currentEpoch = m.currentEpoch,
              BELLATRIX_FORK_EPOCH = m.cfg.BELLATRIX_FORK_EPOCH,
              totalDifficulty = $nextBlock.totalDifficulty,
              ttd = $m.cfg.TERMINAL_TOTAL_DIFFICULTY,
              terminalBlockHash = m.terminalBlockHash,
              candidateBlockNumber = distinctBase(terminalBlock.number)

        if shouldProcessDeposits and
           activeConnection.depositContract.isSome and
           latestBlock.number.uint64 > m.cfg.ETH1_FOLLOW_DISTANCE:
          await m.syncBlockRange(rpcClient,
                                 activeConnection.depositContract.get,
                                 eth1SyncedTo + 1,
                                 syncTargetBlock,
                                 m.earliestBlockOfInterest(Eth1BlockNumber latestBlock.number))

        eth1SyncedTo = syncTargetBlock
        eth1_synced_head.set eth1SyncedTo.toGaugeValue

    except CancelledError as err:
      raise err
    except CatchableError as err:
      if m.elConnections.len > 1:
        info "Trying next " # TODO
      else:
        info "" # TODO
      traceAsyncErrors m.elConnections[activeConnectionIdx].reconnect()

proc start*(m: ELManager) {.gcsafe.} =
  ## Calling `ELManager.start()` on an already started ELManager is a noop
  if m.elConnections.len == 0:
    return

  if m.exchangeTransitionConfigurationLoopFut.isNil:
    m.exchangeTransitionConfigurationLoopFut =
      m.startExchangeTransitionConfigurationLoop()

  if m.depositSyncLoopFut.isNil:
    m.depositSyncLoopFut =
      m.startDepositsSyncingLoop()

proc getEth1BlockHash*(
    url: EngineApiUrl, blockId: RtBlockIdentifier, jwtSecret: Option[seq[byte]]):
    Future[BlockHash] {.async.} =
  let web3 = awaitOrRaiseOnTimeout(url.newWeb3(), 10.seconds)
  try:
    let blk = awaitWithRetries(
      web3.provider.eth_getBlockByNumber(blockId, false),
      web3RequestsTimeout)
    return blk.hash
  finally:
    await web3.close()

func `$`(x: Quantity): string =
  $(x.uint64)

func `$`(x: BlockObject): string =
  $(x.number) & " [" & $(x.hash) & "]"

proc testWeb3Provider*(web3Url: Uri,
                       depositContractAddress: Eth1Address,
                       jwtSecret: Option[seq[byte]]) {.async.} =
  stdout.write "Establishing web3 connection..."
  var web3: Web3
  try:
    web3 = awaitOrRaiseOnTimeout(
      newWeb3($web3Url, getJsonRpcRequestHeaders(jwtSecret)), 5.seconds)
    stdout.write "\rEstablishing web3 connection: Connected\n"
  except CatchableError as err:
    stdout.write "\rEstablishing web3 connection: Failure(" & err.msg & ")\n"
    quit 1

  template request(actionDesc: static string,
                   action: untyped): untyped =
    stdout.write actionDesc & "..."
    stdout.flushFile()
    var res: typeof(read action)
    try:
      res = awaitWithRetries(action, web3RequestsTimeout)
      stdout.write "\r" & actionDesc & ": " & $res
    except CatchableError as err:
      stdout.write "\r" & actionDesc & ": Error(" & err.msg & ")"
    stdout.write "\n"
    res

  let
    clientVersion = request "Client version":
      web3.provider.web3_clientVersion()

    chainId = request "Chain ID":
      web3.provider.eth_chainId()

    latestBlock = request "Latest block":
      web3.provider.eth_getBlockByNumber(blockId("latest"), false)

    syncStatus = request "Sync status":
      web3.provider.eth_syncing()

    peers = request "Peers":
      web3.provider.net_peerCount()

    miningStatus = request "Mining status":
      web3.provider.eth_mining()

    ns = web3.contractSender(DepositContract, depositContractAddress)

    depositRoot = request "Deposit root":
      ns.get_deposit_root.call(blockNumber = latestBlock.number.uint64)

when hasGenesisDetection:
  proc loadPersistedDeposits*(monitor: ELManager) =
    for i in 0 ..< monitor.depositsChain.db.genesisDeposits.len:
      monitor.produceDerivedData monitor.depositsChain.db.genesisDeposits.get(i)

  proc findGenesisBlockInRange(m: ELManager,
                               rpcClient: RpcClient,
                               startBlock, endBlock: Eth1Block):
                               Future[Eth1Block] {.async.} =
    doAssert m.dataProvider != nil, "close not called concurrently"
    doAssert startBlock.timestamp != 0 and not m.isAfterMinGenesisTime(startBlock)
    doAssert endBlock.timestamp != 0 and m.isAfterMinGenesisTime(endBlock)
    doAssert m.hasEnoughValidators(startBlock)
    doAssert m.hasEnoughValidators(endBlock)

    var
      startBlock = startBlock
      endBlock = endBlock
      activeValidatorsCountDuringRange = startBlock.activeValidatorsCount

    while startBlock.number + 1 < endBlock.number:
      let
        MIN_GENESIS_TIME = m.cfg.MIN_GENESIS_TIME
        startBlockTime = genesis_time_from_eth1_timestamp(m.cfg, startBlock.timestamp)
        secondsPerBlock = float(endBlock.timestamp - startBlock.timestamp) /
                          float(endBlock.number - startBlock.number)
        blocksToJump = max(float(MIN_GENESIS_TIME - startBlockTime) / secondsPerBlock, 1.0)
        candidateNumber = min(endBlock.number - 1, startBlock.number + blocksToJump.uint64)
        candidateBlock = awaitWithRetries(
          rpcClient.getBlockByNumber(candidateNumber),
          web3RequestsTimeout)

      var candidateAsEth1Block = Eth1Block(hash: candidateBlock.hash.asEth2Digest,
                                           number: candidateBlock.number.uint64,
                                           timestamp: candidateBlock.timestamp.uint64)

      let candidateGenesisTime = genesis_time_from_eth1_timestamp(
        m.cfg, candidateBlock.timestamp.uint64)

      notice "Probing possible genesis block",
        `block` = candidateBlock.number.uint64,
        candidateGenesisTime

      if candidateGenesisTime < MIN_GENESIS_TIME:
        startBlock = candidateAsEth1Block
      else:
        endBlock = candidateAsEth1Block

    if endBlock.activeValidatorsCount == 0:
      endBlock.activeValidatorsCount = activeValidatorsCountDuringRange

    return endBlock

  proc waitGenesis*(m: ELManager): Future[GenesisStateRef] {.async.} =
    if m.genesisState.isNil:
      m.start()

      if m.genesisStateFut.isNil:
        m.genesisStateFut = newFuture[void]("waitGenesis")

      info "Awaiting genesis event"
      await m.genesisStateFut
      m.genesisStateFut = nil

    if m.genesisState != nil:
      return m.genesisState
    else:
      doAssert bnStatus == BeaconNodeStatus.Stopping
      return nil
