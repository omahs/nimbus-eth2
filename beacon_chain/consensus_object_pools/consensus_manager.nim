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
  chronicles, chronos, web3/ethtypes,
  ../spec/datatypes/base,
  ../consensus_object_pools/[blockchain_dag, block_quarantine, attestation_pool],
  ../eth1/eth1_monitor,
  ../beacon_clock

from ../spec/eth2_apis/dynamic_fee_recipients import
  DynamicFeeRecipientsStore, getDynamicFeeRecipient
from ../validators/keystore_management import
  KeymanagerHost, getSuggestedFeeRecipient
from ../validators/action_tracker import ActionTracker, getNextProposalSlot

type
  ConsensusManager* = object
    expectedSlot: Slot
    expectedBlockReceived: Future[bool]

    # Validated & Verified
    # ----------------------------------------------------------------
    dag*: ChainDAGRef
    attestationPool*: ref AttestationPool

    # Missing info
    # ----------------------------------------------------------------
    quarantine*: ref Quarantine

    # Execution layer integration
    # ----------------------------------------------------------------
    elManager*: ELManager

    # Allow determination of whether there's an upcoming proposal
    # ----------------------------------------------------------------
    actionTracker*: ActionTracker

    # Allow determination of preferred fee recipient during proposals
    # ----------------------------------------------------------------
    dynamicFeeRecipientsStore: ref DynamicFeeRecipientsStore
    validatorsDir: string
    defaultFeeRecipient: Eth1Address

    # Tracking last proposal forkchoiceUpdated payload information
    # ----------------------------------------------------------------
    optimisticHead: tuple[bid: BlockId, execution_block_hash: Eth2Digest]

# Initialization
# ------------------------------------------------------------------------------

func new*(T: type ConsensusManager,
          dag: ChainDAGRef,
          attestationPool: ref AttestationPool,
          quarantine: ref Quarantine,
          elManager: ELManager,
          actionTracker: ActionTracker,
          dynamicFeeRecipientsStore: ref DynamicFeeRecipientsStore,
          validatorsDir: string,
          defaultFeeRecipient: Eth1Address
         ): ref ConsensusManager =
  (ref ConsensusManager)(
    dag: dag,
    attestationPool: attestationPool,
    quarantine: quarantine,
    elManager: elManager,
    actionTracker: actionTracker,
    dynamicFeeRecipientsStore: dynamicFeeRecipientsStore,
    validatorsDir: validatorsDir,
    defaultFeeRecipient: defaultFeeRecipient
  )

# Consensus Management
# -----------------------------------------------------------------------------------

proc checkExpectedBlock(self: var ConsensusManager) =
  if self.expectedBlockReceived == nil:
    return

  if self.dag.head.slot < self.expectedSlot:
    return

  self.expectedBlockReceived.complete(true)
  self.expectedBlockReceived = nil # Don't keep completed futures around!

proc expectBlock*(self: var ConsensusManager, expectedSlot: Slot): Future[bool] =
  ## Return a future that will complete when a head is selected whose slot is
  ## equal or greater than the given slot, or a new expectation is created
  if self.expectedBlockReceived != nil:
    # Reset the old future to not leave it hanging.. an alternative would be to
    # cancel it, but it doesn't make any practical difference for now
    self.expectedBlockReceived.complete(false)

  let fut = newFuture[bool]("ConsensusManager.expectBlock")
  self.expectedSlot = expectedSlot
  self.expectedBlockReceived = fut

  # It might happen that by the time we're expecting a block, it might have
  # already been processed!
  self.checkExpectedBlock()

  return fut

from eth/async_utils import awaitWithTimeout
from web3/engine_api_types import
  ForkchoiceUpdatedResponse,
  PayloadExecutionStatus, PayloadStatusV1, PayloadAttributesV1

func `$`(h: BlockHash): string = $h.asEth2Digest

func shouldSyncOptimistically*(
    optimisticSlot, dagSlot, wallSlot: Slot): bool =
  ## Determine whether an optimistic execution block hash should be reported
  ## to the EL client instead of the current head as determined by fork choice.

  # Check whether optimistic head is sufficiently ahead of DAG
  const minProgress = 8 * SLOTS_PER_EPOCH  # Set arbitrarily
  if optimisticSlot < dagSlot or optimisticSlot - dagSlot < minProgress:
    return false

  # Check whether optimistic head has synced sufficiently close to wall slot
  const maxAge = 2 * SLOTS_PER_EPOCH  # Set arbitrarily
  if optimisticSlot < max(wallSlot, maxAge.Slot) - maxAge:
    return false

  true

func shouldSyncOptimistically*(self: ConsensusManager, wallSlot: Slot): bool =
  if self.optimisticHead.execution_block_hash.isZero:
    return false

  shouldSyncOptimistically(
    optimisticSlot = self.optimisticHead.bid.slot,
    dagSlot = getStateField(self.dag.headState, slot),
    wallSlot = wallSlot)

func optimisticHead*(self: ConsensusManager): BlockId =
  self.optimisticHead.bid

func optimisticExecutionPayloadHash*(self: ConsensusManager): Eth2Digest =
  self.optimisticHead.execution_block_hash

func setOptimisticHead*(
    self: var ConsensusManager,
    bid: BlockId, execution_block_hash: Eth2Digest) =
  self.optimisticHead = (bid: bid, execution_block_hash: execution_block_hash)

proc updateExecutionClientHead(self: ref ConsensusManager,
                               newHead: BeaconHead): Future[Opt[void]] {.async.} =
  let headExecutionPayloadHash = self.dag.loadExecutionBlockRoot(newHead.blck)

  if headExecutionPayloadHash.isZero:
    # Blocks without execution payloads can't be optimistic.
    self.dag.markBlockVerified(self.quarantine[], newHead.blck.root)
    return Opt[void].ok()

  # Can't use dag.head here because it hasn't been updated yet
  let (payloadExecutionStatus, latestValidHash) =
    await self.elManager.forkchoiceUpdated(
      headExecutionPayloadHash,
      newHead.safeExecutionPayloadHash,
      newHead.finalizedExecutionPayloadHash)

  case payloadExecutionStatus
  of PayloadExecutionStatus.valid:
    self.dag.markBlockVerified(self.quarantine[], newHead.blck.root)
  of PayloadExecutionStatus.invalid, PayloadExecutionStatus.invalid_block_hash:
    self.attestationPool[].forkChoice.mark_root_invalid(newHead.blck.root)
    self.quarantine[].addUnviable(newHead.blck.root)
    return Opt.none(void)
  of PayloadExecutionStatus.accepted, PayloadExecutionStatus.syncing:
    self.dag.optimisticRoots.incl newHead.blck.root

  return Opt[void].ok()

proc updateHead*(self: var ConsensusManager, newHead: BlockRef) =
  ## Trigger fork choice and update the DAG with the new head block
  ## This does not automatically prune the DAG after finalization
  ## `pruneFinalized` must be called for pruning.

  # Store the new head in the chain DAG - this may cause epochs to be
  # justified and finalized
  self.dag.updateHead(newHead, self.quarantine[])

  self.checkExpectedBlock()

proc updateHead*(self: var ConsensusManager, wallSlot: Slot) =
  ## Trigger fork choice and update the DAG with the new head block
  ## This does not automatically prune the DAG after finalization
  ## `pruneFinalized` must be called for pruning.

  # Grab the new head according to our latest attestation data
  let newHead = self.attestationPool[].selectOptimisticHead(
      wallSlot.start_beacon_time).valueOr:
    warn "Head selection failed, using previous head",
      head = shortLog(self.dag.head), wallSlot
    return

  if self.dag.loadExecutionBlockRoot(newHead.blck).isZero:
    # Blocks without execution payloads can't be optimistic.
    self.dag.markBlockVerified(self.quarantine[], newHead.blck.root)

  self.updateHead(newHead.blck)

func isSynced(dag: ChainDAGRef, wallSlot: Slot): bool =
  # This is a tweaked version of the validator_duties isSynced. TODO, refactor
  # that one so this becomes the default version, with the same information to
  # work with. For the head slot, use the DAG head regardless of what head the
  # proposer forkchoiceUpdated is using, because by the validator_duties might
  # be ready to actually propose, it's going to do so from the DAG head. Given
  # the defaultSyncHorizon, it will start triggering in time so that potential
  # discrepancies between the head here, and the head the DAG has (which might
  # not yet be updated) won't be visible.
  const defaultSyncHorizon = 50

  if dag.head.slot + defaultSyncHorizon < wallSlot:
    false
  else:
    not dag.is_optimistic(dag.head.root)

proc checkNextProposer(
    dag: ChainDAGRef, actionTracker: ActionTracker,
    dynamicFeeRecipientsStore: ref DynamicFeeRecipientsStore,
    wallSlot: Slot):
    Opt[(ValidatorIndex, ValidatorPubKey)] =
  let nextWallSlot = wallSlot + 1

  # Avoid long rewinds during syncing, when it's not going to propose. Though
  # this is preparing for a proposal on `nextWallSlot`, it can't possibly yet
  # be on said slot, so still check just `wallSlot`.
  if not dag.isSynced(wallSlot):
    return Opt.none((ValidatorIndex, ValidatorPubKey))

  let proposer = dag.getProposer(dag.head, nextWallSlot)
  if proposer.isNone():
    return Opt.none((ValidatorIndex, ValidatorPubKey))
  if  actionTracker.getNextProposalSlot(wallSlot) != nextWallSlot and
      dynamicFeeRecipientsStore[].getDynamicFeeRecipient(
        proposer.get, nextWallSlot.epoch).isNone:
    return Opt.none((ValidatorIndex, ValidatorPubKey))
  let proposerKey = dag.validatorKey(proposer.get).get().toPubKey
  Opt.some((proposer.get, proposerKey))

proc checkNextProposer*(self: ref ConsensusManager, wallSlot: Slot):
    Opt[(ValidatorIndex, ValidatorPubKey)] =
  self.dag.checkNextProposer(
    self.actionTracker, self.dynamicFeeRecipientsStore, wallSlot)

proc getFeeRecipient*(
    self: ConsensusManager, pubkey: ValidatorPubKey,
    validatorIdx: Opt[ValidatorIndex], epoch: Epoch): Eth1Address =
  let dynFeeRecipient = if validatorIdx.isSome:
    self.dynamicFeeRecipientsStore[].getDynamicFeeRecipient(
      validatorIdx.get(), epoch)
  else:
    Opt.none(Eth1Address)

  dynFeeRecipient.valueOr:
    self.validatorsDir.getSuggestedFeeRecipient(
        pubkey, self.defaultFeeRecipient).valueOr:
      # Ignore errors and use default - errors are logged in gsfr
      self.defaultFeeRecipient

from ../spec/datatypes/bellatrix import PayloadID

proc runProposalForkchoiceUpdated*(
    self: ref ConsensusManager, wallSlot: Slot) {.async.} =
  let
    nextWallSlot = wallSlot + 1
    (validatorIndex, nextProposer) = self.checkNextProposer(wallSlot).valueOr:
      return
  debug "runProposalForkchoiceUpdated: expected to be proposing next slot",
    nextWallSlot, validatorIndex, nextProposer

  # Approximately lines up with validator_duties version. Used optimistcally/
  # opportunistically, so mismatches are fine if not too frequent.
  let
    timestamp = withState(self.dag.headState):
      compute_timestamp_at_slot(forkyState.data, nextWallSlot)
    randomData = withState(self.dag.headState):
      get_randao_mix(forkyState.data, get_current_epoch(forkyState.data)).data
    feeRecipient = self[].getFeeRecipient(
      nextProposer, Opt.some(validatorIndex), nextWallSlot.epoch)
    beaconHead = self.attestationPool[].getBeaconHead(self.dag.head)
    headBlockRoot = self.dag.loadExecutionBlockRoot(beaconHead.blck)

  if headBlockRoot.isZero:
    return

  try:
    let
      safeBlockRoot = beaconHead.safeExecutionPayloadHash
      (status, _) = await self.elManager.forkchoiceUpdated(
        headBlockRoot,
        safeBlockRoot,
        beaconHead.finalizedExecutionPayloadHash,
        # TODO Use the correct PyloadAttributes type
        payloadAttributes = some PayloadAttributesV1(
          timestamp: Quantity timestamp,
          prevRandao: FixedBytes[32] randomData,
          suggestedFeeRecipient: feeRecipient))
    debug "forkchoice updated for proposal", status
  except CatchableError as err:
    error "Engine API fork-choice update failed", err = err.msg

proc updateHeadWithExecution*(
    self: ref ConsensusManager, initialNewHead: BeaconHead,
    getBeaconTimeFn: GetBeaconTimeFn) {.async.} =
  ## Trigger fork choice and update the DAG with the new head block
  ## This does not automatically prune the DAG after finalization
  ## `pruneFinalized` must be called for pruning.

  # Grab the new head according to our latest attestation data
  try:
    # Ensure dag.updateHead has most current information
    var
      attempts = 0
      newHead = initialNewHead
    while (await self.updateExecutionClientHead(newHead)).isErr:
      # This proc is called on every new block; guarantee timely return
      inc attempts
      const maxAttempts = 5
      if attempts >= maxAttempts:
        warn "updateHeadWithExecution: too many attempts to recover from invalid payload",
          attempts, maxAttempts, newHead, initialNewHead
        break

      # Select new head for next attempt
      let
        wallTime = getBeaconTimeFn()
        nextHead = self.attestationPool[].selectOptimisticHead(wallTime).valueOr:
          warn "Head selection failed after invalid block, using previous head",
            newHead, wallSlot = wallTime.slotOrZero
          break
      warn "updateHeadWithExecution: attempting to recover from invalid payload",
        attempts, maxAttempts, newHead, initialNewHead, nextHead
      newHead = nextHead

    # Store the new head in the chain DAG - this may cause epochs to be
    # justified and finalized
    self.dag.updateHead(newHead.blck, self.quarantine[])

    # If this node should propose next slot, start preparing payload. Both
    # fcUs are useful: the updateExecutionClientHead(newHead) call updates
    # the head state (including optimistic status) that self.dagUpdateHead
    # needs while runProposalForkchoiceUpdated requires RANDAO information
    # from the head state corresponding to the `newHead` block, which only
    # self.dag.updateHead(...) sets up.
    await self.runProposalForkchoiceUpdated(getBeaconTimeFn().slotOrZero)

    self[].checkExpectedBlock()
  except CatchableError as exc:
    debug "updateHeadWithExecution error",
      error = exc.msg

proc pruneStateCachesAndForkChoice*(self: var ConsensusManager) =
  ## Prune unneeded and invalidated data after finalization
  ## - the DAG state checkpoints
  ## - the DAG EpochRef
  ## - the attestation pool/fork choice

  # Cleanup DAG & fork choice if we have a finalized head
  if self.dag.needStateCachesAndForkChoicePruning():
    self.dag.pruneStateCachesDAG()
    self.attestationPool[].prune()
