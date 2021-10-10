# Nimbus
# Copyright (c) 2021 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  options, stew/endians2,
  ./mocking/mock_deposits,
  ./helpers/math_helpers,
  ../beacon_chain/spec/[
    forks, helpers, state_transition, state_transition_block]

proc valid_deposit[T](state: var T) =
  const deposit_amount = MAX_EFFECTIVE_BALANCE
  let validator_index = state.validators.len
  let deposit = mockUpdateStateForNewDeposit(
                  state,
                  uint64 validator_index,
                  deposit_amount,
                  flags = {}
                )

  let pre_val_count = state.validators.len
  let pre_balance = if validator_index < pre_val_count:
                      state.balances[validator_index]
                    else:
                      0
  doAssert process_deposit(defaultRuntimeConfig, state, deposit, {}).isOk
  doAssert state.validators.len == pre_val_count + 1
  doAssert state.balances.len == pre_val_count + 1
  doAssert state.balances[validator_index] == pre_balance + deposit.data.amount
  doAssert state.validators[validator_index].effective_balance ==
    round_multiple_down(
      min(MAX_EFFECTIVE_BALANCE, state.balances[validator_index]),
      EFFECTIVE_BALANCE_INCREMENT
    )

proc getTestStates*(
    initialState: ForkedHashedBeaconState, stateFork: BeaconStateFork):
    seq[ref ForkedHashedBeaconState] =
  # Randomly generated slot numbers, with a jump to around
  # SLOTS_PER_HISTORICAL_ROOT to force wraparound of those
  # slot-based mod/increment fields.
  const stateEpochs = [
    0, 1,

    # Around minimal wraparound SLOTS_PER_HISTORICAL_ROOT wraparound
    7, 8, 9,

    # Unexceptional cases, with 2 and 3-long runs
    39, 40, 114, 115, 116, 130, 131,

    # Approaching and passing mainnet SLOTS_PER_HISTORICAL_ROOT wraparound
    255, 256, 257]

  var
    tmpState = assignClone(initialState)
    cache = StateCache()
    rewards = RewardInfo()
    cfg = defaultRuntimeConfig

  if stateFork in [forkAltair, forkMerge]:
    cfg.ALTAIR_FORK_EPOCH = 1.Epoch

  if stateFork == forkMerge:
    cfg.MERGE_FORK_EPOCH = 1.Epoch

  for i, epoch in stateEpochs:
    let slot = epoch.Epoch.compute_start_slot_at_epoch
    if getStateField(tmpState[], slot) < slot:
      doAssert process_slots(
        cfg, tmpState[], slot, cache, rewards, {})

    if i mod 3 == 0:
      if tmpState[].beaconStateFork == forkPhase0:
        valid_deposit(tmpState[].hbsPhase0.data)
      elif tmpState[].beaconStateFork == forkAltair:
        valid_deposit(tmpState[].hbsAltair.data)
      else:
        valid_deposit(tmpState[].hbsMerge.data)
    doAssert getStateField(tmpState[], slot) == slot

    if tmpState[].beaconStateFork == stateFork:
      result.add assignClone(tmpState[])