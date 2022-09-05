# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

GETH_NUM_NODES="${GETH_NUM_NODES:-4}"
GETH_BASE_NET_PORT="${BASE_EL_NET_PORT:-30303}"
GETH_BASE_HTTP_PORT="${BASE_EL_HTTP_PORT:-8545}"
GETH_BASE_WS_PORT="${BASE_EL_WS_PORT:-8546}"
GETH_BASE_AUTH_RPC_PORT="${BASE_EL_AUTH_RPC_PORT:-8551}"
GETH_PORT_OFFSET="${EL_PORT_OFFSET:-20}"
EXECUTION_GENESIS_JSON="${EXECUTION_GENESIS_JSON:-${SCRIPTS_DIR}/local_sim_execution_genesis.json}"
DISCOVER="--nodiscover"
