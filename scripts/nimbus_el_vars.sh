# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

NIMBUS_ETH1_GENESIS="${NIMBUS_ETH1_GENESIS:-"${SCRIPTS_DIR}/local_sim_execution_genesis.json"}"
NIMBUS_ETH1_NUM_NODES="${NIMBUS_ETH1_NUM_NODES:-4}"
NIMBUS_ETH1_BASE_NET_PORT="${BASE_EL_NET_PORT:-40404}"
NIMBUS_ETH1_BASE_HTTP_PORT="${BASE_EL_HTTP_PORT:-9545}"
NIMBUS_ETH1_BASE_WS_PORT="${BASE_EL_WS_PORT:-9546}"
NIMBUS_ETH1_BASE_AUTH_RPC_PORT="${BASE_EL_AUTH_RPC_PORT:-9551}"
NIMBUS_ETH1_PORT_OFFSET="${EL_PORT_OFFSET:-10}"

CURL_BINARY=${CURL_BINARY:-curl}
JQ_BINARY=${JQ_BINARY:-jq}
