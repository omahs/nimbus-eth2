#!/usr/bin/env bash

set -euo pipefail

SCRIPTS_DIR="$(dirname "${BASH_SOURCE[0]}")"

. "${SCRIPTS_DIR}/nimbus_el_vars.sh"

#These are used in the caller script
NIMBUS_ETH1_ENODES=()
NIMBUS_ETH1_HTTP_PORTS=()
NIMBUS_ETH1_NET_PORTS=()
NIMBUS_ETH1_WS_PORTS=()
NIMBUS_ETH1_RPC_PORTS=()
NIMBUS_ETH1_DATA_DIRS=()

wait_for_port() {
  for EXPONENTIAL_BACKOFF in {1..10}; do
    nc -w 1 -z $1 $2 > /dev/null && break;
    DELAY=$((2**$EXPONENTIAL_BACKOFF))
    echo "Port ${2} not yet available. Waiting ${DELAY} seconds"
    sleep $DELAY
  done
}

log "Using ${NIMBUS_ETH1_BINARY}"

if [ -d /opt/homebrew/lib ]; then
  # BEWARE
  # The recent versions of homebrew/macOS can't add the libraries
  # installed by Homebrew in the system's library search path, so
  # Nimbus will fail to load RocksDB on start-up. THe new rules in
  # macOS make it very difficult for the user to solve the problem
  # in their profile, so we add an override here as the lessed evil:
  export DYLD_LIBRARY_PATH="${DYLD_LIBRARY_PATH:-}:/opt/homebrew/lib"
  # See https://github.com/Homebrew/brew/issues/13481 for more details
fi

for NUM_NODE in $(seq 1 $NIMBUS_ETH1_NUM_NODES); do
  NIMBUS_ETH1_NET_PORT=$(( NUM_NODE * NIMBUS_ETH1_PORT_OFFSET + NIMBUS_ETH1_BASE_NET_PORT ))
  NIMBUS_ETH1_HTTP_PORT=$(( NUM_NODE * NIMBUS_ETH1_PORT_OFFSET + NIMBUS_ETH1_BASE_HTTP_PORT ))
  NIMBUS_ETH1_WS_PORT=$(( NUM_NODE * NIMBUS_ETH1_PORT_OFFSET + NIMBUS_ETH1_BASE_WS_PORT ))
  NIMBUS_ETH1_AUTH_RPC_PORT=$(( NUM_NODE * NIMBUS_ETH1_PORT_OFFSET + NIMBUS_ETH1_BASE_AUTH_RPC_PORT ))
  log "Starting nimbus EL node ${NUM_NODE} on net port ${NIMBUS_ETH1_NET_PORT} HTTP port ${NIMBUS_ETH1_HTTP_PORT} WS port ${NIMBUS_ETH1_WS_PORT}"
  NIMBUS_ETH1_DATA_DIR=$(mktemp -d "${DATA_DIR}/nimbus-eth1-data-XXXXXX")
  NIMBUS_ETH1_DATA_DIRS+=("${NIMBUS_ETH1_DATA_DIR}")

  ${NIMBUS_ETH1_BINARY} \
    --data-dir="${NIMBUS_ETH1_DATA_DIR}" \
    --custom-network="${NIMBUS_ETH1_GENESIS}" \
    --discovery=None \
    --tcp-port="${NIMBUS_ETH1_NET_PORT}"  \
    --jwt-secret="${JWT_FILE}" \
    --engine-api --engine-api-port="${NIMBUS_ETH1_AUTH_RPC_PORT}" \
    --rpc --rpc-port="${NIMBUS_ETH1_HTTP_PORT}" \
      &> "${DATA_DIR}/nimbus_eth1_log${NUM_NODE}.txt" &
  PIDS="${PIDS},$!"
done

echo "Waiting for the Nimbus ETH1 nodes to come online..."
for NUM_NODE in $(seq 1 $NIMBUS_ETH1_NUM_NODES); do
  wait_for_port localhost "${NIMBUS_ETH1_HTTP_PORT}"

  NODE_ID=$(
    "${CURL_BINARY}" -sS -X POST \
                     -H 'Content-Type: application/json' \
                     -d '{"jsonrpc":"2.0","id":"id","method":"net_nodeInfo"}' \
                     "http://localhost:${NIMBUS_ETH1_HTTP_PORT}" | "${JQ_BINARY}" .result.enode)
  log "EL Node ID" "${NODE_ID}"
  NIMBUS_ETH1_ENODES+=("${NODE_ID}")
  NIMBUS_ETH1_HTTP_PORTS+=("${NIMBUS_ETH1_HTTP_PORT}")
  NIMBUS_ETH1_NET_PORTS+=("${NIMBUS_ETH1_NET_PORT}")
  NIMBUS_ETH1_WS_PORTS+=("${NIMBUS_ETH1_WS_PORT}")
  NIMBUS_ETH1_RPC_PORTS+=("${NIMBUS_ETH1_AUTH_RPC_PORT}")
done

echo "Connect all nodes though the nimbus_addPeer RPC call..."
for enode in "${NIMBUS_ETH1_ENODES[@]}"
do
  for port in "${NIMBUS_ETH1_HTTP_PORTS[@]}"
  do
    "${CURL_BINARY}" -sS -X POST \
                     -H 'Content-Type: application/json' \
                     -d '{"jsonrpc":"2.0","id":"1","method":"nimbus_addPeer","params": ['"${enode}"']}' \
                     "http://localhost:${port}"
  done
done

echo "Nimbus ETH1 HTTP Ports: ${NIMBUS_ETH1_HTTP_PORTS[*]}"
