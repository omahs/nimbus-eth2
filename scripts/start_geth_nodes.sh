#!/usr/bin/env bash

set -euo pipefail

SCRIPTS_DIR="$(dirname "${BASH_SOURCE[0]}")"

source "${SCRIPTS_DIR}/geth_binaries.sh"
source "${SCRIPTS_DIR}/geth_vars.sh"

#These are used in the caller script
GETH_ENODES=()
GETH_HTTP_PORTS=()
GETH_NET_PORTS=()
GETH_WS_PORTS=()
GETH_DATA_DIRS=()

log "Using ${GETH_BINARY}"

for GETH_NUM_NODE in $(seq 1 $GETH_NUM_NODES); do
    GETH_NET_PORT=$(( GETH_NUM_NODE * GETH_PORT_OFFSET + GETH_BASE_NET_PORT ))
    GETH_HTTP_PORT=$(( GETH_NUM_NODE * GETH_PORT_OFFSET + GETH_BASE_HTTP_PORT ))
    GETH_WS_PORT=$(( GETH_NUM_NODE * GETH_PORT_OFFSET + GETH_BASE_WS_PORT ))
    GETH_AUTH_RPC_PORT=$(( GETH_NUM_NODE * GETH_PORT_OFFSET + GETH_BASE_AUTH_RPC_PORT ))
    log "Starting geth node ${GETH_NUM_NODE} on net port ${GETH_NET_PORT} HTTP port ${GETH_HTTP_PORT} WS port ${GETH_WS_PORT}"
    GETH_DATA_DIR=$(mktemp -d "${DATA_DIR}/geth-data-XXX")
    GETH_DATA_DIRS+=(${GETH_DATA_DIR})
    echo "Initializing the Geth database..."
    ${GETH_BINARY} --http --ws -http.api "engine" --datadir "${GETH_DATA_DIR}" init "${EXECUTION_GENESIS_JSON}"
    ${GETH_BINARY} \
      --ws \
      --ws.api "eth,net,engine" \
      --ws.port ${GETH_WS_PORT} \
      --http \
      --http.corsdomain '*' \
      --http.api "eth,net,engine" \
      --http.port ${GETH_HTTP_PORT} \
      --datadir "${GETH_DATA_DIR}" \
      ${DISCOVER} \
      --port ${GETH_NET_PORT} \
      --authrpc.jwtsecret "${JWT_FILE}" \
      &> "${DATA_DIR}/geth-log${GETH_NUM_NODE}.txt" &
    PIDS="${PIDS},$!"
    GETH_RETRY=0
    while :; do
        if [[ -S "${GETH_DATA_DIR}/geth.ipc" ]]; then
            echo "Geth ${GETH_NUM_NODE} started in $(( GETH_RETRY * 100 ))ms"
            break
        fi
        if (( ++GETH_RETRY >= 300 )); then
            echo "Geth ${GETH_NUM_NODE} failed to start"
            exit 1
        fi
        sleep 0.1
    done
    NODE_ID=$(${GETH_BINARY} attach --datadir "${GETH_DATA_DIR}" --exec admin.nodeInfo.enode)
    GETH_ENODES+=("${NODE_ID}")
    GETH_HTTP_PORTS+=("${GETH_HTTP_PORT}")
    GETH_NET_PORTS+=("${GETH_NET_PORT}")
    GETH_WS_PORTS+=("${GETH_WS_PORT}")
done

#Add all nodes as peers
for dir in "${GETH_DATA_DIRS[@]}"
do
    for enode in "${GETH_ENODES[@]}"
    do
      ${GETH_BINARY} attach --datadir "${dir}" --exec "admin.addPeer(${enode})"
    done
done

log "GETH HTTP Ports: ${GETH_HTTP_PORTS[*]}"
