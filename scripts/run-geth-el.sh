#!/usr/bin/env bash
# Via Adrian Sutton

if [ -z "$1" ]; then
  echo "Usage: run-geth-el.sh <network-metadata-dir>"
  exit 1
fi

if [ ! -d "$1" ]; then
  echo "Please supply a valid network metadata directory"
  exit 1
fi

set -Eeu

NETWORK=$(cd "$1"; pwd)

cd $(dirname "$0")

source geth_binaries.sh
source repo_paths.sh

: ${GETH_RPC_PORT:=18550}
: ${GETH_WS_PORT:=18551}

DATA_DIR="$(create_data_dir_for_network "$NETWORK")"

JWT_TOKEN="$DATA_DIR/jwt-token"
create_jwt_token "$JWT_TOKEN"

NETWORK_ID=$(cat "$NETWORK/genesis.json" | jq '.config.chainId')

EXECUTION_BOOTNODES=""
if [[ -f "$NETWORK/el_bootnode.txt" ]]; then
  EXECUTION_BOOTNODES+=$(awk '{print $1}' "$NETWORK/el_bootnode.txt" "$NETWORK/el_bootnode.txt" | paste -s -d, -)
fi

if [[ -f "$NETWORK/el_bootnodes.txt" ]]; then
  EXECUTION_BOOTNODES+=$(awk '{print $1}' "$NETWORK/el_bootnodes.txt" "$NETWORK/el_bootnode.txt" | paste -s -d, -)
fi

GETH_DATA_DIR="$DATA_DIR/geth"
EXECUTION_GENESIS_JSON="${NETWORK}/genesis.json"

if [[ ! -d "$GETH_DATA_DIR/geth" ]]; then
  # Initialize the genesis
  $GETH_EIP_4844_BINARY --http --ws -http.api "engine" --datadir "${GETH_DATA_DIR}" init "${EXECUTION_GENESIS_JSON}"

  # Import the signing key (press enter twice for empty password)
  $GETH_EIP_4844_BINARY --http --ws -http.api "engine" --datadir "${GETH_DATA_DIR}" account import <(echo 45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8)
fi

#--password "execution/geth/passfile.txt"
#--nodekey "execution/signer.key"

$GETH_EIP_4844_BINARY \
    --http \
    --http.corsdomain="*" \
    --http.vhosts="*" \
    --http.addr=127.0.0.1 \
    --http.port="$GETH_RPC_PORT" \
    -http.api=web3,debug,engine,eth,net,txpool \
    --ws \
    --ws.addr=127.0.0.1 \
    --ws.port="$GETH_WS_PORT" \
    --ws.origins="*" \
    --ws.api=debug,eth,txpool,net,engine \
    --authrpc.jwtsecret "$JWT_TOKEN" \
    --allow-insecure-unlock \
    --datadir "${GETH_DATA_DIR}" \
    --bootnodes "${EXECUTION_BOOTNODES}" \
    --port 30308 \
    --password "" \
    --metrics \
    --unlock "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b" \
    --syncmode=full \
    --networkid $NETWORK_ID
