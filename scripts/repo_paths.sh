if [ -z "${REPO_PATHS_SOURCED:-}" ]; then
REPO_PATHS_SOURCED=1

SCRIPTS_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
BUILD_DIR=$(cd "$SCRIPTS_DIR/../build" &> /dev/null && pwd)

create_data_dir_for_network() {
  NETWORK_ID=$(cat "$NETWORK/genesis.json" | jq '.config.chainId')
  NETWORK_DIR="$BUILD_DIR/data/$NETWORK_ID"
  mkdir -p "$NETWORK_DIR"
  echo "$NETWORK_DIR"
}

create_jwt_token() {
  if [ ! -f "$1" ]; then
    openssl rand -hex 32 | tr -d "\n" >  "$1"
  fi
}

fi
