#!/usr/bin/env bash

# Copyright (c) 2020-2022 Status Research & Development GmbH. Licensed under
# either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

# Mostly a duplication of "tests/simulation/{start.sh,run_node.sh}", but with a focus on
# replicating testnets as closely as possible, which means following the Docker execution labyrinth.

set -euo pipefail

SCRIPTS_DIR="$(dirname "${BASH_SOURCE[0]}")"
cd "$SCRIPTS_DIR/.."
BUILD_DIR="$(pwd)/build"

VERBOSE="0"

log() {
  if [[ "${VERBOSE}" -ge "1" ]]; then
    echo "${@}"
  fi
}

# OS detection
OS="linux"
if uname | grep -qi darwin; then
  OS="macos"
elif uname | grep -qiE "mingw|msys"; then
  OS="windows"
fi

# architecture detection
ARCH="$(uname -m)"

# Created processed that will be cleaned up when the script exits
PIDS=""

####################
# argument parsing #
####################

GETOPT_BINARY="getopt"
if [[ "${OS}" == "macos" ]]; then
  GETOPT_BINARY=$(find /opt/homebrew/opt/gnu-getopt/bin/getopt /usr/local/opt/gnu-getopt/bin/getopt 2> /dev/null || true)
  [[ -f "$GETOPT_BINARY" ]] || { echo "GNU getopt not installed. Please run 'brew install gnu-getopt'. Aborting."; exit 1; }
fi

! ${GETOPT_BINARY} --test > /dev/null
if [[ ${PIPESTATUS[0]} != 4 ]]; then
  # shellcheck disable=2016
  echo '`getopt --test` failed in this environment.'
  exit 1
fi

CURL_BINARY="$(command -v curl)" || { echo "Curl not installed. Aborting."; exit 1; }
JQ_BINARY="$(command -v jq)" || { echo "Jq not installed. Aborting."; exit 1; }

OPTS="ht:n:d:g"
LONGOPTS="help,preset:,nodes:,data-dir:,remote-validators-count:,threshold:,nimbus-signer-nodes:,web3signer-nodes:,with-ganache,stop-at-epoch:,disable-htop,disable-vc,enable-payload-builder,enable-logtrace,log-level:,base-port:,base-rest-port:,base-metrics-port:,base-vc-metrics-port:,base-remote-signer-port:,base-remote-signer-metrics-port:,base-el-net-port:,base-el-http-port:,base-el-ws-port:,base-el-auth-rpc-port:,el-port-offset:,reuse-existing-data-dir,reuse-binaries,timeout:,kill-old-processes,eth2-docker-image:,lighthouse-vc-nodes:,run-geth,dl-geth,dl-nimbus-eth1,dl-nimbus-eth2,light-clients:,run-nimbus-eth1,verbose,altair-fork-epoch:,bellatrix-fork-epoch:,capella-fork-epoch:,eip4844-fork-epoch:"

# default values
BINARIES=""
NUM_NODES="10"
DATA_DIR="local_testnet_data"
USE_HTOP="1"
USE_VC="1"
USE_PAYLOAD_BUILDER="false"
: ${PAYLOAD_BUILDER_HOST:=127.0.0.1}
: ${PAYLOAD_BUILDER_PORT:=4888}
LIGHTHOUSE_VC_NODES="0"
USE_GANACHE="0"
LOG_LEVEL="DEBUG; TRACE:networking"
BASE_PORT="9000"
BASE_REMOTE_SIGNER_PORT="6000"
BASE_REMOTE_SIGNER_METRICS_PORT="6100"
BASE_METRICS_PORT="8008"
BASE_REST_PORT="7500"
BASE_VC_KEYMANAGER_PORT="8500"
BASE_VC_METRICS_PORT="9008"
BASE_EL_NET_PORT="30303"
BASE_EL_HTTP_PORT="8545"
BASE_EL_WS_PORT="8546"
BASE_EL_AUTH_RPC_PORT="8551"
EL_PORT_OFFSET="10"
: ${REUSE_EXISTING_DATA_DIR:=0}
: ${REUSE_BINARIES:=0}
: ${NIMFLAGS:=""}
ENABLE_LOGTRACE="0"
STOP_AT_EPOCH_FLAG=""
TIMEOUT_DURATION="0"
CONST_PRESET="mainnet"
KILL_OLD_PROCESSES="0"
ETH2_DOCKER_IMAGE=""
NIMBUS_SIGNER_NODES=0
REMOTE_SIGNER_THRESHOLD=1
REMOTE_VALIDATORS_COUNT=0
LC_NODES=1
ACCOUNT_PASSWORD="nimbus"
RUN_GETH="0"
DL_GETH="0"
DL_NIMBUS_ETH1="0"
DL_NIMBUS_ETH2="0"
BEACON_NODE_COMMAND="./build/nimbus_beacon_node"
WEB3_ARG=()
CLEANUP_DIRS=()
: ${ALTAIR_FORK_EPOCH:=1}
: ${BELLATRIX_FORK_EPOCH:=2}
: ${CAPELLA_FORK_EPOCH:=40}
: ${EIP4844_FORK_EPOCH:=50}
#NIMBUS EL VARS
RUN_NIMBUS_ETH1="0"
: ${NIMBUS_ETH1_BINARY:=../nimbus-eth1/build/nimbus}
: ${WEB3SIGNER_VERSION:=22.11.0}
: ${WEB3SIGNER_DIR:="${BUILD_DIR}/third-party/web3signer-${WEB3SIGNER_VERSION}"}
: ${WEB3SIGNER_BINARY:="${WEB3SIGNER_DIR}/bin/web3signer"}
WEB3SIGNER_NODES=0

EL_HTTP_PORTS=()
EL_DATA_DIRS=()
PROCS_TO_KILL=("nimbus_beacon_node" "nimbus_validator_client" "nimbus_signing_node" "nimbus_light_client")
PORTS_TO_KILL=()

print_help() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS] -- [BEACON NODE OPTIONS]
E.g.: $(basename "$0") --nodes ${NUM_NODES} --stop-at-epoch 5 --data-dir "${DATA_DIR}" # defaults
CI run: $(basename "$0") --disable-htop -- --verify-finalization

  -h, --help                  show this help message
  -n, --nodes                 number of nodes to launch (default: ${NUM_NODES})
  -g, --with-ganache          simulate a genesis event based on a deposit contract
  -s, --stop-at-epoch         stop simulation at epoch (default: infinite)
  -d, --data-dir              directory where all the node data and logs will end up
                              (default: "${DATA_DIR}")
  --preset                    Const preset to be (default: mainnet)
  --base-port                 bootstrap node's Eth2 traffic port (default: ${BASE_PORT})
  --base-rest-port            bootstrap node's REST port (default: ${BASE_REST_PORT})
  --base-metrics-port         bootstrap node's metrics port (default: ${BASE_METRICS_PORT})
  --base-vc-metrics-port      The first validator client metrics port (default: ${BASE_VC_METRICS_PORT})
  --base-remote-signer-port   first remote signer's port (default: ${BASE_REMOTE_SIGNER_PORT})
  --base-remote-signer-metrics-port first remote signer's metrics port (default: ${BASE_REMOTE_SIGNER_METRICS_PORT})
  --base-el-net-port          first EL's network traffic port (default: ${BASE_EL_NET_PORT})
  --base-el-http-port         first EL's HTTP web3 port (default: ${BASE_EL_HTTP_PORT})
  --base-el-ws-port           first EL's WebSocket web3 port (default: ${BASE_EL_WS_PORT})
  --base-el-auth-rpc-port     first EL's authenticated engine API port (default: ${BASE_EL_AUTH_RPC_PORT})
  --el-port-offset            offset to apply between ports of multiple ELs (default: ${EL_PORT_OFFSET})
  --disable-htop              don't use "htop" to see the nimbus_beacon_node processes
  --disable-vc                don't use validator client binaries for validators
                              (by default validators are split 50/50 between beacon nodes
                              and validator clients, with all beacon nodes being paired up
                              with a corresponding validator client)
  --lighthouse-vc-nodes       number of Lighthouse VC nodes (assigned before Nimbus VC nodes, default: ${LIGHTHOUSE_VC_NODES})
  --enable-logtrace           display logtrace analysis
  --log-level                 set the log level (default: "${LOG_LEVEL}")
  --reuse-existing-data-dir   instead of deleting and recreating the data dir, keep it and reuse everything we can from it
  --reuse-binaries            don't (re)build the binaries we need and don't delete them at the end (speeds up testing)
  --timeout                   timeout in seconds (default: ${TIMEOUT_DURATION} - no timeout)
  --kill-old-processes        if any process is found listening on a port we use, kill it (default: disabled)
  --eth2-docker-image         use docker image instead of compiling the beacon node
  --remote-validators-count   number of remote validators which will be generated
  --threshold                 used by a threshold secret sharing mechanism and determine how many shares are need to
                              restore signature of the original secret key
  --web3signer-nodes          number of remote web3signer nodes
  --nimbus-signer-nodes       number of remote nimbus signing nodes
  --light-clients             number of light clients
  --run-nimbus-eth1           Run nimbush-eth1 as EL
  --run-geth                  Run geth EL clients
  --dl-geth                   Download geth binary if not found
  --dl-nimbus-eth2            Download Nimbus CL binary
  --verbose                   Verbose output
EOF
}

! PARSED=$(${GETOPT_BINARY} --options=${OPTS} --longoptions=${LONGOPTS} --name "$0" -- "$@")
if [[ ${PIPESTATUS[0]} != 0 ]]; then
  # getopt has complained about wrong arguments to stdout
  exit 1
fi

# read getopt's output this way to handle the quoting right
eval set -- "$PARSED"
while true; do
  case "$1" in
    -h|--help)
      print_help
      exit
      ;;
    -n|--nodes)
      NUM_NODES="$2"
      shift 2
      ;;
    --web3signer-nodes)
      WEB3SIGNER_NODES=$2
      shift 2
      ;;
    --nimbus-signer-nodes)
      NIMBUS_SIGNER_NODES=$2
      shift 2
      ;;
    --remote-validators-count)
      REMOTE_VALIDATORS_COUNT=$2
      shift 2
      ;;
    --threshold)
      REMOTE_SIGNER_THRESHOLD=$2
      shift 2
      ;;
    -d|--data-dir)
      DATA_DIR="$2"
      shift 2
      ;;
    -g|--with-ganache)
      USE_GANACHE="1"
      shift
      ;;
    --preset)
      CONST_PRESET="$2"
      shift 2
      ;;
    --altair-fork-epoch)
      ALTAIR_FORK_EPOCH="$2"
      shift 2
      ;;
    --bellatrix-fork-epoch)
      BELLATRIX_FORK_EPOCH="$2"
      shift 2
      ;;
    --capella-fork-epoch)
      CAPELLA_FORK_EPOCH="$2"
      shift 2
      ;;
    --eip4844-fork-epoch)
      EIP4844_FORK_EPOCH="$2"
      shift 2
      ;;
    --stop-at-epoch)
      STOP_AT_EPOCH_FLAG="--stop-at-epoch=$2"
      shift 2
      ;;
    --disable-htop)
      USE_HTOP="0"
      shift
      ;;
    --disable-vc)
      USE_VC="0"
      shift
      ;;
    --enable-payload-builder)
      USE_PAYLOAD_BUILDER="true"
      shift
      ;;
    --enable-logtrace)
      ENABLE_LOGTRACE="1"
      shift
      ;;
    --log-level)
      LOG_LEVEL="$2"
      shift 2
      ;;
    --base-port)
      BASE_PORT="$2"
      shift 2
      ;;
    --base-rest-port)
      BASE_REST_PORT="$2"
      shift 2
      ;;
    --base-metrics-port)
      BASE_METRICS_PORT="$2"
      shift 2
      ;;
    --base-vc-metrics-port)
      BASE_VC_METRICS_PORT="$2"
      shift 2
      ;;
    --base-remote-signer-port)
      BASE_REMOTE_SIGNER_PORT="$2"
      shift 2
      ;;
    --base-remote-signer-metrics-port)
      BASE_REMOTE_SIGNER_METRICS_PORT="$2"
      shift 2
      ;;
    --base-el-net-port)
      BASE_EL_NET_PORT="$2"
      shift 2
      ;;
    --base-el-http-port)
      BASE_EL_HTTP_PORT="$2"
      shift 2
      ;;
    --base-el-ws-port)
      BASE_EL_WS_PORT="$2"
      shift 2
      ;;
    --base-el-auth-rpc-port)
      BASE_EL_AUTH_RPC_PORT="$2"
      shift 2
      ;;
    --el-port-offset)
      EL_PORT_OFFSET="$2"
      shift 2
      ;;
    --reuse-existing-data-dir)
      REUSE_EXISTING_DATA_DIR="1"
      shift
      ;;
    --reuse-binaries)
      REUSE_BINARIES="1"
      shift
      ;;
    --timeout)
      TIMEOUT_DURATION="$2"
      shift 2
      ;;
    --kill-old-processes)
      KILL_OLD_PROCESSES="1"
      shift
      ;;
    --eth2-docker-image)
      ETH2_DOCKER_IMAGE="$2"
      shift 2
      # TODO The validator client and light client are not being shipped with
      #      our docker images, so we must disable them:
      echo "warning: --eth-docker-image implies --disable-vc --light-clients=0"
      USE_VC="0"
      LC_NODES="0"
      ;;
    --lighthouse-vc-nodes)
      LIGHTHOUSE_VC_NODES="$2"
      shift 2
      ;;
    --light-clients)
      LC_NODES="$2"
      shift 2
      ;;
    --run-geth)
      RUN_GETH="1"
      shift
      ;;
    --dl-geth)
      DL_GETH="1"
      shift
      ;;
    --dl-nimbus-eth2)
      DL_NIMBUS_ETH2="1"
      shift
      ;;
    --run-nimbus-eth1)
      RUN_NIMBUS_ETH1="1"
      shift
      ;;
    --dl-nimbus-eth1)
      DL_NIMBUS_ETH1="1"
      shift
      ;;
    --verbose)
      VERBOSE="1"
      shift
      ;;
    --)
      shift
      break
      ;;
    *)
      echo "argument parsing error"
      print_help
      exit 1
  esac
done
if [[ -n "${ETH2_DOCKER_IMAGE}" ]]; then
  if (( USE_VC || LC_NODES )); then
    echo "invalid config: USE_VC=${USE_VC} LC_NODES=${LC_NODES}"
    false
  fi
fi

# when sourcing env.sh, it will try to execute $@, so empty it
EXTRA_ARGS="$@"
if [[ $# != 0 ]]; then
  shift $#
fi

if [[ "$REUSE_EXISTING_DATA_DIR" == "0" ]]; then
  log "Deleting ${DATA_DIR}"
  rm -rf "${DATA_DIR}"
fi

if [[ "${LIGHTHOUSE_VC_NODES}" != "0" && "${CONST_PRESET}" != "mainnet" ]]; then
  echo "The prebuilt Lighthouse binary we're using only supports mainnet. Aborting."
  exit 1
fi

scripts/makedir.sh "${DATA_DIR}"
echo x > "${DATA_DIR}/keymanager-token"

JWT_FILE="${DATA_DIR}/jwtsecret"
echo "Generating JWT file '$JWT_FILE'..."
openssl rand -hex 32 | tr -d "\n" > "${JWT_FILE}"

VALIDATORS_DIR="${DATA_DIR}/validators"
scripts/makedir.sh "${VALIDATORS_DIR}"

SECRETS_DIR="${DATA_DIR}/secrets"
scripts/makedir.sh "${SECRETS_DIR}"

USER_VALIDATORS=8
TOTAL_VALIDATORS=1024

# "Make" binary
if [[ "${OS}" == "windows" ]]; then
  MAKE="mingw32-make"
else
  MAKE="make"
fi

# number of CPU cores
if uname | grep -qi darwin; then
  NPROC="$(sysctl -n hw.logicalcpu)"
else
  NPROC="$(nproc)"
fi

if [[ "${RUN_GETH}" == "1" ]]; then
  . ./scripts/geth_vars.sh
fi

if [[ "${RUN_NIMBUS_ETH1}" == "1" ]]; then
  . ./scripts/nimbus_el_vars.sh
fi

# Kill all processes which have open ports in the array passed as parameter
kill_by_port() {
  local ports=("$@")
  for PORT in "${ports[@]}"; do
    for PID in $(lsof -n -i tcp:${PORT} -sTCP:LISTEN -t); do
      echo -n "Found old process listening on port ${PORT}, with PID ${PID}. "
      if [[ "${KILL_OLD_PROCESSES}" == "1" ]]; then
        echo "Killing it."
        kill -SIGKILL "${PID}" || true
      else
        echo "Aborting."
        exit 1
      fi
    done
  done
}

GETH_NUM_NODES="$(( NUM_NODES + LC_NODES ))"
NIMBUS_ETH1_NUM_NODES="$(( NUM_NODES + LC_NODES ))"
REMOTE_SIGNER_NODES=$(( NIMBUS_SIGNER_NODES + WEB3SIGNER_NODES ))

# kill lingering processes from a previous run
if [[ "${OS}" != "windows" ]]; then
  which lsof &>/dev/null || \
    { echo "'lsof' not installed and we need it to check for ports already in use. Aborting."; exit 1; }

  # Stop geth nodes
  if [[ "${RUN_GETH}" == "1" ]]; then
    for NUM_NODE in $(seq 1 $GETH_NUM_NODES); do
      for PORT in $(( NUM_NODE * GETH_PORT_OFFSET + GETH_BASE_NET_PORT )) \
                    $(( NUM_NODE * GETH_PORT_OFFSET + GETH_BASE_HTTP_PORT )) \
                    $(( NUM_NODE * GETH_PORT_OFFSET + GETH_BASE_WS_PORT )) \
                    $(( NUM_NODE * GETH_PORT_OFFSET + GETH_BASE_AUTH_RPC_PORT ));
      do
        PORTS_TO_KILL+=("${PORT}")
      done
    done
  fi

  # Stop Nimbus EL nodes
  if [[ "${RUN_NIMBUS_ETH1}" == "1" ]]; then
    for NUM_NODE in $(seq 1 $NIMBUS_ETH1_NUM_NODES); do
      for PORT in $(( NUM_NODE * NIMBUS_ETH1_PORT_OFFSET + NIMBUS_ETH1_BASE_NET_PORT )) \
                  $(( NUM_NODE * NIMBUS_ETH1_PORT_OFFSET + NIMBUS_ETH1_BASE_HTTP_PORT )) \
                  $(( NUM_NODE * NIMBUS_ETH1_PORT_OFFSET + NIMBUS_ETH1_BASE_WS_PORT )) \
                  $(( NUM_NODE * NIMBUS_ETH1_PORT_OFFSET + NIMBUS_ETH1_BASE_AUTH_RPC_PORT ));
      do
        PORTS_TO_KILL+=("${PORT}")
      done
    done
  fi

  # Stop Remote Signers
  for NUM_REMOTE in $(seq 1 $REMOTE_SIGNER_NODES); do
    for PORT in $(( BASE_REMOTE_SIGNER_PORT + NUM_REMOTE )) \
                $(( BASE_REMOTE_SIGNER_METRICS_PORT + NUM_REMOTE )) ; do
      PORTS_TO_KILL+=("${PORT}")
    done
  done

  # Stop Nimbus validator clients
  if [[ "${USE_VC}" == "1" ]]; then
    for NUM_NODE in $(seq 1 $NUM_NODES); do
      for PORT in $(( BASE_VC_METRICS_PORT + NUM_NODE )) \
                  $(( BASE_VC_KEYMANAGER_PORT + NUM_NODE )); do
        PORTS_TO_KILL+=("${PORT}")
      done
    done
  fi

  # Stop Nimbus CL nodes
  for NUM_NODE in $(seq 1 $NUM_NODES); do
    for PORT in $(( BASE_PORT + NUM_NODE )) $(( BASE_METRICS_PORT + NUM_NODE )) $(( BASE_REST_PORT + NUM_NODE )); do
      PORTS_TO_KILL+=("${PORT}")
    done
  done

  kill_by_port "${PORTS_TO_KILL[@]}"
fi

source "${SCRIPTS_DIR}/geth_binaries.sh"

download_web3signer() {
  if [[ ! -d "${WEB3SIGNER_DIR}" ]]; then
    log "Downloading Web3Signer binary"

    WEB3SIGNER_TARBALL="web3signer-${WEB3SIGNER_VERSION}.tar.gz"
    WEB3SIGNER_URL="https://artifacts.consensys.net/public/web3signer/raw/names/web3signer.tar.gz/versions/${WEB3SIGNER_VERSION}/${WEB3SIGNER_TARBALL}"

    mkdir -p "${WEB3SIGNER_DIR}"
    "${CURL_BINARY}" -sSL "${WEB3SIGNER_URL}" \
      | tar -xzf - --directory "${WEB3SIGNER_DIR}" --strip-components=1
  fi
}

download_nimbus_eth1() {
  if [[ ! -e "${NIMBUS_ETH1_BINARY}" ]]; then
    NIMBUS_ETH1_FULL_BINARY_VERSION=20221205_f4cacdfc
    NIMBUS_ETH1_URL="https://github.com/status-im/nimbus-simulation-binaries/raw/master/nimbus-eth1/nightly-20221205"

    case "${OS}-${ARCH}" in
      linux-amd64)
        NIMBUS_ETH1_PLATFORM=Linux_amd64
        ;;
      linux-arm64)
        NIMBUS_ETH1_PLATFORM=Linux_arm64
        ;;
      macos-amd64)
        NIMBUS_ETH1_PLATFORM=macOS_arm64
        ;;
      macos-arm64)
        NIMBUS_ETH1_PLATFORM=macOS_amd64
        ;;
      windows-amd64)
        NIMBUS_ETH1_PLATFORM=Windows_amd64
        ;;
    esac

    log "Downloading Nimbus ETH1 binary"

    NIMBUS_ETH1_TARBALL="nimbus-eth1_${NIMBUS_ETH1_PLATFORM}_${NIMBUS_ETH1_FULL_BINARY_VERSION}.tar.gz"

    "${CURL_BINARY}" -sSLO "${NIMBUS_ETH1_URL}/${NIMBUS_ETH1_TARBALL}"
    # will extract it in build/ directory
    tar -xzf "${NIMBUS_ETH1_TARBALL}" --strip-components=1
    NIMBUS_ETH1_BINARY="./build/nimbus"
  fi
}

download_nimbus_eth2() {
  if [[ ! -e "${BEACON_NODE_COMMAND}" ]]; then
    # TODO: Allow these to be overriden
    NIMBUS_ETH2_VERSION=22.11.0
    NIMBUS_ETH2_REVISION=356dd4ee
    NIMBUS_ETH2_FULL_BINARY_VERSION="${NIMBUS_ETH2_VERSION}_${NIMBUS_ETH2_REVISION}"
    NIMBUS_ETH2_URL="https://github.com/status-im/nimbus-eth2/releases/download/v${NIMBUS_ETH2_VERSION}"

    case "${OS}" in
      linux)
        NIMBUS_ETH2_TARBALL="nimbus-eth2_Linux_amd64_${NIMBUS_ETH2_FULL_BINARY_VERSION}.tar.gz"
        ;;
      macos)
        NIMBUS_ETH2_TARBALL="nimbus-eth2_macOS_amd64_${NIMBUS_ETH2_FULL_BINARY_VERSION}.tar.gz"
        ;;
      windows)
        NIMBUS_ETH2_TARBALL="nimbus-eth2_Windows_amd64_${NIMBUS_ETH2_FULL_BINARY_VERSION}.tar.gz"
        ;;
    esac

    log "Downloading Nimbus ETH2 binary"

    "${CURL_BINARY}" -sSLO "${NIMBUS_ETH2_URL}/${NIMBUS_ETH2_TARBALL}"
    # will extract it in build/ directory
    tar -xzf "${NIMBUS_ETH2_TARBALL}" --strip-components=1
    REUSE_BINARIES=1
  fi
}

if [[ "${RUN_GETH}" == "1" ]]; then
  if [[ ! -e "${GETH_BINARY}" ]]; then
    if [[ "${DL_GETH}" == "1" ]]; then
      log "Downloading geth ..."
      download_geth_eip_4844
    else
      echo "Missing geth executable"
      exit 1
    fi
  fi

  log "Starting ${GETH_NUM_NODES} Geth Nodes ..."
  . "./scripts/start_geth_nodes.sh"
  EL_HTTP_PORTS+=("${GETH_HTTP_PORTS[@]}")
  EL_DATA_DIRS+=("${GETH_DATA_DIRS[@]}")
  PROCS_TO_KILL+=("${GETH_BINARY}")
  CLEANUP_DIRS+=("${GETH_DATA_DIRS[@]}")
fi

if [[ "${RUN_NIMBUS_ETH1}" == "1" ]]; then
  if [[ "${DL_NIMBUS_ETH1}" == "1" ]]; then
    log "Downloading Nimbus EL"
    download_nimbus_eth1
  fi

  if [[ ! -e "${NIMBUS_ETH1_BINARY}" ]]; then
    echo "Missing nimbus EL executable"
    exit 1
  fi

  . "./scripts/start_nimbus_el_nodes.sh"
  EL_HTTP_PORTS+=("${NIMBUS_ETH1_HTTP_PORTS[@]}")
  EL_DATA_DIRS+=("${NIMBUS_ETH1_DATA_DIRS[@]}")
  PROCS_TO_KILL+=("${NIMBUS_ETH1_BINARY}")
  CLEANUP_DIRS+=("${NIMBUS_ETH1_DATA_DIRS[@]}")
fi

# Download the Lighthouse binary.
LH_VERSION="2.1.3"
LH_ARCH="${ARCH}"
if [[ "${LH_ARCH}" == "arm64" ]]; then
  LH_ARCH="aarch64"
fi

case "${OS}" in
  linux)
    LH_TARBALL="lighthouse-v${LH_VERSION}-${LH_ARCH}-unknown-linux-gnu-portable.tar.gz"
    ;;
  macos)
    LH_TARBALL="lighthouse-v${LH_VERSION}-${LH_ARCH}-apple-darwin-portable.tar.gz"
    ;;
  windows)
    LH_TARBALL="lighthouse-v${LH_VERSION}-${LH_ARCH}-windows-portable.tar.gz"
    ;;
esac
LH_URL="https://github.com/sigp/lighthouse/releases/download/v${LH_VERSION}/${LH_TARBALL}"
LH_BINARY="lighthouse-${LH_VERSION}"

if [[ "${USE_VC}" == "1" && "${LIGHTHOUSE_VC_NODES}" != "0" && ! -e "build/${LH_BINARY}" ]]; then
  echo "Downloading Lighthouse binary"
  pushd "build" >/dev/null
  "${CURL_BINARY}" -sSLO "${LH_URL}"
  tar -xzf "${LH_TARBALL}" # contains just one file named "lighthouse"
  rm lighthouse-* # deletes both the tarball and old binary versions
  mv lighthouse "${LH_BINARY}"
  popd >/dev/null
fi


# Don't build binaries if we are downloading them
if [[ "${DL_NIMBUS_ETH2}" != "1" ]]; then
  # Build the binaries
  BINARIES="deposit_contract"

  if [[ "$NIMBUS_SIGNER_NODES" -gt "0" ]]; then
    BINARIES="${BINARIES} nimbus_signing_node"
  fi

  if [[ "${USE_VC}" == "1" ]]; then
    BINARIES="${BINARIES} nimbus_validator_client"
  fi

  if [[ "$LC_NODES" -ge "1" ]]; then
    BINARIES="${BINARIES} nimbus_light_client"
  fi

  if [[ "$ENABLE_LOGTRACE" == "1" ]]; then
    BINARIES="${BINARIES} logtrace"
  fi

  BINARIES="${BINARIES} nimbus_beacon_node"
fi

if [[ "$WEB3SIGNER_NODES" -gt "0" ]]; then
  download_web3signer
fi

if [[ "$WEB3SIGNER_NODES" -gt "0" && "$NIMBUS_SIGNER_NODES" -gt "0" ]]; then
  echo "You can use either --web3signer-nodes or --nimbus-signer-nodes, but not together"
  exit 1
fi

if [[ -n "${ETH2_DOCKER_IMAGE}" ]]; then
  DATA_DIR_FULL_PATH="$(cd "${DATA_DIR}"; pwd)"
  # CONTAINER_DATA_DIR must be used everywhere where paths are supplied to BEACON_NODE_COMMAND executions.
  # We'll use the CONTAINER_ prefix throughout the file to indicate such paths.
  CONTAINER_DATA_DIR="/home/user/nimbus-eth2/testnet"
  BEACON_NODE_COMMAND="docker run -v /etc/passwd:/etc/passwd -u $(id -u):$(id -g) --net=host -v ${DATA_DIR_FULL_PATH}:${CONTAINER_DATA_DIR}:rw $ETH2_DOCKER_IMAGE"
else
  # When docker is not used CONTAINER_DATA_DIR is just an alias for DATA_DIR
  CONTAINER_DATA_DIR="${DATA_DIR}"
  if [[ "${DL_NIMBUS_ETH2}" == "1" ]]; then
    log "Downloading nimbus_eth2"
    download_nimbus_eth2
    BINARIES=""
  fi
fi

BINARIES_MISSING="0"
for BINARY in ${BINARIES}; do
  if [[ ! -e "build/${BINARY}" ]]; then
    log "Missing binay build/${BINARY}"
    BINARIES_MISSING="1"
    break
  fi
done

if [[ "${REUSE_BINARIES}" == "0" || "${BINARIES_MISSING}" == "1" ]]; then
  if [[ "${DL_NIMBUS_ETH2}" == "0" ]]; then
    log "Rebuilding binaries ${BINARIES}"
    ${MAKE} -j ${NPROC} LOG_LEVEL=TRACE NIMFLAGS="${NIMFLAGS} -d:local_testnet -d:const_preset=${CONST_PRESET}" ${BINARIES}
  fi
fi

# Kill child processes on Ctrl-C/SIGTERM/exit, passing the PID of this shell
# instance as the parent and the target process name as a pattern to the
# "pkill" command.
cleanup() {
  log "Cleaning up"

  for proc in "${PROCS_TO_KILL[@]}"
  do
    pkill -f -P $$ "${proc}" || true
  done

  sleep 2

  for proc in "${PROCS_TO_KILL[@]}"
  do
    pkill -SIGKILL -f -P $$ "${proc}" || true
  done

  # Delete all binaries we just built, because these are unusable outside this
  # local testnet.
  if [[ "${REUSE_BINARIES}" == "0" ]]; then
    for BINARY in ${BINARIES}; do
      rm -f build/${BINARY}
    done
  fi

  if [[ -n "$ETH2_DOCKER_IMAGE" ]]; then
    docker rm $(docker stop $(docker ps -a -q --filter ancestor=$ETH2_DOCKER_IMAGE --format="{{.ID}}"))
  fi

  if [ ${#CLEANUP_DIRS[@]} -ne 0 ]; then # check if the array is empty
    for dir in "${CLEANUP_DIRS[@]}"
    do
      log "Deleting ${dir}"
      rm -rf "${dir}"
    done
  fi
}

trap 'cleanup' SIGINT SIGTERM EXIT

# timeout - implemented with a background job
timeout_reached() {
  echo -e "\nTimeout reached. Aborting.\n"
  cleanup
}
trap 'timeout_reached' SIGALRM

if [[ "${TIMEOUT_DURATION}" != "0" ]]; then
  export PARENT_PID=$$
  ( sleep ${TIMEOUT_DURATION} && kill -ALRM ${PARENT_PID} ) 2>/dev/null & WATCHER_PID=$!
fi

REMOTE_URLS=""

for NUM_REMOTE in $(seq 1 $REMOTE_SIGNER_NODES); do
  REMOTE_PORT=$(( BASE_REMOTE_SIGNER_PORT + NUM_REMOTE ))
  REMOTE_URLS="${REMOTE_URLS} --remote-signer=http://127.0.0.1:${REMOTE_PORT}"
done

# deposit and testnet creation
BOOTSTRAP_TIMEOUT=30 # in seconds
RUNTIME_CONFIG_FILE="${DATA_DIR}/config.yaml"
NUM_JOBS=${NUM_NODES}

DEPOSITS_FILE="${DATA_DIR}/deposits.json"
CONTAINER_DEPOSITS_FILE="${CONTAINER_DATA_DIR}/deposits.json"

if [[ "$REUSE_EXISTING_DATA_DIR" == "0" ]]; then
echo ./build/deposit_contract generateSimulationDeposits \
    --count=${TOTAL_VALIDATORS} \
    --out-validators-dir="${VALIDATORS_DIR}" \
    --out-secrets-dir="${SECRETS_DIR}" \
    --out-deposits-file="${DEPOSITS_FILE}" \
    --threshold=${REMOTE_SIGNER_THRESHOLD} \
    --remote-validators-count=${REMOTE_VALIDATORS_COUNT} \
    ${REMOTE_URLS}
  ./build/deposit_contract generateSimulationDeposits \
    --count=${TOTAL_VALIDATORS} \
    --out-validators-dir="${VALIDATORS_DIR}" \
    --out-secrets-dir="${SECRETS_DIR}" \
    --out-deposits-file="${DEPOSITS_FILE}" \
    --threshold=${REMOTE_SIGNER_THRESHOLD} \
    --remote-validators-count=${REMOTE_VALIDATORS_COUNT} \
    ${REMOTE_URLS}
fi

if [[ $USE_GANACHE == "0" ]]; then
  GENESIS_OFFSET=30
  BOOTSTRAP_IP="127.0.0.1"

  $BEACON_NODE_COMMAND createTestnet \
    --data-dir="${CONTAINER_DATA_DIR}" \
    --deposits-file="${CONTAINER_DEPOSITS_FILE}" \
    --total-validators=${TOTAL_VALIDATORS} \
    --output-genesis="${CONTAINER_DATA_DIR}/genesis.ssz" \
    --output-bootstrap-file="${CONTAINER_DATA_DIR}/bootstrap_nodes.txt" \
    --bootstrap-address=${BOOTSTRAP_IP} \
    --bootstrap-port=${BASE_PORT} \
    --netkey-file=network_key.json \
    --insecure-netkey-password=true \
    --genesis-offset=${GENESIS_OFFSET} # Delay in seconds

  DEPOSIT_CONTRACT_ADDRESS="0x4242424242424242424242424242424242424242"
  DEPOSIT_CONTRACT_BLOCK=0
else
  echo "Launching ganache"
  ganache-cli --blockTime 17 --gasLimit 100000000 -e 100000 --verbose > "${DATA_DIR}/log_ganache.txt" 2>&1 &
  PIDS="${PIDS},$!"

  WEB3_ARG=("--web3-url=ws://localhost:8545")

  echo "Deploying deposit contract"
  DEPLOY_CMD_OUTPUT=$(./build/deposit_contract deploy $WEB3_ARG)
  # https://stackoverflow.com/questions/918886/how-do-i-split-a-string-on-a-delimiter-in-bash
  OUTPUT_PIECES=(${DEPLOY_CMD_OUTPUT//;/ })
  DEPOSIT_CONTRACT_ADDRESS=${OUTPUT_PIECES[0]}
  DEPOSIT_CONTRACT_BLOCK=${OUTPUT_PIECES[1]}

  echo Contract deployed at "$DEPOSIT_CONTRACT_ADDRESS":"$DEPOSIT_CONTRACT_BLOCK"

  MIN_DELAY=1
  MAX_DELAY=5

  BOOTSTRAP_TIMEOUT=$(( MAX_DELAY * TOTAL_VALIDATORS ))

  ./build/deposit_contract sendDeposits \
    --deposits-file="${DEPOSITS_FILE}" \
    --min-delay=$MIN_DELAY --max-delay=$MAX_DELAY \
    "${WEB3_ARG[@]}" \
    --deposit-contract=${DEPOSIT_CONTRACT_ADDRESS} > "${DATA_DIR}/log_deposit_maker.txt" 2>&1 &

  PIDS="${PIDS},$!"
fi

./scripts/make_prometheus_config.sh \
    --nodes ${NUM_NODES} \
    --base-metrics-port ${BASE_METRICS_PORT} \
    --config-file "${DATA_DIR}/prometheus.yml" || true # TODO: this currently fails on macOS,
                                                       # but it can be considered non-critical

cp "$SCRIPTS_DIR/$CONST_PRESET-non-overriden-config.yaml" "$RUNTIME_CONFIG_FILE"
# TODO the runtime config file should be used during deposit generation as well!
echo Wrote $RUNTIME_CONFIG_FILE:
tee -a "$RUNTIME_CONFIG_FILE" <<EOF
PRESET_BASE: ${CONST_PRESET}
MIN_GENESIS_ACTIVE_VALIDATOR_COUNT: ${TOTAL_VALIDATORS}
MIN_GENESIS_TIME: 0
GENESIS_DELAY: 10
DEPOSIT_CONTRACT_ADDRESS: ${DEPOSIT_CONTRACT_ADDRESS}
ETH1_FOLLOW_DISTANCE: 1
ALTAIR_FORK_EPOCH: ${ALTAIR_FORK_EPOCH}
BELLATRIX_FORK_EPOCH: ${BELLATRIX_FORK_EPOCH}
CAPELLA_FORK_EPOCH: ${CAPELLA_FORK_EPOCH}
EIP4844_FORK_EPOCH: ${EIP4844_FORK_EPOCH}
TERMINAL_TOTAL_DIFFICULTY: 0
EOF

echo $DEPOSIT_CONTRACT_BLOCK > "${DATA_DIR}/deposit_contract_block.txt" 

# TODO
# This value is effectively derived from the genesis.json file
# Automate the process of specifying it here.
#
# One way to obtain it is by calling eth_getBlockByNumber immediately after
# initialising the EL client
#
# curl -X POST \
#      -H 'Content-Type: application/json' \
#      --data '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["latest", true],"id":1}' \
#      http://localhost:6307
#
# We can also use this to make sure that Nimbus and the other clients agree on the handling of the genesis file
#
echo 0xe4b24524c45a45b4727c8929d7305e64095f65749e2dcad665b8ef8c654b4842 > "${DATA_DIR}/deposit_contract_block_hash.txt"

if [[ "${LIGHTHOUSE_VC_NODES}" != "0" ]]; then
  # I don't know what this is, but Lighthouse wants it, so we recreate it from
  # Lighthouse's own local testnet.
  echo $DEPOSIT_CONTRACT_BLOCK > "${DATA_DIR}/deploy_block.txt"
fi

dump_logs() {
  LOG_LINES=20
  for LOG in "${DATA_DIR}"/log*.txt; do
    echo "Last ${LOG_LINES} lines of ${LOG}:"
    tail -n ${LOG_LINES} "${LOG}"
    echo "======"
  done
}

dump_logtrace() {
  if [[ "$ENABLE_LOGTRACE" == "1" ]]; then
    find "${DATA_DIR}" -maxdepth 1 -type f -regex '.*/log[0-9]+.txt' | sed -e"s/${DATA_DIR}\//--nodes=/" | sort | xargs ./build/logtrace localSimChecks --log-dir="${DATA_DIR}" --const-preset=${CONST_PRESET} || true
  fi
}

NODES_WITH_VALIDATORS=${NODES_WITH_VALIDATORS:-$NUM_NODES}
BOOTSTRAP_NODE=1
SYSTEM_VALIDATORS=$(( TOTAL_VALIDATORS - USER_VALIDATORS ))
VALIDATORS_PER_NODE=$(( SYSTEM_VALIDATORS / NODES_WITH_VALIDATORS ))
if [[ "${USE_VC}" == "1" ]]; then
  # if using validator client binaries in addition to beacon nodes we will
  # split the keys for this instance in half between the BN and the VC
  # and the validators for the BNs will be from the first half of all validators
  VALIDATORS_PER_NODE=$(( VALIDATORS_PER_NODE / 2 ))
  NUM_JOBS=$(( NUM_JOBS * 2 ))
fi

if [[ "$REMOTE_SIGNER_NODES" -ge "0" ]]; then
  NUM_JOBS=$(( NUM_JOBS + REMOTE_SIGNER_NODES ))
fi

if [[ "$LC_NODES" -ge "1" ]]; then
  NUM_JOBS=$(( NUM_JOBS + LC_NODES ))
fi

if [[ "${RUN_GETH}" == "1" ]]; then
  NUM_JOBS=$(( NUM_JOBS + GETH_NUM_NODES ))
fi

if [[ "${RUN_NIMBUS_ETH1}" == "1" ]]; then
  NUM_JOBS=$(( NUM_JOBS + NIMBUS_ETH1_NUM_NODES ))
fi

VALIDATORS_PER_VALIDATOR=$(( (SYSTEM_VALIDATORS / NODES_WITH_VALIDATORS) / 2 ))
VALIDATOR_OFFSET=$(( SYSTEM_VALIDATORS / 2 ))

BOOTSTRAP_ENR="${DATA_DIR}/node${BOOTSTRAP_NODE}/beacon_node.enr"
CONTAINER_BOOTSTRAP_ENR="${CONTAINER_DATA_DIR}/node${BOOTSTRAP_NODE}/beacon_node.enr"

CONTAINER_NETWORK_KEYFILE="network_key.json"

for NUM_NODE in $(seq 1 $NUM_NODES); do
  # Copy validators to individual nodes.
  # The first $NODES_WITH_VALIDATORS nodes split them equally between them,
  # after skipping the first $USER_VALIDATORS.
  NODE_DATA_DIR="${DATA_DIR}/node${NUM_NODE}"
  rm -rf "${NODE_DATA_DIR}"
  scripts/makedir.sh "${NODE_DATA_DIR}" 2>&1
  scripts/makedir.sh "${NODE_DATA_DIR}/validators" 2>&1
  scripts/makedir.sh "${NODE_DATA_DIR}/secrets" 2>&1

  if [[ $NUM_NODE -le $NODES_WITH_VALIDATORS ]]; then
    if [[ "${USE_VC}" == "1" ]]; then
      VALIDATOR_DATA_DIR="${DATA_DIR}/validator${NUM_NODE}"
      rm -rf "${VALIDATOR_DATA_DIR}"
      scripts/makedir.sh "${VALIDATOR_DATA_DIR}" 2>&1
      scripts/makedir.sh "${VALIDATOR_DATA_DIR}/validators" 2>&1
      scripts/makedir.sh "${VALIDATOR_DATA_DIR}/secrets" 2>&1
      for VALIDATOR in $(ls "${VALIDATORS_DIR}" | tail -n +$(( USER_VALIDATORS + (VALIDATORS_PER_VALIDATOR * (NUM_NODE - 1)) + 1 + VALIDATOR_OFFSET )) | head -n $VALIDATORS_PER_VALIDATOR); do
        cp -a "${VALIDATORS_DIR}/${VALIDATOR}" "${VALIDATOR_DATA_DIR}/validators/" 2>&1
        # Remote validators won't have a secret file
        if [ -f "${SECRETS_DIR}/${VALIDATOR}" ]; then
          cp -a "${SECRETS_DIR}/${VALIDATOR}" "${VALIDATOR_DATA_DIR}/secrets/" 2>&1
        fi
      done
      if [[ "${OS}" == "Windows_NT" ]]; then
        find "${VALIDATOR_DATA_DIR}" -type f \( -iname "*.json" -o ! -iname "*.*" \) -exec icacls "{}" /inheritance:r /grant:r ${USERDOMAIN}\\${USERNAME}:\(F\) \;
      fi
    fi
    for VALIDATOR in $(ls "${VALIDATORS_DIR}" | tail -n +$(( USER_VALIDATORS + (VALIDATORS_PER_NODE * (NUM_NODE - 1)) + 1 )) | head -n $VALIDATORS_PER_NODE); do
      cp -a "${VALIDATORS_DIR}/${VALIDATOR}" "${NODE_DATA_DIR}/validators/" 2>&1
      if [[ -f "${VALIDATORS_DIR}/${VALIDATOR}/keystore.json" ]]; then
        # Only remote key stores doesn't have a secret
        cp -a "${SECRETS_DIR}/${VALIDATOR}" "${NODE_DATA_DIR}/secrets/" 2>&1
      fi
    done
    if [[ "${OS}" == "Windows_NT" ]]; then
      find "${NODE_DATA_DIR}" -type f \( -iname "*.json" -o ! -iname "*.*" \) -exec icacls "{}" /inheritance:r /grant:r ${USERDOMAIN}\\${USERNAME}:\(F\) \;
    fi
  fi
done
for NUM_LC in $(seq 1 $LC_NODES); do
  LC_DATA_DIR="${DATA_DIR}/lc${NUM_LC}"
  rm -rf "${LC_DATA_DIR}"
  scripts/makedir.sh "${LC_DATA_DIR}" 2>&1
done

CLI_CONF_FILE="$CONTAINER_DATA_DIR/config.toml"

cat > "$CLI_CONF_FILE" <<END_CLI_CONFIG
non-interactive = true
nat = "extip:127.0.0.1"
network = "${CONTAINER_DATA_DIR}"
log-level = "${LOG_LEVEL}"
log-format = "json"
rest = true
rest-address = "127.0.0.1"
metrics = true
metrics-address = "127.0.0.1"
END_CLI_CONFIG

# https://ss64.com/osx/seq.html documents that at macOS seq(1) counts backwards
# as probably do some others
if ((NIMBUS_SIGNER_NODES > 0)); then
  launch_nimbus_signing_node() {
    SIGNING_NODE_IDX=$1
    ./build/nimbus_signing_node \
      --validators-dir="${DATA_DIR}/validators_shares/${SIGNING_NODE_IDX}" \
      --secrets-dir="${DATA_DIR}/secrets_shares/${SIGNING_NODE_IDX}" \
      --bind-port=$(( BASE_REMOTE_SIGNER_PORT + SIGNING_NODE_IDX - 1 ))
    echo "Signing not exited with code $?"
  }

  for NUM_REMOTE in $(seq 1 $NIMBUS_SIGNER_NODES); do
    # TODO find some way for this and other background-launched processes to
    # still participate in set -e, ideally
    launch_nimbus_signing_node $NUM_REMOTE > "${DATA_DIR}/log_nimbus_signing_node_${NUM_REMOTE}.txt" &
    PIDS="${PIDS},$!"
  done
fi

if ((WEB3SIGNER_NODES > 0)); then
  if ! command javac > /dev/null || ! javac -version > /dev/null; then
    # On macOS, homebrew doesn't make java available in your PATH by default.
    # Instead, macOS ships with a stub executable that displays a message that
    # Java is not installed (javac -version exits with an error code 1).
    # If the user is running under these default settings, but a homebrew
    # installation is disovered, we are happy to use it just in this script:
    if [[ -d /opt/homebrew/opt/openjdk/bin ]]; then
      export PATH="/opt/homebrew/opt/openjdk/bin:$PATH"
    fi
  fi

  launch_web3signer() {
    WEB3SIGNER_NODE_IDX=$1

    local secrets_dir="${DATA_DIR}/secrets_shares/${WEB3SIGNER_NODE_IDX}"
    local keystores_dir="${DATA_DIR}/validators_shares/${WEB3SIGNER_NODE_IDX}"

    # We re-arrange the keystore files to match the layout expected by the Web3Signer
    # TODO generateSimulationDeposits can be refactored to produce the right layout from the start
    for validator_pubkey in $(ls "$secrets_dir")
    do
      mv "$secrets_dir/$validator_pubkey" "$secrets_dir/$validator_pubkey.txt"
      mv "$keystores_dir/$validator_pubkey/keystore.json" "$keystores_dir/$validator_pubkey.json"
    done

    # still participate in set -e, ideally
    # TODO find some way for this and other background-launched processes to
    "${WEB3SIGNER_BINARY}" \
      --http-listen-port=$(( BASE_REMOTE_SIGNER_PORT + WEB3SIGNER_NODE_IDX - 1 )) \
      --logging=DEBUG \
      --metrics-enabled=true \
      --metrics-port=$(( BASE_REMOTE_SIGNER_METRICS_PORT + WEB3SIGNER_NODE_IDX - 1 )) \
      eth2 \
      --slashing-protection-enabled=false \
      --keystores-passwords-path="${secrets_dir}" \
      --keystores-path="${keystores_dir}" \
      --network="${RUNTIME_CONFIG_FILE}"

    echo "Web3Signer exited with code $?"
  }

  for NUM_REMOTE in $(seq 1 $WEB3SIGNER_NODES); do
    launch_web3signer $NUM_REMOTE > "${DATA_DIR}/log_web3signer_${NUM_REMOTE}.txt" &
    PIDS="${PIDS},$!"
  done
fi

# give each node time to load keys
sleep 10

for NUM_NODE in $(seq 1 $NUM_NODES); do
  NODE_DATA_DIR="${DATA_DIR}/node${NUM_NODE}"
  CONTAINER_NODE_DATA_DIR="${CONTAINER_DATA_DIR}/node${NUM_NODE}"
  VALIDATOR_DATA_DIR="${DATA_DIR}/validator${NUM_NODE}"
  if [[ ${NUM_NODE} == ${BOOTSTRAP_NODE} ]]; then
    # Due to star topology, the bootstrap node must relay all attestations,
    # even if it itself is not interested. --subscribe-all-subnets could be
    # removed by switching to a fully-connected topology.
    BOOTSTRAP_ARG="--netkey-file=${CONTAINER_NETWORK_KEYFILE} --insecure-netkey-password=true --subscribe-all-subnets"
  else
    BOOTSTRAP_ARG="--bootstrap-file=${CONTAINER_BOOTSTRAP_ENR}"

    if [[ "${CONST_PRESET}" == "minimal" ]]; then
      # The fast epoch and slot times in the minimal config might cause the
      # mesh to break down due to re-subscriptions happening within the prune
      # backoff time
      BOOTSTRAP_ARG="${BOOTSTRAP_ARG} --subscribe-all-subnets"
    fi

    # Wait for the master node to write out its address file
    START_TIMESTAMP=$(date +%s)
    while [[ ! -f "${BOOTSTRAP_ENR}" ]]; do
      sleep 0.1
      NOW_TIMESTAMP=$(date +%s)
      if [[ "$(( NOW_TIMESTAMP - START_TIMESTAMP - GENESIS_OFFSET ))" -ge "$BOOTSTRAP_TIMEOUT" ]]; then
        echo "Bootstrap node failed to start in ${BOOTSTRAP_TIMEOUT} seconds. Aborting."
        dump_logs
        exit 1
      fi
    done
  fi

  WEB3_ARG=()
  if [ "${RUN_NIMBUS_ETH1}" == "1" ]; then
    WEB3_ARG+=("--web3-url=http://127.0.0.1:${NIMBUS_ETH1_RPC_PORTS[$(( NUM_NODE - 1 ))]}")
  fi

  if [ "${RUN_GETH}" == "1" ]; then
    WEB3_ARG+=("--web3-url=http://127.0.0.1:${GETH_HTTP_PORTS[$((NUM_NODE - 1))]}")
  fi

  if [ ${#WEB3_ARG[@]} -eq 0 ]; then # check if the array is empty
    WEB3_ARG=("--require-engine-api-in-bellatrix=no")
  fi

  # We enabled the keymanager on half of the nodes in order
  # to make sure that the client can work without it.
  KEYMANAGER_FLAG=""
  if [ $((NUM_NODE % 2)) -eq 0 ]; then
    KEYMANAGER_FLAG="--keymanager"
  fi

  ${BEACON_NODE_COMMAND} \
    --config-file="${CLI_CONF_FILE}" \
    --tcp-port=$(( BASE_PORT + NUM_NODE - 1 )) \
    --udp-port=$(( BASE_PORT + NUM_NODE - 1 )) \
    --max-peers=$(( NUM_NODES + LC_NODES - 1 )) \
    --data-dir="${CONTAINER_NODE_DATA_DIR}" \
    ${BOOTSTRAP_ARG} \
    --jwt-secret=${JWT_FILE} \
    "${WEB3_ARG[@]}" \
    --payload-builder=${USE_PAYLOAD_BUILDER} \
    --payload-builder-url="http://${PAYLOAD_BUILDER_HOST}:${PAYLOAD_BUILDER_PORT}" \
    --light-client-data-serve=on \
    --light-client-data-import-mode=full \
    --light-client-data-max-periods=999999 \
    ${STOP_AT_EPOCH_FLAG} \
    ${KEYMANAGER_FLAG} \
    --keymanager-token-file="${DATA_DIR}/keymanager-token" \
    --rest-port="$(( BASE_REST_PORT + NUM_NODE - 1 ))" \
    --metrics-port="$(( BASE_METRICS_PORT + NUM_NODE - 1 ))" \
    ${EXTRA_ARGS} \
    &> "${DATA_DIR}/log${NUM_NODE}.txt" &

  PIDS="${PIDS},$!"

  if [[ "${USE_VC}" == "1" ]]; then
    if [[ "${LIGHTHOUSE_VC_NODES}" -ge "${NUM_NODE}" ]]; then
      # Lighthouse needs a different keystore filename for its auto-discovery process.
      for D in "${VALIDATOR_DATA_DIR}/validators"/0x*; do
        if [[ -e "${D}/keystore.json" ]]; then
          mv "${D}/keystore.json" "${D}/voting-keystore.json"
        fi
      done

      ./build/${LH_BINARY} vc \
        --debug-level "debug" \
        --logfile-max-number 0 \
        --log-format "JSON" \
        --validators-dir "${VALIDATOR_DATA_DIR}" \
        --secrets-dir "${VALIDATOR_DATA_DIR}/secrets" \
        --beacon-nodes "http://127.0.0.1:$((BASE_REST_PORT + NUM_NODE))" \
        --testnet-dir "${DATA_DIR}" \
        --init-slashing-protection \
        &> "${DATA_DIR}/log_val${NUM_NODE}.txt" &
      # No "--stop-at-epoch" equivalent here, so we let these VC processes be
      # killed the ugly way, when the script exits.
    else
      ./build/nimbus_validator_client \
        --log-level="${LOG_LEVEL}" \
        ${STOP_AT_EPOCH_FLAG} \
        --data-dir="${VALIDATOR_DATA_DIR}" \
        --metrics \
        --metrics-port=$(( BASE_VC_METRICS_PORT + NUM_NODE - 1 )) \
        --payload-builder=${USE_PAYLOAD_BUILDER} \
        ${KEYMANAGER_FLAG} \
        --keymanager-port=$(( BASE_VC_KEYMANAGER_PORT + NUM_NODE - 1 )) \
        --keymanager-token-file="${DATA_DIR}/keymanager-token" \
        --beacon-node="http://127.0.0.1:$(( BASE_REST_PORT + NUM_NODE - 1 ))" \
        &> "${DATA_DIR}/log_val${NUM_NODE}.txt" &
      PIDS="${PIDS},$!"
    fi
  fi
done

# light clients
if [ "$LC_NODES" -ge "1" ]; then
  echo "Waiting for Altair finalization"
  while :; do
    BN_ALTAIR_FORK_EPOCH="$(
      "${CURL_BINARY}" -s "http://localhost:${BASE_REST_PORT}/eth/v1/config/spec" | \
        "${JQ_BINARY}" -r '.data.ALTAIR_FORK_EPOCH')"
    if [ "${BN_ALTAIR_FORK_EPOCH}" -eq "${BN_ALTAIR_FORK_EPOCH}" ]; then # check for number
      break
    fi
    echo "ALTAIR_FORK_EPOCH: ${BN_ALTAIR_FORK_EPOCH}"
    sleep 1
  done
  while :; do
    CURRENT_FORK_EPOCH="$(
      "${CURL_BINARY}" -s "http://localhost:${BASE_REST_PORT}/eth/v1/beacon/states/finalized/fork" | \
      "${JQ_BINARY}" -r '.data.epoch')"
    if [ "${CURRENT_FORK_EPOCH}" -ge "${BN_ALTAIR_FORK_EPOCH}" ]; then
      break
    fi
    sleep 1
  done

  log "After ALTAIR_FORK_EPOCH"

  echo "Altair finalized, launching $LC_NODES light client(s)"
  LC_BOOTSTRAP_NODE="$(
    "${CURL_BINARY}" -s "http://localhost:${BASE_REST_PORT}/eth/v1/node/identity" | \
      "${JQ_BINARY}" -r '.data.enr')"
  LC_TRUSTED_BLOCK_ROOT="$(
    "${CURL_BINARY}" -s "http://localhost:${BASE_REST_PORT}/eth/v1/beacon/headers/finalized" | \
      "${JQ_BINARY}" -r '.data.root')"
  for NUM_LC in $(seq 1 $LC_NODES); do
    LC_DATA_DIR="${DATA_DIR}/lc${NUM_LC}"

    WEB3_ARG=()
    if [ "${RUN_NIMBUS_ETH1}" == "1" ]; then
      WEB3_ARG+=("--web3-url=http://127.0.0.1:${NIMBUS_ETH1_RPC_PORTS[$(( NUM_NODES + NUM_LC - 1 ))]}")
    fi

    if [ "${RUN_GETH}" == "1" ]; then
      WEB3_ARG+=("--web3-url=http://127.0.0.1:${GETH_HTTP_PORTS[$(( NUM_NODES + NUM_LC - 1 ))]}")
    fi

    ./build/nimbus_light_client \
      --log-level="${LOG_LEVEL}" \
      --log-format="json" \
      --data-dir="${LC_DATA_DIR}" \
      --network="${CONTAINER_DATA_DIR}" \
      --bootstrap-node="${LC_BOOTSTRAP_NODE}" \
      --tcp-port=$(( BASE_PORT + NUM_NODES + NUM_LC - 1 )) \
      --udp-port=$(( BASE_PORT + NUM_NODES + NUM_LC - 1 )) \
      --max-peers=$(( NUM_NODES + LC_NODES - 1 )) \
      --nat="extip:127.0.0.1" \
      --trusted-block-root="${LC_TRUSTED_BLOCK_ROOT}" \
      --jwt-secret="${JWT_FILE}" \
      "${WEB3_ARG[@]}" \
      ${STOP_AT_EPOCH_FLAG} \
      &> "${DATA_DIR}/log_lc${NUM_LC}.txt" &
    PIDS="${PIDS},$!"
  done
fi

# give the regular nodes time to crash
sleep 5
BG_JOBS="$(jobs | wc -l | tr -d ' ')"
if [[ "${TIMEOUT_DURATION}" != "0" ]]; then
  BG_JOBS=$(( BG_JOBS - 1 )) # minus the timeout bg job
fi
if [[ "$BG_JOBS" != "$NUM_JOBS" ]]; then
  echo "$(( NUM_JOBS - BG_JOBS )) nimbus_beacon_node/nimbus_validator_client/nimbus_light_client instance(s) exited early. Aborting."
  dump_logs
  dump_logtrace
  exit 1
fi

# launch "htop" or wait for background jobs
if [[ "$USE_HTOP" == "1" ]]; then
  htop -p "$PIDS"
  # Cleanup is done when this script exists, since we listen to the EXIT signal.
else
  FAILED=0
  for PID in $(echo "$PIDS" | tr ',' ' '); do
    wait "$PID" || FAILED="$(( FAILED += 1 ))"
  done
  if [[ "$FAILED" != "0" ]]; then
    echo "${FAILED} child processes had non-zero exit codes (or exited early)."
    dump_logs
    dump_logtrace
    if [[ "${TIMEOUT_DURATION}" != "0" ]]; then
      if uname | grep -qiE "mingw|msys"; then
        taskkill //F //PID ${WATCHER_PID}
      else
        pkill -HUP -P ${WATCHER_PID}
      fi
    fi
    exit 1
  fi
fi

dump_logtrace

if [[ "${TIMEOUT_DURATION}" != "0" ]]; then
  if uname | grep -qiE "mingw|msys"; then
    taskkill //F //PID ${WATCHER_PID}
  else
    pkill -HUP -P ${WATCHER_PID}
  fi
fi
