if [ -z "${GETH_BINARIES_SOURCED:-}" ]; then
GETH_BINARIES_SOURCED=1

SCRIPTS_DIR="$(dirname "${BASH_SOURCE[0]}")"
BUILD_DIR="$(cd "$SCRIPTS_DIR/../build"; pwd)"

source "${SCRIPTS_DIR}/detect_platform.sh"

: ${GETH_BINARY:="${BUILD_DIR}/third-party/geth"}
: ${GETH_CAPELLA_BINARY:="${BUILD_DIR}/third-party/geth_capella"}
: ${GETH_EIP_4844_BINARY:="${BUILD_DIR}/third-party/geth_eip4844"}

download_official_geth_binary() {
  GETH_VERSION="1.11.0-unstable-262bd38f"

  # https://geth.ethereum.org/downloads/
  #  "https://gethstore.blob.core.windows.net/builds/geth-linux-amd64-1.11.0-unstable-262bd38f.tar.gz"
  #  "https://gethstore.blob.core.windows.net/builds/geth-darwin-amd64-1.11.0-unstable-262bd38f.tar.gz"
  #  "https://gethstore.blob.core.windows.net/builds/geth-windows-amd64-1.11.0-unstable-262bd38f.zip"

  GETH_URL="https://gethstore.blob.core.windows.net/builds/"

  case "${OS}" in
    linux)
      GETH_TARBALL="geth-linux-amd64-${GETH_VERSION}.tar.gz"
      ;;
    macos)
      GETH_TARBALL="geth-darwin-amd64-${GETH_VERSION}.tar.gz"
      ;;
    windows)
      GETH_TARBALL="geth-windows-amd64-${GETH_VERSION}.zip"
      ;;
  esac

  if [[ ! -e "${GETH_BINARY}" ]]; then
    log "Downloading Geth binary"
    mkdir -p build/third-party
    pushd build/third-party >/dev/null
    "${CURL_BINARY}" -sSLO "${GETH_URL}/${GETH_TARBALL}"
    local tmp_extract_dir
    tmp_extract_dir=$(mktemp -d geth-extract-XXX)
    CLEANUP_DIRS+=("${tmp_extract_dir}")
    tar -xzf "${GETH_TARBALL}" --directory "${tmp_extract_dir}" --strip-components=1
    mv "${tmp_extract_dir}/geth" .
    GETH_BINARY="${PWD}/geth"
    popd >/dev/null
  fi
}

download_status_geth_binary() {
  BINARY_NAME="$1"
  BINARY_FS_PATH="$2"

  if [[ ! -e "${BINARY_FS_PATH}" ]]; then
    case "${OS}-${ARCH}" in
      linux-arm64)
        GETH_PLATFORM=linux-arm64
        ;;
      linux-amd64)
        GETH_PLATFORM=linux-amd64
        ;;
      macos-arm64)
        GETH_PLATFORM=macos-arm64
        ;;
      macos-amd64)
        GETH_PLATFORM=macos-amd64
        ;;
      windows-amd64)
        GETH_PLATFORM=windows-amd64
        ;;
    esac

    log "Downloading Geth binary (EIP 4844)"

    GETH_URL="https://github.com/status-im/nimbus-simulation-binaries/raw/master/geth/eip-4844-nightly-20221208/${GETH_PLATFORM}/geth"
    "${CURL_BINARY}" -o "${BINARY_FS_PATH}" -sSL "${GETH_URL}"
    chmod +x "${BINARY_FS_PATH}"
  fi
}

download_geth_capella() {
  download_status_geth_binary capella-nightly-20221221 "$GETH_CAPELLA_BINARY" 
}

download_geth_eip_4844() {
  download_status_geth_binary eip-4844-nightly-20221208 "$GETH_EIP_4844_BINARY" 
}

fi
