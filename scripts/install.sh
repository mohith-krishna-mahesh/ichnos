#!/usr/bin/env bash
# ==============================================================================
# Ichnos Standalone Release Installer
# ==============================================================================
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/mohith-krishna-mahesh/ichnos/main/scripts/install.sh | bash
#
# Detects OS and architecture, downloads the pre-built standalone release binary,
# installs it to /usr/local/bin or ~/.local/bin, and verifies functionality.
# ==============================================================================

set -euo pipefail

REPO="mohith-krishna-mahesh/ichnos"
BINARY_NAME="ichnos"

echo "================================================================="
echo " Installing Ichnos — Modular CTF & Security Research Terminal    "
echo "================================================================="

# 1. Detect OS
OS="$(uname -s)"
case "${OS}" in
    Darwin*)  PLATFORM="macos" ;;
    Linux*)   PLATFORM="linux" ;;
    *)
        echo "[!] Unsupported operating system: ${OS}" >&2
        echo "    For Windows, download ichnos-windows-x86_64.zip directly from:" >&2
        echo "    https://github.com/${REPO}/releases/latest" >&2
        exit 1
        ;;
esac

# 2. Detect Architecture
ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64|amd64)   TARGET_ARCH="x86_64" ;;
    arm64|aarch64)  TARGET_ARCH="arm64" ;;
    *)
        echo "[!] Unsupported system architecture: ${ARCH}" >&2
        exit 1
        ;;
esac

ASSET_NAME="ichnos-${PLATFORM}-${TARGET_ARCH}"
RELEASE_URL="https://github.com/${REPO}/releases/latest/download/${ASSET_NAME}"

echo "[*] Detected Platform:     ${PLATFORM}"
echo "[*] Detected Architecture: ${TARGET_ARCH}"
echo "[*] Release Asset Target:  ${ASSET_NAME}"

# 3. Determine Installation Destination
if [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="/usr/local/bin"
elif command -v sudo >/dev/null 2>&1 && [ -t 0 ]; then
    INSTALL_DIR="/usr/local/bin"
    USE_SUDO="true"
else
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "${INSTALL_DIR}"
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

DOWNLOAD_PATH="${TMP_DIR}/${BINARY_NAME}"

echo "[*] Downloading release binary from GitHub..."
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "${RELEASE_URL}" -o "${DOWNLOAD_PATH}"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "${DOWNLOAD_PATH}" "${RELEASE_URL}"
else
    echo "[!] Error: neither curl nor wget is installed." >&2
    exit 1
fi

chmod +x "${DOWNLOAD_PATH}"

echo "[*] Installing binary into: ${INSTALL_DIR}/${BINARY_NAME}..."
if [ "${USE_SUDO:-false}" = "true" ]; then
    sudo install -m 755 "${DOWNLOAD_PATH}" "${INSTALL_DIR}/${BINARY_NAME}"
else
    install -m 755 "${DOWNLOAD_PATH}" "${INSTALL_DIR}/${BINARY_NAME}"
fi

# 4. Verify Installation
echo "[*] Verifying installed binary..."
if "${INSTALL_DIR}/${BINARY_NAME}" --version >/dev/null 2>&1; then
    VERSION_INFO="$("${INSTALL_DIR}/${BINARY_NAME}" --version)"
    echo "[+] Successfully installed ${VERSION_INFO} to ${INSTALL_DIR}/${BINARY_NAME}"
else
    echo "[!] Warning: Installation placed binary at ${INSTALL_DIR}/${BINARY_NAME}, but test run failed." >&2
fi

# 5. Check PATH
if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
    echo ""
    echo "================================================================="
    echo " [!] NOTE: ${INSTALL_DIR} is not currently in your \$PATH."
    echo " Add it to your shell configuration (e.g. ~/.bashrc or ~/.zshrc):"
    echo "   export PATH=\"${INSTALL_DIR}:\$PATH\""
    echo "================================================================="
fi

echo ""
echo "Run 'ichnos' to launch the interactive TUI shell, or 'ichnos --help' for CLI tools."
