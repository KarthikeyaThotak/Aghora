#!/usr/bin/env bash
set -euo pipefail

echo "============================================"
echo " Ghidra-CLI Build Script for Linux/macOS"
echo "============================================"
echo ""

# Check for Rust/Cargo
if ! command -v cargo &>/dev/null; then
    echo "[ERROR] cargo not found. Install Rust from https://rustup.rs/"
    echo "        Run: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi
echo "[OK] Found $(cargo --version)"

# Check for Java 17+
if command -v java &>/dev/null; then
    JAVA_VER=$(java -version 2>&1 | head -1)
    echo "[OK] Found $JAVA_VER"
else
    echo "[WARNING] java not found. Ghidra requires Java 17+."
    echo "          Install via: sudo apt install openjdk-17-jdk  (Debian/Ubuntu)"
    echo "          or:          brew install openjdk@17          (macOS)"
fi

# Check for GHIDRA_INSTALL_DIR
if [ -z "${GHIDRA_INSTALL_DIR:-}" ]; then
    echo ""
    echo "[WARNING] GHIDRA_INSTALL_DIR is not set."
    echo "          Set it before running the server, e.g.:"
    echo "          export GHIDRA_INSTALL_DIR=/opt/ghidra_10.4_PUBLIC"
    echo "          or add it to your .env file."
    echo ""
    echo "          Download Ghidra from https://ghidra-sre.org/"
else
    echo "[OK] GHIDRA_INSTALL_DIR = $GHIDRA_INSTALL_DIR"
fi

# Navigate to ghidra_cli dir
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI_DIR="$SCRIPT_DIR/ghidra_cli"

if [ ! -f "$CLI_DIR/Cargo.toml" ]; then
    echo "[ERROR] $CLI_DIR/Cargo.toml not found."
    echo "        Make sure the ghidra_cli directory exists with source files."
    exit 1
fi

echo ""
echo "[*] Building ghidra-cli (this may take a few minutes)..."
echo ""

cd "$CLI_DIR"
cargo install --path .

echo ""
echo "============================================"
echo " Build successful!"
echo "============================================"
echo ""
echo "  ghidra binary installed to: $HOME/.cargo/bin/ghidra"
echo ""
echo "  Next steps:"
echo "  1. Set GHIDRA_INSTALL_DIR in your .env file"
echo "  2. Restart the Python server (server.py)"
echo "  3. Upload a PE file to trigger Ghidra analysis"
echo ""

# Verify
if command -v ghidra &>/dev/null; then
    echo "[OK] 'ghidra' is on your PATH and ready to use."
else
    echo "[WARNING] 'ghidra' is not on your PATH."
    echo "          Add \$HOME/.cargo/bin to PATH:"
    echo "          echo 'export PATH=\"\$HOME/.cargo/bin:\$PATH\"' >> ~/.bashrc && source ~/.bashrc"
fi
