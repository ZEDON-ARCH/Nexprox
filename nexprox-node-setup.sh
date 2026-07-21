#!/usr/bin/env bash
# ══════════════════════════════════════════════════
#  NEXPROX NODE.JS EDITION — SETUP & LAUNCHER
#  Linux / macOS
# ══════════════════════════════════════════════════
set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║    NEXPROX NODE.JS EDITION — SETUP & LAUNCHER   ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# ── Check Node.js ──
if ! command -v node &> /dev/null; then
    echo -e "${RED}[!] Node.js is NOT installed.${NC}"
    echo ""
    echo "  Install Node.js >= 18.0:"
    echo "    macOS:   brew install node"
    echo "    Ubuntu:  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt install -y nodejs"
    echo "    Fedora:  sudo dnf install nodejs"
    echo ""
    exit 1
fi

echo -e "${GREEN}[OK]${NC} Node.js found: $(node --version)"
echo ""

# ── Verify files ──
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f "server.js" ]; then
    echo -e "${RED}[ERROR]${NC} server.js not found. Run from the Nexprox-Node directory."
    exit 1
fi

# ── Install dependencies ──
if [ ! -d "node_modules" ]; then
    echo "[SETUP] Installing npm dependencies..."
    npm install
    echo ""
fi

# ── Create data files ──
[ ! -f "users.json" ] && echo '{}' > users.json

echo -e "${GREEN}[OK]${NC} Dependencies ready."
echo ""
echo "═════════════════════════════════════════════════"
echo " Starting Nexprox Dashboard on http://localhost:3000"
echo " Press Ctrl+C to stop."
echo "═════════════════════════════════════════════════"
echo ""

node server.js
