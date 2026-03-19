#!/bin/bash
# VeriSol - Setup verification tools
# Run: bash scripts/setup_tools.sh

set -e

echo "========================================="
echo "VeriSol - Verification Tools Setup"
echo "========================================="

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

check_command() {
    if command -v "$1" &> /dev/null; then
        echo -e "${GREEN}✓${NC} $1 is installed"
        return 0
    else
        echo -e "${RED}✗${NC} $1 is not installed"
        return 1
    fi
}

echo ""
echo "Checking prerequisites..."
echo "-----------------------------------------"
check_command python3 || exit 1
check_command pip || exit 1

echo ""
echo "Installing Python dependencies..."
echo "-----------------------------------------"
pip install --upgrade pip
pip install solc-select slither-analyzer

echo ""
echo "Setting up Solidity compiler..."
echo "-----------------------------------------"
if ! solc-select versions 2>/dev/null | grep -q "0.8.24"; then
    echo "Installing solc 0.8.24..."
    solc-select install 0.8.24
fi
solc-select use 0.8.24

echo ""
echo "Installing Foundry..."
echo "-----------------------------------------"
if ! command -v forge &> /dev/null; then
    echo "Installing Foundry (forge)..."
    curl -L https://foundry.paradigm.xyz | bash
    export PATH="$HOME/.foundry/bin:$PATH"
    foundryup
else
    echo -e "${GREEN}✓${NC} Foundry already installed"
fi

echo ""
echo "Verifying installations..."
echo "-----------------------------------------"
check_command solc
check_command slither
check_command forge

echo ""
echo "========================================="
echo -e "${GREEN}Setup complete!${NC}"
echo "========================================="
echo ""
echo "Tool versions:"
echo "  solc:    $(solc --version | head -n2 | tail -n1)"
echo "  slither: $(slither --version 2>&1)"
echo "  forge:   $(forge --version 2>&1)"
echo ""
echo "Run verification:"
echo "  verisol audit examples/SimpleToken.sol --quick"
echo ""
