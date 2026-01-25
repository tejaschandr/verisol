#!/bin/bash
# VeriSol - Setup verification tools
# Run: bash scripts/setup_tools.sh

set -e

echo "========================================="
echo "VeriSol - Verification Tools Setup"
echo "========================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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
echo "Checking existing tools..."
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

# Install solc 0.8.24
if ! solc-select versions 2>/dev/null | grep -q "0.8.24"; then
    echo "Installing solc 0.8.24..."
    solc-select install 0.8.24
fi

echo "Setting solc 0.8.24 as default..."
solc-select use 0.8.24

echo ""
echo "Verifying installations..."
echo "-----------------------------------------"

check_command solc
check_command slither


echo ""
echo "========================================="
echo -e "${GREEN}Setup complete!${NC}"
echo "========================================="
echo ""
echo "Tool versions:"
echo "  solc: $(solc --version | head -n2 | tail -n1)"
echo "  slither: $(slither --version 2>&1)"
echo ""
echo "Run verification:"
echo "  python -m verisol.cli audit examples/SimpleToken.sol"
echo ""
