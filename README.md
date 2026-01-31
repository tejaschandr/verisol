# VeriSol

AI-powered smart contract security verification with **exploit simulation**.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Exploit Simulation** - Proves vulnerabilities are exploitable with working PoCs
- **100% detection rate** on real-world vulnerability patterns
- **4 audit modes** - balance speed, cost, and thoroughness
- **GitHub Action** for CI/CD integration
- **Cross-tool confidence scoring** - reduces false positives

## What Makes VeriSol Different

Other tools say: *"Potential reentrancy at line 15"*

VeriSol says: *"Reentrancy at line 15 - **EXPLOITABLE** - drained 11 ETH"*

```bash
$ verisol audit EtherStore.sol --quick --exploit

Exploit Results: 1/1 EXPLOITABLE
  EXPLOITABLE Reentrancy Eth (profit: 11000000000000000000 wei)
```

VeriSol automatically generates and runs Foundry exploit tests to prove vulnerabilities are real.

## Installation

```bash
git clone https://github.com/tejaschandr/verisol.git
cd verisol
pip install -e .
```

### Dependencies

```bash
# Install Solidity compiler
pip install solc-select
solc-select install 0.8.24
solc-select use 0.8.24

# Install Foundry (for exploit simulation)
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

## Quick Start

```bash
# Check tool availability
verisol check

# Audit a contract
verisol audit contracts/MyContract.sol

# Quick mode (Slither only, fastest)
verisol audit contracts/MyContract.sol --quick

# JSON output for CI
verisol audit contracts/MyContract.sol --json
```

## Audit Modes

| Mode | Command | Tools | Use Case |
|------|---------|-------|----------|
| Default | `verisol audit <file>` | Slither + LLM | Fast, thorough (recommended) |
| Quick | `verisol audit <file> --quick` | Slither only | Fastest, free |
| Offline | `verisol audit <file> --offline` | Slither + SMTChecker | Free, no API needed |
| Full | `verisol audit <file> --full` | All verifiers | Most comprehensive |

### Exploit Simulation

Add `--exploit` to any mode to generate and run Foundry exploit tests:

```bash
verisol audit contract.sol --quick --exploit
```

This will:
1. Detect vulnerabilities (Slither/SMTChecker/LLM)
2. Generate Foundry exploit tests for each finding
3. Execute exploits on a local EVM
4. Report which vulnerabilities are **proven exploitable**

Currently supported exploit types:
- Reentrancy (ETH drain attacks)

## GitHub Action

Add to your workflow:

```yaml
- uses: tejaschandr/verisol@v1
  with:
    contract-path: 'contracts/'
    mode: 'quick'
    fail-on-critical: 'true'
```

See [docs/github-action.md](docs/github-action.md) for full documentation.

## Verification Pipeline

```
Contract → Solc → [Slither | SMTChecker | LLM] → Confidence Scoring → Report
                                                         ↓
                                              [Exploit Simulation]
                                                         ↓
                                              Foundry → EXPLOITABLE / NOT EXPLOITABLE
```

1. **Solc** - Compilation check (gate)
2. **Slither** - Static analysis (90+ detectors)
3. **SMTChecker** - Formal verification (requires z3)
4. **LLM** - Semantic analysis (GPT-4o/Claude)
5. **Confidence Scoring** - Cross-tool consensus
6. **Exploit Simulation** - Generate & run Foundry PoCs (with `--exploit`)

## Benchmark Results

| Metric | Value |
|--------|-------|
| Detection Rate | 100% (8/8 vulnerable contracts) |
| Precision | 80% (2 false positives) |
| F1 Score | 88.9% |

Vulnerability types detected: reentrancy, delegatecall, tx.origin, DoS, access control, integer overflow, unchecked return, price oracle manipulation.

## Configuration

Create `.env` file:

```bash
OPENAI_API_KEY=sk-...          # Required for default/full modes
LLM_PROVIDER=openai            # or anthropic
LLM_MODEL=gpt-4o               # or claude-3-5-sonnet-latest
```

## CLI Commands

```bash
verisol audit <file>              # Audit a contract
verisol audit <file> --exploit    # Audit + prove exploitability
verisol audit <file> --quick      # Slither only (fastest)
verisol audit <file> --json       # JSON output for CI
verisol check                     # Check tool availability
verisol report <file>             # Generate markdown report
verisol --version                 # Show version
```

## Project Structure

```
verisol/
├── src/verisol/           # Main package
│   ├── cli.py             # CLI (verisol command)
│   ├── api.py             # FastAPI server
│   ├── pipeline.py        # Verification orchestrator
│   ├── verifiers/         # Slither, SMTChecker, LLM
│   └── exploits/          # Exploit simulation
│       ├── generator.py   # Finding → Foundry test
│       ├── runner.py      # Execute forge tests
│       └── templates/     # Exploit templates (reentrancy, etc.)
├── .github/workflows/     # CI workflows
├── action.yml             # GitHub Action
├── docs/                  # Documentation
└── tests/                 # Test suite
```

## License

MIT
