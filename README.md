# VeriSol

AI-powered smart contract security verification.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **100% detection rate** on real-world vulnerability patterns
- **4 audit modes** - balance speed, cost, and thoroughness
- **GitHub Action** for CI/CD integration
- **Cross-tool confidence scoring** - reduces false positives

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
```

1. **Solc** - Compilation check (gate)
2. **Slither** - Static analysis (90+ detectors)
3. **SMTChecker** - Formal verification (requires z3)
4. **LLM** - Semantic analysis (GPT-4o/Claude)
5. **Confidence Scoring** - Cross-tool consensus

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
verisol audit <file>    # Audit a contract
verisol check           # Check tool availability
verisol report <file>   # Generate markdown report
verisol --version       # Show version
```

## Project Structure

```
verisol/
├── src/verisol/           # Main package
│   ├── cli.py             # CLI (verisol command)
│   ├── api.py             # FastAPI server
│   ├── pipeline.py        # Verification orchestrator
│   └── verifiers/         # Slither, SMTChecker, LLM
├── .github/workflows/     # CI workflows
├── action.yml             # GitHub Action
├── docs/                  # Documentation
└── tests/                 # Test suite
```

## License

MIT
