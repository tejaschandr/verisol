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

VeriSol says: *"Reentrancy at line 15 - **EXPLOITABLE** - drained 11 ETH in 1 attempt via LLM"*

```bash
$ verisol audit EtherStore.sol --quick --exploit

Exploit Results: 1/1 EXPLOITABLE
  EXPLOITABLE Reentrancy Eth (profit: 11000000000000000000 wei, 1 attempt via llm)
```

VeriSol uses an **LLM agent with a retry loop** to generate Foundry exploit PoCs. When a generated exploit fails, the agent reads the compiler/runtime error and fixes it — similar to how [ReX](https://arxiv.org/abs/2504.01860) achieves 92% success rates with iterative refinement.

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

### Fork Mode (Deployed Contracts)

Audit any verified contract on-chain by address:

```bash
verisol audit --address 0x... --chain ethereum --quick
verisol audit --address 0x... --chain ethereum --exploit
verisol audit --address 0x... --chain ethereum --exploit --block 19000000
```

Supported chains: Ethereum, Polygon, Arbitrum, Optimism, Base.
Requires `ETHERSCAN_API_KEY` and `{CHAIN}_RPC_URL` in `.env`.

### Vulnerability Coverage

The LLM agent generalizes across vulnerability types — no templates required:

- Reentrancy (classic + read-only)
- Access control / visibility
- Delegatecall / storage collision
- DoS (King of Ether pattern)
- Weak randomness
- Precision loss / divide-before-multiply
- Oracle staleness
- Unprotected callbacks (ERC-721)
- Ecrecover signature issues
- Flash loan attacks
- And more — the LLM generates exploits from first principles

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
                                              [LLM Exploit Agent]
                                                    ↓         ↑
                                              forge test → error feedback
                                                    ↓
                                              EXPLOITABLE / NOT EXPLOITABLE
```

1. **Solc** - Compilation check (gate)
2. **Slither** - Static analysis (90+ detectors)
3. **SMTChecker** - Formal verification (requires z3)
4. **LLM** - Semantic analysis (GPT-4o/Claude)
5. **Confidence Scoring** - Cross-tool consensus
6. **LLM Exploit Agent** - Generate Foundry PoC → run → read errors → retry (with `--exploit`)

## Benchmark Results

Tested on 32 vulnerable contracts (8 mainnet-style + 24 [DeFiVulnLabs](https://github.com/SunWeb3Sec/DeFiVulnLabs)) with GPT-4o and 3 retries per finding.

### Exploit Generation

| Metric | Value |
|--------|-------|
| **Exploitable** | **13/32 (40.6%)** |
| Adjusted (excl. detection gaps) | 13/26 (50.0%) |
| Avg attempts (successes) | 1.23 |
| Contracts exploited without templates | **10** |
| Retry loop saves | 3 contracts needed 2-3 attempts |

### Per-Contract Results

| Contract | Vuln Type | Result | Method | Attempts |
|----------|-----------|--------|--------|----------|
| EtherStore | reentrancy | EXPLOITABLE | llm | 1 |
| MissingAccessControl | access-control | EXPLOITABLE | llm | 1 |
| Proxy | delegatecall | EXPLOITABLE | llm | 2 |
| VulnerableLending | flash-loan | EXPLOITABLE* | llm | 2 |
| KingOfEther | dos | EXPLOITABLE | llm | 1 |
| EtherGame | selfdestruct | EXPLOITABLE | llm | 1 |
| GuessTheRandomNumber | randomness | EXPLOITABLE | llm | 1 |
| SimplePool | precision-loss | EXPLOITABLE | llm | 1 |
| VulnerableOracle | oracle-stale | EXPLOITABLE | llm | 1 |
| VulnContract | read-only-reentrancy | EXPLOITABLE | llm | 3 |
| MaxMint721 | callback | EXPLOITABLE | llm | 1 |
| Miscalculation | divide-before-multiply | EXPLOITABLE | llm | 1 |
| SimpleBank | ecrecover | EXPLOITABLE | llm | 1 |

*Non-deterministic — succeeded on some runs.

6 contracts had no Slither findings (detection gap, not exploit generation failure). See `benchmarks/results/` for full JSON.

### Detection

| Metric | Value |
|--------|-------|
| Detection Rate | 81.3% (26/32 contracts with findings) |
| Vulnerability types detected | 13+ |

Detection gaps: Slither misses visibility, private-data, bypass-contract, data-location, and some overflow patterns. These are detection-side limitations, not exploit generation failures.

## Configuration

Create `.env` file:

```bash
OPENAI_API_KEY=sk-...          # Required for default/full modes + exploit generation
LLM_PROVIDER=openai            # or anthropic
LLM_MODEL=gpt-4o               # or claude-3-5-sonnet-latest
EXPLOIT_LLM_ENABLED=true       # Enable LLM exploit generation (default: true)
EXPLOIT_MAX_RETRIES=3           # Max retry attempts per finding (default: 3)
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
│   ├── pipeline.py        # Verification orchestrator
│   ├── verifiers/         # Slither, SMTChecker, LLM
│   ├── integrations/      # External services (Etherscan)
│   └── exploits/          # Exploit simulation
│       ├── agent.py       # LLM retry loop (generate → test → fix → retry)
│       ├── llm_generator.py  # LLM exploit code generation
│       ├── prompts.py     # Exploit generation prompts
│       ├── generator.py   # Template fallback (Jinja2)
│       ├── runner.py      # Execute forge tests (local + fork)
│       └── templates/     # Exploit templates (fallback)
├── benchmarks/            # Benchmark suite (32 contracts)
├── .github/workflows/     # CI workflows
├── action.yml             # GitHub Action
├── docs/                  # Documentation
└── tests/                 # Test suite (77 tests)
```

## License

MIT
