# Benchmarks

Benchmark suite for evaluating VeriSol vulnerability detection.

## Current Results (2026-01-21)

| Benchmark | Detection Rate | Precision |
|-----------|----------------|-----------|
| Educational (169 contracts) | 86.7% | 86.7% |
| DeFiVulnLabs (24 contracts) | **100%** | **85.7%** |

## Scripts

| Script | Purpose | Usage |
|--------|---------|-------|
| `run_slither.py` | Slither baseline | `python run_slither.py --all` |
| `run_gpt4.py` | GPT-4o with FP filtering | `python run_gpt4.py --all --filter` |
| `run_gpt4_fewshot.py` | Few-shot benchmark | `python run_gpt4_fewshot.py --all` |
| `run_defivulnlabs.py` | Real-world validation | `python run_defivulnlabs.py --all` |
| `compare.py` | Generate comparison | `python compare.py` |

## Running Benchmarks

```bash
# Real-world validation (recommended)
python benchmarks/run_defivulnlabs.py --all

# Educational benchmark
python benchmarks/run_gpt4.py --all --filter

# Requires OPENAI_API_KEY in .env
```

## Output

Results are saved to `results/` directory (gitignored, regeneratable):
- `defivulnlabs.json` - Real-world benchmark results
- `gpt4_fewshot.json` - Few-shot benchmark results

## Ground Truth

### DeFiVulnLabs (24 contracts)
Real vulnerability patterns from DeFiVulnLabs repository.

### Educational (15 contracts with known vulnerabilities)
From solidity-by-example.org - see `data/README.md` for full list.
