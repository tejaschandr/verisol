# Benchmarks

Benchmark suite for evaluating VeriSol exploit generation.

## Current Results (v0.4.0)

Tested on 32 contracts (8 mainnet-style + 24 DeFiVulnLabs) with GPT-4o, 3 retries.

| Metric | Value |
|--------|-------|
| **Exploitable** | 13/32 (40.6%) |
| Adjusted (excl. detection gaps) | 13/26 (50.0%) |
| Avg attempts (successes) | 1.23 |
| Contracts exploited without templates | 10 |

## Running Benchmarks

```bash
# Full benchmark (requires OPENAI_API_KEY)
python benchmarks/run_llm_exploits.py --dataset all

# Dry run (no LLM calls)
python benchmarks/run_llm_exploits.py --dry-run

# Limit to N contracts
python benchmarks/run_llm_exploits.py --limit 5

# Specific dataset
python benchmarks/run_llm_exploits.py --dataset mainnet
python benchmarks/run_llm_exploits.py --dataset defivulnlabs
```

## Files

| File | Purpose |
|------|---------|
| `run_llm_exploits.py` | Main benchmark script |
| `contracts.json` | 32-contract manifest with metadata |
| `results/llm_exploit_benchmark.json` | Latest benchmark results |

## Contract Manifest

`contracts.json` defines the benchmark contracts:

```json
{
  "path": "data/contracts/mainnet/EtherStore_Vulnerable.sol",
  "name": "EtherStore",
  "vuln_type": "reentrancy",
  "has_template": true,
  "dataset": "mainnet"
}
```

## Output

Results saved to `results/` (gitignored, regeneratable).
