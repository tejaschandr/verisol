# Scripts

Development and setup utilities.

## setup_tools.sh

Installs all required verification tools:

```bash
bash scripts/setup_tools.sh
```

This will:
- Install `solc-select` and `slither-analyzer`
- Install and configure Solidity 0.8.24
- Verify all tools are working

## run_baseline.py

Run baseline benchmarks:

```bash
python scripts/run_baseline.py
```

Requires `OPENAI_API_KEY` in `.env` for LLM-based analysis.
