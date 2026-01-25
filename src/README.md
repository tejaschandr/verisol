# Source

```
verisol/
├── cli.py          # CLI commands (audit, check, report)
├── api.py          # FastAPI server
├── pipeline.py     # Verification orchestrator
├── config.py       # Settings (from .env)
├── core/
│   ├── contract.py # Contract model
│   └── report.py   # Finding, AuditReport models
└── verifiers/
    ├── base.py     # BaseVerifier ABC
    ├── solc.py     # Compilation
    ├── slither.py  # Static analysis
    ├── smtchecker.py # Formal verification
    └── llm.py      # LLM analysis (GPT-4o/Claude)
```

## Adding a Verifier

1. Create `verifiers/myverifier.py`
2. Extend `BaseVerifier`
3. Implement `verify()` and `is_available()`
4. Register in `verifiers/__init__.py`
