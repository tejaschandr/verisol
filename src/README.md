# Source

```
verisol/
├── cli.py              # CLI commands (audit, check, report)
├── api.py              # FastAPI server (optional)
├── pipeline.py         # Verification orchestrator
├── config.py           # Settings (from .env)
├── core/
│   ├── contract.py     # Contract model (file + address loading)
│   └── report.py       # Finding, ExploitResult, AuditReport
├── verifiers/
│   ├── base.py         # BaseVerifier ABC
│   ├── solc.py         # Compilation (auto version, --via-ir retry)
│   ├── slither.py      # Static analysis (90+ detectors)
│   ├── smtchecker.py   # Formal verification
│   └── llm.py          # LLM analysis (GPT-4o/Claude)
├── exploits/
│   ├── agent.py        # LLM retry loop (generate → test → fix)
│   ├── llm_generator.py # LLM exploit code generation
│   ├── prompts.py      # System prompts + few-shot examples
│   ├── generator.py    # Jinja2 template fallback
│   ├── runner.py       # Foundry execution (local + fork mode)
│   └── templates/      # Exploit templates (reentrancy, access, overflow)
└── integrations/
    └── etherscan.py    # Fetch verified source by address (5 chains)
```

## Adding a Verifier

1. Create `verifiers/myverifier.py`
2. Extend `BaseVerifier`
3. Implement `verify()` and `is_available()`
4. Register in `verifiers/__init__.py`

## Exploit Generation Flow

```
Finding → agent.py → llm_generator.py → runner.py → forge test
                ↑                              ↓
                └──── error feedback ──────────┘
                         (retry up to 3x)
```
