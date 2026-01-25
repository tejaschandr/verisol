# Contributing to VeriSol

Thank you for your interest in contributing to VeriSol! This document provides guidelines for contributing to the project.

## Getting Started

### Development Setup

```bash
# Clone the repository
git clone https://github.com/tejaschandr/verisol.git
cd verisol

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # or `.venv\Scripts\activate` on Windows

# Install in development mode with dev dependencies
pip install -e ".[dev]"

# Install Solidity compiler
pip install solc-select
solc-select install 0.8.24
solc-select use 0.8.24
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=verisol

# Run specific test file
pytest tests/test_verifiers.py
```

### Code Quality

We use `ruff` for linting:

```bash
# Check for issues
ruff check src/

# Auto-fix issues
ruff check --fix src/
```

## How to Contribute

### Reporting Issues

- Check existing issues before creating a new one
- Include reproduction steps, expected vs actual behavior
- For security vulnerabilities, please email directly instead of creating a public issue

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `pytest`
5. Run linter: `ruff check src/`
6. Commit with a clear message
7. Push and create a pull request

### Commit Messages

Use clear, descriptive commit messages:

```
feat: add support for Foundry projects
fix: handle empty contract files gracefully
docs: update GitHub Action examples
test: add tests for SMTChecker timeout
```

## Code Guidelines

### Python Style

- Follow PEP 8
- Use type hints
- Keep functions focused and small
- Write docstrings for public functions

### Testing

- Add tests for new features
- Maintain or improve test coverage
- Tests should be fast and deterministic

### Documentation

- Update README for user-facing changes
- Update CLAUDE.md for developer-facing changes
- Add docstrings for new public APIs

## Project Structure

```
src/verisol/
├── cli.py          # CLI entry point
├── api.py          # FastAPI server
├── pipeline.py     # Verification orchestrator
├── config.py       # Settings management
├── core/
│   ├── contract.py # Contract model
│   └── report.py   # Report generation
└── verifiers/
    ├── base.py     # Abstract base class
    ├── solc.py     # Compilation
    ├── slither.py  # Static analysis
    ├── smtchecker.py # Formal verification
    └── llm.py      # LLM analysis
```

## Need Help?

- Open an issue for questions
- Check existing documentation in `/docs`
- Review test files for usage examples

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
