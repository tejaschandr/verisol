# VeriSol GitHub Action

Integrate AI-powered smart contract security audits into your CI/CD pipeline.

## Quick Start

Add this workflow to `.github/workflows/verisol.yml`:

```yaml
name: Security Audit

on:
  pull_request:
    paths: ['**.sol']

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: tejaschandr/verisol@v1
        with:
          contract-path: 'contracts/MyContract.sol'
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
```

## Usage Options

### Using the Reusable Action

The recommended way to use VeriSol in your workflows:

```yaml
- uses: tejaschandr/verisol@v1
  with:
    contract-path: 'contracts/'
    mode: 'default'
    fail-on-critical: 'true'
    fail-on-high: 'true'
```

### Using the Workflow Template

Copy `.github/workflows/verisol.yml` from this repository for a ready-to-use workflow that:

- Triggers on push/PR when `.sol` files change
- Supports manual dispatch with custom paths
- Uploads audit reports as artifacts

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `contract-path` | Path to Solidity file or directory | Yes | `contracts/` |
| `openai-api-key` | OpenAI API key for LLM analysis | No | - |
| `mode` | Audit mode (see below) | No | `default` |
| `fail-on-critical` | Fail if CRITICAL issues found | No | `true` |
| `fail-on-high` | Fail if HIGH issues found | No | `true` |
| `solc-version` | Solidity compiler version | No | `0.8.20` |

## Audit Modes

| Mode | Description | API Required |
|------|-------------|--------------|
| `default` | Slither + LLM analysis (recommended) | Yes |
| `quick` | Slither only (fastest) | No |
| `offline` | Slither + SMTChecker formal verification | No |
| `full` | Slither + LLM + SMTChecker (most thorough) | Yes |

## Outputs

| Output | Description |
|--------|-------------|
| `score` | Security score (0-100) |
| `status` | `passed`, `failed`, or `error` |
| `findings-count` | Total number of findings |
| `critical-count` | Number of CRITICAL findings |
| `high-count` | Number of HIGH findings |
| `report-path` | Path to JSON report file |

## Examples

### Basic Security Check on PRs

```yaml
name: Contract Security

on:
  pull_request:
    paths: ['**.sol']

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: tejaschandr/verisol@v1
        id: audit
        with:
          contract-path: 'contracts/'
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}

      - name: Comment on PR
        if: always()
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.createComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              body: `## Security Audit Results

              - **Score:** ${{ steps.audit.outputs.score }}%
              - **Status:** ${{ steps.audit.outputs.status }}
              - **Findings:** ${{ steps.audit.outputs.findings-count }}`
            })
```

### Quick Mode (No API Key)

For fast, free audits without LLM analysis:

```yaml
- uses: tejaschandr/verisol@v1
  with:
    contract-path: 'contracts/Token.sol'
    mode: 'quick'
```

### Offline Mode with Formal Verification

For comprehensive analysis without external APIs:

```yaml
- uses: tejaschandr/verisol@v1
  with:
    contract-path: 'contracts/Vault.sol'
    mode: 'offline'
```

### Full Analysis

Maximum coverage with all verifiers:

```yaml
- uses: tejaschandr/verisol@v1
  with:
    contract-path: 'contracts/'
    mode: 'full'
    openai-api-key: ${{ secrets.OPENAI_API_KEY }}
```

### Custom Failure Thresholds

Allow high severity issues but fail on critical:

```yaml
- uses: tejaschandr/verisol@v1
  with:
    contract-path: 'contracts/'
    fail-on-critical: 'true'
    fail-on-high: 'false'
```

### Multiple Contracts

Audit multiple contracts in parallel:

```yaml
jobs:
  audit:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        contract:
          - contracts/Token.sol
          - contracts/Vault.sol
          - contracts/Governance.sol
    steps:
      - uses: actions/checkout@v4
      - uses: tejaschandr/verisol@v1
        with:
          contract-path: ${{ matrix.contract }}
          mode: 'quick'
```

### Manual Dispatch

Trigger audits manually with custom parameters:

```yaml
on:
  workflow_dispatch:
    inputs:
      contract:
        description: 'Contract to audit'
        required: true
      mode:
        description: 'Audit mode'
        type: choice
        options: [default, quick, offline, full]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: tejaschandr/verisol@v1
        with:
          contract-path: ${{ github.event.inputs.contract }}
          mode: ${{ github.event.inputs.mode }}
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
```

### Upload Report Artifact

```yaml
- uses: tejaschandr/verisol@v1
  id: audit
  with:
    contract-path: 'contracts/'

- uses: actions/upload-artifact@v4
  with:
    name: security-report
    path: ${{ steps.audit.outputs.report-path }}
```

## Setting Up Secrets

1. Go to your repository's **Settings** > **Secrets and variables** > **Actions**
2. Click **New repository secret**
3. Add `OPENAI_API_KEY` with your OpenAI API key

For organization-wide usage, set the secret at the organization level.

## Solidity Version

VeriSol uses `solc-select` to manage Solidity compiler versions. By default, it uses `0.8.20`. To use a different version:

```yaml
- uses: tejaschandr/verisol@v1
  with:
    contract-path: 'contracts/'
    solc-version: '0.8.24'
```

Ensure your contracts are compatible with the specified version.

## Troubleshooting

### "solc not found"

The action installs solc automatically via solc-select. If you see this error, ensure you're using the reusable action or have the installation step in your workflow:

```yaml
- name: Install solc
  run: |
    pip install solc-select
    solc-select install 0.8.20
    solc-select use 0.8.20
```

### "OPENAI_API_KEY not set"

This warning appears when using `default` or `full` mode without an API key. Either:
- Add the `OPENAI_API_KEY` secret to your repository
- Use `mode: 'quick'` or `mode: 'offline'` for API-free audits

### "Compilation failed"

Check that:
- Your Solidity version matches `solc-version` input
- All imports are resolvable (install dependencies first)
- The contract path is correct

### JSON Parsing Errors

Ensure `jq` is available (included in GitHub-hosted runners). The action uses jq to parse VeriSol's JSON output.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Audit passed (no critical/high issues or thresholds disabled) |
| 1 | Audit failed (critical/high issues found or compilation error) |

## JSON Output Format

VeriSol outputs structured JSON for CI integration:

```json
{
  "passed": true,
  "overall_score": 0.85,
  "finding_summary": {
    "critical": 0,
    "high": 0,
    "medium": 2,
    "low": 1,
    "informational": 3
  },
  "all_findings": [...],
  "confidence": "high"
}
```

## Support

- Issues: [github.com/tejaschandr/verisol/issues](https://github.com/tejaschandr/verisol/issues)
- Documentation: [github.com/tejaschandr/verisol](https://github.com/tejaschandr/verisol)
