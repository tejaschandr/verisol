#!/usr/bin/env python3
"""
Benchmark Comparison Tool

Compares Slither and GPT-4 baseline results and generates a comparison report.

Usage:
    python benchmarks/compare.py
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass
class ToolMetrics:
    """Metrics for a single tool."""
    name: str
    model: str
    total_contracts: int
    contracts_analyzed: int
    contracts_with_errors: int
    total_known_vulns: int
    true_positives: int
    false_negatives: int
    false_positives: int
    detection_rate: float
    precision: float
    false_positive_rate: float
    total_time: float
    total_tokens: int
    per_contract_results: dict[str, dict]


def load_baseline(path: Path, tool_name: str) -> ToolMetrics | None:
    """Load a baseline JSON file and extract metrics."""
    if not path.exists():
        print(f"Warning: {path} not found")
        return None

    with open(path) as f:
        data = json.load(f)

    # Build per-contract results
    per_contract = {}
    for result in data.get("results", []):
        filename = result["file"]
        known = result.get("known_vulns", [])
        if known:  # Only track contracts with ground truth
            per_contract[filename] = {
                "known_vulns": known,
                "true_positives": result.get("true_positives", []),
                "false_negatives": result.get("false_negatives", []),
                "false_positives": result.get("false_positives", []),
                "error": result.get("error"),
            }

    return ToolMetrics(
        name=tool_name,
        model=data.get("model", "N/A"),
        total_contracts=data.get("total_contracts", 0),
        contracts_analyzed=data.get("contracts_analyzed", 0),
        contracts_with_errors=data.get("contracts_with_errors", 0),
        total_known_vulns=data.get("total_known_vulns", 0),
        true_positives=data.get("total_true_positives", 0),
        false_negatives=data.get("total_false_negatives", 0),
        false_positives=data.get("total_false_positives", 0),
        detection_rate=data.get("detection_rate", 0),
        precision=data.get("precision", 0),
        false_positive_rate=data.get("false_positive_rate", 0),
        total_time=data.get("total_time", 0),
        total_tokens=data.get("total_tokens", 0),
        per_contract_results=per_contract,
    )


def find_unique_detections(tool1: ToolMetrics, tool2: ToolMetrics) -> tuple[list[str], list[str]]:
    """Find vulnerabilities uniquely detected by each tool."""
    tool1_detected = set()
    tool2_detected = set()

    # Get all contracts with ground truth
    all_contracts = set(tool1.per_contract_results.keys()) | set(tool2.per_contract_results.keys())

    for contract in all_contracts:
        t1_result = tool1.per_contract_results.get(contract, {})
        t2_result = tool2.per_contract_results.get(contract, {})

        t1_tp = set(t1_result.get("true_positives", []))
        t2_tp = set(t2_result.get("true_positives", []))

        # Add contract:vuln pairs
        for vuln in t1_tp:
            tool1_detected.add(f"{contract}:{vuln}")
        for vuln in t2_tp:
            tool2_detected.add(f"{contract}:{vuln}")

    unique_to_tool1 = sorted(tool1_detected - tool2_detected)
    unique_to_tool2 = sorted(tool2_detected - tool1_detected)

    return unique_to_tool1, unique_to_tool2


def generate_comparison_md(slither: ToolMetrics, gpt4: ToolMetrics, output_path: Path):
    """Generate markdown comparison report."""
    unique_slither, unique_gpt4 = find_unique_detections(slither, gpt4)

    # Determine winners for each metric
    def winner(s_val, g_val, higher_better=True):
        if higher_better:
            return "Slither" if s_val > g_val else ("GPT-4o" if g_val > s_val else "Tie")
        else:
            return "Slither" if s_val < g_val else ("GPT-4o" if g_val < s_val else "Tie")

    md = f"""# Benchmark Comparison: Slither vs GPT-4o

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Summary Metrics

| Metric | Slither | GPT-4o | Winner |
|--------|---------|--------|--------|
| **Detection Rate (Recall)** | {slither.detection_rate:.1%} | {gpt4.detection_rate:.1%} | {winner(slither.detection_rate, gpt4.detection_rate)} |
| **Precision** | {slither.precision:.1%} | {gpt4.precision:.1%} | {winner(slither.precision, gpt4.precision)} |
| **False Positive Rate** | {slither.false_positive_rate:.1%} | {gpt4.false_positive_rate:.1%} | {winner(slither.false_positive_rate, gpt4.false_positive_rate, higher_better=False)} |
| **True Positives** | {slither.true_positives} | {gpt4.true_positives} | {winner(slither.true_positives, gpt4.true_positives)} |
| **False Negatives** | {slither.false_negatives} | {gpt4.false_negatives} | {winner(slither.false_negatives, gpt4.false_negatives, higher_better=False)} |
| **False Positives** | {slither.false_positives} | {gpt4.false_positives} | {winner(slither.false_positives, gpt4.false_positives, higher_better=False)} |
| **Contracts Analyzed** | {slither.contracts_analyzed}/{slither.total_contracts} | {gpt4.contracts_analyzed}/{gpt4.total_contracts} | {winner(slither.contracts_analyzed, gpt4.contracts_analyzed)} |
| **Errors** | {slither.contracts_with_errors} | {gpt4.contracts_with_errors} | {winner(slither.contracts_with_errors, gpt4.contracts_with_errors, higher_better=False)} |
| **Total Time** | {slither.total_time:.1f}s | {gpt4.total_time:.1f}s | {winner(slither.total_time, gpt4.total_time, higher_better=False)} |
| **Cost** | Free | ~${gpt4.total_tokens * 0.000003:.2f} | Slither |

## Per-Contract Results

| Contract | Vulnerability | Slither | GPT-4o |
|----------|--------------|---------|--------|
"""

    # Combine all contracts with ground truth
    all_contracts = sorted(set(slither.per_contract_results.keys()) | set(gpt4.per_contract_results.keys()))

    for contract in all_contracts:
        s_result = slither.per_contract_results.get(contract, {})
        g_result = gpt4.per_contract_results.get(contract, {})

        known = s_result.get("known_vulns") or g_result.get("known_vulns", [])
        vuln_type = known[0] if known else "?"

        s_tp = len(s_result.get("true_positives", []))
        s_error = s_result.get("error")
        g_tp = len(g_result.get("true_positives", []))
        g_error = g_result.get("error")

        s_status = "Error" if s_error else ("✓" if s_tp > 0 else "✗")
        g_status = "Error" if g_error else ("✓" if g_tp > 0 else "✗")

        md += f"| {contract} | {vuln_type} | {s_status} | {g_status} |\n"

    md += f"""
## Unique Detections

### Only Slither Found ({len(unique_slither)})

"""
    if unique_slither:
        for item in unique_slither:
            md += f"- {item}\n"
    else:
        md += "_None_\n"

    md += f"""
### Only GPT-4o Found ({len(unique_gpt4)})

"""
    if unique_gpt4:
        for item in unique_gpt4:
            md += f"- {item}\n"
    else:
        md += "_None_\n"

    md += f"""
## Analysis

### Detection Capabilities

- **Slither** detected {slither.true_positives} of {slither.total_known_vulns} known vulnerabilities ({slither.detection_rate:.1%})
- **GPT-4o** detected {gpt4.true_positives} of {gpt4.total_known_vulns} known vulnerabilities ({gpt4.detection_rate:.1%})

### Strengths

**Slither:**
- Fast execution ({slither.total_time:.1f}s total)
- Free and open source
- Deterministic results
- Low-level pattern detection (reentrancy, delegatecall, tx.origin)

**GPT-4o:**
- Higher detection rate ({gpt4.detection_rate:.1%} vs {slither.detection_rate:.1%})
- Handles all Solidity versions (no compile errors)
- Detects semantic vulnerabilities (DoS, front-running, honeypots)
- Understands code intent and business logic

### Weaknesses

**Slither:**
- Compile errors on {slither.contracts_with_errors} contracts
- Misses semantic/logic vulnerabilities
- High false positive rate ({slither.false_positive_rate:.1%})

**GPT-4o:**
- Slower ({gpt4.total_time:.1f}s vs {slither.total_time:.1f}s)
- Costs money (~${gpt4.total_tokens * 0.000003:.2f} for this run)
- Non-deterministic (may vary between runs)
- High false positive rate ({gpt4.false_positive_rate:.1%})

## Recommendation

**Use both tools together:**
1. Run Slither first for fast, deterministic detection of common patterns
2. Run GPT-4o for semantic analysis and to catch logic bugs
3. Cross-reference results to reduce false positives

---

*Generated by VeriSol benchmark comparison tool*
"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(md)
    print(f"Comparison report saved to: {output_path}")


def main():
    script_dir = Path(__file__).parent
    results_dir = script_dir / "results"

    slither_path = results_dir / "slither_baseline.json"
    gpt4_path = results_dir / "gpt4_baseline.json"

    print("Loading baseline results...")
    slither = load_baseline(slither_path, "Slither")
    gpt4 = load_baseline(gpt4_path, "GPT-4o")

    if not slither or not gpt4:
        print("Error: Could not load both baseline files")
        return

    print(f"Slither: {slither.true_positives} TPs, {slither.false_positives} FPs")
    print(f"GPT-4o:  {gpt4.true_positives} TPs, {gpt4.false_positives} FPs")

    output_path = results_dir / "comparison.md"
    generate_comparison_md(slither, gpt4, output_path)

    # Print summary to console
    print("\n" + "=" * 60)
    print("COMPARISON SUMMARY")
    print("=" * 60)
    print(f"{'Metric':<25} {'Slither':>12} {'GPT-4o':>12}")
    print("-" * 60)
    print(f"{'Detection Rate':<25} {slither.detection_rate:>11.1%} {gpt4.detection_rate:>11.1%}")
    print(f"{'Precision':<25} {slither.precision:>11.1%} {gpt4.precision:>11.1%}")
    print(f"{'False Positive Rate':<25} {slither.false_positive_rate:>11.1%} {gpt4.false_positive_rate:>11.1%}")
    print(f"{'True Positives':<25} {slither.true_positives:>12} {gpt4.true_positives:>12}")
    print(f"{'False Positives':<25} {slither.false_positives:>12} {gpt4.false_positives:>12}")
    print(f"{'Errors':<25} {slither.contracts_with_errors:>12} {gpt4.contracts_with_errors:>12}")
    print(f"{'Time':<25} {slither.total_time:>10.1f}s {gpt4.total_time:>10.1f}s")
    print("=" * 60)


if __name__ == "__main__":
    main()
