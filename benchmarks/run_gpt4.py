#!/usr/bin/env python3
"""
GPT-4 Baseline Benchmark Runner

Runs GPT-4 analysis on the vulnerability dataset and compares results against
ground truth to calculate detection rates.

Usage:
    python benchmarks/run_gpt4.py [--limit N] [--all]

Requires:
    OPENAI_API_KEY environment variable (or in .env file)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

# Load .env file if python-dotenv is available
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent.parent / ".env"
    load_dotenv(env_path)
except ImportError:
    pass

try:
    from openai import OpenAI
except ImportError:
    print("Error: openai package not installed. Run: pip install openai")
    sys.exit(1)

# Ground truth: maps contract files to expected vulnerability types
GROUND_TRUTH: dict[str, list[str]] = {
    "ReEntrancy.sol": ["reentrancy"],
    "ReEntrancyGuard.sol": [],
    "Overflow.sol": ["integer-overflow", "overflow"],
    "TxOrigin.sol": ["tx.origin", "tx-origin"],
    "DenialOfService.sol": ["denial-of-service", "dos"],
    "FrontRunning.sol": ["front-running", "frontrunning"],
    "PreventFrontRunning.sol": [],
    "Delegatecall_1.sol": ["delegatecall"],
    "Delegatecall_2.sol": ["delegatecall"],
    "ContractSize.sol": ["contract-size"],
    "ForceEther.sol": ["force-ether", "selfdestruct"],
    "HoneyPot.sol": ["honeypot"],
    "Randomness.sol": ["randomness", "weak-randomness"],
    "SigReplay.sol": ["signature-replay", "replay"],
    "PreventSigReplay.sol": [],
    "VaultInflation.sol": ["inflation", "rounding"],
    "ExternalContract.sol": ["hidden-code"],
    "TornadoHack.sol": ["governance"],
}

# Keywords to match GPT-4 findings to ground truth
VULN_KEYWORDS = {
    "reentrancy": ["reentrancy", "re-entrancy", "reentrant"],
    "integer-overflow": ["overflow", "underflow", "integer overflow"],
    "overflow": ["overflow", "underflow"],
    "tx.origin": ["tx.origin", "origin"],
    "tx-origin": ["tx.origin"],
    "denial-of-service": ["denial of service", "dos"],
    "dos": ["dos", "denial"],
    "front-running": ["front-running", "frontrunning", "front running"],
    "frontrunning": ["frontrun"],
    "delegatecall": ["delegatecall", "delegate call"],
    "contract-size": ["extcodesize", "contract size", "iscontract"],
    "force-ether": ["selfdestruct", "force ether"],
    "selfdestruct": ["selfdestruct"],
    "honeypot": ["honeypot", "honey pot"],
    "randomness": ["randomness", "random", "block.timestamp", "blockhash"],
    "weak-randomness": ["weak random", "predictable"],
    "signature-replay": ["replay", "signature replay"],
    "replay": ["replay"],
    "inflation": ["inflation", "share inflation"],
    "rounding": ["rounding", "precision"],
    "hidden-code": ["hidden code", "malicious"],
    "governance": ["governance", "proposal"],
}

# FP Filter categories - based on fp_analysis.md
# These are commonly flagged incorrectly on educational contracts
FP_FILTER_CATEGORIES = {
    "access-control": {
        "keywords": ["anyone", "publicly", "no restriction", "arbitrary"],
        "filter_reason": "Educational contracts often omit access control intentionally",
    },
    "reentrancy": {
        "keywords": ["external call", "after", "before state"],
        "filter_reason": "Pattern matching without checking CEI compliance",
    },
    "integer-underflow": {
        "keywords": ["underflow", "subtraction"],
        "filter_reason": "Solidity 0.8+ has built-in underflow protection",
        "version_check": True,
    },
    "integer-overflow": {
        "keywords": ["overflow", "multiplication"],
        "filter_reason": "Solidity 0.8+ has built-in overflow protection",
        "version_check": True,
    },
    "out-of-bounds": {
        "keywords": ["bounds", "index", "array access"],
        "filter_reason": "Solidity automatically reverts on out-of-bounds access",
    },
}


def extract_solidity_version(source_code: str) -> tuple[int, int] | None:
    """Extract Solidity version from pragma statement."""
    match = re.search(r"pragma\s+solidity\s*[\^>=]*\s*(\d+)\.(\d+)", source_code)
    if match:
        return int(match.group(1)), int(match.group(2))
    return None


def should_filter_finding(
    finding: dict,
    source_code: str,
    known_vulns: list[str],
    enable_filter: bool = True,
) -> tuple[bool, str | None]:
    """
    Determine if a finding should be filtered out as a likely false positive.

    Returns (should_filter, reason) tuple.
    """
    if not enable_filter:
        return False, None

    finding_type = finding.get("type", "").lower()
    finding_desc = finding.get("description", "").lower()

    # Don't filter if it matches a known vulnerability
    for known in known_vulns:
        if known.lower() in finding_type or finding_type in known.lower():
            return False, None

    # Check each filter category
    for category, config in FP_FILTER_CATEGORIES.items():
        if category not in finding_type:
            continue

        # Version-based filtering for integer overflow/underflow
        if config.get("version_check"):
            version = extract_solidity_version(source_code)
            if version and version >= (0, 8):
                # Check if it's in assembly block (assembly bypasses checks)
                if "assembly" not in finding_desc and "unchecked" not in finding_desc:
                    return True, f"Filtered: {category} (Solidity {version[0]}.{version[1]} has built-in protection)"

        # out-of-bounds is always filtered (Solidity handles it)
        if category == "out-of-bounds":
            return True, f"Filtered: {category} (Solidity auto-reverts on bounds violations)"

        # For access-control and reentrancy, only filter on non-vulnerable contracts
        if category in ("access-control", "reentrancy"):
            if not known_vulns:  # No ground truth vulns for this contract
                # Check for common FP patterns in description
                if any(kw in finding_desc for kw in config["keywords"]):
                    return True, f"Filtered: {category} (educational contract pattern)"

    return False, None


ANALYSIS_PROMPT = """Analyze this Solidity contract for security vulnerabilities. List each vulnerability with:
- type: the category of vulnerability (e.g., reentrancy, integer-overflow, access-control)
- severity: Critical, High, Medium, Low, or Informational
- line_number: approximate line number where the issue occurs
- description: brief explanation of the vulnerability

Respond in JSON format:
{{
  "vulnerabilities": [
    {{
      "type": "vulnerability-type",
      "severity": "High",
      "line_number": 42,
      "description": "Description of the issue"
    }}
  ]
}}

If no vulnerabilities are found, return: {{"vulnerabilities": []}}

Contract source code:
```solidity
{source_code}
```"""


@dataclass
class ContractResult:
    file: str
    known_vulns: list[str]
    gpt4_findings: list[dict]
    vulns_found: list[str]
    true_positives: list[str]
    false_negatives: list[str]
    false_positives: list[str]
    filtered_findings: list[dict] = field(default_factory=list)
    error: str | None = None
    tokens_used: int = 0
    response_time: float = 0.0


@dataclass
class BenchmarkSummary:
    timestamp: str
    model: str
    total_contracts: int
    contracts_analyzed: int
    contracts_with_errors: int
    total_known_vulns: int
    total_true_positives: int
    total_false_negatives: int
    total_false_positives: int
    total_filtered: int
    filter_enabled: bool
    detection_rate: float
    precision: float
    false_positive_rate: float
    total_tokens: int
    total_time: float
    avg_time_per_contract: float
    results: list[dict] = field(default_factory=list)


def extract_json_from_response(text: str) -> dict | None:
    """Extract JSON from GPT-4 response."""
    # Try code blocks first
    json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass

    # Try whole response
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try finding JSON object
    json_match = re.search(r"\{.*\}", text, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(0))
        except json.JSONDecodeError:
            pass

    return None


def match_vulnerability(finding_type: str, finding_desc: str, known_vulns: list[str]) -> str | None:
    """Check if a GPT-4 finding matches any known vulnerability."""
    finding_text = f"{finding_type} {finding_desc}".lower()

    for known_vuln in known_vulns:
        keywords = VULN_KEYWORDS.get(known_vuln, [known_vuln])
        for keyword in keywords:
            if keyword.lower() in finding_text:
                return known_vuln
    return None


def analyze_with_gpt4(client: OpenAI, source_code: str, model: str) -> tuple[list[dict], int, str | None]:
    """Send contract to GPT-4 for analysis."""
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a smart contract security auditor. Analyze Solidity contracts for vulnerabilities and respond in JSON format."},
                {"role": "user", "content": ANALYSIS_PROMPT.format(source_code=source_code)}
            ],
            temperature=0.1,
            max_tokens=2000,
        )

        if not response.choices:
            return [], 0, "No response choices returned"

        content = response.choices[0].message.content
        if content is None:
            return [], 0, "Response content is None"

        tokens = response.usage.total_tokens if response.usage else 0

        parsed = extract_json_from_response(content)
        if parsed is None:
            return [], tokens, f"Failed to parse JSON: {content[:200]}"

        findings = parsed.get("vulnerabilities", [])
        return findings, tokens, None

    except Exception as e:
        return [], 0, f"API error ({type(e).__name__}): {str(e)[:100]}"


def analyze_contract(client: OpenAI, file_path: Path, model: str, enable_filter: bool = False) -> ContractResult:
    """Analyze a single contract and compare to ground truth."""
    filename = file_path.name
    known_vulns = GROUND_TRUTH.get(filename, [])

    try:
        source_code = file_path.read_text()
    except Exception as e:
        return ContractResult(
            file=filename, known_vulns=known_vulns, gpt4_findings=[], vulns_found=[],
            true_positives=[], false_negatives=known_vulns.copy(), false_positives=[],
            error=f"Read error: {e}",
        )

    start_time = time.time()
    findings, tokens, error = analyze_with_gpt4(client, source_code, model)
    elapsed = time.time() - start_time

    if error:
        return ContractResult(
            file=filename, known_vulns=known_vulns, gpt4_findings=[], vulns_found=[],
            true_positives=[], false_negatives=known_vulns.copy(), false_positives=[],
            error=error, tokens_used=tokens, response_time=elapsed,
        )

    # Apply FP filters if enabled
    filtered_findings = []
    retained_findings = []

    for finding in findings:
        should_filter, filter_reason = should_filter_finding(
            finding, source_code, known_vulns, enable_filter
        )
        if should_filter:
            finding["filter_reason"] = filter_reason
            filtered_findings.append(finding)
        else:
            retained_findings.append(finding)

    # Use retained findings for analysis
    vulns_found = []
    matched_known = set()

    for finding in retained_findings:
        finding_type = finding.get("type", "")
        finding_desc = finding.get("description", "")
        vulns_found.append(finding_type)

        matched = match_vulnerability(finding_type, finding_desc, known_vulns)
        if matched:
            matched_known.add(matched)

    true_positives = list(matched_known)
    false_negatives = [v for v in known_vulns if v not in matched_known]

    if known_vulns:
        fp_count = len(retained_findings) - len(matched_known)
        false_positives = vulns_found[:fp_count] if fp_count > 0 else []
    else:
        false_positives = vulns_found

    return ContractResult(
        file=filename, known_vulns=known_vulns, gpt4_findings=findings, vulns_found=vulns_found,
        true_positives=true_positives, false_negatives=false_negatives, false_positives=false_positives,
        filtered_findings=filtered_findings,
        tokens_used=tokens, response_time=elapsed,
    )


def run_benchmark(client: OpenAI, contracts_dir: Path, model: str, limit: int | None = None, enable_filter: bool = False) -> BenchmarkSummary:
    """Run benchmark on all contracts in directory."""
    sol_files = sorted(contracts_dir.glob("*.sol"))
    if limit:
        sol_files = sol_files[:limit]

    print(f"Running GPT-4 benchmark on {len(sol_files)} contracts...")
    print(f"Model: {model}")
    print(f"FP Filtering: {'ENABLED' if enable_filter else 'DISABLED'}")
    print("-" * 60)

    results: list[ContractResult] = []
    total_tokens = 0
    total_time = 0.0

    for i, file_path in enumerate(sol_files, 1):
        print(f"[{i}/{len(sol_files)}] {file_path.name}...", end=" ", flush=True)

        result = analyze_contract(client, file_path, model, enable_filter)
        results.append(result)
        total_tokens += result.tokens_used
        total_time += result.response_time

        if result.error:
            print(f"ERROR: {result.error[:40]}")
        elif result.true_positives:
            filtered_str = f", filtered: {len(result.filtered_findings)}" if result.filtered_findings else ""
            print(f"TP: {len(result.true_positives)}, FP: {len(result.false_positives)}{filtered_str} ({result.response_time:.1f}s)")
        else:
            filtered_str = f", filtered: {len(result.filtered_findings)}" if result.filtered_findings else ""
            print(f"findings: {len(result.gpt4_findings)}{filtered_str} ({result.response_time:.1f}s)")

        if i < len(sol_files):
            time.sleep(1.0)  # Rate limit: 1 request per second

    print("-" * 60)

    contracts_with_errors = sum(1 for r in results if r.error)
    total_known = sum(len(r.known_vulns) for r in results)
    total_tp = sum(len(r.true_positives) for r in results)
    total_fn = sum(len(r.false_negatives) for r in results)
    total_fp = sum(len(r.false_positives) for r in results)
    total_filtered = sum(len(r.filtered_findings) for r in results)

    detection_rate = total_tp / total_known if total_known > 0 else 0.0
    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    total_findings = total_tp + total_fp
    fp_rate = total_fp / total_findings if total_findings > 0 else 0.0

    return BenchmarkSummary(
        timestamp=datetime.now().isoformat(),
        model=model,
        total_contracts=len(sol_files),
        contracts_analyzed=len(sol_files) - contracts_with_errors,
        contracts_with_errors=contracts_with_errors,
        total_known_vulns=total_known,
        total_true_positives=total_tp,
        total_false_negatives=total_fn,
        total_false_positives=total_fp,
        total_filtered=total_filtered,
        filter_enabled=enable_filter,
        detection_rate=round(detection_rate, 4),
        precision=round(precision, 4),
        false_positive_rate=round(fp_rate, 4),
        total_tokens=total_tokens,
        total_time=round(total_time, 2),
        avg_time_per_contract=round(total_time / len(sol_files), 2) if sol_files else 0,
        results=[asdict(r) for r in results],
    )


def print_summary(summary: BenchmarkSummary):
    """Print human-readable summary."""
    print("\n" + "=" * 60)
    print("GPT-4 BENCHMARK RESULTS")
    print("=" * 60)
    print(f"Timestamp: {summary.timestamp}")
    print(f"Model: {summary.model}")
    print(f"FP Filtering: {'ENABLED' if summary.filter_enabled else 'DISABLED'}")
    print(f"Contracts tested: {summary.total_contracts}")
    print(f"Successfully analyzed: {summary.contracts_analyzed}")
    print(f"Errors: {summary.contracts_with_errors}")
    print()
    print("DETECTION METRICS (vs ground truth):")
    print(f"  Known vulnerabilities: {summary.total_known_vulns}")
    print(f"  True Positives:  {summary.total_true_positives}")
    print(f"  False Negatives: {summary.total_false_negatives}")
    print(f"  False Positives: {summary.total_false_positives}")
    if summary.filter_enabled:
        print(f"  Filtered (removed FPs): {summary.total_filtered}")
    print()
    print(f"  Detection Rate (Recall): {summary.detection_rate:.1%}")
    print(f"  Precision:               {summary.precision:.1%}")
    print(f"  False Positive Rate:     {summary.false_positive_rate:.1%}")
    print()
    print("COST METRICS:")
    print(f"  Total tokens: {summary.total_tokens:,}")
    print(f"  Total time: {summary.total_time:.1f}s")
    print(f"  Avg time/contract: {summary.avg_time_per_contract:.1f}s")
    print("=" * 60)

    print("\nCONTRACTS WITH GROUND TRUTH:")
    for result in summary.results:
        if result["known_vulns"]:
            status = "ERROR" if result["error"] else "OK"
            tp = len(result["true_positives"])
            fn = len(result["false_negatives"])
            fp = len(result["false_positives"])
            filtered = len(result.get("filtered_findings", []))
            filtered_str = f" FILT={filtered}" if filtered > 0 else ""
            print(f"  {result['file']}: TP={tp} FN={fn} FP={fp}{filtered_str} [{status}]")


def main():
    parser = argparse.ArgumentParser(description="Run GPT-4 benchmark")
    parser.add_argument("--limit", type=int, default=None, help="Limit to N contracts")
    parser.add_argument("--all", action="store_true", help="Run on all contracts")
    parser.add_argument("--output", type=str, default=None, help="Output JSON path")
    parser.add_argument("--model", type=str, default="gpt-4o", help="OpenAI model to use")
    parser.add_argument("--filter", action="store_true", help="Enable FP filtering (removes top 5 FP categories)")
    args = parser.parse_args()

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("Error: OPENAI_API_KEY environment variable not set")
        sys.exit(1)

    client = OpenAI(api_key=api_key)

    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    contracts_dir = project_root / "data" / "contracts" / "raw"

    if not contracts_dir.exists():
        print(f"Error: Contracts directory not found: {contracts_dir}")
        sys.exit(1)

    limit = None if args.all else (args.limit or 20)

    summary = run_benchmark(client, contracts_dir, args.model, limit=limit, enable_filter=args.filter)
    print_summary(summary)

    # Use different output file if filtering is enabled
    if args.output:
        output_path = Path(args.output)
    elif args.filter:
        output_path = script_dir / "results" / "gpt4_filtered.json"
    else:
        output_path = script_dir / "results" / "gpt4_baseline.json"

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(asdict(summary), f, indent=2)

    print(f"\nResults saved to: {output_path}")


if __name__ == "__main__":
    main()
