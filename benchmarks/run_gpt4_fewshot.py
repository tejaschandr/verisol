#!/usr/bin/env python3
"""
GPT-4 Few-Shot Benchmark Runner

Uses the LLMVerifier with few-shot examples from the main codebase.
Compares results against baseline to measure precision/recall improvements.

Usage:
    python benchmarks/run_gpt4_fewshot.py [--limit N] [--all] [--filter]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from verisol.core.contract import Contract
from verisol.verifiers.llm import LLMVerifier

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

# Keywords to match findings to ground truth
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


@dataclass
class ContractResult:
    file: str
    known_vulns: list[str]
    findings: list[dict]
    vulns_found: list[str]
    true_positives: list[str]
    false_negatives: list[str]
    false_positives: list[str]
    error: str | None = None
    tokens_used: int = 0
    response_time: float = 0.0


@dataclass
class BenchmarkSummary:
    timestamp: str
    model: str
    prompt_type: str  # "few-shot" or "baseline"
    total_contracts: int
    contracts_analyzed: int
    contracts_with_errors: int
    total_known_vulns: int
    total_true_positives: int
    total_false_negatives: int
    total_false_positives: int
    filter_enabled: bool
    detection_rate: float  # recall
    precision: float
    f1_score: float
    total_tokens: int
    total_time: float
    avg_time_per_contract: float
    results: list[dict] = field(default_factory=list)


def match_vulnerability(finding_type: str, finding_desc: str, known_vulns: list[str]) -> str | None:
    """Check if a finding matches any known vulnerability."""
    finding_text = f"{finding_type} {finding_desc}".lower()

    for known_vuln in known_vulns:
        keywords = VULN_KEYWORDS.get(known_vuln, [known_vuln])
        for keyword in keywords:
            if keyword.lower() in finding_text:
                return known_vuln
    return None


async def analyze_contract(verifier: LLMVerifier, file_path: Path) -> ContractResult:
    """Analyze a single contract and compare to ground truth."""
    filename = file_path.name
    known_vulns = GROUND_TRUTH.get(filename, [])

    try:
        source_code = file_path.read_text()
    except Exception as e:
        return ContractResult(
            file=filename, known_vulns=known_vulns, findings=[], vulns_found=[],
            true_positives=[], false_negatives=known_vulns.copy(), false_positives=[],
            error=f"Read error: {e}",
        )

    contract = Contract.from_text(source_code, name=filename)

    start_time = time.time()
    result = await verifier.verify(contract)
    elapsed = time.time() - start_time

    if result.error_message:
        return ContractResult(
            file=filename, known_vulns=known_vulns, findings=[], vulns_found=[],
            true_positives=[], false_negatives=known_vulns.copy(), false_positives=[],
            error=result.error_message, response_time=elapsed,
        )

    # Convert findings to dict format
    findings = []
    for f in result.findings:
        findings.append({
            "type": f.detector,
            "severity": f.severity.value,
            "title": f.title,
            "description": f.description,
            "line_number": f.line_start,
            "confidence": f.confidence.value,
        })

    # Analyze results
    vulns_found = []
    matched_known = set()

    for finding in findings:
        finding_type = finding.get("type", "")
        finding_desc = finding.get("description", "")
        vulns_found.append(finding_type)

        matched = match_vulnerability(finding_type, finding_desc, known_vulns)
        if matched:
            matched_known.add(matched)

    true_positives = list(matched_known)
    false_negatives = [v for v in known_vulns if v not in matched_known]

    if known_vulns:
        fp_count = len(findings) - len(matched_known)
        false_positives = vulns_found[:fp_count] if fp_count > 0 else []
    else:
        false_positives = vulns_found

    # Extract token count from raw_output if available
    tokens = 0
    if result.raw_output and "Tokens:" in result.raw_output:
        try:
            tokens = int(result.raw_output.split("Tokens:")[1].split(".")[0].strip())
        except (ValueError, IndexError):
            pass

    return ContractResult(
        file=filename, known_vulns=known_vulns, findings=findings, vulns_found=vulns_found,
        true_positives=true_positives, false_negatives=false_negatives, false_positives=false_positives,
        tokens_used=tokens, response_time=elapsed,
    )


async def run_benchmark(
    contracts_dir: Path,
    model: str,
    limit: int | None = None,
    enable_filter: bool = True,
) -> BenchmarkSummary:
    """Run benchmark on all contracts in directory."""
    sol_files = sorted(contracts_dir.glob("*.sol"))
    if limit:
        sol_files = sol_files[:limit]

    print(f"\nRunning GPT-4 Few-Shot Benchmark on {len(sol_files)} contracts...")
    print(f"Model: {model}")
    print(f"FP Filtering: {'ENABLED' if enable_filter else 'DISABLED'}")
    print("-" * 60)

    verifier = LLMVerifier(
        provider="openai",
        model=model,
        enable_filters=enable_filter,
    )

    if not verifier.is_available():
        print("Error: No API key configured for OpenAI")
        sys.exit(1)

    results: list[ContractResult] = []
    total_tokens = 0
    total_time = 0.0

    for i, file_path in enumerate(sol_files, 1):
        print(f"[{i}/{len(sol_files)}] {file_path.name}...", end=" ", flush=True)

        result = await analyze_contract(verifier, file_path)
        results.append(result)
        total_tokens += result.tokens_used
        total_time += result.response_time

        if result.error:
            print(f"ERROR: {result.error[:40]}")
        elif result.true_positives:
            print(f"TP: {len(result.true_positives)}, FP: {len(result.false_positives)} ({result.response_time:.1f}s)")
        else:
            print(f"findings: {len(result.findings)} ({result.response_time:.1f}s)")

        if i < len(sol_files):
            await asyncio.sleep(2.0)  # Rate limit - 2 seconds between requests

    print("-" * 60)

    contracts_with_errors = sum(1 for r in results if r.error)
    total_known = sum(len(r.known_vulns) for r in results)
    total_tp = sum(len(r.true_positives) for r in results)
    total_fn = sum(len(r.false_negatives) for r in results)
    total_fp = sum(len(r.false_positives) for r in results)

    detection_rate = total_tp / total_known if total_known > 0 else 0.0
    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    f1 = 2 * (precision * detection_rate) / (precision + detection_rate) if (precision + detection_rate) > 0 else 0.0

    return BenchmarkSummary(
        timestamp=datetime.now().isoformat(),
        model=model,
        prompt_type="few-shot",
        total_contracts=len(sol_files),
        contracts_analyzed=len(sol_files) - contracts_with_errors,
        contracts_with_errors=contracts_with_errors,
        total_known_vulns=total_known,
        total_true_positives=total_tp,
        total_false_negatives=total_fn,
        total_false_positives=total_fp,
        filter_enabled=enable_filter,
        detection_rate=round(detection_rate, 4),
        precision=round(precision, 4),
        f1_score=round(f1, 4),
        total_tokens=total_tokens,
        total_time=round(total_time, 2),
        avg_time_per_contract=round(total_time / len(sol_files), 2) if sol_files else 0,
        results=[asdict(r) for r in results],
    )


def print_summary(summary: BenchmarkSummary):
    """Print human-readable summary."""
    print("\n" + "=" * 60)
    print("GPT-4 FEW-SHOT BENCHMARK RESULTS")
    print("=" * 60)
    print(f"Timestamp: {summary.timestamp}")
    print(f"Model: {summary.model}")
    print(f"Prompt Type: {summary.prompt_type}")
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
    print()
    print(f"  Recall (Detection Rate): {summary.detection_rate:.1%}")
    print(f"  Precision:               {summary.precision:.1%}")
    print(f"  F1 Score:                {summary.f1_score:.1%}")
    print()
    print("COMPARISON TO BASELINE:")
    print("  Baseline: 8.3% precision, 60.9% recall, 14.8% F1")
    precision_delta = (summary.precision - 0.083) / 0.083 * 100
    recall_delta = (summary.detection_rate - 0.609) / 0.609 * 100
    f1_delta = (summary.f1_score - 0.148) / 0.148 * 100
    print(f"  Precision change: {precision_delta:+.1f}%")
    print(f"  Recall change:    {recall_delta:+.1f}%")
    print(f"  F1 change:        {f1_delta:+.1f}%")
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
            print(f"  {result['file']}: TP={tp} FN={fn} FP={fp} [{status}]")


async def main():
    parser = argparse.ArgumentParser(description="Run GPT-4 few-shot benchmark")
    parser.add_argument("--limit", type=int, default=None, help="Limit to N contracts")
    parser.add_argument("--all", action="store_true", help="Run on all contracts")
    parser.add_argument("--output", type=str, default=None, help="Output JSON path")
    parser.add_argument("--model", type=str, default="gpt-4o", help="OpenAI model to use")
    parser.add_argument("--no-filter", action="store_true", help="Disable FP filtering")
    args = parser.parse_args()

    # Load .env
    try:
        from dotenv import load_dotenv
        env_path = Path(__file__).parent.parent / ".env"
        load_dotenv(env_path)
    except ImportError:
        pass

    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    contracts_dir = project_root / "data" / "contracts" / "raw"

    if not contracts_dir.exists():
        print(f"Error: Contracts directory not found: {contracts_dir}")
        sys.exit(1)

    limit = None if args.all else (args.limit or 20)

    summary = await run_benchmark(
        contracts_dir,
        args.model,
        limit=limit,
        enable_filter=not args.no_filter,
    )
    print_summary(summary)

    # Save results
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = script_dir / "results" / "gpt4_fewshot.json"

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(asdict(summary), f, indent=2)

    print(f"\nResults saved to: {output_path}")


if __name__ == "__main__":
    asyncio.run(main())
