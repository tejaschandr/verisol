#!/usr/bin/env python3
"""
Slither Benchmark Runner

Runs Slither on the vulnerability dataset and compares results against
ground truth to calculate detection rates.

Usage:
    python benchmarks/run_slither.py [--limit N] [--all]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

# Ground truth: maps contract files to expected Slither detectors
# Based on inventory.md vulnerability categorization
GROUND_TRUTH: dict[str, list[str]] = {
    # Vulnerability demonstration contracts
    "ReEntrancy.sol": ["reentrancy-eth", "reentrancy-no-eth", "reentrancy-benign"],
    "ReEntrancyGuard.sol": [],  # Mitigation - should have no reentrancy findings
    "Overflow.sol": [],  # Uses ^0.7.6, Slither may not detect (no SafeMath pattern)
    "TxOrigin.sol": ["tx-origin"],
    "DenialOfService.sol": [],  # DoS via revert - not directly detectable by Slither
    "FrontRunning.sol": [],  # Front-running - not directly detectable by Slither
    "PreventFrontRunning.sol": [],  # Mitigation
    "Delegatecall_1.sol": ["controlled-delegatecall", "delegatecall-loop"],
    "Delegatecall_2.sol": ["controlled-delegatecall", "delegatecall-loop"],
    "ContractSize.sol": [],  # Logic bug, not detectable
    "ForceEther.sol": [],  # Forceful ether - design pattern, not detectable
    "HoneyPot.sol": [],  # Logic trap, not detectable by static analysis
    "Randomness.sol": ["weak-prng"],
    "SigReplay.sol": [],  # Signature replay - not directly detectable
    "PreventSigReplay.sol": [],  # Mitigation
    "VaultInflation.sol": ["divide-before-multiply"],
    "ExternalContract.sol": [],  # Hidden code - not detectable
    "TornadoHack.sol": [],  # Governance attack - complex, not detectable
}

# Map SWC codes to Slither detectors for reference
SWC_TO_SLITHER = {
    "SWC-107": ["reentrancy-eth", "reentrancy-no-eth", "reentrancy-benign"],
    "SWC-101": [],  # Integer overflow - handled by Solidity 0.8+
    "SWC-115": ["tx-origin"],
    "SWC-113": [],  # DoS
    "SWC-114": [],  # Front-running
    "SWC-112": ["controlled-delegatecall", "delegatecall-loop"],
    "SWC-120": ["weak-prng"],
    "SWC-121": [],  # Signature replay
    "SWC-132": [],  # Forceful ether
}


@dataclass
class ContractResult:
    """Result of analyzing a single contract."""
    file: str
    known_vulns: list[str]
    slither_findings: list[dict]
    detectors_found: list[str]
    true_positives: list[str]
    false_negatives: list[str]
    false_positives: list[str]
    error: str | None = None
    compile_error: bool = False


@dataclass
class BenchmarkSummary:
    """Overall benchmark statistics."""
    timestamp: str
    total_contracts: int
    contracts_analyzed: int
    contracts_with_errors: int
    compile_errors: int

    total_known_vulns: int
    total_true_positives: int
    total_false_negatives: int
    total_false_positives: int

    detection_rate: float  # TP / (TP + FN)
    precision: float  # TP / (TP + FP)
    false_positive_rate: float  # FP / total findings

    results: list[dict] = field(default_factory=list)


def run_slither(contract_path: Path, timeout: int = 120) -> tuple[list[dict], str | None]:
    """
    Run Slither on a contract and return findings.

    Returns:
        Tuple of (findings list, error message or None)
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        json_output = Path(tmpdir) / "output.json"

        cmd = [
            "slither",
            str(contract_path),
            "--json", str(json_output),
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=contract_path.parent,
            )
        except subprocess.TimeoutExpired:
            return [], "Timeout"
        except Exception as e:
            return [], f"Execution error: {e}"

        # Parse JSON output
        if json_output.exists():
            try:
                with open(json_output) as f:
                    data = json.load(f)

                findings = data.get("results", {}).get("detectors", [])
                return findings, None

            except json.JSONDecodeError as e:
                return [], f"JSON parse error: {e}"

        # Check for compilation errors
        if "Error" in result.stderr or result.returncode != 0:
            # Check if it's a compilation error
            if "Compilation warnings/errors" in result.stderr:
                return [], "Compilation error"
            return [], result.stderr[:500]

        return [], None


def analyze_contract(file_path: Path) -> ContractResult:
    """Analyze a single contract and compare to ground truth."""
    filename = file_path.name
    known_vulns = GROUND_TRUTH.get(filename, [])

    findings, error = run_slither(file_path)

    if error:
        return ContractResult(
            file=filename,
            known_vulns=known_vulns,
            slither_findings=[],
            detectors_found=[],
            true_positives=[],
            false_negatives=known_vulns.copy(),
            false_positives=[],
            error=error,
            compile_error="Compilation" in str(error),
        )

    # Extract detector names from findings
    detectors_found = list(set(f.get("check", "") for f in findings))

    # Calculate metrics
    known_set = set(known_vulns)
    found_set = set(detectors_found)

    true_positives = list(known_set & found_set)
    false_negatives = list(known_set - found_set)
    false_positives = list(found_set - known_set)

    return ContractResult(
        file=filename,
        known_vulns=known_vulns,
        slither_findings=findings,
        detectors_found=detectors_found,
        true_positives=true_positives,
        false_negatives=false_negatives,
        false_positives=false_positives,
    )


def run_benchmark(contracts_dir: Path, limit: int | None = None) -> BenchmarkSummary:
    """Run benchmark on all contracts in directory."""
    # Get all .sol files
    sol_files = sorted(contracts_dir.glob("*.sol"))

    if limit:
        sol_files = sol_files[:limit]

    print(f"Running Slither benchmark on {len(sol_files)} contracts...")
    print("-" * 60)

    results: list[ContractResult] = []

    for i, file_path in enumerate(sol_files, 1):
        print(f"[{i}/{len(sol_files)}] {file_path.name}...", end=" ", flush=True)

        result = analyze_contract(file_path)
        results.append(result)

        if result.error:
            print(f"ERROR: {result.error[:50]}")
        elif result.true_positives:
            print(f"TP: {len(result.true_positives)}, FP: {len(result.false_positives)}")
        else:
            print(f"findings: {len(result.detectors_found)}")

    print("-" * 60)

    # Calculate summary statistics
    contracts_with_errors = sum(1 for r in results if r.error)
    compile_errors = sum(1 for r in results if r.compile_error)

    total_known = sum(len(r.known_vulns) for r in results)
    total_tp = sum(len(r.true_positives) for r in results)
    total_fn = sum(len(r.false_negatives) for r in results)
    total_fp = sum(len(r.false_positives) for r in results)

    # Detection rate: what fraction of known vulns did we find?
    detection_rate = total_tp / total_known if total_known > 0 else 0.0

    # Precision: what fraction of our findings were correct?
    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0

    # False positive rate: FP / total findings
    total_findings = total_tp + total_fp
    fp_rate = total_fp / total_findings if total_findings > 0 else 0.0

    return BenchmarkSummary(
        timestamp=datetime.now().isoformat(),
        total_contracts=len(sol_files),
        contracts_analyzed=len(sol_files) - contracts_with_errors,
        contracts_with_errors=contracts_with_errors,
        compile_errors=compile_errors,
        total_known_vulns=total_known,
        total_true_positives=total_tp,
        total_false_negatives=total_fn,
        total_false_positives=total_fp,
        detection_rate=round(detection_rate, 4),
        precision=round(precision, 4),
        false_positive_rate=round(fp_rate, 4),
        results=[asdict(r) for r in results],
    )


def print_summary(summary: BenchmarkSummary):
    """Print human-readable summary."""
    print("\n" + "=" * 60)
    print("SLITHER BENCHMARK RESULTS")
    print("=" * 60)
    print(f"Timestamp: {summary.timestamp}")
    print(f"Contracts tested: {summary.total_contracts}")
    print(f"Successfully analyzed: {summary.contracts_analyzed}")
    print(f"Errors: {summary.contracts_with_errors} ({summary.compile_errors} compile errors)")
    print()
    print("DETECTION METRICS (vs ground truth):")
    print(f"  Known vulnerabilities: {summary.total_known_vulns}")
    print(f"  True Positives:  {summary.total_true_positives}")
    print(f"  False Negatives: {summary.total_false_negatives}")
    print(f"  False Positives: {summary.total_false_positives}")
    print()
    print(f"  Detection Rate (Recall): {summary.detection_rate:.1%}")
    print(f"  Precision:               {summary.precision:.1%}")
    print(f"  False Positive Rate:     {summary.false_positive_rate:.1%}")
    print("=" * 60)

    # Show contracts with findings
    print("\nCONTRACTS WITH GROUND TRUTH:")
    for result in summary.results:
        if result["known_vulns"]:
            status = "ERROR" if result["error"] else "OK"
            tp = len(result["true_positives"])
            fn = len(result["false_negatives"])
            fp = len(result["false_positives"])
            print(f"  {result['file']}: TP={tp} FN={fn} FP={fp} [{status}]")


def main():
    parser = argparse.ArgumentParser(description="Run Slither benchmark")
    parser.add_argument("--limit", type=int, default=None, help="Limit to N contracts")
    parser.add_argument("--all", action="store_true", help="Run on all contracts")
    parser.add_argument("--output", type=str, default=None, help="Output JSON path")
    args = parser.parse_args()

    # Determine paths
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    contracts_dir = project_root / "data" / "contracts" / "raw"

    if not contracts_dir.exists():
        print(f"Error: Contracts directory not found: {contracts_dir}")
        sys.exit(1)

    # Set default limit
    limit = None if args.all else (args.limit or 20)

    # Run benchmark
    summary = run_benchmark(contracts_dir, limit=limit)

    # Print results
    print_summary(summary)

    # Save to JSON
    output_path = args.output or (script_dir / "results" / "slither_baseline.json")
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(asdict(summary), f, indent=2)

    print(f"\nResults saved to: {output_path}")


if __name__ == "__main__":
    main()
