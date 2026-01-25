#!/usr/bin/env python3
"""
DeFiVulnLabs Real-World Validation Benchmark

Tests VeriSol on contracts from DeFiVulnLabs - a more realistic
test set than educational contracts.

Usage:
    python benchmarks/run_defivulnlabs.py [--limit N] [--all]
"""

from __future__ import annotations

import argparse
import asyncio
import json
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
# All contracts from DeFiVulnLabs have known vulnerabilities
GROUND_TRUTH: dict[str, list[str]] = {
    "Reentrancy.sol": ["reentrancy"],
    "Delegatecall.sol": ["delegatecall"],
    "TxOrigin.sol": ["tx.origin", "tx-origin"],
    "DOS.sol": ["denial-of-service", "dos"],
    "Overflow.sol": ["integer-overflow", "overflow"],
    "Selfdestruct.sol": ["selfdestruct", "force-ether"],
    "Visibility.sol": ["access-control", "visibility"],
    "Randomness.sol": ["randomness", "weak-randomness"],
    "SignatureReplay.sol": ["signature-replay", "replay"],
    "PrivateData.sol": ["private-data", "storage"],
    "BypassContract.sol": ["contract-size", "iscontract"],
    "Backdoor.sol": ["backdoor", "hidden-code", "rug-pull"],
    "PriceManipulation.sol": ["price-manipulation", "oracle", "flash-loan"],
    "UnsafeCall.sol": ["unsafe-call", "arbitrary-call"],
    "PrecisionLoss.sol": ["precision-loss", "rounding"],
    "FirstDeposit.sol": ["first-deposit", "inflation", "vault-inflation"],
    "OracleStale.sol": ["oracle-stale", "stale-price", "oracle"],
    "ReadOnlyReentrancy.sol": ["read-only-reentrancy", "reentrancy"],
    "UnprotectedCallback.sol": ["callback", "reentrancy", "erc721"],
    "DataLocation.sol": ["data-location", "storage-memory"],
    "StorageCollision.sol": ["storage-collision", "proxy"],
    "DivideBeforeMultiply.sol": ["precision", "divide-before-multiply"],
    "Ecrecover.sol": ["ecrecover", "signature"],
    "UninitializedProxy.sol": ["uninitialized", "proxy", "access-control"],
}

# Keywords to match findings to ground truth
VULN_KEYWORDS = {
    "reentrancy": ["reentrancy", "re-entrancy", "reentrant", "external call before state"],
    "delegatecall": ["delegatecall", "delegate call", "proxy"],
    "tx.origin": ["tx.origin", "origin"],
    "tx-origin": ["tx.origin"],
    "denial-of-service": ["denial of service", "dos", "unbounded", "loop"],
    "dos": ["dos", "denial", "block"],
    "integer-overflow": ["overflow", "underflow", "integer overflow"],
    "overflow": ["overflow", "underflow"],
    "selfdestruct": ["selfdestruct", "self-destruct", "suicide"],
    "force-ether": ["force ether", "selfdestruct", "balance manipulation"],
    "access-control": ["access control", "missing modifier", "onlyowner", "unauthorized"],
    "visibility": ["visibility", "public", "external", "private"],
    "randomness": ["randomness", "random", "block.timestamp", "blockhash", "predictable"],
    "weak-randomness": ["weak random", "predictable"],
    "signature-replay": ["replay", "signature replay", "nonce"],
    "replay": ["replay"],
    "private-data": ["private data", "storage slot", "readable"],
    "storage": ["storage", "slot"],
    "contract-size": ["extcodesize", "contract size", "iscontract", "code length"],
    "iscontract": ["iscontract", "extcodesize"],
    "backdoor": ["backdoor", "hidden", "assembly", "sstore", "sload"],
    "hidden-code": ["hidden code", "malicious", "backdoor"],
    "rug-pull": ["rug pull", "admin", "backdoor"],
    "price-manipulation": ["price manipulation", "flash loan", "spot price", "balanceof"],
    "oracle": ["oracle", "price feed", "chainlink"],
    "flash-loan": ["flash loan", "flashloan"],
    "unsafe-call": ["unsafe call", "arbitrary call", "low level call"],
    "arbitrary-call": ["arbitrary", "call", "extradata"],
    "precision-loss": ["precision loss", "rounding", "truncation"],
    "rounding": ["rounding", "round down", "precision"],
    "first-deposit": ["first deposit", "share inflation", "donation"],
    "inflation": ["inflation", "share inflation"],
    "vault-inflation": ["vault inflation", "first deposit"],
    "oracle-stale": ["stale", "outdated", "oracle"],
    "stale-price": ["stale price", "updatedAt"],
    "read-only-reentrancy": ["read-only reentrancy", "view reentrancy"],
    "callback": ["callback", "onERC721Received", "safemint"],
    "erc721": ["erc721", "nft", "safemint"],
    "data-location": ["data location", "memory", "storage"],
    "storage-memory": ["storage", "memory", "reference"],
    "storage-collision": ["storage collision", "slot collision", "proxy"],
    "proxy": ["proxy", "delegatecall", "implementation"],
    "precision": ["precision", "divide", "multiply"],
    "divide-before-multiply": ["divide before multiply", "truncation"],
    "ecrecover": ["ecrecover", "address(0)", "signature verification"],
    "signature": ["signature", "ecrecover", "signer"],
    "uninitialized": ["uninitialized", "initialize", "not initialized"],
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
    dataset: str
    total_contracts: int
    contracts_analyzed: int
    contracts_with_errors: int
    total_known_vulns: int
    total_true_positives: int
    total_false_negatives: int
    total_false_positives: int
    detection_rate: float  # recall
    precision: float
    f1_score: float
    total_time: float
    avg_time_per_contract: float
    # Per-vulnerability type breakdown
    vuln_type_results: dict = field(default_factory=dict)
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

    return ContractResult(
        file=filename, known_vulns=known_vulns, findings=findings, vulns_found=vulns_found,
        true_positives=true_positives, false_negatives=false_negatives, false_positives=false_positives,
        response_time=elapsed,
    )


async def run_benchmark(
    contracts_dir: Path,
    model: str,
    limit: int | None = None,
) -> BenchmarkSummary:
    """Run benchmark on all contracts in directory."""
    sol_files = sorted(contracts_dir.glob("*.sol"))
    if limit:
        sol_files = sol_files[:limit]

    print(f"\n{'='*60}")
    print("DEFIVULNLABS REAL-WORLD VALIDATION BENCHMARK")
    print(f"{'='*60}")
    print(f"Contracts: {len(sol_files)}")
    print(f"Model: {model}")
    print("-" * 60)

    verifier = LLMVerifier(
        provider="openai",
        model=model,
        enable_filters=True,
    )

    if not verifier.is_available():
        print("Error: No API key configured for OpenAI")
        sys.exit(1)

    results: list[ContractResult] = []
    total_time = 0.0

    for i, file_path in enumerate(sol_files, 1):
        print(f"[{i}/{len(sol_files)}] {file_path.name}...", end=" ", flush=True)

        result = await analyze_contract(verifier, file_path)
        results.append(result)
        total_time += result.response_time

        if result.error:
            print(f"ERROR: {result.error[:40]}")
        elif result.true_positives:
            print(f"✓ DETECTED: {result.true_positives} ({result.response_time:.1f}s)")
        elif result.false_negatives:
            print(f"✗ MISSED: {result.false_negatives} ({result.response_time:.1f}s)")
        else:
            print(f"findings: {len(result.findings)} ({result.response_time:.1f}s)")

        if i < len(sol_files):
            await asyncio.sleep(2.0)  # Rate limit

    print("-" * 60)

    # Calculate metrics
    contracts_with_errors = sum(1 for r in results if r.error)
    total_known = sum(len(r.known_vulns) for r in results)
    total_tp = sum(len(r.true_positives) for r in results)
    total_fn = sum(len(r.false_negatives) for r in results)
    total_fp = sum(len(r.false_positives) for r in results)

    detection_rate = total_tp / total_known if total_known > 0 else 0.0
    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    f1 = 2 * (precision * detection_rate) / (precision + detection_rate) if (precision + detection_rate) > 0 else 0.0

    # Per-vulnerability type breakdown
    vuln_type_results = {}
    for result in results:
        for vuln in result.known_vulns:
            if vuln not in vuln_type_results:
                vuln_type_results[vuln] = {"total": 0, "detected": 0}
            vuln_type_results[vuln]["total"] += 1
            if vuln in result.true_positives or any(v in result.true_positives for v in GROUND_TRUTH.get(result.file, [])):
                vuln_type_results[vuln]["detected"] += 1

    return BenchmarkSummary(
        timestamp=datetime.now().isoformat(),
        model=model,
        dataset="DeFiVulnLabs",
        total_contracts=len(sol_files),
        contracts_analyzed=len(sol_files) - contracts_with_errors,
        contracts_with_errors=contracts_with_errors,
        total_known_vulns=total_known,
        total_true_positives=total_tp,
        total_false_negatives=total_fn,
        total_false_positives=total_fp,
        detection_rate=round(detection_rate, 4),
        precision=round(precision, 4),
        f1_score=round(f1, 4),
        total_time=round(total_time, 2),
        avg_time_per_contract=round(total_time / len(sol_files), 2) if sol_files else 0,
        vuln_type_results=vuln_type_results,
        results=[asdict(r) for r in results],
    )


def print_summary(summary: BenchmarkSummary):
    """Print human-readable summary."""
    print("\n" + "=" * 60)
    print("DEFIVULNLABS BENCHMARK RESULTS")
    print("=" * 60)
    print(f"Timestamp: {summary.timestamp}")
    print(f"Model: {summary.model}")
    print(f"Dataset: {summary.dataset}")
    print(f"Contracts tested: {summary.total_contracts}")
    print(f"Successfully analyzed: {summary.contracts_analyzed}")
    print(f"Errors: {summary.contracts_with_errors}")
    print()
    print("DETECTION METRICS:")
    print(f"  Known vulnerabilities: {summary.total_known_vulns}")
    print(f"  True Positives:  {summary.total_true_positives}")
    print(f"  False Negatives: {summary.total_false_negatives}")
    print(f"  False Positives: {summary.total_false_positives}")
    print()
    print(f"  Recall (Detection Rate): {summary.detection_rate:.1%}")
    print(f"  Precision:               {summary.precision:.1%}")
    print(f"  F1 Score:                {summary.f1_score:.1%}")
    print()

    print("COMPARISON TO EDUCATIONAL BENCHMARK:")
    print("  Educational: 86.7% precision, 86.7% recall")
    print(f"  Real-World:  {summary.precision:.1%} precision, {summary.detection_rate:.1%} recall")
    print()

    print("PER-CONTRACT RESULTS:")
    for result in summary.results:
        status = "ERROR" if result["error"] else ("✓" if result["true_positives"] else "✗")
        vulns = result["known_vulns"]
        detected = result["true_positives"]
        missed = result["false_negatives"]
        print(f"  {status} {result['file']}")
        if detected:
            print(f"      Detected: {detected}")
        if missed:
            print(f"      Missed: {missed}")

    print()
    print("VULNERABILITY TYPES THAT NEED MORE FEW-SHOT EXAMPLES:")
    missed_types = []
    for result in summary.results:
        if result["false_negatives"]:
            missed_types.extend(result["false_negatives"])

    if missed_types:
        from collections import Counter
        counts = Counter(missed_types)
        for vuln_type, count in counts.most_common():
            print(f"  - {vuln_type}: missed {count} time(s)")
    else:
        print("  None - all vulnerability types detected!")

    print("=" * 60)


async def main():
    parser = argparse.ArgumentParser(description="Run DeFiVulnLabs benchmark")
    parser.add_argument("--limit", type=int, default=None, help="Limit to N contracts")
    parser.add_argument("--all", action="store_true", help="Run on all contracts")
    parser.add_argument("--output", type=str, default=None, help="Output JSON path")
    parser.add_argument("--model", type=str, default="gpt-4o", help="OpenAI model to use")
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
    contracts_dir = project_root / "data" / "contracts" / "defivulnlabs"

    if not contracts_dir.exists():
        print(f"Error: Contracts directory not found: {contracts_dir}")
        print("Run this script from the project root after downloading contracts.")
        sys.exit(1)

    limit = None if args.all else (args.limit or 20)

    summary = await run_benchmark(contracts_dir, args.model, limit=limit)
    print_summary(summary)

    # Save results
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = script_dir / "results" / "defivulnlabs.json"

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(asdict(summary), f, indent=2)

    print(f"\nResults saved to: {output_path}")


if __name__ == "__main__":
    asyncio.run(main())
