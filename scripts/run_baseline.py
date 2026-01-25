#!/usr/bin/env python3
"""
GPT-4 Baseline Evaluation Script

This script evaluates GPT-4's zero-shot smart contract generation capabilities
by generating contracts from specifications and measuring verification pass rates.

Usage:
    python scripts/run_baseline.py --specs data/specs/ --output data/baselines/
    
Requirements:
    - OPENAI_API_KEY environment variable set
    - Verification tools installed (solc, slither)
"""

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from verisol.core.contract import Contract
from verisol.core.report import VerifierStatus
from verisol.pipeline import VerificationPipeline


# Sample specifications for baseline testing
SAMPLE_SPECS = [
    {
        "id": "erc20-basic",
        "description": "Basic ERC20 token with name, symbol, totalSupply, balanceOf, transfer, approve, transferFrom",
        "difficulty": "easy",
    },
    {
        "id": "erc20-mintable",
        "description": "ERC20 token with mint function restricted to owner",
        "difficulty": "easy",
    },
    {
        "id": "erc20-burnable",
        "description": "ERC20 token with burn function allowing holders to destroy their tokens",
        "difficulty": "easy",
    },
    {
        "id": "erc721-basic",
        "description": "Basic ERC721 NFT with mint and transfer functions",
        "difficulty": "medium",
    },
    {
        "id": "vault-simple",
        "description": "Simple vault that accepts ETH deposits and allows withdrawals",
        "difficulty": "easy",
    },
    {
        "id": "vault-timelock",
        "description": "Vault with timelock - deposits can only be withdrawn after a delay",
        "difficulty": "medium",
    },
    {
        "id": "multisig-2of3",
        "description": "2-of-3 multisig wallet requiring 2 signatures to execute transactions",
        "difficulty": "hard",
    },
    {
        "id": "staking-basic",
        "description": "Staking contract where users deposit tokens and earn rewards over time",
        "difficulty": "medium",
    },
    {
        "id": "auction-english",
        "description": "English auction where highest bidder wins after time expires",
        "difficulty": "medium",
    },
    {
        "id": "escrow-simple",
        "description": "Escrow contract with buyer, seller, and arbiter roles",
        "difficulty": "medium",
    },
]


GENERATION_PROMPT = """Generate a Solidity smart contract based on the following specification.

Specification: {description}

Requirements:
1. Use Solidity version 0.8.24
2. Include SPDX license identifier (MIT)
3. Follow best practices for security:
   - Use checks-effects-interactions pattern
   - Validate all inputs
   - Use SafeMath is NOT needed (0.8.x has built-in overflow checks)
   - Include proper access control
4. Include events for state changes
5. Include NatSpec comments

Output ONLY the Solidity code, no explanations. Start with // SPDX-License-Identifier: MIT"""


async def generate_with_gpt4(spec: dict, api_key: str) -> str | None:
    """Generate contract using GPT-4 API."""
    try:
        import httpx
    except ImportError:
        print("Error: httpx not installed. Run: pip install httpx")
        return None
    
    prompt = GENERATION_PROMPT.format(description=spec["description"])
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": "gpt-4-turbo-preview",
                "messages": [
                    {"role": "system", "content": "You are an expert Solidity developer focused on security."},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.7,
                "max_tokens": 4096,
            },
            timeout=60.0,
        )
        
        if response.status_code != 200:
            print(f"API error: {response.status_code} - {response.text}")
            return None
        
        data = response.json()
        content = data["choices"][0]["message"]["content"]
        
        # Extract code if wrapped in markdown
        if "```solidity" in content:
            content = content.split("```solidity")[1].split("```")[0]
        elif "```" in content:
            content = content.split("```")[1].split("```")[0]
        
        return content.strip()
    
    return None


async def evaluate_contract(contract: Contract, pipeline: VerificationPipeline) -> dict:
    """Evaluate a generated contract through the verification pipeline."""
    report = await pipeline.run(contract)
    
    return {
        "compilation_passed": report.compilation and report.compilation.passed,
        "slither_passed": report.slither and report.slither.passed if report.slither else None,
        "smtchecker_passed": report.smtchecker and report.smtchecker.passed if report.smtchecker else None,
        "overall_score": report.overall_score,
        "finding_summary": report.finding_summary,
        "total_duration_ms": report.total_duration_ms,
    }


async def run_baseline(
    specs: list[dict],
    output_dir: Path,
    api_key: str,
    num_samples: int = 3,
) -> dict[str, Any]:
    """
    Run baseline evaluation.
    
    Args:
        specs: List of contract specifications
        output_dir: Directory to save results
        api_key: OpenAI API key
        num_samples: Number of generations per spec
        
    Returns:
        Summary statistics
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    pipeline = VerificationPipeline()
    
    results = []
    total_compilation_passed = 0
    total_slither_passed = 0
    total_smt_passed = 0
    total_generated = 0
    
    for spec in specs:
        print(f"\n{'='*60}")
        print(f"Spec: {spec['id']} ({spec['difficulty']})")
        print(f"{'='*60}")
        
        spec_results = []
        
        for i in range(num_samples):
            print(f"\n  Sample {i+1}/{num_samples}...")
            
            # Generate
            code = await generate_with_gpt4(spec, api_key)
            if not code:
                print(f"    ✗ Generation failed")
                continue
            
            total_generated += 1
            
            # Save generated code
            code_file = output_dir / f"{spec['id']}_sample{i}.sol"
            code_file.write_text(code)
            
            # Evaluate
            contract = Contract.from_text(code, spec["id"])
            eval_result = await evaluate_contract(contract, pipeline)
            
            # Track stats
            if eval_result["compilation_passed"]:
                total_compilation_passed += 1
                print(f"    ✓ Compilation passed")
            else:
                print(f"    ✗ Compilation failed")
            
            if eval_result["slither_passed"]:
                total_slither_passed += 1
                print(f"    ✓ Slither passed")
            elif eval_result["slither_passed"] is not None:
                print(f"    ✗ Slither found issues")
            
            if eval_result["smtchecker_passed"]:
                total_smt_passed += 1
                print(f"    ✓ SMTChecker passed")
            elif eval_result["smtchecker_passed"] is not None:
                print(f"    ✗ SMTChecker found issues")
            
            spec_results.append({
                "sample": i,
                "code_file": str(code_file),
                **eval_result,
            })
        
        results.append({
            "spec": spec,
            "samples": spec_results,
        })
    
    # Compute summary
    summary = {
        "timestamp": datetime.now(UTC).isoformat(),
        "total_specs": len(specs),
        "samples_per_spec": num_samples,
        "total_generated": total_generated,
        "compilation_pass_rate": total_compilation_passed / total_generated if total_generated else 0,
        "slither_pass_rate": total_slither_passed / total_generated if total_generated else 0,
        "smtchecker_pass_rate": total_smt_passed / total_generated if total_generated else 0,
        "results": results,
    }
    
    # Save results
    results_file = output_dir / "baseline_results.json"
    with open(results_file, "w") as f:
        json.dump(summary, f, indent=2)
    
    print(f"\n{'='*60}")
    print("BASELINE SUMMARY")
    print(f"{'='*60}")
    print(f"Total generated: {total_generated}")
    print(f"Compilation pass rate: {summary['compilation_pass_rate']:.1%}")
    print(f"Slither pass rate: {summary['slither_pass_rate']:.1%}")
    print(f"SMTChecker pass rate: {summary['smtchecker_pass_rate']:.1%}")
    print(f"\nResults saved to: {results_file}")
    
    return summary


def main():
    parser = argparse.ArgumentParser(description="Run GPT-4 baseline evaluation")
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=Path("data/baselines"),
        help="Output directory for results",
    )
    parser.add_argument(
        "--samples", "-n",
        type=int,
        default=3,
        help="Number of samples per specification",
    )
    parser.add_argument(
        "--specs-file",
        type=Path,
        help="JSON file with custom specifications",
    )
    
    args = parser.parse_args()
    
    # Check API key
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("Error: OPENAI_API_KEY environment variable not set")
        print("Set it with: export OPENAI_API_KEY=sk-...")
        sys.exit(1)
    
    # Load specs
    if args.specs_file and args.specs_file.exists():
        with open(args.specs_file) as f:
            specs = json.load(f)
    else:
        specs = SAMPLE_SPECS
    
    print(f"Running baseline with {len(specs)} specifications, {args.samples} samples each")
    
    # Run evaluation
    asyncio.run(run_baseline(
        specs=specs,
        output_dir=args.output,
        api_key=api_key,
        num_samples=args.samples,
    ))


if __name__ == "__main__":
    main()
