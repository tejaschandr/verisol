"""SMTChecker formal verification."""

from __future__ import annotations

import re
import shutil
import tempfile
from pathlib import Path

from verisol.config import settings
from verisol.core.contract import Contract
from verisol.core.report import Finding, Severity, VerificationResult, VerifierStatus
from verisol.verifiers.base import BaseVerifier


class SMTCheckerVerifier(BaseVerifier):
    """SMTChecker formal verification using solc's built-in SMT solver."""
    
    name = "smtchecker"
    
    def __init__(self, timeout: int | None = None):
        super().__init__(timeout or settings.smtchecker_timeout)
    
    def is_available(self) -> bool:
        """Check if solc with SMTChecker support is available."""
        # SMTChecker is built into solc, just need solc
        return shutil.which("solc") is not None
    
    async def verify(self, contract: Contract) -> VerificationResult:
        """
        Run SMTChecker formal verification.
        
        Checks for:
        - Arithmetic overflow/underflow
        - Division by zero
        - Assertion violations
        - Unreachable code
        - Out-of-bounds array access
        
        Args:
            contract: Contract to verify
            
        Returns:
            VerificationResult with formal verification findings
        """
        findings = []
        properties_checked = 0
        properties_proven = 0
        
        with tempfile.TemporaryDirectory() as tmpdir:
            contract_path = contract.to_temp_file(Path(tmpdir))
            
            # Run solc with SMTChecker
            # Using CHC engine (Constrained Horn Clauses) - more powerful than BMC
            cmd = [
                "solc",
                "--model-checker-engine=chc",
                "--model-checker-targets=all",  # Check all property types
                "--model-checker-timeout", str(self.timeout * 1000),  # ms
                str(contract_path),
            ]
            
            try:
                returncode, stdout, stderr = await self._run_command(cmd)
            except Exception as e:
                return VerificationResult(
                    verifier=self.name,
                    status=VerifierStatus.ERROR,
                    error_message=f"SMTChecker execution failed: {e}",
                )
            
            output = stdout + stderr
            output_lower = output.lower()

            # Check if SMT solver is actually available
            # Multiple patterns for different solc versions and error messages
            solver_unavailable = (
                "no horn solver was found" in output_lower or
                "no smt solver was found" in output_lower or
                ("solver z3 was selected" in output_lower and "not available" in output_lower) or
                "z3 is not available" in output_lower or
                "smt solver not found" in output_lower
            )

            if solver_unavailable:
                # No solver available - can't do real verification
                return VerificationResult(
                    verifier=self.name,
                    status=VerifierStatus.SKIPPED,
                    findings=[],
                    properties_checked=0,
                    properties_proven=0,
                    raw_output=output,
                    error_message="SMT solver (z3) not available. Install z3 for formal verification.",
                )

            # Parse SMTChecker output
            findings, properties_checked, properties_proven = self._parse_output(output)

            # Check for solver timeout/resource issues
            if "timeout" in output.lower() or "resource limit" in output.lower():
                return VerificationResult(
                    verifier=self.name,
                    status=VerifierStatus.TIMEOUT,
                    findings=findings,
                    properties_checked=properties_checked,
                    properties_proven=properties_proven,
                    raw_output=output,
                    error_message="SMT solver timed out on some properties",
                )
            
            # Determine status
            has_violations = any(
                f.severity in (Severity.CRITICAL, Severity.HIGH)
                for f in findings
            )
            
            return VerificationResult(
                verifier=self.name,
                status=VerifierStatus.FAILED if has_violations else VerifierStatus.PASSED,
                findings=findings,
                properties_checked=properties_checked,
                properties_proven=properties_proven,
                raw_output=output,
            )
    
    def _parse_output(self, output: str) -> tuple[list[Finding], int, int]:
        """
        Parse SMTChecker output for findings and statistics.
        
        Returns:
            Tuple of (findings, properties_checked, properties_proven)
        """
        findings = []
        properties_checked = 0
        properties_proven = 0
        
        lines = output.split("\n")
        
        # Patterns for SMTChecker messages
        warning_pattern = re.compile(
            r"Warning: CHC: ([\w\s]+) (happens here|might happen|violation)",
            re.IGNORECASE
        )
        info_pattern = re.compile(
            r"Info: CHC: ([\w\s]+) check (\w+)",
            re.IGNORECASE
        )
        assertion_pattern = re.compile(
            r"Warning: CHC: Assertion violation",
            re.IGNORECASE
        )
        overflow_pattern = re.compile(
            r"Warning: CHC: (Overflow|Underflow)",
            re.IGNORECASE
        )
        division_pattern = re.compile(
            r"Warning: CHC: Division by zero",
            re.IGNORECASE
        )
        
        current_location = None
        
        for i, line in enumerate(lines):
            # Track file locations
            location_match = re.search(r"([\w/]+\.sol):(\d+):(\d+):", line)
            if location_match:
                current_location = {
                    "file": location_match.group(1),
                    "line_start": int(location_match.group(2)),
                }
            
            # Check for assertion violations
            if assertion_pattern.search(line):
                properties_checked += 1
                findings.append(Finding(
                    id=f"smt-assertion-{len(findings)}",
                    title="Assertion Violation",
                    description="SMTChecker found a possible assertion violation",
                    severity=Severity.HIGH,
                    detector="assertion",
                    verifier=self.name,
                    **(current_location or {}),
                ))
                continue
            
            # Check for overflow/underflow
            overflow_match = overflow_pattern.search(line)
            if overflow_match:
                properties_checked += 1
                issue_type = overflow_match.group(1).lower()
                findings.append(Finding(
                    id=f"smt-{issue_type}-{len(findings)}",
                    title=f"Arithmetic {issue_type.capitalize()}",
                    description=f"SMTChecker detected possible {issue_type}",
                    severity=Severity.HIGH,
                    detector=issue_type,
                    verifier=self.name,
                    **(current_location or {}),
                ))
                continue
            
            # Check for division by zero
            if division_pattern.search(line):
                properties_checked += 1
                findings.append(Finding(
                    id=f"smt-divzero-{len(findings)}",
                    title="Division By Zero",
                    description="SMTChecker detected possible division by zero",
                    severity=Severity.HIGH,
                    detector="division-by-zero",
                    verifier=self.name,
                    **(current_location or {}),
                ))
                continue
            
            # Check for proven properties (Info messages)
            info_match = info_pattern.search(line)
            if info_match:
                properties_checked += 1
                status = info_match.group(2).lower()
                if status in ("safe", "verified", "holds"):
                    properties_proven += 1
            
            # Generic warning handling
            warning_match = warning_pattern.search(line)
            if warning_match and not any(p.search(line) for p in [assertion_pattern, overflow_pattern, division_pattern]):
                properties_checked += 1
                issue_type = warning_match.group(1).strip()
                findings.append(Finding(
                    id=f"smt-{issue_type.lower().replace(' ', '-')}-{len(findings)}",
                    title=issue_type,
                    description=f"SMTChecker warning: {issue_type}",
                    severity=Severity.MEDIUM,
                    detector="generic",
                    verifier=self.name,
                    **(current_location or {}),
                ))
        
        # Don't claim properties were proven if we didn't find explicit evidence
        # The caller should check if solver was available before trusting these numbers

        return findings, properties_checked, properties_proven
