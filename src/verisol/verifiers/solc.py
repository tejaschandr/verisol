"""Solidity compiler verification."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from verisol.config import settings
from verisol.core.contract import Contract
from verisol.core.report import Finding, Severity, VerificationResult, VerifierStatus
from verisol.verifiers.base import BaseVerifier


class SolcVerifier(BaseVerifier):
    """Verify contract compiles with solc."""
    
    name = "solc"
    timeout = 30
    
    def __init__(self, solc_version: str | None = None, timeout: int | None = None):
        super().__init__(timeout)
        self.solc_version = solc_version or settings.solc_version
    
    def is_available(self) -> bool:
        """Check if solc is installed."""
        return shutil.which("solc") is not None
    
    async def verify(self, contract: Contract) -> VerificationResult:
        """
        Compile contract and check for errors/warnings.
        
        Args:
            contract: Contract to compile
            
        Returns:
            VerificationResult with compilation status
        """
        findings = []
        
        # Write contract to temp file
        with tempfile.TemporaryDirectory() as tmpdir:
            contract_path = contract.to_temp_file(Path(tmpdir))
            
            # Run solc
            cmd = [
                "solc",
                "--optimize",
                "--bin",
                "--abi",
                str(contract_path),
            ]
            
            try:
                returncode, stdout, stderr = await self._run_command(cmd)
            except Exception as e:
                return VerificationResult(
                    verifier=self.name,
                    status=VerifierStatus.ERROR,
                    error_message=str(e),
                )
            
            # Parse output for warnings/errors
            output = stdout + stderr
            
            # Check for compilation errors
            if returncode != 0 or "Error:" in output:
                findings.append(Finding(
                    id=f"{self.name}-compile-error",
                    title="Compilation Failed",
                    description=self._extract_error(output),
                    severity=Severity.CRITICAL,
                    detector="compilation",
                    verifier=self.name,
                ))
                return VerificationResult(
                    verifier=self.name,
                    status=VerifierStatus.FAILED,
                    findings=findings,
                    raw_output=output,
                )
            
            # Parse warnings
            findings.extend(self._parse_warnings(output))

            # Only fail for high/critical findings, not INFO-level warnings
            has_critical = any(
                f.severity in (Severity.CRITICAL, Severity.HIGH)
                for f in findings
            )

            return VerificationResult(
                verifier=self.name,
                status=VerifierStatus.FAILED if has_critical else VerifierStatus.PASSED,
                findings=findings,
                raw_output=output,
            )
    
    def _extract_error(self, output: str) -> str:
        """Extract the main error message from compiler output."""
        lines = output.split("\n")
        error_lines = []
        capture = False
        
        for line in lines:
            if "Error:" in line:
                capture = True
            if capture:
                error_lines.append(line)
                if line.strip() == "" and error_lines:
                    break
        
        return "\n".join(error_lines[:10]) if error_lines else output[:500]
    
    def _parse_warnings(self, output: str) -> list[Finding]:
        """Parse compiler warnings into findings."""
        findings = []
        lines = output.split("\n")
        
        i = 0
        while i < len(lines):
            line = lines[i]
            
            if "Warning:" in line:
                # Extract warning details
                warning_type = "general"
                if "SPDX" in line:
                    warning_type = "spdx-missing"
                elif "visibility" in line.lower():
                    warning_type = "visibility"
                elif "unused" in line.lower():
                    warning_type = "unused-variable"
                
                findings.append(Finding(
                    id=f"{self.name}-{warning_type}-{len(findings)}",
                    title=f"Compiler Warning: {warning_type}",
                    description=line.strip(),
                    severity=Severity.INFO,
                    detector="compilation",
                    verifier=self.name,
                ))
            
            i += 1
        
        return findings
