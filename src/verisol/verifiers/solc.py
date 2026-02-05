"""Solidity compiler verification."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from verisol.config import settings
from verisol.core.contract import Contract
from verisol.core.report import Finding, Severity, VerificationResult, VerifierStatus
from verisol.verifiers.base import BaseVerifier


def _resolve_solc_version(pragma: str | None) -> str | None:
    """Resolve a pragma version spec to an exact installable version.

    Handles ``0.8.15``, ``^0.8.15``, ``>=0.8.0 <0.9.0``, etc.
    Returns the exact version string (e.g. ``"0.8.15"``) or ``None``.
    """
    if not pragma:
        return None
    # Exact version: "0.8.15"
    exact = re.match(r"^(\d+\.\d+\.\d+)$", pragma.strip())
    if exact:
        return exact.group(1)
    # Caret: "^0.8.15" — use that exact version
    caret = re.match(r"^\^(\d+\.\d+\.\d+)$", pragma.strip())
    if caret:
        return caret.group(1)
    # Range: ">=0.8.0 <0.9.0" — use the lower bound
    rng = re.match(r"^>=?\s*(\d+\.\d+\.\d+)", pragma.strip())
    if rng:
        return rng.group(1)
    return None


def _ensure_solc_version(version: str) -> bool:
    """Install and activate a solc version via solc-select. Returns True on success."""
    try:
        # Check if already installed
        result = subprocess.run(
            ["solc-select", "versions"],
            capture_output=True, text=True, timeout=10,
        )
        if version in result.stdout:
            subprocess.run(
                ["solc-select", "use", version],
                capture_output=True, text=True, timeout=10,
            )
            return True
        # Install then use
        install = subprocess.run(
            ["solc-select", "install", version],
            capture_output=True, text=True, timeout=120,
        )
        if install.returncode != 0:
            return False
        subprocess.run(
            ["solc-select", "use", version],
            capture_output=True, text=True, timeout=10,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


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

        # Auto-select solc version based on pragma
        target_version = _resolve_solc_version(contract.solidity_version)
        if target_version:
            _ensure_solc_version(target_version)

        # Write contract source(s) to temp directory
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            contract_path, remappings = contract.write_source_project(tmpdir_path)

            # Run solc
            cmd = [
                "solc",
                "--optimize",
                "--bin",
                "--abi",
            ]
            # Add remappings for multi-file contracts
            for remap in remappings:
                cmd.append(remap)
            if remappings:
                cmd.extend(["--base-path", str(tmpdir_path)])
                cmd.extend(["--allow-paths", str(tmpdir_path)])
            cmd.append(str(contract_path))

            try:
                returncode, stdout, stderr = await self._run_command(
                    cmd, cwd=tmpdir_path,
                )
            except Exception as e:
                return VerificationResult(
                    verifier=self.name,
                    status=VerifierStatus.ERROR,
                    error_message=str(e),
                )

            # Retry with --via-ir if "Stack too deep"
            output = stdout + stderr
            if returncode != 0 and "Stack too deep" in output:
                ir_cmd = cmd[:-1] + ["--via-ir"] + cmd[-1:]
                try:
                    returncode, stdout, stderr = await self._run_command(
                        ir_cmd, cwd=tmpdir_path,
                    )
                    output = stdout + stderr
                except Exception:
                    pass  # Fall through to normal error handling

            # Parse output for warnings/errors

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
