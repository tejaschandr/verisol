"""Slither static analysis verifier."""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from verisol.config import settings
from verisol.core.contract import Contract
from verisol.core.report import Confidence, Finding, Severity, VerificationResult, VerifierStatus
from verisol.verifiers.base import BaseVerifier


# Map Slither impact levels to our severity
SLITHER_SEVERITY_MAP = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
    "Optimization": Severity.INFO,
}

# High-signal detectors (prioritize these)
HIGH_SIGNAL_DETECTORS = {
    "reentrancy-eth",
    "reentrancy-no-eth",
    "reentrancy-benign",
    "arbitrary-send-eth",
    "arbitrary-send-erc20",
    "controlled-delegatecall",
    "delegatecall-loop",
    "msg-value-loop",
    "unchecked-transfer",
    "unchecked-lowlevel",
    "unchecked-send",
    "uninitialized-state",
    "uninitialized-storage",
    "uninitialized-local",
    "tx-origin",
    "suicidal",
    "locked-ether",
    "incorrect-equality",
    "shadowing-state",
    "weak-prng",
    "divide-before-multiply",
    "missing-zero-check",
}


class SlitherVerifier(BaseVerifier):
    """Slither static analysis verification."""
    
    name = "slither"
    
    def __init__(self, timeout: int | None = None):
        super().__init__(timeout or settings.slither_timeout)
    
    def is_available(self) -> bool:
        """Check if slither is installed."""
        return shutil.which("slither") is not None
    
    async def verify(self, contract: Contract) -> VerificationResult:
        """
        Run Slither analysis on contract.
        
        Args:
            contract: Contract to analyze
            
        Returns:
            VerificationResult with static analysis findings
        """
        from verisol.verifiers.solc import _resolve_solc_version, _ensure_solc_version

        findings = []

        # Auto-select solc version based on pragma
        target_version = _resolve_solc_version(contract.solidity_version)
        if target_version:
            _ensure_solc_version(target_version)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            contract_path, remappings = contract.write_source_project(tmpdir_path)
            json_output = tmpdir_path / "slither-output.json"

            # Run slither with JSON output
            cmd = [
                "slither",
                str(contract_path),
                "--json", str(json_output),
                "--exclude-informational",  # Skip low-signal findings for now
                "--exclude-optimization",
            ]
            # Pass remappings for multi-file contracts
            if remappings:
                cmd.extend(["--solc-remaps", " ".join(remappings)])

            try:
                returncode, stdout, stderr = await self._run_command(cmd, cwd=tmpdir_path)
            except Exception as e:
                return VerificationResult(
                    verifier=self.name,
                    status=VerifierStatus.ERROR,
                    error_message=f"Slither execution failed: {e}",
                )

            # Retry with --via-ir if Slither's internal solc hit Stack too deep
            if "Stack too deep" in (stdout + stderr):
                ir_cmd = cmd + ["--solc-args", "--via-ir --optimize"]
                try:
                    returncode, stdout, stderr = await self._run_command(
                        ir_cmd, cwd=tmpdir_path,
                    )
                except Exception:
                    pass  # Fall through to normal error handling

            # Parse JSON output
            if json_output.exists():
                try:
                    with open(json_output) as f:
                        results = json.load(f)
                    
                    findings = self._parse_results(results)
                    
                except json.JSONDecodeError as e:
                    return VerificationResult(
                        verifier=self.name,
                        status=VerifierStatus.ERROR,
                        error_message=f"Failed to parse Slither output: {e}",
                        raw_output=stderr,
                    )
            elif "error" in stderr.lower() or returncode != 0:
                # Slither failed (likely compilation issue)
                return VerificationResult(
                    verifier=self.name,
                    status=VerifierStatus.ERROR,
                    error_message=stderr[:1000],
                    raw_output=stderr,
                )
            
            # Determine status based on findings
            has_high_severity = any(
                f.severity in (Severity.CRITICAL, Severity.HIGH) 
                for f in findings
            )
            
            return VerificationResult(
                verifier=self.name,
                status=VerifierStatus.FAILED if has_high_severity else VerifierStatus.PASSED,
                findings=findings,
                raw_output=stdout + stderr,
            )
    
    def _parse_results(self, results: dict) -> list[Finding]:
        """Parse Slither JSON output into findings."""
        findings = []

        detectors = results.get("results", {}).get("detectors", [])

        for i, detector in enumerate(detectors):
            check = detector.get("check", "unknown")
            impact = detector.get("impact", "Informational")
            raw_conf = detector.get("confidence", "Medium")
            description = detector.get("description", "")

            # Get severity
            severity = SLITHER_SEVERITY_MAP.get(impact, Severity.INFO)

            # Boost severity for high-signal detectors
            if check in HIGH_SIGNAL_DETECTORS and severity == Severity.MEDIUM:
                severity = Severity.HIGH

            # Convert Slither confidence to our enum
            confidence = Confidence.from_string(raw_conf)

            # Extract location info
            elements = detector.get("elements", [])
            location_info = self._extract_location(elements)

            findings.append(Finding(
                id=f"slither-{check}-{i}",
                title=self._format_title(check),
                description=description,
                severity=severity,
                detector=check,
                verifier=self.name,
                confidence=confidence,
                raw_confidence=raw_conf,
                **location_info,
            ))

        return findings
    
    def _extract_location(self, elements: list) -> dict:
        """Extract file/line location from Slither elements."""
        if not elements:
            return {}
        
        # Get first element with source mapping
        for elem in elements:
            source_mapping = elem.get("source_mapping", {})
            if source_mapping:
                return {
                    "file": source_mapping.get("filename_relative"),
                    "line_start": source_mapping.get("lines", [None])[0],
                    "line_end": source_mapping.get("lines", [None])[-1] if source_mapping.get("lines") else None,
                }
        
        return {}
    
    def _format_title(self, check: str) -> str:
        """Format detector name into human-readable title."""
        # Convert kebab-case to Title Case
        words = check.replace("-", " ").replace("_", " ").split()
        return " ".join(word.capitalize() for word in words)
