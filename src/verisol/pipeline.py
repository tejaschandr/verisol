"""Verification pipeline orchestrator."""

from __future__ import annotations

import asyncio
import time
from typing import Callable

from verisol.config import settings
from verisol.core.contract import Contract
from verisol.core.report import AuditReport, VerificationResult, VerifierStatus, apply_confidence_scoring
from verisol.verifiers import (
    BaseVerifier,
    SolcVerifier,
    SlitherVerifier,
    SMTCheckerVerifier,
    LLMVerifier,
)


class VerificationPipeline:
    """
    Orchestrates the verification pipeline.

    Pipeline stages:
    1. Compilation (solc) - binary gate, must pass
    2. Static Analysis (slither) - always run
    3. Formal Verification (smtchecker) - always run
    4. LLM Analysis - semantic security analysis

    Stages 2-4 can run in parallel after compilation passes.
    """

    def __init__(
        self,
        solc_verifier: SolcVerifier | None = None,
        slither_verifier: SlitherVerifier | None = None,
        smtchecker_verifier: SMTCheckerVerifier | None = None,
        llm_verifier: LLMVerifier | None = None,
    ):
        self.solc = solc_verifier or SolcVerifier()
        self.slither = slither_verifier or SlitherVerifier()
        self.smtchecker = smtchecker_verifier or SMTCheckerVerifier()
        self.llm = llm_verifier or LLMVerifier(
            provider=settings.llm_provider,
            model=settings.llm_model,
            timeout=settings.llm_timeout,
            enable_filters=settings.llm_enable_filters,
        )

        self._progress_callback: Callable[[str, str], None] | None = None
    
    def set_progress_callback(self, callback: Callable[[str, str], None]) -> None:
        """Set callback for progress updates. callback(stage, status)"""
        self._progress_callback = callback
    
    def _report_progress(self, stage: str, status: str) -> None:
        """Report progress to callback if set."""
        if self._progress_callback:
            self._progress_callback(stage, status)
    
    async def run(self, contract: Contract, include_smt: bool = False, skip_llm: bool = False) -> AuditReport:
        """
        Run verification pipeline on a contract.

        Args:
            contract: Contract to verify
            include_smt: Include SMTChecker formal verification (slow)
            skip_llm: Skip LLM analysis (for offline mode)

        Returns:
            Complete AuditReport with all verification results
        """
        start_time = time.perf_counter()

        report = AuditReport(
            contract_hash=contract.hash,
            contract_name=contract.name,
        )

        # Stage 1: Compilation (must pass to continue)
        self._report_progress("compilation", "running")
        compilation_result = await self.solc.run_with_timeout(contract)
        report.compilation = compilation_result

        if compilation_result.status in (VerifierStatus.ERROR, VerifierStatus.TIMEOUT):
            self._report_progress("compilation", "error")
            report.total_duration_ms = int((time.perf_counter() - start_time) * 1000)
            return report

        if not compilation_result.passed:
            self._report_progress("compilation", "failed")
            report.total_duration_ms = int((time.perf_counter() - start_time) * 1000)
            return report

        self._report_progress("compilation", "passed")

        # Stage 2+: Run verifiers in parallel
        self._report_progress("analysis", "running")

        # Determine which verifiers to run
        # Default: Slither + LLM (fast, catches most vulnerabilities)
        # Offline: Slither + SMTChecker (free, no API)
        # Full: Slither + LLM + SMTChecker (complete)
        verifiers_to_run = [
            ("slither", self.slither),
        ]

        if include_smt:
            verifiers_to_run.append(("smtchecker", self.smtchecker))

        if not skip_llm and settings.llm_enabled and self.llm.is_available():
            verifiers_to_run.append(("llm", self.llm))
        
        # Run verifiers concurrently
        tasks = [
            self._run_verifier(name, verifier, contract)
            for name, verifier in verifiers_to_run
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for (name, _), result in zip(verifiers_to_run, results):
            if isinstance(result, Exception):
                result = VerificationResult(
                    verifier=name,
                    status=VerifierStatus.ERROR,
                    error_message=str(result),
                )
            
            # Assign to report
            if name == "slither":
                report.slither = result
            elif name == "smtchecker":
                report.smtchecker = result
            elif name == "llm":
                report.llm = result
            
            self._report_progress(name, result.status.value)

        # Apply confidence scoring with cross-tool consensus
        apply_confidence_scoring(report, solidity_version=contract.solidity_version)

        report.total_duration_ms = int((time.perf_counter() - start_time) * 1000)
        self._report_progress("complete", "done")

        return report
    
    async def _run_verifier(
        self,
        name: str,
        verifier: BaseVerifier,
        contract: Contract,
    ) -> VerificationResult:
        """Run a single verifier with error handling."""
        try:
            return await verifier.run_with_timeout(contract)
        except Exception as e:
            return VerificationResult(
                verifier=name,
                status=VerifierStatus.ERROR,
                error_message=str(e),
            )
    
    async def run_quick(self, contract: Contract) -> AuditReport:
        """
        Run quick verification (compilation + slither only).
        
        Useful for rapid feedback during development.
        
        Args:
            contract: Contract to verify
            
        Returns:
            AuditReport with compilation and slither results
        """
        start_time = time.perf_counter()
        
        report = AuditReport(
            contract_hash=contract.hash,
            contract_name=contract.name,
        )
        
        # Compilation
        report.compilation = await self.solc.run_with_timeout(contract)
        
        if not report.compilation.passed:
            report.total_duration_ms = int((time.perf_counter() - start_time) * 1000)
            return report
        
        # Slither only
        report.slither = await self.slither.run_with_timeout(contract)
        
        report.total_duration_ms = int((time.perf_counter() - start_time) * 1000)
        return report
    
    def check_tools(self) -> dict[str, bool]:
        """Check which verification tools are available."""
        return {
            "solc": self.solc.is_available(),
            "slither": self.slither.is_available(),
            "smtchecker": self.smtchecker.is_available(),
            "llm": self.llm.is_available(),
        }


# Convenience function
async def audit_contract(contract: Contract, quick: bool = False) -> AuditReport:
    """
    Audit a contract using the default pipeline.
    
    Args:
        contract: Contract to audit
        quick: If True, run quick verification only
        
    Returns:
        AuditReport with verification results
    """
    pipeline = VerificationPipeline()
    
    if quick:
        return await pipeline.run_quick(contract)
    return await pipeline.run(contract)
