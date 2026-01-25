"""Base verifier interface."""

from __future__ import annotations

import asyncio
import os
import time
from abc import ABC, abstractmethod
from pathlib import Path

from verisol.core.contract import Contract
from verisol.core.report import VerificationResult, VerifierStatus


class BaseVerifier(ABC):
    """Abstract base class for all verification tools."""
    
    name: str = "base"
    timeout: int = 60  # Default timeout in seconds
    
    def __init__(self, timeout: int | None = None):
        if timeout is not None:
            self.timeout = timeout
    
    @abstractmethod
    async def verify(self, contract: Contract) -> VerificationResult:
        """
        Run verification on a contract.
        
        Args:
            contract: Contract to verify
            
        Returns:
            VerificationResult with findings and status
        """
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if the verification tool is installed and available."""
        pass
    
    async def run_with_timeout(
        self,
        contract: Contract,
        temp_dir: Path | None = None,
    ) -> VerificationResult:
        """
        Run verification with timeout handling.
        
        Args:
            contract: Contract to verify
            temp_dir: Optional directory for temp files
            
        Returns:
            VerificationResult (may have TIMEOUT status)
        """
        start = time.perf_counter()
        
        try:
            result = await asyncio.wait_for(
                self.verify(contract),
                timeout=self.timeout,
            )
            result.duration_ms = int((time.perf_counter() - start) * 1000)
            return result
            
        except asyncio.TimeoutError:
            return VerificationResult(
                verifier=self.name,
                status=VerifierStatus.TIMEOUT,
                duration_ms=self.timeout * 1000,
                error_message=f"Verification timed out after {self.timeout}s",
            )
        except Exception as e:
            return VerificationResult(
                verifier=self.name,
                status=VerifierStatus.ERROR,
                duration_ms=int((time.perf_counter() - start) * 1000),
                error_message=str(e),
            )
    
    async def _run_command(
        self,
        cmd: list[str],
        cwd: Path | None = None,
        timeout: int | None = None,
    ) -> tuple[int, str, str]:
        """
        Run a shell command asynchronously.
        
        Args:
            cmd: Command and arguments
            cwd: Working directory
            timeout: Override timeout
            
        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        timeout = timeout or self.timeout
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=os.environ.copy(),
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )
            return (
                process.returncode or 0,
                stdout.decode("utf-8", errors="replace"),
                stderr.decode("utf-8", errors="replace"),
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise
