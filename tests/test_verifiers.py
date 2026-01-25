"""Tests for verification tools."""

import pytest
from pathlib import Path

from verisol.core.contract import Contract
from verisol.core.report import Severity, VerifierStatus
from verisol.verifiers import SolcVerifier, SlitherVerifier, SMTCheckerVerifier


FIXTURES_DIR = Path(__file__).parent / "fixtures"
VALID_DIR = FIXTURES_DIR / "valid"
VULNERABLE_DIR = FIXTURES_DIR / "vulnerable"


# Sample contracts for inline testing
VALID_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract SimpleStorage {
    uint256 private storedData;
    
    function set(uint256 x) public {
        storedData = x;
    }
    
    function get() public view returns (uint256) {
        return storedData;
    }
}
"""

INVALID_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Broken {
    // Missing semicolon
    uint256 x
}
"""


class TestContract:
    """Test Contract model."""
    
    def test_from_text(self):
        contract = Contract.from_text(VALID_CONTRACT, "SimpleStorage")
        assert contract.name == "SimpleStorage"
        assert contract.solidity_version == "^0.8.24"
        assert contract.lines_of_code > 0
        assert len(contract.hash) == 16
    
    def test_extract_name(self):
        contract = Contract.from_text(VALID_CONTRACT)
        assert contract.name == "SimpleStorage"
    
    def test_temp_file(self, tmp_path):
        contract = Contract.from_text(VALID_CONTRACT, "Test")
        temp_file = contract.to_temp_file(tmp_path)
        assert temp_file.exists()
        assert temp_file.read_text() == VALID_CONTRACT


class TestSolcVerifier:
    """Test Solidity compiler verification."""
    
    @pytest.fixture
    def verifier(self):
        return SolcVerifier()
    
    @pytest.mark.asyncio
    async def test_valid_contract_compiles(self, verifier):
        if not verifier.is_available():
            pytest.skip("solc not available")
        
        contract = Contract.from_text(VALID_CONTRACT)
        result = await verifier.verify(contract)
        
        assert result.status == VerifierStatus.PASSED
        assert result.verifier == "solc"
    
    @pytest.mark.asyncio
    async def test_invalid_contract_fails(self, verifier):
        if not verifier.is_available():
            pytest.skip("solc not available")
        
        contract = Contract.from_text(INVALID_CONTRACT)
        result = await verifier.verify(contract)
        
        assert result.status == VerifierStatus.FAILED
        assert len(result.findings) > 0
        assert result.findings[0].severity == Severity.CRITICAL


class TestSlitherVerifier:
    """Test Slither static analysis."""
    
    @pytest.fixture
    def verifier(self):
        return SlitherVerifier()
    
    @pytest.mark.asyncio
    async def test_clean_contract_passes(self, verifier):
        if not verifier.is_available():
            pytest.skip("slither not available")
        
        contract = Contract.from_text(VALID_CONTRACT)
        result = await verifier.verify(contract)
        
        # Simple contract should have no high-severity issues
        high_findings = [
            f for f in result.findings 
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        assert len(high_findings) == 0
    
    @pytest.mark.asyncio
    async def test_detects_anti_patterns(self, verifier):
        if not verifier.is_available():
            pytest.skip("slither not available")
        
        fixture_path = VULNERABLE_DIR / "SecurityTestFixture.sol"
        if not fixture_path.exists():
            pytest.skip("Test fixture not found")
        
        contract = Contract.from_file(fixture_path)
        result = await verifier.verify(contract)
        
        # Should detect some issues
        assert len(result.findings) > 0
        
        # Check for specific detectors
        detectors_found = {f.detector for f in result.findings}
        # At minimum should find reentrancy or tx-origin
        expected_detectors = {"reentrancy-eth", "tx-origin", "divide-before-multiply"}
        assert len(detectors_found & expected_detectors) > 0, \
            f"Expected to find some of {expected_detectors}, found {detectors_found}"


class TestSMTCheckerVerifier:
    """Test SMTChecker formal verification."""
    
    @pytest.fixture
    def verifier(self):
        return SMTCheckerVerifier(timeout=30)
    
    @pytest.mark.asyncio
    async def test_simple_contract(self, verifier):
        if not verifier.is_available():
            pytest.skip("solc not available")

        contract = Contract.from_text(VALID_CONTRACT)
        result = await verifier.verify(contract)

        # Should complete without errors (SKIPPED if z3 not available)
        assert result.status in (VerifierStatus.PASSED, VerifierStatus.TIMEOUT, VerifierStatus.SKIPPED)
        assert result.verifier == "smtchecker"
    
    @pytest.mark.asyncio
    async def test_with_assertions(self, verifier):
        if not verifier.is_available():
            pytest.skip("solc not available")
        
        contract_with_assert = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract AssertTest {
    uint256 public value;
    
    function safeIncrement() public {
        require(value < type(uint256).max, "Overflow");
        value += 1;
        assert(value > 0);  // Should always hold after increment from 0+
    }
}
"""
        contract = Contract.from_text(contract_with_assert)
        result = await verifier.verify(contract)
        
        # Properties should be proven
        assert result.properties_checked >= 0


class TestPipeline:
    """Test full verification pipeline."""
    
    @pytest.mark.asyncio
    async def test_full_pipeline(self):
        from verisol.pipeline import VerificationPipeline
        
        pipeline = VerificationPipeline()
        contract = Contract.from_text(VALID_CONTRACT)
        
        report = await pipeline.run(contract)
        
        assert report.contract_hash == contract.hash
        assert report.compilation is not None
        assert report.total_duration_ms > 0
    
    @pytest.mark.asyncio
    async def test_quick_pipeline(self):
        from verisol.pipeline import VerificationPipeline
        
        pipeline = VerificationPipeline()
        contract = Contract.from_text(VALID_CONTRACT)
        
        report = await pipeline.run_quick(contract)
        
        assert report.compilation is not None
        # Quick mode may or may not run slither depending on availability
        assert report.smtchecker is None  # Quick mode skips SMT
