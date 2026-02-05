"""Tests for the exploit retry-loop agent."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from verisol.core.report import ExploitResult, Finding, Severity
from verisol.exploits.agent import exploit_with_retries, _format_error_for_retry


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def reentrancy_finding():
    return Finding(
        id="test-1",
        title="Reentrancy Eth",
        severity=Severity.HIGH,
        description="Reentrancy in EtherStore.withdrawFunds(uint256)",
        detector="reentrancy-eth",
        verifier="slither",
        line_start=15,
    )


@pytest.fixture
def unknown_finding():
    return Finding(
        id="test-2",
        title="Flash Loan Price Manipulation",
        severity=Severity.CRITICAL,
        description="Oracle price can be manipulated via flash loan",
        detector="flash-loan-oracle",
        verifier="llm",
        line_start=42,
    )


SAMPLE_CONTRACT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract EtherStore {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdrawFunds(uint256 _weiToWithdraw) public {
        require(balances[msg.sender] >= _weiToWithdraw);
        (bool send, ) = msg.sender.call{value: _weiToWithdraw}("");
        require(send, "Failed to send Ether");
        balances[msg.sender] -= _weiToWithdraw;
    }
}
"""

GOOD_EXPLOIT_CODE = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/Test.sol";
contract Exploit is Test {
    function testReentrancyExploit() public { assertTrue(true); }
}
"""

BAD_EXPLOIT_CODE = """\
pragma solidity ^0.8.0;
contract Broken { function bad() {} }
"""


def _success_result(code: str = GOOD_EXPLOIT_CODE) -> ExploitResult:
    return ExploitResult(
        generated=True,
        executed=True,
        successful=True,
        exploit_code=code,
        output="PASS testReentrancyExploit\nProfit: 11000000000000000000",
        profit_wei=11000000000000000000,
    )


def _failure_result(error: str = "Compiler run failed", code: str = BAD_EXPLOIT_CODE) -> ExploitResult:
    return ExploitResult(
        generated=True,
        executed=True,
        successful=False,
        exploit_code=code,
        output=f"STDERR: {error}",
        error=error,
    )


# ---------------------------------------------------------------------------
# Single-attempt success
# ---------------------------------------------------------------------------

class TestSingleAttemptSuccess:
    @pytest.mark.asyncio
    async def test_returns_on_first_try(self, reentrancy_finding):
        with patch(
            "verisol.exploits.agent.llm_generate_exploit",
            new_callable=AsyncMock,
            return_value=GOOD_EXPLOIT_CODE,
        ), patch(
            "verisol.exploits.agent.run_exploit",
            return_value=_success_result(),
        ):
            result = await exploit_with_retries(
                finding=reentrancy_finding,
                contract_code=SAMPLE_CONTRACT,
                contract_name="EtherStore",
                max_retries=3,
            )

        assert result.successful
        assert result.exploitable
        assert result.attempts == 1
        assert result.generation_method == "llm"
        assert result.retry_errors == []


# ---------------------------------------------------------------------------
# Retry on failure
# ---------------------------------------------------------------------------

class TestRetryOnFailure:
    @pytest.mark.asyncio
    async def test_retries_after_compilation_error(self, reentrancy_finding):
        """First attempt fails with compilation error, second succeeds."""
        generate_mock = AsyncMock(side_effect=[BAD_EXPLOIT_CODE, GOOD_EXPLOIT_CODE])
        run_mock = MagicMock(side_effect=[_failure_result("Compiler run failed"), _success_result()])

        with patch("verisol.exploits.agent.llm_generate_exploit", generate_mock), \
             patch("verisol.exploits.agent.run_exploit", run_mock):
            result = await exploit_with_retries(
                finding=reentrancy_finding,
                contract_code=SAMPLE_CONTRACT,
                contract_name="EtherStore",
                max_retries=3,
            )

        assert result.successful
        assert result.attempts == 2
        assert result.generation_method == "llm"
        assert len(result.retry_errors) == 1
        assert "Compiler run failed" in result.retry_errors[0]

    @pytest.mark.asyncio
    async def test_previous_error_passed_to_llm(self, reentrancy_finding):
        """Verify the error from attempt 1 is passed as previous_error to attempt 2."""
        generate_mock = AsyncMock(side_effect=[BAD_EXPLOIT_CODE, GOOD_EXPLOIT_CODE])
        run_mock = MagicMock(side_effect=[_failure_result("undeclared identifier"), _success_result()])

        with patch("verisol.exploits.agent.llm_generate_exploit", generate_mock), \
             patch("verisol.exploits.agent.run_exploit", run_mock):
            await exploit_with_retries(
                finding=reentrancy_finding,
                contract_code=SAMPLE_CONTRACT,
                contract_name="EtherStore",
                max_retries=3,
            )

        # First call: no previous_error
        assert generate_mock.call_args_list[0].kwargs.get("previous_error") is None
        # Second call: has the error
        assert "undeclared identifier" in generate_mock.call_args_list[1].kwargs["previous_error"]


# ---------------------------------------------------------------------------
# Max retries exhausted → template fallback
# ---------------------------------------------------------------------------

class TestMaxRetriesExhausted:
    @pytest.mark.asyncio
    async def test_falls_back_to_template(self, reentrancy_finding):
        """All LLM attempts fail, template fallback succeeds."""
        generate_mock = AsyncMock(return_value=BAD_EXPLOIT_CODE)
        # LLM runs fail, template run succeeds
        run_mock = MagicMock(side_effect=[
            _failure_result("error 1"),
            _failure_result("error 2"),
            _success_result(),  # template run
        ])

        with patch("verisol.exploits.agent.llm_generate_exploit", generate_mock), \
             patch("verisol.exploits.agent.run_exploit", run_mock), \
             patch("verisol.exploits.agent.generate_exploit_template", return_value=GOOD_EXPLOIT_CODE):
            result = await exploit_with_retries(
                finding=reentrancy_finding,
                contract_code=SAMPLE_CONTRACT,
                contract_name="EtherStore",
                max_retries=2,
            )

        assert result.successful
        assert result.generation_method == "template"
        assert result.attempts == 3  # 2 LLM + 1 template
        assert len(result.retry_errors) == 2

    @pytest.mark.asyncio
    async def test_returns_failure_when_no_template(self, unknown_finding):
        """All LLM attempts fail and no template exists."""
        generate_mock = AsyncMock(return_value=BAD_EXPLOIT_CODE)
        run_mock = MagicMock(return_value=_failure_result("error"))

        with patch("verisol.exploits.agent.llm_generate_exploit", generate_mock), \
             patch("verisol.exploits.agent.run_exploit", run_mock), \
             patch("verisol.exploits.agent.generate_exploit_template", return_value=None):
            result = await exploit_with_retries(
                finding=unknown_finding,
                contract_code=SAMPLE_CONTRACT,
                contract_name="EtherStore",
                max_retries=2,
            )

        assert not result.successful
        assert not result.generated
        assert result.generation_method == "none"
        assert len(result.retry_errors) == 2


# ---------------------------------------------------------------------------
# LLM unavailable → immediate template fallback
# ---------------------------------------------------------------------------

class TestLLMUnavailable:
    @pytest.mark.asyncio
    async def test_skips_to_template_when_llm_returns_none(self, reentrancy_finding):
        """LLM returns None (no API key) on first attempt, falls back to template."""
        with patch(
            "verisol.exploits.agent.llm_generate_exploit",
            new_callable=AsyncMock,
            return_value=None,
        ), patch(
            "verisol.exploits.agent.run_exploit",
            return_value=_success_result(),
        ), patch(
            "verisol.exploits.agent.generate_exploit_template",
            return_value=GOOD_EXPLOIT_CODE,
        ):
            result = await exploit_with_retries(
                finding=reentrancy_finding,
                contract_code=SAMPLE_CONTRACT,
                contract_name="EtherStore",
                max_retries=3,
            )

        assert result.successful
        assert result.generation_method == "template"


# ---------------------------------------------------------------------------
# Error formatting
# ---------------------------------------------------------------------------

class TestFormatErrorForRetry:
    def test_extracts_compilation_error(self):
        result = ExploitResult(
            generated=True,
            executed=True,
            successful=False,
            error="Compilation failed",
            output="STDERR: Error: undeclared identifier\n  --> test/Exploit.t.sol:5:1",
        )
        formatted = _format_error_for_retry(result)
        assert "Compilation failed" in formatted
        assert "undeclared identifier" in formatted

    def test_extracts_revert_error(self):
        result = ExploitResult(
            generated=True,
            executed=True,
            successful=False,
            error=None,
            output="[FAIL. Reason: revert] testExploit()\nAssertion failed: no profit",
        )
        formatted = _format_error_for_retry(result)
        assert "FAIL" in formatted
        assert "Assertion failed" in formatted

    def test_truncates_long_output(self):
        result = ExploitResult(
            generated=True,
            executed=True,
            successful=False,
            error="x" * 1000,
            output="",
        )
        formatted = _format_error_for_retry(result)
        assert len(formatted) <= 900  # 800 + [truncated] + some margin
        assert "[truncated]" in formatted

    def test_returns_unknown_when_empty(self):
        result = ExploitResult(
            generated=True,
            executed=True,
            successful=False,
            error=None,
            output=None,
        )
        formatted = _format_error_for_retry(result)
        assert formatted == "Unknown error"


# ---------------------------------------------------------------------------
# Field population
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Fork URL passthrough
# ---------------------------------------------------------------------------

class TestForkUrlPassthrough:
    @pytest.mark.asyncio
    async def test_fork_url_forwarded_to_run_exploit(self, reentrancy_finding):
        """Verify fork_url and fork_block are passed from exploit_with_retries to run_exploit."""
        generate_mock = AsyncMock(return_value=GOOD_EXPLOIT_CODE)
        run_mock = MagicMock(return_value=_success_result())

        with patch("verisol.exploits.agent.llm_generate_exploit", generate_mock), \
             patch("verisol.exploits.agent.run_exploit", run_mock):
            await exploit_with_retries(
                finding=reentrancy_finding,
                contract_code=SAMPLE_CONTRACT,
                contract_name="EtherStore",
                max_retries=1,
                fork_url="https://eth-mainnet.example.com",
                fork_block=18000000,
            )

        # run_exploit should have received fork params
        call_kwargs = run_mock.call_args[1]
        assert call_kwargs["fork_url"] == "https://eth-mainnet.example.com"
        assert call_kwargs["fork_block"] == 18000000

    @pytest.mark.asyncio
    async def test_fork_url_forwarded_to_template_fallback(self, reentrancy_finding):
        """Verify fork params are passed through to template fallback run."""
        generate_mock = AsyncMock(return_value=BAD_EXPLOIT_CODE)
        run_mock = MagicMock(side_effect=[_failure_result("error"), _success_result()])

        with patch("verisol.exploits.agent.llm_generate_exploit", generate_mock), \
             patch("verisol.exploits.agent.run_exploit", run_mock), \
             patch("verisol.exploits.agent.generate_exploit_template", return_value=GOOD_EXPLOIT_CODE):
            await exploit_with_retries(
                finding=reentrancy_finding,
                contract_code=SAMPLE_CONTRACT,
                contract_name="EtherStore",
                max_retries=1,
                fork_url="https://rpc.example.com",
                fork_block=99999,
            )

        # Both call sites (LLM attempt + template fallback) should get fork params
        for call in run_mock.call_args_list:
            assert call[1]["fork_url"] == "https://rpc.example.com"
            assert call[1]["fork_block"] == 99999


# ---------------------------------------------------------------------------
# Field population
# ---------------------------------------------------------------------------

class TestFieldPopulation:
    @pytest.mark.asyncio
    async def test_retry_errors_accumulated(self, reentrancy_finding):
        """Verify retry_errors list grows with each failed attempt."""
        generate_mock = AsyncMock(return_value=BAD_EXPLOIT_CODE)
        run_mock = MagicMock(side_effect=[
            _failure_result("error A"),
            _failure_result("error B"),
            _failure_result("error C"),
        ])

        with patch("verisol.exploits.agent.llm_generate_exploit", generate_mock), \
             patch("verisol.exploits.agent.run_exploit", run_mock), \
             patch("verisol.exploits.agent.generate_exploit_template", return_value=None):
            result = await exploit_with_retries(
                finding=reentrancy_finding,
                contract_code=SAMPLE_CONTRACT,
                contract_name="EtherStore",
                max_retries=3,
            )

        assert len(result.retry_errors) == 3
        assert "error A" in result.retry_errors[0]
        assert "error B" in result.retry_errors[1]
        assert "error C" in result.retry_errors[2]
