"""Tests for LLM-driven exploit generation."""

from unittest.mock import AsyncMock, patch

import pytest

from verisol.core.report import Finding, Severity
from verisol.exploits.llm_generator import _extract_solidity, llm_generate_exploit
from verisol.exploits.prompts import SYSTEM_PROMPT, build_exploit_prompt
from verisol.exploits.generator import generate_exploit


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

FAKE_LLM_RESPONSE = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract FakeExploit is Test {
    function testReentrancyExploit() public {
        console.log("Profit:", 1 ether);
        assertTrue(true);
    }
}
"""


# ---------------------------------------------------------------------------
# Prompt construction tests
# ---------------------------------------------------------------------------

class TestPromptConstruction:
    def test_includes_finding_details(self, reentrancy_finding):
        prompt = build_exploit_prompt(
            finding_detector=reentrancy_finding.detector,
            finding_title=reentrancy_finding.title,
            finding_description=reentrancy_finding.description,
            finding_severity=reentrancy_finding.severity.value,
            finding_code_snippet=reentrancy_finding.code_snippet,
            contract_code=SAMPLE_CONTRACT,
            contract_name="EtherStore",
        )
        assert "reentrancy-eth" in prompt
        assert "Reentrancy Eth" in prompt
        assert "withdrawFunds" in prompt

    def test_includes_contract_source(self, reentrancy_finding):
        prompt = build_exploit_prompt(
            finding_detector=reentrancy_finding.detector,
            finding_title=reentrancy_finding.title,
            finding_description=reentrancy_finding.description,
            finding_severity=reentrancy_finding.severity.value,
            finding_code_snippet=None,
            contract_code=SAMPLE_CONTRACT,
            contract_name="EtherStore",
        )
        assert "contract EtherStore" in prompt
        assert "mapping(address => uint256)" in prompt

    def test_includes_format_spec(self, reentrancy_finding):
        prompt = build_exploit_prompt(
            finding_detector=reentrancy_finding.detector,
            finding_title=reentrancy_finding.title,
            finding_description=reentrancy_finding.description,
            finding_severity=reentrancy_finding.severity.value,
            finding_code_snippet=None,
            contract_code=SAMPLE_CONTRACT,
            contract_name="EtherStore",
        )
        assert 'deployCode("Vulnerable.sol:EtherStore")' in prompt
        assert "test.*Exploit" in prompt

    def test_includes_few_shot_example(self, reentrancy_finding):
        prompt = build_exploit_prompt(
            finding_detector=reentrancy_finding.detector,
            finding_title=reentrancy_finding.title,
            finding_description=reentrancy_finding.description,
            finding_severity=reentrancy_finding.severity.value,
            finding_code_snippet=None,
            contract_code=SAMPLE_CONTRACT,
            contract_name="EtherStore",
        )
        assert "ReentrancyExploit" in prompt
        assert 'console.log("Profit:"' in prompt

    def test_includes_previous_error(self, reentrancy_finding):
        prompt = build_exploit_prompt(
            finding_detector=reentrancy_finding.detector,
            finding_title=reentrancy_finding.title,
            finding_description=reentrancy_finding.description,
            finding_severity=reentrancy_finding.severity.value,
            finding_code_snippet=None,
            contract_code=SAMPLE_CONTRACT,
            contract_name="EtherStore",
            previous_error="Compiler run failed: undeclared identifier",
        )
        assert "Previous Attempt Failed" in prompt
        assert "undeclared identifier" in prompt

    def test_no_previous_error_section_when_none(self, reentrancy_finding):
        prompt = build_exploit_prompt(
            finding_detector=reentrancy_finding.detector,
            finding_title=reentrancy_finding.title,
            finding_description=reentrancy_finding.description,
            finding_severity=reentrancy_finding.severity.value,
            finding_code_snippet=None,
            contract_code=SAMPLE_CONTRACT,
            contract_name="EtherStore",
            previous_error=None,
        )
        assert "Previous Attempt Failed" not in prompt

    def test_system_prompt_exists(self):
        assert "security researcher" in SYSTEM_PROMPT
        assert "Foundry" in SYSTEM_PROMPT


# ---------------------------------------------------------------------------
# Code extraction tests
# ---------------------------------------------------------------------------

class TestCodeExtraction:
    def test_extracts_from_fenced_block(self):
        text = "Here is the code:\n```solidity\n" + FAKE_LLM_RESPONSE + "\n```\nDone."
        result = _extract_solidity(text)
        assert result is not None
        assert "pragma solidity" in result
        assert "testReentrancyExploit" in result

    def test_extracts_raw_solidity(self):
        result = _extract_solidity(FAKE_LLM_RESPONSE)
        assert result is not None
        assert "pragma solidity" in result

    def test_extracts_from_pragma_in_text(self):
        text = "Sure! Here's the exploit:\npragma solidity ^0.8.0;\ncontract X {}"
        result = _extract_solidity(text)
        assert result is not None
        assert result.startswith("pragma solidity")

    def test_returns_none_for_garbage(self):
        result = _extract_solidity("I don't know how to help with that.")
        assert result is None

    def test_handles_plain_fenced_block(self):
        text = "```\n" + FAKE_LLM_RESPONSE + "\n```"
        result = _extract_solidity(text)
        assert result is not None
        assert "pragma solidity" in result


# ---------------------------------------------------------------------------
# LLM generate_exploit integration (mocked LLM call)
# ---------------------------------------------------------------------------

class TestLLMGenerateExploit:
    @pytest.mark.asyncio
    async def test_returns_code_on_success(self, reentrancy_finding):
        with patch(
            "verisol.exploits.llm_generator._call_llm",
            new_callable=AsyncMock,
            return_value=FAKE_LLM_RESPONSE,
        ):
            result = await llm_generate_exploit(
                finding=reentrancy_finding,
                contract_code=SAMPLE_CONTRACT,
                contract_name="EtherStore",
            )
        assert result is not None
        assert "pragma solidity" in result

    @pytest.mark.asyncio
    async def test_returns_none_when_no_api_key(self, reentrancy_finding):
        with patch("verisol.config.get_settings") as mock_settings:
            s = mock_settings.return_value
            s.exploit_llm_provider = "openai"
            s.exploit_llm_model = None
            s.llm_provider = "openai"
            s.llm_timeout = 60
            s.openai_api_key = None
            s.anthropic_api_key = None

            with patch.dict("os.environ", {}, clear=True):
                result = await llm_generate_exploit(
                    finding=reentrancy_finding,
                    contract_code=SAMPLE_CONTRACT,
                    contract_name="EtherStore",
                )
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_on_llm_error(self, reentrancy_finding):
        with patch(
            "verisol.exploits.llm_generator._call_llm",
            new_callable=AsyncMock,
            side_effect=RuntimeError("API error 500"),
        ):
            result = await llm_generate_exploit(
                finding=reentrancy_finding,
                contract_code=SAMPLE_CONTRACT,
                contract_name="EtherStore",
            )
        assert result is None


# ---------------------------------------------------------------------------
# Async generate_exploit (LLM-first, template fallback)
# ---------------------------------------------------------------------------

class TestGenerateExploitFallback:
    @pytest.mark.asyncio
    async def test_uses_llm_when_enabled(self, reentrancy_finding):
        with patch(
            "verisol.exploits.llm_generator._call_llm",
            new_callable=AsyncMock,
            return_value=FAKE_LLM_RESPONSE,
        ):
            result = await generate_exploit(
                finding=reentrancy_finding,
                contract_code=SAMPLE_CONTRACT,
                contract_name="EtherStore",
            )
        assert result is not None
        # Should be the LLM output, not the template
        assert "FakeExploit" in result

    @pytest.mark.asyncio
    async def test_falls_back_to_template_when_llm_disabled(self, reentrancy_finding):
        with patch("verisol.config.get_settings") as mock_settings:
            mock_settings.return_value.exploit_llm_enabled = False

            result = await generate_exploit(
                finding=reentrancy_finding,
                contract_code=SAMPLE_CONTRACT,
                contract_name="EtherStore",
            )
        assert result is not None
        # Template output — not the fake LLM response
        assert "ReentrancyExploit" in result

    @pytest.mark.asyncio
    async def test_falls_back_to_template_on_llm_failure(self, reentrancy_finding):
        with patch(
            "verisol.exploits.llm_generator._call_llm",
            new_callable=AsyncMock,
            side_effect=RuntimeError("API down"),
        ):
            result = await generate_exploit(
                finding=reentrancy_finding,
                contract_code=SAMPLE_CONTRACT,
                contract_name="EtherStore",
            )
        assert result is not None
        assert "ReentrancyExploit" in result

    @pytest.mark.asyncio
    async def test_returns_none_for_unknown_detector_no_llm(self, unknown_finding):
        with patch("verisol.config.get_settings") as mock_settings:
            mock_settings.return_value.exploit_llm_enabled = False

            result = await generate_exploit(
                finding=unknown_finding,
                contract_code=SAMPLE_CONTRACT,
                contract_name="EtherStore",
            )
        assert result is None

    @pytest.mark.asyncio
    async def test_llm_handles_unknown_detector(self, unknown_finding):
        with patch(
            "verisol.exploits.llm_generator._call_llm",
            new_callable=AsyncMock,
            return_value=FAKE_LLM_RESPONSE,
        ):
            result = await generate_exploit(
                finding=unknown_finding,
                contract_code=SAMPLE_CONTRACT,
                contract_name="EtherStore",
            )
        # LLM can handle detectors that have no template
        assert result is not None
