"""LLM-based security analysis verifier."""

from __future__ import annotations

import json
import os
import re
from typing import Literal

import httpx

from verisol.core.contract import Contract
from verisol.core.report import Confidence, Finding, Severity, VerificationResult, VerifierStatus
from verisol.verifiers.base import BaseVerifier


# Few-shot examples from real exploits for better detection accuracy
# Sources: The DAO (2016), Parity Wallet (2017), Cream Finance (2021), SWC Registry
FEW_SHOT_EXAMPLES = """
## REAL EXPLOIT EXAMPLES - Learn from these actual vulnerabilities:

### Example 1: Reentrancy - The DAO Hack (2016, $60M stolen)
```solidity
// VULNERABLE - The DAO pattern
function withdraw() public {
    uint amount = balances[msg.sender];
    (bool success, ) = msg.sender.call{value: amount}("");  // External call BEFORE state update
    require(success);
    balances[msg.sender] = 0;  // State update AFTER - TOO LATE!
}
```
**Vulnerability found:**
- Type: reentrancy
- Severity: critical
- Description: External call to msg.sender before balance is set to zero. Attacker's fallback can recursively call withdraw() and drain funds repeatedly before balance updates.
- Detection pattern: Look for .call{value:}(), .transfer(), .send() or external contract calls that occur BEFORE state variable updates.

### Example 2: Reentrancy - ERC-777 Token Callback (Cream Finance 2021, $130M stolen)
```solidity
// VULNERABLE - Token with callbacks
function borrow(uint amount) external {
    require(collateral[msg.sender] >= amount);
    IERC777(token).transfer(msg.sender, amount);  // ERC-777 triggers tokensReceived callback
    borrowed[msg.sender] += amount;  // State update after transfer - vulnerable!
}
```
**Vulnerability found:**
- Type: reentrancy
- Severity: high
- Description: ERC-777 tokens call tokensReceived() on recipient during transfer. Attacker can reenter borrow() before borrowed amount is recorded, bypassing collateral checks.
- Detection pattern: Any token transfer (especially ERC-777/ERC-1155) before state updates. Check if contract interacts with external tokens.

### Example 3: Cross-function Reentrancy
```solidity
// VULNERABLE - Different function reentry
function withdraw(uint amount) external {
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
    balances[msg.sender] -= amount;
}
function transfer(address to, uint amount) external {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;
    balances[to] += amount;
}
```
**Vulnerability found:**
- Type: reentrancy
- Severity: high
- Description: During withdraw()'s external call, attacker can call transfer() which reads the stale balance. Attacker can transfer funds they're also withdrawing.
- Detection pattern: External calls in one function while another function reads/modifies the same state variables.

### Example 4: Access Control - Parity Wallet Hack (2017, $30M stolen)
```solidity
// VULNERABLE - Parity Multisig Wallet
contract WalletLibrary {
    address public owner;

    function initWallet(address _owner) public {  // PUBLIC - anyone can call!
        owner = _owner;
    }

    function withdraw(uint amount) public {
        require(msg.sender == owner);
        payable(msg.sender).transfer(amount);
    }
}
```
**Vulnerability found:**
- Type: access-control
- Severity: critical
- Description: initWallet() is public and can be called by anyone to become owner. Should be internal/private or have initialization guard. Attacker called initWallet() to take ownership, then drained funds.
- Detection pattern: Initialization functions that set owner/admin without access control. Functions that should be called once but have no guard against re-initialization.

### Example 5: Access Control - Missing Modifier
```solidity
// VULNERABLE - No onlyOwner modifier
contract Treasury {
    address public owner;

    function setOwner(address newOwner) external {  // MISSING: onlyOwner modifier!
        owner = newOwner;
    }

    function withdrawAll() external {
        require(msg.sender == owner);
        payable(msg.sender).transfer(address(this).balance);
    }
}
```
**Vulnerability found:**
- Type: access-control
- Severity: critical
- Description: setOwner() has no access control - anyone can call it to become owner, then call withdrawAll() to drain funds.
- Detection pattern: Functions that modify owner/admin/privileged roles without require() checks or modifiers restricting access.

### Example 6: Access Control - Wrong Constructor Name (Pre-0.4.22)
```solidity
// VULNERABLE - Function named like contract but not a constructor
contract Wallet {
    address public owner;

    function Wallet() public {  // Should be constructor() in 0.4.22+
        owner = msg.sender;
    }

    function withdraw() public {
        require(msg.sender == owner);
        payable(msg.sender).transfer(address(this).balance);
    }
}
```
**Vulnerability found:**
- Type: access-control
- Severity: critical
- Description: In Solidity 0.4.22+, constructor() keyword is required. A function named after the contract is just a regular public function that anyone can call to become owner.
- Detection pattern: Functions named after the contract that set owner/admin (should use constructor() keyword instead).

### Example 7: Precision Loss - Divide Before Multiply
```solidity
// VULNERABLE - Division before multiplication loses precision
contract PriceCalculator {
    function calculatePrice(uint256 price, uint256 discount) public pure returns (uint256) {
        return (price / 100) * discount;  // WRONG: 80/100 = 0, then 0*90 = 0
    }
}
// SAFE version:
contract SafePriceCalculator {
    function calculatePrice(uint256 price, uint256 discount) public pure returns (uint256) {
        return (price * discount) / 100;  // CORRECT: 80*90 = 7200, then 7200/100 = 72
    }
}
```
**Vulnerability found:**
- Type: precision-loss
- Severity: medium
- Description: Dividing before multiplying causes integer truncation. If numerator < denominator, result is 0. For price=80, discount=90: (80/100)*90 = 0*90 = 0 instead of correct value 72.
- Detection pattern: Look for division operations that occur BEFORE multiplication in the same expression or calculation flow. Check for patterns like (a / b) * c where a < b would cause truncation.

---
"""

# Structured output prompt for consistent JSON parsing
AUDIT_PROMPT = """Analyze this Solidity contract for security vulnerabilities.

You are an expert smart contract auditor. Study the real exploit examples below carefully, then analyze the target contract using the same detection patterns.

{few_shot_examples}

## TARGET CONTRACT TO ANALYZE:
```solidity
{source_code}
```

## ANALYSIS INSTRUCTIONS:
1. For REENTRANCY: Check every external call (.call, .transfer, .send, token transfers) and verify state updates happen BEFORE the call, not after.
2. For ACCESS CONTROL: Check every function that modifies owner/admin/privileged state - does it have proper require() or modifier guards?
3. Compare patterns in the target contract against the real exploit examples above.
4. Only report vulnerabilities you are confident about - avoid false positives.

## RESPONSE FORMAT:
Respond with a JSON object containing a "vulnerabilities" array. Each vulnerability must have:
- "type": category (e.g., "reentrancy", "access-control", "integer-overflow", "front-running")
- "severity": "critical" | "high" | "medium" | "low" | "informational"
- "title": short description (max 80 chars)
- "description": detailed explanation of the vulnerability and how it could be exploited
- "line_number": approximate line number where the issue occurs (integer or null)
- "confidence": "high" | "medium" | "low"
- "recommendation": how to fix the issue

Example response:
{{
  "vulnerabilities": [
    {{
      "type": "reentrancy",
      "severity": "high",
      "title": "Reentrancy in withdraw function",
      "description": "External call on line 42 occurs before balance is updated on line 45. Attacker can recursively call withdraw() to drain funds.",
      "line_number": 42,
      "confidence": "high",
      "recommendation": "Move balances[msg.sender] = 0 before the external call (Checks-Effects-Interactions pattern)"
    }}
  ]
}}

If no vulnerabilities found, return: {{"vulnerabilities": []}}

## IMPORTANT CONTEXT:
- Solidity version: {solidity_version}
- Solidity 0.8+ has built-in overflow/underflow protection (do NOT flag these unless using unchecked blocks)
- Focus on actual security issues, not gas optimizations or style
- Be precise about severity levels
- Only report high-confidence findings to minimize false positives

Respond ONLY with valid JSON, no markdown code blocks or explanation."""


# FP Filter categories - findings in these categories may be filtered
FP_FILTER_CATEGORIES = {
    "access-control": {
        "filter_reason": "Educational contracts often omit access control intentionally",
    },
    "integer-underflow": {
        "filter_reason": "Solidity 0.8+ has built-in underflow protection",
        "version_check": True,
    },
    "integer-overflow": {
        "filter_reason": "Solidity 0.8+ has built-in overflow protection",
        "version_check": True,
    },
    "out-of-bounds": {
        "filter_reason": "Solidity automatically reverts on out-of-bounds access",
        "always_filter": True,
    },
}


class LLMVerifier(BaseVerifier):
    """
    LLM-based security analysis using GPT-4o or Claude.

    This verifier sends contract source to an LLM for semantic analysis,
    catching vulnerabilities that pattern-based tools like Slither miss.
    """

    name: str = "llm"
    timeout: int = 120
    max_contract_size: int = 50_000  # 50KB max for LLM analysis

    def __init__(
        self,
        provider: Literal["openai", "anthropic"] = "openai",
        model: str | None = None,
        api_key: str | None = None,
        timeout: int | None = None,
        enable_filters: bool = True,
    ):
        """
        Initialize LLM verifier.

        Args:
            provider: LLM provider ("openai" or "anthropic")
            model: Model to use (defaults to gpt-4o or claude-3-5-sonnet)
            api_key: API key (defaults to env var)
            timeout: Request timeout in seconds
            enable_filters: Whether to apply FP filters
        """
        super().__init__(timeout)
        self.provider = provider
        self.enable_filters = enable_filters

        # Import settings here to get values from .env
        from verisol.config import settings as app_settings

        # Set defaults based on provider
        if provider == "openai":
            self.model = model or "gpt-4o"
            self.api_key = api_key or app_settings.openai_api_key or os.environ.get("OPENAI_API_KEY")
            self.api_url = "https://api.openai.com/v1/chat/completions"
        elif provider == "anthropic":
            self.model = model or "claude-3-5-sonnet-latest"
            self.api_key = api_key or app_settings.anthropic_api_key or os.environ.get("ANTHROPIC_API_KEY")
            self.api_url = "https://api.anthropic.com/v1/messages"
        else:
            raise ValueError(f"Unknown provider: {provider}")

    def is_available(self) -> bool:
        """Check if LLM API is configured."""
        return self.api_key is not None and len(self.api_key) > 0

    async def verify(self, contract: Contract) -> VerificationResult:
        """
        Run LLM security analysis on a contract.

        Args:
            contract: Contract to analyze

        Returns:
            VerificationResult with findings
        """
        if not self.is_available():
            return VerificationResult(
                verifier=self.name,
                status=VerifierStatus.SKIPPED,
                error_message=f"No API key configured for {self.provider}",
            )

        # Check contract size before sending to LLM
        if len(contract.code) > self.max_contract_size:
            return VerificationResult(
                verifier=self.name,
                status=VerifierStatus.SKIPPED,
                error_message=f"Contract too large for LLM analysis ({len(contract.code):,} bytes, max {self.max_contract_size:,})",
            )

        # Build prompt with few-shot examples
        solidity_version = contract.solidity_version or "unknown"
        prompt = AUDIT_PROMPT.format(
            few_shot_examples=FEW_SHOT_EXAMPLES,
            source_code=contract.code,
            solidity_version=solidity_version,
        )

        # Call LLM API
        try:
            response_text, tokens_used = await self._call_llm(prompt)
        except Exception as e:
            return VerificationResult(
                verifier=self.name,
                status=VerifierStatus.ERROR,
                error_message=f"API call failed: {str(e)}",
            )

        # Parse response
        parsed = self._extract_json(response_text)
        if parsed is None:
            return VerificationResult(
                verifier=self.name,
                status=VerifierStatus.ERROR,
                error_message="Failed to parse JSON response",
                raw_output=response_text[:500],
            )

        # Convert to findings
        raw_vulns = parsed.get("vulnerabilities", [])
        findings: list[Finding] = []
        filtered_count = 0

        for i, vuln in enumerate(raw_vulns):
            # Apply FP filters
            if self.enable_filters:
                should_filter, reason = self._should_filter(vuln, contract)
                if should_filter:
                    filtered_count += 1
                    continue

            finding = self._vuln_to_finding(vuln, i, contract)
            findings.append(finding)

        # Determine status
        has_critical = any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)
        status = VerifierStatus.FAILED if has_critical else VerifierStatus.PASSED

        return VerificationResult(
            verifier=self.name,
            status=status,
            findings=findings,
            raw_output=f"Analyzed with {self.model}. Tokens: {tokens_used}. Filtered: {filtered_count}",
        )

    async def _call_llm(self, prompt: str) -> tuple[str, int]:
        """
        Call LLM API and return response text and token count.
        """
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            if self.provider == "openai":
                response = await client.post(
                    self.api_url,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "messages": [
                            {
                                "role": "system",
                                "content": "You are a smart contract security auditor. Analyze Solidity contracts for vulnerabilities and respond in JSON format only.",
                            },
                            {"role": "user", "content": prompt},
                        ],
                        "temperature": 0.1,
                        "max_tokens": 4000,
                    },
                )

                if response.status_code != 200:
                    raise RuntimeError(f"OpenAI API error {response.status_code}: {response.text[:200]}")

                data = response.json()
                content = data["choices"][0]["message"]["content"]
                tokens = data.get("usage", {}).get("total_tokens", 0)
                return content, tokens

            elif self.provider == "anthropic":
                response = await client.post(
                    self.api_url,
                    headers={
                        "x-api-key": self.api_key,
                        "Content-Type": "application/json",
                        "anthropic-version": "2023-06-01",
                    },
                    json={
                        "model": self.model,
                        "max_tokens": 4000,
                        "messages": [
                            {"role": "user", "content": prompt},
                        ],
                        "system": "You are a smart contract security auditor. Analyze Solidity contracts for vulnerabilities and respond in JSON format only.",
                    },
                )

                if response.status_code != 200:
                    raise RuntimeError(f"Anthropic API error {response.status_code}: {response.text[:200]}")

                data = response.json()
                content = data["content"][0]["text"]
                tokens = data.get("usage", {}).get("input_tokens", 0) + data.get("usage", {}).get("output_tokens", 0)
                return content, tokens

            else:
                raise ValueError(f"Unknown provider: {self.provider}")

    def _extract_json(self, text: str) -> dict | None:
        """Extract JSON from LLM response."""
        # Try code blocks first
        json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        # Try whole response as JSON
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try finding JSON object anywhere
        json_match = re.search(r"\{.*\}", text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(0))
            except json.JSONDecodeError:
                pass

        return None

    def _should_filter(self, vuln: dict, contract: Contract) -> tuple[bool, str | None]:
        """
        Determine if a finding should be filtered as likely FP.

        Returns (should_filter, reason).
        """
        finding_type = vuln.get("type", "").lower()
        description = vuln.get("description", "").lower()

        for category, config in FP_FILTER_CATEGORIES.items():
            if category not in finding_type:
                continue

            # Always filter certain categories
            if config.get("always_filter"):
                return True, config["filter_reason"]

            # Version-based filtering
            if config.get("version_check"):
                version = contract.solidity_version
                if version:
                    # Parse version string like "0.8.24" or "^0.8.0"
                    match = re.search(r"(\d+)\.(\d+)", version)
                    if match:
                        major, minor = int(match.group(1)), int(match.group(2))
                        if (major, minor) >= (0, 8):
                            # Check if it's in assembly/unchecked block
                            if "assembly" not in description and "unchecked" not in description:
                                return True, config["filter_reason"]

        return False, None

    def _vuln_to_finding(self, vuln: dict, index: int, contract: Contract) -> Finding:
        """Convert raw vulnerability dict to Finding model."""
        # Map severity
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "informational": Severity.INFO,
            "info": Severity.INFO,
        }
        raw_severity = vuln.get("severity", "medium").lower()
        severity = severity_map.get(raw_severity, Severity.MEDIUM)

        # Extract line number
        line_num = vuln.get("line_number")
        if isinstance(line_num, str):
            try:
                line_num = int(line_num)
            except ValueError:
                line_num = None

        # Handle confidence - store raw value and convert to enum
        raw_conf = vuln.get("confidence", "medium")
        confidence = Confidence.from_string(raw_conf)

        return Finding(
            id=f"llm-{index + 1}",
            title=vuln.get("title", vuln.get("type", "Unknown vulnerability")),
            description=vuln.get("description", ""),
            severity=severity,
            detector=vuln.get("type", "llm-analysis"),
            verifier=self.name,
            file=contract.name,
            line_start=line_num,
            confidence=confidence,
            raw_confidence=raw_conf,
            recommendation=vuln.get("recommendation"),
        )
