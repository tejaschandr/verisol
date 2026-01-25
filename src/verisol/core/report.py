"""Report and verification result data models."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, computed_field


class Severity(str, Enum):
    """Finding severity levels (aligned with Slither)."""
    
    CRITICAL = "critical"  # Immediate exploit risk
    HIGH = "high"          # Significant vulnerability
    MEDIUM = "medium"      # Potential issue
    LOW = "low"            # Minor concern
    INFO = "informational" # Suggestion/optimization
    
    @property
    def weight(self) -> float:
        """Numeric weight for scoring."""
        return {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.5,
            Severity.LOW: 0.2,
            Severity.INFO: 0.05,
        }[self]


class VerifierStatus(str, Enum):
    """Status of a verification step."""

    PASSED = "passed"      # All checks passed
    FAILED = "failed"      # Checks found issues
    ERROR = "error"        # Tool failed to run
    TIMEOUT = "timeout"    # Tool timed out
    SKIPPED = "skipped"    # Tool was skipped


class Confidence(str, Enum):
    """Confidence level for findings."""

    HIGH = "high"      # 80%+ likely real vulnerability
    MEDIUM = "medium"  # 50-80% likely real
    LOW = "low"        # <50% likely real (possible FP)

    @classmethod
    def from_string(cls, value: str | None) -> "Confidence":
        """Convert string to Confidence enum, defaulting to MEDIUM."""
        if value is None:
            return cls.MEDIUM
        value = value.lower().strip()
        if value in ("high", "h"):
            return cls.HIGH
        elif value in ("low", "l"):
            return cls.LOW
        return cls.MEDIUM


class Finding(BaseModel):
    """A single finding from a verification tool."""

    id: str = Field(..., description="Unique finding identifier")
    title: str = Field(..., description="Short description")
    description: str = Field(default="", description="Detailed explanation")
    severity: Severity
    detector: str = Field(..., description="Detection rule/check that found this")
    verifier: str = Field(..., description="Tool that produced this finding")

    # Location info (optional)
    file: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    code_snippet: str | None = None

    # Confidence scoring
    confidence: Confidence = Field(default=Confidence.MEDIUM, description="Confidence level")
    confidence_factors: list[str] = Field(
        default_factory=list,
        description="Factors that contributed to the confidence level"
    )
    raw_confidence: str | None = Field(default=None, description="Original confidence from tool")

    # Additional metadata
    reference: str | None = None   # Link to vulnerability database
    recommendation: str | None = None
    
    def to_markdown(self) -> str:
        """Format finding as markdown."""
        # Confidence indicator
        conf_icon = {"high": "🔴", "medium": "🟡", "low": "⚪"}.get(self.confidence.value, "⚪")

        lines = [
            f"### [{self.severity.value.upper()}] {self.title}",
            "",
            f"**Detector:** `{self.detector}` ({self.verifier})",
            f"**Confidence:** {conf_icon} {self.confidence.value.upper()}",
        ]

        if self.line_start:
            loc = f"Line {self.line_start}"
            if self.line_end and self.line_end != self.line_start:
                loc += f"-{self.line_end}"
            lines.append(f"**Location:** {loc}")

        if self.description:
            lines.extend(["", self.description])

        if self.confidence_factors:
            lines.extend(["", "**Confidence factors:**"])
            for factor in self.confidence_factors:
                lines.append(f"- {factor}")

        if self.code_snippet:
            lines.extend(["", "```solidity", self.code_snippet, "```"])

        if self.recommendation:
            lines.extend(["", f"**Recommendation:** {self.recommendation}"])

        return "\n".join(lines)


class VerificationResult(BaseModel):
    """Result from a single verification tool."""
    
    verifier: str = Field(..., description="Tool name")
    status: VerifierStatus
    
    # Timing
    duration_ms: int = Field(default=0, ge=0)
    
    # Results
    findings: list[Finding] = Field(default_factory=list)
    properties_checked: int = Field(default=0, ge=0)
    properties_proven: int = Field(default=0, ge=0)
    
    # Raw output for debugging
    raw_output: str | None = None
    error_message: str | None = None
    
    @computed_field
    @property
    def passed(self) -> bool:
        """Whether this verification step passed (no high/critical findings)."""
        if self.status in (VerifierStatus.ERROR, VerifierStatus.TIMEOUT):
            return False
        critical_findings = [
            f for f in self.findings 
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        return len(critical_findings) == 0
    
    @computed_field
    @property
    def finding_counts(self) -> dict[str, int]:
        """Count findings by severity."""
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts


class AuditReport(BaseModel):
    """Complete audit report for a contract."""
    
    # Metadata
    contract_hash: str
    contract_name: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    version: str = "0.1.0"
    
    # Results from each verifier
    compilation: VerificationResult | None = None
    slither: VerificationResult | None = None
    smtchecker: VerificationResult | None = None
    llm: VerificationResult | None = None
    
    # Aggregate metrics
    total_duration_ms: int = Field(default=0, ge=0)
    
    @computed_field
    @property
    def overall_score(self) -> float:
        """
        Compute overall security score (0-1).
        
        Scoring:
        - Start with 1.0
        - Deduct based on findings weighted by severity
        - Compilation failure = 0.0
        """
        if self.compilation and not self.compilation.passed:
            return 0.0
        
        score = 1.0
        all_findings = self.all_findings
        
        # Deduct for each finding
        for finding in all_findings:
            deduction = finding.severity.weight * 0.1
            score -= deduction
        
        # Bonus for proven SMT properties
        if self.smtchecker and self.smtchecker.properties_checked > 0:
            proven_ratio = self.smtchecker.properties_proven / self.smtchecker.properties_checked
            score += proven_ratio * 0.1  # Up to 10% bonus
        
        return max(0.0, min(1.0, score))
    
    @computed_field
    @property
    def all_findings(self) -> list[Finding]:
        """Aggregate findings from all verifiers."""
        findings = []
        for result in [self.slither, self.smtchecker, self.llm]:
            if result:
                findings.extend(result.findings)
        return findings
    
    @computed_field
    @property
    def finding_summary(self) -> dict[str, int]:
        """Count all findings by severity."""
        counts = {s.value: 0 for s in Severity}
        for f in self.all_findings:
            counts[f.severity.value] += 1
        return counts
    
    @computed_field
    @property
    def passed(self) -> bool:
        """Whether the contract passed the audit (compilation ok, no critical/high findings)."""
        # Compilation must succeed
        if self.compilation and not self.compilation.passed:
            return False
        # No critical or high severity findings
        return (
            self.finding_summary.get("critical", 0) == 0 and
            self.finding_summary.get("high", 0) == 0
        )
    
    @computed_field
    @property
    def confidence(self) -> str:
        """Overall confidence level."""
        if self.overall_score >= 0.9:
            return "high"
        elif self.overall_score >= 0.7:
            return "medium"
        else:
            return "low"
    
    def to_markdown(self) -> str:
        """Generate markdown report."""
        lines = [
            "# VeriSol Security Audit Report",
            "",
            f"**Contract:** {self.contract_name or 'Unknown'}",
            f"**Hash:** `{self.contract_hash}`",
            f"**Date:** {self.timestamp.strftime('%Y-%m-%d %H:%M UTC')}",
            "",
            "## Summary",
            "",
            f"**Overall Score:** {self.overall_score:.0%}",
            f"**Confidence:** {self.confidence.upper()}",
            f"**Status:** {'✅ PASSED' if self.passed else '❌ FAILED'}",
            "",
            "### Finding Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        
        for severity in Severity:
            count = self.finding_summary.get(severity.value, 0)
            emoji = "🔴" if severity in (Severity.CRITICAL, Severity.HIGH) else "🟡" if severity == Severity.MEDIUM else "🔵"
            lines.append(f"| {emoji} {severity.value.capitalize()} | {count} |")
        
        lines.extend([
            "",
            "## Verification Results",
            "",
        ])
        
        # Add each verifier result
        for name, result in [
            ("Compilation", self.compilation),
            ("Slither Static Analysis", self.slither),
            ("SMTChecker Formal Verification", self.smtchecker),
            ("LLM Security Analysis", self.llm),
        ]:
            if result:
                status_emoji = "✅" if result.passed else "❌" if result.status == VerifierStatus.FAILED else "⚠️"
                lines.append(f"### {name} {status_emoji}")
                lines.append("")
                lines.append(f"**Status:** {result.status.value}")
                lines.append(f"**Duration:** {result.duration_ms}ms")
                
                if result.properties_checked > 0:
                    lines.append(f"**Properties:** {result.properties_proven}/{result.properties_checked} proven")
                
                lines.append("")
        
        # Add detailed findings
        if self.all_findings:
            lines.extend([
                "## Detailed Findings",
                "",
            ])
            
            for finding in sorted(self.all_findings, key=lambda f: f.severity.weight, reverse=True):
                lines.append(finding.to_markdown())
                lines.append("")
        
        lines.extend([
            "---",
            f"*Generated by VeriSol v{self.version}*",
        ])
        
        return "\n".join(lines)
    
    def to_json(self) -> dict[str, Any]:
        """Export as JSON-serializable dict."""
        return self.model_dump(mode="json")


# Known false positive patterns with minimum version requirements
# Format: pattern -> (min_major, min_minor, min_patch) or None for always FP
KNOWN_FP_PATTERNS: dict[str, tuple[int, int, int] | None] = {
    "integer-overflow": (0, 8, 0),   # Solidity 0.8+ has built-in overflow protection
    "integer-underflow": (0, 8, 0),  # Solidity 0.8+ has built-in underflow protection
    "out-of-bounds": None,           # Always FP - Solidity auto-reverts
    "self-destruct": (0, 8, 18),     # selfdestruct deprecated in 0.8.18+
}


def _parse_version(version_str: str) -> tuple[int, int, int] | None:
    """Parse Solidity version string like '0.8.24' or '^0.8.0' into tuple."""
    import re
    match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", version_str)
    if match:
        major = int(match.group(1))
        minor = int(match.group(2))
        patch = int(match.group(3)) if match.group(3) else 0
        return (major, minor, patch)
    return None


def _version_gte(version: tuple[int, int, int], min_version: tuple[int, int, int]) -> bool:
    """Check if version >= min_version."""
    return version >= min_version


def _is_known_fp_pattern(finding: Finding, solidity_version: str | None) -> bool:
    """Check if a finding matches a known false positive pattern."""
    if solidity_version is None:
        return False

    parsed_version = _parse_version(solidity_version)
    if parsed_version is None:
        return False

    detector = finding.detector.lower()
    for pattern, min_version in KNOWN_FP_PATTERNS.items():
        if pattern in detector:
            if min_version is None:  # Always FP
                return True
            if _version_gte(parsed_version, min_version):
                return True
    return False


def _find_similar_finding(
    finding: Finding,
    other_findings: list[Finding],
    match_threshold: float = 0.7,
) -> Finding | None:
    """Find a similar finding in another tool's results."""
    for other in other_findings:
        # Same detector type
        if finding.detector.lower() == other.detector.lower():
            return other

        # Overlapping line numbers (if both have them)
        if finding.line_start and other.line_start:
            # Within 5 lines of each other
            if abs(finding.line_start - other.line_start) <= 5:
                # Similar type keywords
                f_type = finding.detector.lower()
                o_type = other.detector.lower()
                for keyword in ["reentrancy", "overflow", "underflow", "access", "delegatecall"]:
                    if keyword in f_type and keyword in o_type:
                        return other

    return None


def compute_confidence(
    finding: Finding,
    other_tool_results: list[VerificationResult] | None = None,
    solidity_version: str | None = None,
) -> tuple[Confidence, list[str]]:
    """
    Compute confidence level for a finding.

    The confidence scoring considers:
    1. LLM self-reported confidence (from raw_confidence)
    2. Cross-tool agreement (if multiple tools flag the same issue)
    3. Known FP patterns (version-specific or general)

    Args:
        finding: The finding to score
        other_tool_results: Results from other verification tools
        solidity_version: Solidity version of the contract

    Returns:
        Tuple of (Confidence level, list of contributing factors)
    """
    score = 0.5  # Base score
    factors: list[str] = []

    # 1. LLM self-reported confidence
    if finding.raw_confidence:
        raw = finding.raw_confidence.lower()
        if raw in ("high", "h"):
            score += 0.2
            factors.append("LLM reports high confidence")
        elif raw in ("low", "l"):
            score -= 0.2
            factors.append("LLM reports low confidence")

    # 2. Cross-tool agreement
    if other_tool_results:
        confirming_tools: list[str] = []
        for result in other_tool_results:
            if result.verifier == finding.verifier:
                continue  # Skip self
            match = _find_similar_finding(finding, result.findings)
            if match:
                confirming_tools.append(result.verifier)

        if confirming_tools:
            bonus = min(0.3, len(confirming_tools) * 0.15)
            score += bonus
            tools_str = ", ".join(confirming_tools)
            factors.append(f"Confirmed by: {tools_str}")

    # 3. Known FP patterns
    if _is_known_fp_pattern(finding, solidity_version):
        score -= 0.3
        factors.append("Matches known FP pattern for this Solidity version")

    # 4. Severity-based adjustment
    if finding.severity in (Severity.CRITICAL, Severity.HIGH):
        score += 0.05
        factors.append("High severity finding")

    # 5. Has specific location info
    if finding.line_start:
        score += 0.05
        factors.append("Has specific line location")

    # Convert score to confidence level
    if score >= 0.7:
        confidence = Confidence.HIGH
    elif score >= 0.4:
        confidence = Confidence.MEDIUM
    else:
        confidence = Confidence.LOW

    if not factors:
        factors.append("Default confidence")

    return confidence, factors


def apply_confidence_scoring(
    report: AuditReport,
    solidity_version: str | None = None,
) -> None:
    """
    Apply confidence scoring to all findings in an audit report.

    This mutates the findings in place, updating their confidence and
    confidence_factors fields.

    Args:
        report: The audit report to process
        solidity_version: Solidity version (used for FP pattern detection)
    """
    # Collect all results for cross-tool comparison
    all_results = [
        r for r in [report.slither, report.smtchecker, report.llm]
        if r is not None
    ]

    # Process each result's findings
    for result in all_results:
        other_results = [r for r in all_results if r != result]
        for finding in result.findings:
            confidence, factors = compute_confidence(
                finding,
                other_tool_results=other_results,
                solidity_version=solidity_version,
            )
            finding.confidence = confidence
            finding.confidence_factors = factors
