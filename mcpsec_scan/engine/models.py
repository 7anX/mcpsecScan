"""Data models for mcpx scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    NEEDS_REVIEW = "needs-review"


class CIAImpact(str, Enum):
    CONFIDENTIALITY = "C"
    INTEGRITY = "I"
    AVAILABILITY = "A"


class SecurityProperty(str, Enum):
    DATA_ISOLATION = "data_isolation"
    TASK_ALIGNMENT = "task_alignment"
    SOURCE_AUTHORIZATION = "source_authorization"
    ACTION_ALIGNMENT = "action_alignment"


@dataclass
class Finding:
    """A single security finding."""

    id: str                              # e.g. "MCPX-019"
    title: str                           # human-readable title
    severity: Severity
    layer: str                           # "L1" / "L2" / "L3" / "L4"
    file: str                            # file path
    line: int = 0                        # line number (0 = unknown)
    evidence: str = ""                   # what matched / data flow path
    description: str = ""                # detailed explanation
    remediation: str = ""                # how to fix
    owasp_mcp: str = ""                  # e.g. "MCP03"
    cia_impact: list[CIAImpact] = field(default_factory=list)
    security_property: Optional[SecurityProperty] = None
    confidence: Confidence = Confidence.HIGH
    tool_name: str = ""                  # which MCP tool is affected

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "layer": self.layer,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
            "description": self.description,
            "remediation": self.remediation,
            "owasp_mcp": self.owasp_mcp,
            "cia_impact": [c.value for c in self.cia_impact],
            "security_property": self.security_property.value if self.security_property else "",
            "confidence": self.confidence.value,
            "tool_name": self.tool_name,
        }


@dataclass
class ScanResult:
    """Aggregated scan result for a target."""

    target: str
    findings: list[Finding] = field(default_factory=list)
    scan_time_ms: int = 0
    suite_version: str = "0.1.0"
    errors: list[str] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "total_findings": len(self.findings),
            "scan_time_ms": self.scan_time_ms,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }
