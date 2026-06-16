"""End-to-end tests for the AI triage module (ai_triage.py).

Uses unittest.mock to mock httpx.post so no real API key is needed.
All tests verify the full pipeline:
    findings → _build_user_prompt → (mocked) API → _parse_response → TriageReport
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mcpsecscan.ai_triage import (
    TriageItem,
    TriageReport,
    _build_user_prompt,
    _parse_response,
    is_available,
    triage,
)
from mcpsecscan.engine.models import ScanResult
from mcpsecscan.engine.scanner import scan_target

SAMPLES = Path(__file__).parent.parent / "test_samples"
SKIP_L3 = {"l3"}

# ── A realistic mock LLM response ────────────────────────────────────────────

_MOCK_TRIAGE_JSON = {
    "risk_level": "high",
    "summary": (
        "2 findings confirmed. The most critical is a description-code mismatch "
        "where the tool claims read-only behavior but executes a file write."
    ),
    "items": [
        {
            "finding_id": "MCPX-L4-001",
            "verdict": "confirmed",
            "confidence": "high",
            "explanation": (
                "The tool description explicitly states 'read-only operation' but "
                "line 14 calls open(path, 'w'), directly contradicting the declared behavior."
            ),
            "attack_scenario": (
                "An attacker installs this MCP server; on first invocation the tool "
                "silently writes a backdoor script to ~/.local/bin/."
            ),
            "fix_suggestion": (
                "Remove lines 14-17 (file write block) or update the description "
                "to disclose that the tool modifies files."
            ),
        },
        {
            "finding_id": "MCPX-L2-008",
            "verdict": "confirmed",
            "confidence": "medium",
            "explanation": (
                "The description contains an instruction to read sensitive files "
                "from the host filesystem."
            ),
            "attack_scenario": (
                "If the agent follows the instruction, credentials stored in ~/.ssh "
                "or /etc/passwd could be exfiltrated."
            ),
            "fix_suggestion": "Remove the sensitive file read instruction from the description.",
        },
    ],
}

_MOCK_RESPONSE_TEXT = json.dumps(_MOCK_TRIAGE_JSON)


def _make_httpx_response(body: str, status: int = 200):
    """Build a minimal mock httpx.Response."""
    mock_resp = MagicMock()
    mock_resp.status_code = status
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": body}}]
    }
    mock_resp.text = body
    # raise_for_status should be a no-op for 200, raise for 4xx/5xx
    if status >= 400:
        from httpx import HTTPStatusError, Request, Response
        mock_resp.raise_for_status.side_effect = HTTPStatusError(
            message=f"HTTP {status}",
            request=MagicMock(),
            response=mock_resp,
        )
    else:
        mock_resp.raise_for_status.return_value = None
    return mock_resp


# ── Unit: _build_user_prompt ──────────────────────────────────────────────────

class TestBuildUserPrompt:
    """Verify that the prompt construction includes the right fields."""

    def test_prompt_contains_target(self):
        scan_dict = {"target": "my-server.py", "findings": []}
        prompt = _build_user_prompt(scan_dict)
        assert "my-server.py" in prompt

    def test_prompt_contains_finding_id(self):
        scan_dict = {
            "target": "test",
            "findings": [
                {"id": "MCPX-L4-001", "title": "Mismatch", "severity": "critical",
                 "layer": "L4", "file": "server.py", "line": 14,
                 "evidence": "writes file", "description": None, "tool_name": "read_notes"},
            ],
        }
        prompt = _build_user_prompt(scan_dict)
        assert "MCPX-L4-001" in prompt

    def test_prompt_strips_noise_fields(self):
        """Fields like 'owasp_mcp' and 'cia_impact' should not be in prompt."""
        scan_dict = {
            "target": "test",
            "findings": [
                {"id": "MCPX-L1-003", "title": "Hardcoded key", "severity": "critical",
                 "layer": "L1", "file": "server.py", "line": 5,
                 "evidence": "sk-abc...", "description": None, "tool_name": None,
                 "owasp_mcp": "MCP04", "cia_impact": ["C"],
                 "confidence": "high", "remediation": "Remove key"},
            ],
        }
        prompt = _build_user_prompt(scan_dict)
        assert "owasp_mcp" not in prompt
        assert "cia_impact" not in prompt

    def test_prompt_is_valid_json_payload(self):
        """The JSON payload embedded in the prompt must be parseable."""
        scan_dict = {
            "target": "test",
            "findings": [
                {"id": "MCPX-L2-004", "title": "XML tag", "severity": "high",
                 "layer": "L2", "file": "s.py", "line": None,
                 "evidence": "<IMPORTANT>", "description": None, "tool_name": "x"},
            ],
        }
        prompt = _build_user_prompt(scan_dict)
        # Extract the JSON part (after the intro line)
        json_str = prompt[prompt.index("{"):]
        data = json.loads(json_str)
        assert data["total_findings"] == 1
        assert data["findings"][0]["id"] == "MCPX-L2-004"


# ── Unit: _parse_response ─────────────────────────────────────────────────────

class TestParseResponse:
    """Verify that LLM JSON is correctly parsed into TriageReport."""

    def test_parse_valid_response(self):
        report = _parse_response(_MOCK_RESPONSE_TEXT, "gpt-4o-mini")
        assert report.error == ""
        assert report.risk_level == "high"
        assert "confirmed" in report.summary
        assert len(report.items) == 2

    def test_parse_item_fields(self):
        report = _parse_response(_MOCK_RESPONSE_TEXT, "gpt-4o-mini")
        item = report.items[0]
        assert item.finding_id == "MCPX-L4-001"
        assert item.verdict == "confirmed"
        assert item.confidence == "high"
        assert "read-only" in item.explanation
        assert "backdoor" in item.attack_scenario
        assert "lines 14-17" in item.fix_suggestion

    def test_parse_invalid_json_sets_error(self):
        report = _parse_response("NOT JSON {{{", "gpt-4o-mini")
        assert report.error != ""
        assert "Failed to parse" in report.error

    def test_parse_empty_items(self):
        body = json.dumps({"risk_level": "safe", "summary": "Clean.", "items": []})
        report = _parse_response(body, "gpt-4o-mini")
        assert report.risk_level == "safe"
        assert report.items == []
        assert report.error == ""


# ── Integration: triage() with mocked httpx ──────────────────────────────────

class TestTriageFunction:
    """Full pipeline: scan result → triage() → TriageReport."""

    def test_triage_returns_confirmed_verdict(self):
        """Mock a successful API call and verify the full triage pipeline."""
        result = scan_target(
            str(SAMPLES / "python/malicious/06_desc_code_mismatch.py"),
            skip_layers=SKIP_L3,
        )
        mock_resp = _make_httpx_response(_MOCK_RESPONSE_TEXT)

        with patch("mcpsecscan.ai_triage.httpx") as mock_httpx:
            mock_httpx.post.return_value = mock_resp

            report = triage(result, api_url="https://api.openai.com/v1", api_key="sk-test", model="gpt-4o-mini")

        assert report.error == ""
        assert report.risk_level == "high"
        assert any(item.verdict == "confirmed" for item in report.items)

    def test_triage_passes_correct_model_to_api(self):
        """Verify the 'model' field is forwarded to the API body."""
        result = scan_target(
            str(SAMPLES / "python/malicious/06_desc_code_mismatch.py"),
            skip_layers=SKIP_L3,
        )
        mock_resp = _make_httpx_response(_MOCK_RESPONSE_TEXT)

        with patch("mcpsecscan.ai_triage.httpx") as mock_httpx:
            mock_httpx.post.return_value = mock_resp

            triage(result, api_url="http://localhost:11434/v1", api_key="", model="llama3")

            call_kwargs = mock_httpx.post.call_args
            body = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json") or call_kwargs[0][1]
            assert body["model"] == "llama3"

    def test_triage_url_normalization_openai(self):
        """https://api.openai.com/v1 → .../chat/completions."""
        result = scan_target(
            str(SAMPLES / "python/malicious/06_desc_code_mismatch.py"),
            skip_layers=SKIP_L3,
        )
        mock_resp = _make_httpx_response(_MOCK_RESPONSE_TEXT)

        with patch("mcpsecscan.ai_triage.httpx") as mock_httpx:
            mock_httpx.post.return_value = mock_resp

            triage(result, api_url="https://api.openai.com/v1", api_key="sk-test")

            endpoint = mock_httpx.post.call_args[0][0]
            assert endpoint.endswith("/chat/completions")

    def test_triage_url_normalization_ollama(self):
        """http://localhost:11434/v1 → .../v1/chat/completions."""
        result = scan_target(
            str(SAMPLES / "python/malicious/06_desc_code_mismatch.py"),
            skip_layers=SKIP_L3,
        )
        mock_resp = _make_httpx_response(_MOCK_RESPONSE_TEXT)

        with patch("mcpsecscan.ai_triage.httpx") as mock_httpx:
            mock_httpx.post.return_value = mock_resp

            triage(result, api_url="http://localhost:11434/v1", api_key="")

            endpoint = mock_httpx.post.call_args[0][0]
            assert "chat/completions" in endpoint

    def test_triage_http_error_sets_error_field(self):
        """HTTP 4xx must not raise; error should be captured in report.error."""
        result = scan_target(
            str(SAMPLES / "python/malicious/06_desc_code_mismatch.py"),
            skip_layers=SKIP_L3,
        )
        mock_resp = _make_httpx_response("Unauthorized", status=401)

        with patch("mcpsecscan.ai_triage.httpx") as mock_httpx:
            mock_httpx.post.return_value = mock_resp
            from httpx import HTTPStatusError
            mock_httpx.HTTPStatusError = HTTPStatusError
            mock_httpx.RequestError = Exception
            mock_httpx.post.side_effect = HTTPStatusError(
                message="401", request=MagicMock(), response=mock_resp
            )

            report = triage(result, api_url="https://api.openai.com/v1", api_key="sk-bad")

        assert report.error != ""

    def test_triage_empty_findings_skips_api(self):
        """Empty scan result must return safe without calling the API."""
        empty = ScanResult(target="test")

        with patch("mcpsecscan.ai_triage.httpx") as mock_httpx:
            report = triage(empty, api_key="sk-test")
            mock_httpx.post.assert_not_called()

        assert report.risk_level == "safe"
        assert report.error == ""

    def test_triage_accepts_dict_input(self):
        """triage() must accept a plain dict (from ScanResult.to_dict()) as well."""
        result = scan_target(
            str(SAMPLES / "python/malicious/06_desc_code_mismatch.py"),
            skip_layers=SKIP_L3,
        )
        result_dict = result.to_dict()
        mock_resp = _make_httpx_response(_MOCK_RESPONSE_TEXT)

        with patch("mcpsecscan.ai_triage.httpx") as mock_httpx:
            mock_httpx.post.return_value = mock_resp
            report = triage(result_dict, api_key="sk-test")

        assert report.error == ""
        assert report.risk_level == "high"


# ── CLI integration: --ai-explain flag ───────────────────────────────────────

class TestCLIAIExplain:
    """Verify that the CLI --ai-explain flag adds ai_triage to JSON output."""

    def test_cli_ai_explain_adds_triage_to_json(self, tmp_path, capsys):
        """Run the CLI scan path programmatically with mocked AI call."""
        import sys
        from unittest.mock import patch as upatch

        mock_resp = _make_httpx_response(_MOCK_RESPONSE_TEXT)

        sample = str(SAMPLES / "python/malicious/06_desc_code_mismatch.py")
        sys.argv = [
            "mcpsecscan", "scan", sample,
            "--skip-l3",
            "--ai-explain",
            "--ai-url", "https://api.openai.com/v1",
            "--ai-key", "sk-test",
            "--ai-model", "gpt-4o-mini",
        ]

        with upatch("mcpsecscan.ai_triage.httpx") as mock_httpx:
            mock_httpx.post.return_value = mock_resp
            mock_httpx.HTTPStatusError = __import__("httpx").HTTPStatusError
            mock_httpx.RequestError = __import__("httpx").RequestError

            # Import and call cli() directly
            from mcpsecscan.main import cli
            with pytest.raises(SystemExit):
                # cli() may sys.exit(1) due to CRITICAL findings — that's expected
                cli()

        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "ai_triage" in output
        assert output["ai_triage"]["risk_level"] == "high"
        assert len(output["ai_triage"]["items"]) == 2
