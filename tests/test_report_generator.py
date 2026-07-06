"""
Tests for report_generator.py's live-mode Claude path (_generate_with_claude).

This file did not exist before this repo was touched to swap in the shared
claude_client.call_claude() wrapper -- _generate_with_claude() had zero test
coverage beforehand. Demo-mode report assembly (_assemble_brief, _build_flags)
is exercised indirectly elsewhere via seed-data-driven CLI tests and is not
duplicated here.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from models import AssessmentReport, OTEnvironment
from report_generator import ReportGeneratorError, generate_report


def _make_report() -> AssessmentReport:
    env = OTEnvironment(
        name="Test Plant",
        sector="ENERGY",
        purdue_levels_present=[1, 2, 3],
        internet_exposed_levels=[3],
        vendor_list=["Siemens"],
        description="Test facility",
    )
    return AssessmentReport(
        environment=env,
        prepared_date="2026-07-06",
        total_advisories_checked=5,
        applicable_advisories=3,
        results=[],
        critical_count=1,
        high_count=1,
        medium_count=1,
        low_count=0,
        overall_risk_tier="CRITICAL",
        volt_typhoon_flags=1,
        brief_text="",
    )


class TestGenerateWithClaude:
    def test_no_api_key_raises(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(ReportGeneratorError, match="ANTHROPIC_API_KEY"):
            generate_report(_make_report(), demo_mode=False)

    def test_success_returns_brief_and_flags(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        import report_generator
        monkeypatch.setattr(report_generator, "call_claude", lambda *a, **kw: "Live memo text.")
        brief, flags = generate_report(_make_report(), demo_mode=False)
        assert brief == "Live memo text."
        assert any("CRITICAL" in f for f in flags)

    def test_claude_failure_raises_report_generator_error(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        import report_generator
        def _raise(*a, **kw):
            raise RuntimeError("simulated API failure")
        monkeypatch.setattr(report_generator, "call_claude", _raise)
        with pytest.raises(ReportGeneratorError, match="Claude brief generation failed"):
            generate_report(_make_report(), demo_mode=False)
