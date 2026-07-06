"""Tests for advisory_parser.py — dict-to-dataclass conversion and validation."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from advisory_parser import parse_advisory, parse_advisories, _dict_to_advisory, AdvisoryParserError
from seed_data import DEMO_ADVISORIES


def _raw(**kwargs) -> dict:
    base = {
        "advisory_id": "ICSA-24-001-01",
        "title": "Test Advisory Title",
        "vendor": "TestVendor",
        "product": "TestProduct v1.0",
        "purdue_level": 1,
        "attack_vector": "NETWORK",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "affected_sectors": ["ENERGY"],
        "patch_available": True,
        "patching_feasible": False,
        "mitigations": ["Isolate from network", "Apply firewall rules"],
        "published_date": "2024-01-01",
        "summary": "Test advisory for unit testing purposes.",
    }
    base.update(kwargs)
    return base


class TestDictToAdvisory:
    def test_returns_ics_advisory(self):
        from models import ICSAdvisory
        adv = _dict_to_advisory(_raw())
        assert isinstance(adv, ICSAdvisory)

    def test_advisory_id_stored(self):
        adv = _dict_to_advisory(_raw(advisory_id="ICSA-24-999-01"))
        assert adv.advisory_id == "ICSA-24-999-01"

    def test_vendor_stored(self):
        adv = _dict_to_advisory(_raw(vendor="Siemens"))
        assert adv.vendor == "Siemens"

    def test_purdue_level_stored(self):
        adv = _dict_to_advisory(_raw(purdue_level=2))
        assert adv.purdue_level == 2

    def test_purdue_level_35_accepted(self):
        adv = _dict_to_advisory(_raw(purdue_level=35))
        assert adv.purdue_level == 35

    def test_purdue_level_0_accepted(self):
        adv = _dict_to_advisory(_raw(purdue_level=0))
        assert adv.purdue_level == 0

    def test_cvss_score_stored(self):
        adv = _dict_to_advisory(_raw(cvss_score=9.8))
        assert adv.cvss_score == 9.8

    def test_attack_vector_uppercased(self):
        adv = _dict_to_advisory(_raw(attack_vector="local"))
        assert adv.attack_vector == "LOCAL"

    def test_patch_available_stored(self):
        adv = _dict_to_advisory(_raw(patch_available=False))
        assert adv.patch_available is False

    def test_patching_feasible_stored(self):
        adv = _dict_to_advisory(_raw(patching_feasible=False))
        assert adv.patching_feasible is False

    def test_mitigations_stored(self):
        adv = _dict_to_advisory(_raw(mitigations=["A", "B"]))
        assert len(adv.mitigations) == 2

    def test_affected_sectors_uppercase(self):
        adv = _dict_to_advisory(_raw(affected_sectors=["energy", "water"]))
        assert "ENERGY" in adv.affected_sectors
        assert "WATER" in adv.affected_sectors


class TestDictToAdvisoryValidation:
    def test_invalid_purdue_level_raises(self):
        with pytest.raises(AdvisoryParserError, match="invalid purdue_level"):
            _dict_to_advisory(_raw(purdue_level=5))

    def test_purdue_level_99_raises(self):
        with pytest.raises(AdvisoryParserError):
            _dict_to_advisory(_raw(purdue_level=99))

    def test_invalid_attack_vector_raises(self):
        with pytest.raises(AdvisoryParserError, match="invalid attack_vector"):
            _dict_to_advisory(_raw(attack_vector="WIRELESS"))

    def test_cvss_above_10_raises(self):
        with pytest.raises(AdvisoryParserError, match="out of range"):
            _dict_to_advisory(_raw(cvss_score=10.1))

    def test_cvss_negative_raises(self):
        with pytest.raises(AdvisoryParserError, match="out of range"):
            _dict_to_advisory(_raw(cvss_score=-1.0))

    def test_cvss_exactly_10_accepted(self):
        adv = _dict_to_advisory(_raw(cvss_score=10.0))
        assert adv.cvss_score == 10.0

    def test_cvss_exactly_0_accepted(self):
        adv = _dict_to_advisory(_raw(cvss_score=0.0))
        assert adv.cvss_score == 0.0


class TestParseAdvisory:
    def test_demo_mode_no_extraction(self):
        raw = _raw()
        adv = parse_advisory(raw, demo_mode=True)
        assert adv.advisory_id == "ICSA-24-001-01"

    def test_demo_mode_with_needs_extraction_flag(self):
        raw = _raw()
        raw["_needs_extraction"] = True
        # Demo mode: should still work — extraction only happens in live mode
        adv = parse_advisory(raw, demo_mode=True)
        assert adv.advisory_id == "ICSA-24-001-01"


class TestParseAdvisories:
    def test_parses_all_demo_advisories(self):
        advisories = parse_advisories(DEMO_ADVISORIES, demo_mode=True)
        assert len(advisories) == 20

    def test_all_are_ics_advisory_objects(self):
        from models import ICSAdvisory
        advisories = parse_advisories(DEMO_ADVISORIES, demo_mode=True)
        for adv in advisories:
            assert isinstance(adv, ICSAdvisory)

    def test_advisory_ids_preserved(self):
        advisories = parse_advisories(DEMO_ADVISORIES, demo_mode=True)
        raw_ids = {a["advisory_id"] for a in DEMO_ADVISORIES}
        parsed_ids = {a.advisory_id for a in advisories}
        assert raw_ids == parsed_ids

    def test_cvss_scores_preserved(self):
        advisories = parse_advisories(DEMO_ADVISORIES, demo_mode=True)
        raw_scores = {a["advisory_id"]: a["cvss_score"] for a in DEMO_ADVISORIES}
        for adv in advisories:
            assert adv.cvss_score == raw_scores[adv.advisory_id]

    def test_purdue_levels_preserved(self):
        advisories = parse_advisories(DEMO_ADVISORIES, demo_mode=True)
        raw_levels = {a["advisory_id"]: a["purdue_level"] for a in DEMO_ADVISORIES}
        for adv in advisories:
            assert adv.purdue_level == raw_levels[adv.advisory_id]

    def test_siemens_s7_parses_correctly(self):
        advisories = parse_advisories(DEMO_ADVISORIES, demo_mode=True)
        s7 = next(a for a in advisories if a.advisory_id == "ICSA-24-102-01")
        assert s7.vendor == "Siemens"
        assert s7.purdue_level == 1
        assert s7.cvss_score == 9.8
        assert s7.attack_vector == "NETWORK"
        assert s7.patch_available is True
        assert s7.patching_feasible is False

    def test_emerson_roc800_no_patch(self):
        advisories = parse_advisories(DEMO_ADVISORIES, demo_mode=True)
        roc = next(a for a in advisories if a.advisory_id == "ICSA-23-229-02")
        assert roc.patch_available is False
        assert roc.patching_feasible is False

    def test_scalance_is_level_35(self):
        advisories = parse_advisories(DEMO_ADVISORIES, demo_mode=True)
        scalance = next(a for a in advisories if "SCALANCE" in a.product)
        assert scalance.purdue_level == 35


class TestExtractWithClaude:
    """
    _extract_with_claude() had zero test coverage before this file was
    touched to swap in the shared claude_client.call_claude() wrapper --
    added here alongside that change.
    """

    def test_no_api_key_raises(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        from advisory_parser import _extract_with_claude
        with pytest.raises(AdvisoryParserError, match="ANTHROPIC_API_KEY"):
            _extract_with_claude(_raw(_needs_extraction=True))

    def test_success_merges_extracted_fields(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        extracted_literal = (
            "{'vendor': 'Rockwell', 'product': 'ControlLogix', 'purdue_level': 2, "
            "'attack_vector': 'ADJACENT', 'cvss_score': 8.1, 'patch_available': True, "
            "'patching_feasible': True, 'affected_sectors': ['MANUFACTURING'], "
            "'mitigations': ['Segment network']}"
        )
        import advisory_parser
        monkeypatch.setattr(advisory_parser, "call_claude", lambda *a, **kw: extracted_literal)
        result = advisory_parser._extract_with_claude(_raw(_needs_extraction=True))
        assert result["vendor"] == "Rockwell"
        assert result["purdue_level"] == 2
        assert "_needs_extraction" not in result

    def test_claude_failure_raises_advisory_parser_error(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        import advisory_parser
        def _raise(*a, **kw):
            raise RuntimeError("simulated API failure")
        monkeypatch.setattr(advisory_parser, "call_claude", _raise)
        with pytest.raises(AdvisoryParserError, match="Claude extraction failed"):
            advisory_parser._extract_with_claude(_raw(_needs_extraction=True))
