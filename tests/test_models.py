"""Tests for models.py — dataclass construction and defaults."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from models import ICSAdvisory, OTEnvironment, ExposureResult, AssessmentReport


def _make_advisory(**kwargs) -> ICSAdvisory:
    defaults = dict(
        advisory_id="ICSA-24-001-01",
        title="Test Advisory",
        vendor="TestVendor",
        product="TestProduct",
        purdue_level=1,
        attack_vector="NETWORK",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        affected_sectors=["ENERGY"],
        patch_available=True,
        patching_feasible=False,
        mitigations=["Isolate from network"],
        published_date="2024-01-01",
        summary="Test summary of the advisory.",
    )
    defaults.update(kwargs)
    return ICSAdvisory(**defaults)


def _make_env(**kwargs) -> OTEnvironment:
    defaults = dict(
        name="Test Facility",
        sector="ENERGY",
        purdue_levels_present=[1, 2, 3],
        internet_exposed_levels=[3],
        vendor_list=["TestVendor"],
        description="A test OT environment.",
    )
    defaults.update(kwargs)
    return OTEnvironment(**defaults)


def _make_result(**kwargs) -> ExposureResult:
    defaults = dict(
        advisory_id="ICSA-24-001-01",
        vendor="TestVendor",
        product="TestProduct",
        purdue_level=1,
        cvss_score=7.5,
        exposure_score=72.5,
        tier="HIGH",
        vendor_match=True,
        level_match=True,
        internet_exposed=False,
        patch_feasible=False,
        patch_note="MITIGATE ONLY -- operationally constrained",
        mitigations=["Isolate from network"],
        volt_typhoon_vector=False,
    )
    defaults.update(kwargs)
    return ExposureResult(**defaults)


def _make_report(**kwargs) -> AssessmentReport:
    env = _make_env()
    defaults = dict(
        environment=env,
        prepared_date="2026-06-24",
        total_advisories_checked=20,
        applicable_advisories=5,
        results=[],
        critical_count=1,
        high_count=2,
        medium_count=2,
        low_count=0,
        overall_risk_tier="CRITICAL",
        volt_typhoon_flags=0,
        brief_text="Test brief.",
    )
    defaults.update(kwargs)
    return AssessmentReport(**defaults)


class TestICSAdvisory:
    def test_construction(self):
        adv = _make_advisory()
        assert adv.advisory_id == "ICSA-24-001-01"

    def test_vendor_stored(self):
        adv = _make_advisory(vendor="Siemens")
        assert adv.vendor == "Siemens"

    def test_purdue_level_stored(self):
        adv = _make_advisory(purdue_level=2)
        assert adv.purdue_level == 2

    def test_purdue_level_35(self):
        adv = _make_advisory(purdue_level=35)
        assert adv.purdue_level == 35

    def test_cvss_score_stored(self):
        adv = _make_advisory(cvss_score=9.8)
        assert adv.cvss_score == 9.8

    def test_attack_vector_stored(self):
        adv = _make_advisory(attack_vector="LOCAL")
        assert adv.attack_vector == "LOCAL"

    def test_patch_available_false(self):
        adv = _make_advisory(patch_available=False)
        assert adv.patch_available is False

    def test_patching_feasible_false(self):
        adv = _make_advisory(patching_feasible=False)
        assert adv.patching_feasible is False

    def test_affected_sectors_list(self):
        adv = _make_advisory(affected_sectors=["ENERGY", "WATER"])
        assert len(adv.affected_sectors) == 2

    def test_mitigations_list(self):
        adv = _make_advisory(mitigations=["A", "B", "C"])
        assert len(adv.mitigations) == 3


class TestOTEnvironment:
    def test_construction(self):
        env = _make_env()
        assert env.name == "Test Facility"

    def test_sector_stored(self):
        env = _make_env(sector="WATER")
        assert env.sector == "WATER"

    def test_purdue_levels_list(self):
        env = _make_env(purdue_levels_present=[1, 2, 3])
        assert env.purdue_levels_present == [1, 2, 3]

    def test_internet_exposed_levels_empty(self):
        env = _make_env(internet_exposed_levels=[])
        assert env.internet_exposed_levels == []

    def test_internet_exposed_level_35(self):
        env = _make_env(internet_exposed_levels=[35])
        assert 35 in env.internet_exposed_levels

    def test_vendor_list_stored(self):
        env = _make_env(vendor_list=["Siemens", "Rockwell"])
        assert len(env.vendor_list) == 2

    def test_description_stored(self):
        env = _make_env(description="Critical facility.")
        assert "Critical" in env.description


class TestExposureResult:
    def test_construction(self):
        r = _make_result()
        assert r.advisory_id == "ICSA-24-001-01"

    def test_tier_stored(self):
        r = _make_result(tier="CRITICAL")
        assert r.tier == "CRITICAL"

    def test_exposure_score_stored(self):
        r = _make_result(exposure_score=84.0)
        assert r.exposure_score == 84.0

    def test_vendor_match_flag(self):
        r = _make_result(vendor_match=True)
        assert r.vendor_match is True

    def test_level_match_flag(self):
        r = _make_result(level_match=False)
        assert r.level_match is False

    def test_volt_typhoon_false(self):
        r = _make_result(volt_typhoon_vector=False)
        assert r.volt_typhoon_vector is False

    def test_volt_typhoon_true(self):
        r = _make_result(purdue_level=35, internet_exposed=True, volt_typhoon_vector=True)
        assert r.volt_typhoon_vector is True

    def test_patch_feasible_flag(self):
        r = _make_result(patch_feasible=False)
        assert r.patch_feasible is False

    def test_advisory_field_defaults_none(self):
        r = _make_result()
        assert r.advisory is None

    def test_advisory_field_accepts_object(self):
        adv = _make_advisory()
        r = _make_result(advisory=adv)
        assert r.advisory is adv


class TestAssessmentReport:
    def test_construction(self):
        rpt = _make_report()
        assert rpt.overall_risk_tier == "CRITICAL"

    def test_counts_stored(self):
        rpt = _make_report(critical_count=2, high_count=3)
        assert rpt.critical_count == 2
        assert rpt.high_count == 3

    def test_volt_typhoon_flags_stored(self):
        rpt = _make_report(volt_typhoon_flags=1)
        assert rpt.volt_typhoon_flags == 1

    def test_results_empty_list(self):
        rpt = _make_report(results=[])
        assert rpt.results == []

    def test_diligence_flags_default_empty(self):
        rpt = _make_report()
        assert isinstance(rpt.diligence_flags, list)

    def test_environment_stored(self):
        env = _make_env(name="Custom Facility")
        rpt = _make_report(environment=env)
        assert rpt.environment.name == "Custom Facility"

    def test_prepared_date_stored(self):
        rpt = _make_report(prepared_date="2026-06-24")
        assert rpt.prepared_date == "2026-06-24"
