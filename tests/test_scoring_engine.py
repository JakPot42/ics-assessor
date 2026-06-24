"""Tests for scoring_engine.py — formula, tier boundaries, matching, assess_environment."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from models import ICSAdvisory, OTEnvironment
from scoring_engine import (
    compute_exposure_score, score_to_tier, vendor_match, level_match,
    assess_environment, _patch_note, _overall_tier,
)
from seed_data import DEMO_ADVISORIES, DEMO_ENVIRONMENTS
from advisory_parser import parse_advisories


def _adv(
    vendor="TestVendor", purdue_level=1, attack_vector="NETWORK", cvss_score=7.5,
    patch_available=True, patching_feasible=True,
) -> ICSAdvisory:
    return ICSAdvisory(
        advisory_id="ICSA-99-001-01", title="Test", vendor=vendor, product="TestProduct",
        purdue_level=purdue_level, attack_vector=attack_vector, cvss_score=cvss_score,
        cvss_vector="", affected_sectors=["ENERGY"], patch_available=patch_available,
        patching_feasible=patching_feasible, mitigations=["Mitigate"], published_date="2024-01-01",
        summary="Test advisory.",
    )


def _env(
    vendor_list=("TestVendor",),
    purdue_levels_present=(1, 2, 3),
    internet_exposed_levels=(),
) -> OTEnvironment:
    return OTEnvironment(
        name="Test Facility", sector="ENERGY",
        purdue_levels_present=list(purdue_levels_present),
        internet_exposed_levels=list(internet_exposed_levels),
        vendor_list=list(vendor_list),
        description="Test.",
    )


# ---------------------------------------------------------------------------
# compute_exposure_score
# ---------------------------------------------------------------------------

class TestComputeExposureScore:
    def test_siemens_s7_1500_critical(self):
        # ICSA-24-102-01: L1, NETWORK, CVSS 9.8 -> (9.8/10)*50 + (2.5/3.0)*30 + 10 = 49+25+10 = 84.0
        adv = _adv(purdue_level=1, attack_vector="NETWORK", cvss_score=9.8)
        env = _env()
        assert compute_exposure_score(adv, env) == 84.0

    def test_rockwell_controllogix_critical(self):
        # L1, NETWORK, CVSS 9.0 -> 45+25+10 = 80.0
        adv = _adv(purdue_level=1, attack_vector="NETWORK", cvss_score=9.0)
        env = _env()
        assert compute_exposure_score(adv, env) == 80.0

    def test_emerson_deltav_high(self):
        # L2, NETWORK, CVSS 8.6 -> (8.6/10)*50 + (2.0/3.0)*30 + 10 = 43+20+10 = 73.0
        adv = _adv(purdue_level=2, attack_vector="NETWORK", cvss_score=8.6)
        env = _env()
        assert compute_exposure_score(adv, env) == 73.0

    def test_honeywell_experion_high(self):
        # L2, NETWORK, CVSS 7.5 -> 37.5+20+10 = 67.5
        adv = _adv(purdue_level=2, attack_vector="NETWORK", cvss_score=7.5)
        env = _env()
        assert compute_exposure_score(adv, env) == 67.5

    def test_rockwell_factorytalk_medium(self):
        # L3, LOCAL, CVSS 6.0 -> 30+15+5 = 50.0
        adv = _adv(purdue_level=3, attack_vector="LOCAL", cvss_score=6.0)
        env = _env()
        assert compute_exposure_score(adv, env) == 50.0

    def test_siemens_siprotec_medium(self):
        # L3, PHYSICAL, CVSS 6.5 -> 32.5+15+7 = 54.5
        adv = _adv(purdue_level=3, attack_vector="PHYSICAL", cvss_score=6.5)
        env = _env()
        assert compute_exposure_score(adv, env) == 54.5

    def test_claroty_low(self):
        # L4, LOCAL, CVSS 4.0 -> 20+10+5 = 35.0
        adv = _adv(purdue_level=4, attack_vector="LOCAL", cvss_score=4.0)
        env = _env()
        assert compute_exposure_score(adv, env) == 35.0

    def test_nozomi_low(self):
        # L4, LOCAL, CVSS 3.8 -> 19+10+5 = 34.0
        adv = _adv(purdue_level=4, attack_vector="LOCAL", cvss_score=3.8)
        env = _env()
        assert compute_exposure_score(adv, env) == 34.0

    def test_internet_exposure_bonus_applies(self):
        # L3, NETWORK, CVSS 6.5 without bonus = 32.5+15+10 = 57.5
        # L3, NETWORK, CVSS 6.5 with internet at L3 = 57.5+15 = 72.5
        adv = _adv(purdue_level=3, attack_vector="NETWORK", cvss_score=6.5)
        env_no_internet = _env(internet_exposed_levels=[])
        env_with_internet = _env(internet_exposed_levels=[3])
        score_no = compute_exposure_score(adv, env_no_internet)
        score_with = compute_exposure_score(adv, env_with_internet)
        assert score_with - score_no == 15.0

    def test_scalance_l35_without_internet_is_high(self):
        # L35, NETWORK, CVSS 9.6, no internet: 48+12+10 = 70.0 HIGH
        adv = _adv(purdue_level=35, attack_vector="NETWORK", cvss_score=9.6)
        env = _env(internet_exposed_levels=[])
        assert compute_exposure_score(adv, env) == 70.0

    def test_scalance_l35_with_internet_is_critical(self):
        # L35, NETWORK, CVSS 9.6, internet at L35: 48+12+10+15 = 85.0 CRITICAL (Volt Typhoon!)
        adv = _adv(purdue_level=35, attack_vector="NETWORK", cvss_score=9.6)
        env = _env(internet_exposed_levels=[35])
        assert compute_exposure_score(adv, env) == 85.0

    def test_abb_ac500_adjacent_high(self):
        # L1, ADJACENT, CVSS 8.5 -> 42.5+25+8 = 75.5 HIGH
        adv = _adv(purdue_level=1, attack_vector="ADJACENT", cvss_score=8.5)
        env = _env()
        assert compute_exposure_score(adv, env) == 75.5

    def test_emerson_roc800_high(self):
        # L1, NETWORK, CVSS 8.0 -> 40+25+10 = 75.0 HIGH
        adv = _adv(purdue_level=1, attack_vector="NETWORK", cvss_score=8.0)
        env = _env()
        assert compute_exposure_score(adv, env) == 75.0

    def test_mitsubishi_melsec_medium(self):
        # L3, ADJACENT, CVSS 6.0 -> 30+15+8 = 53.0 MEDIUM
        adv = _adv(purdue_level=3, attack_vector="ADJACENT", cvss_score=6.0)
        env = _env()
        assert compute_exposure_score(adv, env) == 53.0

    def test_fanuc_robot_medium(self):
        # L3, LOCAL, CVSS 5.5 -> 27.5+15+5 = 47.5 MEDIUM
        adv = _adv(purdue_level=3, attack_vector="LOCAL", cvss_score=5.5)
        env = _env()
        assert compute_exposure_score(adv, env) == 47.5

    def test_abb_acs880_medium(self):
        # L3, LOCAL, CVSS 6.5 -> 32.5+15+5 = 52.5 MEDIUM
        adv = _adv(purdue_level=3, attack_vector="LOCAL", cvss_score=6.5)
        env = _env()
        assert compute_exposure_score(adv, env) == 52.5

    def test_score_capped_at_100(self):
        adv = _adv(purdue_level=0, attack_vector="NETWORK", cvss_score=10.0)
        env = _env(internet_exposed_levels=[0])
        # 50 + 30 + 10 + 15 = 105 -> capped at 100
        assert compute_exposure_score(adv, env) == 100.0


# ---------------------------------------------------------------------------
# score_to_tier
# ---------------------------------------------------------------------------

class TestScoreToTier:
    def test_critical_at_80(self):
        assert score_to_tier(80.0) == "CRITICAL"

    def test_critical_at_84(self):
        assert score_to_tier(84.0) == "CRITICAL"

    def test_critical_at_100(self):
        assert score_to_tier(100.0) == "CRITICAL"

    def test_high_at_60(self):
        assert score_to_tier(60.0) == "HIGH"

    def test_high_at_79_9(self):
        assert score_to_tier(79.9) == "HIGH"

    def test_high_at_73(self):
        assert score_to_tier(73.0) == "HIGH"

    def test_medium_at_40(self):
        assert score_to_tier(40.0) == "MEDIUM"

    def test_medium_at_54_5(self):
        assert score_to_tier(54.5) == "MEDIUM"

    def test_medium_at_59_9(self):
        assert score_to_tier(59.9) == "MEDIUM"

    def test_low_at_0(self):
        assert score_to_tier(0.0) == "LOW"

    def test_low_at_35(self):
        assert score_to_tier(35.0) == "LOW"

    def test_low_at_39_9(self):
        assert score_to_tier(39.9) == "LOW"


# ---------------------------------------------------------------------------
# vendor_match
# ---------------------------------------------------------------------------

class TestVendorMatch:
    def test_exact_match(self):
        adv = _adv(vendor="Siemens")
        env = _env(vendor_list=["Siemens"])
        assert vendor_match(adv, env) is True

    def test_env_vendor_substring_of_adv_vendor(self):
        adv = _adv(vendor="Rockwell Automation")
        env = _env(vendor_list=["Rockwell"])
        assert vendor_match(adv, env) is True

    def test_adv_vendor_substring_of_env_vendor(self):
        adv = _adv(vendor="ABB")
        env = _env(vendor_list=["ABB Limited"])
        assert vendor_match(adv, env) is True

    def test_no_match(self):
        adv = _adv(vendor="Schneider Electric")
        env = _env(vendor_list=["Siemens", "Rockwell"])
        assert vendor_match(adv, env) is False

    def test_case_insensitive(self):
        adv = _adv(vendor="siemens")
        env = _env(vendor_list=["Siemens"])
        assert vendor_match(adv, env) is True

    def test_multiple_vendors_one_matches(self):
        adv = _adv(vendor="Honeywell")
        env = _env(vendor_list=["Emerson", "Honeywell", "ABB"])
        assert vendor_match(adv, env) is True

    def test_empty_vendor_list(self):
        adv = _adv(vendor="Siemens")
        env = _env(vendor_list=[])
        assert vendor_match(adv, env) is False


# ---------------------------------------------------------------------------
# level_match
# ---------------------------------------------------------------------------

class TestLevelMatch:
    def test_level_in_env(self):
        adv = _adv(purdue_level=1)
        env = _env(purdue_levels_present=[1, 2, 3])
        assert level_match(adv, env) is True

    def test_level_not_in_env(self):
        adv = _adv(purdue_level=35)
        env = _env(purdue_levels_present=[1, 2, 3])
        assert level_match(adv, env) is False

    def test_level_35_in_env(self):
        adv = _adv(purdue_level=35)
        env = _env(purdue_levels_present=[1, 2, 3, 35])
        assert level_match(adv, env) is True


# ---------------------------------------------------------------------------
# _patch_note
# ---------------------------------------------------------------------------

class TestPatchNote:
    def test_no_patch_available(self):
        adv = _adv(patch_available=False, patching_feasible=False)
        note = _patch_note(adv)
        assert "no patch available" in note

    def test_patch_available_but_constrained(self):
        adv = _adv(patch_available=True, patching_feasible=False)
        note = _patch_note(adv)
        assert "operationally constrained" in note

    def test_patch_available_and_feasible(self):
        adv = _adv(patch_available=True, patching_feasible=True)
        note = _patch_note(adv)
        assert note == "PATCH AVAILABLE"


# ---------------------------------------------------------------------------
# _overall_tier
# ---------------------------------------------------------------------------

class TestOverallTier:
    def test_any_critical_returns_critical(self):
        assert _overall_tier(critical=1, high=0, medium=0) == "CRITICAL"

    def test_three_or_more_high_returns_critical(self):
        assert _overall_tier(critical=0, high=3, medium=0) == "CRITICAL"

    def test_seven_high_returns_critical(self):
        assert _overall_tier(critical=0, high=7, medium=0) == "CRITICAL"

    def test_two_high_returns_high(self):
        assert _overall_tier(critical=0, high=2, medium=0) == "HIGH"

    def test_one_high_returns_high(self):
        assert _overall_tier(critical=0, high=1, medium=0) == "HIGH"

    def test_three_medium_returns_high(self):
        assert _overall_tier(critical=0, high=0, medium=3) == "HIGH"

    def test_one_medium_returns_medium(self):
        assert _overall_tier(critical=0, high=0, medium=1) == "MEDIUM"

    def test_all_zero_returns_low(self):
        assert _overall_tier(critical=0, high=0, medium=0) == "LOW"


# ---------------------------------------------------------------------------
# assess_environment — full pipeline against demo data
# ---------------------------------------------------------------------------

class TestAssessEnvironment:
    def setup_method(self):
        self.parsed = parse_advisories(DEMO_ADVISORIES, demo_mode=True)

    def _build_env(self, idx: int) -> OTEnvironment:
        ed = DEMO_ENVIRONMENTS[idx]
        return OTEnvironment(
            name=ed["name"], sector=ed["sector"],
            purdue_levels_present=ed["purdue_levels_present"],
            internet_exposed_levels=ed["internet_exposed_levels"],
            vendor_list=ed["vendor_list"], description=ed["description"],
        )

    def test_riverside_returns_report(self):
        env = self._build_env(0)
        rpt = assess_environment(self.parsed, env)
        assert rpt is not None

    def test_riverside_has_critical_findings(self):
        env = self._build_env(0)
        rpt = assess_environment(self.parsed, env)
        assert rpt.critical_count >= 2

    def test_riverside_no_volt_typhoon(self):
        env = self._build_env(0)
        rpt = assess_environment(self.parsed, env)
        assert rpt.volt_typhoon_flags == 0

    def test_riverside_overall_critical(self):
        env = self._build_env(0)
        rpt = assess_environment(self.parsed, env)
        assert rpt.overall_risk_tier == "CRITICAL"

    def test_gulf_coast_no_volt_typhoon(self):
        env = self._build_env(1)
        rpt = assess_environment(self.parsed, env)
        assert rpt.volt_typhoon_flags == 0

    def test_gulf_coast_has_high_findings(self):
        env = self._build_env(1)
        rpt = assess_environment(self.parsed, env)
        assert rpt.high_count >= 5

    def test_gulf_coast_overall_critical(self):
        env = self._build_env(1)
        rpt = assess_environment(self.parsed, env)
        assert rpt.overall_risk_tier == "CRITICAL"

    def test_auto_plant_has_volt_typhoon(self):
        env = self._build_env(2)
        rpt = assess_environment(self.parsed, env)
        assert rpt.volt_typhoon_flags >= 1

    def test_auto_plant_volt_typhoon_is_scalance(self):
        env = self._build_env(2)
        rpt = assess_environment(self.parsed, env)
        vt = [r for r in rpt.results if r.volt_typhoon_vector]
        assert any("SCALANCE" in r.product for r in vt)

    def test_auto_plant_scalance_score_85(self):
        env = self._build_env(2)
        rpt = assess_environment(self.parsed, env)
        scalance = next(r for r in rpt.results if "SCALANCE" in r.product)
        assert scalance.exposure_score == 85.0

    def test_auto_plant_scalance_is_critical(self):
        env = self._build_env(2)
        rpt = assess_environment(self.parsed, env)
        scalance = next(r for r in rpt.results if "SCALANCE" in r.product)
        assert scalance.tier == "CRITICAL"

    def test_auto_plant_overall_critical(self):
        env = self._build_env(2)
        rpt = assess_environment(self.parsed, env)
        assert rpt.overall_risk_tier == "CRITICAL"

    def test_results_sorted_descending(self):
        env = self._build_env(0)
        rpt = assess_environment(self.parsed, env)
        scores = [r.exposure_score for r in rpt.results]
        assert scores == sorted(scores, reverse=True)

    def test_only_vendor_matching_results(self):
        env = self._build_env(0)  # Siemens, Rockwell, GE
        rpt = assess_environment(self.parsed, env)
        for r in rpt.results:
            assert r.vendor_match is True

    def test_total_advisories_checked(self):
        env = self._build_env(0)
        rpt = assess_environment(self.parsed, env)
        assert rpt.total_advisories_checked == 20

    def test_no_match_vendor_excluded(self):
        env = _env(vendor_list=["NonexistentVendorXYZ"])
        rpt = assess_environment(self.parsed, env)
        assert rpt.applicable_advisories == 0

    def test_gulf_coast_has_mitigate_only_findings(self):
        env = self._build_env(1)
        rpt = assess_environment(self.parsed, env)
        constrained = [r for r in rpt.results if not r.patch_feasible]
        assert len(constrained) >= 3

    def test_emerson_roc800_no_patch_note(self):
        env = self._build_env(1)
        rpt = assess_environment(self.parsed, env)
        roc800 = next((r for r in rpt.results if "ROC800" in r.product), None)
        assert roc800 is not None
        assert "no patch available" in roc800.patch_note

    def test_siemens_s7_score_84(self):
        env = self._build_env(0)
        rpt = assess_environment(self.parsed, env)
        s7 = next(r for r in rpt.results if "S7-1500" in r.product)
        assert s7.exposure_score == 84.0

    def test_rockwell_controllogix_score_80(self):
        env = self._build_env(0)
        rpt = assess_environment(self.parsed, env)
        cl = next(r for r in rpt.results if "ControlLogix" in r.product)
        assert cl.exposure_score == 80.0
