"""Tests for seed_data.py — advisory structure, environment shape, brief content."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from seed_data import DEMO_ADVISORIES, DEMO_ENVIRONMENTS, DEMO_REPORT_TEXT, DEMO_ENV_NAME
from config import VALID_PURDUE_LEVELS, VALID_ATTACK_VECTORS, VALID_SECTORS


# ---------------------------------------------------------------------------
# DEMO_ADVISORIES
# ---------------------------------------------------------------------------

class TestAdvisoryCount:
    def test_twenty_advisories(self):
        assert len(DEMO_ADVISORIES) == 20

    def test_advisory_ids_unique(self):
        ids = [a["advisory_id"] for a in DEMO_ADVISORIES]
        assert len(ids) == len(set(ids))

    def test_all_ids_start_with_icsa(self):
        for a in DEMO_ADVISORIES:
            assert a["advisory_id"].startswith("ICSA"), f"Bad ID: {a['advisory_id']}"


class TestAdvisoryRequiredFields:
    REQUIRED = {
        "advisory_id", "title", "vendor", "product", "purdue_level",
        "attack_vector", "cvss_score", "cvss_vector", "affected_sectors",
        "patch_available", "patching_feasible", "mitigations",
        "published_date", "summary",
    }

    def test_all_have_required_fields(self):
        for adv in DEMO_ADVISORIES:
            for field in self.REQUIRED:
                assert field in adv, f"Missing '{field}' in {adv.get('advisory_id')}"

    def test_titles_nonempty(self):
        for adv in DEMO_ADVISORIES:
            assert len(adv["title"]) > 10

    def test_vendors_nonempty(self):
        for adv in DEMO_ADVISORIES:
            assert len(adv["vendor"]) > 0

    def test_products_nonempty(self):
        for adv in DEMO_ADVISORIES:
            assert len(adv["product"]) > 0

    def test_summaries_nonempty(self):
        for adv in DEMO_ADVISORIES:
            assert len(adv["summary"]) > 50

    def test_mitigations_are_lists(self):
        for adv in DEMO_ADVISORIES:
            assert isinstance(adv["mitigations"], list)

    def test_all_have_at_least_one_mitigation(self):
        for adv in DEMO_ADVISORIES:
            assert len(adv["mitigations"]) >= 1

    def test_affected_sectors_are_lists(self):
        for adv in DEMO_ADVISORIES:
            assert isinstance(adv["affected_sectors"], list)

    def test_all_have_at_least_one_sector(self):
        for adv in DEMO_ADVISORIES:
            assert len(adv["affected_sectors"]) >= 1

    def test_patch_available_is_bool(self):
        for adv in DEMO_ADVISORIES:
            assert isinstance(adv["patch_available"], bool)

    def test_patching_feasible_is_bool(self):
        for adv in DEMO_ADVISORIES:
            assert isinstance(adv["patching_feasible"], bool)


class TestAdvisoryValues:
    def test_purdue_levels_valid(self):
        for adv in DEMO_ADVISORIES:
            assert adv["purdue_level"] in VALID_PURDUE_LEVELS, (
                f"{adv['advisory_id']}: invalid level {adv['purdue_level']}"
            )

    def test_attack_vectors_valid(self):
        for adv in DEMO_ADVISORIES:
            assert adv["attack_vector"].upper() in VALID_ATTACK_VECTORS, (
                f"{adv['advisory_id']}: invalid vector {adv['attack_vector']}"
            )

    def test_cvss_scores_in_range(self):
        for adv in DEMO_ADVISORIES:
            assert 0.0 <= adv["cvss_score"] <= 10.0, (
                f"{adv['advisory_id']}: CVSS {adv['cvss_score']} out of range"
            )

    def test_sectors_valid(self):
        for adv in DEMO_ADVISORIES:
            for sector in adv["affected_sectors"]:
                assert sector in VALID_SECTORS, (
                    f"{adv['advisory_id']}: invalid sector {sector}"
                )

    def test_published_dates_format(self):
        for adv in DEMO_ADVISORIES:
            d = adv["published_date"]
            assert len(d) == 10, f"Bad date format: {d}"
            assert d[4] == "-"
            assert d[7] == "-"


class TestAdvisoryDistribution:
    def test_has_critical_tier_candidates(self):
        # CVSS >= 9.0 + L1 or L2 should produce CRITICAL scores
        high_cvss = [a for a in DEMO_ADVISORIES if a["cvss_score"] >= 9.0]
        assert len(high_cvss) >= 3

    def test_has_level_1_advisories(self):
        l1 = [a for a in DEMO_ADVISORIES if a["purdue_level"] == 1]
        assert len(l1) >= 5

    def test_has_level_2_advisories(self):
        l2 = [a for a in DEMO_ADVISORIES if a["purdue_level"] == 2]
        assert len(l2) >= 3

    def test_has_level_35_advisory(self):
        l35 = [a for a in DEMO_ADVISORIES if a["purdue_level"] == 35]
        assert len(l35) >= 1

    def test_has_level_4_advisories(self):
        l4 = [a for a in DEMO_ADVISORIES if a["purdue_level"] == 4]
        assert len(l4) >= 1

    def test_has_no_patch_advisory(self):
        no_patch = [a for a in DEMO_ADVISORIES if not a["patch_available"]]
        assert len(no_patch) >= 1

    def test_has_operationally_constrained_advisories(self):
        constrained = [
            a for a in DEMO_ADVISORIES
            if a["patch_available"] and not a["patching_feasible"]
        ]
        assert len(constrained) >= 3

    def test_has_network_attack_vector(self):
        network = [a for a in DEMO_ADVISORIES if a["attack_vector"] == "NETWORK"]
        assert len(network) >= 8

    def test_multiple_vendors_present(self):
        vendors = {a["vendor"] for a in DEMO_ADVISORIES}
        assert len(vendors) >= 6

    def test_siemens_advisory_present(self):
        siemens = [a for a in DEMO_ADVISORIES if "Siemens" in a["vendor"]]
        assert len(siemens) >= 2

    def test_scalance_is_level_35(self):
        scalance = next(
            (a for a in DEMO_ADVISORIES if "SCALANCE" in a["product"]), None
        )
        assert scalance is not None
        assert scalance["purdue_level"] == 35


# ---------------------------------------------------------------------------
# DEMO_ENVIRONMENTS
# ---------------------------------------------------------------------------

class TestEnvironmentCount:
    def test_three_environments(self):
        assert len(DEMO_ENVIRONMENTS) == 3

    def test_env_names_unique(self):
        names = [e["name"] for e in DEMO_ENVIRONMENTS]
        assert len(names) == len(set(names))


class TestEnvironmentFields:
    REQUIRED = {
        "name", "sector", "purdue_levels_present",
        "internet_exposed_levels", "vendor_list", "description",
    }

    def test_all_have_required_fields(self):
        for env in DEMO_ENVIRONMENTS:
            for field in self.REQUIRED:
                assert field in env, f"Missing '{field}' in {env.get('name')}"

    def test_sectors_valid(self):
        for env in DEMO_ENVIRONMENTS:
            assert env["sector"] in VALID_SECTORS

    def test_purdue_levels_are_lists(self):
        for env in DEMO_ENVIRONMENTS:
            assert isinstance(env["purdue_levels_present"], list)

    def test_purdue_levels_nonempty(self):
        for env in DEMO_ENVIRONMENTS:
            assert len(env["purdue_levels_present"]) >= 1

    def test_vendor_list_nonempty(self):
        for env in DEMO_ENVIRONMENTS:
            assert len(env["vendor_list"]) >= 1

    def test_descriptions_nonempty(self):
        for env in DEMO_ENVIRONMENTS:
            assert len(env["description"]) > 50

    def test_internet_exposed_levels_are_lists(self):
        for env in DEMO_ENVIRONMENTS:
            assert isinstance(env["internet_exposed_levels"], list)


class TestEnvironmentCharacteristics:
    def test_riverside_is_water_sector(self):
        riverside = DEMO_ENVIRONMENTS[0]
        assert riverside["sector"] == "WATER"

    def test_gulf_coast_is_energy_sector(self):
        gulf = DEMO_ENVIRONMENTS[1]
        assert gulf["sector"] == "ENERGY"

    def test_auto_plant_is_manufacturing_sector(self):
        auto = DEMO_ENVIRONMENTS[2]
        assert auto["sector"] == "MANUFACTURING"

    def test_gulf_coast_has_no_internet_exposure(self):
        gulf = DEMO_ENVIRONMENTS[1]
        assert gulf["internet_exposed_levels"] == []

    def test_auto_plant_has_level_35_internet_exposed(self):
        auto = DEMO_ENVIRONMENTS[2]
        assert 35 in auto["internet_exposed_levels"]

    def test_riverside_has_level_3_internet_exposed(self):
        riverside = DEMO_ENVIRONMENTS[0]
        assert 3 in riverside["internet_exposed_levels"]

    def test_auto_plant_has_level_35_present(self):
        auto = DEMO_ENVIRONMENTS[2]
        assert 35 in auto["purdue_levels_present"]


# ---------------------------------------------------------------------------
# DEMO_REPORT_TEXT
# ---------------------------------------------------------------------------

class TestDemoReportText:
    def test_is_string(self):
        assert isinstance(DEMO_REPORT_TEXT, str)

    def test_substantial_length(self):
        assert len(DEMO_REPORT_TEXT) > 3000

    def test_contains_restricted_header(self):
        assert "RESTRICTED" in DEMO_REPORT_TEXT

    def test_contains_memo_fields(self):
        for field in ["TO:", "FROM:", "RE:", "DATE:"]:
            assert field in DEMO_REPORT_TEXT

    def test_seven_sections(self):
        for section in ["I.", "II.", "III.", "IV.", "V.", "VI.", "VII."]:
            assert section in DEMO_REPORT_TEXT

    def test_contains_executive_summary(self):
        assert "EXECUTIVE SUMMARY" in DEMO_REPORT_TEXT

    def test_contains_critical_finding(self):
        assert "CRITICAL" in DEMO_REPORT_TEXT

    def test_references_advisory_icsa_24_102_01(self):
        assert "ICSA-24-102-01" in DEMO_REPORT_TEXT

    def test_references_advisory_icsa_24_065_02(self):
        assert "ICSA-24-065-02" in DEMO_REPORT_TEXT

    def test_references_mitigate_only(self):
        assert "MITIGATE ONLY" in DEMO_REPORT_TEXT

    def test_references_purdue_levels(self):
        assert "Level 1" in DEMO_REPORT_TEXT or "Purdue" in DEMO_REPORT_TEXT

    def test_no_volt_typhoon_vector_for_riverside(self):
        # Riverside has no L35 internet-exposed components
        assert "NO VOLT TYPHOON VECTOR" in DEMO_REPORT_TEXT

    def test_ascii_only(self):
        for ch in DEMO_REPORT_TEXT:
            assert ord(ch) < 128, f"Non-ASCII character: {repr(ch)}"

    def test_demo_env_name_matches(self):
        assert DEMO_ENV_NAME == "Riverside Water Treatment Plant"
