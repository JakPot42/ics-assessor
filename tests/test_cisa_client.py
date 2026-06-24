"""Tests for cisa_client.py — demo mode fetch, filters, and advisory lookup."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from cisa_client import fetch_advisories, get_advisory
from seed_data import DEMO_ADVISORIES
from config import VALID_PURDUE_LEVELS, VALID_ATTACK_VECTORS


class TestFetchAdvisories:
    def test_returns_20_in_demo_mode(self):
        result = fetch_advisories(demo_mode=True)
        assert len(result) == 20

    def test_returns_list(self):
        result = fetch_advisories(demo_mode=True)
        assert isinstance(result, list)

    def test_returns_dicts(self):
        result = fetch_advisories(demo_mode=True)
        for item in result:
            assert isinstance(item, dict)

    def test_all_have_advisory_id(self):
        result = fetch_advisories(demo_mode=True)
        for item in result:
            assert "advisory_id" in item

    def test_all_have_vendor(self):
        result = fetch_advisories(demo_mode=True)
        for item in result:
            assert "vendor" in item

    def test_all_have_cvss_score(self):
        result = fetch_advisories(demo_mode=True)
        for item in result:
            assert "cvss_score" in item


class TestVendorFilter:
    def test_filter_siemens(self):
        result = fetch_advisories(demo_mode=True, vendor_filter="Siemens")
        assert all("siemens" in r["vendor"].lower() or "siemens" in r["vendor"].lower()
                   for r in result)

    def test_filter_siemens_returns_multiple(self):
        result = fetch_advisories(demo_mode=True, vendor_filter="Siemens")
        assert len(result) >= 2

    def test_filter_emerson_returns_results(self):
        result = fetch_advisories(demo_mode=True, vendor_filter="Emerson")
        assert len(result) >= 2

    def test_filter_abb_returns_results(self):
        result = fetch_advisories(demo_mode=True, vendor_filter="ABB")
        assert len(result) >= 2

    def test_filter_nonexistent_vendor(self):
        result = fetch_advisories(demo_mode=True, vendor_filter="NonexistentVendorXYZ")
        assert result == []

    def test_filter_rockwell_returns_results(self):
        result = fetch_advisories(demo_mode=True, vendor_filter="Rockwell")
        assert len(result) >= 2

    def test_vendor_filter_case_insensitive(self):
        result_lower = fetch_advisories(demo_mode=True, vendor_filter="siemens")
        result_upper = fetch_advisories(demo_mode=True, vendor_filter="SIEMENS")
        assert len(result_lower) == len(result_upper)


class TestLevelFilter:
    def test_filter_level_1(self):
        result = fetch_advisories(demo_mode=True, level_filter=1)
        assert all(r["purdue_level"] == 1 for r in result)

    def test_filter_level_1_returns_multiple(self):
        result = fetch_advisories(demo_mode=True, level_filter=1)
        assert len(result) >= 5

    def test_filter_level_2_returns_results(self):
        result = fetch_advisories(demo_mode=True, level_filter=2)
        assert len(result) >= 3

    def test_filter_level_35(self):
        result = fetch_advisories(demo_mode=True, level_filter=35)
        assert all(r["purdue_level"] == 35 for r in result)
        assert len(result) >= 1

    def test_filter_level_4(self):
        result = fetch_advisories(demo_mode=True, level_filter=4)
        assert all(r["purdue_level"] == 4 for r in result)

    def test_filter_level_99_returns_empty(self):
        result = fetch_advisories(demo_mode=True, level_filter=99)
        assert result == []


class TestSectorFilter:
    def test_filter_energy(self):
        result = fetch_advisories(demo_mode=True, sector_filter="ENERGY")
        assert all("ENERGY" in r["affected_sectors"] for r in result)

    def test_filter_water_returns_results(self):
        result = fetch_advisories(demo_mode=True, sector_filter="WATER")
        assert len(result) >= 2

    def test_filter_manufacturing_returns_results(self):
        result = fetch_advisories(demo_mode=True, sector_filter="MANUFACTURING")
        assert len(result) >= 3

    def test_filter_nonexistent_sector(self):
        result = fetch_advisories(demo_mode=True, sector_filter="SPACE")
        assert result == []

    def test_sector_filter_case_insensitive(self):
        # sector_filter is uppercased internally
        result = fetch_advisories(demo_mode=True, sector_filter="energy")
        assert len(result) >= 1


class TestGetAdvisory:
    def test_get_existing_advisory(self):
        result = get_advisory("ICSA-24-102-01", demo_mode=True)
        assert result is not None

    def test_get_advisory_returns_dict(self):
        result = get_advisory("ICSA-24-102-01", demo_mode=True)
        assert isinstance(result, dict)

    def test_get_advisory_correct_vendor(self):
        result = get_advisory("ICSA-24-102-01", demo_mode=True)
        assert result["vendor"] == "Siemens"

    def test_get_advisory_case_insensitive(self):
        result = get_advisory("icsa-24-102-01", demo_mode=True)
        assert result is not None

    def test_get_nonexistent_advisory_returns_none(self):
        result = get_advisory("ICSA-00-000-00", demo_mode=True)
        assert result is None

    def test_get_scalance_advisory(self):
        result = get_advisory("ICSA-24-012-01", demo_mode=True)
        assert result is not None
        assert result["purdue_level"] == 35

    def test_get_roc800_advisory(self):
        result = get_advisory("ICSA-23-229-02", demo_mode=True)
        assert result is not None
        assert result["patch_available"] is False

    def test_get_all_20_advisories(self):
        for adv in DEMO_ADVISORIES:
            result = get_advisory(adv["advisory_id"], demo_mode=True)
            assert result is not None, f"Could not fetch {adv['advisory_id']}"
