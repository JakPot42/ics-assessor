"""CISA ICS advisory client — demo or live feed fetch (P67)."""
from __future__ import annotations

import time
from typing import Optional

from config import CISA_ICS_FEED, CISA_RATE_LIMIT
from seed_data import DEMO_ADVISORIES


class CISAClientError(Exception):
    pass


def fetch_advisories(
    *,
    demo_mode: bool = True,
    vendor_filter: Optional[str] = None,
    level_filter: Optional[int] = None,
    sector_filter: Optional[str] = None,
) -> list[dict]:
    """Return advisory dicts, optionally filtered by vendor, Purdue level, or sector."""
    if demo_mode:
        advisories = list(DEMO_ADVISORIES)
    else:
        advisories = _fetch_live_advisories()

    if vendor_filter:
        vf = vendor_filter.lower()
        advisories = [
            a for a in advisories
            if vf in a["vendor"].lower() or a["vendor"].lower() in vf
        ]
    if level_filter is not None:
        advisories = [a for a in advisories if a["purdue_level"] == level_filter]
    if sector_filter:
        sf = sector_filter.upper()
        advisories = [a for a in advisories if sf in a["affected_sectors"]]

    return advisories


def get_advisory(advisory_id: str, *, demo_mode: bool = True) -> Optional[dict]:
    """Return a single advisory dict by ID, or None if not found."""
    if demo_mode:
        for adv in DEMO_ADVISORIES:
            if adv["advisory_id"].upper() == advisory_id.upper():
                return adv
        return None
    advisories = _fetch_live_advisories()
    for adv in advisories:
        if adv["advisory_id"].upper() == advisory_id.upper():
            return adv
    return None


def _fetch_live_advisories() -> list[dict]:
    """Fetch and parse CISA ICS advisory RSS feed."""
    try:
        import urllib.request
        import xml.etree.ElementTree as ET
    except ImportError as e:
        raise CISAClientError(f"Missing stdlib module: {e}") from e

    try:
        time.sleep(CISA_RATE_LIMIT)
        with urllib.request.urlopen(CISA_ICS_FEED, timeout=15) as resp:
            raw = resp.read()
    except Exception as e:
        raise CISAClientError(f"Failed to fetch CISA ICS feed: {e}") from e

    try:
        root = ET.fromstring(raw)
        channel = root.find("channel")
        if channel is None:
            raise CISAClientError("Unexpected feed structure: no <channel> element")
        items = channel.findall("item")
    except ET.ParseError as e:
        raise CISAClientError(f"Failed to parse CISA ICS feed XML: {e}") from e

    advisories = []
    for item in items[:50]:
        title_el = item.find("title")
        link_el = item.find("link")
        pub_el = item.find("pubDate")
        desc_el = item.find("description")

        if title_el is None:
            continue
        title = (title_el.text or "").strip()
        if not title.startswith("ICSA"):
            continue

        advisory_id = title.split()[0] if title.split() else "UNKNOWN"
        pub_date = (pub_el.text or "")[:10] if pub_el is not None else ""
        summary = (desc_el.text or "").strip() if desc_el is not None else ""

        # Live mode: return minimal structure; advisory_parser.py uses Claude to fill fields
        advisories.append({
            "advisory_id": advisory_id,
            "title": title,
            "vendor": "UNKNOWN",
            "product": "UNKNOWN",
            "purdue_level": -1,
            "attack_vector": "NETWORK",
            "cvss_score": 0.0,
            "cvss_vector": "",
            "affected_sectors": [],
            "patch_available": False,
            "patching_feasible": False,
            "mitigations": [],
            "published_date": pub_date,
            "summary": summary,
            "_needs_extraction": True,
        })
    return advisories
