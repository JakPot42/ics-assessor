"""Advisory parser — converts raw advisory dicts to ICSAdvisory dataclasses (P67).

Demo mode: structured seed dicts pass through directly.
Live mode: Claude extracts Purdue level, attack vector, CVSS, mitigations from advisory text.
"""
from __future__ import annotations

import os

from claude_client import call_claude
from config import (
    CLAUDE_MODEL, VALID_PURDUE_LEVELS, VALID_ATTACK_VECTORS, VALID_SECTORS,
)
from models import ICSAdvisory


class AdvisoryParserError(Exception):
    pass


def parse_advisory(raw: dict, *, demo_mode: bool = True) -> ICSAdvisory:
    """Convert a raw advisory dict to an ICSAdvisory dataclass."""
    if raw.get("_needs_extraction") and not demo_mode:
        raw = _extract_with_claude(raw)
    return _dict_to_advisory(raw)


def parse_advisories(
    raw_list: list[dict], *, demo_mode: bool = True
) -> list[ICSAdvisory]:
    """Convert a list of raw advisory dicts to ICSAdvisory objects."""
    return [parse_advisory(r, demo_mode=demo_mode) for r in raw_list]


def _dict_to_advisory(raw: dict) -> ICSAdvisory:
    """Validate and construct ICSAdvisory from a raw dict."""
    advisory_id = str(raw.get("advisory_id", "UNKNOWN"))
    title = str(raw.get("title", ""))
    vendor = str(raw.get("vendor", ""))
    product = str(raw.get("product", ""))
    purdue_level = int(raw.get("purdue_level", 1))
    attack_vector = str(raw.get("attack_vector", "NETWORK")).upper()
    cvss_score = float(raw.get("cvss_score", 0.0))
    cvss_vector = str(raw.get("cvss_vector", ""))
    affected_sectors = [str(s).upper() for s in raw.get("affected_sectors", [])]
    patch_available = bool(raw.get("patch_available", False))
    patching_feasible = bool(raw.get("patching_feasible", False))
    mitigations = [str(m) for m in raw.get("mitigations", [])]
    published_date = str(raw.get("published_date", ""))
    summary = str(raw.get("summary", ""))

    if purdue_level not in VALID_PURDUE_LEVELS:
        raise AdvisoryParserError(
            f"{advisory_id}: invalid purdue_level {purdue_level}; "
            f"must be one of {VALID_PURDUE_LEVELS}"
        )
    if attack_vector not in VALID_ATTACK_VECTORS:
        raise AdvisoryParserError(
            f"{advisory_id}: invalid attack_vector '{attack_vector}'; "
            f"must be one of {VALID_ATTACK_VECTORS}"
        )
    if not (0.0 <= cvss_score <= 10.0):
        raise AdvisoryParserError(
            f"{advisory_id}: cvss_score {cvss_score} out of range [0.0, 10.0]"
        )

    return ICSAdvisory(
        advisory_id=advisory_id,
        title=title,
        vendor=vendor,
        product=product,
        purdue_level=purdue_level,
        attack_vector=attack_vector,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        affected_sectors=affected_sectors,
        patch_available=patch_available,
        patching_feasible=patching_feasible,
        mitigations=mitigations,
        published_date=published_date,
        summary=summary,
    )


def _extract_with_claude(raw: dict) -> dict:
    """Use Claude to extract structured fields from raw advisory text."""
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise AdvisoryParserError("ANTHROPIC_API_KEY not set for live extraction")

    prompt = (
        f"Advisory ID: {raw.get('advisory_id')}\n"
        f"Title: {raw.get('title')}\n"
        f"Summary: {raw.get('summary')}\n\n"
        "Extract the following fields and respond ONLY with a Python dict literal:\n"
        "- vendor: str (manufacturer name, e.g. 'Siemens')\n"
        "- product: str (specific product name)\n"
        "- purdue_level: int (0, 1, 2, 3, 35, or 4 — 35 means Level 3.5 IT/OT DMZ)\n"
        "- attack_vector: str (NETWORK, ADJACENT, LOCAL, or PHYSICAL)\n"
        "- cvss_score: float (0.0 to 10.0, from CVSS base score if mentioned)\n"
        "- patch_available: bool\n"
        "- patching_feasible: bool (False if patching requires process shutdown)\n"
        "- affected_sectors: list[str] (from ENERGY, WATER, MANUFACTURING, TRANSPORTATION, CHEMICAL, NUCLEAR, OTHER)\n"
        "- mitigations: list[str] (2-4 key mitigations)\n"
        "\nPurdue level guide: 0=physical process, 1=PLC/RTU/field devices, "
        "2=SCADA/HMI/historian, 3=MES/batch/site ops, 35=IT/OT DMZ firewall/jump server, "
        "4=enterprise IT/ERP.\n"
        "Respond ONLY with the dict literal — no markdown, no explanation."
    )

    try:
        text = call_claude(
            [{"role": "user", "content": prompt}],
            max_tokens=512,
            model=CLAUDE_MODEL,
            api_key=api_key,
        ).strip()
        extracted = eval(text)  # nosec — controlled output from Claude
    except Exception as e:
        raise AdvisoryParserError(f"Claude extraction failed for {raw.get('advisory_id')}: {e}") from e

    raw.update(extracted)
    raw.pop("_needs_extraction", None)
    return raw
