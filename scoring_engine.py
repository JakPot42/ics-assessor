"""Deterministic OT exposure scoring engine — Purdue-weighted (P67)."""
from __future__ import annotations

from datetime import date

from config import (
    PURDUE_WEIGHTS, ATTACK_VECTOR_POINTS, INTERNET_EXPOSURE_BONUS,
    TIER_THRESHOLDS, TIER_ORDER,
)
from models import ICSAdvisory, OTEnvironment, ExposureResult, AssessmentReport


def compute_exposure_score(advisory: ICSAdvisory, env: OTEnvironment) -> float:
    """Compute OT exposure score 0-100 for an advisory against a given environment.

    Formula:
      cvss_contribution  = (cvss_score / 10.0) * 50.0
      purdue_contribution = (purdue_weight / 3.0) * 30.0
      av_contribution    = ATTACK_VECTOR_POINTS[attack_vector]
      internet_bonus     = 15 if advisory.purdue_level in env.internet_exposed_levels
      score = min(100, sum of above)
    """
    weight = PURDUE_WEIGHTS.get(advisory.purdue_level, 1.0)
    av_pts = ATTACK_VECTOR_POINTS.get(advisory.attack_vector, 5)
    internet_exposed = advisory.purdue_level in env.internet_exposed_levels
    internet_bonus = INTERNET_EXPOSURE_BONUS if internet_exposed else 0

    cvss_contribution = (advisory.cvss_score / 10.0) * 50.0
    purdue_contribution = (weight / 3.0) * 30.0

    raw = cvss_contribution + purdue_contribution + av_pts + internet_bonus
    return round(min(100.0, raw), 1)


def score_to_tier(score: float) -> str:
    """Map exposure score to CRITICAL / HIGH / MEDIUM / LOW tier."""
    if score >= TIER_THRESHOLDS["CRITICAL"]:
        return "CRITICAL"
    if score >= TIER_THRESHOLDS["MEDIUM"]:
        if score >= TIER_THRESHOLDS["HIGH"]:
            return "HIGH"
        return "MEDIUM"
    return "LOW"


def vendor_match(advisory: ICSAdvisory, env: OTEnvironment) -> bool:
    """True if the advisory vendor matches any vendor in the OT environment."""
    adv_lower = advisory.vendor.lower()
    for env_vendor in env.vendor_list:
        env_lower = env_vendor.lower()
        if env_lower in adv_lower or adv_lower in env_lower:
            return True
    return False


def level_match(advisory: ICSAdvisory, env: OTEnvironment) -> bool:
    """True if the advisory Purdue level is present in the OT environment."""
    return advisory.purdue_level in env.purdue_levels_present


def _patch_note(advisory: ICSAdvisory) -> str:
    if not advisory.patch_available:
        return "MITIGATE ONLY -- no patch available"
    if not advisory.patching_feasible:
        return "MITIGATE ONLY -- operationally constrained"
    return "PATCH AVAILABLE"


def _overall_tier(critical: int, high: int, medium: int) -> str:
    if critical > 0 or high >= 3:
        return "CRITICAL"
    if high > 0 or medium >= 3:
        return "HIGH"
    if medium > 0:
        return "MEDIUM"
    return "LOW"


def assess_environment(
    advisories: list[ICSAdvisory],
    env: OTEnvironment,
) -> AssessmentReport:
    """Score all applicable advisories against the OT environment.

    An advisory is applicable when its vendor matches any vendor in env.vendor_list.
    Results are sorted by exposure_score descending.
    """
    results: list[ExposureResult] = []

    for adv in advisories:
        v_match = vendor_match(adv, env)
        if not v_match:
            continue

        l_match = level_match(adv, env)
        internet_exposed = adv.purdue_level in env.internet_exposed_levels
        score = compute_exposure_score(adv, env)
        tier = score_to_tier(score)
        vt = (adv.purdue_level == 35) and internet_exposed

        results.append(ExposureResult(
            advisory_id=adv.advisory_id,
            vendor=adv.vendor,
            product=adv.product,
            purdue_level=adv.purdue_level,
            cvss_score=adv.cvss_score,
            exposure_score=score,
            tier=tier,
            vendor_match=v_match,
            level_match=l_match,
            internet_exposed=internet_exposed,
            patch_feasible=adv.patch_available and adv.patching_feasible,
            patch_note=_patch_note(adv),
            mitigations=adv.mitigations,
            volt_typhoon_vector=vt,
            advisory=adv,
        ))

    results.sort(key=lambda r: r.exposure_score, reverse=True)

    critical = sum(1 for r in results if r.tier == "CRITICAL")
    high = sum(1 for r in results if r.tier == "HIGH")
    medium = sum(1 for r in results if r.tier == "MEDIUM")
    low = sum(1 for r in results if r.tier == "LOW")
    vt_flags = sum(1 for r in results if r.volt_typhoon_vector)
    overall = _overall_tier(critical, high, medium)

    return AssessmentReport(
        environment=env,
        prepared_date=str(date.today()),
        total_advisories_checked=len(advisories),
        applicable_advisories=len(results),
        results=results,
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        overall_risk_tier=overall,
        volt_typhoon_flags=vt_flags,
        brief_text="",
        diligence_flags=[],
    )
