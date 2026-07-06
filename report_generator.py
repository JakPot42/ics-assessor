"""OT security report generator — demo brief or Claude synthesis (P67)."""
from __future__ import annotations

import os

from claude_client import call_claude
from config import CLAUDE_MODEL, VOLT_TYPHOON_NOTE
from models import AssessmentReport
from seed_data import DEMO_REPORT_TEXT, DEMO_ENV_NAME


class ReportGeneratorError(Exception):
    pass


def generate_report(
    report: AssessmentReport,
    *,
    demo_mode: bool = True,
) -> tuple[str, list[str]]:
    """Return (brief_text, diligence_flags) for an AssessmentReport.

    Demo mode: returns pre-baked text if environment is the demo env,
    otherwise assembles a structured text report from the report data.
    Live mode: calls Claude Haiku for narrative synthesis.
    """
    if demo_mode:
        if report.environment.name == DEMO_ENV_NAME:
            flags = _extract_flags(DEMO_REPORT_TEXT)
            return DEMO_REPORT_TEXT, flags
        # Non-demo env in demo mode: assemble from data
        brief = _assemble_brief(report)
        flags = _build_flags(report)
        return brief, flags

    return _generate_with_claude(report)


def _extract_flags(text: str) -> list[str]:
    """Pull out the numbered action items from a brief text."""
    flags = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and stripped[0].isdigit() and stripped[1:3] in (". ", "] "):
            flags.append(stripped)
        elif stripped.startswith("[IMMEDIATE]") or stripped.startswith("[30 DAYS]") or stripped.startswith("[60 DAYS]"):
            flags.append(stripped)
    return flags[:10]


def _build_flags(report: AssessmentReport) -> list[str]:
    flags = []
    if report.critical_count > 0:
        flags.append(
            f"[CRITICAL] {report.critical_count} critical advisory findings require "
            "immediate network isolation while patching is scheduled"
        )
    if report.volt_typhoon_flags > 0:
        flags.append(
            f"[VOLT TYPHOON] {report.volt_typhoon_flags} Level 3.5 internet-exposed "
            "finding(s) match Volt Typhoon pre-positioning TTPs (CISA AA23-144A)"
        )
    # Identify MITIGATE ONLY findings
    mitigate_only = [r for r in report.results if not r.patch_feasible]
    if mitigate_only:
        flags.append(
            f"[OT CONSTRAINT] {len(mitigate_only)} finding(s) cannot be patched during "
            "operations -- compensating controls (network segmentation, protocol filtering) "
            "are the only remediation path until next scheduled outage"
        )
    no_patch = [r for r in report.results if r.patch_note.startswith("MITIGATE ONLY -- no patch")]
    if no_patch:
        ids = ", ".join(r.advisory_id for r in no_patch)
        flags.append(f"[NO PATCH] {ids} -- vendor has not released a patch; apply network controls")
    return flags


def _assemble_brief(report: AssessmentReport) -> str:
    env = report.environment
    lines = [
        "RESTRICTED // OT SECURITY ASSESSMENT // PRE-DECISIONAL",
        "",
        f"TO: Facility Manager, {env.name}",
        "FROM: ICS Security Assessment Team",
        f"RE: ICS/SCADA Vulnerability Exposure Assessment",
        f"DATE: {report.prepared_date}",
        "",
        "-" * 68,
        "I. EXECUTIVE SUMMARY",
        "-" * 68,
        "",
        f"Overall OT Risk: {report.overall_risk_tier}",
        f"Environment: {env.name} | Sector: {env.sector}",
        f"Advisories Checked: {report.total_advisories_checked} | "
        f"Applicable: {report.applicable_advisories}",
        f"  Critical: {report.critical_count} | High: {report.high_count} | "
        f"Medium: {report.medium_count} | Low: {report.low_count}",
        f"Volt Typhoon Vectors: {report.volt_typhoon_flags}",
        "",
    ]

    if report.volt_typhoon_flags > 0:
        lines += [VOLT_TYPHOON_NOTE, ""]

    # Critical findings
    critical_results = [r for r in report.results if r.tier == "CRITICAL"]
    if critical_results:
        lines += ["-" * 68, "II. CRITICAL FINDINGS (IMMEDIATE ACTION REQUIRED)", "-" * 68, ""]
        for r in critical_results:
            vt = " + VOLT TYPHOON VECTOR" if r.volt_typhoon_vector else ""
            lines += [
                f"[CRITICAL{vt}] {r.advisory_id} -- {r.vendor} {r.product}",
                f"  Purdue Level: {r.purdue_level} | CVSS: {r.cvss_score} | "
                f"Exposure Score: {r.exposure_score}/100",
                f"  Attack Vector: {r.advisory.attack_vector if r.advisory else 'NETWORK'} | "
                f"Internet Exposed: {'YES' if r.internet_exposed else 'No'}",
                f"  Patch Status: {r.patch_note}",
                f"  Primary Mitigation: {r.mitigations[0] if r.mitigations else 'See CISA advisory'}",
                "",
            ]

    # High findings
    high_results = [r for r in report.results if r.tier == "HIGH"]
    if high_results:
        lines += ["-" * 68, "III. HIGH-PRIORITY FINDINGS", "-" * 68, ""]
        for r in high_results:
            lines += [
                f"[HIGH] {r.advisory_id} -- {r.vendor} {r.product}",
                f"  Level: {r.purdue_level} | CVSS: {r.cvss_score} | Score: {r.exposure_score}/100",
                f"  Patch Status: {r.patch_note}",
                "",
            ]

    # Medium findings
    medium_results = [r for r in report.results if r.tier == "MEDIUM"]
    if medium_results:
        lines += ["-" * 68, "IV. MEDIUM-PRIORITY FINDINGS", "-" * 68, ""]
        for r in medium_results:
            lines += [
                f"[MEDIUM] {r.advisory_id} -- {r.vendor} {r.product}",
                f"  Level: {r.purdue_level} | CVSS: {r.cvss_score} | Score: {r.exposure_score}/100",
                "",
            ]

    # Advisory reference list
    lines += [
        "-" * 68,
        "V. APPLICABLE ICS-CERT ADVISORY REFERENCE IDs",
        "-" * 68,
        "",
    ]
    for r in report.results:
        lines.append(f"  {r.advisory_id}  {r.vendor} {r.product}  [{r.tier}]")

    lines += [
        "",
        "Source: CISA ICS-CERT (cisa.gov/ics-advisories)",
        "Assessment Tool: P67 ICS/SCADA Vulnerability Exposure Assessor",
    ]
    return "\n".join(lines)


def _generate_with_claude(report: AssessmentReport) -> tuple[str, list[str]]:
    """Call Claude Haiku to synthesize a narrative OT security brief."""
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise ReportGeneratorError("ANTHROPIC_API_KEY not set")

    env = report.environment
    top_results = report.results[:8]

    findings_text = "\n".join(
        f"  - {r.advisory_id}: {r.vendor} {r.product}, "
        f"Level {r.purdue_level}, CVSS {r.cvss_score}, Score {r.exposure_score}, "
        f"Tier {r.tier}, {r.patch_note}"
        + (" [VOLT TYPHOON VECTOR]" if r.volt_typhoon_vector else "")
        for r in top_results
    )

    prompt = f"""You are an OT/ICS security analyst writing a pre-decisional assessment brief.
Write a 7-section ICS/SCADA vulnerability exposure assessment memo using ONLY ASCII characters.

FACILITY: {env.name}
SECTOR: {env.sector}
PURDUE LEVELS PRESENT: {env.purdue_levels_present}
INTERNET-EXPOSED LEVELS: {env.internet_exposed_levels}
VENDORS: {', '.join(env.vendor_list)}
OVERALL RISK: {report.overall_risk_tier}
CRITICAL: {report.critical_count} | HIGH: {report.high_count} | MEDIUM: {report.medium_count}
VOLT TYPHOON VECTORS: {report.volt_typhoon_flags}

TOP FINDINGS (by exposure score):
{findings_text}

Write the 7-section memo. Sections: I. Executive Summary, II. OT Environment Profile,
III. Critical Findings (if any), IV. High-Priority Findings (if any),
V. Medium-Priority Findings (if any), VI. Purdue Model Coverage Analysis,
VII. Recommended Mitigations (priority ordered).
Include a closing appendix listing all advisory IDs with tier.

Rules:
- Use ASCII only — no Unicode, no box-drawing characters, use --- for dividers
- Reference every finding by its ICSA advisory ID
- Note "MITIGATE ONLY" for operationally constrained or unpatchable findings
- For any Volt Typhoon vector: cite CISA AA23-144A and AA24-038A, link to P63
- Use government memo format with TO/FROM/RE/DATE header
- Mark header: RESTRICTED // OT SECURITY ASSESSMENT // PRE-DECISIONAL
"""

    try:
        brief_text = call_claude(
            [{"role": "user", "content": prompt}],
            max_tokens=2048,
            model=CLAUDE_MODEL,
            api_key=api_key,
        ).strip()
    except Exception as e:
        raise ReportGeneratorError(f"Claude brief generation failed: {e}") from e

    flags = _build_flags(report)
    return brief_text, flags
