"""Rich CLI display -- ICS/SCADA Vulnerability Exposure Assessor (P67).

ASCII-safe: no Unicode box-drawing characters (cp1252 Windows terminal compatibility).
"""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from config import PURDUE_LEVELS, TIER_COLORS
from models import ICSAdvisory, OTEnvironment, ExposureResult, AssessmentReport

console = Console()


def _tier_color(tier: str) -> str:
    return TIER_COLORS.get(tier, "white")


def _purdue_label(level: int) -> str:
    label = PURDUE_LEVELS.get(level, f"Level {level}")
    return label.split(" -- ")[0]


def _score_bar(score: float, width: int = 20) -> str:
    filled = int((score / 100.0) * width)
    return "[" + "#" * filled + "." * (width - filled) + "]"


def print_environment(env: OTEnvironment) -> None:
    """Print OT environment profile."""
    console.print(f"\n[bold]OT Environment:[/bold] {env.name}")
    console.print(f"  Sector:           {env.sector}")
    levels_str = ", ".join(
        _purdue_label(lv) for lv in sorted(env.purdue_levels_present)
    )
    console.print(f"  Purdue Levels:    {levels_str}")
    if env.internet_exposed_levels:
        exposed_str = ", ".join(
            _purdue_label(lv) for lv in sorted(env.internet_exposed_levels)
        )
        console.print(f"  Internet-Exposed: [red]{exposed_str}[/red]")
    else:
        console.print("  Internet-Exposed: [green]None (air-gapped)[/green]")
    console.print(f"  Vendors:          {', '.join(env.vendor_list)}")
    if env.description:
        console.print(f"  Description:      {env.description[:100]}...")


def print_advisory(adv: ICSAdvisory) -> None:
    """Print full advisory detail."""
    console.print(f"\n[bold]{adv.advisory_id}[/bold] -- {adv.title}")
    console.print(f"  Vendor/Product:  {adv.vendor} {adv.product}")
    console.print(f"  Purdue Level:    {_purdue_label(adv.purdue_level)}")
    console.print(f"  Attack Vector:   {adv.attack_vector}")
    console.print(f"  CVSS Score:      {adv.cvss_score}")
    console.print(f"  CVSS Vector:     {adv.cvss_vector}")
    console.print(f"  Sectors:         {', '.join(adv.affected_sectors)}")
    patch_status = "Available" if adv.patch_available else "NOT AVAILABLE"
    feasible = "Feasible" if adv.patching_feasible else "CONSTRAINED (process shutdown required)"
    console.print(f"  Patch:           {patch_status} | {feasible}")
    console.print(f"  Published:       {adv.published_date}")
    console.print(f"  Summary:         {adv.summary[:200]}...")
    if adv.mitigations:
        console.print("  Mitigations:")
        for m in adv.mitigations[:3]:
            console.print(f"    - {m}")


def print_advisories_table(advisories: list[ICSAdvisory]) -> None:
    """Print a summary table of advisories."""
    tbl = Table(box=box.SIMPLE, show_header=True)
    tbl.add_column("Advisory ID", style="bold")
    tbl.add_column("Vendor")
    tbl.add_column("Product")
    tbl.add_column("Level", justify="center")
    tbl.add_column("CVSS", justify="right")
    tbl.add_column("Vector")
    tbl.add_column("Patch")

    for adv in advisories:
        level_short = f"L{adv.purdue_level}" if adv.purdue_level != 35 else "L3.5"
        patch_icon = "OK" if adv.patch_available else "NO PATCH"
        tbl.add_row(
            adv.advisory_id,
            adv.vendor,
            adv.product[:35],
            level_short,
            str(adv.cvss_score),
            adv.attack_vector,
            patch_icon,
        )
    console.print(tbl)
    console.print(f"[dim]{len(advisories)} advisories[/dim]")


def print_findings_table(results: list[ExposureResult]) -> None:
    """Print scored findings table sorted by exposure score."""
    tbl = Table(box=box.SIMPLE, show_header=True)
    tbl.add_column("Advisory ID", style="bold")
    tbl.add_column("Vendor")
    tbl.add_column("Product")
    tbl.add_column("Level", justify="center")
    tbl.add_column("CVSS", justify="right")
    tbl.add_column("Score", justify="right")
    tbl.add_column("Tier")
    tbl.add_column("Patch")
    tbl.add_column("VT")

    for r in results:
        level_str = f"L{r.purdue_level}" if r.purdue_level != 35 else "L3.5"
        tier_display = f"[{_tier_color(r.tier)}]{r.tier}[/{_tier_color(r.tier)}]"
        patch_short = "MITIGATE" if r.patch_note.startswith("MITIGATE") else "PATCH OK"
        vt_flag = "[red]VT![/red]" if r.volt_typhoon_vector else ""
        tbl.add_row(
            r.advisory_id,
            r.vendor,
            r.product[:32],
            level_str,
            str(r.cvss_score),
            str(r.exposure_score),
            tier_display,
            patch_short,
            vt_flag,
        )
    console.print(tbl)


def print_assessment_summary(report: AssessmentReport) -> None:
    """Print assessment header and risk summary."""
    env = report.environment
    tier_color = _tier_color(report.overall_risk_tier)
    console.print(
        f"\n[bold]OT Exposure Assessment:[/bold] {env.name} | "
        f"Sector: {env.sector} | "
        f"Risk: [{tier_color}]{report.overall_risk_tier}[/{tier_color}]"
    )
    console.print(
        f"  Advisories checked: {report.total_advisories_checked} | "
        f"Applicable: {report.applicable_advisories}"
    )
    console.print(
        f"  [red]Critical: {report.critical_count}[/red]  "
        f"[yellow]High: {report.high_count}[/yellow]  "
        f"[blue]Medium: {report.medium_count}[/blue]  "
        f"[green]Low: {report.low_count}[/green]"
    )
    if report.volt_typhoon_flags > 0:
        console.print(
            f"  [red bold]VOLT TYPHOON VECTORS: {report.volt_typhoon_flags} "
            "(Level 3.5 IT/OT DMZ internet-exposed)[/red bold]"
        )
    else:
        console.print("  Volt Typhoon vectors: 0 (no Level 3.5 internet-exposed findings)")


def print_report(report: AssessmentReport) -> None:
    """Print full report text in a Rich panel."""
    if report.brief_text:
        console.print(Panel(report.brief_text, title="OT Security Assessment Report", expand=True))
    if report.diligence_flags:
        console.print("\n[bold]Action Items:[/bold]")
        for flag in report.diligence_flags:
            console.print(f"  {flag}")
