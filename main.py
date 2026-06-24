"""CLI entry point — ICS/SCADA Vulnerability Exposure Assessor (P67)."""
from __future__ import annotations

import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import click
from rich.console import Console

from config import DEMO_MODE
from seed_data import DEMO_ENVIRONMENTS, DEMO_ENV_NAME

console = Console()


def _get_env_by_name(name: str) -> "OTEnvironment | None":
    """Find a demo environment by partial name match."""
    from advisory_parser import parse_advisories, _dict_to_advisory
    from seed_data import DEMO_ENVIRONMENTS

    name_lower = name.lower()
    for env_dict in DEMO_ENVIRONMENTS:
        if name_lower in env_dict["name"].lower():
            from models import OTEnvironment
            return OTEnvironment(
                name=env_dict["name"],
                sector=env_dict["sector"],
                purdue_levels_present=env_dict["purdue_levels_present"],
                internet_exposed_levels=env_dict["internet_exposed_levels"],
                vendor_list=env_dict["vendor_list"],
                description=env_dict["description"],
            )
    return None


def _build_env(env_dict: dict) -> "OTEnvironment":
    from models import OTEnvironment
    return OTEnvironment(
        name=env_dict["name"],
        sector=env_dict["sector"],
        purdue_levels_present=env_dict["purdue_levels_present"],
        internet_exposed_levels=env_dict["internet_exposed_levels"],
        vendor_list=env_dict["vendor_list"],
        description=env_dict["description"],
    )


def _run_assessment(env_name: str, demo: bool) -> "AssessmentReport":
    """Full pipeline: fetch advisories -> parse -> score -> return report."""
    from cisa_client import fetch_advisories
    from advisory_parser import parse_advisories
    from scoring_engine import assess_environment
    from report_generator import generate_report

    raw_advisories = fetch_advisories(demo_mode=demo)
    advisories = parse_advisories(raw_advisories, demo_mode=demo)

    env = _get_env_by_name(env_name)
    if env is None:
        raise click.BadParameter(
            f"Environment '{env_name}' not found. "
            f"Available: {[e['name'] for e in DEMO_ENVIRONMENTS]}"
        )

    report = assess_environment(advisories, env)
    brief_text, flags = generate_report(report, demo_mode=demo)
    report.brief_text = brief_text
    report.diligence_flags = flags
    return report


@click.group()
@click.option("--demo/--live", default=True, help="Use demo data (default) or live CISA feed")
@click.pass_context
def cli(ctx: click.Context, demo: bool) -> None:
    """ICS/SCADA Vulnerability Exposure Assessor (P67)

    Maps ICS-CERT advisories against your OT/SCADA environment
    using the Purdue Model as a physical-consequence scoring framework.
    """
    ctx.ensure_object(dict)
    ctx.obj["demo"] = demo


@cli.command()
@click.option("--env", "env_name", default=DEMO_ENV_NAME,
              help="OT environment name (partial match)")
@click.pass_context
def assess(ctx: click.Context, env_name: str) -> None:
    """Score all applicable ICS-CERT advisories against an OT environment."""
    from dashboard import print_environment, print_findings_table, print_assessment_summary
    demo = ctx.obj.get("demo", True)
    with console.status(f"[cyan]Assessing {env_name}...[/cyan]"):
        report = _run_assessment(env_name, demo)
    print_assessment_summary(report)
    print_environment(report.environment)
    console.print()
    print_findings_table(report.results)


@cli.command()
@click.option("--vendor", default=None, help="Filter by vendor name")
@click.option("--level", "level_filter", default=None, type=int,
              help="Filter by Purdue level (0,1,2,3,35,4)")
@click.option("--tier", default=None,
              help="Filter by computed tier when scored against default env")
@click.pass_context
def advisories(ctx: click.Context, vendor: str, level_filter: int, tier: str) -> None:
    """List ICS-CERT advisories with optional filters."""
    from cisa_client import fetch_advisories
    from advisory_parser import parse_advisories
    from dashboard import print_advisories_table
    demo = ctx.obj.get("demo", True)
    raw = fetch_advisories(demo_mode=demo, vendor_filter=vendor, level_filter=level_filter)
    parsed = parse_advisories(raw, demo_mode=demo)
    print_advisories_table(parsed)


@cli.command("advisory")
@click.argument("advisory_id")
@click.pass_context
def show_advisory(ctx: click.Context, advisory_id: str) -> None:
    """Show full detail for a single advisory by ID (e.g. ICSA-24-102-01)."""
    from cisa_client import get_advisory
    from advisory_parser import _dict_to_advisory
    from dashboard import print_advisory
    demo = ctx.obj.get("demo", True)
    raw = get_advisory(advisory_id, demo_mode=demo)
    if raw is None:
        console.print(f"[red]Advisory {advisory_id} not found.[/red]")
        raise SystemExit(1)
    adv = _dict_to_advisory(raw)
    print_advisory(adv)


@cli.command()
@click.option("--env", "env_name", default=DEMO_ENV_NAME,
              help="OT environment name (partial match)")
@click.pass_context
def report(ctx: click.Context, env_name: str) -> None:
    """Generate a full OT security assessment report for an environment."""
    from dashboard import print_assessment_summary, print_report
    demo = ctx.obj.get("demo", True)
    with console.status(f"[cyan]Generating report for {env_name}...[/cyan]"):
        assessment = _run_assessment(env_name, demo)
    print_assessment_summary(assessment)
    print_report(assessment)


@cli.command()
@click.option("--env", "env_name", default=DEMO_ENV_NAME)
@click.option("--format", "fmt", type=click.Choice(["json", "text"]), default="text")
@click.pass_context
def export(ctx: click.Context, env_name: str, fmt: str) -> None:
    """Export assessment results as JSON or text."""
    demo = ctx.obj.get("demo", True)
    assessment = _run_assessment(env_name, demo)
    safe_name = env_name.replace(" ", "_").lower()[:30]
    if fmt == "text":
        filename = f"{safe_name}_assessment.txt"
        with open(filename, "w", encoding="utf-8") as fh:
            fh.write(assessment.brief_text)
        console.print(f"[green]Exported to {filename}[/green]")
    else:
        import dataclasses
        filename = f"{safe_name}_assessment.json"
        data = {
            "environment": dataclasses.asdict(assessment.environment),
            "prepared_date": assessment.prepared_date,
            "overall_risk_tier": assessment.overall_risk_tier,
            "critical": assessment.critical_count,
            "high": assessment.high_count,
            "medium": assessment.medium_count,
            "low": assessment.low_count,
            "volt_typhoon_flags": assessment.volt_typhoon_flags,
            "results": [
                {
                    "advisory_id": r.advisory_id,
                    "vendor": r.vendor,
                    "product": r.product,
                    "purdue_level": r.purdue_level,
                    "cvss_score": r.cvss_score,
                    "exposure_score": r.exposure_score,
                    "tier": r.tier,
                    "patch_note": r.patch_note,
                    "volt_typhoon_vector": r.volt_typhoon_vector,
                }
                for r in assessment.results
            ],
            "diligence_flags": assessment.diligence_flags,
        }
        with open(filename, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        console.print(f"[green]Exported to {filename}[/green]")


@cli.command()
def demo() -> None:
    """Full demonstration across all three OT environments."""
    from cisa_client import fetch_advisories
    from advisory_parser import parse_advisories
    from scoring_engine import assess_environment
    from report_generator import generate_report
    from dashboard import (
        print_environment, print_findings_table,
        print_assessment_summary, print_report, print_advisories_table,
    )

    console.rule("[bold cyan]P67 -- ICS/SCADA Vulnerability Exposure Assessor[/bold cyan]")
    console.print(
        "[dim]Purdue Model scoring | CISA ICS-CERT advisories | "
        "Volt Typhoon vector detection | P63 connection[/dim]\n"
    )

    # 1. Advisory library
    console.rule("[bold]1 - ICS-CERT Advisory Library (20 advisories)[/bold]")
    raw = fetch_advisories(demo_mode=True)
    parsed = parse_advisories(raw, demo_mode=True)
    print_advisories_table(parsed)

    # 2. All three environments
    for env_dict in DEMO_ENVIRONMENTS:
        env_name = env_dict["name"]
        console.rule(f"[bold]Assessment: {env_name}[/bold]")
        env = _build_env(env_dict)
        report_obj = assess_environment(parsed, env)
        brief_text, flags = generate_report(report_obj, demo_mode=True)
        report_obj.brief_text = brief_text
        report_obj.diligence_flags = flags
        print_assessment_summary(report_obj)
        print_environment(env)
        console.print()
        print_findings_table(report_obj.results)
        console.print()

    # 3. Full report for primary demo env
    console.rule("[bold]Full OT Security Report: Riverside Water Treatment Plant[/bold]")
    env = _build_env(DEMO_ENVIRONMENTS[0])
    report_obj = assess_environment(parsed, env)
    brief_text, flags = generate_report(report_obj, demo_mode=True)
    report_obj.brief_text = brief_text
    report_obj.diligence_flags = flags
    print_report(report_obj)

    # 4. Volt Typhoon vector detail
    console.rule("[bold]4 - Volt Typhoon Vector Detail (Detroit Auto Assembly)[/bold]")
    env_auto = _build_env(DEMO_ENVIRONMENTS[2])
    report_auto = assess_environment(parsed, env_auto)
    vt_results = [r for r in report_auto.results if r.volt_typhoon_vector]
    if vt_results:
        console.print(f"[red bold]Volt Typhoon vectors detected: {len(vt_results)}[/red bold]")
        for r in vt_results:
            console.print(f"  {r.advisory_id} -- {r.vendor} {r.product}")
            console.print(f"  Score: {r.exposure_score}/100 | Tier: {r.tier}")
            console.print(
                "  CISA AA23-144A/AA24-038A: Volt Typhoon targets Level 3.5 "
                "IT/OT DMZ components with internet access to pre-position in OT networks."
            )
            console.print("  See P63 Volt Typhoon Pre-Positioning Tracker for adversary TTP analysis.\n")

    console.rule("[dim]Demo complete[/dim]")


if __name__ == "__main__":
    cli()
