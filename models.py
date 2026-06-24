"""Data models — ICS/SCADA Vulnerability Exposure Assessor (P67)."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ICSAdvisory:
    advisory_id: str           # "ICSA-24-102-01"
    title: str
    vendor: str                # "Siemens"
    product: str               # "SIMATIC S7-1500"
    purdue_level: int          # 0, 1, 2, 3, 35, 4
    attack_vector: str         # NETWORK / ADJACENT / LOCAL / PHYSICAL
    cvss_score: float          # 0.0 - 10.0
    cvss_vector: str
    affected_sectors: list[str]
    patch_available: bool
    patching_feasible: bool    # False when patching requires process shutdown
    mitigations: list[str]
    published_date: str        # YYYY-MM-DD
    summary: str


@dataclass
class OTEnvironment:
    name: str
    sector: str                # ENERGY / WATER / MANUFACTURING / etc.
    purdue_levels_present: list[int]
    internet_exposed_levels: list[int]
    vendor_list: list[str]
    description: str


@dataclass
class ExposureResult:
    advisory_id: str
    vendor: str
    product: str
    purdue_level: int
    cvss_score: float
    exposure_score: float
    tier: str                  # CRITICAL / HIGH / MEDIUM / LOW
    vendor_match: bool
    level_match: bool
    internet_exposed: bool
    patch_feasible: bool       # True only when patch_available AND patching_feasible
    patch_note: str
    mitigations: list[str]
    volt_typhoon_vector: bool
    advisory: ICSAdvisory | None = field(default=None, repr=False)


@dataclass
class AssessmentReport:
    environment: OTEnvironment
    prepared_date: str
    total_advisories_checked: int
    applicable_advisories: int
    results: list[ExposureResult]
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    overall_risk_tier: str
    volt_typhoon_flags: int
    brief_text: str
    diligence_flags: list[str] = field(default_factory=list)
