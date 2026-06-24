"""Configuration -- ICS/SCADA Vulnerability Exposure Assessor (P67)."""
from __future__ import annotations

DEMO_MODE = True

CISA_ICS_FEED = "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"
CISA_RATE_LIMIT = 1.0

CLAUDE_MODEL = "claude-haiku-4-5-20251001"

# ---------------------------------------------------------------------------
# Purdue Reference Model
# Level 35 = integer encoding of "Level 3.5" (IT/OT DMZ boundary)
# ---------------------------------------------------------------------------
PURDUE_LEVELS: dict[int, str] = {
    0:  "Level 0 -- Physical Process (sensors, actuators, physical equipment)",
    1:  "Level 1 -- Field Devices (PLCs, RTUs, field controllers)",
    2:  "Level 2 -- Supervisory/SCADA (HMI, historians, SCADA servers)",
    3:  "Level 3 -- Manufacturing Operations (MES, batch control, site ops)",
    35: "Level 3.5 -- IT/OT DMZ Boundary (firewalls, jump servers, data diodes)",
    4:  "Level 4 -- Enterprise IT (business network, ERP, corporate systems)",
}

VALID_PURDUE_LEVELS = [0, 1, 2, 3, 35, 4]

# Higher weight = greater physical consequence if exploited
PURDUE_WEIGHTS: dict[int, float] = {
    0:  3.0,
    1:  2.5,
    2:  2.0,
    3:  1.5,
    35: 1.2,
    4:  1.0,
}

# ---------------------------------------------------------------------------
# Scoring formula
# score = (cvss/10)*50 + (purdue_weight/3.0)*30 + av_points + internet_bonus
# clamped to [0, 100]
# ---------------------------------------------------------------------------
ATTACK_VECTOR_POINTS: dict[str, int] = {
    "NETWORK":  10,
    "ADJACENT": 8,
    "LOCAL":    5,
    "PHYSICAL": 7,
}

VALID_ATTACK_VECTORS = ["NETWORK", "ADJACENT", "LOCAL", "PHYSICAL"]

INTERNET_EXPOSURE_BONUS = 15

CVSS_CONTRIBUTION_MAX = 50.0   # (10/10) * 50
PURDUE_CONTRIBUTION_MAX = 30.0  # (3.0/3.0) * 30
MAX_SCORE = 100.0

# ---------------------------------------------------------------------------
# Tier thresholds
# ---------------------------------------------------------------------------
TIER_THRESHOLDS: dict[str, int] = {
    "CRITICAL": 80,
    "HIGH":     60,
    "MEDIUM":   40,
    "LOW":      0,
}

TIER_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

TIER_COLORS: dict[str, str] = {
    "CRITICAL": "red",
    "HIGH":     "yellow",
    "MEDIUM":   "blue",
    "LOW":      "green",
}

# ---------------------------------------------------------------------------
# OT Sectors
# ---------------------------------------------------------------------------
VALID_SECTORS = [
    "ENERGY",
    "WATER",
    "MANUFACTURING",
    "TRANSPORTATION",
    "CHEMICAL",
    "NUCLEAR",
    "OTHER",
]

# ---------------------------------------------------------------------------
# Volt Typhoon linkage
# When a Level 35 (IT/OT DMZ) advisory matches an internet-exposed DMZ:
# Level 3.5 is the specific boundary Volt Typhoon crosses from IT to OT
# Ref: CISA Advisory AA23-144A, AA24-038A
# ---------------------------------------------------------------------------
VOLT_TYPHOON_ADVISORIES = ["AA23-144A", "AA24-038A"]
VOLT_TYPHOON_NOTE = (
    "VOLT TYPHOON VECTOR -- This advisory affects an IT/OT DMZ component with "
    "internet exposure, matching Volt Typhoon TTPs (CISA AA23-144A / AA24-038A). "
    "See P63 Volt Typhoon Pre-Positioning Tracker for adversary entry-phase analysis."
)
