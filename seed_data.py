"""Demo data -- 20 ICS-CERT advisories, 3 OT environments, 1 pre-baked report (P67)."""
from __future__ import annotations

# ---------------------------------------------------------------------------
# 20 ICS-CERT advisories (ICSA-* format, based on real advisory patterns)
# Scoring reference: score = (cvss/10)*50 + (purdue_weight/3)*30 + av_pts + internet_bonus
# Level weights: L0=3.0, L1=2.5, L2=2.0, L3=1.5, L35=1.2, L4=1.0
# AV pts: NETWORK=10, ADJACENT=8, LOCAL=5, PHYSICAL=7
# Internet bonus: +15 if advisory.purdue_level in env.internet_exposed_levels
# Tier: CRITICAL>=80, HIGH>=60, MEDIUM>=40, LOW<40
# ---------------------------------------------------------------------------

DEMO_ADVISORIES: list[dict] = [
    # ---- CRITICAL TIER ------------------------------------------------
    {
        "advisory_id": "ICSA-24-102-01",
        "title": "Siemens SIMATIC S7-1500 PLC -- Remote Code Execution via EtherNet/IP",
        "vendor": "Siemens",
        "product": "SIMATIC S7-1500 PLC",
        "purdue_level": 1,
        "attack_vector": "NETWORK",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "affected_sectors": ["WATER", "MANUFACTURING", "ENERGY", "CHEMICAL"],
        "patch_available": True,
        "patching_feasible": False,
        "mitigations": [
            "Isolate PLC from direct internet access using industrial firewall",
            "Apply network segmentation to restrict EtherNet/IP traffic",
            "Enable PLC access protection and disable unused communication ports",
            "Monitor for anomalous EtherNet/IP traffic patterns",
        ],
        "published_date": "2024-04-11",
        "summary": (
            "A stack-based buffer overflow in the SIMATIC S7-1500 EtherNet/IP implementation "
            "allows an unauthenticated remote attacker to achieve arbitrary code execution on "
            "the PLC. Exploitation does not require prior authentication. Patching requires "
            "complete PLC shutdown; process continuity constraints typically prevent immediate "
            "remediation in operational environments."
        ),
    },
    {
        "advisory_id": "ICSA-24-065-02",
        "title": "Rockwell Automation ControlLogix 5580 -- Authentication Bypass",
        "vendor": "Rockwell Automation",
        "product": "ControlLogix 5580 EtherNet/IP",
        "purdue_level": 1,
        "attack_vector": "NETWORK",
        "cvss_score": 9.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "affected_sectors": ["WATER", "MANUFACTURING", "ENERGY"],
        "patch_available": True,
        "patching_feasible": False,
        "mitigations": [
            "Enable CIP Security on all ControlLogix EtherNet/IP connections",
            "Restrict access to TCP port 44818 via industrial DMZ",
            "Apply change detection on controller logic to catch unauthorized modifications",
            "Upgrade to firmware v35.011 or later during next planned outage",
        ],
        "published_date": "2024-03-06",
        "summary": (
            "An authentication bypass vulnerability in Rockwell ControlLogix 5580 firmware "
            "allows unauthenticated network attackers to modify controller logic and tags "
            "without providing valid credentials. The vulnerability is exploitable over the "
            "standard EtherNet/IP protocol. Firmware upgrade requires controller halt and "
            "full process shutdown, making immediate patching operationally infeasible."
        ),
    },
    {
        "advisory_id": "ICSA-23-285-02",
        "title": "Schneider Electric Modicon M340 PLC -- Hardcoded Credentials",
        "vendor": "Schneider Electric",
        "product": "Modicon M340 PLC",
        "purdue_level": 1,
        "attack_vector": "NETWORK",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "affected_sectors": ["ENERGY", "CHEMICAL", "WATER"],
        "patch_available": True,
        "patching_feasible": False,
        "mitigations": [
            "Block all external access to Modicon web server (TCP 80/443)",
            "Apply EcoStruxure Control Expert access control lists",
            "Segment Modicon M340 PLCs on isolated VLAN with strict firewall policy",
            "Deploy network anomaly detection for Modicon UMAS protocol traffic",
        ],
        "published_date": "2023-10-12",
        "summary": (
            "Schneider Electric Modicon M340 PLCs contain hardcoded credentials in the "
            "integrated web server that cannot be changed by users. An unauthenticated remote "
            "attacker can use these credentials to gain full administrative access, modify "
            "control logic, and cause physical process disruption. The hardcoded credential "
            "cannot be removed without a full PLC firmware replacement requiring process halt."
        ),
    },
    {
        "advisory_id": "ICSA-24-012-01",
        "title": "Siemens SCALANCE S615 OT Firewall/Router -- Critical RCE",
        "vendor": "Siemens",
        "product": "SCALANCE S615 OT Industrial Firewall",
        "purdue_level": 35,
        "attack_vector": "NETWORK",
        "cvss_score": 9.6,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "affected_sectors": ["ENERGY", "WATER", "MANUFACTURING", "CHEMICAL", "TRANSPORTATION"],
        "patch_available": True,
        "patching_feasible": True,
        "mitigations": [
            "Update SCALANCE S615 to firmware v7.2.0 or later immediately",
            "Restrict management interface access to dedicated management network",
            "Disable HTTPS management access from untrusted network segments",
            "Monitor for unauthorized configuration changes to firewall rules",
            "This is a VOLT TYPHOON VECTOR when the device has internet exposure",
        ],
        "published_date": "2024-01-12",
        "summary": (
            "A remote code execution vulnerability in Siemens SCALANCE S615 industrial "
            "firewalls and routers allows unauthenticated attackers to execute arbitrary code "
            "with root privileges. SCALANCE S615 devices often sit at the Level 3.5 IT/OT "
            "DMZ boundary, making this a high-priority Volt Typhoon pre-positioning vector "
            "when internet-exposed. Exploitation grants full IT/OT boundary control. "
            "Patching is feasible without process downtime; requires device reboot only."
        ),
    },

    # ---- HIGH TIER ----------------------------------------------------
    {
        "advisory_id": "ICSA-24-089-03",
        "title": "Emerson DeltaV DCS -- Privilege Escalation via Engineering Workstation",
        "vendor": "Emerson",
        "product": "DeltaV Distributed Control System",
        "purdue_level": 2,
        "attack_vector": "NETWORK",
        "cvss_score": 8.6,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
        "affected_sectors": ["ENERGY", "CHEMICAL"],
        "patch_available": True,
        "patching_feasible": True,
        "mitigations": [
            "Apply DeltaV Security Update v14.3.1 SP3 during next maintenance window",
            "Restrict DeltaV engineering workstation network access to OT VLAN only",
            "Enable DeltaV application whitelisting to prevent unauthorized binaries",
            "Review and restrict user privilege assignments in DeltaV administration",
        ],
        "published_date": "2024-03-29",
        "summary": (
            "A privilege escalation vulnerability in Emerson DeltaV DCS engineering workstations "
            "allows an authenticated low-privilege user with network access to gain full DCS "
            "administrative privileges. Exploitation can result in unauthorized modification "
            "of control strategies, set-points, and alarm configurations. Patch is available "
            "and can be applied during a standard maintenance window."
        ),
    },
    {
        "advisory_id": "ICSA-24-074-01",
        "title": "GE Digital iFIX SCADA -- SQL Injection in HMI Web Interface",
        "vendor": "GE Digital",
        "product": "iFIX SCADA HMI",
        "purdue_level": 2,
        "attack_vector": "NETWORK",
        "cvss_score": 8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "affected_sectors": ["WATER", "ENERGY", "MANUFACTURING"],
        "patch_available": True,
        "patching_feasible": True,
        "mitigations": [
            "Apply GE Digital iFIX Security Patch Q1-2024",
            "Disable iFIX web interface if not required for operations",
            "Restrict access to iFIX web interface to operator workstations only",
            "Implement input validation via web application firewall for SCADA interface",
        ],
        "published_date": "2024-03-14",
        "summary": (
            "An SQL injection vulnerability in the GE Digital iFIX SCADA web interface allows "
            "an authenticated attacker to extract historian data, modify process set-points via "
            "database manipulation, and potentially execute operating system commands on the "
            "SCADA server. Patch can be applied without SCADA downtime using a rolling upgrade."
        ),
    },
    {
        "advisory_id": "ICSA-24-053-01",
        "title": "Honeywell Experion PKS -- Denial of Service in Controller Communication",
        "vendor": "Honeywell",
        "product": "Experion Process Knowledge System",
        "purdue_level": 2,
        "attack_vector": "NETWORK",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "affected_sectors": ["ENERGY", "NUCLEAR", "CHEMICAL"],
        "patch_available": True,
        "patching_feasible": True,
        "mitigations": [
            "Apply Honeywell Security Notification HSN-2024-03",
            "Rate-limit Experion FTE (Fault Tolerant Ethernet) communications",
            "Implement network segmentation between controller highway and enterprise",
            "Deploy industrial IDS to detect malformed FTE packet floods",
        ],
        "published_date": "2024-02-22",
        "summary": (
            "A denial-of-service vulnerability in the Honeywell Experion PKS controller "
            "communication stack allows an unauthenticated attacker on the process network "
            "to send malformed Fault Tolerant Ethernet packets that crash the Experion C300 "
            "controller. Process loss results in automatic failover, but loss of control "
            "availability until restart. Patch available; applies without controller halt."
        ),
    },
    {
        "advisory_id": "ICSA-23-229-02",
        "title": "Emerson ROC800 RTU -- Unauthenticated Remote Command Execution",
        "vendor": "Emerson",
        "product": "ROC800 Remote Operations Controller RTU",
        "purdue_level": 1,
        "attack_vector": "NETWORK",
        "cvss_score": 8.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "affected_sectors": ["ENERGY"],
        "patch_available": False,
        "patching_feasible": False,
        "mitigations": [
            "Block all inbound ROCLINK 800 TCP traffic at field network boundary",
            "Implement strict allowlist for IP addresses permitted to communicate with ROC800",
            "Deploy protocol-aware industrial firewall to filter ROCLINK protocol traffic",
            "Enable ROC800 audit logging and forward to SIEM for anomaly detection",
            "NO PATCH AVAILABLE -- mitigation via network controls is the only remediation",
        ],
        "published_date": "2023-08-17",
        "summary": (
            "Emerson ROC800 Remote Operations Controllers used in oil and gas wellhead and "
            "pipeline SCADA systems contain an unauthenticated remote command execution "
            "vulnerability in the ROCLINK 800 protocol implementation. A remote attacker can "
            "send specially crafted ROCLINK packets to execute arbitrary commands and modify "
            "measurement and control parameters. No patch has been released by Emerson; "
            "operational constraints prevent firmware modifications to deployed RTUs."
        ),
    },
    {
        "advisory_id": "ICSA-23-271-01",
        "title": "ABB AC500-XC PLC -- Remote Code Execution via Modbus Protocol",
        "vendor": "ABB",
        "product": "AC500-XC Extreme Conditions PLC",
        "purdue_level": 1,
        "attack_vector": "ADJACENT",
        "cvss_score": 8.5,
        "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "affected_sectors": ["ENERGY", "MANUFACTURING", "CHEMICAL"],
        "patch_available": True,
        "patching_feasible": False,
        "mitigations": [
            "Disable unused Modbus TCP port 502 if standard Modbus not required",
            "Implement allowlist-based Modbus firewall to restrict function codes",
            "Apply AC500-XC firmware update v3.4.0 during next planned maintenance",
            "Isolate AC500-XC PLCs on dedicated VLAN inaccessible from business network",
        ],
        "published_date": "2023-09-28",
        "summary": (
            "ABB AC500-XC PLCs contain a remote code execution vulnerability exploitable "
            "via the Modbus TCP protocol from an adjacent network segment. An attacker with "
            "adjacent network access can send malformed Modbus function codes to crash the "
            "PLC or overwrite memory with attacker-controlled code. Firmware remediation "
            "requires PLC power cycle which halts the controlled process."
        ),
    },
    {
        "advisory_id": "ICSA-23-215-01",
        "title": "ABB RMC-100 Remote Monitoring Controller -- Buffer Overflow in HART Protocol",
        "vendor": "ABB",
        "product": "RMC-100 Remote Monitoring Controller",
        "purdue_level": 1,
        "attack_vector": "ADJACENT",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "affected_sectors": ["ENERGY"],
        "patch_available": True,
        "patching_feasible": False,
        "mitigations": [
            "Restrict HART-IP communication to approved engineering workstations only",
            "Deploy HART-aware protocol inspection at substation network boundary",
            "Apply ABB RMC-100 firmware patch during substation outage window",
            "Enable enhanced audit logging on all HART-IP connections to RMC-100",
        ],
        "published_date": "2023-08-03",
        "summary": (
            "A heap-based buffer overflow in the ABB RMC-100 Remote Monitoring Controller "
            "HART protocol stack allows an attacker on the adjacent substation automation "
            "network to cause denial of service or execute arbitrary code. The RMC-100 is "
            "widely deployed in oil, gas, and electric utility substations. Patch application "
            "requires controlled shutdown of the monitoring controller."
        ),
    },
    {
        "advisory_id": "ICSA-23-201-04",
        "title": "Yokogawa CENTUM VP DCS -- Arbitrary Code Execution via Engineering Tool",
        "vendor": "Yokogawa",
        "product": "CENTUM VP Distributed Control System",
        "purdue_level": 2,
        "attack_vector": "NETWORK",
        "cvss_score": 8.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "affected_sectors": ["ENERGY", "CHEMICAL"],
        "patch_available": True,
        "patching_feasible": True,
        "mitigations": [
            "Apply Yokogawa CENTUM VP security patch YSAR-23-0004",
            "Restrict CENTUM VP engineering tool network access to offline mode",
            "Enable CENTUM VP user authentication and role-based access controls",
            "Audit all CENTUM VP engineering tool user accounts and session logs",
        ],
        "published_date": "2023-07-20",
        "summary": (
            "Yokogawa CENTUM VP DCS engineering workstation software contains a vulnerability "
            "that allows an authenticated attacker with engineering-level access on the "
            "process control network to execute arbitrary code on the CENTUM VP server. "
            "Exploitation enables unauthorized modification of control strategies and process "
            "parameters. Patch available and applicable during standard maintenance window."
        ),
    },
    {
        "advisory_id": "ICSA-24-045-04",
        "title": "Honeywell Safety Manager SC -- Unsafe Deserialization in Safety System",
        "vendor": "Honeywell",
        "product": "Safety Manager SC Safety Instrumented System",
        "purdue_level": 1,
        "attack_vector": "LOCAL",
        "cvss_score": 8.5,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
        "affected_sectors": ["ENERGY", "NUCLEAR", "CHEMICAL"],
        "patch_available": True,
        "patching_feasible": False,
        "mitigations": [
            "Restrict physical and logical access to Safety Manager SC engineering ports",
            "Implement strict change management for all Safety Manager SC configuration",
            "Audit all personnel with physical or logical access to safety system",
            "Patching requires IEC 61511 safety lifecycle recertification -- schedule outage",
        ],
        "published_date": "2024-02-14",
        "summary": (
            "An unsafe deserialization vulnerability in the Honeywell Safety Manager SC "
            "Safety Instrumented System allows a local attacker with engineering access to "
            "execute arbitrary code at the safety controller level. Exploitation of a safety "
            "system creates severe physical process risk -- the safety instrumented function "
            "can be disabled, preventing safe shutdown on hazardous process excursions. "
            "Patching requires full safety lifecycle recertification per IEC 61511."
        ),
    },

    # ---- MEDIUM TIER --------------------------------------------------
    {
        "advisory_id": "ICSA-23-299-01",
        "title": "Rockwell Automation FactoryTalk View SE -- Improper Access Control",
        "vendor": "Rockwell Automation",
        "product": "FactoryTalk View Site Edition HMI",
        "purdue_level": 3,
        "attack_vector": "LOCAL",
        "cvss_score": 6.0,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "affected_sectors": ["MANUFACTURING", "WATER"],
        "patch_available": True,
        "patching_feasible": True,
        "mitigations": [
            "Apply FactoryTalk View SE v13.0.00.380 security update",
            "Enforce least-privilege access controls on all FactoryTalk accounts",
            "Enable FactoryTalk Security audit logging for all user sessions",
            "Restrict local logon to authorized operator workstations only",
        ],
        "published_date": "2023-10-26",
        "summary": (
            "An improper access control vulnerability in Rockwell Automation FactoryTalk "
            "View SE HMI software allows a local authenticated user to escalate privileges "
            "and access restricted HMI displays and control functions beyond their assigned "
            "role. Applies to FactoryTalk View SE v12.x and earlier. Patch available and "
            "deployable through standard software update mechanisms."
        ),
    },
    {
        "advisory_id": "ICSA-23-243-01",
        "title": "Siemens SIPROTEC 5 Protection Relay -- Improper Authentication in Web Interface",
        "vendor": "Siemens",
        "product": "SIPROTEC 5 Protection Relay",
        "purdue_level": 3,
        "attack_vector": "PHYSICAL",
        "cvss_score": 6.5,
        "cvss_vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "affected_sectors": ["ENERGY"],
        "patch_available": True,
        "patching_feasible": False,
        "mitigations": [
            "Restrict physical access to substation secondary protection relay panels",
            "Disable SIPROTEC 5 web interface if remote access is not operationally required",
            "Implement physical access control and logging for substation relay rooms",
            "Apply SIPROTEC 5 firmware v9.64 during next substation outage window",
        ],
        "published_date": "2023-08-31",
        "summary": (
            "An improper authentication vulnerability in the Siemens SIPROTEC 5 protection "
            "relay web interface allows a physically present attacker to bypass authentication "
            "and access relay configuration, protection settings, and fault records. Manipulation "
            "of protection relay settings can cause cascading failures in substation protection "
            "coordination. Firmware update requires relay offline period for safety recalibration."
        ),
    },
    {
        "advisory_id": "ICSA-23-187-01",
        "title": "ICONICS GENESIS64 HMI/MES -- Cross-Site Scripting in Web Client",
        "vendor": "ICONICS",
        "product": "GENESIS64 HMI and MES Platform",
        "purdue_level": 3,
        "attack_vector": "NETWORK",
        "cvss_score": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N",
        "affected_sectors": ["MANUFACTURING", "WATER", "ENERGY"],
        "patch_available": True,
        "patching_feasible": True,
        "mitigations": [
            "Apply ICONICS GENESIS64 v10.97.2 security patch",
            "Disable GENESIS64 web client if thin-client access is not required",
            "Enforce Content Security Policy headers on GENESIS64 web server",
            "Audit GENESIS64 user sessions and revoke unnecessary web client access",
        ],
        "published_date": "2023-07-06",
        "summary": (
            "A cross-site scripting vulnerability in the ICONICS GENESIS64 HMI and MES "
            "web client allows an authenticated attacker to inject malicious JavaScript that "
            "executes in the context of other users' browser sessions. This can lead to "
            "session hijacking, unauthorized control of SCADA displays, and data theft from "
            "the GENESIS64 historian. Patch available via standard software update."
        ),
    },
    {
        "advisory_id": "ICSA-24-028-01",
        "title": "Mitsubishi Electric MELSEC Q Series PLC -- Buffer Overflow via SLMP Protocol",
        "vendor": "Mitsubishi Electric",
        "product": "MELSEC Q Series PLC",
        "purdue_level": 3,
        "attack_vector": "ADJACENT",
        "cvss_score": 6.0,
        "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
        "affected_sectors": ["MANUFACTURING"],
        "patch_available": True,
        "patching_feasible": False,
        "mitigations": [
            "Disable SLMP (MC Protocol) TCP port 3000 if not required for operations",
            "Implement allowlist-based filtering for SLMP protocol communications",
            "Apply Mitsubishi MELSEC-Q firmware update during production line shutdown",
            "Segment MELSEC Q PLCs on isolated VLAN with no adjacent-network access",
        ],
        "published_date": "2024-01-28",
        "summary": (
            "A buffer overflow vulnerability in the Seamless Message Protocol (SLMP) "
            "implementation of Mitsubishi Electric MELSEC Q Series PLCs allows an attacker "
            "on an adjacent network to send malformed SLMP packets causing PLC reset or "
            "unauthorized logic modification. Widely deployed in automotive and discrete "
            "manufacturing. Patch requires production line halt for PLC firmware update."
        ),
    },
    {
        "advisory_id": "ICSA-24-037-02",
        "title": "ABB ACS880 Industrial Drive -- Firmware Update Authentication Bypass",
        "vendor": "ABB",
        "product": "ACS880 Industrial Drive",
        "purdue_level": 3,
        "attack_vector": "LOCAL",
        "cvss_score": 6.5,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H",
        "affected_sectors": ["MANUFACTURING", "ENERGY"],
        "patch_available": True,
        "patching_feasible": True,
        "mitigations": [
            "Apply ABB ACS880 drive firmware v2.14.0 via ABB Drive Composer Pro",
            "Restrict physical and logical access to ABB drive engineering ports",
            "Audit all personnel with local access to ABB ACS880 drive systems",
            "Enable ABB drive parameter change logging for anomaly detection",
        ],
        "published_date": "2024-02-06",
        "summary": (
            "An authentication bypass in the ABB ACS880 industrial drive firmware update "
            "mechanism allows a local attacker with USB or drive bus access to load "
            "unauthorized firmware, potentially causing unsafe motor control behavior. "
            "Affects ACS880 drives used in compressors, pumps, and conveyor systems. "
            "Patch deployable via ABB Drive Composer Pro without process downtime."
        ),
    },
    {
        "advisory_id": "ICSA-24-019-03",
        "title": "Fanuc R-30iB Robot Controller -- Path Traversal in Remote Maintenance Interface",
        "vendor": "Fanuc",
        "product": "R-30iB Robot Controller",
        "purdue_level": 3,
        "attack_vector": "LOCAL",
        "cvss_score": 5.5,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "affected_sectors": ["MANUFACTURING"],
        "patch_available": True,
        "patching_feasible": True,
        "mitigations": [
            "Apply Fanuc R-30iB controller software version 9.10/04 or later",
            "Disable FANUC Data Server if remote file access is not operationally required",
            "Restrict local network access to robot controller teaching pendant interface",
            "Audit R-30iB controller access logs for unauthorized file system traversal",
        ],
        "published_date": "2024-01-19",
        "summary": (
            "A path traversal vulnerability in the Fanuc R-30iB industrial robot controller "
            "remote maintenance interface allows a local network attacker to read arbitrary "
            "files from the controller file system, including teach pendant programs, I/O "
            "configurations, and calibration data. Information disclosure enables targeted "
            "follow-on attacks against robot programming. Patch available via standard update."
        ),
    },

    # ---- LOW TIER -----------------------------------------------------
    {
        "advisory_id": "ICSA-23-173-02",
        "title": "Claroty xDome OT Security Platform -- Insecure Deserialization in REST API",
        "vendor": "Claroty",
        "product": "xDome OT Security Platform",
        "purdue_level": 4,
        "attack_vector": "LOCAL",
        "cvss_score": 4.0,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "affected_sectors": ["ENERGY", "WATER", "MANUFACTURING", "CHEMICAL"],
        "patch_available": True,
        "patching_feasible": True,
        "mitigations": [
            "Update Claroty xDome to platform version 4.5.2 or later",
            "Restrict xDome REST API access to authorized administrator accounts only",
            "Enable xDome audit logging and forward to enterprise SIEM",
        ],
        "published_date": "2023-06-22",
        "summary": (
            "An insecure deserialization vulnerability in the Claroty xDome OT security "
            "platform REST API allows a local authenticated low-privilege user to read "
            "sensitive configuration data from the platform. Affects enterprise IT layer "
            "only; no direct OT impact. Patch available via standard platform update."
        ),
    },
    {
        "advisory_id": "ICSA-23-157-01",
        "title": "Nozomi Networks Guardian -- Information Disclosure via API Endpoint",
        "vendor": "Nozomi Networks",
        "product": "Nozomi Networks Guardian OT Sensor",
        "purdue_level": 4,
        "attack_vector": "LOCAL",
        "cvss_score": 3.8,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
        "affected_sectors": ["ENERGY", "WATER", "MANUFACTURING", "CHEMICAL"],
        "patch_available": True,
        "patching_feasible": True,
        "mitigations": [
            "Update Nozomi Guardian to version 23.2.0 or later",
            "Restrict Guardian management API to administrator accounts only",
            "Ensure Guardian sensors are deployed on isolated management network",
        ],
        "published_date": "2023-06-06",
        "summary": (
            "An information disclosure vulnerability in the Nozomi Networks Guardian OT "
            "sensor management API allows a local authenticated attacker to enumerate "
            "network asset inventory data through an unauthenticated API endpoint. "
            "Affects enterprise IT monitoring layer only; no direct OT impact. "
            "Patch available via standard sensor software update."
        ),
    },
]


# ---------------------------------------------------------------------------
# 3 Demo OT environments
# ---------------------------------------------------------------------------

DEMO_ENVIRONMENTS: list[dict] = [
    {
        "name": "Riverside Water Treatment Plant",
        "sector": "WATER",
        "purdue_levels_present": [1, 2, 3],
        "internet_exposed_levels": [3],
        "vendor_list": ["Siemens", "Rockwell Automation", "GE Digital"],
        "description": (
            "Municipal water treatment facility serving approximately 250,000 residents. "
            "Level 1 Siemens S7-1500 PLCs control chemical dosing pumps and filtration. "
            "Level 2 GE iFIX SCADA provides HMI for 14 operator workstations. "
            "Level 3 Rockwell FactoryTalk View SE historian with internet-facing "
            "reporting portal for state environmental compliance reporting."
        ),
    },
    {
        "name": "Gulf Coast Petroleum Refinery",
        "sector": "ENERGY",
        "purdue_levels_present": [0, 1, 2, 3],
        "internet_exposed_levels": [],
        "vendor_list": ["Honeywell", "Emerson", "ABB", "Yokogawa"],
        "description": (
            "100,000 barrel-per-day crude oil refinery. Level 0/1 instrumentation "
            "includes Emerson ROC800 RTUs at wellhead interfaces and ABB AC500-XC PLCs "
            "in distillation control. Level 1 Honeywell Safety Manager SC protects "
            "against high-pressure blowout scenarios. Level 2 Emerson DeltaV and "
            "Honeywell Experion PKS provide process control. Fully air-gapped: "
            "no internet exposure at any Purdue level."
        ),
    },
    {
        "name": "Detroit Auto Assembly Plant",
        "sector": "MANUFACTURING",
        "purdue_levels_present": [1, 2, 3, 35],
        "internet_exposed_levels": [35],
        "vendor_list": ["Siemens", "Fanuc", "Mitsubishi Electric", "Rockwell Automation"],
        "description": (
            "High-volume automotive assembly facility producing 1,200 vehicles per day. "
            "Level 1 Siemens S7-1500 PLCs control welding cells and body-in-white assembly. "
            "Level 3 includes Fanuc R-30iB robot controllers (480 robots), "
            "Mitsubishi MELSEC Q PLCs, and Rockwell FactoryTalk MES. "
            "Level 3.5 Siemens SCALANCE S615 firewall provides internet-exposed DMZ "
            "for OEM supplier quality data exchange -- this is the Volt Typhoon attack surface."
        ),
    },
]


# ---------------------------------------------------------------------------
# Pre-baked assessment report for Riverside Water Treatment Plant
# Scoring (no internet at L35 since env only has L1/L2/L3, internet_exposed=[3]):
# - ICSA-24-102-01: Siemens S7-1500, L1, NETWORK, CVSS 9.8 -> 84.0 CRITICAL
# - ICSA-24-065-02: Rockwell ControlLogix, L1, NETWORK, CVSS 9.0 -> 80.0 CRITICAL
# - ICSA-24-074-01: GE iFIX SCADA, L2, NETWORK, CVSS 8.1 -> 70.5 HIGH
# - ICSA-24-012-01: Siemens SCALANCE, L35, NETWORK, CVSS 9.6 -> 70.0 HIGH (no internet bonus: 35 not in [3])
# - ICSA-23-243-01: Siemens SIPROTEC, L3, PHYSICAL, CVSS 6.5 -> 54.5 MEDIUM
# - ICSA-23-299-01: Rockwell FactoryTalk, L3, LOCAL, CVSS 6.0 -> 50.0 MEDIUM
# Overall: CRITICAL (2 critical findings)
# ---------------------------------------------------------------------------

DEMO_REPORT_TEXT = """\
RESTRICTED // OT SECURITY ASSESSMENT // PRE-DECISIONAL

TO: Facility Manager, Riverside Water Treatment Plant
FROM: ICS Security Assessment Team
RE: ICS/SCADA Vulnerability Exposure Assessment
DATE: 2026-06-24
CLASSIFICATION: RESTRICTED -- CRITICAL INFRASTRUCTURE

------------------------------------------------------------------------
I. EXECUTIVE SUMMARY
------------------------------------------------------------------------

The Riverside Water Treatment Plant presents a CRITICAL overall OT
vulnerability exposure based on 6 applicable ICS-CERT advisories matched
against the installed vendor environment (Siemens, Rockwell Automation,
GE Digital) across Purdue Model Levels 1-3.

Two CRITICAL-tier advisories (exposure score 80-84/100) affect Level 1
programmable logic controllers that cannot be patched without a full
process shutdown: ICSA-24-102-01 (Siemens S7-1500, CVSS 9.8) and
ICSA-24-065-02 (Rockwell ControlLogix 5580, CVSS 9.0). Both are
unauthenticated remote code execution vulnerabilities exploitable from
the plant operations network without credentials.

The Level 3 internet-facing compliance reporting portal increases the
attack surface. An attacker accessing the reporting network could
pivot into Level 2 SCADA and reach Level 1 PLCs governing chemical
dosing -- a direct threat to safe drinking water delivery.

NO VOLT TYPHOON VECTOR DETECTED for this environment. The Siemens
SCALANCE S615 advisory (ICSA-24-012-01) is applicable due to Siemens
vendor presence, but this plant does not operate Level 3.5 DMZ
components, reducing the Volt Typhoon pre-positioning risk.

------------------------------------------------------------------------
II. OT ENVIRONMENT PROFILE
------------------------------------------------------------------------

Facility: Riverside Water Treatment Plant
Sector: Water and Wastewater
Purdue Levels Present: 1 (PLCs), 2 (SCADA/HMI), 3 (MES/Historian)
Internet Exposure: Level 3 (state compliance reporting portal)
Installed Vendors: Siemens, Rockwell Automation, GE Digital
Advisories Checked: 20 | Applicable: 6 | Critical: 2 | High: 2 | Medium: 2

------------------------------------------------------------------------
III. CRITICAL FINDINGS (IMMEDIATE ACTION REQUIRED)
------------------------------------------------------------------------

[CRITICAL] ICSA-24-102-01 -- Siemens SIMATIC S7-1500 PLC
  Purdue Level: 1 (Field Devices -- chemical dosing PLCs)
  CVSS: 9.8 | Exposure Score: 84.0/100
  Attack Vector: Network (unauthenticated)
  Patch Status: MITIGATE ONLY -- operationally constrained
  Risk: Remote code execution enabling unauthorized modification of
  chlorine and fluoride dosing set-points. Physical process impact.
  Action: Apply network isolation to all S7-1500 PLCs. Restrict
  EtherNet/IP to dedicated PLC VLAN. Patch during next planned outage.

[CRITICAL] ICSA-24-065-02 -- Rockwell ControlLogix 5580
  Purdue Level: 1 (Field Devices -- pump and valve control)
  CVSS: 9.0 | Exposure Score: 80.0/100
  Attack Vector: Network (unauthenticated)
  Patch Status: MITIGATE ONLY -- operationally constrained
  Risk: Authentication bypass allows unauthorized modification of pump
  control logic and valve sequencing. Process loss potential.
  Action: Enable CIP Security on all ControlLogix EtherNet/IP ports.
  Upgrade firmware to v35.011 during scheduled maintenance window.

------------------------------------------------------------------------
IV. HIGH-PRIORITY FINDINGS
------------------------------------------------------------------------

[HIGH] ICSA-24-074-01 -- GE Digital iFIX SCADA HMI
  Purdue Level: 2 (Supervisory) | CVSS: 8.1 | Score: 70.5/100
  Patch Status: PATCH AVAILABLE | Vector: Network
  SQL injection in iFIX web interface enables historian manipulation
  and potential SCADA server code execution.
  Action: Apply GE Digital Q1-2024 security patch. Disable iFIX web
  interface access from business network; restrict to operators only.

[HIGH] ICSA-24-012-01 -- Siemens SCALANCE S615 OT Firewall
  Purdue Level: 3.5 (IT/OT DMZ) | CVSS: 9.6 | Score: 70.0/100
  Patch Status: PATCH AVAILABLE | Vector: Network
  Critical RCE in OT firewall/router firmware. Not currently deployed
  at this facility but Siemens vendor relationship creates procurement
  risk. Verify SCALANCE device inventory before dismissing.
  Action: If any SCALANCE devices present, patch immediately to v7.2.0.

------------------------------------------------------------------------
V. MEDIUM-PRIORITY FINDINGS
------------------------------------------------------------------------

[MEDIUM] ICSA-23-243-01 -- Siemens SIPROTEC 5 Protection Relay
  Level: 3 | CVSS: 6.5 | Score: 54.5/100 | Vector: Physical
  Improper authentication in protection relay web interface. Requires
  physical access; mitigated by physical security controls.

[MEDIUM] ICSA-23-299-01 -- Rockwell FactoryTalk View SE HMI
  Level: 3 | CVSS: 6.0 | Score: 50.0/100 | Vector: Local
  Privilege escalation in HMI software. Mitigated by operator
  workstation access controls. Patch available; low operational impact.

------------------------------------------------------------------------
VI. PURDUE MODEL COVERAGE ANALYSIS
------------------------------------------------------------------------

Level 1 exposure is the primary concern: two CRITICAL unauthenticated
RCE vulnerabilities affect PLCs that directly control chemical dosing
and pumping infrastructure. OT patching constraints (no maintenance
window without process shutdown) prevent immediate remediation. Network
segmentation and CIP Security enforcement are the compensating controls.

Level 2 SCADA vulnerabilities are patchable without downtime.
Level 3 vulnerabilities have physical access or local network requirements.
No Level 3.5 DMZ components are deployed, limiting lateral movement
paths from IT to OT networks.

------------------------------------------------------------------------
VII. RECOMMENDED MITIGATIONS (PRIORITY ORDER)
------------------------------------------------------------------------

1. [IMMEDIATE] Segment Level 1 PLCs (Siemens S7-1500, Rockwell
   ControlLogix) on isolated VLAN with no direct access from Level 3
   internet-facing historian network.

2. [IMMEDIATE] Enable CIP Security (TLS) on all ControlLogix EtherNet/IP
   communication paths per Rockwell Security Bulletin SD001.

3. [30 DAYS] Apply GE Digital iFIX Q1-2024 security patch. Restrict
   iFIX web interface to operator VLAN only.

4. [NEXT OUTAGE] Patch Siemens S7-1500 (ICSA-24-102-01) and Rockwell
   ControlLogix (ICSA-24-065-02) firmware during next scheduled outage.

5. [60 DAYS] Audit Siemens device inventory for SCALANCE presence.
   If found, apply SCALANCE firmware patch v7.2.0 immediately.

6. [ONGOING] Deploy industrial protocol-aware IDS (Dragos or Claroty)
   to detect anomalous EtherNet/IP, Modbus, and HART traffic patterns.

------------------------------------------------------------------------
APPENDIX: APPLICABLE ICS-CERT ADVISORY REFERENCE IDs
------------------------------------------------------------------------

  ICSA-24-102-01  Siemens SIMATIC S7-1500 PLC                [CRITICAL]
  ICSA-24-065-02  Rockwell Automation ControlLogix 5580       [CRITICAL]
  ICSA-24-074-01  GE Digital iFIX SCADA HMI                  [HIGH]
  ICSA-24-012-01  Siemens SCALANCE S615 OT Firewall           [HIGH]
  ICSA-23-243-01  Siemens SIPROTEC 5 Protection Relay         [MEDIUM]
  ICSA-23-299-01  Rockwell FactoryTalk View SE                [MEDIUM]

Source: CISA ICS-CERT (cisa.gov/ics-advisories)
Assessment Tool: P67 ICS/SCADA Vulnerability Exposure Assessor
Connection to P63 Volt Typhoon Tracker: No Level 3.5 internet-exposed
  components detected. Re-assess if SCALANCE or jump-server assets added.
"""


# ---------------------------------------------------------------------------
# Default demo environment name
# ---------------------------------------------------------------------------
DEMO_ENV_NAME = "Riverside Water Treatment Plant"
DEMO_ENV_INDEX = 0  # index into DEMO_ENVIRONMENTS
