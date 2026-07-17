# ICS/SCADA Exposure Assessor

**ICS/SCADA Exposure Assessor scores how exposed an industrial control system is by checking a described environment against real government advisories.** You describe an operational-technology (OT) environment — its network layout, exposure, and defenses — and the tool scores it against published CISA ICS advisories, organized by the Purdue Model layers that structure industrial networks.

## What it does

- Takes a structured description of an OT/ICS environment
- Maps it against real CISA ICS advisories and the Purdue Model reference architecture (the standard layered model for industrial control networks)
- Produces a deterministic exposure score with severity tiers and a report explaining which advisories apply and why
- Highlights the IT/OT boundary, where many real-world compromises begin

## How it works

The scoring engine is fully deterministic and cites the specific advisory behind each finding; Claude writes only the executive-summary prose. It never sets a score. The demo ships with example OT environments spanning the severity range so you can see the scoring discriminate.

## Usage

```bash
pip install -r requirements.txt
python main.py assess                    # interactive questionnaire
python main.py demo                      # run a seeded example environment
python main.py catalog                   # browse the advisory catalog
```

## About

ICS/SCADA Exposure Assessor is a command-line tool, part of a portfolio of national-security and defense-compliance software. It assesses a described environment against public advisories; it does not scan or connect to any real control system.
