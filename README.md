# SIEM Threat Detection Framework for SMEs

**BSc Cybersecurity Dissertation — University of Gloucestershire**

> Design and Evaluation of a SIEM-Based Threat Detection Framework  
> for Small and Medium Enterprises (SMEs)  
> *Human-Centric · Sector-Specific · Low-Cost Deployment*

---

## Overview

This repository contains the full research artefact for a BSc dissertation investigating whether open-source SIEM tools can be made genuinely useful for SME operators with no security background.

The core argument: **detection without comprehension does not produce a response.** Wazuh can detect an attack. A dental clinic owner cannot act on "integrity checksum changed." This framework closes that gap.

---

## What Was Built

### Component 1 — Custom MITRE ATT&CK Rule Set
16 custom Wazuh detection rules (IDs 100001–100016) covering the attack techniques most commonly used against SMEs:

| Technique | Description | Level |
|-----------|-------------|-------|
| T1078 | Valid Accounts / Brute Force | 10–12 |
| T1003 | Credential Dumping | 14 |
| T1059 | Command Shell Execution | 10–12 |
| T1021 | Lateral Movement | 10–12 |
| T1486 | Ransomware File Encryption | 15 |
| T1074 | Data Staging | 10 |
| T1041 | Data Exfiltration | 12 |
| T1136 | New Backdoor Account | 10 |
| T1055 | Process Injection | 13 |

Rules are in `/rules/sme_mitre_rules.xml` — drop directly into `/var/ossec/etc/rules/` on any Wazuh installation.

### Component 2 — Sector Configuration Profiles
Agent group configurations for two SME sector profiles:

- **Healthcare SME** — monitors patient data paths, `/etc/shadow`, `/etc/passwd`, auth logs. Real-time FIM with 5-minute scan frequency. Prioritises GDPR-sensitive file access.
- **Retail SME** — monitors POS-relevant paths, active network connections, registry integrity. 3-minute scan frequency. Includes `netstat` command monitoring for outbound connection detection.

Configs are in `/sector-profiles/` — assign to Wazuh agent groups via `agent_groups`.

### Component 3 — Plain-English Alert Explainer
Python service (`alert_explainer.py`) that monitors `alerts.json` in real time and generates human-readable explanations for every custom rule firing. Each explanation includes:

- What happened (one sentence, no jargon)
- Why it matters (business impact, not technical description)
- What to do (numbered steps, immediately actionable)
- Sector-specific regulatory context (GDPR / PCI-DSS)

Runs as a systemd service alongside Wazuh.

### Component 4 — SME Security Guardian App
See the companion repository: [sme-security-guardian](https://github.com/YOUR_USERNAME/sme-security-guardian)

Web dashboard + Telegram push notifications delivering crisis cards to business owners in real time.

---

## Lab Setup

```
┌─────────────────────────────────────────────────────┐
│                 Host-Only Network                   │
│              192.168.56.0/24                        │
│                                                     │
│  Wazuh Server          Ubuntu Victim                │
│  192.168.56.4          192.168.56.5                 │
│  Amazon Linux 2023     Agent 001                    │
│  Wazuh v4.14.4         Healthcare-SME profile       │
│                                                     │
│  Kali Attacker         Windows Victim               │
│  192.168.56.8          192.168.56.6                 │
│  Hydra / ART           Agent 002                    │
│                        Retail-SME profile           │
└─────────────────────────────────────────────────────┘
```

**Tools used:**
- Wazuh v4.14.4 on Amazon Linux 2023
- VirtualBox host-only network (isolated — no internet on victim VMs)
- Hydra (brute force simulation)
- Atomic Red Team (Windows attack simulation)
- Netcat (reverse shell listener)
- Python 3 / Flask (alert explainer and Guardian app)

---

## Experiment Design

Two conditions were evaluated:

| Condition | Rules Active | Logger Tag |
|-----------|-------------|------------|
| BASELINE | Default Wazuh rules only | `BASELINE` |
| FRAMEWORK | Default + 16 custom SME rules | `FRAMEWORK` |

### Attack Simulations (7 total)

| # | Technique | Tool | Target |
|---|-----------|------|--------|
| 1 | T1078 Brute Force SSH | Hydra | Ubuntu (Healthcare) |
| 2 | T1003 Credential File Access | SSH + cat /etc/shadow | Ubuntu (Healthcare) |
| 3 | T1136 Backdoor User Creation | useradd | Ubuntu (Healthcare) |
| 4 | T1074 Data Staging | tar to /tmp | Ubuntu (Healthcare) |
| 5 | T1059 Reverse Shell | Netcat | Ubuntu (Healthcare) |
| 6 | T1003.001 Credential Dump | Atomic Red Team T1003 | Windows (Retail) |
| 7 | T1059.001 PowerShell | Atomic Red Team T1059.001 | Windows (Retail) |

Each attack was run in both BASELINE and FRAMEWORK conditions. All alerts were automatically logged to CSV by `experiment_logger.py`.

---

## Results Summary

**2,303 total alerts captured. 99 custom SME rule firings.**

### Key Finding 1 — Readability Gap

| Alert Source | Readability Score | Example |
|---|---|---|
| Default Wazuh | 3 / 5 | "syslog: User missed the password more than one time" |
| SME Framework | 5 / 5 | "SME-ALERT: Successful login after multiple failures. Credential brute force may have succeeded." |

Score is consistent across every attack. Non-expert operators cannot act on 3/5 alerts. They can act on 5/5 alerts.

### Key Finding 2 — Severity Escalation

| Attack | Default Level | Framework Level | Change |
|--------|--------------|-----------------|--------|
| T1078 Brute Force | 10 MEDIUM | 12 HIGH | ↑ |
| T1003 Cred Access | 3 LOW | 14 HIGH | ↑↑ |
| T1136 Backdoor User | 8 MEDIUM | 10 MEDIUM + CRITICAL chain | ↑ |

### Key Finding 3 — Chain Detection

Rule 40501 fired at Level 15 CRITICAL in the FRAMEWORK condition correlating brute force (T1078) with subsequent backdoor user creation (T1136). This correlation did not surface in the BASELINE condition at any meaningful severity level.

### Key Finding 4 — Windows Detection Gap

Custom rules 100004, 100006, 100008 (Windows-specific) did not fire in either condition. This is documented as a research limitation — FIM-based Windows detection requires additional Sysmon integration for full coverage.

---

## Repository Structure

```
siem-threat-detection-sme/
│
├── rules/
│   └── sme_mitre_rules.xml          # 16 custom MITRE ATT&CK rules
│
├── sector-profiles/
│   ├── healthcare-sme/
│   │   └── agent.conf               # Healthcare sector Wazuh config
│   └── retail-sme/
│       └── agent.conf               # Retail sector Wazuh config
│
├── scripts/
│   ├── alert_explainer.py           # Plain-English alert service
│   ├── experiment_logger.py         # CSV auto-logger (BASELINE/FRAMEWORK)
│   └── sme-explainer.service        # systemd service file
│
├── results/
│   └── dissertation_results.csv     # Full 2,303-alert experiment dataset
│
└── README.md
```

---

## How to Deploy

**1 — Install Wazuh** (if not already running)

Follow the [official Wazuh installation guide](https://documentation.wazuh.com/current/installation-guide/).

**2 — Add custom rules**

```bash
sudo cp rules/sme_mitre_rules.xml /var/ossec/etc/rules/
sudo systemctl restart wazuh-manager
```

**3 — Create sector agent groups**

```bash
sudo /var/ossec/bin/agent_groups -a -g healthcare-sme
sudo /var/ossec/bin/agent_groups -a -g retail-sme

# Copy sector configs
sudo cp sector-profiles/healthcare-sme/agent.conf \
     /var/ossec/etc/shared/healthcare-sme/

sudo cp sector-profiles/retail-sme/agent.conf \
     /var/ossec/etc/shared/retail-sme/
```

**4 — Assign agents to sectors**

```bash
# Replace 001/002 with your actual agent IDs
sudo /var/ossec/bin/agent_groups -a -i 001 -g healthcare-sme
sudo /var/ossec/bin/agent_groups -a -i 002 -g retail-sme
```

**5 — Run the alert explainer**

```bash
sudo cp scripts/sme-explainer.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable sme-explainer
sudo systemctl start sme-explainer
```

**6 — (Optional) Run the experiment logger**

```bash
# For baseline measurement (default rules only)
sudo python3 scripts/experiment_logger.py BASELINE

# For framework measurement (all rules active)
sudo python3 scripts/experiment_logger.py FRAMEWORK
```

Results write automatically to `~/dissertation_results.csv`.

---

## Research Context

**Research Questions:**

- RQ1: Does sector-specific, human-centric SIEM improve detection accuracy vs default Wazuh?
- RQ2: Does plain-language alert explanation improve non-expert operator response?
- RQ3: Can the framework run on low-cost commodity hardware?

**Methodology:** Design Science Research (Hevner et al., 2004) — framework designed as a research artefact, implemented, and evaluated through controlled experiment.

**Key literature:**
- Manzoor et al. (2024) — open-source SIEM benchmarking for SMEs
- Le et al. (2025) — systematic review confirming <5% of security analytics research addresses SME needs
- Nobles (2022) — human factors and complexity debt in non-expert security contexts
- González-Granadillo et al. (2021) — sector-specific SIEM requirements

---

## Limitations

- Virtualised testbed only — not tested on live production SME infrastructure
- Healthcare and Retail sectors only
- Human response evaluation (measuring actual non-expert response time/accuracy) designed but not executed — planned as future work
- Windows attack coverage limited by network isolation in lab environment

---

## Author

**Harshil Patel**  
BSc Cybersecurity — University of Gloucestershire  
📍 Köln, Germany  
📧 pharshil2114@gmail.com  
🔗 [LinkedIn](https://linkedin.com/in/harshil-patel-878977308)

---

## License

MIT License — open for use, modification, and community contribution.

Contributions welcome — particularly sector configs for Legal, Accountancy, and non-UK regulatory contexts.
