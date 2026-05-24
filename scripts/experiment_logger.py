#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════
# SME SIEM Dissertation — Experiment Logger
# Harshil Patel — University of Gloucestershire — 2026
# ═══════════════════════════════════════════════════════════════════
# Run: sudo python3 experiment_logger.py BASELINE
#      sudo python3 experiment_logger.py FRAMEWORK
# ═══════════════════════════════════════════════════════════════════

import json
import sys
import csv
import os
import time
from datetime import datetime

ALERTS_LOG = "/var/ossec/logs/alerts/alerts.json"
CSV_OUTPUT = "/home/wazuh-user/dissertation_results.csv"

CSV_HEADERS = [
    "timestamp", "condition", "rule_id", "rule_level",
    "severity", "mitre_technique", "agent_name", "agent_id",
    "sector_profile", "is_sme_rule", "alert_description",
    "readability_score", "sme_explanation_triggered", "raw_alert_snippet"
]

SECTOR_MAP = {
    "001": "healthcare-sme",
    "002": "retail-sme",
    "000": "wazuh-server"
}

SME_RULES = {
    "100001", "100002", "100003", "100004", "100005",
    "100006", "100007", "100008", "100009", "100010",
    "100011", "100012", "100013", "100014", "100015", "100016"
}

def get_severity(level):
    l = int(level) if str(level).isdigit() else 0
    if l >= 15: return "CRITICAL"
    if l >= 12: return "HIGH"
    if l >= 8:  return "MEDIUM"
    if l >= 4:  return "LOW"
    return "LOW"

def get_readability(rule_id, description):
    if str(rule_id) in SME_RULES:
        return 5
    desc = str(description).lower()
    if any(w in desc for w in ["sme-alert", "plain", "sector"]):
        return 5
    if any(w in desc for w in ["failed password", "authentication failure",
                                "user added", "new user"]):
        return 3
    if any(w in desc for w in ["checksum", "integrity", "syslog",
                                "pam:", "sshd:"]):
        return 3
    return 3

def get_mitre(alert):
    try:
        return alert.get("rule", {}).get("mitre", {}).get("id", [""])[0]
    except Exception:
        return ""

def process_alert(alert, condition):
    rule      = alert.get("rule", {})
    agent     = alert.get("agent", {})
    rule_id   = str(rule.get("id", ""))
    level     = rule.get("level", 0)
    desc      = rule.get("description", "")
    agent_id  = str(agent.get("id", "000")).zfill(3)
    agent_name = agent.get("name", "unknown")
    timestamp = alert.get("timestamp", datetime.now().isoformat())

    severity    = get_severity(level)
    readability = get_readability(rule_id, desc)
    is_sme      = rule_id in SME_RULES
    sector      = SECTOR_MAP.get(agent_id, "unknown")
    mitre       = get_mitre(alert)
    sme_exp     = is_sme

    tag = "[SME RULE]" if is_sme else "[DEFAULT] "
    sev_colour = {"CRITICAL":"CRITICAL","HIGH":"HIGH ",
                  "MEDIUM":"MEDIUM  ","LOW":"LOW     "}.get(severity, "LOW     ")

    print(f"{tag} {timestamp[:19]} | Rule {rule_id:>6} | "
          f"Level {level:>2} | {sev_colour} | "
          f"{agent_name:<22} | Readability: {readability}/5 | "
          f"{desc[:50]}")

    return {
        "timestamp":              timestamp,
        "condition":              condition,
        "rule_id":                rule_id,
        "rule_level":             level,
        "severity":               severity,
        "mitre_technique":        mitre,
        "agent_name":             agent_name,
        "agent_id":               agent_id,
        "sector_profile":         sector,
        "is_sme_rule":            is_sme,
        "alert_description":      desc[:120],
        "readability_score":      readability,
        "sme_explanation_triggered": sme_exp,
        "raw_alert_snippet":      json.dumps(alert)[:200]
    }

def monitor(condition):
    file_exists = os.path.isfile(CSV_OUTPUT)
    with open(CSV_OUTPUT, "a", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=CSV_HEADERS)
        if not file_exists:
            writer.writeheader()

        print(f"\n{'='*68}")
        print(f" SME Dissertation Logger — CONDITION: {condition}")
        print(f" CSV output : {CSV_OUTPUT}")
        print(f" Monitoring : {ALERTS_LOG}")
        print(f"{'='*68}\n")

        while not os.path.exists(ALERTS_LOG):
            print("[Logger] Waiting for alerts.json...")
            time.sleep(5)

        with open(ALERTS_LOG, "r") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                try:
                    alert  = json.loads(line.strip())
                    record = process_alert(alert, condition)
                    writer.writerow(record)
                    csvfile.flush()
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    print(f"[Logger] Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ["BASELINE", "FRAMEWORK"]:
        print("Usage: sudo python3 experiment_logger.py BASELINE")
        print("       sudo python3 experiment_logger.py FRAMEWORK")
        sys.exit(1)
    monitor(sys.argv[1])
