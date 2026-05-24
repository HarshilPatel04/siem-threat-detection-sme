#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════
# SME SIEM Dissertation — Alert Explainer Service
# Harshil Patel — University of Gloucestershire — 2026
# ═══════════════════════════════════════════════════════════════════
# Run as service: sudo systemctl start sme-explainer
# Or directly:    sudo python3 alert_explainer.py
# ═══════════════════════════════════════════════════════════════════

import json
import time
import os
from datetime import datetime

ALERTS_LOG = "/var/ossec/logs/alerts/alerts.json"

SME_EXPLANATIONS = {
    "100001": {
        "title": "Multiple Failed Login Attempts Detected",
        "plain": (
            "Someone is trying many different passwords to get into your system. "
            "This is called a brute force attack. They have not got in yet but "
            "they are actively trying."
        ),
        "action": "Check who is trying to log in. If it is not your staff, "
                  "block the IP address and change all passwords immediately.",
        "severity": "AMBER",
        "mitre": "T1078"
    },
    "100002": {
        "title": "Successful Login After Multiple Failures",
        "plain": (
            "Someone tried many passwords and one of them worked. An attacker "
            "may now be logged into your system. This is a serious incident "
            "that needs immediate attention."
        ),
        "action": "Unplug the internet cable now. Do not turn the computer off. "
                  "Call your IT support or NHS Digital Cyber Helpline: 0300 303 5035.",
        "severity": "RED",
        "mitre": "T1078"
    },
    "100003": {
        "title": "Sensitive Password File Accessed",
        "plain": (
            "The file that stores all passwords on your system has been accessed "
            "or changed. This is very serious. An attacker with this file can "
            "access everything on your system."
        ),
        "action": "Disconnect from internet immediately. Change all passwords "
                  "from a different device. Contact IT support urgently.",
        "severity": "RED",
        "mitre": "T1003"
    },
    "100004": {
        "title": "Credential Dumping Attempt on Windows",
        "plain": (
            "A program is trying to steal saved passwords from your Windows "
            "computer memory. This technique is used in almost every major "
            "cyberattack. Your passwords may be at risk."
        ),
        "action": "Stop all activity on the affected computer. Do not enter "
                  "any passwords. Contact IT support immediately.",
        "severity": "RED",
        "mitre": "T1003"
    },
    "100005": {
        "title": "Suspicious Remote Shell Activity",
        "plain": (
            "Someone may have created a hidden connection from outside into "
            "your computer. This allows an attacker to control your system "
            "remotely without being physically present."
        ),
        "action": "Disconnect from internet. Do not use the affected computer. "
                  "Contact IT support or call Action Fraud: 0300 123 2040.",
        "severity": "RED",
        "mitre": "T1059"
    },
    "100015": {
        "title": "New User Account Created",
        "plain": (
            "A new user account has been created on your system. If none of "
            "your staff did this, an attacker may have created a hidden account "
            "to keep access even after you change passwords."
        ),
        "action": "Ask your staff if anyone created a new account. "
                  "If not, contact IT support. Do not delete the account "
                  "yourself as it is evidence.",
        "severity": "AMBER",
        "mitre": "T1136"
    },
}

def explain_alert(alert):
    rule    = alert.get("rule", {})
    rule_id = str(rule.get("id", ""))
    level   = rule.get("level", 0)
    desc    = rule.get("description", "No description")
    agent   = alert.get("agent", {}).get("name", "unknown")
    ts      = datetime.now().strftime("%H:%M:%S %d/%m/%Y")

    if rule_id not in SME_EXPLANATIONS:
        return

    exp = SME_EXPLANATIONS[rule_id]
    sev = exp["severity"]
    bar = {"RED": "🔴", "AMBER": "🟡", "GREEN": "🟢"}.get(sev, "⚪")

    print(f"\n{'='*65}")
    print(f"{bar}  SME SECURITY ALERT — {sev}")
    print(f"{'='*65}")
    print(f"Time:    {ts}")
    print(f"System:  {agent}")
    print(f"Rule:    {rule_id} (Level {level})")
    print(f"MITRE:   {exp['mitre']}")
    print(f"\nWHAT HAPPENED:")
    print(f"  {exp['plain']}")
    print(f"\nWHAT TO DO:")
    print(f"  {exp['action']}")
    print(f"{'='*65}\n")

def monitor():
    print("\n" + "="*65)
    print("  SME Alert Explainer Service — Running")
    print("  Monitoring:", ALERTS_LOG)
    print("="*65 + "\n")

    while not os.path.exists(ALERTS_LOG):
        print("[Explainer] Waiting for alerts.json...")
        time.sleep(5)

    with open(ALERTS_LOG, "r") as f:
        f.seek(0, 2)
        print("[Explainer] Live monitoring active\n")
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                alert = json.loads(line.strip())
                explain_alert(alert)
            except json.JSONDecodeError:
                continue
            except Exception as e:
                print(f"[Explainer] Error: {e}")

if __name__ == "__main__":
    monitor()
