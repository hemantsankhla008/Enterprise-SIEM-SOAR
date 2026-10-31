import re
from database import SecurityAlert
from ml_engine import anomaly_detector
from threat_intel import enrich_ip_intel
from soar_playbook import execute_soar_playbook

RULES = [
    {
        "id": "RULE_SQLI_01",
        "name": "SQL Injection Attack",
        "severity": "CRITICAL",
        "pattern": r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|OR\s+1=1)",
    },
    {
        "id": "RULE_SSH_02",
        "name": "SSH Brute Force Attempt",
        "severity": "HIGH",
        "pattern": r"(?i)(Failed password|authentication failure)",
    }
]

def analyze_and_respond(raw_log: str, source_ip: str, db: Session):
    triggered_rules = []
    rule_matched = False
    playbook_actions = []

    # Fetch Threat Intel & GeoIP Metadata
    intel = enrich_ip_intel(source_ip)

    # 1. Rule-based Detection
    for rule in RULES:
        if re.search(rule["pattern"], raw_log):
            rule_matched = True
            actions = execute_soar_playbook(rule["name"], rule["severity"], source_ip, intel["threat_score"])
            playbook_actions.extend(actions)
            primary_action = actions[1] if len(actions) > 1 else actions[0]

            alert = SecurityAlert(
                rule_name=rule["name"],
                severity=rule["severity"],
                source_ip=source_ip,
                action_taken=primary_action,
                country=intel["country"],
                isp=intel["isp"],
                threat_score=intel["threat_score"]
            )
            db.add(alert)
            db.commit()
            triggered_rules.append(rule["name"])

    # 2. AI Machine Learning Anomaly Detection
    if not rule_matched and anomaly_detector.is_anomaly(raw_log):
        actions = execute_soar_playbook("AI Anomaly Detected (Zero-Day Pattern)", "HIGH", source_ip, intel["threat_score"])
        playbook_actions.extend(actions)
        primary_action = actions[1] if len(actions) > 1 else actions[0]

        alert = SecurityAlert(
            rule_name="AI Anomaly Detected (Zero-Day Pattern)",
            severity="HIGH",
            source_ip=source_ip,
            action_taken=primary_action,
            country=intel["country"],
            isp=intel["isp"],
            threat_score=intel["threat_score"]
        )
        db.add(alert)
        db.commit()
        triggered_rules.append("AI Anomaly Detected (Zero-Day Pattern)")

    return triggered_rules, intel, playbook_actions
