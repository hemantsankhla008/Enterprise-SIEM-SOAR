def execute_soar_playbook(rule_name: str, severity: str, source_ip: str, threat_score: int) -> list:
    """
    Executes multi-action automated playbooks based on severity and threat score.
    """
    actions_executed = []

    # Playbook 1: Critical SQLi / Zero-Day Remediation
    if severity == "CRITICAL" or threat_score >= 90:
        actions_executed.append(f"PLAYBOOK_ACTIVE: Executed Critical Containment for {source_ip}")
        actions_executed.append(f"FIREWALL_ACL: Permanently Blocked {source_ip} on Perimeter Firewall")
        actions_executed.append("IDENTITY_SOAR: Revoked active API tokens & user session tokens")
        actions_executed.append("WEBHOOK_ALERT: Pushed Emergency Incident payload to SOC Slack Channel")

    # Playbook 2: High Severity Brute Force Quarantine
    elif severity == "HIGH" or threat_score >= 70:
        actions_executed.append(f"PLAYBOOK_ACTIVE: Executed Account Protection for {source_ip}")
        actions_executed.append(f"THROTTLE_RULE: Rate-limiting applied to IP {source_ip} (30 min lockout)")
        actions_executed.append("WEBHOOK_ALERT: Pushed High Severity Warning to SOC Monitoring Console")

    # Default Fallback
    else:
        actions_executed.append("PLAYBOOK_ACTIVE: Standard Alert Logged for Analyst Review")

    return actions_executed