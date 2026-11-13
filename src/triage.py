
def evaluate_alert(alert):
    """
    Analyse a security alert and return:
    - Classification
    - Recommended priority
    - Explanation
    """

    event_type = alert.get("event_type", "")
    classification = "needs_review"
    priority = "medium"
    reason = "Unknown event type. Manual investigation is recommended."

    # Rule 1: Failed login attempts
    if event_type == "failed_login":
        attempts = alert.get("failed_attempts", 0)

        if attempts >= 10:
            classification = "suspicious"
            priority = "high"
            reason = f"{attempts} failed login attempts exceed the threshold of 10."

        elif attempts >= 5:
            classification = "suspicious"
            priority = "medium"
            reason = f"{attempts} failed login attempts require investigation."

        else:
            classification = "needs_review"
            priority = "low"
            reason = f"Only {attempts} failed attempts detected. Monitor for repetition."

    # Rule 2: Successful login after failures
    elif event_type == "successful_login_after_failures":
        attempts = alert.get("failed_attempts", 0)

        classification = "suspicious"
        priority = "critical" if attempts >= 10 else "high"
        reason = (
            f"A successful login occurred after {attempts} failed attempts. "
            "Possible account compromise requires investigation."
        )

    # Rule 3: Unusual outbound traffic
    elif event_type == "unusual_outbound_traffic":
        transferred = alert.get("data_transferred_mb", 0)

        classification = "suspicious"

        if transferred >= 500:
            priority = "critical"
            reason = f"Large outbound transfer detected: {transferred} MB."

        elif transferred >= 100:
            priority = "high"
            reason = f"Unusual outbound transfer detected: {transferred} MB."

        else:
            priority = "medium"
            reason = f"Outbound transfer requires review: {transferred} MB."

    # Rule 4: Suspicious process execution
    elif event_type == "suspicious_process":
        classification = "suspicious"
        priority = "high"
        process = alert.get("process_name", "Unknown process")
        reason = f"Suspicious process execution detected: {process}."

    # Rule 5: Privilege escalation
    elif event_type == "privilege_escalation":
        classification = "suspicious"
        priority = "critical"
        reason = "Unexpected administrative privilege assignment detected."

    # Rule 6: Normal DNS query
    elif event_type == "normal_dns_query":
        classification = "benign"
        priority = "low"
        reason = "Routine DNS activity with no suspicious indicators in this dataset."

    # Rule 7: Malware detection
    elif event_type == "malware_detection":
        classification = "suspicious"
        priority = "critical"
        reason = "Endpoint security reported a potentially malicious executable."

    return {
        "classification": classification,
        "recommended_priority": priority,
        "reason": reason
    }
