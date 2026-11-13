
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

        if alert.get("known_identity_provider_outage") is True:
            classification = "needs_review"
            priority = "medium"
            reason = "Failed logins occurred during a reported identity-provider outage; validate scope and affected accounts."

        elif (
            attempts < 10
            and alert.get("activity_authorized") is True
            and alert.get("user_confirmed") is True
        ):
            classification = "benign"
            priority = "low"
            reason = "The user confirmed an authorized sign-in or password-reset activity."

        elif attempts >= 10:
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

        if alert.get("known_identity_provider_outage") is True:
            classification = "needs_review"
            priority = "medium"
            reason = "The successful login followed failures during a reported identity-provider outage."

        elif (
            attempts < 10
            and alert.get("activity_authorized") is True
            and (alert.get("user_confirmed") is True or alert.get("service_account") is True)
        ):
            classification = "benign"
            priority = "low"
            reason = "The successful login followed authorized, confirmed activity or a documented service-account rotation."

        else:
            classification = "suspicious"
            priority = "critical" if attempts >= 10 else "high"
            reason = (
                f"A successful login occurred after {attempts} failed attempts. "
                "Possible account compromise requires investigation."
            )

    # Rule 3: Unusual outbound traffic
    elif event_type == "unusual_outbound_traffic":
        transferred = alert.get("data_transferred_mb", 0)

        has_context = "destination_trusted" in alert or "activity_authorized" in alert
        if has_context and alert.get("destination_trusted") is True and alert.get("activity_authorized") is True:
            classification = "benign"
            priority = "low"
            reason = "The transfer matches an authorized activity to a documented trusted destination."

        elif has_context and transferred < 500:
            classification = "needs_review"
            priority = "high" if transferred >= 100 else "medium"
            reason = f"Outbound transfer of {transferred} MB lacks enough trusted-destination evidence for disposition."

        elif transferred >= 500:
            classification = "suspicious"
            priority = "critical"
            reason = f"Large outbound transfer detected: {transferred} MB."

        elif transferred >= 100:
            classification = "suspicious"
            priority = "high"
            reason = f"Unusual outbound transfer detected: {transferred} MB."

        else:
            classification = "suspicious"
            priority = "medium"
            reason = f"Outbound transfer requires review: {transferred} MB."

    # Rule 4: Suspicious process execution
    elif event_type == "suspicious_process":
        process = alert.get("process_name", "Unknown process")
        has_context = "suspicious_command_line" in alert or "activity_authorized" in alert or "process_signed" in alert
        if alert.get("suspicious_command_line") is True:
            classification = "suspicious"
            priority = "high"
            reason = f"Suspicious command-line behavior detected for {process}."
        elif (
            alert.get("activity_authorized") is True
            and alert.get("process_signed") is True
        ):
            classification = "benign"
            priority = "low"
            reason = f"Signed process {process} ran as part of authorized activity."
        elif has_context:
            classification = "needs_review"
            priority = "medium"
            reason = f"Process {process} lacks enough execution context for a confident disposition."
        else:
            classification = "suspicious"
            priority = "high"
            reason = f"Suspicious process execution detected: {process}."

    # Rule 5: Privilege escalation
    elif event_type == "privilege_escalation":
        if alert.get("privilege_approved") is False:
            classification = "suspicious"
            priority = "critical"
            reason = "Administrative privilege was explicitly reported as unapproved."
        elif (
            alert.get("privilege_approved") is True
            and alert.get("change_ticket_present") is True
        ):
            classification = "benign"
            priority = "low"
            reason = "Privilege assignment is supported by an approved change ticket."
        elif "privilege_approved" in alert or "change_ticket_present" in alert:
            classification = "needs_review"
            priority = "medium"
            reason = "Privilege assignment lacks complete approval evidence."
        else:
            classification = "suspicious"
            priority = "critical"
            reason = "Unexpected administrative privilege assignment detected."

    # Rule 6: Normal DNS query
    elif event_type == "normal_dns_query":
        domain_assessment = alert.get("domain_assessment")
        if domain_assessment == "suspicious_indicator":
            classification = "suspicious"
            priority = "high"
            reason = "DNS activity contains a suspicious domain indicator requiring investigation."
        elif domain_assessment == "unresolved":
            classification = "needs_review"
            priority = "medium"
            reason = "The queried domain or resolver status is not sufficiently assessed."
        elif domain_assessment == "routine":
            classification = "benign"
            priority = "low"
            reason = "Routine DNS activity with no suspicious indicators in this dataset."
        elif "domain_assessment" in alert:
            classification = "needs_review"
            priority = "medium"
            reason = "DNS context value is unrecognized; analyst validation is recommended."
        else:
            classification = "benign"
            priority = "low"
            reason = "Routine DNS activity with no suspicious indicators in this dataset."

    # Rule 7: Malware detection
    elif event_type == "malware_detection":
        detection_verdict = alert.get("detection_verdict")
        if detection_verdict == "confirmed_malware":
            classification = "suspicious"
            priority = "critical"
            reason = "Endpoint evidence confirms the detected file is malicious."
        elif detection_verdict in {"test_signature", "confirmed_false_positive"}:
            classification = "benign"
            priority = "low"
            reason = "The detection is identified as a test artifact or confirmed false positive."
        elif detection_verdict in {"heuristic", "insufficient_evidence"}:
            classification = "needs_review"
            priority = "medium"
            reason = "The detection lacks a confirmed verdict and requires analyst review."
        elif "detection_verdict" in alert:
            classification = "needs_review"
            priority = "medium"
            reason = "Detection verdict is unrecognized; analyst validation is recommended."
        else:
            classification = "suspicious"
            priority = "critical"
            reason = "Endpoint security reported a potentially malicious executable."

    return {
        "classification": classification,
        "recommended_priority": priority,
        "reason": reason
    }
