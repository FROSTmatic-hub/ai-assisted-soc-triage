
import sys
import unittest
from pathlib import Path

# Allow the test file to import the triage module from src
project_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_dir / "src"))

from triage import evaluate_alert


class TestAlertTriage(unittest.TestCase):

    def test_high_failed_login_attempts(self):
        alert = {
            "event_type": "failed_login",
            "failed_attempts": 12
        }

        result = evaluate_alert(alert)

        self.assertEqual(result["classification"], "suspicious")
        self.assertEqual(result["recommended_priority"], "high")

    def test_low_failed_login_attempts(self):
        alert = {
            "event_type": "failed_login",
            "failed_attempts": 3
        }

        result = evaluate_alert(alert)

        self.assertEqual(result["classification"], "needs_review")
        self.assertEqual(result["recommended_priority"], "low")

    def test_successful_login_after_failures(self):
        alert = {
            "event_type": "successful_login_after_failures",
            "failed_attempts": 8
        }

        result = evaluate_alert(alert)

        self.assertEqual(result["classification"], "suspicious")
        self.assertEqual(result["recommended_priority"], "high")

    def test_privilege_escalation(self):
        alert = {
            "event_type": "privilege_escalation"
        }

        result = evaluate_alert(alert)

        self.assertEqual(result["classification"], "suspicious")
        self.assertEqual(result["recommended_priority"], "critical")

    def test_normal_dns_query(self):
        alert = {
            "event_type": "normal_dns_query"
        }

        result = evaluate_alert(alert)

        self.assertEqual(result["classification"], "benign")
        self.assertEqual(result["recommended_priority"], "low")

    def test_unknown_event_type(self):
        alert = {
            "event_type": "unknown_event"
        }

        result = evaluate_alert(alert)

        self.assertEqual(result["classification"], "needs_review")
        self.assertEqual(result["recommended_priority"], "medium")


    def test_unusual_outbound_traffic(self):
        alert = {
            "event_type": "unusual_outbound_traffic",
            "data_transferred_mb": 950
        }

        result = evaluate_alert(alert)

        self.assertEqual(result["classification"], "suspicious")
        self.assertEqual(result["recommended_priority"], "critical")

    def test_suspicious_process(self):
        alert = {
            "event_type": "suspicious_process",
            "process_name": "powershell.exe"
        }

        result = evaluate_alert(alert)

        self.assertEqual(result["classification"], "suspicious")
        self.assertEqual(result["recommended_priority"], "high")

    def test_malware_detection(self):
        alert = {
            "event_type": "malware_detection"
        }

        result = evaluate_alert(alert)

        self.assertEqual(result["classification"], "suspicious")
        self.assertEqual(result["recommended_priority"], "critical")

    def test_failed_login_at_exact_threshold(self):
        alert = {
            "event_type": "failed_login",
            "failed_attempts": 10
        }

        result = evaluate_alert(alert)

        self.assertEqual(result["classification"], "suspicious")
        self.assertEqual(result["recommended_priority"], "high")


if __name__ == "__main__":
    unittest.main()
