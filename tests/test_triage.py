
import ipaddress
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

# Allow the test file to import the triage module from src
project_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_dir / "src"))

from triage import evaluate_alert
from evaluate import evaluate_dataset
from ml_baseline import CategoricalNaiveBayes


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

    def test_failed_login_threshold_boundaries(self):
        expected = {
            4: ("needs_review", "low"),
            5: ("suspicious", "medium"),
            9: ("suspicious", "medium"),
            10: ("suspicious", "high"),
        }
        for attempts, (classification, priority) in expected.items():
            with self.subTest(attempts=attempts):
                result = evaluate_alert({"event_type": "failed_login", "failed_attempts": attempts})
                self.assertEqual(result["classification"], classification)
                self.assertEqual(result["recommended_priority"], priority)

    def test_outbound_transfer_threshold_boundaries(self):
        expected = {
            99: "medium",
            100: "high",
            499: "high",
            500: "critical",
        }
        for transferred, priority in expected.items():
            with self.subTest(transferred=transferred):
                result = evaluate_alert({
                    "event_type": "unusual_outbound_traffic",
                    "data_transferred_mb": transferred,
                })
                self.assertEqual(result["recommended_priority"], priority)


class TestSampleDataset(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        dataset_path = project_dir / "data" / "sample_alerts.json"
        with dataset_path.open(encoding="utf-8") as dataset_file:
            cls.alerts = json.load(dataset_file)

    def test_dataset_size_ids_event_coverage_and_labels(self):
        alerts = self.alerts
        self.assertGreaterEqual(len(alerts), 50)
        self.assertLessEqual(len(alerts), 100)
        ids = [alert["alert_id"] for alert in alerts]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(ids[:8], [f"ALT-{number:03d}" for number in range(1, 9)])
        self.assertEqual({alert["event_type"] for alert in alerts}, {
            "failed_login",
            "successful_login_after_failures",
            "unusual_outbound_traffic",
            "suspicious_process",
            "privilege_escalation",
            "normal_dns_query",
            "malware_detection",
        })
        allowed_labels = {"benign", "suspicious", "needs_review"}
        self.assertTrue(all(alert.get("ground_truth_classification") in allowed_labels for alert in alerts))

    def test_dataset_schema_and_documentation_reserved_source_ips(self):
        reserved_ranges = [
            ipaddress.ip_network("192.0.2.0/24"),
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("203.0.113.0/24"),
        ]
        for alert in self.alerts:
            with self.subTest(alert_id=alert["alert_id"]):
                for field in ("alert_id", "event_type", "source_ip", "description", "severity", "ground_truth_classification"):
                    self.assertIn(field, alert)
                source_ip = ipaddress.ip_address(alert["source_ip"])
                self.assertTrue(any(source_ip in network for network in reserved_ranges))

    def test_ground_truth_is_independent_and_not_modified_by_triage(self):
        # ALT-009 is narratively benign despite the intentionally conservative
        # rule engine's low-attempt needs_review output.
        alert = next(item for item in self.alerts if item["alert_id"] == "ALT-009")
        original_label = alert["ground_truth_classification"]
        result = evaluate_alert(alert)
        self.assertEqual(original_label, "benign")
        self.assertEqual(result["classification"], "needs_review")
        self.assertEqual(alert["ground_truth_classification"], original_label)


class TestDatasetEvaluation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        dataset_path = project_dir / "data" / "sample_alerts.json"
        with dataset_path.open(encoding="utf-8") as dataset_file:
            cls.alerts = json.load(dataset_file)

    def test_evaluation_covers_dataset_and_all_ground_truth_classes(self):
        report = evaluate_dataset(self.alerts)
        self.assertEqual(report["total"], 64)
        self.assertEqual(set(report["per_class"]), {"benign", "suspicious", "needs_review"})
        self.assertEqual(
            {label: report["per_class"][label]["support"] for label in report["labels"]},
            {"benign": 22, "suspicious": 25, "needs_review": 17},
        )
        self.assertEqual(
            sum(sum(row.values()) for row in report["confusion_matrix"].values()),
            report["total"],
        )
        self.assertAlmostEqual(report["accuracy"], sum(
            report["confusion_matrix"][label][label] for label in report["labels"]
        ) / report["total"])

    def test_ground_truth_is_stripped_before_engine_and_inputs_are_unchanged(self):
        sample = {
            "event_type": "failed_login",
            "failed_attempts": 4,
            "ground_truth_classification": "benign",
        }
        with patch("evaluate.evaluate_alert") as engine:
            engine.return_value = {"classification": "needs_review"}
            evaluate_dataset([sample])
        engine_input = engine.call_args.args[0]
        self.assertNotIn("ground_truth_classification", engine_input)
        self.assertEqual(sample["ground_truth_classification"], "benign")

    def test_empty_or_invalid_ground_truth_is_rejected(self):
        with self.assertRaises(ValueError):
            evaluate_dataset([])
        with self.assertRaises(ValueError):
            evaluate_dataset([{"event_type": "failed_login"}])
        with self.assertRaises(ValueError):
            evaluate_dataset([{"ground_truth_classification": "unknown"}])

    def test_frozen_baseline_evaluation_is_unchanged(self):
        report = evaluate_dataset(self.alerts)
        self.assertEqual(report["total"], 64)
        self.assertAlmostEqual(report["accuracy"], 0.46875)


class TestRuleDevelopmentDataset(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        dataset_path = project_dir / "data" / "rule_development_alerts.json"
        with dataset_path.open(encoding="utf-8") as dataset_file:
            cls.alerts = json.load(dataset_file)

    def test_expanded_development_dataset_has_all_labels(self):
        self.assertEqual(len(self.alerts), 98)
        label_counts = {}
        for alert in self.alerts:
            label = alert["ground_truth_classification"]
            label_counts[label] = label_counts.get(label, 0) + 1
        self.assertEqual(label_counts, {"benign": 35, "needs_review": 31, "suspicious": 32})

    def test_development_alert_ids_and_source_ips_are_valid(self):
        allowed_ranges = [
            ipaddress.ip_network("192.0.2.0/24"),
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("203.0.113.0/24"),
        ]
        ids = [alert["alert_id"] for alert in self.alerts]
        self.assertEqual(len(ids), len(set(ids)))
        for alert in self.alerts:
            with self.subTest(alert_id=alert["alert_id"]):
                source_ip = ipaddress.ip_address(alert["source_ip"])
                self.assertTrue(any(source_ip in network for network in allowed_ranges))


class TestContextAwareRules(unittest.TestCase):
    def test_unrecognized_dns_assessment_goes_to_review(self):
        result = evaluate_alert({"event_type": "normal_dns_query", "domain_assessment": "uncertain_typo"})
        self.assertEqual(result["classification"], "needs_review")

    def test_unrecognized_malware_verdict_goes_to_review(self):
        result = evaluate_alert({"event_type": "malware_detection", "detection_verdict": "unknown_typo"})
        self.assertEqual(result["classification"], "needs_review")


class TestContextHoldout(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        dataset_path = project_dir / "data" / "context_holdout_alerts.json"
        with dataset_path.open(encoding="utf-8") as dataset_file:
            cls.alerts = json.load(dataset_file)

    def test_holdout_has_new_ids_reserved_ips_and_all_event_types(self):
        self.assertEqual(len(self.alerts), 35)
        ids = [alert["alert_id"] for alert in self.alerts]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(alert_id.startswith("HOLD-") for alert_id in ids))
        event_counts = {}
        for alert in self.alerts:
            event_counts[alert["event_type"]] = event_counts.get(alert["event_type"], 0) + 1
            self.assertIn(alert["ground_truth_classification"], {"benign", "suspicious", "needs_review"})
            source_ip = ipaddress.ip_address(alert["source_ip"])
            self.assertTrue(any(source_ip in network for network in [
                ipaddress.ip_network("192.0.2.0/24"),
                ipaddress.ip_network("198.51.100.0/24"),
                ipaddress.ip_network("203.0.113.0/24"),
            ]))
        self.assertEqual(set(event_counts), {
            "failed_login",
            "successful_login_after_failures",
            "unusual_outbound_traffic",
            "suspicious_process",
            "privilege_escalation",
            "normal_dns_query",
            "malware_detection",
        })
        self.assertEqual(set(event_counts.values()), {5})

    def test_holdout_ids_are_disjoint_from_development_and_baseline_sets(self):
        development_path = project_dir / "data" / "rule_development_alerts.json"
        baseline_path = project_dir / "data" / "sample_alerts.json"
        with development_path.open(encoding="utf-8") as dataset_file:
            development = json.load(dataset_file)
        with baseline_path.open(encoding="utf-8") as dataset_file:
            baseline = json.load(dataset_file)
        holdout_ids = {alert["alert_id"] for alert in self.alerts}
        self.assertTrue(holdout_ids.isdisjoint(alert["alert_id"] for alert in development))
        self.assertTrue(holdout_ids.isdisjoint(alert["alert_id"] for alert in baseline))


class TestNaiveBayesBaseline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with (project_dir / "data" / "rule_development_alerts.json").open(encoding="utf-8") as dataset_file:
            cls.training_alerts = json.load(dataset_file)

    def test_model_fits_expanded_training_set_and_predicts(self):
        model = CategoricalNaiveBayes().fit(self.training_alerts)
        prediction = model.predict_one(self.training_alerts[0])
        self.assertEqual(model.total, 98)
        self.assertIn(prediction, {"benign", "suspicious", "needs_review"})

    def test_model_ignores_reference_label_descriptions_and_identifiers(self):
        model = CategoricalNaiveBayes().fit(self.training_alerts)
        alert = self.training_alerts[0]
        altered = dict(alert)
        altered.update({
            "alert_id": "OTHER-ID",
            "source_ip": "203.0.113.254",
            "description": "Completely changed narrative text",
            "severity": "critical",
            "ground_truth_classification": "suspicious",
        })
        self.assertEqual(model.predict_one(alert), model.predict_one(altered))

    def test_empty_training_data_and_untrained_prediction_are_rejected(self):
        with self.assertRaises(ValueError):
            CategoricalNaiveBayes().fit([])
        with self.assertRaises(ValueError):
            CategoricalNaiveBayes().predict_one({"event_type": "failed_login"})
        with self.assertRaises(ValueError):
            CategoricalNaiveBayes(alpha=0)


class TestMLHoldoutV2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with (project_dir / "data" / "ml_holdout_v2.json").open(encoding="utf-8") as dataset_file:
            cls.alerts = json.load(dataset_file)

    def test_new_holdout_is_structurally_valid_and_disjoint(self):
        self.assertEqual(len(self.alerts), 35)
        ids = [alert["alert_id"] for alert in self.alerts]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(alert_id.startswith("MLH-") for alert_id in ids))
        event_counts = {}
        allowed_networks = [
            ipaddress.ip_network("192.0.2.0/24"),
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("203.0.113.0/24"),
        ]
        for alert in self.alerts:
            event_counts[alert["event_type"]] = event_counts.get(alert["event_type"], 0) + 1
            self.assertIn(alert["ground_truth_classification"], {"benign", "suspicious", "needs_review"})
            source_ip = ipaddress.ip_address(alert["source_ip"])
            self.assertTrue(any(source_ip in network for network in allowed_networks))
        self.assertEqual(set(event_counts), {
            "failed_login",
            "successful_login_after_failures",
            "unusual_outbound_traffic",
            "suspicious_process",
            "privilege_escalation",
            "normal_dns_query",
            "malware_detection",
        })
        self.assertEqual(set(event_counts.values()), {5})

        compared_files = (
            "rule_development_alerts.json",
            "sample_alerts.json",
            "context_holdout_alerts.json",
        )
        holdout_ids = set(ids)
        for filename in compared_files:
            with (project_dir / "data" / filename).open(encoding="utf-8") as dataset_file:
                other_alerts = json.load(dataset_file)
            self.assertTrue(holdout_ids.isdisjoint(alert["alert_id"] for alert in other_alerts))


if __name__ == "__main__":
    unittest.main()
