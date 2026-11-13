"""Small dependency-free categorical Naive Bayes comparison model."""

import argparse
import json
import math
from collections import Counter, defaultdict
from pathlib import Path

from evaluate import LABELS, evaluate_dataset, load_alerts


# Keep identifiers, IPs, descriptions, severity, and the reference label out of
# the model. Numeric telemetry is binned using fixed, documented boundaries.
FEATURE_FIELDS = (
    "event_type",
    "failed_attempts",
    "data_transferred_mb",
    "activity_authorized",
    "user_confirmed",
    "known_identity_provider_outage",
    "service_account",
    "destination_trusted",
    "process_name",
    "process_signed",
    "suspicious_command_line",
    "privilege_approved",
    "change_ticket_present",
    "domain_assessment",
    "detection_verdict",
)


def _feature_values(alert):
    values = {}
    for field in FEATURE_FIELDS:
        value = alert.get(field, "<missing>")
        if field == "failed_attempts" and value != "<missing>":
            value = "0-4" if value < 5 else "5-9" if value < 10 else "10+"
        elif field == "data_transferred_mb" and value != "<missing>":
            value = "0-99" if value < 100 else "100-499" if value < 500 else "500+"
        else:
            value = str(value)
        values[field] = value
    return values


class CategoricalNaiveBayes:
    """Multiclass categorical Naive Bayes with Laplace smoothing."""

    def __init__(self, alpha=1.0):
        if alpha <= 0:
            raise ValueError("alpha must be greater than zero")
        self.alpha = alpha
        self.class_counts = Counter()
        self.feature_counts = defaultdict(Counter)
        self.vocabularies = {field: set() for field in FEATURE_FIELDS}
        self.total = 0

    def fit(self, alerts):
        alerts = list(alerts)
        if not alerts:
            raise ValueError("Cannot train on an empty dataset.")

        for index, alert in enumerate(alerts):
            if "ground_truth_classification" not in alert:
                raise ValueError(f"Training alert at index {index} has no ground-truth label.")
            label = alert["ground_truth_classification"]
            if label not in LABELS:
                raise ValueError(f"Unsupported training label: {label!r}.")
            self.class_counts[label] += 1
            self.total += 1
            for field, value in _feature_values(alert).items():
                self.feature_counts[(label, field)][value] += 1
                self.vocabularies[field].add(value)
        return self

    def predict_one(self, alert):
        if not self.total:
            raise ValueError("Model has not been trained.")

        values = _feature_values(alert)
        best_label = None
        best_score = float("-inf")
        for label in LABELS:
            class_count = self.class_counts[label]
            score = math.log((class_count + self.alpha) / (self.total + self.alpha * len(LABELS)))
            for field, value in values.items():
                vocabulary_size = len(self.vocabularies[field]) + 1  # reserve an unseen-value bucket
                count = self.feature_counts[(label, field)][value]
                likelihood = (count + self.alpha) / (class_count + self.alpha * vocabulary_size)
                score += math.log(likelihood)
            if score > best_score:
                best_label = label
                best_score = score
        return best_label


def print_report(title, report):
    print(f"\n{title}")
    print(f"Accuracy: {report['accuracy']:.3f} ({report['total']} alerts)")
    print(f"{'Class':<14} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Support':>9}")
    for label in report["labels"]:
        metrics = report["per_class"][label]
        print(
            f"{label:<14} {metrics['precision']:>10.3f} {metrics['recall']:>10.3f} "
            f"{metrics['f1']:>10.3f} {metrics['support']:>9}"
        )
    macro = report["macro_avg"]
    print(
        f"{'Macro avg':<14} {macro['precision']:>10.3f} {macro['recall']:>10.3f} "
        f"{macro['f1']:>10.3f} {report['total']:>9}"
    )
    print("Confusion matrix (rows = ground truth, columns = predicted):")
    print(f"{'Actual / Predicted':<18}" + "".join(f"{label:>14}" for label in report["labels"]))
    for actual in report["labels"]:
        values = report["confusion_matrix"][actual]
        print(f"{actual:<18}" + "".join(f"{values[label]:>14}" for label in report["labels"]))


def main():
    project_dir = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Compare the rule engine with a Naive Bayes baseline.")
    parser.add_argument(
        "--train",
        type=Path,
        default=project_dir / "data" / "rule_development_alerts.json",
        help="Labeled training dataset (default: data/rule_development_alerts.json)",
    )
    parser.add_argument(
        "--test",
        type=Path,
        default=project_dir / "data" / "ml_holdout_v2.json",
        help="Held-out evaluation dataset (default: data/ml_holdout_v2.json)",
    )
    args = parser.parse_args()
    if args.train.resolve() == args.test.resolve():
        parser.error("training and held-out evaluation paths must be different")
    train_alerts = load_alerts(args.train)
    test_alerts = load_alerts(args.test)
    train_ids = {alert.get("alert_id") for alert in train_alerts}
    test_ids = {alert.get("alert_id") for alert in test_alerts}
    overlap = train_ids & test_ids
    if overlap:
        parser.error(f"training and held-out sets share alert IDs: {sorted(overlap)}")
    model = CategoricalNaiveBayes().fit(train_alerts)

    print(f"Training alerts: {len(train_alerts)}")
    print(f"Held-out alerts: {len(test_alerts)}")
    print_report("Context-aware rules", evaluate_dataset(test_alerts))
    print_report("Categorical Naive Bayes", evaluate_dataset(test_alerts, predictor=model.predict_one))


if __name__ == "__main__":
    main()
