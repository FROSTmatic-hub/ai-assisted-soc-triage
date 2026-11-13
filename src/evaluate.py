"""Evaluate the rule-based triage classifications against reference labels."""

import json
import argparse
from pathlib import Path

from triage import evaluate_alert


LABELS = ("benign", "suspicious", "needs_review")


def evaluate_dataset(alerts, predictor=None):
    """Return classification metrics for alerts with independent labels.

    The ground-truth field is removed from a shallow copy before the alert is
    passed to the predictor. Metric rows represent ground truth; columns
    represent predictions. The default predictor is the rule engine.
    """
    alerts = list(alerts)
    if not alerts:
        raise ValueError("Cannot evaluate an empty alert dataset.")

    confusion = {actual: {predicted: 0 for predicted in LABELS} for actual in LABELS}
    if predictor is None:
        predictor = lambda alert: evaluate_alert(alert)["classification"]

    for index, alert in enumerate(alerts):
        if "ground_truth_classification" not in alert:
            raise ValueError(f"Alert at index {index} is missing ground_truth_classification.")
        actual = alert["ground_truth_classification"]
        if actual not in LABELS:
            raise ValueError(f"Alert at index {index} has unsupported ground-truth label: {actual!r}.")

        engine_input = {key: value for key, value in alert.items() if key != "ground_truth_classification"}
        predicted = predictor(engine_input)
        if predicted not in LABELS:
            raise ValueError(f"Rule engine returned unsupported classification: {predicted!r}.")
        confusion[actual][predicted] += 1

    per_class = {}
    for label in LABELS:
        true_positive = confusion[label][label]
        false_positive = sum(confusion[actual][label] for actual in LABELS if actual != label)
        false_negative = sum(confusion[label][predicted] for predicted in LABELS if predicted != label)
        support = sum(confusion[label].values())
        precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
        recall = true_positive / support if support else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        per_class[label] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": support,
        }

    total = len(alerts)
    correct = sum(confusion[label][label] for label in LABELS)
    return {
        "total": total,
        "accuracy": correct / total,
        "per_class": per_class,
        "macro_avg": {
            metric: sum(per_class[label][metric] for label in LABELS) / len(LABELS)
            for metric in ("precision", "recall", "f1")
        },
        "confusion_matrix": confusion,
        "labels": LABELS,
    }


def load_alerts(dataset_path=None):
    project_dir = Path(__file__).resolve().parent.parent
    dataset_path = Path(dataset_path) if dataset_path else project_dir / "data" / "sample_alerts.json"
    if not dataset_path.is_absolute():
        dataset_path = project_dir / dataset_path
    with dataset_path.open(encoding="utf-8") as dataset_file:
        return json.load(dataset_file)


def main():
    project_dir = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Compare rule triage classifications with independent reference labels.")
    parser.add_argument(
        "--dataset",
        default=project_dir / "data" / "sample_alerts.json",
        type=Path,
        help="JSON dataset path (default: data/sample_alerts.json)",
    )
    args = parser.parse_args()
    report = evaluate_dataset(load_alerts(args.dataset))
    print(f"Alerts evaluated: {report['total']}")
    print(f"Accuracy: {report['accuracy']:.3f}")
    print("\nPer-class metrics (zero when a metric has no positive predictions/support):")
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

    print("\nConfusion matrix (rows = ground truth, columns = predicted):")
    heading = "Actual / Predicted"
    print(f"{heading:<18}" + "".join(f"{label:>14}" for label in report["labels"]))
    for actual in report["labels"]:
        values = report["confusion_matrix"][actual]
        print(f"{actual:<18}" + "".join(f"{values[label]:>14}" for label in report["labels"]))


if __name__ == "__main__":
    main()
