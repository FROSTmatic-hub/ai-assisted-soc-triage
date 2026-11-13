
import json
from pathlib import Path

from triage import evaluate_alert


def load_alerts():
    project_dir = Path(__file__).resolve().parent.parent
    dataset_path = project_dir / "data" / "sample_alerts.json"

    with open(dataset_path, "r", encoding="utf-8") as file:
        alerts = json.load(file)

    return alerts


def main():
    alerts = load_alerts()

    print("=" * 60)
    print("          SOC ALERT TRIAGE DEMONSTRATOR")
    print("=" * 60)

    print(f"\nTotal alerts loaded: {len(alerts)}")

    for alert in alerts:
        result = evaluate_alert(alert)

        print("\n" + "-" * 60)
        print(f"Alert ID:              {alert['alert_id']}")
        print(f"Event Type:            {alert['event_type']}")
        print(f"Original Severity:     {alert['severity']}")
        print(f"Classification:        {result['classification']}")
        print(f"Recommended Priority:  {result['recommended_priority'].upper()}")
        print(f"Explanation:           {result['reason']}")

    print("\n" + "=" * 60)
    print("             TRIAGE COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()
