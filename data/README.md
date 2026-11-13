# Synthetic alert dataset

`sample_alerts.json` contains 64 fictional SOC alerts. The original eight
baseline records remain first, followed by eight additional examples for each
of the seven event types handled by `src/triage.py`. This set is the frozen
baseline evaluation set; use it to report the rule-only baseline.

`rule_development_alerts.json` contains 98 fictional, context-rich scenarios
for rule development and ML training. It includes structured evidence such as
authorization status, user confirmation, trusted destinations, process
evidence, privilege approval, domain assessment, and malware verdict. Labels
were assigned from scenario facts, not generated from engine predictions. The
original 28 scenarios were used during rule development; the added 70 scenarios
expand the training set. Scores on this file are development results, not
independent performance estimates.

`context_holdout_alerts.json` contains 35 context-rich scenarios used for the
previous rule-versus-ML comparison. Its results have been examined, so do not
use it for future independent performance claims.

`ml_holdout_v2.json` contains 35 new context-rich scenarios, five per event
type, with IDs disjoint from the training and earlier evaluation datasets. Its
labels were assigned from scenario facts before predictions. Use it as the
fresh held-out evaluation set; do not use its outcomes to tune this model. If
the model changes after examining these results, create a new holdout before
making a new independent performance claim.

`src/ml_baseline.py` trains a categorical Naive Bayes model only on the 98-alert
development/training set, then evaluates it and the context-aware rules on
`ml_holdout_v2.json`. Model inputs exclude `alert_id`, `source_ip`,
`description`, `severity`, and `ground_truth_classification`; numeric
failed-attempt and transfer values use fixed bins. The fresh holdout is used
only for evaluation, not training or model selection.

## Fields and compatibility

Every record keeps the original fields: `alert_id`, `event_type`, `source_ip`,
`description`, event-specific evidence fields, and `severity`. The additional
`ground_truth_classification` field is an independently assigned reference
label with one of these values:

- `benign`: the fictional context supplies an authorized, routine, or otherwise
  non-malicious explanation.
- `suspicious`: the fictional context includes a concrete indicator of likely
  malicious activity.
- `needs_review`: the context is ambiguous or lacks enough evidence for a
  confident benign or suspicious conclusion.

Labels were assigned from the alert narratives and contextual assumptions
before comparison with the rule engine. They are not copied from
`evaluate_alert` predictions. Some intentional disagreements demonstrate why
the labels are independent. `severity` is the source alert's stated severity;
it is not the ground-truth class or the engine's recommended priority.

The label is an additive JSON field, so existing code that reads the original
fields continues to work. `src/main.py` continues to display the rule engine's
classification and priority; it does not use the reference label.

The added context fields are optional. When the context evidence needed by a
rule is absent, the engine retains its original baseline behavior. The frozen
64-alert dataset does not include these development-only context fields.

## Synthetic data assumptions and limits

All names, accounts, hosts, domains described in the narratives, and incidents
are fictional. Each `source_ip` is in one of the IPv4 documentation ranges
TEST-NET-1 (`192.0.2.0/24`), TEST-NET-2 (`198.51.100.0/24`), or TEST-NET-3
(`203.0.113.0/24`); none identifies a real endpoint. Event-specific fields
vary across records and include values around the rule engine's numeric
thresholds.

These labels are illustrative scenario judgments, not adjudicated incident
outcomes. The dataset is small, hand-authored, and deliberately balanced for
demonstration. It is suitable for exercising code and discussing evaluation
methods, but it cannot support claims about real-world SOC performance or
generalization.
