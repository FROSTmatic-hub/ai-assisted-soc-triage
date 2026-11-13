
# AI-Assisted Alert Triage in Security Operations Centers

## Overview
This project explores how Artificial Intelligence (AI) and Machine Learning (ML) can assist Security Operations Center (SOC) analysts in classifying, prioritising, and reviewing security alerts.

The project focuses on reducing alert fatigue, improving alert-handling workflows, and maintaining human oversight in security operations.

## Objectives
- Understand the problem of alert fatigue in SOC environments.
- Explore AI and ML techniques for security alert classification and prioritisation.
- Examine the benefits and limitations of AI-assisted alert triage.
- Highlight the importance of explainability and human analyst oversight.
- Develop a small Python-based alert triage demonstrator using synthetic security data.

## Project Scope
The project primarily uses secondary research, including academic papers, technical documentation, and cybersecurity frameworks.

A supplementary Python demonstrator will use fictional security alerts to illustrate basic alert classification and prioritisation.

**Note:** The demonstrator is an educational prototype, not a production SOC tool.

## Planned Repository Structure
```text
ai-assisted-soc-triage/
├── data/      # Synthetic security alert dataset
├── research/   # Research sources and source tracker
├── report/     # Academic project report and research notes
├── src/        # Python implementation
├── tests/      # Unit tests
├── README.md
└── .gitignore
```

## Technologies
- Python
- Git and GitHub
- Visual Studio Code
- Python standard library (rule engine and categorical Naive Bayes demonstrator)

## Project Status
Research and documentation completed in draft form.

Python demonstrator: In development.

## Evaluate the rule-based baseline

From the repository root, run:

```powershell
.venv\Scripts\python.exe src\evaluate.py
```

The script compares each rule-engine classification with the independent
`ground_truth_classification` label in `data/sample_alerts.json`. It reports
accuracy, per-class precision/recall/F1, macro averages, and a confusion matrix.
Ground-truth labels are removed from each alert before it reaches the rule
engine. See [data/README.md](data/README.md) for labeling assumptions and
limitations. Because the dataset is synthetic and hand-authored, these metrics
demonstrate an evaluation method; they do not estimate real-world SOC
performance.

To run a development check against the separate context-rich scenarios, use:

```powershell
.venv\Scripts\python.exe src\evaluate.py --dataset data\rule_development_alerts.json
```

Do not report development-set metrics as independent performance results; the
rules were written and checked against those scenarios.

## Compare with a simple ML baseline

Run the dependency-free categorical Naive Bayes comparison with:

```powershell
.venv\Scripts\python.exe src\ml_baseline.py
```

The model trains on `data/rule_development_alerts.json` and compares both
methods on the fresh `data/ml_holdout_v2.json` set. It uses structured event and
context fields, with numeric telemetry placed into fixed bins; it excludes
alert IDs, source IPs, descriptions, severity, and ground-truth labels as
features. The holdout is never used for model fitting. The small synthetic
training set makes this an educational comparison, not evidence of production
performance.

Evaluate the context-aware rules on the separate holdout set with:

```powershell
.venv\Scripts\python.exe src\evaluate.py --dataset data\context_holdout_alerts.json
```

Treat this as a one-time held-out evaluation. Do not tune rules against its
results; it was used for the earlier context-aware rule evaluation. The current
ML comparison uses `data/ml_holdout_v2.json` as a fresh holdout. See
[data/README.md](data/README.md) for the evaluation boundaries.

## Ethical Considerations
This project uses synthetic data and is intended for educational and research purposes. It does not use real organisational security logs or attempt to interact with live systems.

## Author
Cybersecurity postgraduate student.
