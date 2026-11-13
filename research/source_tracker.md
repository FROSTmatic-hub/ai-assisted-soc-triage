# Research Source Tracker

## Project
AI-Assisted Alert Triage in Security Operations Centers

## Research Question
How can AI-assisted alert triage improve SOC efficiency while addressing false positives, explainability, and human oversight?



## Source 1
- Title: Alert Fatigue in Security Operations Centres: Research Challenges and Opportunities
- Authors: Shahroz Tariq, Mohan Baruwal Chhetri, Surya Nepal, and Cecile Paris
- Publication year: 2025
- Source type: Peer-reviewed survey article
- Research objective: To review the causes of SOC alert fatigue and examine academic and industry approaches for mitigating it through automation, augmentation, and human-AI collaboration.
- Key findings:
  1. Alert fatigue has multiple causes, including staff and skills shortages, high false-alarm rates, fragmented dashboards, and inefficient procedures.
  2. Automation can assist with alert prioritisation and routine triage.
  3. Human-AI collaboration offers opportunities to reduce analyst workload.
  4. AI-assisted systems still face challenges involving explainability, bias, integration, and human oversight.
- Limitations: This is a review of existing research and industry solutions, not a direct experimental evaluation of our proposed Python prototype. The effectiveness of individual approaches must be assessed using their own supporting evidence.
- Relevance to my project: Provides the problem background, a framework for categorising triage solutions, and limitations to consider when designing the prototype.
- APA reference: Tariq, S., Chhetri, M. B., Nepal, S., & Paris, C. (2025). Alert fatigue in security operations centres: Research challenges and opportunities. ACM Computing Surveys, 57(9), Article 224. https://doi.org/10.1145/3723158
- URL or DOI: https://doi.org/10.1145/3723158



## Source 2
- Title: Possibilities and Limitations of Using Large Language Models (LLMs) for Alert Classification and Prioritisation in Security Operations Centers (SOCs)
- Authors: Matthias Rieger, Atif Shah, Abu Alam, and Md. Jakir Hossain
- Publication year: 2026
- Source type: Empirical research article
- Research objective: To evaluate the ability of large language models to classify security alerts and assign alert priorities, with comparisons against traditional machine-learning baselines.
- Key findings:
  1. Several evaluated LLMs achieved recall above 90% for binary alert classification.
  2. Alert prioritisation was more challenging, with low precision contributing to additional alert noise.
  3. Lightweight machine-learning models were competitive with LLMs for binary classification.
  4. Linear SVM achieved the highest overall F1-score among the reported binary-classification comparisons.
- Limitations: The reported evaluation used 178 manually labelled alerts. The results should not automatically be generalised to all SOC environments, alert distributions, or unseen attack types. Further limitations should be verified from the full paper.
- Relevance to my project: Provides empirical evidence for distinguishing alert classification from prioritisation and motivates evaluating both precision and recall in the proposed Python prototype.
- APA reference: Rieger, M., Shah, A., Alam, A., & Hossain, M. J. (2026). Possibilities and limitations of using large language models (LLMs) for alert classification and prioritisation in security operations centers (SOCs). Expert Systems with Applications, 331, Article 133194. https://doi.org/10.1016/j.eswa.2026.133194
- URL or DOI: https://doi.org/10.1016/j.eswa.2026.133194



## Source 3
- Title: Towards Human-AI Teaming to Mitigate Alert Fatigue in Security Operations Centres
- Authors: Mohan Baruwal Chhetri, Shahroz Tariq, Ronal Singh, Fatemeh Jalalvand, Cecile Paris, and Surya Nepal
- Publication year: 2024
- Source type: Peer-reviewed research article proposing a conceptual framework
- Research objective: To propose a human-AI teaming framework that addresses SOC alert fatigue through flexible transitions between automation, AI augmentation, and collaborative decision-making.
- Key findings:
  1. Routine alerts may be suitable for automation when their handling is well understood.
  2. AI augmentation can provide analysts with relevant information and recommendations.
  3. Complex or uncertain cases may require human-AI collaborative investigation.
  4. Human oversight, explainability, shared situational awareness, and verification are important considerations.
- Limitations: The paper primarily proposes a conceptual framework and discusses illustrative scenarios. It does not establish through a completed real-world deployment that the framework reduces alert fatigue in every SOC.
- Relevance to my project: Supports designing the proposed triage prototype to provide explanations and preserve human review, particularly for uncertain or high-impact alerts.
- APA reference: Chhetri, M. B., Tariq, S., Singh, R., Jalalvand, F., Paris, C., & Nepal, S. (2024). Towards human-AI teaming to mitigate alert fatigue in security operations centres. ACM Transactions on Internet Technology, 24(3), Article 12, 1–22. https://doi.org/10.1145/3670009
- URL or DOI: https://doi.org/10.1145/3670009



## Source 4
- Title: Artificial Intelligence Risk Management Framework (AI RMF 1.0)
- Author: Elham Tabassi
- Publication year: 2023
- Source type: Official technical framework published by the National Institute of Standards and Technology (NIST)
- Research objective: To provide organisations with a voluntary framework for identifying, assessing, and managing risks associated with artificial intelligence systems.
- Key findings:
  1. The framework organises risk management into Govern, Map, Measure, and Manage.
  2. Trustworthy AI involves considerations such as validity, reliability, safety, security, accountability, transparency, explainability, privacy, and fairness.
  3. AI risks should be considered throughout system design, development, deployment, use, and evaluation.
- Limitations: This is a general AI risk-management framework, not a SOC-specific alert-triage evaluation. Its principles must be adapted to the project's context.
- Relevance to my project: Provides a foundation for documenting system limitations, testing performance, explaining recommendations, and preserving appropriate human oversight.
- APA reference: Tabassi, E. (2023). Artificial intelligence risk management framework (AI RMF 1.0) (NIST AI 100-1). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.AI.100-1
- URL or DOI: https://doi.org/10.6028/NIST.AI.100-1
 



## Source 5
- Title: MITRE ATT&CK Enterprise Framework
- Author: MITRE
- Publication year: Current framework documentation (continuously maintained)
- Source type: Official cybersecurity knowledge base and technical framework
- Research objective: To categorise adversary behaviour into tactics, techniques, and sub-techniques, supporting threat-informed cyber defence and detection development.
- Key findings:
  1. Tactics describe why an adversary performs an action.
  2. Techniques describe how an adversary achieves a tactical objective.
  3. Sub-techniques provide more specific descriptions of adversary behaviour.
  4. Detection strategies organise high-level approaches for identifying adversary techniques.
  5. ATT&CK can help defenders understand and investigate suspicious activity.
- Limitations: ATT&CK does not independently determine whether an alert represents a genuine attack or automatically assign alert severity. Its usefulness depends on available telemetry, detection coverage, and the analyst's interpretation.
- Relevance to my project: Provides a standardised framework for contextualising suspicious alerts and understanding how multiple security events may relate to adversary behaviour.
- APA reference: MITRE. (n.d.). Get started. MITRE ATT&CK. Retrieved November 2, 2026, from https://attack.mitre.org/resources/enterprise-introduction/
- URL or DOI: https://attack.mitre.org/resources/enterprise-introduction/




## Source 6
- Title: Detections and Alerts
- Author: Elastic
- Publication year: n.d. (continuously maintained technical documentation)
- Source type: Official technical documentation
- Research objective: To explain how Elastic Security detection rules evaluate security events, generate alerts, correlate activity, and support the management of detection programs.
- Key findings:
  1. Detection engines evaluate event data against defined detection rules.
  2. Correlation rules can identify relationships between events across connected data sources.
  3. Different detection methods include field matching, event correlation, threshold rules, and machine-learning anomaly detection.
  4. Detection rules should be validated against historical data before deployment.
  5. Detection noise can be reduced through tuning, exceptions, suppression, and other rule-management techniques.
- Limitations: This is product-specific documentation describing Elastic Security capabilities and recommended workflows. It is not an independent comparative evaluation of all SIEM platforms or evidence that every detection approach performs equally well.
- Relevance to my project: Explains practical SIEM detection workflows and provides a foundation for designing event correlation and alert-prioritisation functionality in the proposed prototype.
- APA reference: Elastic. (n.d.). Detections and alerts. Elastic Security Documentation. Retrieved November 2, 2026, from https://www.elastic.co/docs/solutions/security/detect-and-alert
- URL or DOI: https://www.elastic.co/docs/solutions/security/detect-and-alert




## Source 7
- Title: A Systematic Literature Study of Machine Learning Techniques Based Intrusion Detection: Datasets, Models, Challenges, and Future Directions
- Authors: Hafiz Muhammad Raza Ur Rehman, Saira Liaquat, Muhammad Junaid Gul, Muhammad Zeeshan Jhandir, Daniel Gavilanes, Manuel Masias Vergara, et al.
- Publication year: 2025
- Source type: Peer-reviewed systematic literature review
- Journal: Journal of Big Data, Volume 12, Article 264
- Research objective: To systematically review machine-learning-based intrusion detection techniques, commonly used datasets, evaluation metrics, existing limitations, and future research directions.
- Key findings:
  1. Machine learning approaches include supervised learning, unsupervised learning, deep learning, and hybrid methods.
  2. Commonly studied datasets include NSL-KDD, CICIDS2017, and UNSW-NB15.
  3. Dataset imbalance, outdated attack patterns, and differences in preprocessing affect model evaluation.
  4. Reported performance across different datasets cannot be directly compared without considering dataset characteristics and evaluation conditions.
  5. Explainability, generalisation, scalability, and real-time detection remain important research challenges.
- Limitations: The review highlights that benchmark datasets may not represent modern real-world network environments. Its findings synthesise previous studies rather than independently testing every discussed algorithm.
- Relevance to my project: Supports the selection of appropriate machine-learning approaches and evaluation metrics for an optional AI-assisted alert-classification component. It also highlights why prototype results using synthetic or limited data must not be generalised to production SOC environments.
- Ur Rehman, H. M. R., Liaquat, S., Gul, M. J., Jhandir, M. Z., Gavilanes, D., Vergara, M. M., & Ashraf, I. (2025). A systematic literature study of machine learning techniques based intrusion detection: Datasets, models, challenges, and future directions. Journal of Big Data, 12, Article 264. https://doi.org/10.1186/s40537-025-01323-2
- URL or DOI: https://doi.org/10.1186/s40537-025-01323-2

