# Secure-IDS: A Network Intrusion Detector Built to Survive Attacks

> An ML intrusion-detection system on **UNSW-NB15** that treats the IDS itself as an attack target, and reports its own accuracy honestly.

## Why this project

Most IDS notebooks stop at “train a model, get a high score.” This one asks whether the score can be trusted.

- A naive random split gives **macro-F1 ≈ 0.948**.
- About **40% of the dataset is duplicated**, and the LSTM windows overlapped across train and test, so that number is inflated.
- With official train/test capture separation and removal of flows already seen in training, macro-F1 drops to **≈ 0.818** and the false-positive rate rises sharply.

> A secure IDS is not “train a high-scoring model.” It is trustworthy data splitting, adversarial testing, robust deployment, human review, and traceable model lifecycle controls.

## Features

| Component | What it does |
|---|---|
| **Random Forest** | Per-flow attack detector that outputs P(attack) with a validation-tuned threshold |
| **Family classifier** | Second RF, trained on attack rows only, that estimates the likely family (Recon, Exploits, DoS, Backdoor, ...) |
| **BiLSTM (optional)** | Scores windows of flows, with leakage-free window splitting |
| **FastAPI service** | Security-hardened scoring API that produces SOC-ready alerts |
| **Feedback loop** | Analyst-only labels feed guarded retraining |

## Architecture

```text
Sensor / simulator ──► FastAPI trust boundary
                        ├─ schema validation, body-size limit
                        ├─ hashed API keys + roles, rate limits
                        └─ startup-time model artifact verification (SHA-256)
                              │
                 ┌────────────┼─────────────┐
                 ▼            ▼             ▼
            RF P(attack)  Family clf   BiLSTM (optional)
                 └────────────┬─────────────┘
                              ▼
                       SOC alert builder
        (severity · MITRE ATT&CK · top drivers · triage note)
                              │
                 SIEM/ticketing + SQLite prediction log
                              ▼
              analyst /feedback ──► guarded retraining ──► new manifest
```

## Leakage-aware evaluation

`src/data/splits.py` implements four protocols:

- **Random**: reproduces the inflated baseline.
- **Random + dedup**
- **Official**: original training capture vs. original testing capture.
- **`official_novel`**: official split, minus test flows that are exact copies of training flows. This is the most defensible protocol and the one the served model uses.

Preprocessing (imputation, encoding, scaling, SMOTE) is fitted **on the training partition only**.

## Adversarial ML defenses

### Label poisoning

- `/predict` rejects unknown fields, including `Label`.
- Labels are accepted only through the analyst-only `/feedback`, tied to a logged prediction, with who and when recorded.
- Retraining trusts analyst labels only. Pseudo-labeling is off by default.
- A candidate model is rejected if it does not improve enough or if any attack family’s recall drops past a configured limit. This catches poisoning that hides behind stable overall accuracy.

### Evasion

- A black-box attacker can pad bytes, add packets, slow timing, and set the initial TTL.
- `sttl` turned out to be a dataset artifact, and changing it evaded the plain model completely.
- The hardened model removes TTL features and is adversarially trained on perturbed attack copies, at the cost of a tiny drop in clean macro-F1.

### Supply chain

- A manifest pins model files, preprocessing metadata, thresholds, and feature lists with **SHA-256**.
- Artifacts are verified at startup, and any mismatch stops the API from starting.

## API

| Endpoint | Role | Purpose |
|---|---|---|
| `POST /predict` | sensor | Score one validated flow and return a verdict plus an alert if P(attack) ≥ threshold |
| `POST /predict/sequence` | sensor | Score up to 512 flows as windows with the BiLSTM |
| `POST /feedback` | analyst | Confirm or dismiss a logged prediction, which becomes a trusted label |

Security controls: hashed API keys, constant-time comparison, RBAC, token-bucket rate limits, body-size limits, strict Pydantic schemas, no public docs by default, minimal health disclosure, and defensive response headers.

## SOC-ready alerts

Each alert includes an ECS-style structure, P(attack) and threshold, severity, likely family, **MITRE ATT&CK** tactic and techniques, exact top RF tree-path contributions, and a triage note. If most of the contribution comes from known UNSW-NB15 TTL artifacts, the alert tells the analyst to verify before escalating.

The system **deliberately does not auto-block**. At realistic attack prevalence, even a strong AUC produces large volumes of false alerts, so it is built for human-in-the-loop triage.

## Repository layout

```text
.
├── src/
│   ├── data/            # download_dataset, explore, leakage_check, splits (leakage-aware protocols)
│   ├── features/        # extract (flow features), preprocess (train-only fit + SMOTE)
│   ├── models/          # random_forest, family_classifier, lstm_model,
│   │                    # hardening (adversarial training), manifest (SHA-256 integrity), retrain (guarded)
│   ├── attacks/         # evasion, perturb, poisoning: attacker simulations
│   ├── evaluation/      # evaluate, metrics, per_class_metrics, rigorous_eval
│   ├── serving/         # api, security (auth/rate limits), prediction_log, simulate_traffic
│   ├── soc/             # alerts, attack_mapping (MITRE ATT&CK), explain (tree-path contributions)
│   └── dashboard/       # app (analyst dashboard)
├── models/              # generated artifacts, manifest.json, operating_point.json, ablations/
├── tests/               # attacks, evaluation, LSTM, pipeline, retrain, rigor, serving, SOC, windowing
├── scripts/             # reproduce.sh, demo.sh
├── docs/                # threat_model.md, limitations.md, report/ (LaTeX + PDF)
├── requirements.txt · requirements-dev.txt · requirements.lock
└── README.md
```

## Quick start

Use Python **3.12–3.13**. TensorFlow does not currently provide Python 3.14 wheels.

```bash
python3.13 -m venv .venv
.venv/bin/pip install -r requirements.lock

bash scripts/reproduce.sh  # downloads UNSW-NB15, then trains, evaluates, attacks, verifies, and tests (~15 min, 8 CPU cores, no GPU)
bash scripts/demo.sh       # 2-minute demo (needs artifacts from reproduce.sh)
PREDICTION_LOG_PATH=reports/demo_log.sqlite streamlit run src/dashboard/app.py
```

`reproduce.sh` rebuilds every artifact and report from the raw dataset in a seeded order. It requires network access to download UNSW-NB15, verifies the model manifest, and runs the test suite at the end. The scripts use `.venv/bin/python` by default; override it with `PY=...` if needed.

The demo starts the hardened API, streams 40 held-out flows as a sensor, confirms verdicts as an analyst, prints a triage note, and then shows the controls rejecting a request with no key, a sensor sending a `Label`, a sensor calling `/feedback`, and an out-of-range `sttl`.

## Documentation

- [`docs/threat_model.md`](docs/threat_model.md): attacker model and defenses
- [`docs/limitations.md`](docs/limitations.md): what this project does not claim
- [`docs/report/report.pdf`](docs/report/report.pdf): full write-up

## Key takeaways

- Audit the data split before celebrating the model.
- Measure per-family recall, not just aggregate accuracy.
- Treat the ML system as an attack surface.
- Keep untrusted telemetry separate from trusted analyst labels.
- Version and integrity-check the whole inference contract: model, pipeline, features, threshold.
- Make limitations visible.

## Limitations

- The cleaned UNSW-NB15 lacks identity and time context, so the LSTM adds little over the RF.
- Results are on one benchmark dataset and need validation on live traffic.
- Some features are known dataset artifacts, which is why TTL is excluded.

## Author

**Meev**, cybersecurity student at ESI Sidi Bel Abbès · [github.com/meev777](https://github.com/meev777)
