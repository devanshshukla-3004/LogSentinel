# 🛡️ LogSentinel

### Security Log Analysis & Threat Detection Engine

> 100 Days • 100 Cybersecurity + Data Science Projects — Day 01/100

LogSentinel is a defensive security analytics engine that converts authentication logs into structured security findings. It validates and normalizes events, detects suspicious authentication patterns, assigns transparent risk scores, and presents the results through an interactive Streamlit dashboard.

## ✨ Core capabilities

- CSV authentication-log ingestion and schema validation
- Timestamp normalization and chronological event processing
- Brute-force burst detection
- Password-spraying detection
- Failure → success sequence detection
- Off-hours authentication detection
- Transparent severity-to-risk scoring
- Interactive Streamlit investigation dashboard
- Automated unit tests for core detection rules

## 🧠 Detection rules

| Detection | Logic | Severity | Score |
|---|---|:---:|---:|
| Brute-force burst | 5+ failed logins from one IP within 10 minutes | HIGH | 75 |
| Password spraying | 5+ distinct users targeted by one IP within 10 minutes | HIGH | 75 |
| Failure → success | Repeated failures followed by successful authentication | HIGH | 75 |
| Repeated failures | 3+ failures from one IP | MEDIUM | 40 |
| Off-hours authentication | Before 06:00 or at/after 23:00 UTC | LOW | 15 |

The first version deliberately uses interpretable rules rather than a black-box ML model, making every finding explainable and testable.

## 🎯 Problem

Authentication systems produce large volumes of events that are difficult to investigate manually. LogSentinel answers practical analyst questions such as which source IPs are behaving unusually, whether failures target one account or many users, whether repeated failures precede a success, and what evidence caused an alert.

## 🏗️ Architecture

    Authentication CSV
           ↓
    Parser + Validator
           ↓
    Normalized Events
           ↓
    Frequency / Pattern / Time Analysis
           ↓
    Threat Detection
           ↓
    Risk Scoring
           ↓
    Streamlit Analyst Dashboard

## 📊 Dashboard

The dashboard provides:
- event totals, failed logins, successful logins, unique IPs and alerts
- threat-category distribution
- top source-IP analysis
- authentication activity timeline
- detailed findings with timestamp, IP, username, severity, score and evidence
- CSV upload for additional synthetic/test datasets

## 📁 Project structure

    LogSentinel/
    ├── app.py
    ├── requirements.txt
    ├── .gitignore
    ├── README.md
    ├── analyzer/
    │   ├── __init__.py
    │   ├── parser.py
    │   ├── features.py
    │   ├── detector.py
    │   └── scorer.py
    ├── data/
    │   └── sample_auth_logs.csv
    └── tests/
        └── test_detector.py

## 🛠️ Tech stack

Python 3 · Pandas · NumPy · Plotly · Streamlit · Pytest · CSV

## 🚀 Run locally

    git clone https://github.com/devanshshukla-3004/LogSentinel.git
    cd LogSentinel
    python -m venv .venv
    .venv\Scripts\Activate.ps1
    pip install -r requirements.txt
    streamlit run app.py

## 🧪 Tests

Run:

    pytest -q

Current test suite covers brute-force detection, password spraying, and failure → success detection. The prepared project passed all 3 tests locally.

## 📄 Input format

Required columns:

    timestamp,source_ip,username,event_type

Supported events:

    FAILED_LOGIN
    SUCCESSFUL_LOGIN

The parser validates the schema, parses timestamps as UTC, normalizes text fields, validates event types, and sorts events chronologically.

## 🔐 Responsible use

LogSentinel is a defensive security analytics and education project. The included dataset is synthetic and contains no real credentials or private authentication records.

It does not attempt authentication, scan external infrastructure, exploit vulnerabilities, collect passwords or secrets, block IPs, or modify production security infrastructure. Only analyze logs you own or are authorized to use.

## 🔮 Roadmap

- configurable thresholds
- optimized sliding-window detection
- alert aggregation and deduplication
- statistical anomaly detection
- ML-based behavioral detection
- threat-intelligence and IOC enrichment
- user/IP/entity risk profiles
- graph-based authentication analytics
- analyst investigation workflow
- security forecasting
- AI-assisted alert explanation

## 📈 Skills demonstrated

Security log analysis · authentication-event modeling · behavioral detection · time-window analytics · data validation · risk scoring · Python architecture · visualization · Streamlit · automated testing · defensive security engineering

## 👨‍💻 Author

Devansh Shukla — BTech CSE · Cybersecurity · Data Science · AI/ML

GitHub: https://github.com/devanshshukla-3004
LinkedIn: https://www.linkedin.com/in/devansh-shukla-22b7a7429/

## 📌 Challenge

100 Days • 100 Cybersecurity + Data Science Projects

Day 01/100 — LogSentinel