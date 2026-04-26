# Open Security Lakehouse — Design

> **Status:** Draft skeleton. Sections marked **TODO** are decisions still to be made.

## 1. Overview

A Databricks-native security data platform that ingests public threat intelligence and sample security telemetry, transforms it through a medallion architecture, runs version-controlled detections, and surfaces enriched alerts via an LLM-backed triage layer.

The architecture intentionally mirrors the patterns underlying Databricks Lakewatch (open agentic SIEM, GA-pending as of April 2026), built using only generally-available Databricks features so the design is reproducible by anyone with a Free Edition account.

## 2. Goals & Non-Goals

**Goals**
- Demonstrate breadth across the Databricks platform: Delta Lake, Delta Live Tables, Unity Catalog, Databricks SQL, Mosaic AI / Foundation Model APIs.
- Show the *security* design choices an SA would justify to a customer (governance, lineage, retention, separation of duties).
- Be demoable end-to-end in under 10 minutes.

**Non-Goals**
- Production-grade SIEM replacement.
- Coverage of every MITRE ATT&CK technique.
- Realtime detection at enterprise scale.

## 3. Architecture

```
[ Public feeds ] ──> Bronze (raw)  ──> Silver (normalized)  ──> Gold (analytics)
                          │                  │                       │
                          └─ Auto Loader     └─ DLT transforms       └─ Detections
                                                                     └─ Triage agent
                                                                     └─ Dashboard
                                  Unity Catalog governs all of the above
```

**TODO:** Replace with a proper diagram once the components are firm.

## 4. Data Sources

| Source | Format | Cadence | Purpose |
|---|---|---|---|
| NVD CVE feed | JSON | Hourly | Vulnerability context |
| MITRE ATT&CK STIX | JSON | Weekly | Technique enrichment |
| Sample Zeek logs | TSV | Static (demo) | Network telemetry |
| Sample Sysmon | XML/JSON | Static (demo) | Endpoint telemetry |

**TODO:** Confirm licensing for each. NVD and MITRE are public domain; Zeek/Sysmon samples need a clear-license source.

## 5. Layers

### Bronze — Raw ingestion
- Auto Loader watches a landing volume for new files.
- One Delta table per source, schema-on-read.
- Retention: **TODO** (default 90 days?).

### Silver — Normalized
- DLT transforms parse, deduplicate, and conform to a common schema (timestamp, source, asset, indicator, severity, raw).
- Quality expectations (DLT `EXPECT`) enforce required fields.

### Gold — Analytics
- Aggregations: trending CVEs, top IOCs, alert volume by detection.
- Materialized views feeding the dashboard.

## 6. Detection-as-Code

- **Format:** **TODO** — Sigma → SQL transpiled at CI time, or native YAML rules with a small runner. Sigma gives portability; native gives expressiveness.
- **Storage:** `detections/` directory, one rule per file.
- **Testing:** every rule ships with positive and negative test fixtures; CI runs them against synthetic data.
- **Deployment:** merged-to-main rules are auto-deployed to the Databricks workspace via Asset Bundles.

## 7. Governance (Unity Catalog)

- **Catalog:** `lakehouse_demo`
- **Schemas:** `bronze`, `silver`, `gold`, `detections`
- **Tagging:** `pii`, `sensitive`, `public` tags on columns; row-level security via dynamic views where indicated.
- **Lineage:** UC lineage automatically captures bronze→silver→gold flow.

## 8. AI Triage

- Single agent that takes an alert from Gold, enriches it with related CVE/ATT&CK context, and produces a structured triage summary (severity, recommended next step, confidence).
- Model: **TODO** — Foundation Model API (Llama-3 or Claude on Databricks) vs. a local Ollama model on the home server for sensitive workloads.
- Stored as an MLflow model; called from a notebook for the demo.

## 9. Operations

- **CI:** GitHub Actions running gitleaks (already in pre-commit), detection-rule tests, signed-commit verification, branch protection on `main`.
- **CD:** Asset Bundles deploy notebooks, DLT pipelines, and SQL dashboards on merge.
- **Cost:** Free Edition compute caps; document the wall we hit and what would change at paid tier.

## 10. Open Questions

- Detection rule format (Sigma vs native).
- Triage model location (cloud FM API vs. self-hosted).
- Whether to add a streaming bronze source for a "live demo" effect.
- Scope of dashboards — single page or multiple personas?
