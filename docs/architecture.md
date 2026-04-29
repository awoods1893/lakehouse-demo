# Architecture & Data Flow

This document explains **what this project is, what it isn't, where the components live, and how data moves through the system**. It's the fastest way to onboard someone (or future-you) to the project.

## What this is

A Databricks-native security data lakehouse, built on **public data only**, that demonstrates the platform patterns underlying [Databricks Lakewatch](https://www.databricks.com/product/lakewatch). The use case is security; the point of the project is platform fluency on Databricks.

## What this is NOT

- ❌ Not connected to your home network
- ❌ Not pulling traffic from your router
- ❌ Not running on your Ubuntu home server
- ❌ Not a production SIEM

If you want a "home SOC" project that *does* collect from your home network, see [Future extensions](#future-extensions). It's a viable separate effort, not part of this scope.

## Components — where things live

```
       LAPTOP                                      CLOUD
+-------------------+
| ~/projects/       |
| lakehouse-demo/   |
| (this repo)       |
+--------+----------+
         |
   git push (signed)
         |
         v
+-------------------+              +---------------------+
| GitHub            |              | NVD                 |
| awoods1893/       |              | nvd.nist.gov        |
| lakehouse-demo    |              | (public CVE API)    |
+--------+----------+              +----------+----------+
         |                                    |
  databricks CLI                              | HTTPS GET
  (deploy Asset Bundles)                      |
         |                                    |
         v                                    v
+-----------------------------------------------------------+
| Databricks Free Edition workspace                         |
|                                                           |
|   Unity Catalog: lakehouse_demo                           |
|   +-----------+----------+--------+--------------+        |
|   |  bronze   |  silver  |  gold  |  detections  |        |
|   |           |          |        |              |        |
|   |  Volume:  |          |        |              |        |
|   |  nvd_     |          |        |              |        |
|   |  landing  |          |        |              |        |
|   +-----------+----------+--------+--------------+        |
|                                                           |
|   Compute: serverless (Free Edition)                      |
|   Notebooks, DLT pipelines, SQL warehouses, MLflow        |
+-----------------------------------------------------------+
```

**Three trust boundaries to be aware of:**
1. **Laptop ↔ GitHub:** SSH keys, signed commits, gitleaks pre-commit
2. **Laptop ↔ Databricks:** OAuth U2M (refresh token at `~/.databricks/token-cache.json`)
3. **Databricks ↔ NVD:** HTTPS, optional NVD API key stored as a Databricks secret

## Data flow — NVD CVE pipeline

This is the main flow the project demonstrates. End-to-end, here's how a CVE published by NIST shows up on the dashboard.

```
[1] NVD downloader notebook (scheduled in Databricks)
        |
        | HTTPS GET https://services.nvd.nist.gov/rest/json/cves/2.0
        |   ?lastModStartDate=...&lastModEndDate=...
        v
    NVD API returns JSON (paginated)
        |
        v
[2] Notebook writes JSON files to UC Volume:
        /Volumes/lakehouse_demo/bronze/nvd_landing/
            cves_2026-04-28T22-30-00_p0.json
            cves_2026-04-28T22-30-00_p1.json
            ...
        |
        v
[3] Auto Loader (DLT pipeline) detects new files in the volume
        |
        v
[4] Bronze table:  lakehouse_demo.bronze.nvd_cves_raw
        - one row per CVE
        - raw JSON column + ingestion metadata (file_path, ingest_ts, source)
        - schema-on-read; minimal validation
        |
        v
[5] Silver table:  lakehouse_demo.silver.cves
        - normalized: cve_id, published_at, modified_at, description,
          cvss_v3_score, cvss_v3_severity, cwe_ids[], references[]
        - DLT EXPECT clauses enforce required fields
        |
        v
[6] Gold table:  lakehouse_demo.gold.cve_trends
        - aggregations: count by severity by day, top affected vendors, etc.
        - powers the dashboard
```

## Data flow — Detection-as-code (planned)

Detections live in this repo as version-controlled YAML/SQL files (`detections/`). They run on Silver/Gold tables.

```
[a] Pull request modifies detections/*.yml
        |
        | CI: rule syntax check + positive/negative fixture tests
        v
[b] Merge to main triggers Asset Bundle deployment
        |
        v
[c] Detection rules registered in workspace as scheduled jobs/queries
        |
        | run on a schedule against silver/gold tables
        v
[d] Alerts written to:  lakehouse_demo.detections.alerts
        - alert_id, rule_id, severity, matched_rows, created_at
```

## Data flow — AI triage (planned)

A small LLM-backed triage step runs after a detection fires. It enriches the alert with related CVE/ATT&CK context and produces a structured summary.

```
[i]   New row appears in lakehouse_demo.detections.alerts
        |
        v
[ii]  Triage notebook (or Mosaic AI Agent) joins the alert with
      relevant CVEs from silver, ATT&CK technique catalog, recent
      similar alerts
        |
        v
[iii] LLM call (Foundation Model API) returns:
        { severity_calibrated, recommended_action, confidence, summary }
        |
        v
[iv]  Result written to:  lakehouse_demo.detections.alerts_triaged
```

## Operational flow — how code gets to the workspace

```
laptop  ──>  git push  ──>  GitHub  ──>  CI (lint + tests)
                                            |
                                            | merge to main
                                            v
                                   Databricks Asset Bundle deploy
                                            |
                                            v
                                   Notebooks / DLT pipelines / SQL
                                   updated in workspace
```

In other words: **nothing in the workspace is configured by hand.** Everything is reproducible from this repo, by anyone with a Free Edition account and the ability to clone.

## Future extensions

These are explicitly **out of scope** for the current project but worth noting so the architecture can be extended sensibly later.

### A. Home network telemetry (a "home SOC")

Adds your own network data as another bronze source:

```
+--------+     mirror     +-------------------+    HTTPS POST    +-----------------+
| Router |--------------->| Ubuntu server     |----------------->| UC Volume:      |
| (span/ |                | running Zeek      |  (databricks fs  | bronze.         |
| mirror)|                | + filebeat or     |   cp via CLI)    | network_landing |
+--------+                | a small Python    |                  +-----------------+
                          | uploader          |
                          +-------------------+
```

Reuses the same bronze→silver→gold pipeline shape; just another source. Auth from Ubuntu server would use a service principal with scoped privileges, NOT the user OAuth token.

### B. Real-time threat intel (live feed)

Replace the batch NVD downloader with a streaming source (e.g. webhook → Databricks streaming endpoint, or Auto Loader on a continuously-updated cloud bucket). Same downstream layers; only the ingest changes.

### C. SOAR-like response

Wire the triaged alerts to a webhook (Slack, PagerDuty, etc.). Useful for the demo but doesn't change architecture meaningfully.
