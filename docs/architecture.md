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

---

## Components — where things live

```mermaid
flowchart TB
    subgraph laptop ["💻 Laptop"]
        repo["~/projects/lakehouse-demo<br/><i>this repo</i>"]
    end

    subgraph cloud ["☁️ Cloud"]
        direction LR

        subgraph gh ["GitHub"]
            ghrepo["awoods1893/lakehouse-demo"]
        end

        nvd[("NVD<br/>nvd.nist.gov<br/><i>public CVE API</i>")]:::external

        subgraph dbx ["Databricks Free Edition Workspace"]
            subgraph uc ["Unity Catalog · lakehouse_demo"]
                bronze[("bronze<br/><i>+ nvd_landing volume</i>")]:::storage
                silver[("silver")]:::storage
                gold[("gold")]:::storage
                det[("detections")]:::storage
            end
            nb["Notebooks · DLT · SQL · MLflow"]:::compute
            cmp["Serverless compute"]:::compute
        end
    end

    repo -->|"git push (SSH-signed)"| ghrepo
    repo -->|"databricks CLI<br/>(asset bundles)"| dbx
    ghrepo -.->|"CI deploy"| dbx
    nb -->|"HTTPS"| nvd

    classDef storage fill:#dbeafe,stroke:#1d4ed8,stroke-width:2px,color:#1e3a8a
    classDef compute fill:#fef3c7,stroke:#b45309,stroke-width:2px,color:#78350f
    classDef external fill:#f3f4f6,stroke:#6b7280,stroke-width:2px,color:#374151
```

**Three trust boundaries to be aware of:**
1. **Laptop ↔ GitHub** — SSH keys, signed commits, gitleaks pre-commit
2. **Laptop ↔ Databricks** — OAuth U2M (refresh token at `~/.databricks/token-cache.json`)
3. **Databricks ↔ NVD** — HTTPS, optional NVD API key stored as a Databricks secret

---

## Data flow — NVD CVE pipeline

The main flow the project demonstrates. End-to-end: a CVE published by NIST shows up on the dashboard.

```mermaid
flowchart TD
    dl["NVD downloader<br/><i>scheduled notebook</i>"]:::compute
    api[("NVD API<br/><i>nvd.nist.gov</i>")]:::external
    vol[/"UC Volume<br/>/Volumes/lakehouse_demo/<br/>bronze/nvd_landing/<br/><i>cves_*.json</i>"/]:::volume
    al["Auto Loader · DLT pipeline"]:::compute
    bt[("bronze.nvd_cves_raw<br/><i>1 row per page<br/>raw JSON + metadata</i>")]:::storage
    st[("silver.cves<br/><i>normalized<br/>+ DLT EXPECT</i>")]:::storage
    gt[("gold.cve_trends<br/><i>aggregations</i>")]:::storage
    dash["📊 Dashboard"]:::compute

    dl -->|"HTTPS GET<br/>(paginated)"| api
    api -->|"JSON pages"| dl
    dl -->|"atomic write<br/>(tmp + rename)"| vol
    vol -->|"new files detected"| al
    al --> bt
    bt -->|"parse + normalize"| st
    st -->|"aggregate"| gt
    gt --> dash

    classDef storage fill:#dbeafe,stroke:#1d4ed8,stroke-width:2px,color:#1e3a8a
    classDef compute fill:#fef3c7,stroke:#b45309,stroke-width:2px,color:#78350f
    classDef volume fill:#ede9fe,stroke:#6d28d9,stroke-width:2px,color:#4c1d95
    classDef external fill:#f3f4f6,stroke:#6b7280,stroke-width:2px,color:#374151
```

**Key fields produced at each layer:**

| Layer | Table | What's there |
|---|---|---|
| Bronze | `bronze.nvd_cves_raw` | raw JSON column + `file_path`, `ingest_ts`, `source` |
| Silver | `silver.cves` | `cve_id`, `published_at`, `modified_at`, `description`, `cvss_v3_score`, `cvss_v3_severity`, `cwe_ids`, `references` |
| Gold | `gold.cve_trends` | counts by severity by day, top affected vendors, etc. |

---

## Data flow — Detection-as-code (planned)

Detections live in this repo as version-controlled YAML/SQL files (`detections/`). They run on Silver/Gold tables.

```mermaid
flowchart LR
    pr["PR modifies<br/>detections/*.yml"]:::compute
    ci["CI · syntax<br/>+ fixture tests"]:::compute
    merge{"merge to main"}
    deploy["Asset Bundle deploy"]:::compute
    jobs["Detection rules<br/><i>scheduled jobs / queries</i>"]:::compute
    tables[("silver · gold tables")]:::storage
    alerts[("detections.alerts<br/><i>alert_id, rule_id,<br/>severity, matched_rows</i>")]:::storage

    pr --> ci
    ci -->|"pass"| merge
    merge --> deploy
    deploy --> jobs
    jobs -->|"run on schedule"| tables
    tables -->|"matched rows"| alerts

    classDef storage fill:#dbeafe,stroke:#1d4ed8,stroke-width:2px,color:#1e3a8a
    classDef compute fill:#fef3c7,stroke:#b45309,stroke-width:2px,color:#78350f
```

---

## Data flow — AI triage (planned)

A small LLM-backed triage step runs after a detection fires. It enriches the alert with related CVE/ATT&CK context and produces a structured summary.

```mermaid
sequenceDiagram
    autonumber
    participant A as detections.alerts
    participant T as Triage agent
    participant S as silver.cves
    participant K as ATT&CK catalog
    participant L as Foundation Model API
    participant O as detections.alerts_triaged

    A->>T: new alert row
    T->>S: lookup related CVEs
    T->>K: lookup MITRE techniques
    T->>L: enrich + summarize
    L-->>T: severity_calibrated, recommended_action,<br/>confidence, summary
    T->>O: write triaged record
```

---

## Operational flow — how code gets to the workspace

```mermaid
flowchart LR
    laptop["💻 Laptop"]:::compute --> push["git push"]
    push --> gh["GitHub"]:::external
    gh --> ci["CI<br/>(lint + tests)"]:::compute
    ci -->|"merge to main"| dab["Asset Bundle<br/>deploy"]:::compute
    dab --> ws["Databricks workspace<br/>updated"]:::compute

    classDef compute fill:#fef3c7,stroke:#b45309,stroke-width:2px,color:#78350f
    classDef external fill:#f3f4f6,stroke:#6b7280,stroke-width:2px,color:#374151
```

**The point:** nothing in the workspace is configured by hand. Everything is reproducible from this repo, by anyone with a Free Edition account and the ability to clone.

---

## Future extensions

These are explicitly **out of scope** for the current project but worth noting so the architecture can be extended sensibly later.

### A. Home network telemetry (a "home SOC")

Adds your own network data as another bronze source. Reuses the same bronze→silver→gold shape; only the ingest path changes. Auth from the Ubuntu server uses a service principal with scoped privileges, **not** the user OAuth token.

```mermaid
flowchart LR
    router["🛜 Router<br/><i>span / mirror port</i>"]
    server["🖥️ Ubuntu server<br/><i>Zeek + filebeat<br/>or Python uploader</i>"]:::compute
    vol[/"UC Volume<br/>bronze.network_landing"/]:::volume
    rest["bronze → silver → gold<br/><i>same pipeline shape as NVD</i>"]:::storage

    router -->|"mirror"| server
    server -->|"HTTPS<br/>(databricks fs cp / REST)"| vol
    vol --> rest

    classDef storage fill:#dbeafe,stroke:#1d4ed8,stroke-width:2px,color:#1e3a8a
    classDef compute fill:#fef3c7,stroke:#b45309,stroke-width:2px,color:#78350f
    classDef volume fill:#ede9fe,stroke:#6d28d9,stroke-width:2px,color:#4c1d95
```

### B. Real-time threat intel (live feed)

Replace the batch NVD downloader with a streaming source — webhook → Databricks streaming endpoint, or Auto Loader on a continuously-updated bucket. Same downstream layers; only the ingest changes.

### C. SOAR-like response

Wire triaged alerts to a webhook (Slack, PagerDuty, etc.). Useful for the demo; doesn't change architecture meaningfully.
