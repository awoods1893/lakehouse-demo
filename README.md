# lakehouse-demo

An open security lakehouse built on Databricks Free Edition. Ingests public threat intel and security telemetry through a medallion architecture, runs detection-as-code, and uses an LLM-backed triage layer to enrich alerts. The shape of the system mirrors patterns underlying Databricks Lakewatch.

**Status:** Work in progress. See [docs/design.md](docs/design.md) for the full design.

## Layout

| Path | Purpose |
|---|---|
| `pipelines/` | Delta Live Tables pipelines (bronze / silver / gold) |
| `detections/` | Detection-as-code rules (YAML + SQL) |
| `notebooks/` | Exploration and demo notebooks |
| `dashboards/` | Databricks SQL dashboard definitions |
| `infra/` | Databricks Asset Bundles / IaC |
| `docs/` | Design docs and runbooks |
| `.github/workflows/` | CI: secret scan, signed-commit check, detection tests |
