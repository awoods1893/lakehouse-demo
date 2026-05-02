# DLT pipelines

## `nvd_cves.py`

Bronze + Silver for the NVD CVE feed.

### What it produces

| Table | Layer | Shape | Source |
|---|---|---|---|
| `lakehouse_demo.bronze.nvd_cves_raw` | bronze | 1 row per API page | Auto Loader on `nvd_landing` volume |
| `lakehouse_demo.silver.cves` | silver | 1 row per CVE (latest by `modified_at`) | `apply_changes` from exploded view |

### Key design choices

- **Auto Loader with `multiLine=true`** because each landing file is one JSON document (the full API response), not JSON Lines.
- **`pathGlobFilter: cves_*.json`** so the in-progress `_tmp/` directory is ignored.
- **Streaming view between bronze and silver** (`cves_exploded`) for the explode + flatten + quality-check transform. Not persisted — just a transformation.
- **`apply_changes` SCD Type 1** for dedup. NVD modifies CVEs over time; a single CVE can appear in multiple bronze pages. We keep the latest by `modified_at` and discard older versions.
- **CVSS v3.1 → v3.0 → v2 fallback columns** because old CVEs only have v2 scores, newer ones have v3.

### Data quality (DLT EXPECT)

Applied as `expect_all_or_drop` on `cves_exploded`:

- `cve_id IS NOT NULL`
- `published_at IS NOT NULL`
- `modified_at IS NOT NULL`

A CVE missing any of these is dropped with metrics emitted to the DLT event log.

### Deployment

Configure a DLT pipeline pointed at this notebook. Catalog: `lakehouse_demo`. Storage: managed (Free Edition default storage).

### Running

Pipeline runs in `Triggered` mode (one-shot batch) for backfill, or `Continuous` for ongoing ingestion. The downstream `silver.cves` updates incrementally as new files appear in the landing volume.
