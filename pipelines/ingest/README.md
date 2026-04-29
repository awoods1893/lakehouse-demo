# Ingest pipelines

## `nvd_downloader.py`

Pulls CVEs from the public NVD CVE 2.0 API and lands JSON files in
`/Volumes/lakehouse_demo/bronze/nvd_landing/`. Auto Loader downstream picks them up.

### Modes

| Mode | Window | Use |
|---|---|---|
| `backfill` | last `backfill_days` (default 365) | one-time seed |
| `incremental` | last `incremental_hours` (default 24) | scheduled daily |

### File layout

```
/Volumes/lakehouse_demo/bronze/nvd_landing/
├── cves_20260101_20260501_p000_20260428T230000Z.json
├── cves_20260101_20260501_p001_20260428T230000Z.json
├── ...
└── _tmp/   # in-progress writes; renamed atomically into the parent
```

The leading `_tmp/` directory holds files mid-write. Each file is moved into
the volume root only when the JSON payload is fully written, so Auto Loader
never sees a partial file.

### Prerequisites

1. Catalog/schema/volume: `lakehouse_demo.bronze.nvd_landing` (created via CLI in setup)
2. Databricks secret with NVD API key (optional but recommended for backfill speed):

   ```
   databricks secrets create-scope lakehouse_demo --profile free-edition
   databricks secrets put-secret lakehouse_demo nvd_api_key --profile free-edition
   ```

   Without the key, the API limits anonymous callers to **5 requests / 30 s**;
   with the key, **50 / 30 s**.

### Running

After deploying as a notebook in the workspace, set the `mode` widget and run.
First run should be `mode=backfill`, `backfill_days=365`. Subsequent runs are
`mode=incremental` on a daily schedule.

### Rate-limit behavior

- Anonymous: 6.0 s sleep between requests (under 5/30s)
- With key: 0.7 s sleep between requests (under 50/30s)
- Retries on HTTP 429 and 503 with exponential backoff (5s → 10s → 20s → 40s → 80s)
