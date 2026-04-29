# Databricks notebook source
# MAGIC %md
# MAGIC # NVD CVE Downloader
# MAGIC
# MAGIC Pulls vulnerability data from NIST NVD's public API and lands JSON files in
# MAGIC `/Volumes/lakehouse_demo/bronze/nvd_landing/`. Auto Loader downstream picks up
# MAGIC new files and writes to the bronze table.
# MAGIC
# MAGIC ## Modes
# MAGIC - **`backfill`** — pulls the last `backfill_days` days, chunked by NVD's 120-day
# MAGIC   max date range. Run once to seed the dataset.
# MAGIC - **`incremental`** — pulls CVEs modified in the last `incremental_hours` hours.
# MAGIC   Schedule daily.
# MAGIC
# MAGIC Re-running is safe: file names include the run timestamp, so existing files are
# MAGIC never overwritten. Auto Loader is content-addressed by path, so duplicate
# MAGIC payloads from re-runs will be ingested again at bronze and deduplicated at silver.
# MAGIC
# MAGIC ## API key
# MAGIC Reads from Databricks secret `lakehouse_demo/nvd_api_key`. If absent, falls back
# MAGIC to anonymous access (rate-limited to 5 req / 30 s; expect slow backfills).

# COMMAND ----------
# DBTITLE 1,Imports
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone

import requests

# COMMAND ----------
# DBTITLE 1,Widgets & constants
dbutils.widgets.dropdown("mode", "backfill", ["backfill", "incremental"], "Run mode")
dbutils.widgets.text("backfill_days", "365", "Backfill window (days)")
dbutils.widgets.text("incremental_hours", "24", "Incremental window (hours)")

MODE = dbutils.widgets.get("mode")
BACKFILL_DAYS = int(dbutils.widgets.get("backfill_days"))
INCREMENTAL_HOURS = int(dbutils.widgets.get("incremental_hours"))

LANDING_VOLUME = "/Volumes/lakehouse_demo/bronze/nvd_landing"
TMP_DIR = f"{LANDING_VOLUME}/_tmp"
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000          # NVD max
NVD_MAX_RANGE_DAYS = 120         # NVD constraint on lastModStartDate/lastModEndDate
SECRET_SCOPE = "lakehouse_demo"
SECRET_KEY = "nvd_api_key"
MAX_RETRIES = 5

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("nvd_downloader")

# COMMAND ----------
# DBTITLE 1,Resolve API key from Databricks secret
def get_api_key():
    try:
        return dbutils.secrets.get(scope=SECRET_SCOPE, key=SECRET_KEY)
    except Exception:
        log.warning(
            f"No secret at {SECRET_SCOPE}/{SECRET_KEY}; using anonymous access "
            f"(rate-limited; backfills will be slow)."
        )
        return None


API_KEY = get_api_key()
REQUEST_DELAY = 0.7 if API_KEY else 6.0   # rate-limit-friendly: 50/30s vs 5/30s
log.info(f"API key configured: {bool(API_KEY)}; per-request delay: {REQUEST_DELAY}s")

# COMMAND ----------
# DBTITLE 1,Plan the date window and split into <=120-day chunks
def iso_z(dt):
    """ISO 8601 with millisecond precision, NVD-friendly."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def plan_chunks(start, end, max_days):
    chunks = []
    current = start
    while current < end:
        chunk_end = min(current + timedelta(days=max_days), end)
        chunks.append((current, chunk_end))
        current = chunk_end
    return chunks


now = datetime.now(timezone.utc)
if MODE == "backfill":
    window_start = now - timedelta(days=BACKFILL_DAYS)
    window_end = now
elif MODE == "incremental":
    window_start = now - timedelta(hours=INCREMENTAL_HOURS)
    window_end = now
else:
    raise ValueError(f"unknown mode: {MODE}")

CHUNKS = plan_chunks(window_start, window_end, NVD_MAX_RANGE_DAYS)
log.info(
    f"Mode: {MODE}; window {iso_z(window_start)} → {iso_z(window_end)}; "
    f"planned {len(CHUNKS)} chunk(s)"
)

# COMMAND ----------
# DBTITLE 1,Fetch with retry / backoff
def fetch_page(start, end, start_index):
    """
    One paginated NVD API call. Retries with exponential backoff on:
      - connection-level errors (ChunkedEncodingError, ConnectionError, Timeout, ...)
      - HTTP 429 / 503 (rate-limit / unavailable)
      - JSON decode errors (truncated body)

    Other 4xx/5xx responses fail fast (auth/path issues are not retryable).
    """
    params = {
        "lastModStartDate": iso_z(start),
        "lastModEndDate": iso_z(end),
        "resultsPerPage": RESULTS_PER_PAGE,
        "startIndex": start_index,
    }
    headers = {"apiKey": API_KEY} if API_KEY else {}

    backoff = 5
    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = requests.get(NVD_BASE_URL, params=params, headers=headers, timeout=60)
        except requests.exceptions.RequestException as e:
            last_err = e
            log.warning(
                f"NVD connection error (attempt {attempt}/{MAX_RETRIES}): "
                f"{type(e).__name__}: {e}; sleeping {backoff}s"
            )
            time.sleep(backoff)
            backoff *= 2
            continue

        if r.status_code == 200:
            try:
                return r.json()
            except (json.JSONDecodeError, requests.exceptions.JSONDecodeError) as e:
                last_err = e
                log.warning(
                    f"NVD response parse error (attempt {attempt}/{MAX_RETRIES}): "
                    f"{e}; sleeping {backoff}s"
                )
                time.sleep(backoff)
                backoff *= 2
                continue

        if r.status_code in (429, 503):
            log.warning(f"NVD {r.status_code} (attempt {attempt}/{MAX_RETRIES}); sleeping {backoff}s")
            time.sleep(backoff)
            backoff *= 2
            continue

        # Other 4xx/5xx: fail fast
        r.raise_for_status()
    raise RuntimeError(f"NVD fetch failed after {MAX_RETRIES} attempts: {last_err}")

# COMMAND ----------
# DBTITLE 1,Atomic write to landing volume (tmp + rename)
os.makedirs(TMP_DIR, exist_ok=True)


def write_page(payload, chunk_start, chunk_end, page_index, run_ts):
    fname = (
        f"cves_{chunk_start.strftime('%Y%m%d')}_"
        f"{chunk_end.strftime('%Y%m%d')}_"
        f"p{page_index:03d}_{run_ts}.json"
    )
    final_path = f"{LANDING_VOLUME}/{fname}"
    tmp_path = f"{TMP_DIR}/{fname}"
    with open(tmp_path, "w") as f:
        json.dump(payload, f)
    os.rename(tmp_path, final_path)
    return final_path

# COMMAND ----------
# DBTITLE 1,Main loop
run_ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
total_files = 0
total_records = 0

for chunk_idx, (chunk_start, chunk_end) in enumerate(CHUNKS, start=1):
    log.info(f"Chunk {chunk_idx}/{len(CHUNKS)}: {iso_z(chunk_start)} → {iso_z(chunk_end)}")

    page_index = 0
    while True:
        payload = fetch_page(chunk_start, chunk_end, page_index * RESULTS_PER_PAGE)
        total = payload.get("totalResults", 0)
        records = len(payload.get("vulnerabilities", []))

        if records == 0:
            log.info(f"  page {page_index}: empty (totalResults={total})")
            break

        path = write_page(payload, chunk_start, chunk_end, page_index, run_ts)
        log.info(f"  page {page_index}: {records} records → {path}")
        total_files += 1
        total_records += records

        if (page_index + 1) * RESULTS_PER_PAGE >= total:
            break
        page_index += 1
        time.sleep(REQUEST_DELAY)

log.info(f"Done. Files written: {total_files}; records ingested: {total_records}")

# COMMAND ----------
# DBTITLE 1,Summary — recent files in the landing volume
files = [f for f in dbutils.fs.ls(LANDING_VOLUME) if f.name.startswith("cves_")]
recent = sorted(files, key=lambda f: f.modificationTime, reverse=True)[:20]
print(f"Volume contents: {len(files)} cve_*.json files. Most recent {len(recent)}:")
for f in recent:
    print(f"  {f.size / 1024:>10,.1f} KB   {f.name}")
