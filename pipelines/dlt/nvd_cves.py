# Databricks notebook source
# MAGIC %md
# MAGIC # NVD CVE — Bronze + Silver DLT Pipeline
# MAGIC
# MAGIC Reads JSON files from the `bronze.nvd_landing` volume and produces:
# MAGIC
# MAGIC | Layer | Table | Shape |
# MAGIC |---|---|---|
# MAGIC | Bronze | `lakehouse_demo.bronze.nvd_cves_raw` | one row per API page (raw NVD payload + ingest metadata) |
# MAGIC | Silver | `lakehouse_demo.silver.cves` | one row per CVE, latest by `modified_at` (SCD Type 1 via `apply_changes`) |
# MAGIC
# MAGIC Auto Loader handles file discovery; `_tmp/` is excluded by `pathGlobFilter`.
# MAGIC
# MAGIC ## Why a streaming view between bronze and silver?
# MAGIC
# MAGIC `cves_exploded` is a streaming view (not a persisted table) that does the
# MAGIC bronze→silver transformation: explode the `vulnerabilities` array, flatten the
# MAGIC fields we care about, drop bad rows. `apply_changes` then deduplicates on
# MAGIC `cve_id`, keeping the latest by `modified_at`. We don't persist the exploded
# MAGIC step — it's just a transformation, not a stable contract.

# COMMAND ----------
# DBTITLE 1,Imports
import dlt
from pyspark.sql import functions as F

LANDING_PATH = "/Volumes/lakehouse_demo/bronze/nvd_landing/"

# COMMAND ----------
# DBTITLE 1,Bronze — raw NVD pages from the landing volume
@dlt.table(
    name="bronze.nvd_cves_raw",
    comment="Raw NVD CVE pages from the downloader; one row per API response page.",
    table_properties={
        "quality": "bronze",
        "delta.autoOptimize.optimizeWrite": "true",
    },
)
def nvd_cves_raw():
    return (
        spark.readStream
        .format("cloudFiles")
        .option("cloudFiles.format", "json")
        .option("multiLine", "true")
        .option("pathGlobFilter", "cves_*.json")
        .option("cloudFiles.includeExistingFiles", "true")
        .option("cloudFiles.inferColumnTypes", "true")
        .option("cloudFiles.schemaEvolutionMode", "addNewColumns")
        .load(LANDING_PATH)
        .withColumn("_ingest_ts", F.current_timestamp())
        .withColumn("_ingest_file", F.col("_metadata.file_path"))
    )

# COMMAND ----------
# DBTITLE 1,Streaming view — explode + flatten + quality-check
@dlt.view(
    name="cves_exploded",
    comment="One row per CVE per occurrence; pre-dedup. Drops rows missing required fields.",
)
@dlt.expect_all_or_drop({
    "valid_cve_id":      "cve_id IS NOT NULL",
    "valid_published":   "published_at IS NOT NULL",
    "valid_modified":    "modified_at IS NOT NULL",
})
def cves_exploded():
    raw = dlt.read_stream("nvd_cves_raw")

    # Step 1: explode the vulnerabilities array; carry ingestion metadata forward
    flat = raw.select(
        F.explode("vulnerabilities").alias("v"),
        "_ingest_ts",
        "_ingest_file",
    )

    # Step 2: project the fields we care about
    return flat.select(
        F.col("v.cve.id").alias("cve_id"),
        F.to_timestamp(F.col("v.cve.published")).alias("published_at"),
        F.to_timestamp(F.col("v.cve.lastModified")).alias("modified_at"),
        F.col("v.cve.vulnStatus").alias("vuln_status"),
        F.col("v.cve.sourceIdentifier").alias("source_identifier"),

        # English description (first match in the descriptions array)
        F.expr(
            "filter(v.cve.descriptions, x -> x.lang = 'en')[0].value"
        ).alias("description_en"),

        # CVSS v3.1 (preferred when available)
        F.col("v.cve.metrics.cvssMetricV31")[0]["cvssData"]["baseScore"].cast("double").alias("cvss_v31_score"),
        F.col("v.cve.metrics.cvssMetricV31")[0]["cvssData"]["baseSeverity"].alias("cvss_v31_severity"),
        F.col("v.cve.metrics.cvssMetricV31")[0]["cvssData"]["vectorString"].alias("cvss_v31_vector"),

        # CVSS v3.0 fallback
        F.col("v.cve.metrics.cvssMetricV30")[0]["cvssData"]["baseScore"].cast("double").alias("cvss_v30_score"),
        F.col("v.cve.metrics.cvssMetricV30")[0]["cvssData"]["baseSeverity"].alias("cvss_v30_severity"),

        # CVSS v2 fallback (older CVEs without v3 scores; severity lives at a different path)
        F.col("v.cve.metrics.cvssMetricV2")[0]["cvssData"]["baseScore"].cast("double").alias("cvss_v2_score"),
        F.col("v.cve.metrics.cvssMetricV2")[0]["baseSeverity"].alias("cvss_v2_severity"),

        # CWE IDs — extract en-language values from the nested weaknesses array, dedup
        F.expr(
            "array_distinct(transform(v.cve.weaknesses, w -> filter(w.description, d -> d.lang = 'en')[0].value))"
        ).alias("cwe_ids"),

        # Reference URLs — flat array
        F.expr(
            "transform(v.cve.references, r -> r.url)"
        ).alias("reference_urls"),

        "_ingest_ts",
        "_ingest_file",
    )

# COMMAND ----------
# DBTITLE 1,Silver — cves (one row per CVE, latest version wins)
dlt.create_streaming_table(
    name="silver.cves",
    comment=(
        "Normalized CVEs; one row per cve_id, latest version by modified_at. "
        "Sourced from cves_exploded via apply_changes (SCD Type 1)."
    ),
    table_properties={
        "quality": "silver",
        "delta.autoOptimize.optimizeWrite": "true",
    },
)

dlt.apply_changes(
    target="silver.cves",
    source="cves_exploded",
    keys=["cve_id"],
    sequence_by=F.col("modified_at"),
    stored_as_scd_type=1,
)
