# Databricks notebook source
# MAGIC %md
# MAGIC # NVD CVE — Gold Aggregations
# MAGIC
# MAGIC Materialized views built from `cves` (silver) for dashboard consumption.
# MAGIC Each table answers one question; each is denormalized for fast reads.
# MAGIC
# MAGIC | Table | Question | Widget |
# MAGIC |---|---|---|
# MAGIC | `cve_severity_daily` | How many new CVEs were published each day, by severity? | trend chart |
# MAGIC | `cve_recent_critical` | What CRITICAL CVEs landed in the last 90 days? | top-of-news table |
# MAGIC | `cve_cwe_top` | Which CWE categories have the most CVEs? | ranked bar chart |
# MAGIC
# MAGIC ## Why batch (not streaming) at gold?
# MAGIC
# MAGIC Gold here is **aggregations**, not narrow filters/projections. Aggregations
# MAGIC over the full silver table are simplest as full recomputes (`dlt.read`,
# MAGIC not `dlt.read_stream`). DLT handles this as a materialized view:
# MAGIC recomputed each pipeline run, but the table itself is just a Delta table
# MAGIC the dashboard can query. Streaming gold (with stateful aggregation) is an
# MAGIC option for low-latency dashboards; for a triggered pipeline like this one,
# MAGIC batch is the right call.

# COMMAND ----------
# DBTITLE 1,Imports
import dlt
from pyspark.sql import functions as F

# COMMAND ----------
# DBTITLE 1,gold.cve_severity_daily — daily new-CVE count by severity
@dlt.table(
    name="cve_severity_daily",
    comment="Count of CVEs published per day, bucketed by severity (CVSS v3.1 → v3.0 → v2 → UNKNOWN).",
    table_properties={"quality": "gold"},
)
def cve_severity_daily():
    severity = F.coalesce(
        F.col("cvss_v31_severity"),
        F.col("cvss_v30_severity"),
        F.col("cvss_v2_severity"),
        F.lit("UNKNOWN"),
    )
    return (
        dlt.read("cves")
        .withColumn("severity", severity)
        .withColumn("day", F.to_date("published_at"))
        .groupBy("day", "severity")
        .agg(F.count("*").alias("cve_count"))
        .orderBy(F.col("day").desc(), "severity")
    )

# COMMAND ----------
# DBTITLE 1,gold.cve_recent_critical — denormalized CRITICAL CVEs from last 90 days
@dlt.table(
    name="cve_recent_critical",
    comment="CRITICAL-severity CVEs published in the last 90 days. Denormalized for dashboard.",
    table_properties={"quality": "gold"},
)
def cve_recent_critical():
    severity_any = F.coalesce(
        F.col("cvss_v31_severity"),
        F.col("cvss_v30_severity"),
        F.col("cvss_v2_severity"),
    )
    score_any = F.coalesce(
        F.col("cvss_v31_score"),
        F.col("cvss_v30_score"),
        F.col("cvss_v2_score"),
    )
    return (
        dlt.read("cves")
        .filter(severity_any == "CRITICAL")
        .filter(F.col("published_at") >= F.date_sub(F.current_date(), 90))
        .select(
            "cve_id",
            "published_at",
            "modified_at",
            score_any.alias("cvss_score"),
            severity_any.alias("cvss_severity"),
            F.col("cvss_v31_vector").alias("cvss_vector"),
            F.substring("description_en", 0, 280).alias("description_short"),
            "cwe_ids",
            F.size("reference_urls").alias("reference_count"),
            "vuln_status",
        )
        .orderBy(F.col("published_at").desc(), F.col("cvss_score").desc())
    )

# COMMAND ----------
# DBTITLE 1,gold.cve_cwe_top — CWE categories ranked by CVE count
@dlt.table(
    name="cve_cwe_top",
    comment="CWE categories ranked by number of CVEs. Filters out non-CWE entries (NVD-CWE-noinfo etc.).",
    table_properties={"quality": "gold"},
)
def cve_cwe_top():
    return (
        dlt.read("cves")
        .select(F.explode("cwe_ids").alias("cwe_id"))
        .filter(F.col("cwe_id").rlike(r"^CWE-\d+$"))
        .groupBy("cwe_id")
        .agg(F.count("*").alias("cve_count"))
        .orderBy(F.col("cve_count").desc())
    )
