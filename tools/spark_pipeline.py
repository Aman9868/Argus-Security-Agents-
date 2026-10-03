"""
Argus Cyber Agent — Apache PySpark Distributed Feature Pipeline
Processes massive real PE telemetry datasets, normalizes feature vectors,
and supports distributed training & batch inference.
"""

import os
import sys
os.environ["SPARK_LOCAL_IP"] = "127.0.0.1"
from typing import Tuple, Optional
import structlog

logger = structlog.get_logger("argus.tools.spark_pipeline")

FEATURE_COLS = [
    "file_size",
    "overall_entropy",
    "num_sections",
    "mean_section_entropy",
    "max_section_entropy",
    "min_section_entropy",
    "num_suspicious_sections",
    "num_imported_dlls",
    "num_imported_functions",
    "num_suspicious_apis",
    "api_density",
    "injection_api_count",
    "anti_debug_api_count",
    "persistence_api_count",
    "networking_api_count",
    "crypto_api_count",
    "has_debug_stripped",
    "has_tls",
    "has_relocations",
    "is_packed_heuristic",
    "entrypoint_section_entropy",
]


def get_spark_session(app_name: str = "Argus-Malware-Feature-Pipeline"):
    """Initializes and returns a configured local Apache Spark Session."""
    import os
    os.environ["SPARK_LOCAL_IP"] = "127.0.0.1"
    from pyspark.sql import SparkSession
    return SparkSession.builder \
        .appName(app_name) \
        .master("local[*]") \
        .config("spark.driver.host", "127.0.0.1") \
        .config("spark.driver.bindAddress", "127.0.0.1") \
        .config("spark.driver.memory", "4g") \
        .config("spark.sql.execution.arrow.pyspark.enabled", "true") \
        .config("spark.ui.enabled", "false") \
        .getOrCreate()


def run_spark_feature_etl(input_parquet_path: str, output_parquet_path: str) -> str:
    """
    Reads the raw real PE dataset via PySpark, applies transformations
    (VectorAssembler, Scaler), and exports partition-optimized parquet tables.
    """
    spark = get_spark_session()
    logger.info("spark_etl_started", input=input_parquet_path)

    # 1. Read dataset
    df = spark.read.parquet(input_parquet_path)
    total_count = df.count()
    logger.info("spark_dataset_loaded", total_rows=total_count)

    from pyspark.ml.feature import VectorAssembler, StandardScaler
    from pyspark.sql.functions import col

    # Ensure numerical types
    for c in FEATURE_COLS:
        df = df.withColumn(c, col(c).cast("double"))
    df = df.withColumn("is_malware", col("is_malware").cast("integer"))

    # 2. Vector Assembly
    assembler = VectorAssembler(inputCols=FEATURE_COLS, outputCol="raw_features")
    assembled_df = assembler.transform(df)

    # 3. Standard Scaling
    scaler = StandardScaler(inputCol="raw_features", outputCol="scaled_features", withStd=True, withMean=True)
    scaler_model = scaler.fit(assembled_df)
    scaled_df = scaler_model.transform(assembled_df)

    # 4. Save normalized dataset
    os.makedirs(os.path.dirname(output_parquet_path), exist_ok=True)
    scaled_df.write.mode("overwrite").parquet(output_parquet_path)
    logger.info("spark_etl_complete", output=output_parquet_path)
    print(f"[+] PySpark ETL Complete: {total_count} rows processed and saved to {output_parquet_path}")

    return output_parquet_path


if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    in_path = os.path.join(base_dir, "data", "malware_dataset", "malware_features_real.parquet")
    out_path = os.path.join(base_dir, "data", "malware_dataset", "malware_features_spark_processed.parquet")
    run_spark_feature_etl(in_path, out_path)
