#!/usr/bin/env python3
""" full_graph_model_to_iceberg.py
Exporta TODO el grafo Neo4j al esquema tabular Iceberg alineado con el modelo de riesgos.

Requisitos:
  pip install neo4j pyspark==3.5.1 pandas pyarrow iceberg-rest-client boto3
"""

from __future__ import annotations
import argparse, datetime, math, os
from typing import List, Dict
import pandas as pd
from neo4j import GraphDatabase
from pyspark.sql import SparkSession, Row
from pyspark.sql.functions import lit

SNAPSHOT = datetime.date.today().isoformat()
BATCH = 20000

# -- Definición de tablas ----------------------------------------
NODE_TABLES: Dict[str, Dict[str, str]] = {
    # label -> cypher (id, props) & columns
    "organizations": {
        "cypher": """MATCH (n:Organization)
                      RETURN id(n) AS neo_id, n.id AS id, n.name AS name,
                             n.type AS type, n.industry AS industry,
                             n.country AS country, n.risk_score AS risk_score,
                             n.risk_tier AS risk_tier""",
        "columns": ["neo_id","id","name","type","industry","country","risk_score","risk_tier"]
    },
    "domains": {
        "cypher": """MATCH (n:Domain)
                      RETURN id(n) AS neo_id, n.fqdn AS fqdn, n.tld AS tld,
                             n.dns_sec_enabled AS dns_sec_enabled,
                             n.registered_date AS registered_date,
                             n.expiry_date AS expiry_date,
                             n.status AS status, n.risk_score AS risk_score,
                             n.business_criticality AS business_criticality""",
        "columns": ["neo_id","fqdn","tld","dns_sec_enabled","registered_date",
                    "expiry_date","status","risk_score","business_criticality"]
    },
    "providers": {
        "cypher": """MATCH (p:Provider)
                      RETURN id(p) AS neo_id, p.id AS id, p.name AS name,
                             p.type AS type, p.tier AS tier,
                             p.country AS country,
                             p.market_share AS market_share,
                             p.security_rating AS security_rating,
                             p.concentration_risk AS concentration_risk,
                             p.criticality_score AS criticality_score""",
        "columns": ["neo_id","id","name","type","tier","country","market_share",
                    "security_rating","concentration_risk","criticality_score"]
    },
    "services": {
        "cypher": """MATCH (s:Service)
                      RETURN id(s) AS neo_id, s.id AS id, s.name AS name,
                             s.type AS type, s.category AS category,
                             s.provider_name AS provider_name,
                             s.sla_availability AS sla_availability,
                             s.vendor_lock_in_score AS vendor_lock_in_score,
                             s.risk_score AS risk_score""",
        "columns": ["neo_id","id","name","type","category","provider_name",
                    "sla_availability","vendor_lock_in_score","risk_score"]
    },
    "certificates": {
        "cypher": """MATCH (c:Certificate)
                      RETURN id(c) AS neo_id, c.serial_number AS serial_number,
                             c.issuer_cn AS issuer_cn, c.valid_from AS valid_from,
                             c.valid_to AS valid_to, c.algorithm AS algorithm,
                             c.key_size AS key_size""",
        "columns": ["neo_id","serial_number","issuer_cn","valid_from",
                    "valid_to","algorithm","key_size"]
    },
    "ips": {
        "cypher": """MATCH (i:IP)
                      RETURN id(i) AS neo_id, i.ip AS ip,
                             i.asn AS asn, i.provider_name AS provider_name""",
        "columns": ["neo_id","ip","asn","provider_name"]
    },
    "asns": {
        "cypher": """MATCH (a:ASN)
                      RETURN id(a) AS neo_id, a.asn AS asn, 
                             a.org_name AS org_name""",
        "columns": ["neo_id","asn","org_name"]
    },
    "netblocks": {
        "cypher": """MATCH (n:Netblock)
                      RETURN id(n) AS neo_id, n.cidr AS cidr""",
        "columns": ["neo_id","cidr"]
    },
    "incidents": {
        "cypher": """MATCH (i:Incident)
                      RETURN id(i) AS neo_id, i.id AS id, i.title AS title,
                             i.category AS category, i.severity AS severity,
                             i.detected AS detected, i.resolved AS resolved""",
        "columns": ["neo_id","id","title","category","severity","detected","resolved"]
    }
}

REL_TABLES: Dict[str, Dict[str, str]] = {
    "rel_depends_on": {
        "cypher": """MATCH (d:Domain)-[r:DEPENDS_ON]->(s:Service)
                      RETURN id(r) AS neo_id, id(d) AS start_id, id(s) AS end_id,
                             r.dependency_type AS dependency_type,
                             r.service_level AS service_level,
                             r.priority AS priority,
                             r.failover_exists AS failover_exists""",
        "columns": ["neo_id","start_id","end_id","dependency_type","service_level",
                    "priority","failover_exists"]
    },
    "rel_announces": {
        "cypher": """MATCH (a:ASN)-[r:ANNOUNCES]->(n:Netblock)
                      RETURN id(r) AS neo_id, id(a) AS start_id, id(n) AS end_id""",
        "columns": ["neo_id","start_id","end_id"]
    },
    "rel_contains": {
        "cypher": """MATCH (n:Netblock)-[r:CONTAINS]->(i:IP)
                      RETURN id(r) AS neo_id, id(n) AS start_id, id(i) AS end_id""",
        "columns": ["neo_id","start_id","end_id"]
    },
    "rel_affects": {
        "cypher": """MATCH (inc:Incident)-[r:AFFECTS]->(n)
                      RETURN id(r) AS neo_id, id(inc) AS start_id, id(n) AS end_id""",
        "columns": ["neo_id","start_id","end_id"]
    },
    "rel_secured_by": {
        "cypher": """MATCH (d:Domain)-[r:SECURED_BY]->(c:Certificate)
                      RETURN id(r) AS neo_id, id(d) AS start_id, id(c) AS end_id""",
        "columns": ["neo_id","start_id","end_id"]
    },
    "rel_resolves_to": {
        "cypher": """MATCH (d:Domain)-[r:RESOLVES_TO]->(ip:IP)
                      RETURN id(r) AS neo_id, id(d) AS start_id, id(ip) AS end_id""",
        "columns": ["neo_id","start_id","end_id"]
    },
    "rel_has_subdomain": {
        "cypher": """MATCH (p:Domain)-[r:HAS_SUBDOMAIN]->(c:Domain)
                      RETURN id(r) AS neo_id, id(p) AS start_id, id(c) AS end_id""",
        "columns": ["neo_id","start_id","end_id"]
    },
    "rel_cname_to": {
        "cypher": """MATCH (a:Domain)-[r:CNAME_TO]->(t:Domain)
                      RETURN id(r) AS neo_id, id(a) AS start_id, id(t) AS end_id""",
        "columns": ["neo_id","start_id","end_id"]
    }
}

# -------------------------------------------------------------------
def spark_session(args) -> SparkSession:
    return (SparkSession.builder
            .appName("graph-model-snapshot")
            .config("spark.jars.packages", "org.apache.iceberg:iceberg-spark-runtime-3.5_2.12:1.4.2,org.apache.iceberg:iceberg-aws-bundle:1.4.2")
            .config("spark.sql.extensions",
                    "org.apache.iceberg.spark.extensions.IcebergSparkSessionExtensions")
            .config("spark.sql.catalog.ice", "org.apache.iceberg.spark.SparkCatalog")
            .config("spark.sql.catalog.ice.catalog-impl", "org.apache.iceberg.rest.RESTCatalog")
            .config("spark.sql.catalog.ice.uri", args.iceberg_uri)
            .config("spark.sql.catalog.ice.warehouse", args.warehouse)
            .config("spark.sql.catalog.ice.io-impl", "org.apache.iceberg.aws.s3.S3FileIO")
            .config("spark.hadoop.fs.s3a.endpoint", args.s3_endpoint)
            .config("spark.hadoop.fs.s3a.access.key", args.s3_key)
            .config("spark.hadoop.fs.s3a.secret.key", args.s3_secret)
            .config("spark.hadoop.fs.s3a.path.style.access", "true")
            .master("local[*]").getOrCreate())

def ensure_table(spark: SparkSession, name: str, cols: List[str]):
    cols_ddl = ", ".join(f"{c} STRING" for c in cols) + ", snapshot_date STRING"
    spark.sql(f"""CREATE TABLE IF NOT EXISTS ice.risk_db.{name}
                     ({cols_ddl}) USING iceberg
                     PARTITIONED BY (snapshot_date)""")

def fetch_batches(driver, cypher: str, cols: List[str]):
    total = driver.session().run(f"CALL {{ {cypher} }} RETURN count(*) AS c").single()[0]
    for skip in range(0, total, BATCH):
        q = f"{cypher} SKIP {skip} LIMIT {BATCH}"
        for rec in driver.session().run(q):
            yield Row(**{c: rec.get(c) for c in cols})

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bolt', default='bolt://localhost:7687')
    ap.add_argument('--user', default='neo4j')
    ap.add_argument('--password', default='test')
    ap.add_argument('--iceberg-uri', required=True)
    ap.add_argument('--warehouse', required=True)
    ap.add_argument('--s3-endpoint', required=True)
    ap.add_argument('--s3-key', required=True)
    ap.add_argument('--s3-secret', required=True)
    args = ap.parse_args()

    spark = spark_session(args)
    driver = GraphDatabase.driver(args.bolt, auth=(args.user,args.password))

    try:
        for tbl, meta in {**NODE_TABLES, **REL_TABLES}.items():
            ensure_table(spark, tbl, meta['columns'])
            rows = list(fetch_batches(driver, meta['cypher'], meta['columns']))
            if not rows: continue
            df = spark.createDataFrame(rows).withColumn('snapshot_date', lit(SNAPSHOT))
            df.writeTo(f'ice.risk_db.{tbl}').append()
            print(f"{tbl}: {df.count()} filas")
    finally:
        spark.stop(); driver.close()
        print('Snapshot completo', SNAPSHOT)

if __name__ == '__main__':
    main()
