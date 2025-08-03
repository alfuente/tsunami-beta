package com.example.risk;

import org.apache.spark.sql.*;
import static org.apache.spark.sql.functions.*;
import java.util.HashMap;

public class Neo4jToIcebergTransfer {

  public static void main(String[] args) {
    SparkSession spark = SparkSession.builder()
        .appName("neo4j-to-iceberg")
        .master("spark://spark:7077")         // usa el master del contenedor Spark
        .config("spark.sql.catalog.ice", "org.apache.iceberg.spark.SparkCatalog")
        .config("spark.sql.catalog.ice.catalog-impl", "org.apache.iceberg.rest.RESTCatalog")
        .config("spark.sql.catalog.ice.uri", "http://iceberg-rest:8181")
        .config("spark.sql.catalog.ice.warehouse", "s3://iceberg/warehouse")
        .config("spark.sql.defaultCatalog", "ice")
        .getOrCreate();

    HashMap<String,String> neo4jOpts = new HashMap<>();
    neo4jOpts.put("url", "bolt://neo4j:7687");
    neo4jOpts.put("authentication.type","basic");
    neo4jOpts.put("authentication.basic.username","neo4j");
    neo4jOpts.put("authentication.basic.password","test");
    neo4jOpts.put("labels","Domain");
    neo4jOpts.put("query","MATCH (d:Domain) RETURN d.fqdn AS fqdn, d.risk_score AS risk_score, datetime() AS scan_date");

    Dataset<Row> df = spark.read()
        .format("org.neo4j.spark.DataSource")
        .options(neo4jOpts)
        .load();

    df.write()
      .format("iceberg")
      .mode("append")
      .save("ice.risk_db.domains");

    spark.stop();
    System.out.println("Exportación completada");
  }
}
