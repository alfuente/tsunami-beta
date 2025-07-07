package com.example.risk;

import org.apache.iceberg.catalog.rest.RESTCatalog;
import org.apache.iceberg.Table;
import org.apache.iceberg.catalog.Catalog;
import org.apache.iceberg.Schema;
import org.apache.iceberg.types.Types;

import java.util.HashMap;
import java.util.Map;

public class IcebergCatalogManager {
  private static Catalog catalog;

  public static void main(String[] args) throws Exception {
    if (args.length == 0) {
      System.err.println("Acciones: init|backup|drop");
      return;
    }
    connect();
    switch (args[0]) {
      case "init" -> initTables();
      case "backup" -> backup();
      case "drop" -> dropTables();
    }
  }

  private static void connect() {
    Map<String, String> props = new HashMap<>();
    props.put("uri", "http://localhost:8181");   // iceberg-rest
    props.put("warehouse", "s3://iceberg/warehouse");
    props.put("s3.endpoint", "http://localhost:9000");
    props.put("s3.access-key-id", "minio");
    props.put("s3.secret-access-key", "minio123");
    catalog = new RESTCatalog();
    catalog.initialize("risk", props);
  }

  private static void initTables() {
    Schema domainSchema = new Schema(
      Types.NestedField.optional(1, "fqdn", Types.StringType.get()),
      Types.NestedField.optional(2, "risk_score", Types.DoubleType.get()),
      Types.NestedField.optional(3, "scan_date", Types.TimestampType.withZone())
    );
    catalog.createTable(org.apache.iceberg.catalog.TableIdentifier.of("risk_db", "domains"), domainSchema);
    System.out.println("Tabla domains creada");
  }

  private static void backup() {
    // Con Iceberg basta con exportar el snapshot actual
    Table tbl = catalog.loadTable(org.apache.iceberg.catalog.TableIdentifier.of("risk_db", "domains"));
    System.out.println("Último snapshot: " + tbl.currentSnapshot().snapshotId());
  }

  private static void dropTables() {
    catalog.dropTable(org.apache.iceberg.catalog.TableIdentifier.of("risk_db", "domains"));
    System.out.println("Tablas Iceberg eliminadas");
  }
}
