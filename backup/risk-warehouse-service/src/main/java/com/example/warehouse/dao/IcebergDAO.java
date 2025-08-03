package com.example.warehouse.dao;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import org.apache.iceberg.catalog.TableIdentifier;
import org.apache.iceberg.catalog.rest.RESTCatalog;
import org.apache.iceberg.catalog.*;
import org.apache.iceberg.Schema;
import org.apache.iceberg.types.Types;
import org.neo4j.driver.*;

import java.time.LocalDate;
import java.util.*;

@ApplicationScoped
public class IcebergDAO {

    private Catalog catalog;

    @PostConstruct
    void init() {
        Map<String,String> props = Map.of(
                "uri", System.getProperty("iceberg.uri","http://localhost:8181"),
                "warehouse", System.getProperty("iceberg.warehouse","s3://iceberg/warehouse"),
                "s3.endpoint", System.getProperty("iceberg.s3.endpoint","http://localhost:9000"),
                "s3.access-key-id", System.getProperty("iceberg.s3.access-key","minio"),
                "s3.secret-access-key", System.getProperty("iceberg.s3.secret-key","minio123")
        );
        catalog = new RESTCatalog();
        catalog.initialize("risk", props);
    }

    // Very simplified: just inserts a tiny record saying snapshot done
    public void snapshotDomain(String fqdn){
        TableIdentifier tid = TableIdentifier.of("risk_db","snapshots");
        if (!catalog.tableExists(tid)){
            Schema sch = new Schema(
                    Types.NestedField.optional(1,"fqdn",Types.StringType.get()),
                    Types.NestedField.optional(2,"snapshot_date",Types.StringType.get())
            );
            catalog.createTable(tid, sch);
        }
        Table tbl = catalog.loadTable(tid);
        Map<String,Object> rec = Map.of("fqdn", fqdn,
                                        "snapshot_date", LocalDate.now().toString());
        tbl.newAppend().appendFile(
                org.apache.iceberg.data.GenericAppenderFactory.get()
        );
        // For brevity we don't implement full write; placeholder.
    }
}
