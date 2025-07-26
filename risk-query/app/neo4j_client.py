import logging
from neo4j import GraphDatabase, time
from typing import Dict, List, Any, Optional
from datetime import datetime, date
import json

logger = logging.getLogger(__name__)

def serialize_neo4j_value(value):
    """Convert Neo4j values to JSON-serializable Python objects"""
    if hasattr(value, 'iso_format'):  # Neo4j DateTime
        return value.iso_format()
    elif hasattr(value, 'to_native'):  # Neo4j Date, Time
        native_value = value.to_native()
        if isinstance(native_value, (datetime, date)):
            return native_value.isoformat()
        return native_value
    elif isinstance(value, (datetime, date)):
        return value.isoformat()
    elif hasattr(value, '_properties'):  # Neo4j Node or Relationship
        result = dict(value._properties)
        # Recursively serialize properties
        for key, prop_value in result.items():
            result[key] = serialize_neo4j_value(prop_value)
        
        if hasattr(value, 'labels'):
            result['_labels'] = list(value.labels)
        if hasattr(value, 'type'):
            result['_type'] = value.type
        return result
    elif isinstance(value, (list, tuple)):
        return [serialize_neo4j_value(item) for item in value]
    elif isinstance(value, dict):
        return {key: serialize_neo4j_value(val) for key, val in value.items()}
    else:
        return value

class Neo4jClient:
    def __init__(self, uri: str, user: str, password: str, database: str = "neo4j"):
        self.uri = uri
        self.user = user
        self.password = password
        self.database = database
        self.driver = None
        self._connect()
    
    def _connect(self):
        """Initialize the Neo4j driver"""
        try:
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            logger.info(f"Connected to Neo4j at {self.uri}")
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            raise
    
    def close(self):
        """Close the Neo4j driver"""
        if self.driver:
            self.driver.close()
            logger.info("Neo4j connection closed")
    
    def test_connection(self) -> Dict[str, Any]:
        """Test the Neo4j connection"""
        try:
            with self.driver.session(database=self.database) as session:
                result = session.run("RETURN 'Connection successful' as message")
                record = result.single()
                return {"message": record["message"]}
        except Exception as e:
            logger.error(f"Neo4j connection test failed: {e}")
            raise
    
    def execute_query(self, cypher_query: str, parameters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Execute a Cypher query and return results"""
        try:
            with self.driver.session(database=self.database) as session:
                logger.info(f"Executing Cypher query: {cypher_query[:200]}...")
                
                result = session.run(cypher_query, parameters or {})
                records = []
                
                for record in result:
                    # Convert neo4j record to dictionary using our serialization function
                    record_dict = {}
                    for key in record.keys():
                        value = record[key]
                        record_dict[key] = serialize_neo4j_value(value)
                    
                    records.append(record_dict)
                
                logger.info(f"Query returned {len(records)} records")
                return records
                
        except Exception as e:
            logger.error(f"Query execution failed: {e}")
            raise
    
    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information from the database"""
        try:
            schema_info = {}
            
            with self.driver.session(database=self.database) as session:
                # Get node labels
                result = session.run("CALL db.labels()")
                labels = [record["label"] for record in result]
                schema_info["node_labels"] = labels
                
                # Get relationship types
                result = session.run("CALL db.relationshipTypes()")
                relationships = [record["relationshipType"] for record in result]
                schema_info["relationship_types"] = relationships
                
                # Get property keys
                result = session.run("CALL db.propertyKeys()")
                properties = [record["propertyKey"] for record in result]
                schema_info["property_keys"] = properties
                
                # Get sample nodes for each label (limited to understand structure)
                schema_info["sample_data"] = {}
                for label in labels[:5]:  # Limit to first 5 labels
                    try:
                        result = session.run(f"MATCH (n:`{label}`) RETURN n LIMIT 3")
                        samples = []
                        for record in result:
                            node = record["n"]
                            sample = serialize_neo4j_value(node)
                            samples.append(sample)
                        schema_info["sample_data"][label] = samples
                    except Exception as e:
                        logger.warning(f"Failed to get sample data for label {label}: {e}")
                        schema_info["sample_data"][label] = []
            
            return schema_info
            
        except Exception as e:
            logger.error(f"Failed to get schema info: {e}")
            raise
    
    def validate_cypher_query(self, cypher_query: str) -> Dict[str, Any]:
        """Validate a Cypher query without executing it"""
        try:
            with self.driver.session(database=self.database) as session:
                # Use EXPLAIN to validate the query structure
                explain_query = f"EXPLAIN {cypher_query}"
                result = session.run(explain_query)
                
                # If no exception is raised, the query is valid
                return {
                    "valid": True,
                    "message": "Query is syntactically valid"
                }
                
        except Exception as e:
            return {
                "valid": False,
                "message": f"Query validation failed: {str(e)}"
            }