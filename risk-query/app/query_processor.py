import logging
from typing import Dict, List, Any, Optional
from neo4j_client import Neo4jClient
from ollama_client import OllamaClient

logger = logging.getLogger(__name__)

class QueryProcessor:
    def __init__(self, neo4j_client: Neo4jClient, ollama_client: OllamaClient):
        self.neo4j_client = neo4j_client
        self.ollama_client = ollama_client
        self._schema_cache = None
    
    async def get_schema_info(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Get cached schema information or refresh it"""
        if self._schema_cache is None or force_refresh:
            try:
                logger.info("Fetching Neo4j schema information...")
                self._schema_cache = self.neo4j_client.get_schema_info()
                logger.info("Schema information cached successfully")
            except Exception as e:
                logger.error(f"Failed to get schema info: {e}")
                # Return basic schema as fallback
                self._schema_cache = {
                    "node_labels": ["Domain", "BaseDomain", "ThirdPartyProvider", "Incident", "Assessment"],
                    "relationship_types": ["DEPENDS_ON", "HAS_SUBDOMAIN", "USES_PROVIDER", "HAS_INCIDENT", "HAS_ASSESSMENT"],
                    "property_keys": ["fqdn", "risk_score", "risk_tier", "business_criticality", "monitoring_enabled"],
                    "sample_data": {}
                }
        
        return self._schema_cache
    
    async def process_query(self, query: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Process a natural language query and return interpreted results"""
        try:
            logger.info(f"Processing query: {query[:100]}...")
            
            # Get schema information
            schema_info = await self.get_schema_info()
            
            # Convert natural language to Cypher
            logger.info("Converting natural language to Cypher...")
            cypher_query = await self.ollama_client.convert_natural_language_to_cypher(
                query, schema_info
            )
            
            # Validate the generated Cypher query
            validation_result = self.neo4j_client.validate_cypher_query(cypher_query)
            if not validation_result["valid"]:
                logger.warning(f"Generated Cypher query is invalid: {validation_result['message']}")
                # Try to fix common issues or return error
                raise Exception(f"Generated query is invalid: {validation_result['message']}")
            
            # Execute the Cypher query
            logger.info("Executing Cypher query...")
            raw_results = self.neo4j_client.execute_query(cypher_query)
            
            # Interpret the results using Ollama
            logger.info("Interpreting query results...")
            interpretation = await self.ollama_client.interpret_cypher_results(
                query, cypher_query, raw_results
            )
            
            # Prepare the response
            response = {
                "response": interpretation,
                "cypher_query": cypher_query,
                "raw_results": {
                    "count": len(raw_results),
                    "data": raw_results[:10] if len(raw_results) > 10 else raw_results  # Limit to first 10 for UI
                },
                "metadata": {
                    "query_length": len(query),
                    "results_count": len(raw_results),
                    "execution_successful": True,
                    "schema_version": "1.0"
                }
            }
            
            logger.info(f"Query processed successfully, returned {len(raw_results)} results")
            return response
            
        except Exception as e:
            logger.error(f"Query processing failed: {e}")
            
            # Return error response
            return {
                "response": f"Sorry, I couldn't process your query. Error: {str(e)}",
                "cypher_query": None,
                "raw_results": None,
                "metadata": {
                    "query_length": len(query),
                    "results_count": 0,
                    "execution_successful": False,
                    "error": str(e)
                }
            }
    
    async def get_example_queries(self) -> List[Dict[str, str]]:
        """Get a list of example queries for the UI"""
        return [
            {
                "query": "Show me all domains with high risk scores",
                "description": "Find domains that have been classified as high risk"
            },
            {
                "query": "Which domains have the most dependencies?",
                "description": "Identify domains with the highest number of dependencies"
            },
            {
                "query": "Find domains with critical security vulnerabilities",
                "description": "Show domains that have critical CVEs or security issues"
            },
            {
                "query": "What are the third-party providers for financial services domains?",
                "description": "List external providers used by financial industry domains"
            },
            {
                "query": "Show me domains that haven't been assessed recently",
                "description": "Find domains with outdated security assessments"
            },
            {
                "query": "Which base domains have the highest average risk scores?",
                "description": "Identify parent domains with highest risk across subdomains"
            },
            {
                "query": "Show me all incidents from the last 30 days",
                "description": "Recent security incidents across all domains"
            },
            {
                "query": "Find domains with poor TLS grades",
                "description": "Domains with weak SSL/TLS configurations"
            }
        ]
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics for the dashboard"""
        try:
            stats = {}
            
            # Get node counts
            node_stats = self.neo4j_client.execute_query("""
                MATCH (n)
                RETURN labels(n) as labels, count(n) as count
                ORDER BY count DESC
            """)
            
            stats["node_counts"] = {}
            for stat in node_stats:
                labels = stat["labels"]
                if labels:
                    label = labels[0]  # Use first label
                    stats["node_counts"][label] = stat["count"]
            
            # Get relationship counts
            rel_stats = self.neo4j_client.execute_query("""
                MATCH ()-[r]->()
                RETURN type(r) as relationship_type, count(r) as count
                ORDER BY count DESC
            """)
            
            stats["relationship_counts"] = {}
            for stat in rel_stats:
                stats["relationship_counts"][stat["relationship_type"]] = stat["count"]
            
            # Get risk tier distribution
            risk_stats = self.neo4j_client.execute_query("""
                MATCH (d:Domain)
                WHERE d.risk_tier IS NOT NULL
                RETURN d.risk_tier as risk_tier, count(d) as count
                ORDER BY count DESC
            """)
            
            stats["risk_distribution"] = {}
            for stat in risk_stats:
                stats["risk_distribution"][stat["risk_tier"]] = stat["count"]
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {
                "error": str(e),
                "node_counts": {},
                "relationship_counts": {},
                "risk_distribution": {}
            }