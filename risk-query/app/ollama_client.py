import asyncio
import logging
import json
import subprocess
import requests
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class OllamaClient:
    def __init__(self, host: str = "http://localhost:11434", model: str = "llama3.1", 
                 timeout: int = 60, max_tokens: int = 2048):
        self.host = host.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.max_tokens = max_tokens
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test connection to Ollama"""
        try:
            response = requests.get(f"{self.host}/api/tags", timeout=10)
            if response.status_code == 200:
                return {
                    "status": "connected",
                    "models": response.json().get("models", [])
                }
            else:
                raise Exception(f"Ollama server returned status {response.status_code}")
        except Exception as e:
            logger.error(f"Ollama connection test failed: {e}")
            raise
    
    async def list_models(self) -> List[str]:
        """List available models in Ollama"""
        try:
            response = requests.get(f"{self.host}/api/tags", timeout=10)
            if response.status_code == 200:
                models_data = response.json()
                return [model["name"] for model in models_data.get("models", [])]
            else:
                raise Exception(f"Failed to list models: {response.status_code}")
        except Exception as e:
            logger.error(f"Failed to list models: {e}")
            raise
    
    async def check_model_availability(self, model_name: str) -> bool:
        """Check if a specific model is available"""
        try:
            available_models = await self.list_models()
            return any(model_name in model for model in available_models)
        except Exception as e:
            logger.error(f"Failed to check model availability: {e}")
            return False
    
    async def pull_model(self, model_name: str) -> bool:
        """Pull a model if it's not available"""
        try:
            logger.info(f"Pulling model {model_name}...")
            
            # Use subprocess to run ollama pull command
            result = subprocess.run(
                ["ollama", "pull", model_name],
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout for model pull
            )
            
            if result.returncode == 0:
                logger.info(f"Successfully pulled model {model_name}")
                return True
            else:
                logger.error(f"Failed to pull model {model_name}: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout while pulling model {model_name}")
            return False
        except Exception as e:
            logger.error(f"Error pulling model {model_name}: {e}")
            return False
    
    async def generate_response(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate a response using Ollama"""
        try:
            # Ensure model is available
            if not await self.check_model_availability(self.model):
                logger.info(f"Model {self.model} not available, attempting to pull...")
                if not await self.pull_model(self.model):
                    raise Exception(f"Failed to pull model {self.model}")
            
            # Prepare the request
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "num_predict": self.max_tokens,
                    "temperature": 0.1,  # Low temperature for more deterministic responses
                    "top_k": 40,
                    "top_p": 0.9
                }
            }
            
            if system_prompt:
                payload["system"] = system_prompt
            
            logger.info(f"Sending request to Ollama with model {self.model}")
            
            response = requests.post(
                f"{self.host}/api/generate",
                json=payload,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get("response", "").strip()
            else:
                raise Exception(f"Ollama API returned status {response.status_code}: {response.text}")
                
        except Exception as e:
            logger.error(f"Failed to generate response: {e}")
            raise
    
    async def convert_natural_language_to_cypher(self, natural_query: str, schema_info: Dict[str, Any]) -> str:
        """Convert natural language query to Cypher using Ollama"""
        
        system_prompt = """You are an expert in converting natural language queries to Cypher queries for Neo4j.

You have access to a risk management graph database with the following schema:

Node Labels: Domain, BaseDomain, ThirdPartyProvider, Incident, Assessment
Relationship Types: DEPENDS_ON, HAS_SUBDOMAIN, USES_PROVIDER, HAS_INCIDENT, HAS_ASSESSMENT

Key Properties:
- Domain: fqdn, risk_score, risk_tier, business_criticality, monitoring_enabled
- BaseDomain: base_domain, total_subdomains, avg_risk_score, industry
- ThirdPartyProvider: provider_name, risk_level, services
- Incident: severity, detected, resolved, impact_score
- Assessment: assessment_date, tls_grade, critical_cves, high_cves

Important guidelines:
1. Always return ONLY the Cypher query, no explanations
2. Use proper Cypher syntax with MATCH, WHERE, RETURN clauses
3. Handle case-insensitive searches with toLower() when appropriate
4. Limit results with LIMIT clause when appropriate (default 20)
5. Use ORDER BY for sorting results
6. For risk-related queries, consider risk_score and risk_tier fields
7. For dependency queries, use DEPENDS_ON relationships
8. For subdomain queries, use HAS_SUBDOMAIN relationships

Examples:
- "Show high risk domains" → MATCH (d:Domain) WHERE d.risk_tier = 'high' RETURN d ORDER BY d.risk_score DESC LIMIT 20
- "Domains with most dependencies" → MATCH (d:Domain)-[r:DEPENDS_ON]->() RETURN d, COUNT(r) as dep_count ORDER BY dep_count DESC LIMIT 10
- "Financial domains" → MATCH (bd:BaseDomain) WHERE toLower(bd.industry) CONTAINS 'financial' MATCH (bd)-[:HAS_SUBDOMAIN]->(d:Domain) RETURN d LIMIT 20
"""
        
        prompt = f"""Convert this natural language query to Cypher:

Query: "{natural_query}"

Schema context:
{json.dumps(schema_info, indent=2)}

Return only the Cypher query:"""
        
        try:
            cypher_query = await self.generate_response(prompt, system_prompt)
            
            # Clean up the response - remove any markdown formatting or explanations
            cypher_query = cypher_query.strip()
            
            # Remove code block markers if present
            if "```" in cypher_query:
                # Extract content between first ``` and next ```
                parts = cypher_query.split("```")
                if len(parts) >= 3:
                    # Take the first code block
                    cypher_query = parts[1].strip()
                    # Remove language identifier like 'cypher'
                    lines = cypher_query.split('\n')
                    if lines and lines[0].lower() in ['cypher', 'cql']:
                        cypher_query = '\n'.join(lines[1:]).strip()
                elif len(parts) == 2:
                    cypher_query = parts[1].strip()
            
            # Remove any remaining explanatory text - keep only the query
            lines = cypher_query.split("\n")
            query_lines = []
            in_query = False
            
            for line in lines:
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#') or line.startswith('//'):
                    continue
                    
                # Check if this line starts a Cypher query
                if line.upper().startswith(('MATCH', 'CREATE', 'MERGE', 'DELETE', 'WITH', 'UNWIND', 'CALL')):
                    in_query = True
                    query_lines.append(line)
                # If we're in a query, continue adding lines that are part of it
                elif in_query and (line.upper().startswith(('WHERE', 'RETURN', 'ORDER', 'LIMIT', 'SKIP', 'SET', 'REMOVE', 'ON', 'AND', 'OR')) or
                                   line.startswith('-') or
                                   line.endswith(',') or
                                   line.endswith(';') or
                                   '(' in line or ')' in line):
                    query_lines.append(line)
                # Stop when we encounter explanatory text
                elif in_query and (line.startswith('This') or line.startswith('The') or line.startswith('**')):
                    break
            
            final_query = " ".join(query_lines).strip()
            
            # Remove trailing semicolon if present
            if final_query.endswith(';'):
                final_query = final_query[:-1]
            
            # If we couldn't extract a proper query, try a more aggressive approach
            if not final_query or not any(final_query.upper().startswith(keyword) for keyword in ['MATCH', 'CREATE', 'MERGE', 'DELETE', 'WITH']):
                # Look for the first line that starts with a Cypher keyword
                original_lines = cypher_query.split('\n')
                for line in original_lines:
                    line = line.strip()
                    if line.upper().startswith(('MATCH', 'CREATE', 'MERGE', 'DELETE', 'WITH')):
                        # Take this line and try to find a complete statement
                        end_idx = line.find('```')
                        if end_idx > 0:
                            final_query = line[:end_idx].strip()
                        else:
                            final_query = line
                        break
            
            logger.info(f"Generated Cypher query: {final_query}")
            return final_query
            
        except Exception as e:
            logger.error(f"Failed to convert natural language to Cypher: {e}")
            raise
    
    async def interpret_cypher_results(self, natural_query: str, cypher_query: str, 
                                     results: List[Dict[str, Any]]) -> str:
        """Interpret Cypher query results in natural language"""
        
        system_prompt = """You are an expert at interpreting database query results and explaining them in clear, natural language.

Your task is to:
1. Analyze the results from a Cypher query
2. Provide a clear, concise summary in natural language
3. Highlight key insights and patterns
4. Format the response to be user-friendly

Guidelines:
- Be concise but informative
- Use bullet points or numbered lists when appropriate
- Mention specific numbers and metrics when relevant
- If no results, explain what this means
- Focus on answering the original user question"""
        
        results_summary = f"Results count: {len(results)}\n"
        if results:
            results_summary += f"Sample results (showing first 3):\n{json.dumps(results[:3], indent=2, default=str)}"
        else:
            results_summary += "No results returned"
        
        prompt = f"""Original question: "{natural_query}"

Cypher query executed: {cypher_query}

{results_summary}

Please interpret these results and provide a clear, natural language response that answers the user's question:"""
        
        try:
            interpretation = await self.generate_response(prompt, system_prompt)
            return interpretation.strip()
            
        except Exception as e:
            logger.error(f"Failed to interpret results: {e}")
            # Return a basic interpretation as fallback
            if not results:
                return f"No results found for your query: '{natural_query}'"
            else:
                return f"Found {len(results)} results for your query: '{natural_query}'. The data includes various properties and relationships as requested."