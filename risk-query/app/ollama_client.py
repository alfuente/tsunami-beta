import asyncio
import logging
import json
import subprocess
import aiohttp
import time
from typing import Dict, List, Any, Optional
from ai_client_base import AIClientBase

logger = logging.getLogger(__name__)

class OllamaClient(AIClientBase):
    def __init__(self, host: str = "http://localhost:11434", model: str = "llama3.1", 
                 timeout: int = 60, max_tokens: int = 2048):
        self.host = host.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.max_tokens = max_tokens
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test connection to Ollama"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.host}/api/tags", timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            "status": "connected",
                            "models": data.get("models", [])
                        }
                    else:
                        raise Exception(f"Ollama server returned status {response.status}")
        except Exception as e:
            logger.error(f"Ollama connection test failed: {e}")
            raise
    
    async def list_models(self) -> List[str]:
        """List available models in Ollama"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.host}/api/tags", timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status == 200:
                        models_data = await response.json()
                        return [model["name"] for model in models_data.get("models", [])]
                    else:
                        raise Exception(f"Failed to list models: {response.status}")
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
            # Ensure model is available (skip check for performance if model is already loaded)
            logger.info(f"Starting generation with model {self.model}, timeout: {self.timeout}s")
            
            # Prepare the request with optimized settings
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "num_predict": self.max_tokens,
                    "temperature": 0.1,  # Low temperature for more deterministic responses
                    "top_k": 40,
                    "top_p": 0.9,
                    "num_ctx": 4096,  # Increase context window
                    "num_thread": 8   # Use more threads for faster processing
                }
            }
            
            if system_prompt:
                payload["system"] = system_prompt
            
            logger.info(f"Sending request to Ollama (prompt length: {len(prompt)} chars)")
            start_time = time.time()
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.host}/api/generate",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    
                    end_time = time.time()
                    logger.info(f"Ollama request completed in {end_time - start_time:.2f} seconds")
                    
                    if response.status == 200:
                        result = await response.json()
                        generated_text = result.get("response", "").strip()
                        logger.info(f"Generated response length: {len(generated_text)} characters")
                        return generated_text
                    else:
                        response_text = await response.text()
                        raise Exception(f"Ollama API returned status {response.status}: {response_text}")
                
        except Exception as e:
            logger.error(f"Failed to generate response: {e}")
            raise
    
    async def convert_natural_language_to_cypher(self, natural_query: str, schema_info: Dict[str, Any]) -> str:
        """Convert natural language query to Cypher using Ollama"""
        
        system_prompt = """Convert natural language to Cypher queries. Return ONLY the query.

Schema:
- Nodes: Domain, BaseDomain, ThirdPartyProvider, Incident, Assessment  
- Relations: DEPENDS_ON, HAS_SUBDOMAIN, USES_PROVIDER, HAS_INCIDENT, HAS_ASSESSMENT
- Key fields: fqdn, risk_score, risk_tier, business_criticality

Examples:
"high risk domains" → MATCH (d:Domain) WHERE d.risk_tier = 'high' RETURN d LIMIT 20
"domains with dependencies" → MATCH (d:Domain)-[r:DEPENDS_ON]->() RETURN d, COUNT(r) as deps LIMIT 10

Return only the Cypher query."""
        
        prompt = f"""Query: "{natural_query}"

Return Cypher:"""
        
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