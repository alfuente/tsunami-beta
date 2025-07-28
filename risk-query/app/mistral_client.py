import asyncio
import logging
import json
import os
import aiohttp
import time
from typing import Dict, List, Any, Optional
from ai_client_base import AIClientBase

logger = logging.getLogger(__name__)

class MistralClient(AIClientBase):
    def __init__(self, api_key: str, model: str = "mistral-large-latest", 
                 timeout: int = 300, max_tokens: int = 4096):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.base_url = "https://api.mistral.ai/v1"
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test connection to Mistral AI API"""
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            # Test with a simple chat completion
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "user", "content": "Hello"}
                ],
                "max_tokens": 10,
                "temperature": 0.1
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        content = ""
                        if data.get("choices") and len(data["choices"]) > 0:
                            content = data["choices"][0].get("message", {}).get("content", "")
                        
                        return {
                            "status": "connected",
                            "model": self.model,
                            "response": content
                        }
                    else:
                        error_text = await response.text()
                        raise Exception(f"Mistral AI API returned status {response.status}: {error_text}")
        except Exception as e:
            logger.error(f"Mistral AI connection test failed: {e}")
            raise
    
    async def list_models(self) -> List[str]:
        """List available models from Mistral AI"""
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}/models",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        models = [model["id"] for model in data.get("data", [])]
                        return models
                    else:
                        # Fallback to known models if API doesn't respond
                        return [
                            "mistral-large-latest",
                            "mistral-small-latest", 
                            "codestral-latest",
                            "mistral-medium-latest"
                        ]
        except Exception as e:
            logger.error(f"Failed to list Mistral models: {e}")
            # Return fallback models
            return [
                "mistral-large-latest",
                "mistral-small-latest", 
                "codestral-latest",
                "mistral-medium-latest"
            ]
    
    async def check_model_availability(self, model_name: str) -> bool:
        """Check if a specific model is available"""
        available_models = await self.list_models()
        return model_name in available_models
    
    async def generate_response(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate a response using Mistral AI"""
        try:
            logger.info(f"Starting generation with Mistral {self.model}, timeout: {self.timeout}s")
            
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})
            
            payload = {
                "model": self.model,
                "messages": messages,
                "max_tokens": self.max_tokens,
                "temperature": 0.1,  # Low temperature for more deterministic responses
                "top_p": 0.9
            }
            
            logger.info(f"Sending request to Mistral AI (prompt length: {len(prompt)} chars)")
            start_time = time.time()
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    
                    end_time = time.time()
                    logger.info(f"Mistral AI request completed in {end_time - start_time:.2f} seconds")
                    
                    if response.status == 200:
                        result = await response.json()
                        
                        # Extract text from Mistral's response format
                        choices = result.get("choices", [])
                        if choices and len(choices) > 0:
                            message = choices[0].get("message", {})
                            generated_text = message.get("content", "").strip()
                        else:
                            generated_text = ""
                        
                        logger.info(f"Generated response length: {len(generated_text)} characters")
                        return generated_text
                    else:
                        response_text = await response.text()
                        raise Exception(f"Mistral AI API returned status {response.status}: {response_text}")
                        
        except Exception as e:
            logger.error(f"Failed to generate response: {e}")
            raise
    
    async def convert_natural_language_to_cypher(self, natural_query: str, schema_info: Dict[str, Any]) -> str:
        """Convert natural language query to Cypher using Mistral AI"""
        
        system_prompt = """You are an expert at converting natural language queries to Cypher queries for Neo4j databases.

Your task is to convert the user's natural language query into a valid Cypher query based on the provided schema information.

IMPORTANT RULES:
1. Return ONLY the Cypher query, no explanations or markdown formatting
2. Use the exact node labels and relationship types from the schema
3. Always include LIMIT clauses to prevent overwhelming results (default: LIMIT 20)
4. Use appropriate WHERE clauses for filtering
5. Return results in a useful format with RETURN statements

Schema Information:
- Node Labels: Domain, BaseDomain, ThirdPartyProvider, Incident, Assessment  
- Relationship Types: DEPENDS_ON, HAS_SUBDOMAIN, USES_PROVIDER, HAS_INCIDENT, HAS_ASSESSMENT
- Common Properties: fqdn, risk_score, risk_tier, business_criticality, monitoring_enabled

Examples:
"high risk domains" → MATCH (d:Domain) WHERE d.risk_tier = 'high' RETURN d LIMIT 20
"domains with dependencies" → MATCH (d:Domain)-[r:DEPENDS_ON]->() RETURN d, COUNT(r) as dependency_count ORDER BY dependency_count DESC LIMIT 10

Return only the Cypher query without any formatting or explanation."""
        
        prompt = f"""Convert this natural language query to Cypher:

Query: "{natural_query}"

Schema context: {json.dumps(schema_info, indent=2)}

Cypher query:"""
        
        try:
            cypher_query = await self.generate_response(prompt, system_prompt)
            
            # Clean up the response - remove any remaining formatting
            cypher_query = cypher_query.strip()
            
            # Remove code block markers if present
            if "```" in cypher_query:
                parts = cypher_query.split("```")
                if len(parts) >= 3:
                    cypher_query = parts[1].strip()
                    # Remove language identifier
                    lines = cypher_query.split('\n')
                    if lines and lines[0].lower() in ['cypher', 'cql']:
                        cypher_query = '\n'.join(lines[1:]).strip()
                elif len(parts) == 2:
                    cypher_query = parts[1].strip()
            
            # Remove any explanatory text - find the actual query
            lines = cypher_query.split("\n")
            query_lines = []
            
            for line in lines:
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#') or line.startswith('//'):
                    continue
                    
                # Check if this line starts a Cypher query
                if line.upper().startswith(('MATCH', 'CREATE', 'MERGE', 'DELETE', 'WITH', 'UNWIND', 'CALL')):
                    # This is likely the start of our query
                    query_lines = [line]
                    continue
                
                # If we have started collecting query lines, continue
                if query_lines and (
                    line.upper().startswith(('WHERE', 'RETURN', 'ORDER', 'LIMIT', 'SKIP', 'SET', 'REMOVE', 'ON', 'AND', 'OR')) or
                    line.startswith('-') or
                    line.endswith(',') or
                    line.endswith(';') or
                    '(' in line or ')' in line
                ):
                    query_lines.append(line)
                elif query_lines and not line.startswith(('This', 'The', '**', 'Note:')):
                    # Might be a continuation of the query
                    query_lines.append(line)
                elif query_lines:
                    # Probably hit explanatory text, stop here
                    break
            
            final_query = " ".join(query_lines).strip()
            
            # Remove trailing semicolon if present
            if final_query.endswith(';'):
                final_query = final_query[:-1]
            
            # If we couldn't extract a proper query, return the cleaned original
            if not final_query or not any(final_query.upper().startswith(keyword) for keyword in ['MATCH', 'CREATE', 'MERGE', 'DELETE', 'WITH']):
                # Look for any line that looks like a Cypher query
                for line in cypher_query.split('\n'):
                    line = line.strip()
                    if line.upper().startswith(('MATCH', 'CREATE', 'MERGE', 'DELETE', 'WITH')):
                        final_query = line
                        break
                
                if not final_query:
                    final_query = cypher_query
            
            logger.info(f"Generated Cypher query: {final_query}")
            return final_query
            
        except Exception as e:
            logger.error(f"Failed to convert natural language to Cypher: {e}")
            raise
    
    async def interpret_cypher_results(self, natural_query: str, cypher_query: str, 
                                     results: List[Dict[str, Any]]) -> str:
        """Interpret Cypher query results in natural language using Mistral AI"""
        
        system_prompt = """You are an expert at interpreting database query results and explaining them in clear, natural language.

Your task is to:
1. Analyze the results from a Cypher query
2. Provide a clear, concise summary in natural language
3. Highlight key insights and patterns
4. Format the response to be user-friendly and informative

Guidelines:
- Be concise but informative
- Use bullet points or numbered lists when appropriate
- Mention specific numbers and metrics when relevant
- If no results, explain what this means in context
- Focus on answering the original user question
- Highlight important risk-related information
- Use professional but accessible language"""
        
        results_summary = f"Query Results:\n- Total count: {len(results)}\n"
        if results:
            results_summary += f"- Sample data (first 3 results):\n{json.dumps(results[:3], indent=2, default=str)}"
        else:
            results_summary += "- No results returned from the database"
        
        prompt = f"""Please interpret these database query results for the user.

Original question: "{natural_query}"

Cypher query that was executed:
{cypher_query}

{results_summary}

Provide a clear, natural language interpretation that answers the user's question:"""
        
        try:
            interpretation = await self.generate_response(prompt, system_prompt)
            return interpretation.strip()
            
        except Exception as e:
            logger.error(f"Failed to interpret results: {e}")
            # Return a basic interpretation as fallback
            if not results:
                return f"No results found for your query: '{natural_query}'. This could mean no data matches your criteria or the query needs to be refined."
            else:
                return f"Found {len(results)} results for your query: '{natural_query}'. The data includes various properties and relationships as requested."