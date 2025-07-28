from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional

class AIClientBase(ABC):
    """Base class for AI clients (Ollama, Anthropic, etc.)"""
    
    @abstractmethod
    async def test_connection(self) -> Dict[str, Any]:
        """Test connection to the AI service"""
        pass
    
    @abstractmethod
    async def list_models(self) -> List[str]:
        """List available models"""
        pass
    
    @abstractmethod
    async def check_model_availability(self, model_name: str) -> bool:
        """Check if a specific model is available"""
        pass
    
    @abstractmethod
    async def generate_response(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate a response using the AI model"""
        pass
    
    @abstractmethod
    async def convert_natural_language_to_cypher(self, natural_query: str, schema_info: Dict[str, Any]) -> str:
        """Convert natural language query to Cypher"""
        pass
    
    @abstractmethod
    async def interpret_cypher_results(self, natural_query: str, cypher_query: str, 
                                     results: List[Dict[str, Any]]) -> str:
        """Interpret Cypher query results in natural language"""
        pass