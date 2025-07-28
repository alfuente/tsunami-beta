import os
import logging
from typing import Dict, Any
from ai_client_base import AIClientBase
from ollama_client import OllamaClient
from anthropic_client import AnthropicClient
from mistral_client import MistralClient

logger = logging.getLogger(__name__)

def create_ai_client(config: Dict[str, Any]) -> AIClientBase:
    """Factory function to create the appropriate AI client based on configuration"""
    
    provider = config.get("ai_provider", "ollama").lower()
    
    if provider == "ollama":
        ollama_config = config.get("ollama", {})
        return OllamaClient(
            host=ollama_config.get("host", "http://localhost:11434"),
            model=ollama_config.get("model", "llama3.1"),
            timeout=ollama_config.get("timeout", 60),
            max_tokens=ollama_config.get("max_tokens", 2048)
        )
    
    elif provider == "anthropic":
        anthropic_config = config.get("anthropic", {})
        
        # Get API key from environment variable or config
        api_key = anthropic_config.get("api_key")
        if api_key and api_key.startswith("${") and api_key.endswith("}"):
            # Extract environment variable name
            env_var = api_key[2:-1]
            api_key = os.getenv(env_var)
            
        if not api_key:
            raise ValueError(
                "Anthropic API key not found. Set ANTHROPIC_API_KEY environment variable "
                "or configure api_key in config.yaml"
            )
        
        return AnthropicClient(
            api_key=api_key,
            model=anthropic_config.get("model", "claude-3-5-sonnet-20241022"),
            timeout=anthropic_config.get("timeout", 300),
            max_tokens=anthropic_config.get("max_tokens", 4096)
        )
    
    elif provider == "mistral":
        mistral_config = config.get("mistral", {})
        
        # Get API key from environment variable or config
        api_key = mistral_config.get("api_key")
        if api_key and api_key.startswith("${") and api_key.endswith("}"):
            # Extract environment variable name
            env_var = api_key[2:-1]
            api_key = os.getenv(env_var)
            
        if not api_key:
            raise ValueError(
                "Mistral AI API key not found. Set MISTRAL_API_KEY environment variable "
                "or configure api_key in config.yaml"
            )
        
        return MistralClient(
            api_key=api_key,
            model=mistral_config.get("model", "mistral-large-latest"),
            timeout=mistral_config.get("timeout", 300),
            max_tokens=mistral_config.get("max_tokens", 4096)
        )
    
    else:
        raise ValueError(f"Unsupported AI provider: {provider}. Supported providers: ollama, anthropic, mistral")

def get_supported_providers() -> Dict[str, Dict[str, Any]]:
    """Get information about supported AI providers"""
    return {
        "ollama": {
            "name": "Ollama",
            "description": "Local LLM hosting platform",
            "supports_models": ["llama3.1", "mistral", "codellama", "deepseek-coder", "phi3"],
            "requires_api_key": False
        },
        "anthropic": {
            "name": "Anthropic Claude",
            "description": "Anthropic's Claude AI models via API",
            "supports_models": [
                "claude-3-5-sonnet-20241022",
                "claude-3-5-haiku-20241022", 
                "claude-3-opus-20240229",
                "claude-3-sonnet-20240229",
                "claude-3-haiku-20240307"
            ],
            "requires_api_key": True
        },
        "mistral": {
            "name": "Mistral AI",
            "description": "Mistral AI's language models via API",
            "supports_models": [
                "mistral-large-latest",
                "mistral-small-latest",
                "codestral-latest",
                "mistral-medium-latest"
            ],
            "requires_api_key": True
        }
    }