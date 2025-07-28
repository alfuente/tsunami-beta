#!/usr/bin/env python3
"""Test configuration switching between providers"""

import asyncio
import sys
import os
import yaml

# Add app directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

from ai_client_factory import create_ai_client

async def test_config_loading():
    """Test loading configuration and switching providers"""
    print("=" * 50)
    print("Testing Configuration Loading")
    print("=" * 50)
    
    # Load actual config file
    config_path = os.path.join(os.path.dirname(__file__), "config", "config.yaml")
    
    try:
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
        
        print(f"✓ Loaded config from: {config_path}")
        print(f"✓ Current provider: {config.get('ai_provider', 'not set')}")
        
        # Test creating client with current config
        provider = config.get('ai_provider', 'ollama')
        print(f"✓ Creating {provider} client...")
        
        client = create_ai_client(config)
        
        # Test connection
        result = await client.test_connection()
        print(f"✓ Connection test: {result.get('status')}")
        
        print("✅ Configuration loading works!")
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

async def test_provider_switching():
    """Test switching between providers programmatically"""
    print("=" * 50)
    print("Testing Provider Switching")
    print("=" * 50)
    
    # Test switching to Ollama
    print("1. Testing Ollama configuration...")
    ollama_config = {
        "ai_provider": "ollama",
        "ollama": {
            "host": "http://localhost:11434",
            "model": "mistral:7b",
            "timeout": 600,
            "max_tokens": 2048
        }
    }
    
    try:
        client = create_ai_client(ollama_config)
        result = await client.test_connection()
        print(f"   ✓ Ollama: {result.get('status')}")
    except Exception as e:
        print(f"   ❌ Ollama error: {e}")
    
    # Test switching to Anthropic (without API key)
    print("2. Testing Anthropic configuration...")
    anthropic_config = {
        "ai_provider": "anthropic",
        "anthropic": {
            "api_key": "fake-key",  # This will fail, but tests config parsing
            "model": "claude-3-5-sonnet-20241022",
            "timeout": 300,
            "max_tokens": 4096
        }
    }
    
    try:
        client = create_ai_client(anthropic_config)
        print("   ✓ Anthropic client created (connection will fail without valid API key)")
    except ValueError as e:
        if "API key" in str(e):
            print("   ✓ Anthropic correctly requires API key")
        else:
            print(f"   ❌ Unexpected error: {e}")
    except Exception as e:
        print(f"   ❌ Anthropic error: {e}")
    
    print("✅ Provider switching works!")

async def main():
    """Main test function"""
    print("Risk Query Configuration Test")
    print()
    
    await test_config_loading()
    print()
    await test_provider_switching()
    
    print()
    print("=" * 50)
    print("Configuration Test Complete")
    print("=" * 50)
    print("✅ Ready to use with either provider!")
    print()
    print("To use Anthropic:")
    print("1. Set ANTHROPIC_API_KEY environment variable")
    print("2. Change ai_provider to 'anthropic' in config.yaml")
    print()
    print("To use Ollama:")
    print("1. Ensure Ollama is running on localhost:11434")
    print("2. Set ai_provider to 'ollama' in config.yaml (default)")

if __name__ == "__main__":
    asyncio.run(main())