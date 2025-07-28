#!/usr/bin/env python3
"""Test script for AI providers"""

import asyncio
import sys
import os
import yaml

# Add app directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

from ai_client_factory import create_ai_client, get_supported_providers

async def test_ollama():
    """Test Ollama client"""
    print("=" * 50)
    print("Testing Ollama Provider")
    print("=" * 50)
    
    config = {
        "ai_provider": "ollama",
        "ollama": {
            "host": "http://localhost:11434",
            "model": "mistral:7b",
            "timeout": 600,
            "max_tokens": 2048
        }
    }
    
    try:
        client = create_ai_client(config)
        
        # Test connection
        print("1. Testing connection...")
        result = await client.test_connection()
        print(f"   ✓ Connection: {result.get('status')}")
        
        # Test models
        print("2. Listing models...")
        models = await client.list_models()
        print(f"   ✓ Available models: {models[:3]}...")  # Show first 3
        
        # Test simple generation
        print("3. Testing generation...")
        response = await client.generate_response("Say hello in one word")
        print(f"   ✓ Response: '{response}'")
        
        print("   ✅ Ollama client works!")
        return True
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

async def test_anthropic():
    """Test Anthropic client"""
    print("=" * 50)
    print("Testing Anthropic Provider")
    print("=" * 50)
    
    # Check if API key is available
    api_key = os.getenv('ANTHROPIC_API_KEY')
    if not api_key:
        print("   ⚠️  ANTHROPIC_API_KEY not set, skipping Anthropic test")
        return False
    
    config = {
        "ai_provider": "anthropic",
        "anthropic": {
            "api_key": "${ANTHROPIC_API_KEY}",
            "model": "claude-3-5-sonnet-20241022",
            "timeout": 300,
            "max_tokens": 4096
        }
    }
    
    try:
        client = create_ai_client(config)
        
        # Test connection
        print("1. Testing connection...")
        result = await client.test_connection()
        print(f"   ✓ Connection: {result.get('status')}")
        
        # Test models
        print("2. Listing models...")
        models = await client.list_models()
        print(f"   ✓ Available models: {models[:3]}...")  # Show first 3
        
        # Test simple generation
        print("3. Testing generation...")
        response = await client.generate_response("Say hello in one word")
        print(f"   ✓ Response: '{response}'")
        
        print("   ✅ Anthropic client works!")
        return True
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

async def test_mistral():
    """Test Mistral client"""
    print("=" * 50)
    print("Testing Mistral Provider")
    print("=" * 50)
    
    # Check if API key is available
    api_key = os.getenv('MISTRAL_API_KEY')
    if not api_key:
        print("   ⚠️  MISTRAL_API_KEY not set, skipping Mistral test")
        return False
    
    config = {
        "ai_provider": "mistral",
        "mistral": {
            "api_key": "${MISTRAL_API_KEY}",
            "model": "mistral-large-latest",
            "timeout": 300,
            "max_tokens": 4096
        }
    }
    
    try:
        client = create_ai_client(config)
        
        # Test connection
        print("1. Testing connection...")
        result = await client.test_connection()
        print(f"   ✓ Connection: {result.get('status')}")
        
        # Test models
        print("2. Listing models...")
        models = await client.list_models()
        print(f"   ✓ Available models: {models[:3]}...")  # Show first 3
        
        # Test simple generation
        print("3. Testing generation...")
        response = await client.generate_response("Say hello in one word")
        print(f"   ✓ Response: '{response}'")
        
        print("   ✅ Mistral client works!")
        return True
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

async def main():
    """Main test function"""
    print("Risk Query AI Provider Test")
    print("=" * 50)
    
    # Show supported providers
    providers = get_supported_providers()
    print("Supported providers:")
    for name, info in providers.items():
        print(f"  - {name}: {info['description']}")
    print()
    
    # Test each provider
    results = {}
    results['ollama'] = await test_ollama()
    print()
    results['anthropic'] = await test_anthropic()
    print()
    results['mistral'] = await test_mistral()
    
    print()
    print("=" * 50)
    print("Test Summary")
    print("=" * 50)
    for provider, success in results.items():
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{provider:15}: {status}")

if __name__ == "__main__":
    asyncio.run(main())