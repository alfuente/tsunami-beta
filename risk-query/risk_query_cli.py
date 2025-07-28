#!/usr/bin/env python3
"""
Risk Query CLI - Command Line Interface for Risk Query Service

This tool allows you to execute natural language queries against the risk database
from the command line using the same configuration as the web service.
"""

import argparse
import asyncio
import sys
import os
import yaml
import json
import logging
from typing import Dict, Any, Optional
from pathlib import Path

# Add app directory to path
script_dir = Path(__file__).parent
app_dir = script_dir / "app"
sys.path.append(str(app_dir))

from query_processor import QueryProcessor
from neo4j_client import Neo4jClient
from ai_client_factory import create_ai_client, get_supported_providers

# Configure logging
logging.basicConfig(
    level=logging.WARNING,  # Only show warnings and errors by default
    format='%(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

class RiskQueryCLI:
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the CLI with configuration"""
        self.config_path = config_path or str(script_dir / "config" / "config.yaml")
        self.config = self._load_config()
        self.neo4j_client = None
        self.ai_client = None
        self.query_processor = None
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as file:
                config = yaml.safe_load(file)
                return config
        except FileNotFoundError:
            print(f"❌ Configuration file not found: {self.config_path}")
            sys.exit(1)
        except yaml.YAMLError as e:
            print(f"❌ Error parsing configuration file: {e}")
            sys.exit(1)
    
    async def initialize(self, verbose: bool = False):
        """Initialize clients and connections"""
        if verbose:
            logging.getLogger().setLevel(logging.INFO)
            
        try:
            # Initialize Neo4j client
            neo4j_config = self.config.get("neo4j", {})
            self.neo4j_client = Neo4jClient(
                uri=neo4j_config.get("uri", "bolt://localhost:7687"),
                user=neo4j_config.get("user", "neo4j"),
                password=neo4j_config.get("password", "password"),
                database=neo4j_config.get("database", "neo4j")
            )
            
            # Initialize AI client
            provider = self.config.get("ai_provider", "ollama")
            if verbose:
                print(f"🤖 Initializing AI client: {provider}")
            
            self.ai_client = create_ai_client(self.config)
            
            # Test connections
            if verbose:
                print("🔗 Testing connections...")
                
                # Test Neo4j
                neo4j_result = self.neo4j_client.test_connection()
                print(f"   ✓ Neo4j: Connected")
                
                # Test AI client
                ai_result = await self.ai_client.test_connection()
                print(f"   ✓ {provider}: {ai_result.get('status', 'unknown')}")
            
            # Initialize query processor
            self.query_processor = QueryProcessor(self.neo4j_client, self.ai_client)
            
            if verbose:
                print("✅ Initialization complete")
                
        except Exception as e:
            print(f"❌ Initialization failed: {e}")
            sys.exit(1)
    
    async def execute_query(self, query: str, verbose: bool = False, raw: bool = False) -> Dict[str, Any]:
        """Execute a natural language query"""
        if not self.query_processor:
            await self.initialize(verbose)
        
        try:
            if verbose:
                print(f"🔍 Processing query: {query}")
            
            result = await self.query_processor.process_query(query)
            
            if raw:
                return result
            
            # Format and display result
            print("\n" + "="*60)
            print("📊 QUERY RESULTS")
            print("="*60)
            
            if result.get("metadata", {}).get("execution_successful", False):
                print(f"💬 Response:")
                print(f"   {result['response']}")
                
                if verbose and result.get("cypher_query"):
                    print(f"\n🔧 Generated Cypher:")
                    print(f"   {result['cypher_query']}")
                
                raw_results = result.get("raw_results", {})
                count = raw_results.get("count", 0)
                print(f"\n📈 Results: {count} records found")
                
                if verbose and count > 0:
                    data = raw_results.get("data", [])
                    print(f"\n📋 Sample Data (first {min(3, len(data))} records):")
                    for i, record in enumerate(data[:3]):
                        print(f"   {i+1}. {json.dumps(record, indent=6, default=str)}")
            else:
                error = result.get("metadata", {}).get("error", "Unknown error")
                print(f"❌ Query failed: {error}")
            
            return result
            
        except Exception as e:
            print(f"❌ Query execution failed: {e}")
            return {"error": str(e)}
    
    def show_providers(self):
        """Show available AI providers"""
        providers = get_supported_providers()
        current = self.config.get("ai_provider", "unknown")
        
        print("\n🤖 AVAILABLE AI PROVIDERS")
        print("="*50)
        
        for name, info in providers.items():
            status = "🟢 ACTIVE" if name == current else "⚪ Available"
            api_key_req = "🔑 API Key Required" if info["requires_api_key"] else "🆓 No API Key"
            
            print(f"\n{status} {name.upper()}")
            print(f"   Name: {info['name']}")
            print(f"   Description: {info['description']}")
            print(f"   {api_key_req}")
            print(f"   Models: {', '.join(info['supports_models'][:3])}{'...' if len(info['supports_models']) > 3 else ''}")
    
    def show_examples(self):
        """Show example queries"""
        examples = [
            "Show me all domains with high risk scores",
            "Which domains have the most dependencies?",
            "Find domains with critical security vulnerabilities", 
            "What are the third-party providers for financial services domains?",
            "Show me domains that haven't been assessed recently",
            "Which base domains have the highest average risk scores?",
            "Show me all incidents from the last 30 days",
            "Find domains with poor TLS grades"
        ]
        
        print("\n💡 EXAMPLE QUERIES")
        print("="*50)
        for i, example in enumerate(examples, 1):
            print(f"{i:2d}. {example}")
        
        print(f"\n📝 Usage: risk_query_cli.py \"<your query here>\"")
    
    def cleanup(self):
        """Cleanup connections"""
        if self.neo4j_client:
            self.neo4j_client.close()

async def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(
        description="Risk Query CLI - Natural language interface to risk database",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s "show me high risk domains"
  %(prog)s "which domains have incidents?" --verbose
  %(prog)s --providers
  %(prog)s --examples
  
Environment Variables:
  ANTHROPIC_API_KEY    API key for Anthropic Claude
  MISTRAL_API_KEY      API key for Mistral AI
        """
    )
    
    # Main arguments
    parser.add_argument(
        "query",
        nargs="?",
        help="Natural language query to execute"
    )
    
    # Options
    parser.add_argument(
        "--config", "-c",
        help="Path to configuration file (default: config/config.yaml)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed output including Cypher queries and sample data"
    )
    
    parser.add_argument(
        "--raw", "-r",
        action="store_true",
        help="Output raw JSON result"
    )
    
    parser.add_argument(
        "--providers", "-p",
        action="store_true",
        help="Show available AI providers and current configuration"
    )
    
    parser.add_argument(
        "--examples", "-e",
        action="store_true",
        help="Show example queries"
    )
    
    args = parser.parse_args()
    
    # Initialize CLI
    cli = RiskQueryCLI(args.config)
    
    try:
        # Handle special commands
        if args.providers:
            cli.show_providers()
            return
        
        if args.examples:
            cli.show_examples()
            return
        
        # Check if query provided
        if not args.query:
            print("❌ No query provided. Use --help for usage information.")
            print("\n💡 Try: risk_query_cli.py --examples")
            sys.exit(1)
        
        # Execute query
        if args.raw:
            result = await cli.execute_query(args.query, args.verbose, raw=True)
            print(json.dumps(result, indent=2, default=str))
        else:
            await cli.execute_query(args.query, args.verbose)
    
    except KeyboardInterrupt:
        print("\n\n⏹️  Query interrupted by user")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
    finally:
        cli.cleanup()

if __name__ == "__main__":
    # Check Python version
    if sys.version_info < (3, 7):
        print("❌ Python 3.7 or higher is required")
        sys.exit(1)
    
    asyncio.run(main())