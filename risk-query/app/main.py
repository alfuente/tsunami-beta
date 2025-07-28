import os
import sys
import logging
import yaml
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any
import json
from datetime import datetime, date

# Add the app directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from query_processor import QueryProcessor
from neo4j_client import Neo4jClient, serialize_neo4j_value
from ai_client_factory import create_ai_client, get_supported_providers

class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        return serialize_neo4j_value(obj)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load configuration
def load_config():
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "config.yaml")
    try:
        with open(config_path, 'r') as file:
            return yaml.safe_load(file)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        return {}

config = load_config()

# Initialize FastAPI app
app = FastAPI(
    title="Risk Query Service",
    description="Natural language query interface for risk graph data",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.get("server", {}).get("cors_origins", ["*"]),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize clients
neo4j_client = None
ai_client = None
query_processor = None

@app.on_event("startup")
async def startup_event():
    global neo4j_client, ai_client, query_processor
    
    logger.info("Starting Risk Query Service...")
    
    try:
        # Initialize Neo4j client
        neo4j_config = config.get("neo4j", {})
        neo4j_client = Neo4jClient(
            uri=neo4j_config.get("uri", "bolt://localhost:7687"),
            user=neo4j_config.get("user", "neo4j"),
            password=neo4j_config.get("password", "password"),
            database=neo4j_config.get("database", "neo4j")
        )
        
        # Initialize AI client based on configuration
        provider = config.get("ai_provider", "ollama")
        logger.info(f"Initializing AI client: {provider}")
        
        ai_client = create_ai_client(config)
        
        # Test AI client connection
        connection_test = await ai_client.test_connection()
        logger.info(f"AI client connection test: {connection_test.get('status', 'unknown')}")
        
        # Initialize query processor
        query_processor = QueryProcessor(neo4j_client, ai_client)
        
        logger.info("Risk Query Service started successfully")
        
    except Exception as e:
        logger.error(f"Failed to start service: {e}")
        raise

@app.on_event("shutdown")
async def shutdown_event():
    global neo4j_client, ai_client
    
    logger.info("Shutting down Risk Query Service...")
    
    if neo4j_client:
        neo4j_client.close()
    
    logger.info("Risk Query Service shut down")

# Request/Response models
class QueryRequest(BaseModel):
    query: str
    context: Optional[Dict[str, Any]] = None

class QueryResponse(BaseModel):
    response: str
    cypher_query: Optional[str] = None
    raw_results: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None

# Health check endpoint
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "Risk Query Service",
        "version": "1.0.0"
    }

# Main query endpoint
@app.post("/api/query")
async def process_query(request: QueryRequest):
    if not query_processor:
        raise HTTPException(status_code=503, detail="Service not initialized")
    
    try:
        logger.info(f"Processing query: {request.query[:100]}...")
        
        result = await query_processor.process_query(
            query=request.query,
            context=request.context
        )
        
        # Ensure all data is properly serialized
        serialized_result = serialize_neo4j_value(result)
        
        return JSONResponse(
            content=serialized_result,
            headers={"Content-Type": "application/json"}
        )
        
    except Exception as e:
        logger.error(f"Query processing error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Get available models endpoint
@app.get("/api/models")
async def get_available_models():
    if not ai_client:
        raise HTTPException(status_code=503, detail="AI client not initialized")
    
    try:
        models = await ai_client.list_models()
        provider = config.get("ai_provider", "unknown")
        return {
            "provider": provider,
            "models": models
        }
    except Exception as e:
        logger.error(f"Failed to get models: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Test Neo4j connection endpoint
@app.get("/api/test/neo4j")
async def test_neo4j_connection():
    if not neo4j_client:
        raise HTTPException(status_code=503, detail="Neo4j client not initialized")
    
    try:
        result = neo4j_client.test_connection()
        serialized_result = serialize_neo4j_value({"status": "connected", "result": result})
        return JSONResponse(content=serialized_result)
    except Exception as e:
        logger.error(f"Neo4j connection test failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Test AI client connection endpoint
@app.get("/api/test/ai")
async def test_ai_connection():
    if not ai_client:
        raise HTTPException(status_code=503, detail="AI client not initialized")
    
    try:
        result = await ai_client.test_connection()
        provider = config.get("ai_provider", "unknown")
        return {
            "provider": provider,
            "status": "connected", 
            "result": result
        }
    except Exception as e:
        logger.error(f"AI client connection test failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Get supported AI providers endpoint
@app.get("/api/providers")
async def get_supported_providers_endpoint():
    try:
        providers = get_supported_providers()
        current_provider = config.get("ai_provider", "ollama")
        return {
            "current_provider": current_provider,
            "supported_providers": providers
        }
    except Exception as e:
        logger.error(f"Failed to get providers: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    
    server_config = config.get("server", {})
    host = server_config.get("host", "0.0.0.0")
    port = server_config.get("port", 8003)
    
    uvicorn.run(app, host=host, port=port)