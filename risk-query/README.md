# Risk Query Service

Natural language query interface for the risk graph database using Ollama for LLM processing.

## Features

- Convert natural language queries to Cypher queries using Ollama
- Execute queries against Neo4j database
- Interpret and format results in natural language
- RESTful API interface
- Integration with existing risk management dashboard

## Prerequisites

- Python 3.8+
- Ollama installed and running
- Neo4j database with risk graph data
- Access to the existing risk-graph-service

## Installation

1. Install Ollama if not already installed:
```bash
curl -fsSL https://ollama.ai/install.sh | sh
```

2. Create virtual environment and install dependencies:
```bash
cd risk-query
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

3. Configure the service by editing `config/config.yaml`

## Configuration

Edit `config/config.yaml` to configure:
- Ollama host and model settings
- Neo4j connection parameters
- Server settings and CORS origins

## Usage

### Using the Management Script

Start all services including risk-query:
```bash
./manage-services.sh start-dev
```

Start only the risk-query service:
```bash
./manage-services.sh start-query
```

Check service status:
```bash
./manage-services.sh status
```

View logs:
```bash
./manage-services.sh logs query
```

### Manual Startup

```bash
cd risk-query
source venv/bin/activate
python app/main.py
```

The service will start on `http://localhost:8003`

## API Endpoints

- `POST /api/query` - Process natural language query
- `GET /health` - Health check
- `GET /api/models` - List available Ollama models
- `GET /api/test/neo4j` - Test Neo4j connection
- `GET /api/test/ollama` - Test Ollama connection

## Example Queries

- "Show me all domains with high risk scores"
- "Which domains have the most dependencies?"
- "Find domains with critical security vulnerabilities"
- "What are the third-party providers for financial services domains?"
- "Show me domains that haven't been assessed recently"

## Integration

The service is integrated with the risk-dashboard React application through the new "Queries" menu item. Users can enter natural language queries and receive interpreted results along with the generated Cypher queries.

## Development

The service uses:
- FastAPI for the web framework
- Neo4j Python driver for database connectivity
- Ollama Python client for LLM integration
- Pydantic for data validation
- Uvicorn for ASGI server