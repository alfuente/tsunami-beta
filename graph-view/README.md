# 🌊 Tsunami Graph Visualization Module

A comprehensive 3D graph visualization system for the Tsunami domain analysis platform.

## Overview

This module provides interactive 3D visualization of the Neo4j graph database containing domain security analysis data. It includes a Python FastAPI backend and a modern web frontend using Three.js and 3D Force Graph.

## Architecture

```
graph-view/
├── backend/                    # Python FastAPI backend
│   ├── graph_visualization_api.py  # Main API server
│   ├── requirements.txt        # Python dependencies
│   ├── start_server.sh         # Startup script
│   └── venv/                   # Virtual environment
├── frontend/                   # Web frontend
│   ├── index.html             # 3D visualization interface
│   └── serve.py               # Simple HTTP server
└── README.md                  # This file
```

## Features

### Backend API (Port 8082)
- **Complete Graph Export**: Get all nodes and relationships with filtering options
- **Domain-Focused Views**: Explore specific domains and their connections
- **Provider Analysis**: View all domains using specific providers
- **Risk-Based Filtering**: Filter by risk levels (low, medium, high, critical)
- **Search Functionality**: Search across domains, providers, and technologies
- **Real-time Statistics**: Graph metrics and distribution analysis

### Frontend Visualization (Port 8083)
- **3D Interactive Graph**: Navigate through the graph in 3D space
- **Color-Coded Nodes**: Risk-based coloring and type-based categorization
- **Multiple View Modes**: Complete graph, domain focus, provider focus, risk filtering
- **Real-time Controls**: Adjust physics, filter subdomains, limit node count
- **Node Details**: Click on nodes to see detailed information
- **Search Integration**: Search and focus on specific nodes

## API Endpoints

### Health & Info
- `GET /` - API information and available endpoints
- `GET /health` - Health check and Neo4j connection status

### Graph Data
- `GET /graph/complete` - Complete graph with optional filtering
- `GET /graph/domain/{domain}` - Domain-focused subgraph
- `GET /graph/provider/{provider}` - Provider-focused subgraph
- `GET /graph/risk/{level}` - Risk-filtered graph (low, medium, high, critical)
- `GET /graph/search` - Search nodes by text query

### Statistics
- `GET /stats` - Comprehensive graph statistics

## Quick Start

### Prerequisites
- Neo4j running on `bolt://localhost:7687` with credentials `neo4j:test.password`
- Python 3.8+
- Modern web browser with WebGL support

### Starting the Backend
```bash
cd backend/
bash start_server.sh
```

The API will be available at: `http://localhost:8082`

### Starting the Frontend
```bash
cd frontend/
python3 serve.py
```

The visualization will be available at: `http://localhost:8083`

## Data Model Integration

The visualization reads from the Neo4j graph model documented in [GraphModel.md](../domain-backend/GraphModel.md).

### Supported Node Types
- **Domains**: Base domains with risk scores and security metadata
- **Subdomains**: Discovered subdomains with their analysis data
- **Providers**: Service providers (CDN, hosting, analytics, etc.)
- **Technologies**: Web technologies and their versions
- **Services**: Network services running on domains
- **Certificates**: SSL/TLS certificates and their properties
- **Vulnerabilities**: Security vulnerabilities linked to technologies

### Color Coding
- 🟢 **Green**: Low risk domains and valid certificates
- 🟡 **Yellow**: Medium risk domains and technologies
- 🟠 **Orange**: High risk domains
- 🔴 **Red**: Critical risk domains, expired certificates, critical vulnerabilities
- 🔵 **Blue**: CDN and infrastructure providers
- 🟣 **Purple**: Hosting providers and services
- 🌸 **Magenta**: Analytics and tracking services

## Configuration

### Backend Configuration
The backend API can be configured by modifying `graph_visualization_api.py`:

```python
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "test.password"
```

### Frontend Configuration
The frontend can be configured by modifying the `apiBaseUrl` in `index.html`:

```javascript
this.apiBaseUrl = 'http://localhost:8082';
```

## Usage Examples

### Complete Graph with Filtering
```bash
curl "http://localhost:8082/graph/complete?limit=100&include_subdomains=true&min_risk_score=50"
```

### Domain Analysis
```bash
curl "http://localhost:8082/graph/domain/example.com"
```

### Provider Usage Analysis
```bash
curl "http://localhost:8082/graph/provider/AWS CloudFront"
```

### Risk Analysis
```bash
curl "http://localhost:8082/graph/risk/critical"
```

### Search
```bash
curl "http://localhost:8082/graph/search?query_string=apache&node_types=Technology"
```

## Performance Considerations

- **Node Limits**: Default limit of 200 nodes for performance
- **Edge Optimization**: Relationships are color-coded for visual clarity
- **Physics Simulation**: Can be disabled for large graphs
- **Progressive Loading**: Consider implementing pagination for very large datasets

## Extending the Visualization

### Adding New Node Types
1. Update the color mapping in `get_node_color()`
2. Update the size mapping in `get_node_size()`
3. Add to the legend in `index.html`

### Custom Queries
Add new endpoints to `graph_visualization_api.py` following the existing patterns.

### Visual Enhancements
Modify the Three.js configuration in `initializeGraph()` method.

## Troubleshooting

### Backend Issues
- Verify Neo4j is running: `docker ps | grep neo4j`
- Check Neo4j credentials: `docker exec neo4j cypher-shell -u neo4j -p test.password "RETURN 1"`
- View API logs: Check the console output when running `start_server.sh`

### Frontend Issues
- Ensure backend is running on port 8082
- Check browser console for JavaScript errors
- Verify CORS settings in the backend

### Performance Issues
- Reduce node limit in the controls
- Disable physics simulation for large graphs
- Use specific queries instead of complete graph

## Integration with Tsunami Platform

This visualization module integrates with:
- **Domain Backend**: Reads data from the same Neo4j instance
- **Risk Dashboard**: Provides 3D visualization of analyzed domains
- **Risk Graph Service**: Can trigger risk calculations from the UI

## Development

### Backend Development
```bash
cd backend/
source venv/bin/activate
pip install -r requirements.txt
uvicorn graph_visualization_api:app --reload --port 8082
```

### Frontend Development
The frontend is a single HTML file with embedded JavaScript. For development, simply edit `index.html` and refresh the browser.

## License

This module is part of the Tsunami domain analysis platform.