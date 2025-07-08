# Risk Graph Service

## Overview

The Risk Graph Service is a Quarkus-based REST API service that provides risk analysis and domain provisioning capabilities. It uses Neo4j as the graph database to store and analyze risk relationships between domains, and integrates with external services for comprehensive risk assessment.

## Features

- **Domain Provisioning**: Automatically provision domains in the risk graph with configurable depth scanning
- **Risk Calculation**: Multi-dimensional risk scoring system including:
  - Base score calculation
  - Third-party risk assessment
  - Incident impact analysis
  - Context-based risk boosting
- **Risk Propagation**: Analyze and propagate risk scores across domain hierarchies
- **Graph Analytics**: Query and analyze risk relationships using Neo4j graph database

## Technology Stack

- **Framework**: Quarkus 3.15.0
- **Java Version**: 21
- **Database**: Neo4j (Graph Database)
- **REST API**: JAX-RS with RESTEasy Reactive
- **JSON Processing**: Jackson

## Project Structure

```
src/
├── main/
│   ├── java/com/example/risk/
│   │   ├── dao/
│   │   │   └── GraphQueries.java          # Neo4j graph queries
│   │   ├── resource/
│   │   │   └── ProvisionResource.java     # REST API endpoints
│   │   ├── service/
│   │   │   ├── BaseScoreCalculator.java
│   │   │   ├── ContextBoostCalculator.java
│   │   │   ├── DomainProvisioningService.java
│   │   │   ├── IncidentImpactCalculator.java
│   │   │   ├── RiskCalculator.java
│   │   │   ├── RiskPropagationService.java
│   │   │   └── ThirdPartyScoreCalculator.java
│   │   └── validation/
│   │       └── RiskValidationService.java
│   └── resources/
│       └── application.properties
└── test/
    └── java/com/example/risk/service/
        ├── BaseScoreCalculatorTest.java
        ├── IncidentImpactCalculatorTest.java
        └── RiskCalculatorTest.java
```

## Configuration

Configure the service through `application.properties`:

```properties
# Neo4j Configuration
quarkus.neo4j.uri=bolt://localhost:7687
quarkus.neo4j.authentication.username=neo4j
quarkus.neo4j.authentication.password=test

# HTTP Configuration
quarkus.http.port=8080

# Risk Loader Configuration
risk.loader.path=/opt/risk/bin/risk_loader_advanced.py
warehouse.snapshot.url=http://risk-warehouse:8081/snapshot/domain
ipinfo.token=YOUR_IPINFO_TOKEN
```

## API Endpoints

### Domain Provisioning

- **POST** `/provision/domain/{fqdn}`
  - **Description**: Provision a domain in the risk graph
  - **Parameters**:
    - `fqdn` (path): Fully qualified domain name
    - `depth` (query, optional): Scanning depth (default: 1)
  - **Response**: `{"created": boolean}`

## OpenAPI Documentation

The service includes comprehensive OpenAPI/Swagger documentation:

- **Swagger UI**: Available at `/swagger-ui` when the service is running
- **OpenAPI Spec**: Available at `/q/openapi` in JSON format
- **ReDoc**: Available at `/q/swagger-ui` for alternative documentation view

### API Documentation Features

- Complete endpoint documentation with examples
- Request/response schema definitions
- Parameter descriptions and validation rules
- Error response documentation
- Interactive API testing interface

### Accessing the Documentation

1. Start the service: `./mvnw quarkus:dev`
2. Open your browser to `http://localhost:8080/swagger-ui`
3. Explore and test the API endpoints directly from the UI

## Running the Service

### Prerequisites

- Java 21
- Maven 3.8+
- Neo4j database running on `bolt://localhost:7687`
- Python 3 with risk loader script at configured path

### Development Mode

```bash
./mvnw quarkus:dev
```

### Production Build

```bash
./mvnw package
java -jar target/quarkus-app/quarkus-run.jar
```

### Docker

```bash
docker build -t risk-graph-service .
docker run -p 8080:8080 risk-graph-service
```

## Testing

Run tests with Maven:

```bash
./mvnw test
```

## Architecture

The service follows a layered architecture:

1. **Resource Layer**: REST API endpoints using JAX-RS
2. **Service Layer**: Business logic and risk calculation algorithms
3. **DAO Layer**: Data access and Neo4j queries
4. **Validation Layer**: Input validation and business rules

### Risk Calculation Components

- **BaseScoreCalculator**: Fundamental risk scoring based on domain characteristics
- **ThirdPartyScoreCalculator**: External risk assessment integration
- **IncidentImpactCalculator**: Historical incident impact analysis
- **ContextBoostCalculator**: Context-aware risk adjustments
- **RiskPropagationService**: Risk propagation across domain hierarchies

## Dependencies

The service integrates with:

- **Neo4j**: Graph database for storing domain relationships
- **Risk Warehouse**: External service for domain snapshots
- **IPInfo**: IP geolocation and threat intelligence
- **Python Risk Loader**: Advanced risk data loading script

## Contributing

1. Ensure all tests pass: `./mvnw test`
2. Follow Java code style conventions
3. Add tests for new functionality
4. Update documentation as needed

## License

Copyright © 2024 Example Corp. All rights reserved.