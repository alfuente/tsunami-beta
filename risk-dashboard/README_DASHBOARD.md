# Risk Dashboard

A React + Material-UI dashboard for managing and visualizing domain risk analysis data from the risk-graph-service API.

## Features

- **Dashboard Overview**: Security metrics, risk distribution charts, and high-risk node alerts
- **Domain Management**: Add, view, filter, and search domains with risk scoring
- **Domain Details**: Comprehensive view of domain security, DNS, and infrastructure information
- **Risk Analysis**: Advanced analytics with charts, trends, and filtering capabilities

## API Integration

The dashboard integrates with the following risk-graph-service endpoints:

### Domain APIs (`/api/v1/domains`)
- `GET /{fqdn}` - Get domain information
- `GET /` - List domains with filtering
- `GET /tree/{rootFqdn}` - Get domain tree
- `GET /critical` - Get critical domains
- `GET /security-summary` - Get security overview

### Risk Scoring APIs (`/api/v1/risk`)
- `GET /score/{nodeType}/{nodeId}` - Get risk score with breakdown
- `GET /high-risk` - Get high-risk nodes
- `GET /metrics` - Get risk calculation metrics
- `GET /scores/bulk` - Get bulk risk scores

### Calculation APIs (`/api/v1/calculations`)
- `POST /domain/{fqdn}` - Calculate domain risk
- `POST /domain-tree/{rootFqdn}` - Calculate domain tree risk
- `POST /bulk` - Bulk risk recalculation

## Setup and Installation

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Configure API endpoint:**
   Update the `.env` file:
   ```
   REACT_APP_API_BASE_URL=http://localhost:8081
   ```

3. **Start the development server:**
   ```bash
   npm start
   ```

4. **Build for production:**
   ```bash
   npm run build
   ```

## Project Structure

```
src/
├── components/
│   └── Layout/
│       ├── Header.tsx
│       └── Sidebar.tsx
├── pages/
│   ├── Dashboard.tsx
│   ├── DomainManagement.tsx
│   ├── DomainDetail.tsx
│   └── RiskAnalysis.tsx
├── services/
│   └── api.ts
├── types/
│   └── api.ts
└── App.tsx
```

## Key Components

### Dashboard
- Security metrics overview
- Risk distribution pie chart
- Security metrics bar chart
- High-risk nodes list

### Domain Management
- Searchable and filterable domain table
- Add new domains with automatic risk calculation
- Navigation to detailed domain views

### Domain Details
- Comprehensive domain information
- Risk score breakdown
- Security, DNS, and infrastructure details
- Recent incidents
- Manual risk recalculation

### Risk Analysis
- Multiple chart visualizations
- Advanced filtering by node type and risk tier
- Risk threshold analysis
- High-risk nodes table

## Technologies Used

- **React 18** with TypeScript
- **Material-UI (MUI)** for components and theming
- **MUI X Charts** for data visualization
- **MUI X Data Grid** for data tables
- **React Router** for navigation
- **Axios** for API communication

## Available Scripts

- `npm start` - Runs the app in development mode
- `npm test` - Launches the test runner
- `npm run build` - Builds the app for production
- `npm run eject` - Ejects from Create React App (one-way operation)

## Environment Variables

- `REACT_APP_API_BASE_URL` - Base URL for the risk-graph-service API (default: http://localhost:8081)

## Browser Support

This project supports modern browsers that are compatible with React 18 and ES6+ features.

## Usage Instructions

1. **Start the risk-graph-service** on port 8081
2. **Start the dashboard** with `npm start`
3. **Access the dashboard** at http://localhost:3000

The dashboard will automatically connect to your risk-graph-service API and provide:
- Real-time domain risk monitoring
- Interactive charts and visualizations
- Domain management capabilities
- Risk analysis tools

## Note on Filtering

The current implementation includes basic filtering capabilities. For country and industry filtering, you would need to extend the API and domain model to include geographic and industry classification data.