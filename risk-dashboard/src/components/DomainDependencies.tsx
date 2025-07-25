import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Chip,
  Grid,
  CircularProgress,
  Alert,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Tabs,
  Tab,
  IconButton,
  Collapse,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  List,
  ListItem,
  ListItemText,
  Tooltip
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Security as SecurityIcon,
  Cloud as CloudIcon,
  Email as EmailIcon,
  Dns as DnsIcon,
  Code as CodeIcon,
  Analytics as AnalyticsIcon,
  Business as BusinessIcon,
  Timeline as TimelineIcon,
  AccountTree as GraphIcon
} from '@mui/icons-material';
import { dependencyApi } from '../services/api';
import DependencyGraphView from './DependencyGraphView';

interface DomainDependenciesProps {
  domain: string;
  onBaseDomainDetected?: (baseDomain: string) => void;
}

interface Provider {
  id: string;
  name: string;
  type: 'provider';
  risk_score?: number;
  risk_tier?: string;
  source: string;
  service_type: string;
  confidence: number;
  subdomain?: string;
  service_name?: string;
}

interface Service {
  id: string;
  name: string;
  type: 'service';
  risk_score?: number;
  risk_tier?: string;
  source: string;
  service_type: string;
  confidence: number;
  subdomain?: string;
}

interface DependencyData {
  domain: string;
  node_type?: string;
  base_domain?: string;  
  providers: Provider[];
  services: Service[];
  summary: {
    total_providers: number;
    total_services: number;
    risk_analysis: {
      average_provider_risk: number;
      average_service_risk: number;
      high_risk_providers: number;
      high_risk_services: number;
      total_dependencies: number;
      risk_distribution: {
        low_risk: number;
        medium_risk: number;
        high_risk: number;
      };
    };
  };
}

const getRiskColor = (riskTier?: string, riskScore?: number): string => {
  if (riskTier) {
    switch (riskTier.toLowerCase()) {
      case 'critical': return '#d32f2f';
      case 'high': return '#f57c00';
      case 'medium': return '#1976d2';
      case 'low': return '#388e3c';
      default: return '#757575';
    }
  }
  if (riskScore !== undefined) {
    if (riskScore >= 8) return '#d32f2f';
    if (riskScore >= 6) return '#f57c00';
    if (riskScore >= 4) return '#1976d2';
    return '#388e3c';
  }
  return '#757575';
};

const getServiceTypeIcon = (serviceType: string) => {
  switch (serviceType.toLowerCase()) {
    case 'security': return <SecurityIcon />;
    case 'cloud': return <CloudIcon />;
    case 'email': return <EmailIcon />;
    case 'hosting': case 'cdn': return <DnsIcon />;
    case 'development': return <CodeIcon />;
    case 'analytics': return <AnalyticsIcon />;
    case 'saas': return <BusinessIcon />;
    default: return <BusinessIcon />;
  }
};

const DomainDependencies: React.FC<DomainDependenciesProps> = ({ domain, onBaseDomainDetected }) => {
  const [data, setData] = useState<DependencyData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tabValue, setTabValue] = useState(0);
  const [expandedSections, setExpandedSections] = useState<{[key: string]: boolean}>({
    summary: true,
    riskAnalysis: true
  });
  const [pathsDialogOpen, setPathsDialogOpen] = useState(false);
  const [dependencyPaths, setDependencyPaths] = useState<any>(null);
  const [graphDialogOpen, setGraphDialogOpen] = useState(false);

  useEffect(() => {
    fetchDependencies();
  }, [domain]); // eslint-disable-line react-hooks/exhaustive-deps

  const fetchDependencies = async () => {
    try {
      setLoading(true);
      setError(null);
      const result = await dependencyApi.getDomainProvidersAndServices(domain, true, false);
      setData(result);
      
      // If this is a subdomain, notify parent component about the base domain
      if (result.node_type === 'Subdomain' && result.base_domain && onBaseDomainDetected) {
        onBaseDomainDetected(result.base_domain);
      }
    } catch (err: any) {
      setError(err.response?.data?.message || err.message || 'Failed to load dependencies');
    } finally {
      setLoading(false);
    }
  };

  const fetchDependencyPaths = async () => {
    try {
      const result = await dependencyApi.getDomainProvidersAndServices(domain, true, true);
      setDependencyPaths(result.dependency_paths);
      setPathsDialogOpen(true);
    } catch (err: any) {
      setError('Failed to load dependency paths');
    }
  };

  const toggleSection = (section: string) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="300px">
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error" sx={{ m: 2 }}>
        {error}
      </Alert>
    );
  }

  if (!data) {
    return (
      <Alert severity="info" sx={{ m: 2 }}>
        No dependency data available for {domain}
      </Alert>
    );
  }

  const renderSummaryCard = () => (
    <Card sx={{ mb: 2 }}>
      <CardContent>
        <Box display="flex" alignItems="center" justifyContent="space-between">
          <Typography variant="h6" gutterBottom>
            Dependencies Summary
          </Typography>
          <IconButton
            onClick={() => toggleSection('summary')}
            size="small"
          >
            {expandedSections.summary ? <ExpandLessIcon /> : <ExpandMoreIcon />}
          </IconButton>
        </Box>
        
        <Collapse in={expandedSections.summary}>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={6} md={3}>
              <Box textAlign="center">
                <Typography variant="h4" color="primary">
                  {data.summary.total_providers}
                </Typography>
                <Typography variant="body2" color="textSecondary">
                  Providers
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={6} md={3}>
              <Box textAlign="center">
                <Typography variant="h4" color="secondary">
                  {data.summary.total_services}
                </Typography>
                <Typography variant="body2" color="textSecondary">
                  Services
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={6} md={3}>
              <Box textAlign="center">
                <Typography variant="h4" color="warning.main">
                  {(data.summary.risk_analysis?.high_risk_providers || 0) + (data.summary.risk_analysis?.high_risk_services || 0)}
                </Typography>
                <Typography variant="body2" color="textSecondary">
                  High Risk
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={6} md={3}>
              <Box textAlign="center">
                <Typography variant="h4" color="success.main">
                  {data.summary.risk_analysis?.total_dependencies || 0}
                </Typography>
                <Typography variant="body2" color="textSecondary">
                  Total Dependencies
                </Typography>
              </Box>
            </Grid>
          </Grid>
        </Collapse>
      </CardContent>
    </Card>
  );

  const renderRiskAnalysisCard = () => (
    <Card sx={{ mb: 2 }}>
      <CardContent>
        <Box display="flex" alignItems="center" justifyContent="space-between">
          <Typography variant="h6" gutterBottom>
            Risk Analysis
          </Typography>
          <IconButton
            onClick={() => toggleSection('riskAnalysis')}
            size="small"
          >
            {expandedSections.riskAnalysis ? <ExpandLessIcon /> : <ExpandMoreIcon />}
          </IconButton>
        </Box>
        
        <Collapse in={expandedSections.riskAnalysis}>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" gutterBottom>
                Average Risk Scores
              </Typography>
              <Box display="flex" gap={2}>
                <Chip
                  label={`Providers: ${(data.summary.risk_analysis?.average_provider_risk || 0).toFixed(1)}`}
                  color="primary"
                  variant="outlined"
                />
                <Chip
                  label={`Services: ${(data.summary.risk_analysis?.average_service_risk || 0).toFixed(1)}`}
                  color="secondary"
                  variant="outlined"
                />
              </Box>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" gutterBottom>
                Risk Distribution
              </Typography>
              <Box display="flex" gap={1}>
                <Chip
                  label={`Low: ${data.summary.risk_analysis?.risk_distribution?.low_risk || 0}`}
                  size="small"
                  sx={{ backgroundColor: '#e8f5e8' }}
                />
                <Chip
                  label={`Medium: ${data.summary.risk_analysis?.risk_distribution?.medium_risk || 0}`}
                  size="small"
                  sx={{ backgroundColor: '#e3f2fd' }}
                />
                <Chip
                  label={`High: ${data.summary.risk_analysis?.risk_distribution?.high_risk || 0}`}
                  size="small"
                  sx={{ backgroundColor: '#fff3e0' }}
                />
              </Box>
            </Grid>
          </Grid>
          
          <Box sx={{ mt: 2, display: 'flex', gap: 1 }}>
            <Button
              variant="outlined"
              startIcon={<TimelineIcon />}
              onClick={fetchDependencyPaths}
              size="small"
            >
              View Dependency Paths
            </Button>
            <Button
              variant="outlined"
              startIcon={<GraphIcon />}
              onClick={() => setGraphDialogOpen(true)}
              size="small"
            >
              View Graph
            </Button>
          </Box>
        </Collapse>
      </CardContent>
    </Card>
  );

  const renderDependencyTable = (items: (Provider | Service)[], type: 'providers' | 'services') => (
    <TableContainer component={Paper}>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Name</TableCell>
            <TableCell>Type</TableCell>
            <TableCell>Source</TableCell>
            <TableCell>Risk</TableCell>
            <TableCell>Confidence</TableCell>
            <TableCell>Details</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {items.map((item) => (
            <TableRow key={item.id}>
              <TableCell>
                <Box display="flex" alignItems="center" gap={1}>
                  {getServiceTypeIcon(item.service_type)}
                  <Typography variant="body2" fontWeight="medium">
                    {item.name}
                  </Typography>
                </Box>
              </TableCell>
              <TableCell>
                <Chip
                  label={item.service_type}
                  size="small"
                  variant="outlined"
                />
              </TableCell>
              <TableCell>
                <Typography variant="body2" color="textSecondary">
                  {item.source.replace(/_/g, ' ')}
                </Typography>
              </TableCell>
              <TableCell>
                {item.risk_score !== undefined && (
                  <Tooltip title={`Score: ${item.risk_score} | Tier: ${item.risk_tier || 'Unknown'}`}>
                    <Chip
                      label={item.risk_score.toFixed(1)}
                      size="small"
                      sx={{
                        backgroundColor: getRiskColor(item.risk_tier, item.risk_score),
                        color: 'white'
                      }}
                    />
                  </Tooltip>
                )}
              </TableCell>
              <TableCell>
                <Typography variant="body2">
                  {(item.confidence * 100).toFixed(0)}%
                </Typography>
              </TableCell>
              <TableCell>
                {item.subdomain && (
                  <Typography variant="body2" color="textSecondary">
                    via {item.subdomain}
                  </Typography>
                )}
                {'service_name' in item && item.service_name && (
                  <Typography variant="body2" color="textSecondary">
                    service: {item.service_name}
                  </Typography>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );

  const renderPathsDialog = () => (
    <Dialog
      open={pathsDialogOpen}
      onClose={() => setPathsDialogOpen(false)}
      maxWidth="md"
      fullWidth
    >
      <DialogTitle>Dependency Paths for {domain}</DialogTitle>
      <DialogContent>
        {dependencyPaths && dependencyPaths.paths?.length > 0 ? (
          <List>
            {dependencyPaths.paths.map((path: any, index: number) => (
              <ListItem key={index} divider>
                <ListItemText
                  primary={
                    <Typography variant="subtitle2">
                      {path.target_name} ({path.target_type})
                    </Typography>
                  }
                  secondary={
                    <Typography variant="body2" color="textSecondary">
                      Path: {path.path.join(' → ')} (Length: {path.path_length})
                    </Typography>
                  }
                />
              </ListItem>
            ))}
          </List>
        ) : (
          <Typography>No dependency paths found.</Typography>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={() => setPathsDialogOpen(false)}>Close</Button>
      </DialogActions>
    </Dialog>
  );

  const renderGraphDialog = () => (
    <Dialog
      open={graphDialogOpen}
      onClose={() => setGraphDialogOpen(false)}
      maxWidth="lg"
      fullWidth
      PaperProps={{
        sx: { height: '90vh' }
      }}
    >
      <DialogTitle>
        Dependency Graph for {domain}
        <IconButton
          aria-label="close"
          onClick={() => setGraphDialogOpen(false)}
          sx={{
            position: 'absolute',
            right: 8,
            top: 8,
            color: (theme) => theme.palette.grey[500],
          }}
        >
          ×
        </IconButton>
      </DialogTitle>
      <DialogContent sx={{ p: 0, height: 'calc(100% - 64px)' }}>
        <DependencyGraphView 
          domain={domain} 
          height={600}
          showFullscreen={true}
        />
      </DialogContent>
    </Dialog>
  );

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
        <Box>
          <Typography variant="h5" gutterBottom>
            Dependencies for {domain}
          </Typography>
          {data?.node_type === 'Subdomain' && data?.base_domain && (
            <Typography variant="body2" color="textSecondary">
              Subdomain of: {data.base_domain}
            </Typography>
          )}
        </Box>
        <Button
          variant="contained"
          startIcon={<GraphIcon />}
          onClick={() => setGraphDialogOpen(true)}
          size="large"
          sx={{ 
            backgroundColor: '#4caf50',
            '&:hover': { backgroundColor: '#45a049' },
            fontWeight: 'bold',
            fontSize: '1.1rem',
            px: 3
          }}
        >
          VIEW GRAPH
        </Button>
      </Box>
      
      {renderSummaryCard()}
      {renderRiskAnalysisCard()}
      
      <Card>
        <CardContent>
          <Tabs
            value={tabValue}
            onChange={(_, newValue) => setTabValue(newValue)}
            sx={{ borderBottom: 1, borderColor: 'divider', mb: 2 }}
          >
            <Tab label={`Providers (${data.providers.length})`} />
            <Tab label={`Services (${data.services.length})`} />
          </Tabs>
          
          {tabValue === 0 && (
            <Box>
              {data.providers.length > 0 ? (
                renderDependencyTable(data.providers, 'providers')
              ) : (
                <Alert severity="info">
                  No providers found for this domain.
                </Alert>
              )}
            </Box>
          )}
          
          {tabValue === 1 && (
            <Box>
              {data.services.length > 0 ? (
                renderDependencyTable(data.services, 'services')
              ) : (
                <Alert severity="info">
                  No services found for this domain.
                </Alert>
              )}
            </Box>
          )}
        </CardContent>
      </Card>
      
      {renderPathsDialog()}
      {renderGraphDialog()}
    </Box>
  );
};

export default DomainDependencies;