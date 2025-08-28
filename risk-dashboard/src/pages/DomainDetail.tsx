import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  Button,
  Card,
  CardContent,
  Grid,
  Chip,
  CircularProgress,
  Alert,
  Divider,
  List,
  ListItem,
  ListItemText,
  Dialog,
  DialogTitle,
  DialogContent,
  IconButton,
} from '@mui/material';
import {
  ArrowBack as ArrowBackIcon,
  Refresh as RefreshIcon,
  Security as SecurityIcon,
  Public as PublicIcon,
  Storage as StorageIcon,
  AccountTree as GraphIcon,
} from '@mui/icons-material';
import { domainApi, riskApi, calculationApi, statisticsApi } from '../services/api';
import { DomainResponse, RiskScoreResponse } from '../types/api';
import DomainDependencies from '../components/DomainDependencies';
import DependencyGraphView from '../components/DependencyGraphView';

const DomainDetail: React.FC = () => {
  const { fqdn } = useParams<{ fqdn: string }>();
  const navigate = useNavigate();
  const [domain, setDomain] = useState<DomainResponse | null>(null);
  const [riskScore, setRiskScore] = useState<RiskScoreResponse | null>(null);
  const [domainPerformance, setDomainPerformance] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [calculating, setCalculating] = useState(false);
  const [baseDomain, setBaseDomain] = useState<string | null>(null);
  const [graphDialogOpen, setGraphDialogOpen] = useState(false);

  const fetchDomainData = async () => {
    if (!fqdn) return;
    
    try {
      setLoading(true);
      // First load critical domain and risk data
      const [domainData, riskData] = await Promise.all([
        domainApi.getDomain(fqdn, true),
        riskApi.getRiskScore('domain', fqdn, true)
      ]);
      
      setDomain(domainData);
      setRiskScore(riskData);
      
      // Load performance data separately with timeout handling
      try {
        const performanceData = await Promise.race([
          statisticsApi.getDomainPerformance(fqdn),
          new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Performance API timeout')), 5000)
          )
        ]);
        setDomainPerformance(performanceData);
      } catch (perfError) {
        console.warn('Performance data not available:', perfError);
        setDomainPerformance({
          available: false,
          domain: fqdn,
          message: 'Performance data unavailable (timeout)',
          timestamp: new Date().toISOString()
        });
      }
      
      setError(null);
    } catch (err) {
      setError('Failed to load domain data');
      console.error('Domain detail error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleRecalculateRisk = async () => {
    if (!fqdn) return;
    
    try {
      setCalculating(true);
      const response = await calculationApi.calculateDomainRisk(fqdn, false);
      console.log('Risk calculation started:', response);
      
      // Wait a bit longer for calculation to complete
      setTimeout(() => {
        fetchDomainData();
        setCalculating(false);
      }, 3000);
    } catch (err) {
      setCalculating(false);
      console.error('Risk calculation error:', err);
      setError('Failed to recalculate risk. Please try again.');
    }
  };

  // Helper function to extract base domain from FQDN
  const extractBaseDomain = (fqdn: string): string | null => {
    const parts = fqdn.split('.');
    if (parts.length > 2) {
      // For subdomains, return domain + TLD (e.g., app.entel.cl -> entel.cl)
      return parts.slice(-2).join('.');
    }
    return null; // This is already a base domain
  };

  useEffect(() => {
    if (fqdn) {
      const base = extractBaseDomain(fqdn);
      setBaseDomain(base);
    }
    fetchDomainData();
  }, [fqdn]); // eslint-disable-line react-hooks/exhaustive-deps

  console.log('DomainDetail render - loading:', loading, 'error:', error, 'domain:', !!domain, 'fqdn:', fqdn);

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" height="400px">
        <CircularProgress />
        <Typography sx={{ ml: 2 }}>Loading {fqdn}...</Typography>
      </Box>
    );
  }

  if (error || !domain) {
    return (
      <Box>
        <Button startIcon={<ArrowBackIcon />} onClick={() => navigate('/domains')}>
          Back to Domains
        </Button>
        <Alert severity="error" sx={{ mt: 2 }}>
          {error || 'Domain not found'} - {fqdn}
          <br />
          Debug: domain exists: {!!domain}, error: {error}
        </Alert>
      </Box>
    );
  }

  const getRiskTierColor = (tier: string): 'default' | 'primary' | 'secondary' | 'error' | 'info' | 'success' | 'warning' => {
    switch (tier.toLowerCase()) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  return (
    <Box>
      
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Box display="flex" alignItems="center">
          <Box display="flex" gap={1} mr={2}>
            <Button
              startIcon={<ArrowBackIcon />}
              onClick={() => baseDomain ? navigate(`/domains/base-domains/${baseDomain}`) : navigate('/domains')}
              variant={baseDomain ? "outlined" : "contained"}
            >
              {baseDomain ? `Back to ${baseDomain}` : 'Back to Domains'}
            </Button>
            {baseDomain && (
              <Button
                variant="text"
                onClick={() => navigate('/domains')}
                sx={{ ml: 1 }}
              >
                All Domains
              </Button>
            )}
          </Box>
          <Box>
            <Typography variant="h4">{domain.fqdn}</Typography>
            {baseDomain && (
              <Typography variant="body2" color="textSecondary">
                Subdomain of {baseDomain}
              </Typography>
            )}
          </Box>
        </Box>
        <Box display="flex" gap={1}>
          <Button
            variant="contained"
            startIcon={<GraphIcon />}
            onClick={() => setGraphDialogOpen(true)}
            sx={{ 
              backgroundColor: '#4caf50',
              '&:hover': { backgroundColor: '#45a049' },
              fontWeight: 'bold'
            }}
          >
            VIEW GRAPH
          </Button>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={fetchDomainData}
          >
            Refresh
          </Button>
          <Button
            variant="contained"
            startIcon={calculating ? <CircularProgress size={20} /> : <SecurityIcon />}
            onClick={handleRecalculateRisk}
            disabled={calculating}
          >
            {calculating ? 'Calculating...' : 'Recalculate Risk'}
          </Button>
        </Box>
      </Box>

      <Grid container spacing={3}>
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Risk Overview
              </Typography>
              <Box display="flex" alignItems="center" mb={2}>
                <Typography variant="h3" color="primary" sx={{ mr: 2 }}>
                  {domain.risk_score.toFixed(1)}
                </Typography>
                <Chip 
                  label={domain.risk_tier} 
                  color={getRiskTierColor(domain.risk_tier)}
                />
              </Box>
              <Typography variant="body2" color="textSecondary" gutterBottom>
                Last Calculated: {domain.last_calculated ? new Date(domain.last_calculated).toLocaleString() : 'Never'}
              </Typography>
              
              {riskScore?.score_breakdown && (
                <Box mt={2}>
                  <Divider sx={{ mb: 2 }} />
                  <Typography variant="subtitle2" gutterBottom>Score Breakdown:</Typography>
                  <Typography variant="body2">Base Score: {riskScore.score_breakdown.base_score.toFixed(1)}</Typography>
                  <Typography variant="body2">Third Party: {riskScore.score_breakdown.third_party_score.toFixed(1)}</Typography>
                  <Typography variant="body2">Incident Impact: {riskScore.score_breakdown.incident_impact.toFixed(1)}</Typography>
                  <Typography variant="body2">Context Boost: {riskScore.score_breakdown.context_boost.toFixed(1)}</Typography>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Detailed Risk Calculation Section */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                📊 Detailed Risk Score Calculation
              </Typography>
              <Typography variant="body2" color="textSecondary" sx={{ mb: 3 }}>
                This section shows how the risk score is calculated based on subdomain analysis, DNS/MX records, technologies, and providers.
              </Typography>
              
              <Grid container spacing={3}>


                {/* Technology Stack */}
                <Grid item xs={12} md={6}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="h6" gutterBottom color="primary">
                        💻 Technology Analysis
                      </Typography>
                      <List dense>
                        <ListItem>
                          <ListItemText 
                            primary="Web Server" 
                            secondary={
                              <Typography component="span">
                                <strong>{domain.technology_info?.web_server || 'Not Detected'}</strong>
                                {!domain.technology_info?.web_server && (
                                  <Chip label="Protected by CDN" color="info" size="small" sx={{ ml: 1 }} />
                                )}
                              </Typography>
                            }
                          />
                        </ListItem>
                        <ListItem>
                          <ListItemText 
                            primary="CMS/Framework" 
                            secondary={
                              <Typography component="span">
                                <strong>{domain.technology_info?.cms || 'Not Detected'}</strong>
                                {!domain.technology_info?.cms && (
                                  <Chip label="Hidden Stack" color="info" size="small" sx={{ ml: 1 }} />
                                )}
                              </Typography>
                            }
                          />
                        </ListItem>
                        <ListItem>
                          <ListItemText 
                            primary="TLS Configuration" 
                            secondary={
                              <Box display="flex" alignItems="center">
                                <Chip 
                                  label={`Grade ${domain.security_info?.tls_grade || 'Unknown'}`} 
                                  color={domain.security_info?.tls_grade === 'A' ? 'success' : 
                                         domain.security_info?.tls_grade === 'B' ? 'warning' : 'error'}
                                  size="small"
                                />
                                <Typography variant="body2" sx={{ ml: 1 }}>
                                  ({domain.security_info?.tls_grade === 'A' ? '-5' : 
                                     domain.security_info?.tls_grade === 'B' ? '0' : '+10'} risk points)
                                </Typography>
                              </Box>
                            }
                          />
                        </ListItem>
                        <ListItem>
                          <ListItemText 
                            primary="Detected Technologies" 
                            secondary={
                              <Box>
                                {domain.technology_info?.technologies ? (
                                  (() => {
                                    try {
                                      const techs = JSON.parse(domain.technology_info.technologies);
                                      return (
                                        <Box sx={{ mt: 1 }}>
                                          <Typography variant="body2" sx={{ mb: 1 }}>
                                            <strong>{techs.length}</strong> technologies identified:
                                          </Typography>
                                          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                                            {techs.slice(0, 10).map((tech: any, index: number) => (
                                              <Chip 
                                                key={index} 
                                                label={typeof tech === 'string' ? tech : tech.name || tech.category || JSON.stringify(tech)} 
                                                size="small" 
                                                variant="outlined" 
                                                color="primary"
                                              />
                                            ))}
                                            {techs.length > 10 && (
                                              <Chip 
                                                label={`+${techs.length - 10} more`} 
                                                size="small" 
                                                variant="outlined" 
                                                color="secondary"
                                              />
                                            )}
                                          </Box>
                                        </Box>
                                      );
                                    } catch (e) {
                                      return (
                                        <Typography component="span">
                                          <strong>0</strong> technologies identified
                                          <Chip label="Analysis Needed" color="warning" size="small" sx={{ ml: 1 }} />
                                        </Typography>
                                      );
                                    }
                                  })()
                                ) : (
                                  <Typography component="span">
                                    <strong>0</strong> technologies identified
                                    <Chip label="Analysis Needed" color="warning" size="small" sx={{ ml: 1 }} />
                                  </Typography>
                                )}
                              </Box>
                            }
                          />
                        </ListItem>
                        <ListItem>
                          <ListItemText 
                            primary="Technology Risk Weight" 
                            secondary={
                              <Typography component="span" color="primary">
                                <strong>25%</strong> of total score
                              </Typography>
                            }
                          />
                        </ListItem>
                      </List>
                    </CardContent>
                  </Card>
                </Grid>

                {/* Provider Dependencies */}
                <Grid item xs={12} md={6}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="h6" gutterBottom color="primary">
                        🏢 Third-Party Providers
                      </Typography>
                      <List dense>
                        <ListItem>
                          <ListItemText 
                            primary="Detected Providers" 
                            secondary={
                              <Box>
                                {(() => {
                                  // Get providers from various sources
                                  const providers: Array<{name: string, type: string, color: string}> = [];
                                  
                                  // From web server (e.g., Cloudflare)
                                  if (domain.technology_info?.web_server && domain.technology_info.web_server !== 'Not Detected') {
                                    providers.push({
                                      name: domain.technology_info.web_server,
                                      type: 'Web Server / CDN',
                                      color: 'primary'
                                    });
                                  }
                                  
                                  // From providers array if available
                                  if (domain.providers && domain.providers.length > 0) {
                                    domain.providers.forEach((p: any) => {
                                      providers.push({
                                        name: p.name || p.provider_name,
                                        type: p.service_type || 'Service Provider',
                                        color: p.criticality === 'high' ? 'error' : 'info'
                                      });
                                    });
                                  }
                                  
                                  // From DNS/MX records if available
                                  if (domain.dns_info?.dns_records) {
                                    try {
                                      const records = JSON.parse(domain.dns_info.dns_records);
                                      if (records.MX) {
                                        records.MX.forEach((mx: string) => {
                                          if (mx.includes('google') || mx.includes('outlook') || mx.includes('microsoft')) {
                                            const provider = mx.includes('google') ? 'Google Workspace' : 'Microsoft 365';
                                            if (!providers.some(p => p.name.includes(provider.split(' ')[0]))) {
                                              providers.push({
                                                name: provider,
                                                type: 'Email Provider',
                                                color: 'secondary'
                                              });
                                            }
                                          }
                                        });
                                      }
                                    } catch (e) {
                                      // Ignore parsing errors
                                    }
                                  }
                                  
                                  if (providers.length === 0) {
                                    return (
                                      <Typography component="span">
                                        <strong>No providers detected</strong>
                                        <Chip label="Hidden Infrastructure" color="info" size="small" sx={{ ml: 1 }} />
                                      </Typography>
                                    );
                                  }
                                  
                                  return (
                                    <Box sx={{ mt: 1 }}>
                                      <Typography variant="body2" sx={{ mb: 1 }}>
                                        <strong>{providers.length}</strong> providers identified:
                                      </Typography>
                                      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                                        {providers.map((provider, index) => (
                                          <Box key={index} sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                            <Chip 
                                              label={provider.name} 
                                              size="small" 
                                              color={provider.color as any}
                                              variant="outlined"
                                            />
                                            <Typography variant="caption" color="textSecondary">
                                              {provider.type}
                                            </Typography>
                                          </Box>
                                        ))}
                                      </Box>
                                    </Box>
                                  );
                                })()}
                              </Box>
                            }
                          />
                        </ListItem>
                        <ListItem>
                          <ListItemText 
                            primary="Provider Risk Weight" 
                            secondary={
                              <Typography component="span" color="primary">
                                <strong>25%</strong> of total score
                              </Typography>
                            }
                          />
                        </ListItem>
                      </List>
                    </CardContent>
                  </Card>
                </Grid>

                {/* Security Information */}
                <Grid item xs={12} md={6}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="h6" gutterBottom color="primary">
                        🔒 Security Analysis
                      </Typography>
                      <List dense>
                        <ListItem>
                          <ListItemText 
                            primary="TLS Configuration" 
                            secondary={
                              <Box display="flex" alignItems="center">
                                <Chip 
                                  label={`Grade ${domain.security_info?.tls_grade || 'Unknown'}`} 
                                  color={domain.security_info?.tls_grade === 'A' ? 'success' : 
                                         domain.security_info?.tls_grade === 'B' ? 'warning' : 'error'}
                                  size="small"
                                />
                                <Typography variant="body2" sx={{ ml: 1 }}>
                                  ({domain.security_info?.tls_grade === 'A' ? '-5' : 
                                     domain.security_info?.tls_grade === 'B' ? '0' : '+10'} risk points)
                                </Typography>
                              </Box>
                            }
                          />
                        </ListItem>
                        <ListItem>
                          <ListItemText 
                            primary="Critical Vulnerabilities" 
                            secondary={
                              <Typography component="span">
                                <strong>{domain.security_info?.critical_cves || 0}</strong> critical CVEs
                                {(domain.security_info?.critical_cves || 0) > 0 && (
                                  <Chip label="High Risk" color="error" size="small" sx={{ ml: 1 }} />
                                )}
                              </Typography>
                            }
                          />
                        </ListItem>
                        <ListItem>
                          <ListItemText 
                            primary="High Vulnerabilities" 
                            secondary={
                              <Typography component="span">
                                <strong>{domain.security_info?.high_cves || 0}</strong> high CVEs
                                {(domain.security_info?.high_cves || 0) > 0 && (
                                  <Chip label="Medium Risk" color="warning" size="small" sx={{ ml: 1 }} />
                                )}
                              </Typography>
                            }
                          />
                        </ListItem>
                        <ListItem>
                          <ListItemText 
                            primary="TLS Certificate Details" 
                            secondary={
                              <Box>
                                {domain.security_info?.tls_grade ? (
                                  <Box sx={{ mt: 1 }}>
                                    <Typography variant="body2" sx={{ mb: 1 }}>
                                      <strong>Certificate Analysis:</strong>
                                    </Typography>
                                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                        <Chip 
                                          label={`SSL Grade: ${domain.security_info.tls_grade}`}
                                          color={domain.security_info.tls_grade === 'A' ? 'success' : 
                                                 domain.security_info.tls_grade === 'B' ? 'warning' : 'error'}
                                          size="small"
                                        />
                                      </Box>
                                      {(domain.security_info as any).cert_valid_from && (
                                        <Typography variant="caption" color="textSecondary">
                                          Certificate Valid From: {new Date((domain.security_info as any).cert_valid_from).toLocaleDateString()}
                                        </Typography>
                                      )}
                                      {(domain.security_info as any).cert_valid_to && (
                                        <Typography variant="caption" color="textSecondary">
                                          Certificate Expires: {new Date((domain.security_info as any).cert_valid_to).toLocaleDateString()}
                                        </Typography>
                                      )}
                                      {(domain.security_info as any).cipher_suite && (
                                        <Typography variant="caption" color="textSecondary">
                                          Cipher Suite: {(domain.security_info as any).cipher_suite}
                                        </Typography>
                                      )}
                                      {domain.last_calculated && (
                                        <Typography variant="caption" color="textSecondary">
                                          Last Analyzed: {new Date(domain.last_calculated).toLocaleDateString()}
                                        </Typography>
                                      )}
                                    </Box>
                                  </Box>
                                ) : (
                                  <Typography component="span">
                                    <strong>Analysis Pending</strong>
                                    <Chip label="TLS Scan Needed" color="warning" size="small" sx={{ ml: 1 }} />
                                  </Typography>
                                )}
                              </Box>
                            }
                          />
                        </ListItem>
                        <ListItem>
                          <ListItemText 
                            primary="Security Risk Weight" 
                            secondary={
                              <Typography component="span" color="primary">
                                <strong>15%</strong> of total score
                              </Typography>
                            }
                          />
                        </ListItem>
                      </List>
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>

              {/* Risk Calculation Formula */}
              <Box sx={{ mt: 3, p: 2, bgcolor: 'background.paper', border: '1px dashed #ccc', borderRadius: 1 }}>
                <Typography variant="h6" gutterBottom>
                  📐 Risk Calculation Formula
                </Typography>
                <Typography variant="body2" component="div">
                  <strong>Final Risk Score = </strong>
                  (Subdomain Risk × 0.35) + 
                  (Technology Risk × 0.25) + 
                  (Provider Risk × 0.25) + 
                  (DNS/Infrastructure Risk × 0.15)
                  <br /><br />
                  <strong>Risk Tiers:</strong>
                  <br />• Low: 0-25 points
                  <br />• Medium: 26-50 points  
                  <br />• High: 51-75 points
                  <br />• Critical: 76-100 points
                </Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>


        {domain.incidents && domain.incidents.length > 0 && (
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>Recent Incidents</Typography>
                <List>
                  {domain.incidents.map((incident, index) => (
                    <ListItem key={incident.incident_id} divider={index < domain.incidents!.length - 1}>
                      <ListItemText
                        primary={`Incident ${incident.incident_id}`}
                        secondary={
                          <Box>
                            <Typography variant="body2">
                              Severity: <Chip label={incident.severity} size="small" />
                            </Typography>
                            <Typography variant="body2">
                              Detected: {new Date(incident.detected).toLocaleString()}
                            </Typography>
                            <Typography variant="body2">
                              Status: {incident.resolved ? 'Resolved' : 'Active'}
                            </Typography>
                          </Box>
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>
        )}
        
        {/* Performance Statistics Section */}
        {domainPerformance?.available && domainPerformance?.has_data && (
          <Grid item xs={12} sx={{ mt: 3 }}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  🏃 Performance Statistics
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} sm={6} md={3}>
                    <Card variant="outlined">
                      <CardContent>
                        <Typography color="textSecondary" gutterBottom>
                          Total Executions
                        </Typography>
                        <Typography variant="h6">
                          {domainPerformance.summary?.total_executions || 0}
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <Card variant="outlined">
                      <CardContent>
                        <Typography color="textSecondary" gutterBottom>
                          Success Rate
                        </Typography>
                        <Typography variant="h6" color="success.main">
                          {domainPerformance.summary?.success_rate?.toFixed(1) || 0}%
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <Card variant="outlined">
                      <CardContent>
                        <Typography color="textSecondary" gutterBottom>
                          Failed Executions
                        </Typography>
                        <Typography variant="h6" color="error.main">
                          {domainPerformance.summary?.failed_executions || 0}
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <Card variant="outlined">
                      <CardContent>
                        <Typography color="textSecondary" gutterBottom>
                          Timeouts
                        </Typography>
                        <Typography variant="h6" color="warning.main">
                          {domainPerformance.summary?.timeout_executions || 0}
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                </Grid>

                {/* Task Breakdown */}
                {domainPerformance.task_breakdown && domainPerformance.task_breakdown.length > 0 && (
                  <Box sx={{ mt: 3 }}>
                    <Typography variant="h6" gutterBottom>
                      Task Performance Breakdown
                    </Typography>
                    <Grid container spacing={2}>
                      {domainPerformance.task_breakdown.map((task: any, index: number) => (
                        <Grid item xs={12} md={6} key={index}>
                          <Card variant="outlined">
                            <CardContent>
                              <Typography variant="subtitle1" gutterBottom>
                                {task.task_type.replace('_', ' ').toUpperCase()}
                              </Typography>
                              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                                <Typography variant="body2">Executions:</Typography>
                                <Typography variant="body2">{task.total_executions}</Typography>
                              </Box>
                              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                                <Typography variant="body2">Success Rate:</Typography>
                                <Typography variant="body2" color="success.main">
                                  {task.success_rate?.toFixed(1)}%
                                </Typography>
                              </Box>
                              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                                <Typography variant="body2">Avg Duration:</Typography>
                                <Typography variant="body2">
                                  {task.avg_duration ? `${Math.round(task.avg_duration / 60)}m` : 'N/A'}
                                </Typography>
                              </Box>
                              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                                <Typography variant="body2">Avg Subdomains:</Typography>
                                <Typography variant="body2">
                                  {task.avg_subdomains_found?.toFixed(1) || '0'}
                                </Typography>
                              </Box>
                              {task.last_execution && (
                                <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                                  <Typography variant="body2">Last Run:</Typography>
                                  <Typography variant="body2">
                                    {new Date(task.last_execution).toLocaleDateString()}
                                  </Typography>
                                </Box>
                              )}
                            </CardContent>
                          </Card>
                        </Grid>
                      ))}
                    </Grid>
                  </Box>
                )}

                {/* Time Estimations */}
                {domainPerformance.time_estimations && Object.keys(domainPerformance.time_estimations).length > 0 && (
                  <Box sx={{ mt: 3 }}>
                    <Typography variant="h6" gutterBottom>
                      Time Estimations for New Analysis
                    </Typography>
                    <Grid container spacing={2}>
                      {Object.entries(domainPerformance.time_estimations).map(([taskType, estimation]: [string, any]) => (
                        <Grid item xs={12} sm={6} md={3} key={taskType}>
                          <Card variant="outlined">
                            <CardContent>
                              <Typography variant="subtitle2" gutterBottom>
                                {taskType.replace('_', ' ').toUpperCase()}
                              </Typography>
                              <Typography variant="h6" color="primary.main">
                                {Math.round(estimation.estimated_seconds / 60)}m
                              </Typography>
                              <Typography variant="caption" color="textSecondary">
                                {estimation.confidence_level * 100}% confidence
                              </Typography>
                              <br />
                              <Typography variant="caption" color="textSecondary">
                                Based on {estimation.based_on_executions} runs
                              </Typography>
                            </CardContent>
                          </Card>
                        </Grid>
                      ))}
                    </Grid>
                  </Box>
                )}
              </CardContent>
            </Card>
          </Grid>
        )}
        
        {/* Dependencies Section */}
        <Grid item xs={12} sx={{ mt: 3 }}>
          <Card>
            <CardContent>
              <DomainDependencies 
                domain={fqdn || ''} 
                onBaseDomainDetected={setBaseDomain}
              />
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Graph Dialog */}
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
          Dependency Graph for {domain?.fqdn}
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
            domain={fqdn || ''} 
            height={600}
            showFullscreen={true}
          />
        </DialogContent>
      </Dialog>
    </Box>
  );
};

export default DomainDetail;