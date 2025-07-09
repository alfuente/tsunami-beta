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
  IconButton,
} from '@mui/material';
import {
  ArrowBack as ArrowBackIcon,
  Refresh as RefreshIcon,
  Security as SecurityIcon,
  Public as PublicIcon,
  Storage as StorageIcon,
} from '@mui/icons-material';
import { domainApi, riskApi, calculationApi } from '../services/api';
import { DomainResponse, RiskScoreResponse } from '../types/api';

const DomainDetail: React.FC = () => {
  const { fqdn } = useParams<{ fqdn: string }>();
  const navigate = useNavigate();
  const [domain, setDomain] = useState<DomainResponse | null>(null);
  const [riskScore, setRiskScore] = useState<RiskScoreResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [calculating, setCalculating] = useState(false);

  const fetchDomainData = async () => {
    if (!fqdn) return;
    
    try {
      setLoading(true);
      const [domainData, riskData] = await Promise.all([
        domainApi.getDomain(fqdn, true),
        riskApi.getRiskScore('domain', fqdn, true)
      ]);
      
      setDomain(domainData);
      setRiskScore(riskData);
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

  useEffect(() => {
    fetchDomainData();
  }, [fqdn]);

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" height="400px">
        <CircularProgress />
      </Box>
    );
  }

  if (error || !domain) {
    return (
      <Box>
        <Button startIcon={<ArrowBackIcon />} onClick={() => navigate('/domains')}>
          Back to Domains
        </Button>
        <Alert severity="error" sx={{ mt: 2 }}>{error || 'Domain not found'}</Alert>
      </Box>
    );
  }

  const getRiskTierColor = (tier: string) => {
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
          <Button
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate('/domains')}
            sx={{ mr: 2 }}
          >
            Back
          </Button>
          <Typography variant="h4">{domain.fqdn}</Typography>
        </Box>
        <Box display="flex" gap={1}>
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
                  color={getRiskTierColor(domain.risk_tier) as any}
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

        <Grid item xs={12} md={8}>
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6}>
              <Card>
                <CardContent>
                  <Box display="flex" alignItems="center" mb={2}>
                    <SecurityIcon sx={{ mr: 1 }} />
                    <Typography variant="h6">Security Information</Typography>
                  </Box>
                  {domain.security_info && (
                    <List dense>
                      <ListItem>
                        <ListItemText 
                          primary="TLS Grade" 
                          secondary={domain.security_info.tls_grade}
                        />
                      </ListItem>
                      <ListItem>
                        <ListItemText 
                          primary="Critical CVEs" 
                          secondary={domain.security_info.critical_cves}
                        />
                      </ListItem>
                      <ListItem>
                        <ListItemText 
                          primary="High CVEs" 
                          secondary={domain.security_info.high_cves}
                        />
                      </ListItem>
                      <ListItem>
                        <ListItemText 
                          primary="Last Assessment" 
                          secondary={domain.security_info.last_assessment ? new Date(domain.security_info.last_assessment).toLocaleDateString() : 'Never'}
                        />
                      </ListItem>
                    </List>
                  )}
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} sm={6}>
              <Card>
                <CardContent>
                  <Box display="flex" alignItems="center" mb={2}>
                    <PublicIcon sx={{ mr: 1 }} />
                    <Typography variant="h6">DNS Information</Typography>
                  </Box>
                  {domain.dns_info && (
                    <List dense>
                      <ListItem>
                        <ListItemText 
                          primary="DNSSEC Enabled" 
                          secondary={
                            <Chip 
                              label={domain.dns_info.dns_sec_enabled ? 'Yes' : 'No'} 
                              color={domain.dns_info.dns_sec_enabled ? 'success' : 'default'}
                              size="small"
                            />
                          }
                        />
                      </ListItem>
                      <ListItem>
                        <ListItemText 
                          primary="Name Servers" 
                          secondary={`${domain.dns_info.name_servers?.length || 0} configured`}
                        />
                      </ListItem>
                    </List>
                  )}
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} sm={6}>
              <Card>
                <CardContent>
                  <Box display="flex" alignItems="center" mb={2}>
                    <StorageIcon sx={{ mr: 1 }} />
                    <Typography variant="h6">Infrastructure</Typography>
                  </Box>
                  {domain.infrastructure_info && (
                    <List dense>
                      <ListItem>
                        <ListItemText 
                          primary="Multi-AZ" 
                          secondary={
                            <Chip 
                              label={domain.infrastructure_info.multi_az ? 'Yes' : 'No'} 
                              color={domain.infrastructure_info.multi_az ? 'success' : 'default'}
                              size="small"
                            />
                          }
                        />
                      </ListItem>
                      <ListItem>
                        <ListItemText 
                          primary="Multi-Region" 
                          secondary={
                            <Chip 
                              label={domain.infrastructure_info.multi_region ? 'Yes' : 'No'} 
                              color={domain.infrastructure_info.multi_region ? 'success' : 'default'}
                              size="small"
                            />
                          }
                        />
                      </ListItem>
                      <ListItem>
                        <ListItemText 
                          primary="Has Failover" 
                          secondary={
                            <Chip 
                              label={domain.infrastructure_info.has_failover ? 'Yes' : 'No'} 
                              color={domain.infrastructure_info.has_failover ? 'success' : 'default'}
                              size="small"
                            />
                          }
                        />
                      </ListItem>
                    </List>
                  )}
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} sm={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>General Information</Typography>
                  <List dense>
                    <ListItem>
                      <ListItemText 
                        primary="Business Criticality" 
                        secondary={
                          <Chip 
                            label={domain.business_criticality} 
                            variant="outlined"
                            size="small"
                          />
                        }
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText 
                        primary="Monitoring Enabled" 
                        secondary={
                          <Chip 
                            label={domain.monitoring_enabled ? 'Yes' : 'No'} 
                            color={domain.monitoring_enabled ? 'success' : 'default'}
                            size="small"
                          />
                        }
                      />
                    </ListItem>
                  </List>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
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
      </Grid>
    </Box>
  );
};

export default DomainDetail;