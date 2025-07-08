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
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  IconButton,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from '@mui/material';
import {
  ArrowBack as ArrowBackIcon,
  Refresh as RefreshIcon,
  Security as SecurityIcon,
  Public as PublicIcon,
  Storage as StorageIcon,
  ExpandMore as ExpandMoreIcon,
  Visibility as VisibilityIcon,
} from '@mui/icons-material';
import { domainApi } from '../services/api';
import { BaseDomainDetailsResponse } from '../types/api';

const BaseDomainDetail: React.FC = () => {
  const { baseDomain } = useParams<{ baseDomain: string }>();
  const navigate = useNavigate();
  const [domainDetails, setDomainDetails] = useState<BaseDomainDetailsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchDomainDetails = async () => {
    if (!baseDomain) return;
    
    try {
      setLoading(true);
      const data = await domainApi.getBaseDomainDetails(baseDomain, true);
      setDomainDetails(data);
      setError(null);
    } catch (err) {
      setError('Failed to load base domain details');
      console.error('Base domain detail error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDomainDetails();
  }, [baseDomain]);

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" height="400px">
        <CircularProgress />
      </Box>
    );
  }

  if (error || !domainDetails) {
    return (
      <Box>
        <Button startIcon={<ArrowBackIcon />} onClick={() => navigate('/domains')}>
          Back to Base Domains
        </Button>
        <Alert severity="error" sx={{ mt: 2 }}>{error || 'Base domain not found'}</Alert>
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
          <Typography variant="h4">{domainDetails.base_domain}</Typography>
        </Box>
        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
          onClick={fetchDomainDetails}
        >
          Refresh
        </Button>
      </Box>

      <Grid container spacing={3}>
        {/* Risk Summary */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Risk Summary
              </Typography>
              <Box display="flex" alignItems="center" mb={2}>
                <Typography variant="h3" color="primary" sx={{ mr: 2 }}>
                  {domainDetails.risk_summary.max_risk_score.toFixed(1)}
                </Typography>
                <Typography variant="body2" color="textSecondary">
                  Max Risk Score
                </Typography>
              </Box>
              <Typography variant="body2" gutterBottom>
                Average: {domainDetails.risk_summary.average_risk_score.toFixed(1)}
              </Typography>
              <Divider sx={{ my: 2 }} />
              <Box display="flex" gap={1} mb={1}>
                <Chip 
                  label={`${domainDetails.risk_summary.critical_subdomains} Critical`} 
                  color="error"
                  size="small"
                />
                <Chip 
                  label={`${domainDetails.risk_summary.high_risk_subdomains} High`} 
                  color="warning"
                  size="small"
                />
              </Box>
              <Typography variant="body2" color="textSecondary">
                Active Incidents: {domainDetails.risk_summary.total_incidents}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        {/* Service Summary */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" mb={2}>
                <StorageIcon sx={{ mr: 1 }} />
                <Typography variant="h6">Services</Typography>
              </Box>
              <Typography variant="h4" color="primary" gutterBottom>
                {domainDetails.service_summary.total_services}
              </Typography>
              <Typography variant="body2" color="textSecondary" gutterBottom>
                Total Services
              </Typography>
              {domainDetails.service_summary.services.length > 0 && (
                <Box>
                  <Divider sx={{ my: 2 }} />
                  <Box display="flex" flexWrap="wrap" gap={0.5}>
                    {domainDetails.service_summary.services.slice(0, 5).map((service, index) => (
                      <Chip key={index} label={service} size="small" variant="outlined" />
                    ))}
                    {domainDetails.service_summary.services.length > 5 && (
                      <Chip label={`+${domainDetails.service_summary.services.length - 5} more`} size="small" />
                    )}
                  </Box>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Provider Summary */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" mb={2}>
                <PublicIcon sx={{ mr: 1 }} />
                <Typography variant="h6">Providers</Typography>
              </Box>
              <Typography variant="h4" color="primary" gutterBottom>
                {domainDetails.provider_summary.total_providers}
              </Typography>
              <Typography variant="body2" color="textSecondary" gutterBottom>
                Total Providers
              </Typography>
              {domainDetails.provider_summary.providers.length > 0 && (
                <Box>
                  <Divider sx={{ my: 2 }} />
                  <Box display="flex" flexWrap="wrap" gap={0.5}>
                    {domainDetails.provider_summary.providers.slice(0, 5).map((provider, index) => (
                      <Chip key={index} label={provider} size="small" variant="outlined" />
                    ))}
                    {domainDetails.provider_summary.providers.length > 5 && (
                      <Chip label={`+${domainDetails.provider_summary.providers.length - 5} more`} size="small" />
                    )}
                  </Box>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Subdomains Detail */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Subdomains ({domainDetails.total_count})
              </Typography>
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Subdomain</TableCell>
                      <TableCell>Risk Score</TableCell>
                      <TableCell>Risk Tier</TableCell>
                      <TableCell>Services</TableCell>
                      <TableCell>Providers</TableCell>
                      <TableCell>Incidents</TableCell>
                      <TableCell>Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {domainDetails.subdomains.map((subdomain) => (
                      <TableRow key={subdomain.fqdn}>
                        <TableCell>
                          <Typography variant="body2" fontWeight="bold">
                            {subdomain.fqdn}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">
                            {subdomain.risk_score.toFixed(1)}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={subdomain.risk_tier} 
                            color={getRiskTierColor(subdomain.risk_tier) as any}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          <Box display="flex" flexWrap="wrap" gap={0.5}>
                            {subdomain.services.slice(0, 2).map((service, index) => (
                              <Chip key={index} label={service} size="small" variant="outlined" />
                            ))}
                            {subdomain.services.length > 2 && (
                              <Chip label={`+${subdomain.services.length - 2}`} size="small" />
                            )}
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Box display="flex" flexWrap="wrap" gap={0.5}>
                            {subdomain.providers.slice(0, 2).map((provider, index) => (
                              <Chip key={index} label={provider} size="small" variant="outlined" />
                            ))}
                            {subdomain.providers.length > 2 && (
                              <Chip label={`+${subdomain.providers.length - 2}`} size="small" />
                            )}
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" color={subdomain.active_incidents > 0 ? 'error' : 'textSecondary'}>
                            {subdomain.active_incidents}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <IconButton 
                            size="small" 
                            onClick={() => navigate(`/domains/${subdomain.fqdn}`)}
                          >
                            <VisibilityIcon />
                          </IconButton>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default BaseDomainDetail;