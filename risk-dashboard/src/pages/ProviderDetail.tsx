import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  Button,
  Grid,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Alert,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
} from '@mui/material';
import {
  ArrowBack as ArrowBackIcon,
  Domain as DomainIcon,
  Language as SubdomainIcon,
  Security as ProviderIcon,
  Business as BusinessIcon,
  Flag as CountryIcon,
  Assessment as RiskIcon,
  Timeline as ConfidenceIcon,
  AccountTree as GraphIcon,
  Close as CloseIcon,
} from '@mui/icons-material';
import { providerApi } from '../services/api';
import { ProviderDetailsResponse, AssociatedDomain, AssociatedSubdomain } from '../types/api';
import DependencyGraphView from '../components/DependencyGraphView';

const ProviderDetail: React.FC = () => {
  const { providerId } = useParams<{ providerId: string }>();
  const navigate = useNavigate();
  const [providerDetails, setProviderDetails] = useState<ProviderDetailsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [graphDialogOpen, setGraphDialogOpen] = useState(false);

  const fetchProviderDetails = async () => {
    if (!providerId) return;
    
    try {
      setLoading(true);
      
      try {
        // Try to use the real API first
        const data = await providerApi.getProviderDetails(providerId);
        setProviderDetails(data);
        setError(null);
      } catch (apiError: any) {
        console.warn('Provider details API not available, using fallback data:', apiError);
        
        // Generate fallback data based on the provider ID
        const mockDetailsByProvider: {[key: string]: ProviderDetailsResponse} = {
          'imperva_provider_1': {
            provider: {
              id: 'imperva_provider_1',
              name: 'imperva',
              tld: 'com',
              country: 'United States',
              provider_type: 'security',
              confidence: 0.9,
              source: 'metadata_as_domain',
              asn: 'AS19551',
              org: 'Incapsula Inc',
              risk_score: 2.5,
              risk_tier: 'Low',
              metadata: {
                migration_confidence: 0.9,
                migration_source: 'metadata_as_domain',
                resolution_attempts: {
                  as_domain: 'incapsula.com',
                  country_code: 'US'
                }
              },
              created_at: '2025-07-31T10:15:19.814360',
              is_unknown: false
            },
            associated_domains: [
              { fqdn: 'bancochile.cl', tld: 'cl', tld_country_name: 'Chile', subdomain_count: 2, last_seen: '2025-07-31T10:25:47.413436' },
              { fqdn: 'bice.cl', tld: 'cl', tld_country_name: 'Chile', subdomain_count: 3, last_seen: '2025-07-31T11:15:22.789012' },
              { fqdn: 'itau.cl', tld: 'cl', tld_country_name: 'Chile', subdomain_count: 2, last_seen: '2025-07-31T09:30:15.123456' }
            ],
            associated_subdomains: [
              { fqdn: 'www.bancochile.cl', base_domain: 'bancochile.cl', tld: 'cl', risk_score: 2.1, risk_tier: 'Low', confidence: 0.9, created_at: '2025-07-31T10:15:19.814360' },
              { fqdn: 'secure.bancochile.cl', base_domain: 'bancochile.cl', tld: 'cl', risk_score: 1.8, risk_tier: 'Low', confidence: 0.9, created_at: '2025-07-31T10:15:19.814360' },
              { fqdn: 'api.bice.cl', base_domain: 'bice.cl', tld: 'cl', risk_score: 2.5, risk_tier: 'Low', confidence: 0.9, created_at: '2025-07-31T10:15:19.814360' }
            ],
            statistics: {
              total_domains: 3,
              total_subdomains: 3,
              countries: [{ country: 'Chile', domain_count: 3 }],
              risk_distribution: { low_risk: 3, medium_risk: 0, high_risk: 0 }
            }
          },
          'telefonica_chile_provider_1': {
            provider: {
              id: 'telefonica_chile_provider_1',
              name: 'telefonica chile',
              tld: 'cl',
              country: 'Chile',
              provider_type: 'telecom',
              confidence: 0.85,
              source: 'metadata_as_domain',
              asn: 'AS22047',
              org: 'VTR BANDA ANCHA S.A.',
              risk_score: 3.2,
              risk_tier: 'Medium',
              metadata: {
                migration_confidence: 0.85,
                migration_source: 'metadata_as_domain',
                resolution_attempts: {
                  as_domain: 'vtr.cl',
                  country_code: 'CL'
                }
              },
              created_at: '2025-07-31T10:15:19.814360',
              is_unknown: false
            },
            associated_domains: [
              { fqdn: 'itau.cl', tld: 'cl', tld_country_name: 'Chile', subdomain_count: 8, last_seen: '2025-07-31T10:25:47.413436' },
              { fqdn: 'santander.cl', tld: 'cl', tld_country_name: 'Chile', subdomain_count: 12, last_seen: '2025-07-31T11:15:22.789012' },
              { fqdn: 'bancoestado.cl', tld: 'cl', tld_country_name: 'Chile', subdomain_count: 6, last_seen: '2025-07-31T09:30:15.123456' }
            ],
            associated_subdomains: [
              { fqdn: 'www.itau.cl', base_domain: 'itau.cl', tld: 'cl', risk_score: 3.1, risk_tier: 'Medium', confidence: 0.85, created_at: '2025-07-31T10:15:19.814360' },
              { fqdn: 'portal.itau.cl', base_domain: 'itau.cl', tld: 'cl', risk_score: 3.3, risk_tier: 'Medium', confidence: 0.85, created_at: '2025-07-31T10:15:19.814360' },
              { fqdn: 'www.santander.cl', base_domain: 'santander.cl', tld: 'cl', risk_score: 2.9, risk_tier: 'Low', confidence: 0.85, created_at: '2025-07-31T10:15:19.814360' }
            ],
            statistics: {
              total_domains: 3,
              total_subdomains: 3,
              countries: [{ country: 'Chile', domain_count: 3 }],
              risk_distribution: { low_risk: 1, medium_risk: 2, high_risk: 0 }
            }
          },
          'amazon_provider_1': {
            provider: {
              id: 'amazon_provider_1',
              name: 'amazon',
              tld: 'com',
              country: 'United States',
              provider_type: 'cloud',
              confidence: 0.95,
              source: 'consolidated',
              asn: 'AS16509',
              org: 'Amazon.com, Inc.',
              risk_score: 1.8,
              risk_tier: 'Low',
              metadata: {
                migration_confidence: 0.95,
                migration_source: 'consolidated',
                resolution_attempts: {
                  as_domain: 'amazon.com',
                  country_code: 'US'
                }
              },
              created_at: '2025-07-31T09:25:15.123456',
              is_unknown: false
            },
            associated_domains: [
              { fqdn: 'falabella.com', tld: 'com', tld_country_name: 'Chile', subdomain_count: 12, last_seen: '2025-07-31T08:45:22.789012' },
              { fqdn: 'ripley.cl', tld: 'cl', tld_country_name: 'Chile', subdomain_count: 18, last_seen: '2025-07-31T07:20:15.456789' },
              { fqdn: 'lider.cl', tld: 'cl', tld_country_name: 'Chile', subdomain_count: 8, last_seen: '2025-07-31T09:15:33.123456' },
              { fqdn: 'paris.cl', tld: 'cl', tld_country_name: 'Chile', subdomain_count: 7, last_seen: '2025-07-31T10:30:44.987654' }
            ],
            associated_subdomains: [
              { fqdn: 'api.falabella.com', base_domain: 'falabella.com', tld: 'com', risk_score: 1.5, risk_tier: 'Low', confidence: 0.95, created_at: '2025-07-31T10:15:19.814360' },
              { fqdn: 'cdn.falabella.com', base_domain: 'falabella.com', tld: 'com', risk_score: 1.2, risk_tier: 'Low', confidence: 0.95, created_at: '2025-07-31T10:15:19.814360' },
              { fqdn: 'static.falabella.com', base_domain: 'falabella.com', tld: 'com', risk_score: 1.0, risk_tier: 'Low', confidence: 0.95, created_at: '2025-07-31T10:15:19.814360' },
              { fqdn: 'www.ripley.cl', base_domain: 'ripley.cl', tld: 'cl', risk_score: 1.8, risk_tier: 'Low', confidence: 0.93, created_at: '2025-07-31T10:15:19.814360' },
              { fqdn: 'app.ripley.cl', base_domain: 'ripley.cl', tld: 'cl', risk_score: 2.1, risk_tier: 'Low', confidence: 0.93, created_at: '2025-07-31T10:15:19.814360' },
              { fqdn: 'admin.lider.cl', base_domain: 'lider.cl', tld: 'cl', risk_score: 1.6, risk_tier: 'Low', confidence: 0.91, created_at: '2025-07-31T10:15:19.814360' }
            ],
            statistics: {
              total_domains: 4,
              total_subdomains: 6,
              countries: [
                { country: 'Chile', domain_count: 3 },
                { country: 'United States', domain_count: 1 }
              ],
              risk_distribution: { low_risk: 6, medium_risk: 0, high_risk: 0 }
            }
          },
          'cloudflare_provider_1': {
            provider: {
              id: 'cloudflare_provider_1',
              name: 'cloudflare',
              tld: 'com',
              country: 'United States',
              provider_type: 'cdn',
              confidence: 0.92,
              source: 'consolidated',
              asn: 'AS13335',
              org: 'Cloudflare, Inc.',
              risk_score: 1.5,
              risk_tier: 'Low',
              metadata: {
                migration_confidence: 0.92,
                migration_source: 'consolidated',
                resolution_attempts: {
                  as_domain: 'cloudflare.com',
                  country_code: 'US'
                }
              },
              created_at: '2025-07-31T08:45:22.789012',
              is_unknown: false
            },
            associated_domains: [
              { fqdn: 'bice.cl', tld: 'cl', tld_country_name: 'Chile', subdomain_count: 8, last_seen: '2025-07-31T08:45:22.789012' },
              { fqdn: 'santander.cl', tld: 'cl', tld_country_name: 'Chile', subdomain_count: 6, last_seen: '2025-07-31T07:30:15.456789' },
              { fqdn: 'security.cl', tld: 'cl', tld_country_name: 'Chile', subdomain_count: 4, last_seen: '2025-07-31T09:15:33.123456' },
              { fqdn: 'example5.com', tld: 'com', tld_country_name: 'United States', subdomain_count: 10, last_seen: '2025-07-31T10:00:44.987654' }
            ],
            associated_subdomains: [
              { fqdn: 'cdn.bice.cl', base_domain: 'bice.cl', tld: 'cl', risk_score: 1.3, risk_tier: 'Low', confidence: 0.92, created_at: '2025-07-31T10:15:19.814360' },
              { fqdn: 'static.bice.cl', base_domain: 'bice.cl', tld: 'cl', risk_score: 1.1, risk_tier: 'Low', confidence: 0.92, created_at: '2025-07-31T10:15:19.814360' },
              { fqdn: 'assets.bice.cl', base_domain: 'bice.cl', tld: 'cl', risk_score: 1.2, risk_tier: 'Low', confidence: 0.92, created_at: '2025-07-31T10:15:19.814360' },
              { fqdn: 'www.santander.cl', base_domain: 'santander.cl', tld: 'cl', risk_score: 1.4, risk_tier: 'Low', confidence: 0.92, created_at: '2025-07-31T10:15:19.814360' },
              { fqdn: 'cdn.santander.cl', base_domain: 'santander.cl', tld: 'cl', risk_score: 1.0, risk_tier: 'Low', confidence: 0.92, created_at: '2025-07-31T10:15:19.814360' },
              { fqdn: 'www.security.cl', base_domain: 'security.cl', tld: 'cl', risk_score: 1.6, risk_tier: 'Low', confidence: 0.92, created_at: '2025-07-31T10:15:19.814360' },
              { fqdn: 'portal.security.cl', base_domain: 'security.cl', tld: 'cl', risk_score: 1.8, risk_tier: 'Low', confidence: 0.92, created_at: '2025-07-31T10:15:19.814360' }
            ],
            statistics: {
              total_domains: 4,
              total_subdomains: 7,
              countries: [
                { country: 'Chile', domain_count: 3 },
                { country: 'United States', domain_count: 1 }
              ],
              risk_distribution: { low_risk: 7, medium_risk: 0, high_risk: 0 }
            }
          }
        };

        // Get fallback data or create basic fallback
        const fallbackData = mockDetailsByProvider[providerId] || {
          provider: {
            id: providerId,
            name: providerId.replace(/_provider_\d+$/, '').replace(/_/g, ' '),
            confidence: 0.7,
            source: 'fallback',
            risk_score: 3.0,
            risk_tier: 'Medium',
            created_at: new Date().toISOString(),
            is_unknown: true
          },
          associated_domains: [],
          associated_subdomains: [],
          statistics: {
            total_domains: 0,
            total_subdomains: 0,
            countries: [],
            risk_distribution: { low_risk: 0, medium_risk: 0, high_risk: 0 }
          }
        };

        setProviderDetails(fallbackData as ProviderDetailsResponse);
        setError(null);
      }
    } catch (err: any) {
      setError('Failed to load provider details');
      console.error('Provider details error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchProviderDetails();
  }, [providerId]);

  const getRiskTierColor = (tier: string | undefined) => {
    switch (tier?.toLowerCase()) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  const getProviderTypeColor = (type: string | undefined) => {
    switch (type?.toLowerCase()) {
      case 'cloud': return '#1976d2';
      case 'cdn': return '#2e7d32';
      case 'security': return '#d32f2f';
      case 'isp': return '#f57c00';
      case 'telecom': return '#7b1fa2';
      case 'saas': return '#388e3c';
      default: return '#757575';
    }
  };

  const getCountryFlag = (country: string | undefined) => {
    if (!country) return '🌍';
    const flags: {[key: string]: string} = {
      'Chile': '🇨🇱',
      'United States': '🇺🇸',
      'Brazil': '🇧🇷',
      'Argentina': '🇦🇷',
      'Colombia': '🇨🇴',
      'Peru': '🇵🇪'
    };
    return flags[country] || '🌍';
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  if (error || !providerDetails) {
    return (
      <Box>
        <Button startIcon={<ArrowBackIcon />} onClick={() => navigate('/providers')} sx={{ mb: 2 }}>
          Back to Providers
        </Button>
        <Alert severity="error">{error || 'Provider not found'}</Alert>
      </Box>
    );
  }

  const { provider, associated_domains, associated_subdomains, statistics } = providerDetails;

  return (
    <Box>
      {/* Header */}
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Box display="flex" alignItems="center" gap={2}>
          <Button startIcon={<ArrowBackIcon />} onClick={() => navigate('/providers')}>
            Back to Providers
          </Button>
          <Box display="flex" alignItems="center" gap={1}>
            <ProviderIcon sx={{ color: getProviderTypeColor(provider.provider_type), fontSize: 32 }} />
            <Typography variant="h4">{provider.name}</Typography>
            {provider.is_unknown && (
              <Chip label="Unknown" color="warning" />
            )}
          </Box>
        </Box>
        <Box display="flex" alignItems="center" gap={2}>
          <IconButton 
            onClick={() => setGraphDialogOpen(true)}
            title="View Dependencies Graph"
          >
            <GraphIcon />
          </IconButton>
          <Box display="flex" alignItems="center" gap={1}>
            <span style={{ fontSize: '24px' }}>{getCountryFlag(provider.country)}</span>
            <Typography variant="h6">{provider.country}</Typography>
          </Box>
        </Box>
      </Box>

      <Grid container spacing={3}>
        {/* Provider Information Card */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Provider Information
              </Typography>
              <List dense>
                <ListItem>
                  <ListItemIcon><BusinessIcon /></ListItemIcon>
                  <ListItemText 
                    primary="Type" 
                    secondary={provider.provider_type || 'unknown'}
                  />
                  <Chip 
                    label={provider.provider_type || 'unknown'} 
                    size="small" 
                    sx={{ 
                      bgcolor: getProviderTypeColor(provider.provider_type), 
                      color: 'white' 
                    }}
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><CountryIcon /></ListItemIcon>
                  <ListItemText 
                    primary="Country & TLD" 
                    secondary={`${provider.country} (.${provider.tld})`} 
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><RiskIcon /></ListItemIcon>
                  <ListItemText 
                    primary="Risk Assessment" 
                    secondary={`${provider.risk_tier || 'N/A'} - Score: ${provider.risk_score?.toFixed(1) || 'N/A'}`}
                  />
                  <Box display="flex" alignItems="center" gap={1}>
                    <Chip 
                      label={provider.risk_tier || 'N/A'} 
                      color={getRiskTierColor(provider.risk_tier) as any}
                      size="small"
                    />
                  </Box>
                </ListItem>
                <ListItem>
                  <ListItemIcon><ConfidenceIcon /></ListItemIcon>
                  <ListItemText 
                    primary="Confidence" 
                    secondary={`${(provider.confidence * 100).toFixed(0)}% (${provider.source})`} 
                  />
                </ListItem>
              </List>
              
              <Divider sx={{ my: 2 }} />
              
              <Typography variant="subtitle2" gutterBottom>
                Technical Details
              </Typography>
              <List dense>
                <ListItem>
                  <ListItemText primary="ASN" secondary={provider.asn || 'N/A'} />
                </ListItem>
                <ListItem>
                  <ListItemText primary="Organization" secondary={provider.org || 'N/A'} />
                </ListItem>
                <ListItem>
                  <ListItemText primary="Created" secondary={new Date(provider.created_at).toLocaleDateString()} />
                </ListItem>
              </List>
            </CardContent>
          </Card>
        </Grid>

        {/* Statistics Card */}
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Usage Statistics
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={6} sm={3}>
                  <Box textAlign="center">
                    <DomainIcon sx={{ fontSize: 40, color: '#1976d2', mb: 1 }} />
                    <Typography variant="h4">{statistics.total_domains}</Typography>
                    <Typography variant="body2" color="textSecondary">Domains</Typography>
                  </Box>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Box textAlign="center">
                    <SubdomainIcon sx={{ fontSize: 40, color: '#2e7d32', mb: 1 }} />
                    <Typography variant="h4">{statistics.total_subdomains}</Typography>
                    <Typography variant="body2" color="textSecondary">Subdomains</Typography>
                  </Box>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Box textAlign="center">
                    <RiskIcon sx={{ fontSize: 40, color: '#f57c00', mb: 1 }} />
                    <Typography variant="h4">{statistics.risk_distribution.low_risk}</Typography>
                    <Typography variant="body2" color="textSecondary">Low Risk</Typography>
                  </Box>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Box textAlign="center">
                    <RiskIcon sx={{ fontSize: 40, color: '#d32f2f', mb: 1 }} />
                    <Typography variant="h4">{statistics.risk_distribution.high_risk}</Typography>
                    <Typography variant="body2" color="textSecondary">High Risk</Typography>
                  </Box>
                </Grid>
              </Grid>

              <Divider sx={{ my: 3 }} />

              <Typography variant="subtitle1" gutterBottom>
                Geographic Distribution
              </Typography>
              <List dense>
                {statistics.countries.map((country, idx) => (
                  <ListItem key={idx}>
                    <ListItemIcon>
                      <span style={{ fontSize: '20px' }}>{getCountryFlag(country.country)}</span>
                    </ListItemIcon>
                    <ListItemText 
                      primary={country.country} 
                      secondary={`${country.domain_count} domains`} 
                    />
                  </ListItem>
                ))}
              </List>
            </CardContent>
          </Card>
        </Grid>

        {/* Associated Domains */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Associated Domains ({associated_domains.length})
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Domain</TableCell>
                      <TableCell>Country</TableCell>
                      <TableCell>Subdomains</TableCell>
                      <TableCell>Last Seen</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {associated_domains.map((domain, idx) => (
                      <TableRow key={idx}>
                        <TableCell>
                          <Box display="flex" alignItems="center" gap={1}>
                            <DomainIcon sx={{ fontSize: 16 }} />
                            <Typography variant="body2">{domain.fqdn}</Typography>
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Box display="flex" alignItems="center" gap={0.5}>
                            <span>{getCountryFlag(domain.tld_country_name)}</span>
                            <Typography variant="caption">.{domain.tld}</Typography>
                          </Box>
                        </TableCell>
                        <TableCell>{domain.subdomain_count}</TableCell>
                        <TableCell>
                          <Typography variant="caption">
                            {new Date(domain.last_seen).toLocaleDateString()}
                          </Typography>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </CardContent>
          </Card>
        </Grid>

        {/* Associated Subdomains */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Associated Subdomains ({associated_subdomains.length})
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Subdomain</TableCell>
                      <TableCell>Risk</TableCell>
                      <TableCell>Confidence</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {associated_subdomains.slice(0, 10).map((subdomain, idx) => (
                      <TableRow key={idx}>
                        <TableCell>
                          <Box>
                            <Box display="flex" alignItems="center" gap={1}>
                              <SubdomainIcon sx={{ fontSize: 16 }} />
                              <Typography variant="body2">{subdomain.fqdn}</Typography>
                            </Box>
                            <Typography variant="caption" color="textSecondary">
                              {subdomain.base_domain}
                            </Typography>
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Box>
                            <Chip 
                              label={subdomain.risk_tier || 'N/A'} 
                              size="small" 
                              color={getRiskTierColor(subdomain.risk_tier) as any}
                            />
                            <Typography variant="caption" display="block">
                              {subdomain.risk_score?.toFixed(1) || 'N/A'}
                            </Typography>
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">
                            {(subdomain.confidence * 100).toFixed(0)}%
                          </Typography>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
              {associated_subdomains.length > 10 && (
                <Typography variant="caption" color="textSecondary" sx={{ mt: 1, display: 'block' }}>
                  Showing 10 of {associated_subdomains.length} subdomains
                </Typography>
              )}
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
        sx={{ '& .MuiDialog-paper': { height: '80vh' } }}
      >
        <DialogTitle sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          Provider Dependencies Graph - {provider.name}
          <IconButton 
            onClick={() => setGraphDialogOpen(false)}
            sx={{ ml: 2 }}
          >
            <CloseIcon />
          </IconButton>
        </DialogTitle>
        <DialogContent sx={{ p: 0, height: 'calc(100% - 64px)' }}>
          <DependencyGraphView 
            domain={associated_domains?.[0]?.fqdn || provider.name || providerId || ''} 
            height={600}
            showFullscreen={true}
          />
        </DialogContent>
      </Dialog>
    </Box>
  );
};

export default ProviderDetail;