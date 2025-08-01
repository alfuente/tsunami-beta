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
} from '@mui/icons-material';
import { providerApi } from '../services/api';
import { ProviderDetailsResponse, AssociatedDomain, AssociatedSubdomain } from '../types/api';

const ProviderDetail: React.FC = () => {
  const { providerId } = useParams<{ providerId: string }>();
  const navigate = useNavigate();
  const [providerDetails, setProviderDetails] = useState<ProviderDetailsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchProviderDetails = async () => {
    if (!providerId) return;
    
    try {
      setLoading(true);
      
      // Generate dynamic mock data based on the provider
      const providerName = providerId.includes('imperva') ? 'imperva' : 
                           providerId.includes('amazon') ? 'amazon' :
                           providerId.includes('gtd') ? 'gtd' :
                           providerId.includes('cloudflare') ? 'cloudflare' :
                           providerId.includes('entel') ? 'entel' : 
                           providerId.includes('salesforce') ? 'salesforce' :
                           providerId.includes('bice') ? 'bice' :
                           providerId.includes('itau') ? 'itau' :
                           providerId.includes('movistar') ? 'movistar' : 'unknown';

      // Define provider-specific data
      const providerDataMap: {[key: string]: any} = {
        'imperva': {
          domains: [
            { fqdn: 'bancochile.cl', tld: 'cl', tld_country_name: 'Chile', subdomain_count: 2, last_seen: '2025-07-31T10:25:47.413436' },
            { fqdn: 'bice.cl', tld: 'cl', tld_country_name: 'Chile', subdomain_count: 3, last_seen: '2025-07-31T11:15:22.789012' },
            { fqdn: 'itau.cl', tld: 'cl', tld_country_name: 'Chile', subdomain_count: 2, last_seen: '2025-07-31T09:30:15.123456' },
          ],
          subdomains: [
            { fqdn: 'www.bancochile.cl', base_domain: 'bancochile.cl', tld: 'cl', risk_score: 2.1, risk_tier: 'Low', confidence: 0.9 },
            { fqdn: 'secure.bancochile.cl', base_domain: 'bancochile.cl', tld: 'cl', risk_score: 1.8, risk_tier: 'Low', confidence: 0.9 },
            { fqdn: 'api.bice.cl', base_domain: 'bice.cl', tld: 'cl', risk_score: 2.5, risk_tier: 'Low', confidence: 0.9 },
            { fqdn: 'portal.bice.cl', base_domain: 'bice.cl', tld: 'cl', risk_score: 2.3, risk_tier: 'Low', confidence: 0.9 },
            { fqdn: 'mobile.bice.cl', base_domain: 'bice.cl', tld: 'cl', risk_score: 1.9, risk_tier: 'Low', confidence: 0.9 },
            { fqdn: 'www.itau.cl', base_domain: 'itau.cl', tld: 'cl', risk_score: 2.0, risk_tier: 'Low', confidence: 0.9 },
            { fqdn: 'secure.itau.cl', base_domain: 'itau.cl', tld: 'cl', risk_score: 1.7, risk_tier: 'Low', confidence: 0.9 },
          ],
          stats: { total_domains: 3, total_subdomains: 7, low_risk: 7, medium_risk: 0, high_risk: 0 }
        },
        'amazon': {
          domains: [
            { fqdn: 'example1.com', tld: 'com', tld_country_name: 'United States', subdomain_count: 12, last_seen: '2025-07-31T08:45:22.789012' },
            { fqdn: 'example2.com', tld: 'com', tld_country_name: 'United States', subdomain_count: 18, last_seen: '2025-07-31T07:20:15.456789' },
            { fqdn: 'example3.org', tld: 'org', tld_country_name: 'United States', subdomain_count: 8, last_seen: '2025-07-31T09:15:33.123456' },
            { fqdn: 'example4.net', tld: 'net', tld_country_name: 'United States', subdomain_count: 7, last_seen: '2025-07-31T10:30:44.987654' },
          ],
          subdomains: [
            { fqdn: 'api.example1.com', base_domain: 'example1.com', tld: 'com', risk_score: 1.5, risk_tier: 'Low', confidence: 0.95 },
            { fqdn: 'cdn.example1.com', base_domain: 'example1.com', tld: 'com', risk_score: 1.2, risk_tier: 'Low', confidence: 0.95 },
            { fqdn: 'static.example1.com', base_domain: 'example1.com', tld: 'com', risk_score: 1.0, risk_tier: 'Low', confidence: 0.95 },
            { fqdn: 'www.example2.com', base_domain: 'example2.com', tld: 'com', risk_score: 1.8, risk_tier: 'Low', confidence: 0.93 },
            { fqdn: 'app.example2.com', base_domain: 'example2.com', tld: 'com', risk_score: 2.1, risk_tier: 'Low', confidence: 0.93 },
            { fqdn: 'admin.example3.org', base_domain: 'example3.org', tld: 'org', risk_score: 1.6, risk_tier: 'Low', confidence: 0.91 },
          ],
          stats: { total_domains: 4, total_subdomains: 45, low_risk: 42, medium_risk: 3, high_risk: 0 }
        },
        'gtd': {
          domains: [
            { fqdn: 'bancoripley.cl', tld: 'cl', tld_country_name: 'Chile', subdomain_count: 4, last_seen: '2025-07-31T10:13:38.400904' },
            { fqdn: 'coopeuch.cl', tld: 'cl', tld_country_name: 'Chile', subdomain_count: 3, last_seen: '2025-07-31T11:25:15.789012' },
            { fqdn: 'transbank.cl', tld: 'cl', tld_country_name: 'Chile', subdomain_count: 2, last_seen: '2025-07-31T09:45:22.456789' },
          ],
          subdomains: [
            { fqdn: 'www.bancoripley.cl', base_domain: 'bancoripley.cl', tld: 'cl', risk_score: 4.1, risk_tier: 'Medium', confidence: 0.8 },
            { fqdn: 'portal.bancoripley.cl', base_domain: 'bancoripley.cl', tld: 'cl', risk_score: 4.5, risk_tier: 'Medium', confidence: 0.8 },
            { fqdn: 'api.bancoripley.cl', base_domain: 'bancoripley.cl', tld: 'cl', risk_score: 3.8, risk_tier: 'Medium', confidence: 0.8 },
            { fqdn: 'mobile.bancoripley.cl', base_domain: 'bancoripley.cl', tld: 'cl', risk_score: 4.2, risk_tier: 'Medium', confidence: 0.8 },
            { fqdn: 'www.coopeuch.cl', base_domain: 'coopeuch.cl', tld: 'cl', risk_score: 3.9, risk_tier: 'Medium', confidence: 0.8 },
            { fqdn: 'secure.coopeuch.cl', base_domain: 'coopeuch.cl', tld: 'cl', risk_score: 4.0, risk_tier: 'Medium', confidence: 0.8 },
            { fqdn: 'www.transbank.cl', base_domain: 'transbank.cl', tld: 'cl', risk_score: 3.7, risk_tier: 'Medium', confidence: 0.8 },
            { fqdn: 'api.transbank.cl', base_domain: 'transbank.cl', tld: 'cl', risk_score: 4.3, risk_tier: 'Medium', confidence: 0.8 },
          ],
          stats: { total_domains: 3, total_subdomains: 9, low_risk: 1, medium_risk: 8, high_risk: 0 }
        },
        'cloudflare': {
          domains: [
            { fqdn: 'bice.cl', tld: 'cl', tld_country_name: 'Chile', subdomain_count: 8, last_seen: '2025-07-31T08:45:22.789012' },
            { fqdn: 'santander.cl', tld: 'cl', tld_country_name: 'Chile', subdomain_count: 6, last_seen: '2025-07-31T07:30:15.456789' },
            { fqdn: 'security.cl', tld: 'cl', tld_country_name: 'Chile', subdomain_count: 4, last_seen: '2025-07-31T09:15:33.123456' },
            { fqdn: 'example5.com', tld: 'com', tld_country_name: 'United States', subdomain_count: 10, last_seen: '2025-07-31T10:00:44.987654' },
          ],
          subdomains: [
            { fqdn: 'cdn.bice.cl', base_domain: 'bice.cl', tld: 'cl', risk_score: 1.3, risk_tier: 'Low', confidence: 0.92 },
            { fqdn: 'static.bice.cl', base_domain: 'bice.cl', tld: 'cl', risk_score: 1.1, risk_tier: 'Low', confidence: 0.92 },
            { fqdn: 'assets.bice.cl', base_domain: 'bice.cl', tld: 'cl', risk_score: 1.2, risk_tier: 'Low', confidence: 0.92 },
            { fqdn: 'www.santander.cl', base_domain: 'santander.cl', tld: 'cl', risk_score: 1.4, risk_tier: 'Low', confidence: 0.92 },
            { fqdn: 'cdn.santander.cl', base_domain: 'santander.cl', tld: 'cl', risk_score: 1.0, risk_tier: 'Low', confidence: 0.92 },
            { fqdn: 'www.security.cl', base_domain: 'security.cl', tld: 'cl', risk_score: 1.6, risk_tier: 'Low', confidence: 0.92 },
            { fqdn: 'portal.security.cl', base_domain: 'security.cl', tld: 'cl', risk_score: 1.8, risk_tier: 'Low', confidence: 0.92 },
          ],
          stats: { total_domains: 4, total_subdomains: 28, low_risk: 26, medium_risk: 2, high_risk: 0 }
        },
        'entel': {
          domains: [
            { fqdn: 'scotiabank.cl', tld: 'cl', tld_country_name: 'Chile', subdomain_count: 5, last_seen: '2025-07-31T10:13:39.125024' },
            { fqdn: 'bancoestado.cl', tld: 'cl', tld_country_name: 'Chile', subdomain_count: 4, last_seen: '2025-07-31T11:20:15.789012' },
          ],
          subdomains: [
            { fqdn: 'www.scotiabank.cl', base_domain: 'scotiabank.cl', tld: 'cl', risk_score: 3.5, risk_tier: 'Medium', confidence: 0.8 },
            { fqdn: 'portal.scotiabank.cl', base_domain: 'scotiabank.cl', tld: 'cl', risk_score: 4.1, risk_tier: 'Medium', confidence: 0.8 },
            { fqdn: 'mobile.scotiabank.cl', base_domain: 'scotiabank.cl', tld: 'cl', risk_score: 3.8, risk_tier: 'Medium', confidence: 0.8 },
            { fqdn: 'api.scotiabank.cl', base_domain: 'scotiabank.cl', tld: 'cl', risk_score: 4.2, risk_tier: 'Medium', confidence: 0.8 },
            { fqdn: 'secure.scotiabank.cl', base_domain: 'scotiabank.cl', tld: 'cl', risk_score: 3.9, risk_tier: 'Medium', confidence: 0.8 },
            { fqdn: 'www.bancoestado.cl', base_domain: 'bancoestado.cl', tld: 'cl', risk_score: 3.6, risk_tier: 'Medium', confidence: 0.8 },
            { fqdn: 'portal.bancoestado.cl', base_domain: 'bancoestado.cl', tld: 'cl', risk_score: 4.0, risk_tier: 'Medium', confidence: 0.8 },
            { fqdn: 'mobile.bancoestado.cl', base_domain: 'bancoestado.cl', tld: 'cl', risk_score: 3.7, risk_tier: 'Medium', confidence: 0.8 },
          ],
          stats: { total_domains: 2, total_subdomains: 9, low_risk: 2, medium_risk: 7, high_risk: 0 }
        },
        'salesforce': {
          domains: [
            { fqdn: 'example6.com', tld: 'com', tld_country_name: 'United States', subdomain_count: 3, last_seen: '2025-07-31T10:14:35.503059' },
            { fqdn: 'example7.org', tld: 'org', tld_country_name: 'United States', subdomain_count: 2, last_seen: '2025-07-31T09:30:22.456789' },
          ],
          subdomains: [
            { fqdn: 'crm.example6.com', base_domain: 'example6.com', tld: 'com', risk_score: 2.5, risk_tier: 'Low', confidence: 0.85 },
            { fqdn: 'api.example6.com', base_domain: 'example6.com', tld: 'com', risk_score: 3.1, risk_tier: 'Medium', confidence: 0.85 },
            { fqdn: 'portal.example6.com', base_domain: 'example6.com', tld: 'com', risk_score: 2.8, risk_tier: 'Low', confidence: 0.85 },
            { fqdn: 'app.example7.org', base_domain: 'example7.org', tld: 'org', risk_score: 2.9, risk_tier: 'Low', confidence: 0.85 },
            { fqdn: 'admin.example7.org', base_domain: 'example7.org', tld: 'org', risk_score: 3.2, risk_tier: 'Medium', confidence: 0.85 },
          ],
          stats: { total_domains: 2, total_subdomains: 5, low_risk: 3, medium_risk: 2, high_risk: 0 }
        }
      };

      // Get provider-specific data or default
      const providerData = providerDataMap[providerName] || {
        domains: [
          { fqdn: 'example.com', tld: 'com', tld_country_name: 'United States', subdomain_count: 1, last_seen: '2025-07-31T12:00:00.000000' }
        ],
        subdomains: [
          { fqdn: 'www.example.com', base_domain: 'example.com', tld: 'com', risk_score: 5.0, risk_tier: 'Medium', confidence: 0.5 }
        ],
        stats: { total_domains: 1, total_subdomains: 1, low_risk: 0, medium_risk: 1, high_risk: 0 }
      };

      const mockDetails: ProviderDetailsResponse = {
        provider: {
          id: providerId,
          name: providerName,
          tld: providerId.includes('gtd') || providerId.includes('entel') ? 'cl' : 'com',
          country: providerId.includes('gtd') || providerId.includes('entel') ? 'Chile' : 'United States',
          provider_type: providerId.includes('imperva') ? 'security' :
                        providerId.includes('amazon') ? 'cloud' :
                        providerId.includes('gtd') ? 'isp' :
                        providerId.includes('cloudflare') ? 'cdn' :
                        providerId.includes('entel') ? 'telecom' : 'saas',
          confidence: 0.9,
          source: 'metadata_as_domain',
          asn: providerId.includes('imperva') ? 'AS19551' :
               providerId.includes('amazon') ? 'AS16509' :
               providerId.includes('gtd') ? 'AS14259' :
               providerId.includes('cloudflare') ? 'AS13335' :
               providerId.includes('entel') ? 'AS27651' : 'AS13717',
          org: providerId.includes('imperva') ? 'Incapsula Inc' :
               providerId.includes('amazon') ? 'Amazon.com, Inc.' :
               providerId.includes('gtd') ? 'Gtd Internet S.A.' :
               providerId.includes('cloudflare') ? 'Cloudflare, Inc.' :
               providerId.includes('entel') ? 'ENTEL CHILE S.A.' : 'Salesforce.com, Inc.',
          risk_score: providerId.includes('imperva') || providerId.includes('cloudflare') ? 1.5 :
                     providerId.includes('amazon') ? 1.8 :
                     providerId.includes('salesforce') ? 2.8 : 4.2,
          risk_tier: providerId.includes('imperva') || providerId.includes('cloudflare') || providerId.includes('amazon') ? 'Low' :
                    providerId.includes('salesforce') ? 'Low' : 'Medium',
          metadata: {
            migration_confidence: 0.9,
            migration_source: 'metadata_as_domain',
            resolution_attempts: {
              as_domain: providerId.includes('imperva') ? 'incapsula.com' : `${providerName}.com`,
              country_code: providerId.includes('gtd') || providerId.includes('entel') ? 'CL' : 'US'
            }
          },
          created_at: '2025-07-31T10:15:19.814360',
          is_unknown: false
        },
        associated_domains: providerData.domains.map((domain: any) => ({
          ...domain,
          created_at: '2025-07-31T10:15:19.814360'
        })),
        associated_subdomains: providerData.subdomains.map((subdomain: any) => ({
          ...subdomain,
          created_at: '2025-07-31T10:15:19.814360'
        })),
        statistics: {
          total_domains: providerData.stats.total_domains,
          total_subdomains: providerData.stats.total_subdomains,
          countries: providerName === 'gtd' || providerName === 'entel' ? [
            { country: 'Chile', domain_count: providerData.stats.total_domains }
          ] : providerName === 'cloudflare' ? [
            { country: 'Chile', domain_count: 3 },
            { country: 'United States', domain_count: 1 }
          ] : [
            { country: 'United States', domain_count: providerData.stats.total_domains }
          ],
          risk_distribution: {
            low_risk: providerData.stats.low_risk,
            medium_risk: providerData.stats.medium_risk,
            high_risk: providerData.stats.high_risk
          }
        }
      };

      setProviderDetails(mockDetails);
      setError(null);
    } catch (err) {
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
        <Box display="flex" alignItems="center" gap={1}>
          <span style={{ fontSize: '24px' }}>{getCountryFlag(provider.country)}</span>
          <Typography variant="h6">{provider.country}</Typography>
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
                  <ListItemText primary="Type" secondary={
                    <Chip 
                      label={provider.provider_type || 'unknown'} 
                      size="small" 
                      sx={{ 
                        bgcolor: getProviderTypeColor(provider.provider_type), 
                        color: 'white' 
                      }}
                    />
                  } />
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
                    secondary={
                      <Box display="flex" alignItems="center" gap={1}>
                        <Chip 
                          label={provider.risk_tier || 'N/A'} 
                          color={getRiskTierColor(provider.risk_tier) as any}
                          size="small"
                        />
                        <Typography variant="caption">
                          Score: {provider.risk_score?.toFixed(1) || 'N/A'}
                        </Typography>
                      </Box>
                    } 
                  />
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
    </Box>
  );
};

export default ProviderDetail;