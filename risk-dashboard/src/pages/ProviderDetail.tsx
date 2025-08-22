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
  Storage as IPIcon,
  Public as NetworkIcon,
  Verified as EvidenceIcon,
} from '@mui/icons-material';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { providerApi } from '../services/api';

interface ProviderDetails {
  id: string;
  name: string;
  country?: string;
  type?: string;
  confidence: number;
  evidence?: string;
  risk_score?: number;
  risk_tier?: string;
  created_at: string;
  updated_at: string;
  domains?: string[];
  ip_ranges?: string[];
  aliases?: string[];
  usage?: {
    domains: string[];
    subdomains: string[];
    total_domains: number;
    total_subdomains: number;
  };
}

const ProviderDetail: React.FC = () => {
  const { providerId } = useParams<{ providerId: string }>();
  const navigate = useNavigate();
  const [providerDetails, setProviderDetails] = useState<ProviderDetails | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchProviderDetails = async () => {
    if (!providerId) return;
    
    try {
      setLoading(true);
      const data = await providerApi.getProviderDetails(providerId);
      setProviderDetails(data);
      setError(null);
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
      'Peru': '🇵🇪',
      'Global': '🌍'
    };
    return flags[country] || '🌍';
  };

  const getRiskDistributionData = () => {
    if (!providerDetails?.usage) return [];
    
    const total = providerDetails.usage.total_domains + providerDetails.usage.total_subdomains;
    const riskScore = providerDetails.risk_score || 0;
    
    // Simulate risk distribution based on risk score
    let lowRisk = 0, mediumRisk = 0, highRisk = 0;
    
    if (riskScore < 30) {
      lowRisk = Math.floor(total * 0.8);
      mediumRisk = Math.floor(total * 0.2);
      highRisk = 0;
    } else if (riskScore < 60) {
      lowRisk = Math.floor(total * 0.5);
      mediumRisk = Math.floor(total * 0.4);
      highRisk = Math.floor(total * 0.1);
    } else {
      lowRisk = Math.floor(total * 0.3);
      mediumRisk = Math.floor(total * 0.4);
      highRisk = Math.floor(total * 0.3);
    }
    
    return [
      { name: 'Low Risk', value: lowRisk, color: '#4caf50' },
      { name: 'Medium Risk', value: mediumRisk, color: '#ff9800' },
      { name: 'High Risk', value: highRisk, color: '#f44336' }
    ].filter(item => item.value > 0);
  };

  const getUsageData = () => {
    if (!providerDetails?.usage) return [];
    
    return [
      { name: 'Domains', value: providerDetails.usage.total_domains, color: '#1976d2' },
      { name: 'Subdomains', value: providerDetails.usage.total_subdomains, color: '#2e7d32' }
    ];
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

  return (
    <Box>
      {/* Header */}
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Box display="flex" alignItems="center" gap={2}>
          <Button startIcon={<ArrowBackIcon />} onClick={() => navigate('/providers')}>
            Back to Providers
          </Button>
          <Box display="flex" alignItems="center" gap={1}>
            <ProviderIcon sx={{ color: getProviderTypeColor(providerDetails.type), fontSize: 32 }} />
            <Typography variant="h4">{providerDetails.name}</Typography>
            <Chip 
              label={providerDetails.type || 'Unknown'} 
              size="small"
              sx={{ 
                bgcolor: getProviderTypeColor(providerDetails.type), 
                color: 'white' 
              }}
            />
          </Box>
        </Box>
        <Box display="flex" alignItems="center" gap={2}>
          <Box display="flex" alignItems="center" gap={1}>
            <span style={{ fontSize: '24px' }}>{getCountryFlag(providerDetails.country)}</span>
            <Typography variant="h6">{providerDetails.country || 'Unknown'}</Typography>
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
                    secondary={providerDetails.type || 'unknown'}
                  />
                  <Chip 
                    label={providerDetails.type || 'unknown'} 
                    size="small" 
                    sx={{ 
                      bgcolor: getProviderTypeColor(providerDetails.type), 
                      color: 'white' 
                    }}
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><CountryIcon /></ListItemIcon>
                  <ListItemText 
                    primary="Country" 
                    secondary={providerDetails.country || 'Global'} 
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><RiskIcon /></ListItemIcon>
                  <ListItemText 
                    primary="Risk Assessment" 
                    secondary={`${providerDetails.risk_tier || 'N/A'} - Score: ${providerDetails.risk_score?.toFixed(1) || 'N/A'}`}
                  />
                  <Box display="flex" alignItems="center" gap={1}>
                    <Chip 
                      label={providerDetails.risk_tier || 'N/A'} 
                      color={getRiskTierColor(providerDetails.risk_tier) as any}
                      size="small"
                    />
                  </Box>
                </ListItem>
                <ListItem>
                  <ListItemIcon><ConfidenceIcon /></ListItemIcon>
                  <ListItemText 
                    primary="Confidence" 
                    secondary={`${(providerDetails.confidence * 100).toFixed(0)}%`} 
                  />
                </ListItem>
                {providerDetails.evidence && (
                  <ListItem>
                    <ListItemIcon><EvidenceIcon /></ListItemIcon>
                    <ListItemText 
                      primary="Evidence" 
                      secondary={providerDetails.evidence} 
                    />
                  </ListItem>
                )}
              </List>
              
              <Divider sx={{ my: 2 }} />
              
              <Typography variant="subtitle2" gutterBottom>
                Technical Details
              </Typography>
              <List dense>
                <ListItem>
                  <ListItemText primary="Provider ID" secondary={providerDetails.id} />
                </ListItem>
                {providerDetails.aliases && providerDetails.aliases.length > 0 && (
                  <ListItem>
                    <ListItemText 
                      primary="Aliases" 
                      secondary={providerDetails.aliases.join(', ')} 
                    />
                  </ListItem>
                )}
                <ListItem>
                  <ListItemText 
                    primary="Created" 
                    secondary={new Date(providerDetails.created_at).toLocaleDateString()} 
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary="Last Updated" 
                    secondary={new Date(providerDetails.updated_at).toLocaleDateString()} 
                  />
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
                    <Typography variant="h4">{providerDetails.usage?.total_domains || 0}</Typography>
                    <Typography variant="body2" color="textSecondary">Domains</Typography>
                  </Box>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Box textAlign="center">
                    <SubdomainIcon sx={{ fontSize: 40, color: '#2e7d32', mb: 1 }} />
                    <Typography variant="h4">{providerDetails.usage?.total_subdomains || 0}</Typography>
                    <Typography variant="body2" color="textSecondary">Subdomains</Typography>
                  </Box>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Box textAlign="center">
                    <NetworkIcon sx={{ fontSize: 40, color: '#f57c00', mb: 1 }} />
                    <Typography variant="h4">{providerDetails.domains?.length || 0}</Typography>
                    <Typography variant="body2" color="textSecondary">Own Domains</Typography>
                  </Box>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Box textAlign="center">
                    <IPIcon sx={{ fontSize: 40, color: '#7b1fa2', mb: 1 }} />
                    <Typography variant="h4">{providerDetails.ip_ranges?.length || 0}</Typography>
                    <Typography variant="body2" color="textSecondary">IP Ranges</Typography>
                  </Box>
                </Grid>
              </Grid>

              {/* Charts */}
              {providerDetails.usage && (providerDetails.usage.total_domains > 0 || providerDetails.usage.total_subdomains > 0) && (
                <>
                  <Divider sx={{ my: 3 }} />
                  <Grid container spacing={3}>
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle1" gutterBottom textAlign="center">
                        Usage Distribution
                      </Typography>
                      <ResponsiveContainer width="100%" height={200}>
                        <BarChart data={getUsageData()}>
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis dataKey="name" />
                          <YAxis />
                          <Tooltip />
                          <Bar dataKey="value" fill="#8884d8">
                            {getUsageData().map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={entry.color} />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle1" gutterBottom textAlign="center">
                        Estimated Risk Distribution
                      </Typography>
                      <ResponsiveContainer width="100%" height={200}>
                        <PieChart>
                          <Pie
                            data={getRiskDistributionData()}
                            cx="50%"
                            cy="50%"
                            labelLine={false}
                            label={({ name, percent }) => `${name} ${((percent || 0) * 100).toFixed(0)}%`}
                            outerRadius={70}
                            fill="#8884d8"
                            dataKey="value"
                          >
                            {getRiskDistributionData().map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={entry.color} />
                            ))}
                          </Pie>
                          <Tooltip />
                        </PieChart>
                      </ResponsiveContainer>
                    </Grid>
                  </Grid>
                </>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Provider Domains */}
        {providerDetails.domains && providerDetails.domains.length > 0 && (
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Provider Domains ({providerDetails.domains.length})
                </Typography>
                <Typography variant="body2" color="textSecondary" gutterBottom>
                  Domains owned by this provider
                </Typography>
                <List dense>
                  {providerDetails.domains.map((domain, idx) => (
                    <ListItem key={idx}>
                      <ListItemIcon>
                        <NetworkIcon sx={{ fontSize: 16 }} />
                      </ListItemIcon>
                      <ListItemText primary={domain} />
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>
        )}

        {/* IP Ranges */}
        {providerDetails.ip_ranges && providerDetails.ip_ranges.length > 0 && (
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  IP Ranges ({providerDetails.ip_ranges.length})
                </Typography>
                <Typography variant="body2" color="textSecondary" gutterBottom>
                  Network ranges managed by this provider
                </Typography>
                <List dense>
                  {providerDetails.ip_ranges.map((range, idx) => (
                    <ListItem key={idx}>
                      <ListItemIcon>
                        <IPIcon sx={{ fontSize: 16 }} />
                      </ListItemIcon>
                      <ListItemText 
                        primary={range}
                        secondary="Network range"
                      />
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>
        )}

        {/* Associated Domains */}
        {providerDetails.usage && providerDetails.usage.domains.length > 0 && (
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Associated Domains ({providerDetails.usage.total_domains})
                </Typography>
                <Typography variant="body2" color="textSecondary" gutterBottom>
                  Domains using this provider's services
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Domain</TableCell>
                        <TableCell>TLD</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {providerDetails.usage.domains.slice(0, 10).map((domain, idx) => (
                        <TableRow key={idx} hover>
                          <TableCell>
                            <Box display="flex" alignItems="center" gap={1}>
                              <DomainIcon sx={{ fontSize: 16 }} />
                              <Typography 
                                variant="body2" 
                                sx={{ cursor: 'pointer', '&:hover': { textDecoration: 'underline' } }}
                                onClick={() => navigate(`/domains/${domain}`)}
                              >
                                {domain}
                              </Typography>
                            </Box>
                          </TableCell>
                          <TableCell>
                            <Typography variant="caption">
                              .{domain.split('.').pop()}
                            </Typography>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
                {providerDetails.usage.domains.length > 10 && (
                  <Typography variant="caption" color="textSecondary" sx={{ mt: 1, display: 'block' }}>
                    Showing 10 of {providerDetails.usage.domains.length} domains
                  </Typography>
                )}
              </CardContent>
            </Card>
          </Grid>
        )}

        {/* Associated Subdomains */}
        {providerDetails.usage && providerDetails.usage.subdomains.length > 0 && (
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Associated Subdomains ({providerDetails.usage.total_subdomains})
                </Typography>
                <Typography variant="body2" color="textSecondary" gutterBottom>
                  Subdomains using this provider's services
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Subdomain</TableCell>
                        <TableCell>Base Domain</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {providerDetails.usage.subdomains.slice(0, 15).map((subdomain, idx) => (
                        <TableRow key={idx} hover>
                          <TableCell>
                            <Box>
                              <Box display="flex" alignItems="center" gap={1}>
                                <SubdomainIcon sx={{ fontSize: 16 }} />
                                <Typography 
                                  variant="body2"
                                  sx={{ cursor: 'pointer', '&:hover': { textDecoration: 'underline' } }}
                                  onClick={() => navigate(`/domains/${subdomain}`)}
                                >
                                  {subdomain}
                                </Typography>
                              </Box>
                            </Box>
                          </TableCell>
                          <TableCell>
                            <Typography 
                              variant="caption" 
                              color="textSecondary"
                              sx={{ cursor: 'pointer', '&:hover': { textDecoration: 'underline' } }}
                              onClick={() => {
                                const baseDomain = subdomain.split('.').slice(-2).join('.');
                                navigate(`/domains/${baseDomain}`);
                              }}
                            >
                              {subdomain.split('.').slice(-2).join('.')}
                            </Typography>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
                {providerDetails.usage.subdomains.length > 15 && (
                  <Typography variant="caption" color="textSecondary" sx={{ mt: 1, display: 'block' }}>
                    Showing 15 of {providerDetails.usage.subdomains.length} subdomains
                  </Typography>
                )}
              </CardContent>
            </Card>
          </Grid>
        )}
      </Grid>
    </Box>
  );
};

export default ProviderDetail;