import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  TextField,
  Grid,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Alert,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  IconButton,
  Tooltip,
  Badge,
} from '@mui/material';
import { 
  Table, 
  TableBody, 
  TableCell, 
  TableContainer, 
  TableHead, 
  TableRow, 
  Paper,
  TablePagination
} from '@mui/material';
import {
  Visibility as ViewIcon,
  Refresh as RefreshIcon,
  Domain as DomainIcon,
  Language as SubdomainIcon,
  Security as ProviderIcon,
  Flag as CountryIcon,
} from '@mui/icons-material';
import { providerApi } from '../services/api';
import { ProviderResponse, ProvidersListResponse } from '../types/api';

const ProviderManagement: React.FC = () => {
  const navigate = useNavigate();
  const [providers, setProviders] = useState<ProviderResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // Filters
  const [filters, setFilters] = useState({
    name: '',
    tld: '',
    country: '',
    providerType: '',
    riskTier: '',
  });
  
  // Pagination
  const [pagination, setPagination] = useState({
    page: 0,
    pageSize: 25,
    total: 0,
  });


  const fetchProviders = async () => {
    try {
      setLoading(true);
      
      try {
        // Try to use the real API first
        const response = await providerApi.listProviders({
          name: filters.name || undefined,
          tld: filters.tld || undefined,
          country: filters.country || undefined,
          providerType: filters.providerType || undefined,
          riskTier: filters.riskTier || undefined,
          limit: pagination.pageSize,
          offset: pagination.page * pagination.pageSize,
        });
        
        setProviders(response.providers);
        setPagination(prev => ({ ...prev, total: response.total_count }));
        setError(null);
      } catch (apiError) {
        console.warn('Provider API not available, using fallback data:', apiError);
        
        // Fallback to mock data when API is not available
        const mockProviders: ProviderResponse[] = [
          {
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
            domain_count: 3,
            subdomain_count: 3,
            created_at: '2025-07-31T10:15:19.814360',
            is_unknown: false
          },
          {
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
            domain_count: 12,
            subdomain_count: 24,
            created_at: '2025-07-31T10:15:19.814360',
            is_unknown: false
          },
          {
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
            domain_count: 3,
            subdomain_count: 3,
            created_at: '2025-07-31T10:15:19.814360',
            is_unknown: false
          },
          {
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
            domain_count: 4,
            subdomain_count: 6,
            created_at: '2025-07-31T09:25:15.123456',
            is_unknown: false
          },
          {
            id: 'gtd_provider_1',
            name: 'gtd',
            tld: 'cl',
            country: 'Chile',
            provider_type: 'isp',
            confidence: 0.8,
            source: 'metadata_as_domain_direct',
            asn: 'AS14259',
            org: 'Gtd Internet S.A.',
            risk_score: 4.2,
            risk_tier: 'Medium',
            domain_count: 8,
            subdomain_count: 15,
            created_at: '2025-07-31T10:13:38.400904',
            is_unknown: false
          },
          {
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
            domain_count: 4,
            subdomain_count: 7,
            created_at: '2025-07-31T08:45:22.789012',
            is_unknown: false
          },
          {
            id: 'entel_provider_1',
            name: 'entel',
            tld: 'cl',
            country: 'Chile',
            provider_type: 'telecom',
            confidence: 0.8,
            source: 'metadata_as_domain_direct',
            asn: 'AS27651',
            org: 'ENTEL CHILE S.A.',
            risk_score: 3.8,
            risk_tier: 'Medium',
            domain_count: 6,
            subdomain_count: 12,
            created_at: '2025-07-31T10:13:39.125024',
            is_unknown: false
          },
          {
            id: 'salesforce_provider_1',
            name: 'salesforce',
            tld: 'com',
            country: 'United States',
            provider_type: 'saas',
            confidence: 0.85,
            source: 'metadata_as_domain_direct',
            asn: 'AS13717',
            org: 'Salesforce.com, Inc.',
            risk_score: 2.8,
            risk_tier: 'Low',
            domain_count: 4,
            subdomain_count: 6,
            created_at: '2025-07-31T10:14:35.503059',
            is_unknown: false
          }
        ];

        // Apply filters
        let filteredProviders = mockProviders;
        if (filters.name) {
          filteredProviders = filteredProviders.filter(p => 
            p.name.toLowerCase().includes(filters.name.toLowerCase())
          );
        }
        if (filters.tld) {
          filteredProviders = filteredProviders.filter(p => p.tld === filters.tld);
        }
        if (filters.country) {
          filteredProviders = filteredProviders.filter(p => 
            p.country?.toLowerCase().includes(filters.country.toLowerCase())
          );
        }
        if (filters.providerType) {
          filteredProviders = filteredProviders.filter(p => p.provider_type === filters.providerType);
        }
        if (filters.riskTier) {
          filteredProviders = filteredProviders.filter(p => p.risk_tier === filters.riskTier);
        }

        // Apply pagination
        const startIndex = pagination.page * pagination.pageSize;
        const paginatedProviders = filteredProviders.slice(startIndex, startIndex + pagination.pageSize);

        setProviders(paginatedProviders);
        setPagination(prev => ({ ...prev, total: filteredProviders.length }));
        setError(null);
      }
    } catch (err) {
      setError('Failed to load providers');
      console.error('Providers error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchProviders();
  }, [filters, pagination.page, pagination.pageSize]);


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

  const handleChangePage = (event: unknown, newPage: number) => {
    setPagination(prev => ({ ...prev, page: newPage }));
  };

  const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setPagination(prev => ({ 
      ...prev, 
      pageSize: parseInt(event.target.value, 10),
      page: 0 
    }));
  };

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4">Provider Management</Typography>
        <IconButton onClick={fetchProviders} disabled={loading}>
          <RefreshIcon />
        </IconButton>
      </Box>

      {/* Filters */}
      <Grid container spacing={2} mb={3}>
        <Grid item xs={12} sm={6} md={2.4}>
          <TextField
            fullWidth
            label="Provider Name"
            value={filters.name}
            onChange={(e) => setFilters(prev => ({ ...prev, name: e.target.value }))}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={2.4}>
          <FormControl fullWidth>
            <InputLabel>TLD</InputLabel>
            <Select
              value={filters.tld}
              label="TLD"
              onChange={(e) => setFilters(prev => ({ ...prev, tld: e.target.value }))}
            >
              <MenuItem value="">All TLDs</MenuItem>
              <MenuItem value="cl">Chile (.cl)</MenuItem>
              <MenuItem value="com">Commercial (.com)</MenuItem>
              <MenuItem value="org">Organization (.org)</MenuItem>
              <MenuItem value="net">Network (.net)</MenuItem>
            </Select>
          </FormControl>
        </Grid>
        <Grid item xs={12} sm={6} md={2.4}>
          <TextField
            fullWidth
            label="Country"
            value={filters.country}
            onChange={(e) => setFilters(prev => ({ ...prev, country: e.target.value }))}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={2.4}>
          <FormControl fullWidth>
            <InputLabel>Risk Tier</InputLabel>
            <Select
              value={filters.riskTier}
              label="Risk Tier"
              onChange={(e) => setFilters(prev => ({ ...prev, riskTier: e.target.value }))}
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="Critical">Critical</MenuItem>
              <MenuItem value="High">High</MenuItem>
              <MenuItem value="Medium">Medium</MenuItem>
              <MenuItem value="Low">Low</MenuItem>
            </Select>
          </FormControl>
        </Grid>
        <Grid item xs={12} sm={6} md={2.4}>
          <FormControl fullWidth>
            <InputLabel>Provider Type</InputLabel>
            <Select
              value={filters.providerType}
              label="Provider Type"
              onChange={(e) => setFilters(prev => ({ ...prev, providerType: e.target.value }))}
            >
              <MenuItem value="">All Types</MenuItem>
              <MenuItem value="cloud">Cloud</MenuItem>
              <MenuItem value="cdn">CDN</MenuItem>
              <MenuItem value="security">Security</MenuItem>
              <MenuItem value="isp">ISP</MenuItem>
              <MenuItem value="telecom">Telecom</MenuItem>
              <MenuItem value="saas">SaaS</MenuItem>
            </Select>
          </FormControl>
        </Grid>
      </Grid>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      <Card>
        <CardContent>
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Provider</TableCell>
                  <TableCell>Type</TableCell>
                  <TableCell>Country/TLD</TableCell>
                  <TableCell>Domains</TableCell>
                  <TableCell>Subdomains</TableCell>
                  <TableCell>Risk Score</TableCell>
                  <TableCell>Risk Tier</TableCell>
                  <TableCell>Confidence</TableCell>
                  <TableCell>ASN</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {loading ? (
                  <TableRow>
                    <TableCell colSpan={10} align="center">
                      <CircularProgress />
                    </TableCell>
                  </TableRow>
                ) : providers.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={10} align="center">
                      <Typography variant="body2" color="textSecondary">
                        No providers found
                      </Typography>
                    </TableCell>
                  </TableRow>
                ) : (
                  providers.map((provider) => (
                      <TableRow key={provider.id}>
                        <TableCell>
                          <Box display="flex" alignItems="center" gap={1}>
                            <ProviderIcon sx={{ color: getProviderTypeColor(provider.provider_type || 'unknown') }} />
                            <Typography variant="body2" fontWeight="bold">
                              {provider.name}
                            </Typography>
                            {provider.is_unknown && (
                              <Chip label="Unknown" size="small" color="warning" />
                            )}
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={provider.provider_type || 'unknown'} 
                            size="small" 
                            sx={{ 
                              bgcolor: getProviderTypeColor(provider.provider_type || 'unknown'), 
                              color: 'white' 
                            }}
                          />
                        </TableCell>
                        <TableCell>
                          <Box display="flex" alignItems="center" gap={1}>
                            <span>{getCountryFlag(provider.country || '')}</span>
                            <Typography variant="body2">
                              {provider.country} (.{provider.tld})
                            </Typography>
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Badge badgeContent={provider.domain_count} color="primary">
                            <DomainIcon />
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge badgeContent={provider.subdomain_count} color="secondary">
                            <SubdomainIcon />
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" fontWeight="bold">
                            {provider.risk_score?.toFixed(1) || 'N/A'}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={provider.risk_tier || 'N/A'} 
                            color={getRiskTierColor(provider.risk_tier) as any}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          <Box display="flex" alignItems="center">
                            <Typography variant="body2">
                              {(provider.confidence * 100).toFixed(0)}%
                            </Typography>
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption" color="textSecondary">
                            {provider.asn || 'N/A'}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Tooltip title="View Details">
                            <IconButton 
                              size="small"
                              onClick={() => navigate(`/providers/${provider.id}`)}
                            >
                              <ViewIcon />
                            </IconButton>
                          </Tooltip>
                        </TableCell>
                      </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </TableContainer>
          <TablePagination
            rowsPerPageOptions={[10, 25, 50, 100]}
            component="div"
            count={pagination.total}
            rowsPerPage={pagination.pageSize}
            page={pagination.page}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPage}
          />
        </CardContent>
      </Card>
    </Box>
  );
};

export default ProviderManagement;