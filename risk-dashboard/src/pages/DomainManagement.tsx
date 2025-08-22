import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  Button,
  TextField,
  Grid,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
} from '@mui/material';
import { 
  Table, 
  TableBody, 
  TableCell, 
  TableContainer, 
  TableHead, 
  TableRow, 
  Paper,
  TablePagination,
  IconButton 
} from '@mui/material';
import {
  Add as AddIcon,
  Visibility as ViewIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { domainApi, calculationApi, dependencyApi } from '../services/api';
import { BaseDomainResponse, BaseDomainsListResponse } from '../types/api';

// Helper functions for provider extraction
const extractProviderFromFQDN = (fqdn: string): string | null => {
  const domain = fqdn.toLowerCase();
  
  // Cloud providers
  if (domain.includes('amazonaws.com')) return 'aws';
  if (domain.includes('azurewebsites') || domain.includes('azure')) return 'azure';
  if (domain.includes('googleusercontent') || domain.includes('gcp') || domain.includes('googleapis')) return 'google-cloud';
  if (domain.includes('digitalocean')) return 'digitalocean';
  
  // CDN/Security providers
  if (domain.includes('cloudflare')) return 'cloudflare';
  if (domain.includes('imperva')) return 'imperva';
  if (domain.includes('akamai')) return 'akamai';
  if (domain.includes('fastly')) return 'fastly';
  if (domain.includes('maxcdn')) return 'maxcdn';
  
  // Business platforms
  if (domain.includes('salesforce')) return 'salesforce';
  if (domain.includes('hubspot')) return 'hubspot';
  if (domain.includes('mailchimp')) return 'mailchimp';
  if (domain.includes('zendesk')) return 'zendesk';
  
  // Generic patterns
  if (domain.includes('cdn')) return 'cdn-service';
  if (domain.includes('api.') && !domain.includes(fqdn.split('.').slice(-2).join('.'))) return 'api-provider';
  
  return null;
};

const extractProviderFromService = (serviceName: string): string | null => {
  const service = serviceName.toLowerCase();
  
  // Map service names to provider names
  const serviceToProvider: { [key: string]: string } = {
    'cloudflare': 'cloudflare',
    'imperva': 'imperva',
    'akamai': 'akamai',
    'aws': 'aws',
    'amazon': 'aws',
    'google': 'google-cloud',
    'microsoft': 'azure',
    'fastly': 'fastly',
    'salesforce': 'salesforce',
    'cdn': 'cdn-service',
    'security': 'security-service',
    'dns': 'dns-service',
    'email': 'email-service',
    'analytics': 'analytics-service'
  };
  
  for (const [key, provider] of Object.entries(serviceToProvider)) {
    if (service.includes(key)) {
      return provider;
    }
  }
  
  return service !== 'unknown' ? service : null;
};

const DomainManagement: React.FC = () => {
  const navigate = useNavigate();
  const [domains, setDomains] = useState<BaseDomainResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [addDialogOpen, setAddDialogOpen] = useState(false);
  const [newDomainFqdn, setNewDomainFqdn] = useState('');

  // TLD to Country mapping
  const tldCountryMap: { [key: string]: string } = {
    '.cl': 'Chile (.cl)',
    '.ar': 'Argentina (.ar)',
    '.br': 'Brazil (.br)',
    '.mx': 'Mexico (.mx)',
    '.co': 'Colombia (.co)',
    '.pe': 'Peru (.pe)',
    '.ve': 'Venezuela (.ve)',
    '.uy': 'Uruguay (.uy)',
    '.py': 'Paraguay (.py)',
    '.ec': 'Ecuador (.ec)',
    '.bo': 'Bolivia (.bo)',
    '.gt': 'Guatemala (.gt)',
    '.cr': 'Costa Rica (.cr)',
    '.pa': 'Panama (.pa)',
    '.us': 'United States (.us)',
    '.ca': 'Canada (.ca)',
    '.uk': 'United Kingdom (.uk)',
    '.de': 'Germany (.de)',
    '.fr': 'France (.fr)',
    '.es': 'Spain (.es)',
    '.it': 'Italy (.it)',
    '.com': 'Commercial (.com)',
    '.org': 'Organization (.org)',
    '.net': 'Network (.net)',
    '.edu': 'Education (.edu)',
    '.gov': 'Government (.gov)',
  };
  const [filters, setFilters] = useState({
    riskTier: '',
    businessCriticality: '',
    search: '',
    tld: '',
  });
  const [pagination, setPagination] = useState({
    page: 0,
    pageSize: 100,
    total: 0,
  });

  const fetchDomains = async () => {
    try {
      setLoading(true);
      const response: BaseDomainsListResponse = await domainApi.listBaseDomains({
        riskTier: filters.riskTier || undefined,
        businessCriticality: filters.businessCriticality || undefined,
        search: filters.search || undefined,
        tld: filters.tld || undefined,
        limit: pagination.pageSize,
        offset: pagination.page * pagination.pageSize,
      });
      
      // Use service_count as provider count since provider_count is 0 for all domains
      const domainsWithProviderInfo = response.base_domains.map(domain => {
        console.log(`🔍 DOMAIN DEBUG: ${domain.base_domain} - subdomain_count=${domain.subdomain_count}, service_count=${domain.service_count}, provider_count=${domain.provider_count}`);
        
        // Use services as providers since that's where the real data is
        const actualProviderCount = domain.service_count || 0;
        const preview = actualProviderCount > 0 ? 
          Array.from({length: Math.min(actualProviderCount, 3)}, (_, i) => `Service ${i + 1}`) : 
          [];
        
        console.log(`✅ SETTING ${domain.base_domain}: related_domains_count=${actualProviderCount}, preview=${JSON.stringify(preview)}`);
        
        return {
          ...domain,
          related_domains_count: actualProviderCount,
          related_domains_preview: preview
        };
      });
      
      setDomains(domainsWithProviderInfo);
      setPagination(prev => ({ ...prev, total: response.total_count }));
      setError(null);
    } catch (err) {
      setError('Failed to load base domains');
      console.error('Base domains error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDomains();
  }, [filters, pagination.page, pagination.pageSize]);

  const handleAddDomain = async () => {
    if (!newDomainFqdn.trim()) return;
    
    try {
      await calculationApi.calculateDomainRisk(newDomainFqdn.trim());
      setAddDialogOpen(false);
      setNewDomainFqdn('');
      fetchDomains();
    } catch (err) {
      console.error('Failed to add domain:', err);
    }
  };

  const getRiskTierColor = (tier: string) => {
    switch (tier.toLowerCase()) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'success';
      default: return 'default';
    }
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
      <Box display="flex" justifyContent="between" alignItems="center" mb={3}>
        <Typography variant="h4">Base Domain Management</Typography>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => setAddDialogOpen(true)}
        >
          Add Domain
        </Button>
      </Box>

      <Grid container spacing={2} mb={3}>
        <Grid item xs={12} sm={6} md={3}>
          <TextField
            fullWidth
            label="Search Base Domains"
            value={filters.search}
            onChange={(e) => setFilters(prev => ({ ...prev, search: e.target.value }))}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
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
        <Grid item xs={12} sm={6} md={3}>
          <FormControl fullWidth>
            <InputLabel>Business Criticality</InputLabel>
            <Select
              value={filters.businessCriticality}
              label="Business Criticality"
              onChange={(e) => setFilters(prev => ({ ...prev, businessCriticality: e.target.value }))}
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="Critical">Critical</MenuItem>
              <MenuItem value="High">High</MenuItem>
              <MenuItem value="Medium">Medium</MenuItem>
              <MenuItem value="Low">Low</MenuItem>
            </Select>
          </FormControl>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <FormControl fullWidth>
            <InputLabel>Country / TLD</InputLabel>
            <Select
              value={filters.tld}
              label="Country / TLD"
              onChange={(e) => setFilters(prev => ({ ...prev, tld: e.target.value }))}
            >
              <MenuItem value="">All Countries</MenuItem>
              {Object.entries(tldCountryMap).map(([tld, country]) => (
                <MenuItem key={tld} value={tld}>
                  {country}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Button
            fullWidth
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={fetchDomains}
            sx={{ height: '56px' }}
          >
            Refresh
          </Button>
        </Grid>
      </Grid>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      
      {domains.length > 0 && domains.every(d => d.service_count === 0 && d.provider_count === 0) && (
        <Alert severity="info" sx={{ mb: 2 }}>
          Notice: Service and provider data appears to be incomplete. Consider running domain discovery to populate detailed information.
        </Alert>
      )}

      <Card>
        <CardContent>
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Base Domain</TableCell>
                  <TableCell>Subdomains</TableCell>
                  <TableCell>Services</TableCell>
                  <TableCell>Providers</TableCell>
                  <TableCell>Risk Score</TableCell>
                  <TableCell>Risk Tier</TableCell>
                  <TableCell>Critical/High</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {loading ? (
                  <TableRow>
                    <TableCell colSpan={8} align="center">
                      <CircularProgress />
                    </TableCell>
                  </TableRow>
                ) : domains.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} align="center">
                      <Typography variant="body2" color="textSecondary">
                        No base domains found
                      </Typography>
                    </TableCell>
                  </TableRow>
                ) : (
                  domains.map((domain) => (
                    <TableRow key={domain.base_domain}>
                    <TableCell>
                      <Typography variant="body2" fontWeight="bold">
                        {domain.base_domain}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {domain.subdomain_count}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {domain.service_count}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {domain.provider_count}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" fontWeight="bold">
                        {domain.max_risk_score.toFixed(1)}
                      </Typography>
                      <Typography variant="caption" color="textSecondary">
                        (avg: {domain.avg_risk_score.toFixed(1)})
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={domain.risk_tier} 
                        color={getRiskTierColor(domain.risk_tier) as any}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>
                      <Box display="flex" gap={1}>
                        {domain.critical_subdomains > 0 && (
                          <Chip 
                            label={`${domain.critical_subdomains} Critical`} 
                            color="error"
                            size="small"
                          />
                        )}
                        {domain.high_risk_subdomains > 0 && (
                          <Chip 
                            label={`${domain.high_risk_subdomains} High`} 
                            color="warning"
                            size="small"
                          />
                        )}
                      </Box>
                    </TableCell>
                    <TableCell>
                      <IconButton 
                        size="small" 
                        onClick={() => navigate(`/base-domains/${domain.base_domain}`)}
                      >
                        <ViewIcon />
                      </IconButton>
                    </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </TableContainer>
          <TablePagination
            rowsPerPageOptions={[25, 50, 100, 200]}
            component="div"
            count={pagination.total}
            rowsPerPage={pagination.pageSize}
            page={pagination.page}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPage}
          />
        </CardContent>
      </Card>

      <Dialog open={addDialogOpen} onClose={() => setAddDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Add New Domain</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            margin="dense"
            label="Domain FQDN"
            placeholder="example.com"
            fullWidth
            variant="outlined"
            value={newDomainFqdn}
            onChange={(e) => setNewDomainFqdn(e.target.value)}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAddDialogOpen(false)}>Cancel</Button>
          <Button onClick={handleAddDomain} variant="contained">
            Add Domain
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default DomainManagement;