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
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  TablePagination,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  List,
  ListItem,
  ListItemText,
} from '@mui/material';
import {
  ArrowBack as ArrowBackIcon,
  Refresh as RefreshIcon,
  Security as SecurityIcon,
  Public as PublicIcon,
  Storage as StorageIcon,
  Visibility as VisibilityIcon,
  AccountTree as GraphIcon,
  Dns as DnsIcon,
  Mail as MailIcon,
} from '@mui/icons-material';
import { domainApi, calculationApi, riskApi } from '../services/api';
import { BaseDomainDetailsResponse, RiskScoreResponse } from '../types/api';
import DomainDependencies from '../components/DomainDependencies';
import DependencyGraphView from '../components/DependencyGraphView';

const BaseDomainDetail: React.FC = () => {
  const { baseDomain } = useParams<{ baseDomain: string }>();
  const navigate = useNavigate();
  const [domainDetails, setDomainDetails] = useState<BaseDomainDetailsResponse | null>(null);
  const [riskScore, setRiskScore] = useState<RiskScoreResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [calculating, setCalculating] = useState(false);
  const [pagination, setPagination] = useState({ page: 0, pageSize: 10 });
  const [servicesDialogOpen, setServicesDialogOpen] = useState(false);
  const [providersDialogOpen, setProvidersDialogOpen] = useState(false);
  const [graphDialogOpen, setGraphDialogOpen] = useState(false);

  const fetchDomainDetails = async () => {
    if (!baseDomain) return;
    
    try {
      setLoading(true);
      const [domainData, riskData] = await Promise.all([
        domainApi.getBaseDomainDetails(baseDomain, true),
        riskApi.getRiskScore('domain', baseDomain, true)
      ]);
      setDomainDetails(domainData);
      setRiskScore(riskData);
      setError(null);
    } catch (err) {
      setError('Failed to load base domain details');
      console.error('Base domain detail error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleRecalculateRisk = async () => {
    if (!baseDomain) return;
    
    try {
      setCalculating(true);
      // Calculate risk for all subdomains in the base domain
      const promises = domainDetails?.subdomains?.map(subdomain => 
        calculationApi.calculateDomainRisk(subdomain.fqdn, false)
      ) || [];
      
      await Promise.all(promises);
      
      // Wait a bit for calculations to complete and then refresh
      setTimeout(() => {
        fetchDomainDetails();
        setCalculating(false);
      }, 3000);
    } catch (err) {
      setCalculating(false);
      console.error('Risk calculation error:', err);
    }
  };

  // Helper function to get letter grade from risk score
  const getRiskGrade = (score: number): { grade: string; color: string; bgColor: string } => {
    if (score >= 80) return { grade: 'A', color: '#4caf50', bgColor: '#e8f5e8' };
    if (score >= 60) return { grade: 'B', color: '#8bc34a', bgColor: '#f1f8e9' };
    if (score >= 40) return { grade: 'C', color: '#ff9800', bgColor: '#fff3e0' };
    if (score >= 20) return { grade: 'D', color: '#ff5722', bgColor: '#fce4ec' };
    return { grade: 'E', color: '#f44336', bgColor: '#ffebee' };
  };

  const getRiskTierColor = (tier: string) => {
    switch (tier?.toLowerCase()) {
      case 'critical': return '#d32f2f';
      case 'high': return '#f57c00';
      case 'medium': return '#1976d2';
      case 'low': return '#388e3c';
      default: return '#757575';
    }
  };

  const getRiskTierChipColor = (tier: string): 'default' | 'primary' | 'secondary' | 'error' | 'info' | 'success' | 'warning' => {
    switch (tier?.toLowerCase()) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  // Helper functions to aggregate DNS and MX data from subdomains
  const getDnsData = () => {
    if (!domainDetails?.subdomains) return null;
    
    let dnssecEnabled = 0;
    let spfRecords = 0;
    let dmarcRecords = 0;
    let totalWithDns = 0;
    let nameServers: Set<string> = new Set();
    
    domainDetails.subdomains.forEach(subdomain => {
      // We would need to fetch individual domain details to get DNS info
      // For now, we'll show placeholder data
    });
    
    return {
      hasData: totalWithDns > 0,
      dnssecEnabled,
      spfRecords,
      dmarcRecords,
      totalWithDns,
      nameServers: Array.from(nameServers)
    };
  };
  
  const getMxData = () => {
    if (!domainDetails?.subdomains) return null;
    
    let mxProviders: Set<string> = new Set();
    let totalWithMx = 0;
    
    domainDetails.subdomains.forEach(subdomain => {
      // We would need to fetch individual domain details to get MX info
      // For now, we'll show placeholder data
    });
    
    return {
      hasData: totalWithMx > 0,
      mxProviders: Array.from(mxProviders),
      totalWithMx
    };
  };

  useEffect(() => {
    fetchDomainDetails();
  }, [baseDomain]); // eslint-disable-line react-hooks/exhaustive-deps

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

  const paginatedSubdomains = domainDetails?.subdomains?.slice(
    pagination.page * pagination.pageSize,
    pagination.page * pagination.pageSize + pagination.pageSize
  ) || [];

  return (
    <Box>
      {/* Emergency Graph Button - Always Visible */}
      <Box 
        position="fixed" 
        top={80} 
        right={20} 
        zIndex={1000}
        sx={{ display: { xs: 'none', md: 'block' } }}
      >
        <Button
          variant="contained"
          startIcon={<GraphIcon />}
          onClick={() => setGraphDialogOpen(true)}
          sx={{ 
            backgroundColor: '#ff5722',
            '&:hover': { backgroundColor: '#e64a19' },
            fontWeight: 'bold',
            fontSize: '0.9rem',
            boxShadow: 3
          }}
        >
          🔍 GRAPH
        </Button>
      </Box>
      
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Box display="flex" alignItems="center">
          <Button
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate('/domains')}
            sx={{ mr: 2 }}
          >
            Back
          </Button>
          <Typography variant="h4">{domainDetails?.base_domain || 'Unknown Domain'}</Typography>
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
            onClick={fetchDomainDetails}
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

      {domainDetails && domainDetails.subdomains?.every(d => d.services?.length === 0 && d.providers?.length === 0) && (
        <Alert severity="info" sx={{ mb: 2 }}>
          Notice: This base domain has limited service and provider information. Use the "Recalculate Risk" button to trigger a comprehensive analysis.
        </Alert>
      )}

      <Grid container spacing={3}>
        {/* Risk Summary with Detailed Breakdown */}
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Risk Analysis & Calculation
              </Typography>
              
              {riskScore?.score_breakdown ? (
                <Box>
                  {/* Overall Risk Score and Grade */}
                  <Box display="flex" alignItems="center" mb={3}>
                    <Box 
                      sx={{
                        width: 80,
                        height: 80,
                        borderRadius: '50%',
                        backgroundColor: getRiskGrade(riskScore.risk_score).bgColor,
                        border: `3px solid ${getRiskGrade(riskScore.risk_score).color}`,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        mr: 3
                      }}
                    >
                      <Typography 
                        variant="h3" 
                        sx={{ 
                          color: getRiskGrade(riskScore.risk_score).color,
                          fontWeight: 'bold' 
                        }}
                      >
                        {getRiskGrade(riskScore.risk_score).grade}
                      </Typography>
                    </Box>
                    <Box>
                      <Typography variant="h4" sx={{ color: getRiskTierColor(riskScore.risk_tier) }}>
                        {riskScore.risk_score.toFixed(1)}
                      </Typography>
                      <Typography variant="h6" color="textSecondary">
                        {riskScore.risk_tier} Risk
                      </Typography>
                      <Typography variant="caption" color="textSecondary">
                        Last calculated: {riskScore.last_calculated ? new Date(riskScore.last_calculated).toLocaleString() : 'Never'}
                      </Typography>
                    </Box>
                  </Box>

                  <Divider sx={{ mb: 3 }} />

                  {/* Risk Component Breakdown */}
                  <Typography variant="h6" gutterBottom>
                    Risk Components Breakdown
                  </Typography>
                  
                  <Grid container spacing={2}>
                    <Grid item xs={6} md={3}>
                      <Box textAlign="center" p={2} bgcolor="#f5f5f5" borderRadius={1}>
                        <Typography variant="h5" color="primary" gutterBottom>
                          {(riskScore.score_breakdown.base_score || 0).toFixed(1)}
                        </Typography>
                        <Typography variant="body2" fontWeight="medium">
                          Base Score
                        </Typography>
                        <Typography variant="caption" color="textSecondary">
                          Weight: {((riskScore.score_breakdown.weights?.base_score || 0) * 100).toFixed(0)}%
                        </Typography>
                      </Box>
                    </Grid>
                    
                    <Grid item xs={6} md={3}>
                      <Box textAlign="center" p={2} bgcolor="#f5f5f5" borderRadius={1}>
                        <Typography variant="h5" color="warning.main" gutterBottom>
                          {(riskScore.score_breakdown.third_party_score || 0).toFixed(1)}
                        </Typography>
                        <Typography variant="body2" fontWeight="medium">
                          3rd Party Risk
                        </Typography>
                        <Typography variant="caption" color="textSecondary">
                          Weight: {((riskScore.score_breakdown.weights?.third_party_score || 0) * 100).toFixed(0)}%
                        </Typography>
                      </Box>
                    </Grid>
                    
                    <Grid item xs={6} md={3}>
                      <Box textAlign="center" p={2} bgcolor="#f5f5f5" borderRadius={1}>
                        <Typography variant="h5" color="error.main" gutterBottom>
                          {(riskScore.score_breakdown.incident_impact || 0).toFixed(1)}
                        </Typography>
                        <Typography variant="body2" fontWeight="medium">
                          Incident Impact
                        </Typography>
                        <Typography variant="caption" color="textSecondary">
                          Weight: {((riskScore.score_breakdown.weights?.incident_impact || 0) * 100).toFixed(0)}%
                        </Typography>
                      </Box>
                    </Grid>
                    
                    <Grid item xs={6} md={3}>
                      <Box textAlign="center" p={2} bgcolor="#f5f5f5" borderRadius={1}>
                        <Typography variant="h5" color="info.main" gutterBottom>
                          {(riskScore.score_breakdown.context_boost || 0).toFixed(1)}
                        </Typography>
                        <Typography variant="body2" fontWeight="medium">
                          Context Boost
                        </Typography>
                        <Typography variant="caption" color="textSecondary">
                          Weight: {((riskScore.score_breakdown.weights?.context_boost || 0) * 100).toFixed(0)}%
                        </Typography>
                      </Box>
                    </Grid>
                  </Grid>

                  <Box mt={3} p={2} bgcolor="#e3f2fd" borderRadius={1}>
                    <Typography variant="body2" gutterBottom>
                      <strong>Risk Grading Scale:</strong>
                    </Typography>
                    <Box display="flex" gap={1} flexWrap="wrap">
                      {[
                        { grade: 'A', range: '80-100', desc: 'Excellent', color: '#4caf50' },
                        { grade: 'B', range: '60-79', desc: 'Good', color: '#8bc34a' },
                        { grade: 'C', range: '40-59', desc: 'Average', color: '#ff9800' },
                        { grade: 'D', range: '20-39', desc: 'Poor', color: '#ff5722' },
                        { grade: 'E', range: '0-19', desc: 'Critical', color: '#f44336' }
                      ].map((item) => (
                        <Chip
                          key={item.grade}
                          label={`${item.grade} (${item.range}): ${item.desc}`}
                          size="small"
                          sx={{
                            backgroundColor: item.color + '20',
                            color: item.color,
                            border: `1px solid ${item.color}`
                          }}
                        />
                      ))}
                    </Box>
                  </Box>
                </Box>
              ) : (
                <Box>
                  <Typography variant="h4" color="primary" gutterBottom>
                    {domainDetails.risk_summary?.max_risk_score?.toFixed(1) || '0.0'}
                  </Typography>
                  <Typography variant="body2" color="textSecondary" gutterBottom>
                    Max Risk Score (detailed breakdown not available)
                  </Typography>
                  <Typography variant="body2" gutterBottom>
                    Average: {domainDetails.risk_summary?.average_risk_score?.toFixed(1) || '0.0'}
                  </Typography>
                </Box>
              )}

              <Divider sx={{ my: 2 }} />
              <Box display="flex" gap={1} mb={1}>
                <Chip 
                  label={`${domainDetails.risk_summary?.critical_subdomains || 0} Critical`} 
                  color="error"
                  size="small"
                />
                <Chip 
                  label={`${domainDetails.risk_summary?.high_risk_subdomains || 0} High`} 
                  color="warning"
                  size="small"
                />
              </Box>
              <Typography variant="body2" color="textSecondary">
                Active Incidents: {domainDetails.risk_summary?.total_incidents || 0}
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
                {domainDetails.service_summary?.total_services || 0}
              </Typography>
              <Typography variant="body2" color="textSecondary" gutterBottom>
                Total Services
              </Typography>
              {domainDetails.service_summary?.services && domainDetails.service_summary.services.length > 0 && (
                <Box>
                  <Divider sx={{ my: 2 }} />
                  <Box display="flex" flexWrap="wrap" gap={0.5}>
                    {domainDetails.service_summary.services.slice(0, 5).map((service, index) => (
                      <Chip key={index} label={service} size="small" variant="outlined" />
                    ))}
                    {domainDetails.service_summary.services.length > 5 && (
                      <Chip 
                        label={`+${domainDetails.service_summary.services.length - 5} more`} 
                        size="small" 
                        onClick={() => setServicesDialogOpen(true)}
                        sx={{ cursor: 'pointer' }}
                      />
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
                {domainDetails.provider_summary?.total_providers || 0}
              </Typography>
              <Typography variant="body2" color="textSecondary" gutterBottom>
                Total Providers
              </Typography>
              {domainDetails.provider_summary?.providers && domainDetails.provider_summary.providers.length > 0 && (
                <Box>
                  <Divider sx={{ my: 2 }} />
                  <Box display="flex" flexWrap="wrap" gap={0.5}>
                    {domainDetails.provider_summary.providers.slice(0, 5).map((provider, index) => (
                      <Chip key={index} label={provider} size="small" variant="outlined" />
                    ))}
                    {domainDetails.provider_summary.providers.length > 5 && (
                      <Chip 
                        label={`+${domainDetails.provider_summary.providers.length - 5} more`} 
                        size="small" 
                        onClick={() => setProvidersDialogOpen(true)}
                        sx={{ cursor: 'pointer' }}
                      />
                    )}
                  </Box>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>
        
        {/* DNS Summary */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" mb={2}>
                <DnsIcon sx={{ mr: 1 }} />
                <Typography variant="h6">DNS Information</Typography>
              </Box>
              <Typography variant="h4" color="primary" gutterBottom>
                {domainDetails?.total_count || 0}
              </Typography>
              <Typography variant="body2" color="textSecondary" gutterBottom>
                Subdomains with DNS Data
              </Typography>
              
              <List dense>
                <ListItem>
                  <ListItemText 
                    primary="Base Domain DNS" 
                    secondary={
                      <Chip 
                        label="Available at subdomain level" 
                        color="info"
                        size="small"
                      />
                    }
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary="DNSSEC Analysis" 
                    secondary="Check individual subdomains for DNSSEC status"
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary="SPF/DMARC Records" 
                    secondary="Email security records per subdomain"
                  />
                </ListItem>
              </List>
            </CardContent>
          </Card>
        </Grid>
        
        {/* MX Summary */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" mb={2}>
                <MailIcon sx={{ mr: 1 }} />
                <Typography variant="h6">Mail (MX) Information</Typography>
              </Box>
              <Typography variant="h4" color="primary" gutterBottom>
                {domainDetails?.total_count || 0}
              </Typography>
              <Typography variant="body2" color="textSecondary" gutterBottom>
                Subdomains with Mail Services
              </Typography>
              
              <List dense>
                <ListItem>
                  <ListItemText 
                    primary="MX Records" 
                    secondary={
                      <Chip 
                        label="Available at subdomain level" 
                        color="info"
                        size="small"
                      />
                    }
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary="Mail Providers" 
                    secondary="Check individual subdomains for mail servers"
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary="Email Security" 
                    secondary="SPF, DMARC, DKIM analysis per subdomain"
                  />
                </ListItem>
              </List>
            </CardContent>
          </Card>
        </Grid>

        {/* Subdomains Detail */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Subdomains ({domainDetails?.total_count || 0})
              </Typography>
              <Alert severity="info" sx={{ mb: 2 }}>
                DNS and MX information is available at the individual subdomain level. Click the view icon to see detailed DNS and MX records for each subdomain.
              </Alert>
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
                    {paginatedSubdomains.map((subdomain) => (
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
                            color={getRiskTierChipColor(subdomain.risk_tier)}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          <Box display="flex" flexWrap="wrap" gap={0.5}>
                            {subdomain.services?.slice(0, 2).map((service, index) => (
                              <Chip key={index} label={service} size="small" variant="outlined" />
                            )) || []}
                            {(subdomain.services?.length || 0) > 2 && (
                              <Chip label={`+${(subdomain.services?.length || 0) - 2}`} size="small" />
                            )}
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Box display="flex" flexWrap="wrap" gap={0.5}>
                            {subdomain.providers?.slice(0, 2).map((provider, index) => (
                              <Chip key={index} label={provider} size="small" variant="outlined" />
                            )) || []}
                            {(subdomain.providers?.length || 0) > 2 && (
                              <Chip label={`+${(subdomain.providers?.length || 0) - 2}`} size="small" />
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
              <TablePagination
                rowsPerPageOptions={[5, 10, 25, 50]}
                component="div"
                count={domainDetails?.total_count || 0}
                rowsPerPage={pagination.pageSize}
                page={pagination.page}
                onPageChange={handleChangePage}
                onRowsPerPageChange={handleChangeRowsPerPage}
              />
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Services Dialog */}
      <Dialog open={servicesDialogOpen} onClose={() => setServicesDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>All Services ({domainDetails?.service_summary?.total_services})</DialogTitle>
        <DialogContent>
          <Box display="flex" flexWrap="wrap" gap={1}>
            {domainDetails?.service_summary?.services?.map((service, index) => (
              <Chip key={index} label={service} variant="outlined" />
            ))}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setServicesDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Providers Dialog */}
      <Dialog open={providersDialogOpen} onClose={() => setProvidersDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>All Providers ({domainDetails?.provider_summary?.total_providers})</DialogTitle>
        <DialogContent>
          <Box display="flex" flexWrap="wrap" gap={1}>
            {domainDetails?.provider_summary?.providers?.map((provider, index) => (
              <Chip key={index} label={provider} variant="outlined" />
            ))}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setProvidersDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

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
          Dependency Graph for {domainDetails?.base_domain}
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
            domain={baseDomain || ''} 
            height={600}
            showFullscreen={true}
          />
        </DialogContent>
      </Dialog>

      {/* Dependencies Section */}
      <Card sx={{ mt: 3 }}>
        <CardContent>
          <DomainDependencies domain={baseDomain || ''} />
        </CardContent>
      </Card>
    </Box>
  );
};

export default BaseDomainDetail;