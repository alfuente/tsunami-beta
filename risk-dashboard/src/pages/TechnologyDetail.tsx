import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Grid,
  Chip,
  CircularProgress,
  Alert,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  FormControlLabel,
  Switch,
  Button,
  Divider,
  Paper,
  IconButton,
  Tooltip,
  Breadcrumbs,
  Link,
} from '@mui/material';
import {
  Computer as TechIcon,
  ArrowBack as BackIcon,
  Visibility as ViewIcon,
  Security as SecurityIcon,
  Cloud as CloudIcon,
  Web as WebIcon,
  Code as CodeIcon,
  Refresh as RefreshIcon,
  Category as CategoryIcon,
} from '@mui/icons-material';
import { technologyApi } from '../services/api';

interface TechnologyDomain {
  domain: string;
  base_domain: string;
  risk_score: number;
  risk_tier: string;
  category: string;
  confidence: number;
  services: string[];
  providers: string[];
  analyzed_at: string;
  source: string;
}

interface TechnologyDetailData {
  technology_name: string;
  domains_from_analysis: TechnologyDomain[];
  domains_from_scraping: TechnologyDomain[];
  total_domains_analysis: number;
  total_domains_scraping: number;
  total_domains_combined: number;
}

const TechnologyDetail: React.FC = () => {
  const { technologyName } = useParams<{ technologyName: string }>();
  const navigate = useNavigate();
  const [technologyData, setTechnologyData] = useState<TechnologyDetailData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [includeScraped, setIncludeScraped] = useState(true);

  const decodedTechName = decodeURIComponent(technologyName || '');

  const fetchTechnologyDetails = async () => {
    if (!technologyName) return;
    
    setLoading(true);
    setError(null);

    try {
      const data = await technologyApi.getTechnologyDetails(decodedTechName, {
        include_scraped: includeScraped,
        limit: 500
      });
      setTechnologyData(data);
    } catch (err) {
      console.error('Error fetching technology details:', err);
      setError('Failed to load technology details');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTechnologyDetails();
  }, [technologyName, includeScraped]);

  const getCategoryIcon = (category: string) => {
    switch (category.toLowerCase()) {
      case 'javascript':
      case 'javascript_framework':
      case 'css_framework':
        return <CodeIcon />;
      case 'web_server':
      case 'web_server_version':
        return <WebIcon />;
      case 'threat_intelligence':
      case 'threat_intelligence_risk':
      case 'tls_vulnerability':
        return <SecurityIcon />;
      case 'infrastructure_intelligence':
      case 'third_party_provider':
        return <CloudIcon />;
      default:
        return <TechIcon />;
    }
  };

  const getCategoryColor = (category: string) => {
    switch (category.toLowerCase()) {
      case 'javascript':
      case 'javascript_framework':
        return '#f7df1e';
      case 'css_framework':
        return '#563d7c';
      case 'web_server':
      case 'web_server_version':
        return '#2196f3';
      case 'threat_intelligence':
      case 'threat_intelligence_risk':
      case 'tls_vulnerability':
        return '#f44336';
      case 'infrastructure_intelligence':
        return '#4caf50';
      case 'third_party_provider':
        return '#ff9800';
      case 'tls_configuration':
      case 'tls_certificate':
        return '#9c27b0';
      default:
        return '#757575';
    }
  };

  const getRiskTierColor = (tier: string) => {
    switch (tier?.toLowerCase()) {
      case 'critical':
        return 'error';
      case 'high':
        return 'warning';
      case 'medium':
        return 'info';
      case 'low':
        return 'success';
      default:
        return 'default';
    }
  };

  const getAllDomains = () => {
    if (!technologyData) return [];
    
    const allDomains = [
      ...technologyData.domains_from_analysis,
      ...(includeScraped ? technologyData.domains_from_scraping : [])
    ];
    
    // Remove duplicates based on domain name
    const uniqueDomains = allDomains.reduce((acc: TechnologyDomain[], current) => {
      const isDuplicate = acc.find(domain => domain.domain === current.domain);
      if (!isDuplicate) {
        acc.push(current);
      }
      return acc;
    }, []);
    
    return uniqueDomains;
  };

  const paginatedDomains = getAllDomains().slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" height="400px">
        <CircularProgress />
      </Box>
    );
  }

  if (!technologyData) {
    return (
      <Box>
        <Alert severity="error">Technology not found</Alert>
      </Box>
    );
  }

  return (
    <Box>
      {/* Header with breadcrumbs */}
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Box>
          <Breadcrumbs aria-label="breadcrumb" sx={{ mb: 1 }}>
            <Link
              component="button"
              underline="hover"
              onClick={() => navigate('/technologies')}
            >
              Technologies
            </Link>
            <Typography color="text.primary">{decodedTechName}</Typography>
          </Breadcrumbs>
          
          <Box display="flex" alignItems="center">
            <IconButton onClick={() => navigate('/technologies')} sx={{ mr: 1 }}>
              <BackIcon />
            </IconButton>
            <Typography variant="h4">{decodedTechName}</Typography>
          </Box>
        </Box>
        
        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
          onClick={fetchTechnologyDetails}
        >
          Refresh
        </Button>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Statistics Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <TechIcon sx={{ mr: 2, color: '#2196f3' }} />
                <Box>
                  <Typography variant="h4" color="primary">
                    {technologyData.total_domains_combined}
                  </Typography>
                  <Typography variant="body2" color="textSecondary">
                    Total Domains
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <CodeIcon sx={{ mr: 2, color: '#4caf50' }} />
                <Box>
                  <Typography variant="h4" color="primary">
                    {technologyData.total_domains_analysis}
                  </Typography>
                  <Typography variant="body2" color="textSecondary">
                    From Tech Analysis
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <WebIcon sx={{ mr: 2, color: '#ff9800' }} />
                <Box>
                  <Typography variant="h4" color="primary">
                    {technologyData.total_domains_scraping}
                  </Typography>
                  <Typography variant="body2" color="textSecondary">
                    From Web Scraping
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <CategoryIcon sx={{ mr: 2, color: '#9c27b0' }} />
                <Box>
                  <Typography variant="h4" color="primary">
                    {getAllDomains().length}
                  </Typography>
                  <Typography variant="body2" color="textSecondary">
                    Unique Domains
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Controls */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Display Options
          </Typography>
          <FormControlLabel
            control={
              <Switch
                checked={includeScraped}
                onChange={(e) => setIncludeScraped(e.target.checked)}
              />
            }
            label="Include domains from web scraping analysis"
          />
        </CardContent>
      </Card>

      {/* Domains Table */}
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Domains Using {decodedTechName} ({getAllDomains().length})
          </Typography>
          
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Domain</TableCell>
                  <TableCell>Base Domain</TableCell>
                  <TableCell>Risk Score</TableCell>
                  <TableCell>Category</TableCell>
                  <TableCell>Confidence</TableCell>
                  <TableCell>Services</TableCell>
                  <TableCell>Providers</TableCell>
                  <TableCell>Source</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {paginatedDomains.map((domain, index) => (
                  <TableRow key={`${domain.domain}-${index}`}>
                    <TableCell>
                      <Typography variant="subtitle2" fontWeight="bold">
                        {domain.domain}
                      </Typography>
                      <Typography variant="body2" color="textSecondary">
                        Analyzed: {new Date(domain.analyzed_at).toLocaleDateString()}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {domain.base_domain}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Box display="flex" alignItems="center">
                        <Typography variant="h6" color="primary" sx={{ mr: 1 }}>
                          {domain.risk_score?.toFixed(1) || 'N/A'}
                        </Typography>
                        <Chip
                          label={domain.risk_tier || 'Unknown'}
                          size="small"
                          color={getRiskTierColor(domain.risk_tier) as any}
                        />
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Chip
                        icon={getCategoryIcon(domain.category)}
                        label={domain.category?.replace(/_/g, ' ') || 'Unknown'}
                        size="small"
                        sx={{
                          backgroundColor: getCategoryColor(domain.category) + '20',
                          color: getCategoryColor(domain.category),
                          borderColor: getCategoryColor(domain.category),
                          border: `1px solid ${getCategoryColor(domain.category)}40`,
                        }}
                      />
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {domain.confidence ? `${(domain.confidence * 100).toFixed(0)}%` : 'N/A'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Box display="flex" flexWrap="wrap" gap={0.5}>
                        {domain.services?.slice(0, 2).map((service) => (
                          <Chip
                            key={service}
                            label={service}
                            size="small"
                            variant="outlined"
                            sx={{ fontSize: '0.7rem' }}
                          />
                        ))}
                        {(domain.services?.length || 0) > 2 && (
                          <Chip
                            label={`+${(domain.services?.length || 0) - 2}`}
                            size="small"
                            color="primary"
                            sx={{ fontSize: '0.7rem' }}
                          />
                        )}
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Box display="flex" flexWrap="wrap" gap={0.5}>
                        {domain.providers?.slice(0, 2).map((provider) => (
                          <Chip
                            key={provider}
                            label={provider}
                            size="small"
                            variant="outlined"
                            sx={{ fontSize: '0.7rem' }}
                          />
                        ))}
                        {(domain.providers?.length || 0) > 2 && (
                          <Chip
                            label={`+${(domain.providers?.length || 0) - 2}`}
                            size="small"
                            color="secondary"
                            sx={{ fontSize: '0.7rem' }}
                          />
                        )}
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={domain.source}
                        size="small"
                        variant="outlined"
                        color={domain.source === 'tech_analysis' ? 'primary' : 'secondary'}
                      />
                    </TableCell>
                    <TableCell>
                      <Tooltip title="View Domain Details">
                        <IconButton
                          size="small"
                          onClick={() => navigate(`/domains/${domain.domain}`)}
                        >
                          <ViewIcon />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <TablePagination
            rowsPerPageOptions={[10, 25, 50, 100]}
            component="div"
            count={getAllDomains().length}
            rowsPerPage={rowsPerPage}
            page={page}
            onPageChange={(event, newPage) => setPage(newPage)}
            onRowsPerPageChange={(event) => {
              setRowsPerPage(parseInt(event.target.value, 10));
              setPage(0);
            }}
          />
        </CardContent>
      </Card>
    </Box>
  );
};

export default TechnologyDetail;