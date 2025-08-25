import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
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
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  TextField,
  Button,
  Divider,
  Paper,
  IconButton,
  Tooltip,
} from '@mui/material';
import {
  Computer as TechIcon,
  Category as CategoryIcon,
  Analytics as StatsIcon,
  Search as SearchIcon,
  Refresh as RefreshIcon,
  Visibility as ViewIcon,
  Code as CodeIcon,
  Security as SecurityIcon,
  Cloud as CloudIcon,
  Web as WebIcon,
} from '@mui/icons-material';
import { technologyApi } from '../services/api';

interface Technology {
  name: string;
  category: string;
  domain_count: number;
  domains: string[];
  total_domains: number;
}

interface Category {
  category: string;
  technology_count: number;
  domain_count: number;
}

interface Statistics {
  total_domains: number;
  total_technologies: number;
  total_services: number;
  total_providers: number;
  domains_with_tech_analysis: number;
  domains_with_scraping_analysis: number;
  analysis_coverage: number;
}

const Technologies: React.FC = () => {
  const navigate = useNavigate();
  const [technologies, setTechnologies] = useState<Technology[]>([]);
  const [categories, setCategories] = useState<Category[]>([]);
  const [statistics, setStatistics] = useState<Statistics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [selectedCategory, setSelectedCategory] = useState<string>('');
  const [searchTerm, setSearchTerm] = useState('');
  const [minUsageCount, setMinUsageCount] = useState(1);

  const fetchData = async () => {
    setLoading(true);
    setError(null);

    try {
      const [techData, catData, statsData] = await Promise.all([
        technologyApi.getOverview({
          limit: 200,
          category: selectedCategory || undefined,
          min_usage_count: minUsageCount,
        }),
        technologyApi.getCategories(),
        technologyApi.getStatistics(),
      ]);

      setTechnologies(techData.technologies);
      setCategories(catData.categories);
      setStatistics(statsData);
    } catch (err) {
      console.error('Error fetching technologies data:', err);
      setError('Failed to load technologies data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [selectedCategory, minUsageCount]);

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

  const filteredTechnologies = technologies.filter(tech =>
    tech.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const paginatedTechnologies = filteredTechnologies.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  const handleViewTechnology = (techName: string) => {
    navigate(`/technologies/${encodeURIComponent(techName)}`);
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" height="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Box>
          <Typography variant="h4">Technologies Overview</Typography>
          <Typography variant="body1" color="textSecondary" sx={{ mt: 1 }}>
            Comprehensive technology analysis across domains and subdomains with associated services and providers
          </Typography>
        </Box>
        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
          onClick={fetchData}
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
      {statistics && (
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center">
                  <TechIcon sx={{ mr: 2, color: '#2196f3' }} />
                  <Box>
                    <Typography variant="h4" color="primary">
                      {statistics.total_technologies}
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      Total Technologies
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
                  <WebIcon sx={{ mr: 2, color: '#4caf50' }} />
                  <Box>
                    <Typography variant="h4" color="primary">
                      {statistics.total_domains}
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
                  <StatsIcon sx={{ mr: 2, color: '#ff9800' }} />
                  <Box>
                    <Typography variant="h4" color="primary">
                      {statistics.analysis_coverage}%
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      Analysis Coverage
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
                  <CloudIcon sx={{ mr: 2, color: '#9c27b0' }} />
                  <Box>
                    <Typography variant="h4" color="primary">
                      {statistics.total_providers}
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      Third-party Providers
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Categories Overview */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Technology Categories
          </Typography>
          <Grid container spacing={2}>
            {categories.map((category) => (
              <Grid item xs={12} sm={6} md={4} lg={3} key={category.category}>
                <Paper
                  sx={{
                    p: 2,
                    cursor: 'pointer',
                    '&:hover': { backgroundColor: 'action.hover' },
                    borderLeft: `4px solid ${getCategoryColor(category.category)}`,
                  }}
                  onClick={() => setSelectedCategory(category.category)}
                >
                  <Box display="flex" alignItems="center" mb={1}>
                    {getCategoryIcon(category.category)}
                    <Typography variant="subtitle2" sx={{ ml: 1, textTransform: 'capitalize' }}>
                      {category.category.replace(/_/g, ' ')}
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="textSecondary">
                    {category.technology_count} technologies
                  </Typography>
                  <Typography variant="body2" color="textSecondary">
                    {category.domain_count} domains
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </CardContent>
      </Card>

      {/* Filters and Search */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Filters
          </Typography>
          <Grid container spacing={2} alignItems="center">
            <Grid item xs={12} sm={4}>
              <FormControl fullWidth>
                <InputLabel>Category</InputLabel>
                <Select
                  value={selectedCategory}
                  label="Category"
                  onChange={(e) => setSelectedCategory(e.target.value)}
                >
                  <MenuItem value="">All Categories</MenuItem>
                  {categories.map((cat) => (
                    <MenuItem key={cat.category} value={cat.category}>
                      {cat.category.replace(/_/g, ' ')} ({cat.technology_count})
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>

            <Grid item xs={12} sm={4}>
              <TextField
                fullWidth
                label="Search Technologies"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                InputProps={{
                  startAdornment: <SearchIcon sx={{ mr: 1, color: 'action.active' }} />,
                }}
              />
            </Grid>

            <Grid item xs={12} sm={4}>
              <TextField
                fullWidth
                type="number"
                label="Min Usage Count"
                value={minUsageCount}
                onChange={(e) => setMinUsageCount(parseInt(e.target.value) || 1)}
                inputProps={{ min: 1 }}
              />
            </Grid>
          </Grid>

          {(selectedCategory || searchTerm) && (
            <Box mt={2}>
              <Button
                variant="text"
                onClick={() => {
                  setSelectedCategory('');
                  setSearchTerm('');
                  setMinUsageCount(1);
                }}
              >
                Clear Filters
              </Button>
            </Box>
          )}
        </CardContent>
      </Card>

      {/* Technologies Table */}
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Technologies Overview ({filteredTechnologies.length})
          </Typography>
          <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>
            Comprehensive view of all technologies detected across domains and subdomains, including associated services and providers
          </Typography>
          
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Technology</TableCell>
                  <TableCell>Category</TableCell>
                  <TableCell>Usage Statistics</TableCell>
                  <TableCell>Associated Domains</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {paginatedTechnologies.map((tech) => (
                  <TableRow key={tech.name}>
                    <TableCell>
                      <Box display="flex" alignItems="center">
                        {getCategoryIcon(tech.category)}
                        <Box ml={1}>
                          <Typography variant="subtitle2" fontWeight="bold">
                            {tech.name}
                          </Typography>
                          <Typography variant="body2" color="textSecondary">
                            Technology Detection
                          </Typography>
                        </Box>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={tech.category.replace(/_/g, ' ')}
                        size="small"
                        sx={{
                          backgroundColor: getCategoryColor(tech.category) + '20',
                          color: getCategoryColor(tech.category),
                          borderColor: getCategoryColor(tech.category),
                          border: `1px solid ${getCategoryColor(tech.category)}40`,
                        }}
                      />
                    </TableCell>
                    <TableCell>
                      <Box>
                        <Typography variant="h6" color="primary">
                          {tech.domain_count}
                        </Typography>
                        <Typography variant="body2" color="textSecondary">
                          domains & subdomains
                        </Typography>
                        <Typography variant="body2" color="primary">
                          View details for services & providers →
                        </Typography>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Box display="flex" flexWrap="wrap" gap={0.5}>
                        {tech.domains.slice(0, 3).map((domain) => (
                          <Chip
                            key={domain}
                            label={domain}
                            size="small"
                            variant="outlined"
                            onClick={() => navigate(`/domains/${domain}`)}
                            sx={{ 
                              cursor: 'pointer',
                              '&:hover': { backgroundColor: 'action.hover' }
                            }}
                          />
                        ))}
                        {tech.domains.length > 3 && (
                          <Chip
                            label={`+${tech.domains.length - 3} more domains`}
                            size="small"
                            color="primary"
                            onClick={() => handleViewTechnology(tech.name)}
                            sx={{ cursor: 'pointer' }}
                          />
                        )}
                      </Box>
                      <Typography variant="body2" color="textSecondary" sx={{ mt: 0.5 }}>
                        Click technology name for complete domain, service & provider mapping
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Tooltip title="View Complete Technology Analysis - Domains, Subdomains, Services & Providers">
                        <IconButton
                          size="small"
                          onClick={() => handleViewTechnology(tech.name)}
                          color="primary"
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
            count={filteredTechnologies.length}
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

export default Technologies;