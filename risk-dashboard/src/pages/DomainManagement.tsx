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
import { DataGrid, GridColDef, GridActionsCellItem } from '@mui/x-data-grid';
import {
  Add as AddIcon,
  Visibility as ViewIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { domainApi, calculationApi } from '../services/api';
import { DomainResponse, DomainsListResponse } from '../types/api';

const DomainManagement: React.FC = () => {
  const navigate = useNavigate();
  const [domains, setDomains] = useState<DomainResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [addDialogOpen, setAddDialogOpen] = useState(false);
  const [newDomainFqdn, setNewDomainFqdn] = useState('');
  const [filters, setFilters] = useState({
    riskTier: '',
    businessCriticality: '',
    search: '',
  });
  const [pagination, setPagination] = useState({
    page: 0,
    pageSize: 25,
    total: 0,
  });

  const fetchDomains = async () => {
    try {
      setLoading(true);
      const response: DomainsListResponse = await domainApi.listDomains({
        riskTier: filters.riskTier || undefined,
        businessCriticality: filters.businessCriticality || undefined,
        search: filters.search || undefined,
        limit: pagination.pageSize,
        offset: pagination.page * pagination.pageSize,
      });
      
      setDomains(response.domains);
      setPagination(prev => ({ ...prev, total: response.total_count }));
      setError(null);
    } catch (err) {
      setError('Failed to load domains');
      console.error('Domains error:', err);
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

  const columns: GridColDef[] = [
    {
      field: 'fqdn',
      headerName: 'Domain',
      flex: 1,
      minWidth: 200,
    },
    {
      field: 'risk_score',
      headerName: 'Risk Score',
      width: 120,
      renderCell: (params) => (
        <Typography variant="body2" fontWeight="bold">
          {params.value.toFixed(1)}
        </Typography>
      ),
    },
    {
      field: 'risk_tier',
      headerName: 'Risk Tier',
      width: 120,
      renderCell: (params) => (
        <Chip 
          label={params.value} 
          color={getRiskTierColor(params.value) as any}
          size="small"
        />
      ),
    },
    {
      field: 'business_criticality',
      headerName: 'Criticality',
      width: 130,
      renderCell: (params) => (
        <Chip 
          label={params.value} 
          variant="outlined"
          size="small"
        />
      ),
    },
    {
      field: 'monitoring_enabled',
      headerName: 'Monitored',
      width: 100,
      renderCell: (params) => (
        <Chip 
          label={params.value ? 'Yes' : 'No'} 
          color={params.value ? 'success' : 'default'}
          size="small"
        />
      ),
    },
    {
      field: 'last_calculated',
      headerName: 'Last Calculated',
      width: 150,
      renderCell: (params) => {
        if (!params.value) return '-';
        const date = new Date(params.value);
        return date.toLocaleDateString();
      },
    },
    {
      field: 'actions',
      type: 'actions',
      headerName: 'Actions',
      width: 100,
      getActions: (params) => [
        <GridActionsCellItem
          icon={<ViewIcon />}
          label="View"
          onClick={() => navigate(`/domains/${params.row.fqdn}`)}
        />,
      ],
    },
  ];

  return (
    <Box>
      <Box display="flex" justifyContent="between" alignItems="center" mb={3}>
        <Typography variant="h4">Domain Management</Typography>
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
            label="Search Domains"
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

      <Card>
        <CardContent>
          <DataGrid
            rows={domains}
            columns={columns}
            loading={loading}
            getRowId={(row) => row.fqdn}
            pagination
            paginationMode="server"
            rowCount={pagination.total}
            page={pagination.page}
            pageSize={pagination.pageSize}
            onPageChange={(newPage) => setPagination(prev => ({ ...prev, page: newPage }))}
            onPageSizeChange={(newPageSize) => setPagination(prev => ({ ...prev, pageSize: newPageSize }))}
            pageSizeOptions={[10, 25, 50, 100]}
            disableSelectionOnClick
            autoHeight
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