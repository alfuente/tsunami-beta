import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Button,
  CircularProgress,
  Alert,
  Slider,
} from '@mui/material';
import { BarChart } from '@mui/x-charts/BarChart';
import { LineChart } from '@mui/x-charts/LineChart';
import { ScatterChart } from '@mui/x-charts/ScatterChart';
import { DataGrid, GridColDef } from '@mui/x-data-grid';
import { Refresh as RefreshIcon } from '@mui/icons-material';
import { riskApi, domainApi } from '../services/api';
import { RiskScoreResponse, DomainResponse } from '../types/api';

const RiskAnalysis: React.FC = () => {
  const [riskScores, setRiskScores] = useState<RiskScoreResponse[]>([]);
  const [highRiskNodes, setHighRiskNodes] = useState<RiskScoreResponse[]>([]);
  const [riskMetrics, setRiskMetrics] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState({
    nodeType: '',
    riskTier: '',
    threshold: 70,
  });

  const fetchRiskData = async () => {
    try {
      setLoading(true);
      setError(null);

      const [scoresData, highRiskData, metricsData] = await Promise.all([
        riskApi.getBulkRiskScores({
          nodeType: filters.nodeType || undefined,
          riskTier: filters.riskTier || undefined,
          limit: 100,
        }),
        riskApi.getHighRiskNodes(filters.threshold, 50),
        riskApi.getRiskMetrics().catch(() => ({})),
      ]);

      setRiskScores(scoresData.risk_scores);
      setHighRiskNodes(highRiskData.high_risk_nodes);
      setRiskMetrics(metricsData);
    } catch (err) {
      setError('Failed to load risk analysis data');
      console.error('Risk analysis error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRiskData();
  }, [filters]);

  const riskDistributionData = React.useMemo(() => {
    const distribution = riskScores.reduce((acc, score) => {
      const tier = score.risk_tier || 'Unknown';
      acc[tier] = (acc[tier] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return {
      categories: Object.keys(distribution),
      values: Object.values(distribution),
    };
  }, [riskScores]);

  const riskScoreHistogram = React.useMemo(() => {
    const buckets = Array.from({ length: 10 }, (_, i) => ({
      range: `${i * 10}-${(i + 1) * 10}`,
      count: 0,
    }));

    riskScores.forEach(score => {
      const bucketIndex = Math.min(Math.floor(score.risk_score / 10), 9);
      buckets[bucketIndex].count++;
    });

    return {
      ranges: buckets.map(b => b.range),
      counts: buckets.map(b => b.count),
    };
  }, [riskScores]);

  const riskTrendData = React.useMemo(() => {
    const sortedScores = [...riskScores]
      .filter(s => s.last_calculated)
      .sort((a, b) => new Date(a.last_calculated!).getTime() - new Date(b.last_calculated!).getTime())
      .slice(-30);

    return {
      dates: sortedScores.map(s => new Date(s.last_calculated!).toLocaleDateString()),
      scores: sortedScores.map(s => s.risk_score),
    };
  }, [riskScores]);

  const scatterData = React.useMemo(() => {
    return riskScores.map((score, index) => ({
      id: index,
      x: score.risk_score,
      y: Math.random() * 100,
      nodeType: score.node_type,
    }));
  }, [riskScores]);

  const columns: GridColDef[] = [
    {
      field: 'node_id',
      headerName: 'Node ID',
      flex: 1,
      minWidth: 200,
    },
    {
      field: 'node_type',
      headerName: 'Type',
      width: 120,
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
  ];

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Risk Analysis
      </Typography>

      <Grid container spacing={2} mb={3}>
        <Grid item xs={12} sm={6} md={3}>
          <FormControl fullWidth>
            <InputLabel>Node Type</InputLabel>
            <Select
              value={filters.nodeType}
              label="Node Type"
              onChange={(e) => setFilters(prev => ({ ...prev, nodeType: e.target.value }))}
            >
              <MenuItem value="">All Types</MenuItem>
              <MenuItem value="domain">Domain</MenuItem>
              <MenuItem value="provider">Provider</MenuItem>
              <MenuItem value="service">Service</MenuItem>
              <MenuItem value="organization">Organization</MenuItem>
            </Select>
          </FormControl>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <FormControl fullWidth>
            <InputLabel>Risk Tier</InputLabel>
            <Select
              value={filters.riskTier}
              label="Risk Tier"
              onChange={(e) => setFilters(prev => ({ ...prev, riskTier: e.target.value }))}
            >
              <MenuItem value="">All Tiers</MenuItem>
              <MenuItem value="Critical">Critical</MenuItem>
              <MenuItem value="High">High</MenuItem>
              <MenuItem value="Medium">Medium</MenuItem>
              <MenuItem value="Low">Low</MenuItem>
            </Select>
          </FormControl>
        </Grid>
        <Grid item xs={12} sm={6} md={4}>
          <Typography gutterBottom>High Risk Threshold: {filters.threshold}</Typography>
          <Slider
            value={filters.threshold}
            onChange={(_, value) => setFilters(prev => ({ ...prev, threshold: value as number }))}
            min={0}
            max={100}
            valueLabelDisplay="auto"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={2}>
          <Button
            fullWidth
            variant="outlined"
            startIcon={loading ? <CircularProgress size={20} /> : <RefreshIcon />}
            onClick={fetchRiskData}
            disabled={loading}
            sx={{ height: '56px' }}
          >
            Refresh
          </Button>
        </Grid>
      </Grid>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Risk Distribution by Tier
              </Typography>
              {riskDistributionData.categories.length > 0 && (
                <BarChart
                  xAxis={[{
                    scaleType: 'band',
                    data: riskDistributionData.categories,
                  }]}
                  series={[{
                    data: riskDistributionData.values,
                    label: 'Count',
                  }]}
                  width={500}
                  height={300}
                />
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Risk Score Distribution
              </Typography>
              {riskScoreHistogram.ranges.length > 0 && (
                <BarChart
                  xAxis={[{
                    scaleType: 'band',
                    data: riskScoreHistogram.ranges,
                  }]}
                  series={[{
                    data: riskScoreHistogram.counts,
                    label: 'Count',
                  }]}
                  width={500}
                  height={300}
                />
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Risk Score Trend (Last 30 Calculations)
              </Typography>
              {riskTrendData.dates.length > 0 && (
                <LineChart
                  xAxis={[{
                    scaleType: 'point',
                    data: riskTrendData.dates,
                  }]}
                  series={[{
                    data: riskTrendData.scores,
                    label: 'Risk Score',
                  }]}
                  width={500}
                  height={300}
                />
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Risk Score vs Node Distribution
              </Typography>
              {scatterData.length > 0 && (
                <ScatterChart
                  series={[{
                    data: scatterData,
                    label: 'Nodes',
                  }]}
                  width={500}
                  height={300}
                  xAxis={[{ label: 'Risk Score' }]}
                  yAxis={[{ label: 'Distribution' }]}
                />
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                High Risk Nodes (Score ≥ {filters.threshold})
              </Typography>
              <DataGrid
                rows={highRiskNodes}
                columns={columns}
                getRowId={(row) => `${row.node_type}-${row.node_id}`}
                pageSize={10}
                rowsPerPageOptions={[10, 25, 50]}
                disableSelectionOnClick
                autoHeight
                loading={loading}
              />
            </CardContent>
          </Card>
        </Grid>

        {riskMetrics && Object.keys(riskMetrics).length > 0 && (
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Risk Calculation Metrics
                </Typography>
                <pre style={{ fontSize: '12px', overflow: 'auto' }}>
                  {JSON.stringify(riskMetrics, null, 2)}
                </pre>
              </CardContent>
            </Card>
          </Grid>
        )}
      </Grid>
    </Box>
  );
};

export default RiskAnalysis;