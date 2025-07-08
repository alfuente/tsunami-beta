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
import { 
  BarChart, 
  Bar, 
  LineChart, 
  Line, 
  ScatterChart, 
  Scatter, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend, 
  ResponsiveContainer 
} from 'recharts';
import { 
  Table, 
  TableBody, 
  TableCell, 
  TableContainer, 
  TableHead, 
  TableRow, 
  Paper 
} from '@mui/material';
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

    return Object.keys(distribution).map(key => ({
      name: key,
      value: distribution[key],
    }));
  }, [riskScores]);

  const riskScoreHistogram = React.useMemo(() => {
    const buckets = Array.from({ length: 10 }, (_, i) => ({
      name: `${i * 10}-${(i + 1) * 10}`,
      value: 0,
    }));

    riskScores.forEach(score => {
      const bucketIndex = Math.min(Math.floor(score.risk_score / 10), 9);
      buckets[bucketIndex].value++;
    });

    return buckets;
  }, [riskScores]);

  const riskTrendData = React.useMemo(() => {
    const sortedScores = [...riskScores]
      .filter(s => s.last_calculated)
      .sort((a, b) => new Date(a.last_calculated!).getTime() - new Date(b.last_calculated!).getTime())
      .slice(-30);

    return sortedScores.map(s => ({
      date: new Date(s.last_calculated!).toLocaleDateString(),
      score: s.risk_score,
    }));
  }, [riskScores]);


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
              {riskDistributionData.length > 0 && (
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={riskDistributionData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <Tooltip />
                    <Bar dataKey="value" fill="#1976d2" />
                  </BarChart>
                </ResponsiveContainer>
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
              {riskScoreHistogram.length > 0 && (
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={riskScoreHistogram}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <Tooltip />
                    <Bar dataKey="value" fill="#ff9800" />
                  </BarChart>
                </ResponsiveContainer>
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
              {riskTrendData.length > 0 && (
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={riskTrendData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="date" />
                    <YAxis />
                    <Tooltip />
                    <Line type="monotone" dataKey="score" stroke="#4caf50" />
                  </LineChart>
                </ResponsiveContainer>
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Risk Score Statistics
              </Typography>
              {riskScores.length > 0 && (
                <Box>
                  <Typography variant="body2">
                    Total Nodes: {riskScores.length}
                  </Typography>
                  <Typography variant="body2">
                    Average Score: {(riskScores.reduce((sum, s) => sum + s.risk_score, 0) / riskScores.length).toFixed(1)}
                  </Typography>
                  <Typography variant="body2">
                    Max Score: {Math.max(...riskScores.map(s => s.risk_score)).toFixed(1)}
                  </Typography>
                  <Typography variant="body2">
                    Min Score: {Math.min(...riskScores.map(s => s.risk_score)).toFixed(1)}
                  </Typography>
                </Box>
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
              <TableContainer component={Paper}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Node ID</TableCell>
                      <TableCell>Type</TableCell>
                      <TableCell>Risk Score</TableCell>
                      <TableCell>Risk Tier</TableCell>
                      <TableCell>Last Calculated</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {highRiskNodes.slice(0, 10).map((node, index) => (
                      <TableRow key={`${node.node_type}-${node.node_id}`}>
                        <TableCell>{node.node_id}</TableCell>
                        <TableCell>{node.node_type}</TableCell>
                        <TableCell>
                          <Typography variant="body2" fontWeight="bold">
                            {node.risk_score.toFixed(1)}
                          </Typography>
                        </TableCell>
                        <TableCell>{node.risk_tier}</TableCell>
                        <TableCell>
                          {node.last_calculated ? new Date(node.last_calculated).toLocaleDateString() : '-'}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
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