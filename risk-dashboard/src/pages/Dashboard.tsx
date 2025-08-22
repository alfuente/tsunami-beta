import React, { useState, useEffect } from 'react';
import {
  Grid,
  Card,
  CardContent,
  Typography,
  Box,
  CircularProgress,
  Alert,
} from '@mui/material';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, LineChart, Line } from 'recharts';
import { domainApi, riskApi, statisticsApi } from '../services/api';
import { SecuritySummary, RiskScoreResponse } from '../types/api';

const Dashboard: React.FC = () => {
  const [securitySummary, setSecuritySummary] = useState<SecuritySummary | null>(null);
  const [highRiskNodes, setHighRiskNodes] = useState<RiskScoreResponse[]>([]);
  const [statisticsSummary, setStatisticsSummary] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        setLoading(true);
        const [summaryData, highRiskData, statsData] = await Promise.all([
          domainApi.getSecuritySummary(),
          riskApi.getHighRiskNodes(70, 10),
          statisticsApi.getStatisticsSummary()
        ]);
        
        setSecuritySummary(summaryData);
        setHighRiskNodes(highRiskData.high_risk_nodes);
        setStatisticsSummary(statsData);
        setError(null);
      } catch (err) {
        setError('Failed to load dashboard data');
        console.error('Dashboard error:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchDashboardData();
  }, []);

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" height="400px">
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return <Alert severity="error">{error}</Alert>;
  }

  const riskDistributionData = securitySummary ? [
    { name: 'Critical', value: securitySummary.risk_distribution.critical },
    { name: 'High', value: securitySummary.risk_distribution.high },
    { name: 'Other', value: securitySummary.total_domains - securitySummary.risk_distribution.critical - securitySummary.risk_distribution.high },
  ] : [];

  const securityMetrics = securitySummary ? [
    { name: 'DNSSEC Enabled', value: securitySummary.security.dnssec_enabled },
    { name: 'Good TLS Grade', value: securitySummary.security.good_tls_grade },
    { name: 'Monitored', value: securitySummary.monitoring.monitored_domains },
  ] : [];

  const COLORS = ['#f44336', '#ff9800', '#4caf50'];

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Security Dashboard
      </Typography>
      
      <Grid container spacing={3}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Total Domains
              </Typography>
              <Typography variant="h5">
                {securitySummary?.total_domains || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Average Risk Score
              </Typography>
              <Typography variant="h5">
                {securitySummary?.average_risk_score.toFixed(1) || '0.0'}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Critical Domains
              </Typography>
              <Typography variant="h5" color="error">
                {securitySummary?.risk_distribution.critical || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Active Incidents
              </Typography>
              <Typography variant="h5" color="warning.main">
                {securitySummary?.security.active_incidents || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        {/* Performance Statistics Cards */}
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Domains Analyzed
              </Typography>
              <Typography variant="h5" color="info.main">
                {statisticsSummary?.available && statisticsSummary?.total_domains ? statisticsSummary.total_domains : 'N/A'}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Analysis Success Rate
              </Typography>
              <Typography variant="h5" color="success.main">
                {statisticsSummary?.available && statisticsSummary?.success_rate ? `${statisticsSummary.success_rate.toFixed(1)}%` : 'N/A'}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Avg Processing Time
              </Typography>
              <Typography variant="h5" color="primary.main">
                {statisticsSummary?.available && statisticsSummary?.avg_processing_time ? 
                  `${Math.round(statisticsSummary.avg_processing_time / 60)}m` : 'N/A'}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Total Executions
              </Typography>
              <Typography variant="h5">
                {statisticsSummary?.available && statisticsSummary?.total_executions ? statisticsSummary.total_executions : 'N/A'}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Risk Distribution
              </Typography>
              {riskDistributionData.length > 0 && (
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie
                      data={riskDistributionData}
                      cx="50%"
                      cy="50%"
                      outerRadius={60}
                      fill="#8884d8"
                      dataKey="value"
                      label={({ name, percent }) => `${name} ${percent ? (percent * 100).toFixed(0) : 0}%`}
                    >
                      {riskDistributionData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Security Metrics
              </Typography>
              {securityMetrics.length > 0 && (
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={securityMetrics}>
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

        {/* TLD Analysis Chart */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Most Analyzed TLDs
              </Typography>
              {statisticsSummary?.available && statisticsSummary?.most_analyzed_tlds?.length > 0 ? (
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={statisticsSummary.most_analyzed_tlds}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="tld" />
                    <YAxis />
                    <Tooltip />
                    <Bar dataKey="executions" fill="#2196f3" />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <Typography color="textSecondary">No TLD analysis data available</Typography>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Recent Activity */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Recent Analysis Activity
              </Typography>
              {statisticsSummary?.available && statisticsSummary?.recent_activity?.length > 0 ? (
                <Box sx={{ maxHeight: 200, overflow: 'auto' }}>
                  {statisticsSummary.recent_activity.slice(0, 5).map((activity: any, index: number) => (
                    <Box key={index} sx={{ mb: 1, p: 1, border: '1px solid #ddd', borderRadius: 1 }}>
                      <Typography variant="subtitle2">
                        {activity.domain}
                      </Typography>
                      <Typography variant="body2" color="textSecondary">
                        {activity.task_type} - {activity.success_rate.toFixed(1)}% success
                      </Typography>
                      <Typography variant="caption" color="textSecondary">
                        {new Date(activity.last_execution).toLocaleDateString()}
                      </Typography>
                    </Box>
                  ))}
                </Box>
              ) : (
                <Typography color="textSecondary">No recent activity data available</Typography>
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                High Risk Nodes
              </Typography>
              {highRiskNodes.length > 0 ? (
                <Box>
                  {highRiskNodes.map((node, index) => (
                    <Box key={index} sx={{ mb: 1, p: 1, border: '1px solid #ddd', borderRadius: 1 }}>
                      <Typography variant="subtitle1">
                        {node.node_id} ({node.node_type})
                      </Typography>
                      <Typography variant="body2" color="textSecondary">
                        Risk Score: {node.risk_score?.toFixed(1) || 'N/A'} - {node.risk_tier || 'Unknown'}
                      </Typography>
                    </Box>
                  ))}
                </Box>
              ) : (
                <Typography color="textSecondary">No high-risk nodes found</Typography>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Dashboard;