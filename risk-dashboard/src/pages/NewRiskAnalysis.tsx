import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  Button,
  CircularProgress,
  Alert,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
  Divider,
  Paper,
  LinearProgress,
} from '@mui/material';
import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  PlayArrow as PlayIcon,
  Info as InfoIcon,
  Assessment as AssessmentIcon,
  Timeline as TimelineIcon,
} from '@mui/icons-material';
import { newRiskAnalysisApi } from '../services/api';

interface Algorithm {
  name: string;
  description: string;
  type: string;
  enabled: boolean;
  parameters: Record<string, any>;
}

interface Task {
  task_id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress: number;
  current_step?: string;
  started_at: string;
  completed_at?: string;
  task_type: string;
  parameters: any;
}

const NewRiskAnalysis: React.FC = () => {
  const [healthData, setHealthData] = useState<any>(null);
  const [statistics, setStatistics] = useState<any>(null);
  const [algorithms, setAlgorithms] = useState<Algorithm[]>([]);
  const [tasks, setTasks] = useState<Task[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  // Form states
  const [domainInput, setDomainInput] = useState('');
  const [selectedAlgorithms, setSelectedAlgorithms] = useState<string[]>([]);
  const [multiDomainInput, setMultiDomainInput] = useState('');
  
  // Calculation states
  const [calculationResult, setCalculationResult] = useState<any>(null);
  const [calculatingDomain, setCalculatingDomain] = useState(false);
  const [calculatingMultiple, setCalculatingMultiple] = useState(false);

  const fetchData = async () => {
    try {
      setLoading(true);
      setError(null);

      const [healthResponse, statsResponse, algorithmsResponse, tasksResponse] = await Promise.all([
        newRiskAnalysisApi.getHealth().catch(() => null),
        newRiskAnalysisApi.getStatistics().catch(() => null),
        newRiskAnalysisApi.getAlgorithms().catch(() => ({ algorithms: [], total_algorithms: 0 })),
        newRiskAnalysisApi.getAllTasks().catch(() => ({ tasks: [], total_count: 0 }))
      ]);

      setHealthData(healthResponse);
      setStatistics(statsResponse);
      setAlgorithms(algorithmsResponse.algorithms);
      setTasks(tasksResponse.tasks);
      
      // Set default algorithms (all enabled ones)
      if (algorithmsResponse.algorithms.length > 0) {
        const enabledAlgorithms = algorithmsResponse.algorithms
          .filter(alg => alg.enabled)
          .map(alg => alg.name);
        setSelectedAlgorithms(enabledAlgorithms);
      }
      
    } catch (err) {
      setError('Failed to load risk analysis data. Make sure the risk-analysis service is running on port 8002.');
      console.error('New Risk Analysis error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    
    // Set up auto-refresh for tasks
    const interval = setInterval(() => {
      newRiskAnalysisApi.getAllTasks().then(response => {
        setTasks(response.tasks);
      }).catch(console.error);
    }, 5000);
    
    return () => clearInterval(interval);
  }, []);

  const handleCalculateDomain = async () => {
    if (!domainInput.trim()) return;
    
    try {
      setCalculatingDomain(true);
      setError(null);
      
      const result = await newRiskAnalysisApi.calculateDomainRisk(
        domainInput.trim(), 
        selectedAlgorithms
      );
      
      setCalculationResult(result);
      await fetchData(); // Refresh data
      
    } catch (err) {
      setError('Failed to calculate domain risk: ' + String(err));
    } finally {
      setCalculatingDomain(false);
    }
  };

  const handleCalculateMultiple = async () => {
    if (!multiDomainInput.trim()) return;
    
    const domains = multiDomainInput
      .split('\n')
      .map(d => d.trim())
      .filter(d => d.length > 0);
    
    if (domains.length === 0) return;
    
    try {
      setCalculatingMultiple(true);
      setError(null);
      
      await newRiskAnalysisApi.calculateMultipleRisk(domains, selectedAlgorithms);
      await fetchData(); // Refresh data to show new task
      
    } catch (err) {
      setError('Failed to start multiple domain calculation: ' + String(err));
    } finally {
      setCalculatingMultiple(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'success';
      case 'failed': return 'error';
      case 'running': return 'info';
      default: return 'default';
    }
  };

  if (loading && !healthData) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="200px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        <AssessmentIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        Systemic Risk Analysis
      </Typography>
      
      <Typography variant="body1" color="text.secondary" gutterBottom sx={{ mb: 3 }}>
        Advanced risk analysis using specialized algorithms: ICS, HHI-M, APR, IRC, IISP, IRN
      </Typography>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      {/* Health Status */}
      {healthData && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Service Health
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={3}>
                <Typography variant="body2">Status:</Typography>
                <Chip 
                  label={healthData.status} 
                  color={healthData.status === 'healthy' ? 'success' : 'error'} 
                  size="small" 
                />
              </Grid>
              <Grid item xs={12} sm={3}>
                <Typography variant="body2">Neo4j:</Typography>
                <Chip 
                  label={healthData.services.neo4j} 
                  color={healthData.services.neo4j === 'connected' ? 'success' : 'error'} 
                  size="small" 
                />
              </Grid>
              <Grid item xs={12} sm={3}>
                <Typography variant="body2">Nodes:</Typography>
                <Typography variant="h6">{healthData.graph_stats.total_nodes.toLocaleString()}</Typography>
              </Grid>
              <Grid item xs={12} sm={3}>
                <Typography variant="body2">Relationships:</Typography>
                <Typography variant="h6">{healthData.graph_stats.total_relationships.toLocaleString()}</Typography>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      )}

      <Grid container spacing={3}>
        {/* Single Domain Calculation */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Single Domain Analysis
              </Typography>
              
              <TextField
                fullWidth
                label="Domain"
                value={domainInput}
                onChange={(e) => setDomainInput(e.target.value)}
                placeholder="example.com"
                sx={{ mb: 2 }}
              />
              
              <FormControl fullWidth sx={{ mb: 2 }}>
                <InputLabel>Algorithms</InputLabel>
                <Select
                  multiple
                  value={selectedAlgorithms}
                  onChange={(e) => setSelectedAlgorithms(e.target.value as string[])}
                  renderValue={(selected) => (
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                      {selected.map((value) => (
                        <Chip key={value} label={value} size="small" />
                      ))}
                    </Box>
                  )}
                >
                  {algorithms.map((algorithm) => (
                    <MenuItem key={algorithm.name} value={algorithm.name}>
                      {algorithm.name} ({algorithm.type})
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
              
              <Button
                fullWidth
                variant="contained"
                startIcon={calculatingDomain ? <CircularProgress size={20} /> : <PlayIcon />}
                onClick={handleCalculateDomain}
                disabled={calculatingDomain || !domainInput.trim() || selectedAlgorithms.length === 0}
              >
                Calculate Risk
              </Button>
              
              {calculationResult && (
                <Box sx={{ mt: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Results for {calculationResult.domain}:
                  </Typography>
                  <Paper sx={{ p: 2, maxHeight: 300, overflow: 'auto' }}>
                    <pre style={{ fontSize: '12px', margin: 0 }}>
                      {JSON.stringify(calculationResult.results, null, 2)}
                    </pre>
                  </Paper>
                  <Typography variant="caption" display="block" sx={{ mt: 1 }}>
                    Execution time: {calculationResult.metadata.execution_time_seconds}s
                  </Typography>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Multiple Domain Calculation */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Batch Domain Analysis
              </Typography>
              
              <TextField
                fullWidth
                multiline
                rows={4}
                label="Domains (one per line)"
                value={multiDomainInput}
                onChange={(e) => setMultiDomainInput(e.target.value)}
                placeholder="example1.com&#10;example2.com&#10;example3.com"
                sx={{ mb: 2 }}
              />
              
              <Button
                fullWidth
                variant="contained"
                startIcon={calculatingMultiple ? <CircularProgress size={20} /> : <TimelineIcon />}
                onClick={handleCalculateMultiple}
                disabled={calculatingMultiple || !multiDomainInput.trim() || selectedAlgorithms.length === 0}
              >
                Start Batch Calculation
              </Button>
              
              <Typography variant="caption" display="block" sx={{ mt: 1 }}>
                This will create a background task. Monitor progress in the Tasks section below.
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        {/* Available Algorithms */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Available Algorithms
              </Typography>
              <List dense>
                {algorithms.map((algorithm) => (
                  <ListItem key={algorithm.name}>
                    <ListItemText
                      primary={algorithm.name}
                      secondary={`${algorithm.type} - ${algorithm.description}`}
                    />
                    <ListItemSecondaryAction>
                      <Chip
                        label={algorithm.enabled ? 'Enabled' : 'Disabled'}
                        color={algorithm.enabled ? 'success' : 'default'}
                        size="small"
                      />
                    </ListItemSecondaryAction>
                  </ListItem>
                ))}
              </List>
            </CardContent>
          </Card>
        </Grid>

        {/* Statistics */}
        {statistics && (
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
              <Typography variant="h6" gutterBottom>
                Graph Statistics
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <Typography variant="subtitle2">Node Counts:</Typography>
                  {Object.entries(statistics.node_counts).slice(0, 8).map(([type, count]) => (
                    <Box key={type} display="flex" justifyContent="space-between">
                      <Typography variant="body2">{type}:</Typography>
                      <Typography variant="body2" fontWeight="bold">{count}</Typography>
                    </Box>
                  ))}
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        )}

        {/* Active Tasks */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
                <Typography variant="h6">
                  Active Tasks
                </Typography>
                <Button
                  startIcon={<RefreshIcon />}
                  onClick={fetchData}
                  size="small"
                >
                  Refresh
                </Button>
              </Box>
              
              {tasks.length === 0 ? (
                <Typography color="text.secondary">No active tasks</Typography>
              ) : (
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Task ID</TableCell>
                        <TableCell>Type</TableCell>
                        <TableCell>Status</TableCell>
                        <TableCell>Progress</TableCell>
                        <TableCell>Started</TableCell>
                        <TableCell>Current Step</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {tasks.map((task) => (
                        <TableRow key={task.task_id}>
                          <TableCell>
                            <Typography variant="body2" fontFamily="monospace">
                              {task.task_id.substring(0, 8)}...
                            </Typography>
                          </TableCell>
                          <TableCell>{task.task_type}</TableCell>
                          <TableCell>
                            <Chip
                              label={task.status}
                              color={getStatusColor(task.status)}
                              size="small"
                            />
                          </TableCell>
                          <TableCell>
                            <Box width={100}>
                              <LinearProgress 
                                variant="determinate" 
                                value={task.progress} 
                                sx={{ mr: 1 }}
                              />
                              <Typography variant="caption">{task.progress}%</Typography>
                            </Box>
                          </TableCell>
                          <TableCell>
                            <Typography variant="caption">
                              {new Date(task.started_at).toLocaleString()}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Typography variant="caption">
                              {task.current_step || '-'}
                            </Typography>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default NewRiskAnalysis;