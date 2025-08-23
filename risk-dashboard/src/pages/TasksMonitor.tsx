import React, { useState, useEffect } from 'react';
import {
  Grid,
  Card,
  CardContent,
  Typography,
  Box,
  CircularProgress,
  Button,
  Chip,
  LinearProgress,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Tooltip,
  Checkbox,
  FormControlLabel,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  IconButton,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  Schedule as ClockIcon,
  CheckCircle as CheckCircleIcon,
  Cancel as XCircleIcon,
  Warning as AlertCircleIcon,
  PlayArrow as PlayIcon,
  TextSnippet as LogIcon,
} from '@mui/icons-material';
import { tasksApi } from '../services/api';

interface Task {
  task_id: string;
  task_type: string;
  domain: string;
  subdomain?: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress: number;
  started_at: string;
  completed_at?: string;
  result?: any;
  error?: string;
  metadata?: any;
}

const TasksMonitor: React.FC = () => {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [showCompleted, setShowCompleted] = useState(false);
  const [logDialogOpen, setLogDialogOpen] = useState(false);
  const [selectedTaskLogs, setSelectedTaskLogs] = useState<string>('');
  const [selectedTaskId, setSelectedTaskId] = useState<string>('');

  const fetchTasks = async () => {
    setLoading(true);
    try {
      const response = await tasksApi.getAllTasks();
      setTasks(response.tasks);
      setLastRefresh(new Date());
    } catch (error) {
      console.error('Error fetching tasks:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleShowLogs = async (taskId: string) => {
    try {
      setSelectedTaskId(taskId);
      setSelectedTaskLogs('Loading logs...');
      setLogDialogOpen(true);
      
      const response = await tasksApi.getTaskLogs(taskId);
      setSelectedTaskLogs(response.logs || 'No logs available');
    } catch (error) {
      setSelectedTaskLogs('Error loading logs: ' + String(error));
    }
  };

  useEffect(() => {
    fetchTasks();
  }, []);

  useEffect(() => {
    if (!autoRefresh) return;

    const interval = setInterval(() => {
      fetchTasks();
    }, 15000); // Refresh every 15 seconds

    return () => clearInterval(interval);
  }, [autoRefresh]);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'pending':
        return <ClockIcon style={{ color: '#ff9800' }} />;
      case 'running':
        return <PlayIcon style={{ color: '#2196f3' }} />;
      case 'completed':
        return <CheckCircleIcon style={{ color: '#4caf50' }} />;
      case 'failed':
        return <XCircleIcon style={{ color: '#f44336' }} />;
      default:
        return <AlertCircleIcon style={{ color: '#9e9e9e' }} />;
    }
  };

  const getStatusColor = (status: string): 'default' | 'primary' | 'secondary' | 'error' | 'info' | 'success' | 'warning' => {
    switch (status) {
      case 'pending':
        return 'warning';
      case 'running':
        return 'info';
      case 'completed':
        return 'success';
      case 'failed':
        return 'error';
      default:
        return 'default';
    }
  };

  const getTaskTypeDisplayName = (taskType: string) => {
    const typeMap: { [key: string]: string } = {
      'amass_discovery': 'Amass Discovery',
      'service_discovery': 'Service Discovery',
      'tech_analysis': 'Technology Analysis',
      'dns_analysis': 'DNS Analysis',
      'mx_analysis': 'MX Analysis',
      'tls_analysis': 'TLS Analysis',
      'batch_analysis': 'Complete Analysis',
      'subdomain_discovery': 'Subdomain Discovery'
    };
    return typeMap[taskType] || taskType;
  };

  const formatDuration = (startTime: string, endTime?: string) => {
    const start = new Date(startTime);
    const end = endTime ? new Date(endTime) : new Date();
    const duration = Math.floor((end.getTime() - start.getTime()) / 1000);
    
    if (duration < 60) return `${duration}s`;
    if (duration < 3600) return `${Math.floor(duration / 60)}m ${duration % 60}s`;
    return `${Math.floor(duration / 3600)}h ${Math.floor((duration % 3600) / 60)}m`;
  };

  // Filter tasks based on showCompleted setting
  const visibleTasks = showCompleted ? tasks : tasks.filter(task => task.status !== 'completed');
  
  const runningTasks = tasks.filter(task => task.status === 'running');
  const pendingTasks = tasks.filter(task => task.status === 'pending');
  const completedTasks = tasks.filter(task => task.status === 'completed');
  const failedTasks = tasks.filter(task => task.status === 'failed');

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h3" component="h1" gutterBottom>
            Tasks Monitor
          </Typography>
          <Typography variant="subtitle1" color="text.secondary">
            Monitor analysis tasks in real-time
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
          <FormControlLabel
            control={
              <Checkbox
                checked={showCompleted}
                onChange={(e) => setShowCompleted(e.target.checked)}
                size="small"
              />
            }
            label="Show Completed"
            sx={{ mr: 2 }}
          />
          <Button
            variant="outlined"
            size="small"
            onClick={() => setAutoRefresh(!autoRefresh)}
          >
            {autoRefresh ? 'Disable Auto Refresh' : 'Enable Auto Refresh'}
          </Button>
          <Button
            variant="outlined"
            size="small"
            onClick={fetchTasks}
            disabled={loading}
            startIcon={<RefreshIcon />}
          >
            Refresh
          </Button>
        </Box>
      </Box>

      {/* Summary Cards */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <PlayIcon color="info" />
                <Box>
                  <Typography variant="body2" color="text.secondary">
                    Running
                  </Typography>
                  <Typography variant="h4" color="info.main">
                    {runningTasks.length}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <ClockIcon color="warning" />
                <Box>
                  <Typography variant="body2" color="text.secondary">
                    Pending
                  </Typography>
                  <Typography variant="h4" color="warning.main">
                    {pendingTasks.length}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <CheckCircleIcon color="success" />
                <Box>
                  <Typography variant="body2" color="text.secondary">
                    Completed
                  </Typography>
                  <Typography variant="h4" color="success.main">
                    {completedTasks.length}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <XCircleIcon color="error" />
                <Box>
                  <Typography variant="body2" color="text.secondary">
                    Failed
                  </Typography>
                  <Typography variant="h4" color="error.main">
                    {failedTasks.length}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Last Refresh Info */}
      <Box sx={{ textAlign: 'center', mb: 2 }}>
        <Typography variant="body2" color="text.secondary">
          Last updated: {lastRefresh.toLocaleTimeString()}
          {autoRefresh && ' (Auto-refreshing every 15 seconds)'}
          {!showCompleted && ' - Completed tasks hidden'}
        </Typography>
      </Box>

      {/* Running Tasks */}
      {runningTasks.length > 0 && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <PlayIcon color="info" />
              Running Tasks ({runningTasks.length})
            </Typography>
            <Typography variant="body2" color="text.secondary" gutterBottom>
              Tasks currently being executed
            </Typography>
            
            <Box sx={{ mt: 2 }}>
              {runningTasks.map((task) => (
                <Card key={task.task_id} sx={{ mb: 2, bgcolor: 'info.light', color: 'info.contrastText' }}>
                  <CardContent>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1 }}>
                      <Box sx={{ flexGrow: 1 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                          {getStatusIcon(task.status)}
                          <Typography variant="h6" component="h3">
                            {getTaskTypeDisplayName(task.task_type)}
                          </Typography>
                          <Chip 
                            label={task.status.toUpperCase()}
                            color={getStatusColor(task.status)}
                            size="small"
                          />
                        </Box>
                        <Typography variant="body2">
                          Domain: <strong>{task.domain}</strong>
                          {task.subdomain && (
                            <span> → Subdomain: <strong>{task.subdomain}</strong></span>
                          )}
                        </Typography>
                        <Typography variant="caption" display="block">
                          Started: {new Date(task.started_at).toLocaleString()} 
                          ({formatDuration(task.started_at)})
                        </Typography>
                      </Box>
                      <Box sx={{ textAlign: 'right', minWidth: 100 }}>
                        <Typography variant="h5" color="info.main" gutterBottom>
                          {task.progress}%
                        </Typography>
                        <LinearProgress 
                          variant="determinate" 
                          value={task.progress} 
                          sx={{ width: 80 }}
                        />
                      </Box>
                    </Box>
                    <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                      Task ID: {task.task_id}
                    </Typography>
                  </CardContent>
                </Card>
              ))}
            </Box>
          </CardContent>
        </Card>
      )}

      {/* All Tasks Table */}
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            {showCompleted ? `All Tasks (${tasks.length})` : `Active Tasks (${visibleTasks.length})`}
          </Typography>
          <Typography variant="body2" color="text.secondary" gutterBottom>
            {showCompleted ? 'Complete list of analysis tasks' : 'Analysis tasks (completed tasks hidden)'}
          </Typography>
          
          {loading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', py: 4 }}>
              <CircularProgress />
              <Typography sx={{ ml: 2 }}>Loading tasks...</Typography>
            </Box>
          ) : visibleTasks.length === 0 ? (
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <Typography color="text.secondary">
                {!showCompleted && tasks.some(task => task.status === 'completed') 
                  ? 'No active tasks found. Check "Show Completed" to see completed tasks.' 
                  : 'No tasks found'}
              </Typography>
            </Box>
          ) : (
            <TableContainer component={Paper} sx={{ mt: 2 }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Status</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Domain</TableCell>
                    <TableCell>Progress</TableCell>
                    <TableCell>Started</TableCell>
                    <TableCell>Duration</TableCell>
                    <TableCell>Task ID</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {visibleTasks.map((task) => (
                    <TableRow key={task.task_id} hover>
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          {getStatusIcon(task.status)}
                          <Chip 
                            label={task.status}
                            color={getStatusColor(task.status)}
                            size="small"
                          />
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Box>
                          <Typography variant="body2" fontWeight="medium">
                            {getTaskTypeDisplayName(task.task_type)}
                          </Typography>
                          {task.subdomain && (
                            <Typography variant="caption" color="text.secondary">
                              Subdomain scan
                            </Typography>
                          )}
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Box>
                          <Typography variant="body2" fontWeight="medium">
                            {task.domain}
                          </Typography>
                          {task.subdomain && (
                            <Typography variant="caption" color="text.secondary">
                              {task.subdomain}
                            </Typography>
                          )}
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <LinearProgress 
                            variant="determinate" 
                            value={task.progress} 
                            sx={{ width: 60 }}
                          />
                          <Typography variant="caption">
                            {task.progress}%
                          </Typography>
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption">
                          {new Date(task.started_at).toLocaleString()}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption">
                          {formatDuration(task.started_at, task.completed_at)}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Tooltip title={task.task_id}>
                          <Typography 
                            variant="caption" 
                            sx={{ 
                              fontFamily: 'monospace',
                              maxWidth: 100,
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                              display: 'block'
                            }}
                          >
                            {task.task_id}
                          </Typography>
                        </Tooltip>
                      </TableCell>
                      <TableCell>
                        <IconButton
                          size="small"
                          onClick={() => handleShowLogs(task.task_id)}
                          title="View Logs"
                        >
                          <LogIcon fontSize="small" />
                        </IconButton>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </CardContent>
      </Card>

      {/* Logs Dialog */}
      <Dialog
        open={logDialogOpen}
        onClose={() => setLogDialogOpen(false)}
        maxWidth="lg"
        fullWidth
      >
        <DialogTitle>
          Task Logs - {selectedTaskId.substring(0, 8)}...
        </DialogTitle>
        <DialogContent>
          <Box
            component="pre"
            sx={{
              backgroundColor: '#f5f5f5',
              padding: 2,
              borderRadius: 1,
              fontFamily: 'monospace',
              fontSize: '0.875rem',
              overflow: 'auto',
              maxHeight: '60vh',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word'
            }}
          >
            {selectedTaskLogs}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setLogDialogOpen(false)}>
            Close
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default TasksMonitor;