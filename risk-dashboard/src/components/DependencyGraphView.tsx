import React, { useCallback, useEffect, useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  IconButton,
  Tooltip,
  Chip,
  Alert,
  CircularProgress,
  Switch,
  FormControlLabel,
  Paper,
  Menu,
  MenuItem,
  Button
} from '@mui/material';
import {
  Fullscreen as FullscreenIcon,
  FullscreenExit as FullscreenExitIcon,
  ZoomIn as ZoomInIcon,
  ZoomOut as ZoomOutIcon,
  CenterFocusStrong as CenterIcon,
  Refresh as RefreshIcon,
  AccountTree as TreeIcon,
  CloudQueue as CloudIcon,
  Business as BusinessIcon,
  Storage as StorageIcon
} from '@mui/icons-material';
import { dependencyApi } from '../services/api';

// Simple graph visualization without external dependencies
interface Node {
  id: string;
  label: string;
  type: 'domain' | 'subdomain' | 'provider' | 'service';
  x: number;
  y: number;
  risk_score?: number;
  risk_tier?: string;
  industry?: string;
  industry_confidence?: number;
  metadata?: any;
}

interface Edge {
  id: string;
  source: string;
  target: string;
  type: string;
  label?: string;
}

interface GraphData {
  nodes: Node[];
  edges: Edge[];
}

interface DependencyGraphViewProps {
  domain: string;
  height?: number;
  showFullscreen?: boolean;
}

const NodeIcon: React.FC<{ type: string }> = ({ type }) => {
  switch (type) {
    case 'domain':
    case 'subdomain':
      return <TreeIcon />;
    case 'provider':
      return <CloudIcon />;
    case 'service':
      return <BusinessIcon />;
    default:
      return <StorageIcon />;
  }
};

const getRiskColor = (riskTier?: string, riskScore?: number): string => {
  if (riskTier) {
    switch (riskTier.toLowerCase()) {
      case 'critical': return '#d32f2f';
      case 'high': return '#f57c00';
      case 'medium': return '#1976d2';
      case 'low': return '#388e3c';
      default: return '#757575';
    }
  }
  if (riskScore !== undefined) {
    if (riskScore >= 8) return '#d32f2f';
    if (riskScore >= 6) return '#f57c00';
    if (riskScore >= 4) return '#1976d2';
    return '#388e3c';
  }
  return '#757575';
};

const getNodeColor = (node: Node): string => {
  if (node.risk_score !== undefined || node.risk_tier) {
    return getRiskColor(node.risk_tier, node.risk_score);
  }
  
  switch (node.type) {
    case 'domain': return '#1976d2';
    case 'subdomain': return '#424242';
    case 'provider': return '#f57c00';
    case 'service': return '#388e3c';
    default: return '#757575';
  }
};

const DependencyGraphView: React.FC<DependencyGraphViewProps> = ({
  domain,
  height = 600,
  showFullscreen = false
}) => {
  const [graphData, setGraphData] = useState<GraphData>({ nodes: [], edges: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);
  const [contextMenu, setContextMenu] = useState<{
    mouseX: number;
    mouseY: number;
  } | null>(null);
  const [showLabels, setShowLabels] = useState(true);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [draggedNode, setDraggedNode] = useState<Node | null>(null);
  const [nodeDragOffset, setNodeDragOffset] = useState({ x: 0, y: 0 });
  const [hoveredNode, setHoveredNode] = useState<Node | null>(null);
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 });

  useEffect(() => {
    fetchGraphData();
  }, [domain]); // eslint-disable-line react-hooks/exhaustive-deps

  const fetchGraphData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Fetch dependency data
      const result = await dependencyApi.getDomainProvidersAndServices(domain, true, true);
      
      // Convert to graph format
      const nodes: Node[] = [];
      const edges: Edge[] = [];
      
      // Add main domain node
      nodes.push({
        id: domain,
        label: domain,
        type: result.node_type === 'Subdomain' ? 'subdomain' : 'domain',
        x: 400,
        y: 300,
        risk_score: undefined,
        risk_tier: undefined
      });

      // Add provider nodes
      result.providers.forEach((provider: any, index: number) => {
        const angle = (index / result.providers.length) * 2 * Math.PI;
        const radius = 200;
        nodes.push({
          id: provider.id,
          label: provider.name,
          type: 'provider',
          x: 400 + Math.cos(angle) * radius,
          y: 300 + Math.sin(angle) * radius,
          risk_score: provider.risk_score,
          risk_tier: provider.risk_tier,
          metadata: provider
        });

        edges.push({
          id: `${domain}-${provider.id}`,
          source: domain,
          target: provider.id,
          type: 'USES_PROVIDER',
          label: 'uses'
        });
      });

      // Add service nodes
      result.services.forEach((service: any, index: number) => {
        const angle = (index / result.services.length) * 2 * Math.PI + Math.PI;
        const radius = 150;
        nodes.push({
          id: service.id,
          label: service.name,
          type: 'service',
          x: 400 + Math.cos(angle) * radius,
          y: 300 + Math.sin(angle) * radius,
          risk_score: service.risk_score,
          risk_tier: service.risk_tier,
          metadata: service
        });

        edges.push({
          id: `${domain}-${service.id}`,
          source: domain,
          target: service.id,
          type: 'RUNS_SERVICE',
          label: 'runs'
        });
      });

      // Add dependency paths if available
      if (result.dependency_paths && result.dependency_paths.paths) {
        result.dependency_paths.paths.forEach((path: any, pathIndex: number) => {
          // Create intermediate nodes for complex paths
          for (let i = 0; i < path.path.length - 1; i++) {
            const sourceId = path.path[i];
            const targetId = path.path[i + 1];
            
            // Check if nodes exist, if not create them
            if (!nodes.find(n => n.id === sourceId)) {
              nodes.push({
                id: sourceId,
                label: sourceId,
                type: 'subdomain',
                x: 400 + (Math.random() - 0.5) * 300,
                y: 300 + (Math.random() - 0.5) * 300
              });
            }
            
            if (!nodes.find(n => n.id === targetId)) {
              nodes.push({
                id: targetId,
                label: targetId,
                type: path.target_type === 'Provider' ? 'provider' : 'service',
                x: 400 + (Math.random() - 0.5) * 300,
                y: 300 + (Math.random() - 0.5) * 300
              });
            }

            // Add edge
            const edgeId = `path-${pathIndex}-${i}`;
            if (!edges.find(e => e.id === edgeId)) {
              edges.push({
                id: edgeId,
                source: sourceId,
                target: targetId,
                type: 'DEPENDS_ON',
                label: 'depends'
              });
            }
          }
        });
      }

      setGraphData({ nodes, edges });
    } catch (err: any) {
      setError(err.response?.data?.message || err.message || 'Failed to load graph data');
    } finally {
      setLoading(false);
    }
  };

  const handleNodeClick = useCallback((node: Node) => {
    setSelectedNode(node);
  }, []);

  const handleContextMenu = useCallback((event: React.MouseEvent) => {
    event.preventDefault();
    setContextMenu(
      contextMenu === null
        ? {
            mouseX: event.clientX + 2,
            mouseY: event.clientY - 6,
          }
        : null,
    );
  }, [contextMenu]);

  const handleCloseContextMenu = () => {
    setContextMenu(null);
  };

  const handleZoomIn = () => {
    setZoom(prev => Math.min(prev * 1.2, 3));
  };

  const handleZoomOut = () => {
    setZoom(prev => Math.max(prev / 1.2, 0.3));
  };

  const handleCenter = () => {
    setPan({ x: 0, y: 0 });
    setZoom(1);
  };

  const handleMouseDown = (event: React.MouseEvent) => {
    if (event.button === 0) { // Left mouse button
      setIsDragging(true);
      setDragStart({ x: event.clientX - pan.x, y: event.clientY - pan.y });
    }
  };

  const handleMouseMove = (event: React.MouseEvent) => {
    setMousePosition({ x: event.clientX, y: event.clientY });
    
    if (isDragging && !draggedNode) {
      setPan({
        x: event.clientX - dragStart.x,
        y: event.clientY - dragStart.y
      });
    }
    
    if (draggedNode) {
      const rect = event.currentTarget.getBoundingClientRect();
      const x = (event.clientX - rect.left - pan.x) / zoom;
      const y = (event.clientY - rect.top - pan.y) / zoom;
      
      setGraphData(prev => ({
        ...prev,
        nodes: prev.nodes.map(node =>
          node.id === draggedNode.id
            ? { ...node, x: x - nodeDragOffset.x, y: y - nodeDragOffset.y }
            : node
        )
      }));
    }
  };

  const handleMouseUp = () => {
    setIsDragging(false);
    setDraggedNode(null);
    setHoveredNode(null);
  };

  const handleNodeMouseDown = (event: React.MouseEvent, node: Node) => {
    event.stopPropagation();
    const rect = event.currentTarget.getBoundingClientRect();
    const svgRect = event.currentTarget.closest('svg')?.getBoundingClientRect();
    if (svgRect) {
      const x = (event.clientX - svgRect.left - pan.x) / zoom;
      const y = (event.clientY - svgRect.top - pan.y) / zoom;
      
      setDraggedNode(node);
      setNodeDragOffset({
        x: x - node.x,
        y: y - node.y
      });
    }
  };

  const renderNode = (node: Node) => {
    const nodeColor = getNodeColor(node);
    const isSelected = selectedNode?.id === node.id;
    const isDragged = draggedNode?.id === node.id;
    
    return (
      <g
        key={node.id}
        transform={`translate(${node.x}, ${node.y})`}
        style={{ cursor: isDragged ? 'grabbing' : 'grab' }}
        onClick={() => handleNodeClick(node)}
        onMouseDown={(e) => handleNodeMouseDown(e, node)}
        onMouseEnter={() => setHoveredNode(node)}
        onMouseLeave={() => setHoveredNode(null)}
      >
        <circle
          r={isSelected ? 25 : 20}
          fill={nodeColor}
          stroke={isSelected ? '#000' : isDragged ? '#333' : '#666'}
          strokeWidth={isSelected ? 3 : isDragged ? 2 : 1}
          opacity={isDragged ? 0.9 : 0.8}
        />
        <foreignObject x={-15} y={-8} width={30} height={16}>
          <div style={{ 
            display: 'flex', 
            justifyContent: 'center', 
            alignItems: 'center',
            color: 'white',
            fontSize: '16px'
          }}>
            <NodeIcon type={node.type} />
          </div>
        </foreignObject>
        {showLabels && (
          <g>
            <rect
              x={-Math.max(60, node.label.length * 3.5)}
              y={25}
              width={Math.max(120, node.label.length * 7)}
              height={18}
              fill="rgba(255, 255, 255, 0.9)"
              stroke="#ccc"
              strokeWidth={0.5}
              rx={3}
            />
            <text
              y={37}
              textAnchor="middle"
              fontSize="11"
              fill="#333"
              fontWeight={isSelected ? 'bold' : 'normal'}
              fontFamily="Arial, sans-serif"
            >
              {node.label.length > 25 ? `${node.label.substring(0, 25)}...` : node.label}
            </text>
          </g>
        )}
        {node.risk_score !== undefined && (
          <circle
            cx={15}
            cy={-15}
            r={8}
            fill={getRiskColor(node.risk_tier, node.risk_score)}
            stroke="#fff"
            strokeWidth={1}
          />
        )}
      </g>
    );
  };

  const renderEdge = (edge: Edge) => {
    const sourceNode = graphData.nodes.find(n => n.id === edge.source);
    const targetNode = graphData.nodes.find(n => n.id === edge.target);
    
    if (!sourceNode || !targetNode) return null;

    const dx = targetNode.x - sourceNode.x;
    const dy = targetNode.y - sourceNode.y;
    const length = Math.sqrt(dx * dx + dy * dy);
    const unitX = dx / length;
    const unitY = dy / length;
    
    // Adjust for node radius
    const startX = sourceNode.x + unitX * 20;
    const startY = sourceNode.y + unitY * 20;
    const endX = targetNode.x - unitX * 20;
    const endY = targetNode.y - unitY * 20;

    return (
      <g key={edge.id}>
        <line
          x1={startX}
          y1={startY}
          x2={endX}
          y2={endY}
          stroke="#666"
          strokeWidth={2}
          opacity={0.6}
          markerEnd="url(#arrowhead)"
        />
        {showLabels && edge.label && (
          <text
            x={(startX + endX) / 2}
            y={(startY + endY) / 2}
            textAnchor="middle"
            fontSize="10"
            fill="#666"
            dy={-5}
          >
            {edge.label}
          </text>
        )}
      </g>
    );
  };

  const graphHeight = isFullscreen ? window.innerHeight - 100 : height;

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" height={height}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error" sx={{ m: 2 }}>
        {error}
      </Alert>
    );
  }

  return (
    <Card sx={{ 
      height: isFullscreen ? '100vh' : 'auto',
      position: isFullscreen ? 'fixed' : 'relative',
      top: isFullscreen ? 0 : 'auto',
      left: isFullscreen ? 0 : 'auto',
      right: isFullscreen ? 0 : 'auto',
      bottom: isFullscreen ? 0 : 'auto',
      zIndex: isFullscreen ? 9999 : 'auto',
      maxWidth: isFullscreen ? 'none' : '100%'
    }}>
      <CardContent sx={{ p: 1 }}>
        <Box display="flex" alignItems="center" justifyContent="space-between" mb={1}>
          <Typography variant="h6">
            Dependency Graph - {domain}
          </Typography>
          <Box display="flex" alignItems="center" gap={1}>
            <FormControlLabel
              control={
                <Switch
                  checked={showLabels}
                  onChange={(e) => setShowLabels(e.target.checked)}
                  size="small"
                />
              }
              label="Labels"
              sx={{ mr: 1 }}
            />
            <Tooltip title="Zoom In">
              <IconButton size="small" onClick={handleZoomIn}>
                <ZoomInIcon />
              </IconButton>
            </Tooltip>
            <Tooltip title="Zoom Out">
              <IconButton size="small" onClick={handleZoomOut}>
                <ZoomOutIcon />
              </IconButton>
            </Tooltip>
            <Tooltip title="Center View">
              <IconButton size="small" onClick={handleCenter}>
                <CenterIcon />
              </IconButton>
            </Tooltip>
            <Tooltip title="Refresh">
              <IconButton size="small" onClick={fetchGraphData}>
                <RefreshIcon />
              </IconButton>
            </Tooltip>
            {showFullscreen && (
              <Tooltip title={isFullscreen ? "Exit Fullscreen" : "Fullscreen"}>
                <IconButton 
                  size="small" 
                  onClick={() => setIsFullscreen(!isFullscreen)}
                >
                  {isFullscreen ? <FullscreenExitIcon /> : <FullscreenIcon />}
                </IconButton>
              </Tooltip>
            )}
          </Box>
        </Box>
        
        <Paper 
          elevation={1} 
          sx={{ 
            height: graphHeight,
            overflow: 'hidden',
            position: 'relative',
            cursor: isDragging ? 'grabbing' : 'grab'
          }}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
          onContextMenu={handleContextMenu}
        >
          <svg
            width="100%"
            height="100%"
            style={{
              transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
              transformOrigin: '0 0'
            }}
          >
            <defs>
              <marker
                id="arrowhead"
                markerWidth="10"
                markerHeight="7"
                refX="9"
                refY="3.5"
                orient="auto"
              >
                <polygon
                  points="0 0, 10 3.5, 0 7"
                  fill="#666"
                />
              </marker>
            </defs>
            
            {graphData.edges.map(renderEdge)}
            {graphData.nodes.map(renderNode)}
          </svg>
          
          {selectedNode && (
            <Box
              position="absolute"
              top={16}
              right={16}
              p={2}
              bgcolor="background.paper"
              boxShadow={3}
              borderRadius={1}
              minWidth={200}
            >
              <Typography variant="subtitle1" fontWeight="bold">
                {selectedNode.label}
              </Typography>
              <Typography variant="body2" color="textSecondary">
                Type: {selectedNode.type}
              </Typography>
              {selectedNode.risk_score !== undefined && (
                <Box mt={1}>
                  <Chip
                    label={`Risk: ${selectedNode.risk_score.toFixed(1)}`}
                    size="small"
                    sx={{
                      backgroundColor: getRiskColor(selectedNode.risk_tier, selectedNode.risk_score),
                      color: 'white'
                    }}
                  />
                </Box>
              )}
              {selectedNode.industry && (
                <Box mt={1}>
                  <Chip
                    label={`${selectedNode.industry.replace(/_/g, ' ')} ${selectedNode.industry_confidence ? `(${(selectedNode.industry_confidence * 100).toFixed(0)}%)` : ''}`}
                    size="small"
                    variant="outlined"
                    sx={{ mr: 1 }}
                  />
                </Box>
              )}
              {selectedNode.metadata && (
                <Box mt={1}>
                  <Typography variant="caption" display="block">
                    Source: {selectedNode.metadata.source?.replace(/_/g, ' ')}
                  </Typography>
                  {selectedNode.metadata.confidence && (
                    <Typography variant="caption" display="block">
                      Confidence: {(selectedNode.metadata.confidence * 100).toFixed(0)}%
                    </Typography>
                  )}
                </Box>
              )}
              <Button
                size="small"
                onClick={() => setSelectedNode(null)}
                sx={{ mt: 1 }}
              >
                Close
              </Button>
            </Box>
          )}

          {hoveredNode && !draggedNode && (
            <Box
              position="absolute"
              left={mousePosition.x - 100}
              top={mousePosition.y - 40}
              p={1}
              bgcolor="rgba(0, 0, 0, 0.8)"
              color="white"
              borderRadius={1}
              fontSize="12px"
              zIndex={1000}
              maxWidth={200}
              sx={{
                transform: mousePosition.x > window.innerWidth - 200 ? 'translateX(-100%)' : 'none',
                pointerEvents: 'none'
              }}
            >
              <Typography variant="caption" display="block" color="inherit">
                {hoveredNode.label}
              </Typography>
              <Typography variant="caption" display="block" color="inherit" sx={{ opacity: 0.7 }}>
                {hoveredNode.type}
              </Typography>
              {hoveredNode.risk_score !== undefined && (
                <Typography variant="caption" display="block" color="inherit">
                  Risk: {hoveredNode.risk_score.toFixed(1)}
                </Typography>
              )}
              {hoveredNode.industry && (
                <Typography variant="caption" display="block" color="inherit">
                  Industry: {hoveredNode.industry.replace(/_/g, ' ')}
                  {hoveredNode.industry_confidence && ` (${(hoveredNode.industry_confidence * 100).toFixed(0)}%)`}
                </Typography>
              )}
            </Box>
          )}
        </Paper>

        <Menu
          open={contextMenu !== null}
          onClose={handleCloseContextMenu}
          anchorReference="anchorPosition"
          anchorPosition={
            contextMenu !== null
              ? { top: contextMenu.mouseY, left: contextMenu.mouseX }
              : undefined
          }
        >
          <MenuItem onClick={handleCenter}>Center View</MenuItem>
          <MenuItem onClick={fetchGraphData}>Refresh Graph</MenuItem>
          <MenuItem onClick={() => setShowLabels(!showLabels)}>
            {showLabels ? 'Hide' : 'Show'} Labels
          </MenuItem>
        </Menu>

        <Box mt={1} display="flex" gap={1} flexWrap="wrap" alignItems="center">
          <Chip size="small" icon={<TreeIcon />} label="Domain/Subdomain" />
          <Chip size="small" icon={<CloudIcon />} label="Provider" />
          <Chip size="small" icon={<BusinessIcon />} label="Service" />
          <Typography variant="caption" color="textSecondary" sx={{ ml: 2 }}>
            💡 Drag nodes to reposition them • Click for details • Right-click for options
          </Typography>
        </Box>
      </CardContent>
    </Card>
  );
};

export default DependencyGraphView;