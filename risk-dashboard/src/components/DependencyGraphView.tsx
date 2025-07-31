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
  type: 'domain' | 'subdomain' | 'related_domain' | 'provider' | 'service';
  x: number;
  y: number;
  risk_score?: number;
  risk_tier?: string;
  industry?: string;
  industry_confidence?: number;
  is_related?: boolean;
  relationship_type?: string;
  discovered_during_scan_of?: string;
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
    case 'related_domain':
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
    case 'related_domain': return '#9c27b0';
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
  const [showRelatedDomains, setShowRelatedDomains] = useState(true);
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
      
      // Fetch comprehensive graph data with related domains
      const result = await dependencyApi.getDomainGraphWithRelated(domain, true, true, 2);
      
      // Convert to graph format
      const nodes: Node[] = [];
      const edges: Edge[] = [];
      
      // Process nodes from the graph API
      result.graph.nodes.forEach((node: any, index: number) => {
        let x, y;
        
        // Position nodes in a circular layout based on type
        if (node.type === 'domain') {
          x = 400;
          y = 300;
        } else if (node.type === 'subdomain') {
          const angle = (index / result.graph.nodes.filter((n: any) => n.type === 'subdomain').length) * 2 * Math.PI;
          const radius = 120;
          x = 400 + Math.cos(angle) * radius;
          y = 300 + Math.sin(angle) * radius;
        } else if (node.type === 'related_domain') {
          const relatedNodes = result.graph.nodes.filter((n: any) => n.type === 'related_domain');
          const relatedIndex = relatedNodes.findIndex((n: any) => n.id === node.id);
          const angle = (relatedIndex / relatedNodes.length) * 2 * Math.PI + Math.PI / 4;
          const radius = 180;
          x = 400 + Math.cos(angle) * radius;
          y = 300 + Math.sin(angle) * radius;
        } else if (node.type === 'provider') {
          const providerNodes = result.graph.nodes.filter((n: any) => n.type === 'provider');
          const providerIndex = providerNodes.findIndex((n: any) => n.id === node.id);
          const angle = (providerIndex / providerNodes.length) * 2 * Math.PI;
          const radius = 250;
          x = 400 + Math.cos(angle) * radius;
          y = 300 + Math.sin(angle) * radius;
        } else if (node.type === 'service') {
          const serviceNodes = result.graph.nodes.filter((n: any) => n.type === 'service');
          const serviceIndex = serviceNodes.findIndex((n: any) => n.id === node.id);
          const angle = (serviceIndex / serviceNodes.length) * 2 * Math.PI + Math.PI;
          const radius = 200;
          x = 400 + Math.cos(angle) * radius;
          y = 300 + Math.sin(angle) * radius;
        } else {
          x = 400 + (Math.random() - 0.5) * 300;
          y = 300 + (Math.random() - 0.5) * 300;
        }
        
        nodes.push({
          id: node.id,
          label: node.label,
          type: node.type,
          x,
          y,
          risk_score: node.risk_score,
          risk_tier: node.risk_tier,
          is_related: node.is_related,
          relationship_type: node.relationship_type,
          discovered_during_scan_of: node.discovered_during_scan_of,
          metadata: node
        });
      });
      
      // Process edges from the graph API
      result.graph.edges.forEach((edge: any) => {
        edges.push({
          id: edge.id,
          source: edge.source,
          target: edge.target,
          type: edge.type,
          label: edge.relationship_type
        });
      });

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
    // Hide related domains if toggle is off
    if (node.type === 'related_domain' && !showRelatedDomains) {
      return null;
    }
    
    const nodeColor = getNodeColor(node);
    const isSelected = selectedNode?.id === node.id;
    const isDragged = draggedNode?.id === node.id;
    const isRelatedDomain = node.type === 'related_domain';
    
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
          stroke={isSelected ? '#000' : isDragged ? '#333' : isRelatedDomain ? '#9c27b0' : '#666'}
          strokeWidth={isSelected ? 3 : isDragged ? 2 : isRelatedDomain ? 2 : 1}
          strokeDasharray={isRelatedDomain ? '5,5' : 'none'}
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
              fill={isRelatedDomain ? "rgba(156, 39, 176, 0.1)" : "rgba(255, 255, 255, 0.9)"}
              stroke={isRelatedDomain ? "#9c27b0" : "#ccc"}
              strokeWidth={0.5}
              strokeDasharray={isRelatedDomain ? '2,2' : 'none'}
              rx={3}
            />
            <text
              y={37}
              textAnchor="middle"
              fontSize="11"
              fill={isRelatedDomain ? "#9c27b0" : "#333"}
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
        {isRelatedDomain && (
          <text
            x={-15}
            y={-20}
            fontSize="10"
            fill="#9c27b0"
            fontWeight="bold"
          >
            R
          </text>
        )}
      </g>
    );
  };

  const renderEdge = (edge: Edge) => {
    const sourceNode = graphData.nodes.find(n => n.id === edge.source);
    const targetNode = graphData.nodes.find(n => n.id === edge.target);
    
    if (!sourceNode || !targetNode) return null;
    
    // Hide edges to/from related domains if toggle is off
    if (!showRelatedDomains && (sourceNode.type === 'related_domain' || targetNode.type === 'related_domain')) {
      return null;
    }

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
    
    const isRelatedEdge = edge.type === 'DISCOVERED_RELATED' || sourceNode.type === 'related_domain' || targetNode.type === 'related_domain';

    return (
      <g key={edge.id}>
        <line
          x1={startX}
          y1={startY}
          x2={endX}
          y2={endY}
          stroke={isRelatedEdge ? "#9c27b0" : "#666"}
          strokeWidth={2}
          strokeDasharray={isRelatedEdge ? '5,5' : 'none'}
          opacity={0.6}
          markerEnd="url(#arrowhead)"
        />
        {showLabels && edge.label && (
          <text
            x={(startX + endX) / 2}
            y={(startY + endY) / 2}
            textAnchor="middle"
            fontSize="10"
            fill={isRelatedEdge ? "#9c27b0" : "#666"}
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
            <FormControlLabel
              control={
                <Switch
                  checked={showRelatedDomains}
                  onChange={(e) => setShowRelatedDomains(e.target.checked)}
                  size="small"
                />
              }
              label="Related"
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
                Type: {selectedNode.type.replace('_', ' ')}
              </Typography>
              {selectedNode.type === 'related_domain' && (
                <Box mt={1}>
                  <Chip
                    label="Related Domain"
                    size="small"
                    sx={{
                      backgroundColor: '#9c27b0',
                      color: 'white'
                    }}
                  />
                  {selectedNode.relationship_type && (
                    <Typography variant="caption" display="block" sx={{ mt: 1 }}>
                      Relationship: {selectedNode.relationship_type}
                    </Typography>
                  )}
                  {selectedNode.discovered_during_scan_of && (
                    <Typography variant="caption" display="block">
                      Discovered during scan of: {selectedNode.discovered_during_scan_of}
                    </Typography>
                  )}
                </Box>
              )}
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
          <Chip 
            size="small" 
            icon={<TreeIcon />} 
            label="Related Domain" 
            sx={{ 
              bgcolor: '#f3e5f5', 
              color: '#9c27b0', 
              border: '1px dashed #9c27b0',
              '& .MuiChip-icon': { color: '#9c27b0' }
            }} 
          />
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