import React, { useState } from 'react';
import {
  Box,
  Typography,
  TextField,
  Button,
  Card,
  CardContent,
  CircularProgress,
  Alert,
  Paper,
  Divider,
} from '@mui/material';
import {
  Send as SendIcon,
  Search as SearchIcon,
} from '@mui/icons-material';

const Queries: React.FC = () => {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;

    setLoading(true);
    setError(null);
    setResponse(null);

    try {
      // TODO: Implement actual API call to risk-query service
      const res = await fetch('http://localhost:8003/api/query', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ query: query.trim() }),
      });

      if (!res.ok) {
        throw new Error(`Server error: ${res.status}`);
      }

      const data = await res.json();
      setResponse(data.response || 'No response received');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to process query');
      console.error('Query error:', err);
    } finally {
      setLoading(false);
    }
  };

  const exampleQueries = [
    "Show me all domains with high risk scores",
    "Which domains have the most dependencies?",
    "Find domains with critical security vulnerabilities",
    "What are the third-party providers for financial services domains?",
    "Show me domains that haven't been assessed recently"
  ];

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Graph Queries
      </Typography>
      <Typography variant="body1" color="textSecondary" paragraph>
        Ask questions about your domain risk graph in natural language. 
        The system will convert your query to Cypher and execute it against the Neo4j database.
      </Typography>

      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box component="form" onSubmit={handleSubmit}>
            <TextField
              fullWidth
              multiline
              rows={3}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Ask a question about your domains, risks, or dependencies..."
              variant="outlined"
              sx={{ mb: 2 }}
              disabled={loading}
            />
            <Box display="flex" justifyContent="space-between" alignItems="center">
              <Typography variant="caption" color="textSecondary">
                {query.length}/500 characters
              </Typography>
              <Button
                type="submit"
                variant="contained"
                startIcon={loading ? <CircularProgress size={20} /> : <SendIcon />}
                disabled={loading || !query.trim()}
              >
                {loading ? 'Processing...' : 'Send Query'}
              </Button>
            </Box>
          </Box>
        </CardContent>
      </Card>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {response && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Response
            </Typography>
            <Paper sx={{ p: 2, backgroundColor: '#f5f5f5' }}>
              <Typography variant="body1" component="pre" sx={{ whiteSpace: 'pre-wrap' }}>
                {response}
              </Typography>
            </Paper>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            <SearchIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
            Example Queries
          </Typography>
          <Divider sx={{ mb: 2 }} />
          {exampleQueries.map((example, index) => (
            <Box key={index} sx={{ mb: 1 }}>
              <Button
                variant="text"
                onClick={() => setQuery(example)}
                sx={{ 
                  textAlign: 'left', 
                  justifyContent: 'flex-start',
                  textTransform: 'none',
                  color: 'text.secondary',
                  '&:hover': {
                    backgroundColor: 'action.hover',
                    color: 'primary.main',
                  }
                }}
              >
                {example}
              </Button>
            </Box>
          ))}
        </CardContent>
      </Card>
    </Box>
  );
};

export default Queries;