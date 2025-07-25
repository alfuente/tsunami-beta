import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { Box } from '@mui/material';
import Sidebar from './components/Layout/Sidebar';
import Header from './components/Layout/Header';
import Dashboard from './pages/Dashboard';
import DomainManagement from './pages/DomainManagement';
import RiskAnalysis from './pages/RiskAnalysis';
import DomainDetail from './pages/DomainDetail';
import BaseDomainDetail from './pages/BaseDomainDetail';
import Queries from './pages/Queries';

const theme = createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: '#1976d2',
    },
    secondary: {
      main: '#dc004e',
    },
    background: {
      default: '#f5f5f5',
    },
  },
  typography: {
    fontFamily: '"Roboto", "Helvetica", "Arial", sans-serif',
  },
});

const drawerWidth = 240;

function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Router>
        <Box sx={{ display: 'flex' }}>
          <Header drawerWidth={drawerWidth} />
          <Sidebar drawerWidth={drawerWidth} />
          <Box
            component="main"
            sx={{
              flexGrow: 1,
              p: 3,
              width: { sm: `calc(100% - ${drawerWidth}px)` },
              ml: { sm: `${drawerWidth}px` },
              mt: 8,
            }}
          >
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/domains" element={<DomainManagement />} />
              <Route path="/domains/:fqdn" element={<DomainDetail />} />
              <Route path="/domains/base-domains/:baseDomain" element={<BaseDomainDetail />} />
              <Route path="/base-domains/:baseDomain" element={<BaseDomainDetail />} />
              <Route path="/risk-analysis" element={<RiskAnalysis />} />
              <Route path="/queries" element={<Queries />} />
            </Routes>
          </Box>
        </Box>
      </Router>
    </ThemeProvider>
  );
}

export default App;
