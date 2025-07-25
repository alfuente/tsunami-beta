import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import {
  Drawer,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Divider,
  Box,
} from '@mui/material';
import {
  Dashboard as DashboardIcon,
  Domain as DomainIcon,
  Analytics as AnalyticsIcon,
  Security as SecurityIcon,
  Search as SearchIcon,
} from '@mui/icons-material';

interface SidebarProps {
  drawerWidth: number;
}

const menuItems = [
  { text: 'Dashboard', path: '/', icon: <DashboardIcon /> },
  { text: 'Domain Management', path: '/domains', icon: <DomainIcon /> },
  { text: 'Risk Analysis', path: '/risk-analysis', icon: <AnalyticsIcon /> },
  { text: 'Queries', path: '/queries', icon: <SearchIcon /> },
];

const Sidebar: React.FC<SidebarProps> = ({ drawerWidth }) => {
  const location = useLocation();
  const navigate = useNavigate();

  const drawer = (
    <div>
      <Box sx={{ p: 2, display: 'flex', alignItems: 'center' }}>
        <SecurityIcon sx={{ mr: 1 }} />
        <strong>Risk Graph</strong>
      </Box>
      <Divider />
      <List>
        {menuItems.map((item) => (
          <ListItem key={item.text} disablePadding>
            <ListItemButton
              selected={location.pathname === item.path}
              onClick={() => navigate(item.path)}
            >
              <ListItemIcon>{item.icon}</ListItemIcon>
              <ListItemText primary={item.text} />
            </ListItemButton>
          </ListItem>
        ))}
      </List>
    </div>
  );

  return (
    <Box
      component="nav"
      sx={{ width: { sm: drawerWidth }, flexShrink: { sm: 0 } }}
    >
      <Drawer
        variant="permanent"
        sx={{
          display: { xs: 'none', sm: 'block' },
          '& .MuiDrawer-paper': {
            boxSizing: 'border-box',
            width: drawerWidth,
          },
        }}
        open
      >
        {drawer}
      </Drawer>
    </Box>
  );
};

export default Sidebar;