import axios from 'axios';
import { DomainResponse, DomainsListResponse, RiskScoreResponse, SecuritySummary, CalculationResponse, BaseDomainsListResponse, BaseDomainDetailsResponse } from '../types/api';

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'http://localhost:8081';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const domainApi = {
  getDomain: async (fqdn: string, includeIncidents: boolean = true): Promise<DomainResponse> => {
    const response = await api.get(`/api/v1/domains/${fqdn}`, {
      params: { includeIncidents }
    });
    return response.data;
  },

  listDomains: async (params: {
    riskTier?: string;
    businessCriticality?: string;
    monitoringEnabled?: boolean;
    search?: string;
    limit?: number;
    offset?: number;
  } = {}): Promise<DomainsListResponse> => {
    const response = await api.get('/api/v1/domains', { params });
    return response.data;
  },

  getDomainTree: async (rootFqdn: string, includeRisk: boolean = true): Promise<{
    root_domain: string;
    domain_tree: DomainResponse[];
    total_count: number;
    include_risk: boolean;
  }> => {
    const response = await api.get(`/api/v1/domains/tree/${rootFqdn}`, {
      params: { includeRisk }
    });
    return response.data;
  },

  getCriticalDomains: async (missingMonitoring: boolean = false): Promise<{
    critical_domains: DomainResponse[];
    total_count: number;
    missing_monitoring_filter: boolean;
  }> => {
    const response = await api.get('/api/v1/domains/critical', {
      params: { missingMonitoring }
    });
    return response.data;
  },

  getSecuritySummary: async (): Promise<SecuritySummary> => {
    const response = await api.get('/api/v1/domains/security-summary');
    return response.data;
  },

  listBaseDomains: async (params: {
    riskTier?: string;
    businessCriticality?: string;
    monitoringEnabled?: boolean;
    search?: string;
    tld?: string;
    limit?: number;
    offset?: number;
  } = {}): Promise<BaseDomainsListResponse> => {
    const response = await api.get('/api/v1/domains/base-domains', { params });
    return response.data;
  },

  getBaseDomainDetails: async (baseDomain: string, includeRiskBreakdown: boolean = true): Promise<BaseDomainDetailsResponse> => {
    const response = await api.get(`/api/v1/domains/base-domains/${baseDomain}/details`, {
      params: { includeRiskBreakdown }
    });
    return response.data;
  }
};

export const riskApi = {
  getRiskScore: async (nodeType: string, nodeId: string, includeBreakdown: boolean = false): Promise<RiskScoreResponse> => {
    const response = await api.get(`/api/v1/risk/score/${nodeType}/${nodeId}`, {
      params: { includeBreakdown }
    });
    return response.data;
  },

  getHighRiskNodes: async (threshold: number = 70.0, limit: number = 100): Promise<{
    high_risk_nodes: RiskScoreResponse[];
    threshold: number;
    total_count: number;
  }> => {
    const response = await api.get('/api/v1/risk/high-risk', {
      params: { threshold, limit }
    });
    return response.data;
  },

  getRiskMetrics: async (): Promise<any> => {
    const response = await api.get('/api/v1/risk/metrics');
    return response.data;
  },

  getBulkRiskScores: async (params: {
    nodeType?: string;
    riskTier?: string;
    limit?: number;
  } = {}): Promise<{
    risk_scores: RiskScoreResponse[];
    total_count: number;
    filters: {
      node_type: string;
      risk_tier: string;
    };
  }> => {
    const response = await api.get('/api/v1/risk/scores/bulk', { params });
    return response.data;
  }
};

export const calculationApi = {
  calculateDomainRisk: async (fqdn: string, propagate: boolean = false): Promise<CalculationResponse> => {
    const response = await api.post(`/api/v1/calculations/domain/${fqdn}`, {}, {
      params: { propagate }
    });
    return response.data;
  },

  calculateDomainTreeRisk: async (rootFqdn: string): Promise<CalculationResponse> => {
    const response = await api.post(`/api/v1/calculations/domain-tree/${rootFqdn}`);
    return response.data;
  },

  bulkRiskRecalculation: async (): Promise<CalculationResponse> => {
    const response = await api.post('/api/v1/calculations/bulk');
    return response.data;
  },

  getCalculationStatus: async (calculationId: string): Promise<{
    calculation_id: string;
    status: string;
    message: string;
  }> => {
    const response = await api.get(`/api/v1/calculations/status/${calculationId}`);
    return response.data;
  }
};

export const dependencyApi = {
  getDomainProvidersAndServices: async (fqdn: string, includeRisk: boolean = true, includePaths: boolean = false): Promise<{
    domain: string;
    node_type?: string;
    base_domain?: string;
    providers: Array<{
      id: string;
      name: string;
      type: 'provider';
      risk_score?: number;
      risk_tier?: string;
      source: string;
      service_type: string;
      confidence: number;
      subdomain?: string;
      service_name?: string;
    }>;
    services: Array<{
      id: string;
      name: string;
      type: 'service';
      risk_score?: number;
      risk_tier?: string;
      source: string;
      service_type: string;
      confidence: number;
      subdomain?: string;
    }>;
    summary: {
      total_providers: number;
      total_services: number;
      risk_analysis: {
        average_provider_risk: number;
        average_service_risk: number;
        high_risk_providers: number;
        high_risk_services: number;
        total_dependencies: number;
        risk_distribution: {
          low_risk: number;
          medium_risk: number;
          high_risk: number;
        };
      };
    };
    dependency_paths?: {
      paths: Array<{
        target_id: string;
        target_name: string;
        target_type: string;
        path: string[];
        path_length: number;
      }>;
      total_paths: number;
    };
  }> => {
    const response = await api.get(`/api/v1/dependencies/domain/${fqdn}/providers-services`, {
      params: { includeRisk, includePaths }
    });
    return response.data;
  }
};

export default api;