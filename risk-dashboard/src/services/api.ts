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
  },

  getDomainRelatedDomains: async (fqdn: string, includeRisk: boolean = true, limit: number = 50): Promise<{
    domain: string;
    related_domains: Array<{
      fqdn: string;
      base_domain: string;
      tld: string;
      discovered_during_scan_of: string;
      relationship_type: string;
      risk_score?: number;
      risk_tier?: string;
      created_at: string;
      last_updated: string;
    }>;
    total_count: number;
    include_risk: boolean;
    limit: number;
  }> => {
    const response = await api.get(`/api/v1/dependencies/domain/${fqdn}/related-domains`, {
      params: { includeRisk, limit }
    });
    return response.data;
  },

  getDomainGraphWithRelated: async (fqdn: string, includeRelated: boolean = true, includeRisk: boolean = true, depth: number = 2): Promise<{
    domain: string;
    graph: {
      nodes: Array<{
        id: string;
        label: string;
        type: 'domain' | 'subdomain' | 'related_domain' | 'provider' | 'service';
        risk_score?: number;
        risk_tier?: string;
        is_base_domain?: boolean;
        is_related?: boolean;
        base_domain?: string;
        tld?: string;
        relationship_type?: string;
        discovered_during_scan_of?: string;
        subdomain_parts?: string[];
      }>;
      edges: Array<{
        id: string;
        source: string;
        target: string;
        type: 'HAS_SUBDOMAIN' | 'DISCOVERED_RELATED' | 'USES_SERVICE' | 'RUNS';
        relationship_type: 'subdomain' | 'related' | 'service' | 'provider';
      }>;
    };
    metadata: {
      include_related: boolean;
      include_risk: boolean;
      depth: number;
      node_count: number;
      edge_count: number;
    };
  }> => {
    const response = await api.get(`/api/v1/dependencies/domain/${fqdn}/graph-with-related`, {
      params: { includeRelated, includeRisk, depth }
    });
    return response.data;
  }
};

export const providerApi = {
  listProviders: async (params: {
    name?: string;
    tld?: string;
    country?: string;
    providerType?: string;
    riskTier?: string;
    limit?: number;
    offset?: number;
  } = {}): Promise<{
    providers: Array<{
      id: string;
      name: string;
      tld?: string;
      country?: string;
      provider_type?: string;
      confidence: number;
      source: string;
      asn?: string;
      org?: string;
      risk_score?: number;
      risk_tier?: string;
      domain_count: number;
      subdomain_count: number;
      created_at: string;
      is_unknown: boolean;
    }>;
    total_count: number;
  }> => {
    const response = await api.get('/api/v1/providers', { params });
    return response.data;
  },

  getProviderDetails: async (providerId: string): Promise<{
    id: string;
    name: string;
    country?: string;
    type?: string;
    confidence: number;
    evidence?: string;
    risk_score?: number;
    risk_tier?: string;
    created_at: string;
    updated_at: string;
    domains?: string[];
    ip_ranges?: string[];
    aliases?: string[];
    usage?: {
      domains: string[];
      subdomains: string[];
      total_domains: number;
      total_subdomains: number;
    };
  }> => {
    const response = await api.get(`/api/v1/providers/${providerId}`);
    return response.data;
  },

  getProvidersByTLD: async (tld: string): Promise<{
    tld: string;
    tld_info: {
      country_code?: string;
      country_name?: string;
      tld_type: string;
    };
    providers: Array<{
      name: string;
      domain_count: number;
      subdomain_count: number;
      confidence: number;
    }>;
    total_count: number;
  }> => {
    const response = await api.get(`/api/v1/providers/by-tld/${tld}`);
    return response.data;
  }
};

// Domain Backend Statistics API (from domain-backend service)
const DOMAIN_BACKEND_URL = process.env.REACT_APP_DOMAIN_BACKEND_URL || 'http://localhost:8000';
// Async Discovery API (for tasks monitoring)
const ASYNC_API_URL = process.env.REACT_APP_ASYNC_API_URL || 'http://localhost:8001';

const domainBackendApi = axios.create({
  baseURL: DOMAIN_BACKEND_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

const asyncApi = axios.create({
  baseURL: ASYNC_API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const statisticsApi = {
  getStatisticsSummary: async (): Promise<{
    available: boolean;
    total_domains?: number;
    total_executions?: number;
    avg_processing_time?: number;
    success_rate?: number;
    most_analyzed_tlds?: Array<{
      tld: string;
      executions: number;
      unique_domains: number;
    }>;
    recent_activity?: Array<{
      domain: string;
      task_type: string;
      last_execution: string;
      success_rate: number;
    }>;
    message?: string;
    error?: string;
    timestamp: string;
  }> => {
    try {
      const response = await domainBackendApi.get('/api/v1/statistics/summary');
      return response.data;
    } catch (error) {
      return {
        available: false,
        message: 'Statistics service not available',
        timestamp: new Date().toISOString()
      };
    }
  },

  getDomainPerformance: async (domain: string): Promise<{
    available: boolean;
    domain: string;
    has_data?: boolean;
    summary?: {
      total_executions: number;
      successful_executions: number;
      failed_executions: number;
      timeout_executions: number;
      success_rate: number;
    };
    task_breakdown?: Array<{
      task_type: string;
      total_executions: number;
      success_rate: number;
      avg_duration: number;
      median_duration: number;
      p95_duration: number;
      avg_subdomains_found: number;
      avg_providers_found: number;
      last_execution: string;
    }>;
    time_estimations?: Record<string, {
      estimated_seconds: number;
      confidence_level: number;
      based_on_executions: number;
      similar_domains_used: boolean;
    }>;
    message?: string;
    error?: string;
    timestamp: string;
  }> => {
    try {
      const response = await domainBackendApi.get(`/api/v1/domains/${domain}/performance`);
      return response.data;
    } catch (error) {
      return {
        available: false,
        domain,
        message: 'Performance data not available',
        timestamp: new Date().toISOString()
      };
    }
  },

  estimateTaskDuration: async (domain: string, taskType: string = 'complete_discovery', confidenceLevel: number = 0.9): Promise<{
    domain: string;
    task_type: string;
    estimation: {
      estimated_seconds: number;
      confidence_level: number;
      based_on_executions: number;
      similar_domains_used: boolean;
    };
    timestamp: string;
  } | null> => {
    try {
      const response = await domainBackendApi.get(`/api/v1/estimate/${domain}`, {
        params: { task_type: taskType, confidence_level: confidenceLevel }
      });
      return response.data;
    } catch (error) {
      return null;
    }
  }
};

// Tasks API (from async discovery API)
export const tasksApi = {
  getAllTasks: async (): Promise<{
    tasks: Array<{
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
    }>;
  }> => {
    try {
      const response = await asyncApi.get('/api/v1/tasks');
      return response.data;
    } catch (error) {
      console.error('Error fetching tasks:', error);
      return { tasks: [] };
    }
  },

  getTaskById: async (taskId: string): Promise<{
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
  } | null> => {
    try {
      const response = await asyncApi.get(`/api/v1/tasks/${taskId}`);
      return response.data;
    } catch (error) {
      console.error('Error fetching task:', error);
      return null;
    }
  },

  getTaskLogs: async (taskId: string): Promise<{ logs: string; task_id: string }> => {
    try {
      const response = await asyncApi.get(`/api/v1/tasks/${taskId}/logs`);
      return response.data;
    } catch (error) {
      console.error('Error fetching task logs:', error);
      return { logs: 'Error loading logs: ' + String(error), task_id: taskId };
    }
  }
};

export default api;