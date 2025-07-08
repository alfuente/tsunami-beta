export interface DomainResponse {
  fqdn: string;
  risk_score: number;
  risk_tier: string;
  last_calculated: string | null;
  business_criticality: string;
  monitoring_enabled: boolean;
  dns_info?: {
    dns_sec_enabled: boolean;
    name_servers: Array<{
      asn: string;
      country: string;
    }>;
  };
  security_info?: {
    tls_grade: string;
    critical_cves: number;
    high_cves: number;
    last_assessment: string | null;
  };
  infrastructure_info?: {
    multi_az: boolean;
    multi_region: boolean;
    has_failover: boolean;
  };
  incidents?: IncidentInfo[];
}

export interface IncidentInfo {
  incident_id: string;
  severity: string;
  detected: string;
  resolved: string | null;
}

export interface RiskScoreResponse {
  node_id: string;
  node_type: string;
  risk_score: number;
  risk_tier: string;
  last_calculated: string | null;
  score_breakdown?: {
    base_score: number;
    third_party_score: number;
    incident_impact: number;
    context_boost: number;
  };
}

export interface DomainsListResponse {
  domains: DomainResponse[];
  total_count: number;
  filters: {
    risk_tier: string;
    business_criticality: string;
    monitoring_enabled: string;
    search: string;
  };
  pagination: {
    limit: number;
    offset: number;
  };
}

export interface SecuritySummary {
  total_domains: number;
  average_risk_score: number;
  risk_distribution: {
    critical: number;
    high: number;
  };
  monitoring: {
    monitored_domains: number;
    monitoring_coverage: number;
  };
  security: {
    dnssec_enabled: number;
    good_tls_grade: number;
    active_incidents: number;
  };
}

export interface CalculationResponse {
  calculation_id: string;
  calculation_type: string;
  target_node: string;
  nodes_processed: number | null;
  status: string;
  message?: string;
  error?: string;
}

export interface BaseDomainResponse {
  base_domain: string;
  subdomain_count: number;
  service_count: number;
  provider_count: number;
  avg_risk_score: number;
  max_risk_score: number;
  risk_tier: string;
  critical_subdomains: number;
  high_risk_subdomains: number;
  business_criticality: string;
  monitoring_enabled: boolean;
}

export interface BaseDomainsListResponse {
  base_domains: BaseDomainResponse[];
  total_count: number;
  filters: {
    risk_tier: string;
    business_criticality: string;
    monitoring_enabled: string;
    search: string;
  };
  pagination: {
    limit: number;
    offset: number;
  };
}

export interface SubdomainDetail {
  fqdn: string;
  risk_score: number;
  risk_tier: string;
  business_criticality: string;
  monitoring_enabled: boolean;
  last_calculated: string | null;
  services: string[];
  providers: string[];
  active_incidents: number;
}

export interface BaseDomainDetailsResponse {
  base_domain: string;
  subdomains: SubdomainDetail[];
  risk_summary: {
    average_risk_score: number;
    max_risk_score: number;
    critical_subdomains: number;
    high_risk_subdomains: number;
    total_incidents: number;
  };
  service_summary: {
    total_services: number;
    services: string[];
  };
  provider_summary: {
    total_providers: number;
    providers: string[];
  };
  total_count: number;
}