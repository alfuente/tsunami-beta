export interface DomainResponse {
  fqdn: string;
  risk_score: number;
  risk_tier: string;
  last_calculated: string | null;
  business_criticality: string;
  monitoring_enabled: boolean;
  subdomains_count?: number;
  active_subdomains_count?: number;
  high_risk_subdomains_count?: number;
  dns_info?: {
    dns_sec_enabled: boolean;
    name_servers: Array<{
      asn: string;
      country: string;
    }>;
    has_spf?: boolean;
    has_dmarc?: boolean;
    dns_records?: any;
    mx_records?: any;
    spf_record?: string;
    dmarc_record?: string;
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
  technology_info?: {
    web_server: string | null;
    cms: string | null;
    technologies?: string;
    tech_analyzed_at?: string | null;
    technology_nodes?: Array<{
      name: string;
      category: string;
      version?: string | null;
      confidence?: number | null;
    }>;
    tls_grade?: string;
  };
  providers?: Array<{
    id: string;
    name: string;
    service_type?: string;
    criticality?: string;
    confidence?: number;
    source?: string;
  }>;
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
    // New risk components
    subdomain_risk?: number;
    provider_risk?: number;
    dns_risk?: number;
    mx_risk?: number;
    weights?: {
      base_score: number;
      third_party_score: number;
      incident_impact: number;
      context_boost: number;
      // New weight components
      subdomain_risk?: number;
      provider_risk?: number;
      dns_risk?: number;
      mx_risk?: number;
    };
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
  related_domains_count?: number;
  related_domains_preview?: string[];
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
  services?: string[];
  providers?: string[];
  active_incidents: number;
  // Enhanced TLS information from SSL Labs
  tls_info?: {
    ssl_grade?: string;
    grade_trust_ignored?: string;
    has_tls: boolean;
    tls_ports_available?: boolean;
    scan_time?: string;
    certificates?: Array<{
      subject: string;
      issuer: string;
      not_before: number;
      not_after: number;
      key_algorithm: string;
      key_size: number;
      signature_algorithm: string;
      alt_names: string[];
      common_names: string[];
      sha256_hash: string;
      revocation_status?: number;
      must_staple?: boolean;
      sct?: boolean;
    }>;
    vulnerabilities?: {
      heartbleed?: boolean;
      freak?: boolean;
      poodle_tls?: boolean;
      logjam?: boolean;
      beast?: boolean;
      rc4_with_modern?: boolean;
    };
    protocols?: {
      tls_versions: string[];
      cipher_suites: string[];
      forward_secrecy?: number;
    };
    hsts_policy?: {
      status: string;
      max_age?: number;
      include_subdomains?: boolean;
      preloaded?: boolean;
    };
    http_transactions?: Array<{
      status_code?: number;
      request_url?: string;
      response_headers?: any;
    }>;
    raw_ssl_labs_data?: any;
  };
}

export interface BaseDomainDetailsResponse {
  base_domain?: string;
  subdomains?: SubdomainDetail[];
  risk_summary?: {
    average_risk_score?: number;
    max_risk_score?: number;
    critical_subdomains?: number;
    high_risk_subdomains?: number;
    total_incidents?: number;
  };
  service_summary?: {
    total_services?: number;
    services?: string[];
  };
  provider_summary?: {
    total_providers?: number;
    providers?: string[];
  };
  total_count?: number;
}

// Provider-related types
export interface ProviderResponse {
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
}

export interface ProvidersListResponse {
  providers: ProviderResponse[];
  total_count: number;
  filters: {
    name?: string;
    tld?: string;
    country?: string;
    provider_type?: string;
    risk_tier?: string;
  };
  pagination: {
    limit: number;
    offset: number;
  };
}

export interface AssociatedDomain {
  fqdn: string;
  tld: string;
  tld_country_name?: string;
  subdomain_count: number;
  last_seen: string;
}

export interface AssociatedSubdomain {
  fqdn: string;
  base_domain: string;
  tld: string;
  risk_score?: number;
  risk_tier?: string;
  confidence: number;
  created_at: string;
}

export interface ProviderDetailsResponse {
  provider: {
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
    metadata?: any;
    created_at: string;
    is_unknown: boolean;
  };
  associated_domains: AssociatedDomain[];
  associated_subdomains: AssociatedSubdomain[];
  statistics: {
    total_domains: number;
    total_subdomains: number;
    countries: Array<{
      country: string;
      domain_count: number;
    }>;
    risk_distribution: {
      low_risk: number;
      medium_risk: number;
      high_risk: number;
    };
  };
}