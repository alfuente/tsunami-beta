package com.example.risk.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public class BaseDomainResponse {
    
    @JsonProperty("base_domain")
    private String baseDomain;
    
    @JsonProperty("subdomain_count")
    private Integer subdomainCount;
    
    @JsonProperty("service_count")
    private Integer serviceCount;
    
    @JsonProperty("provider_count")
    private Integer providerCount;
    
    @JsonProperty("avg_risk_score")
    private Double avgRiskScore;
    
    @JsonProperty("max_risk_score")
    private Double maxRiskScore;
    
    @JsonProperty("risk_tier")
    private String riskTier;
    
    @JsonProperty("critical_subdomains")
    private Integer criticalSubdomains;
    
    @JsonProperty("high_risk_subdomains")
    private Integer highRiskSubdomains;
    
    @JsonProperty("business_criticality")
    private String businessCriticality;
    
    @JsonProperty("monitoring_enabled")
    private Boolean monitoringEnabled;
    
    public BaseDomainResponse() {}
    
    public BaseDomainResponse(String baseDomain) {
        this.baseDomain = baseDomain;
    }
    
    // Getters and setters
    public String getBaseDomain() { return baseDomain; }
    public void setBaseDomain(String baseDomain) { this.baseDomain = baseDomain; }
    
    public Integer getSubdomainCount() { return subdomainCount; }
    public void setSubdomainCount(Integer subdomainCount) { this.subdomainCount = subdomainCount; }
    
    public Integer getServiceCount() { return serviceCount; }
    public void setServiceCount(Integer serviceCount) { this.serviceCount = serviceCount; }
    
    public Integer getProviderCount() { return providerCount; }
    public void setProviderCount(Integer providerCount) { this.providerCount = providerCount; }
    
    public Double getAvgRiskScore() { return avgRiskScore; }
    public void setAvgRiskScore(Double avgRiskScore) { this.avgRiskScore = avgRiskScore; }
    
    public Double getMaxRiskScore() { return maxRiskScore; }
    public void setMaxRiskScore(Double maxRiskScore) { this.maxRiskScore = maxRiskScore; }
    
    public String getRiskTier() { return riskTier; }
    public void setRiskTier(String riskTier) { this.riskTier = riskTier; }
    
    public Integer getCriticalSubdomains() { return criticalSubdomains; }
    public void setCriticalSubdomains(Integer criticalSubdomains) { this.criticalSubdomains = criticalSubdomains; }
    
    public Integer getHighRiskSubdomains() { return highRiskSubdomains; }
    public void setHighRiskSubdomains(Integer highRiskSubdomains) { this.highRiskSubdomains = highRiskSubdomains; }
    
    public String getBusinessCriticality() { return businessCriticality; }
    public void setBusinessCriticality(String businessCriticality) { this.businessCriticality = businessCriticality; }
    
    public Boolean getMonitoringEnabled() { return monitoringEnabled; }
    public void setMonitoringEnabled(Boolean monitoringEnabled) { this.monitoringEnabled = monitoringEnabled; }
}