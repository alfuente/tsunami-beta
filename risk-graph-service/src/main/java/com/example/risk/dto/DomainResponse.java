package com.example.risk.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

public class DomainResponse {
    
    @JsonProperty("fqdn")
    private String fqdn;
    
    @JsonProperty("risk_score")
    private Double riskScore;
    
    @JsonProperty("risk_tier")
    private String riskTier;
    
    @JsonProperty("last_calculated")
    private LocalDateTime lastCalculated;
    
    @JsonProperty("business_criticality")
    private String businessCriticality;
    
    @JsonProperty("monitoring_enabled")
    private Boolean monitoringEnabled;
    
    @JsonProperty("dns_info")
    private DnsInfo dnsInfo;
    
    @JsonProperty("security_info")
    private SecurityInfo securityInfo;
    
    @JsonProperty("infrastructure_info")
    private InfrastructureInfo infrastructureInfo;
    
    @JsonProperty("incidents")
    private List<IncidentInfo> incidents;
    
    public static class DnsInfo {
        @JsonProperty("dns_sec_enabled")
        private Boolean dnsSecEnabled;
        
        @JsonProperty("name_servers")
        private List<Map<String, Object>> nameServers;
        
        public DnsInfo() {}

        public DnsInfo(Boolean dnsSecEnabled, List<Map<String, Object>> nameServers) {
            this.dnsSecEnabled = dnsSecEnabled;
            this.nameServers = nameServers;
        }

        public Boolean getDnsSecEnabled() { return dnsSecEnabled; }
        public void setDnsSecEnabled(Boolean dnsSecEnabled) { this.dnsSecEnabled = dnsSecEnabled; }
        
        public List<Map<String, Object>> getNameServers() { return nameServers; }
        public void setNameServers(List<Map<String, Object>> nameServers) { this.nameServers = nameServers; }
    }
    
    public static class SecurityInfo {
        @JsonProperty("tls_grade")
        private String tlsGrade;
        
        @JsonProperty("critical_cves")
        private Integer criticalCves;
        
        @JsonProperty("high_cves")
        private Integer highCves;
        
        @JsonProperty("last_assessment")
        private LocalDateTime lastAssessment;
        
        public SecurityInfo() {}

        public SecurityInfo(String tlsGrade, Integer criticalCves, Integer highCves, LocalDateTime lastAssessment) {
            this.tlsGrade = tlsGrade;
            this.criticalCves = criticalCves;
            this.highCves = highCves;
            this.lastAssessment = lastAssessment;
        }

        public String getTlsGrade() { return tlsGrade; }
        public void setTlsGrade(String tlsGrade) { this.tlsGrade = tlsGrade; }
        
        public Integer getCriticalCves() { return criticalCves; }
        public void setCriticalCves(Integer criticalCves) { this.criticalCves = criticalCves; }
        
        public Integer getHighCves() { return highCves; }
        public void setHighCves(Integer highCves) { this.highCves = highCves; }
        
        public LocalDateTime getLastAssessment() { return lastAssessment; }
        public void setLastAssessment(LocalDateTime lastAssessment) { this.lastAssessment = lastAssessment; }
    }
    
    public static class InfrastructureInfo {
        @JsonProperty("multi_az")
        private Boolean multiAz;
        
        @JsonProperty("multi_region")
        private Boolean multiRegion;
        
        @JsonProperty("has_failover")
        private Boolean hasFailover;
        
        public InfrastructureInfo() {}

        public InfrastructureInfo(Boolean multiAz, Boolean multiRegion, Boolean hasFailover) {
            this.multiAz = multiAz;
            this.multiRegion = multiRegion;
            this.hasFailover = hasFailover;
        }

        public Boolean getMultiAz() { return multiAz; }
        public void setMultiAz(Boolean multiAz) { this.multiAz = multiAz; }
        
        public Boolean getMultiRegion() { return multiRegion; }
        public void setMultiRegion(Boolean multiRegion) { this.multiRegion = multiRegion; }
        
        public Boolean getHasFailover() { return hasFailover; }
        public void setHasFailover(Boolean hasFailover) { this.hasFailover = hasFailover; }
    }
    
    public static class IncidentInfo {
        @JsonProperty("incident_id")
        private String incidentId;
        
        @JsonProperty("severity")
        private String severity;
        
        @JsonProperty("detected")
        private LocalDateTime detected;
        
        @JsonProperty("resolved")
        private LocalDateTime resolved;
        
        @JsonProperty("is_active")
        private Boolean isActive;
        
        public IncidentInfo() {}

        public IncidentInfo(String incidentId, String severity, LocalDateTime detected, LocalDateTime resolved) {
            this.incidentId = incidentId;
            this.severity = severity;
            this.detected = detected;
            this.resolved = resolved;
            this.isActive = resolved == null;
        }

        public String getIncidentId() { return incidentId; }
        public void setIncidentId(String incidentId) { this.incidentId = incidentId; }
        
        public String getSeverity() { return severity; }
        public void setSeverity(String severity) { this.severity = severity; }
        
        public LocalDateTime getDetected() { return detected; }
        public void setDetected(LocalDateTime detected) { this.detected = detected; }
        
        public LocalDateTime getResolved() { return resolved; }
        public void setResolved(LocalDateTime resolved) { this.resolved = resolved; }
        
        public Boolean getIsActive() { return isActive; }
        public void setIsActive(Boolean isActive) { this.isActive = isActive; }
    }

    public DomainResponse() {}

    public DomainResponse(String fqdn) {
        this.fqdn = fqdn;
    }

    // Getters and setters
    public String getFqdn() { return fqdn; }
    public void setFqdn(String fqdn) { this.fqdn = fqdn; }
    
    public Double getRiskScore() { return riskScore; }
    public void setRiskScore(Double riskScore) { this.riskScore = riskScore; }
    
    public String getRiskTier() { return riskTier; }
    public void setRiskTier(String riskTier) { this.riskTier = riskTier; }
    
    public LocalDateTime getLastCalculated() { return lastCalculated; }
    public void setLastCalculated(LocalDateTime lastCalculated) { this.lastCalculated = lastCalculated; }
    
    public String getBusinessCriticality() { return businessCriticality; }
    public void setBusinessCriticality(String businessCriticality) { this.businessCriticality = businessCriticality; }
    
    public Boolean getMonitoringEnabled() { return monitoringEnabled; }
    public void setMonitoringEnabled(Boolean monitoringEnabled) { this.monitoringEnabled = monitoringEnabled; }
    
    public DnsInfo getDnsInfo() { return dnsInfo; }
    public void setDnsInfo(DnsInfo dnsInfo) { this.dnsInfo = dnsInfo; }
    
    public SecurityInfo getSecurityInfo() { return securityInfo; }
    public void setSecurityInfo(SecurityInfo securityInfo) { this.securityInfo = securityInfo; }
    
    public InfrastructureInfo getInfrastructureInfo() { return infrastructureInfo; }
    public void setInfrastructureInfo(InfrastructureInfo infrastructureInfo) { this.infrastructureInfo = infrastructureInfo; }
    
    public List<IncidentInfo> getIncidents() { return incidents; }
    public void setIncidents(List<IncidentInfo> incidents) { this.incidents = incidents; }
}