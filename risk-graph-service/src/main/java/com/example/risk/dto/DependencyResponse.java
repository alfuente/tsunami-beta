package com.example.risk.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class DependencyResponse {
    
    @JsonProperty("node_id")
    private String nodeId;
    
    @JsonProperty("node_type")
    private String nodeType;
    
    @JsonProperty("dependencies")
    private List<Dependency> dependencies;
    
    @JsonProperty("dependents")
    private List<Dependency> dependents;
    
    @JsonProperty("dependency_summary")
    private DependencySummary summary;
    
    public static class Dependency {
        @JsonProperty("target_id")
        private String targetId;
        
        @JsonProperty("target_type")
        private String targetType;
        
        @JsonProperty("dependency_type")
        private String dependencyType;
        
        @JsonProperty("risk_score")
        private Double riskScore;
        
        @JsonProperty("risk_tier")
        private String riskTier;
        
        public Dependency() {}

        public Dependency(String targetId, String targetType, String dependencyType, Double riskScore, String riskTier) {
            this.targetId = targetId;
            this.targetType = targetType;
            this.dependencyType = dependencyType;
            this.riskScore = riskScore;
            this.riskTier = riskTier;
        }

        // Getters and setters
        public String getTargetId() { return targetId; }
        public void setTargetId(String targetId) { this.targetId = targetId; }
        
        public String getTargetType() { return targetType; }
        public void setTargetType(String targetType) { this.targetType = targetType; }
        
        public String getDependencyType() { return dependencyType; }
        public void setDependencyType(String dependencyType) { this.dependencyType = dependencyType; }
        
        public Double getRiskScore() { return riskScore; }
        public void setRiskScore(Double riskScore) { this.riskScore = riskScore; }
        
        public String getRiskTier() { return riskTier; }
        public void setRiskTier(String riskTier) { this.riskTier = riskTier; }
    }
    
    public static class DependencySummary {
        @JsonProperty("total_dependencies")
        private Integer totalDependencies;
        
        @JsonProperty("total_dependents")
        private Integer totalDependents;
        
        @JsonProperty("critical_dependencies")
        private Integer criticalDependencies;
        
        @JsonProperty("high_risk_dependencies")
        private Integer highRiskDependencies;
        
        @JsonProperty("average_dependency_risk")
        private Double averageDependencyRisk;

        public DependencySummary() {}

        public DependencySummary(Integer totalDependencies, Integer totalDependents, Integer criticalDependencies, 
                               Integer highRiskDependencies, Double averageDependencyRisk) {
            this.totalDependencies = totalDependencies;
            this.totalDependents = totalDependents;
            this.criticalDependencies = criticalDependencies;
            this.highRiskDependencies = highRiskDependencies;
            this.averageDependencyRisk = averageDependencyRisk;
        }

        // Getters and setters
        public Integer getTotalDependencies() { return totalDependencies; }
        public void setTotalDependencies(Integer totalDependencies) { this.totalDependencies = totalDependencies; }
        
        public Integer getTotalDependents() { return totalDependents; }
        public void setTotalDependents(Integer totalDependents) { this.totalDependents = totalDependents; }
        
        public Integer getCriticalDependencies() { return criticalDependencies; }
        public void setCriticalDependencies(Integer criticalDependencies) { this.criticalDependencies = criticalDependencies; }
        
        public Integer getHighRiskDependencies() { return highRiskDependencies; }
        public void setHighRiskDependencies(Integer highRiskDependencies) { this.highRiskDependencies = highRiskDependencies; }
        
        public Double getAverageDependencyRisk() { return averageDependencyRisk; }
        public void setAverageDependencyRisk(Double averageDependencyRisk) { this.averageDependencyRisk = averageDependencyRisk; }
    }

    public DependencyResponse() {}

    public DependencyResponse(String nodeId, String nodeType) {
        this.nodeId = nodeId;
        this.nodeType = nodeType;
    }

    // Getters and setters
    public String getNodeId() { return nodeId; }
    public void setNodeId(String nodeId) { this.nodeId = nodeId; }
    
    public String getNodeType() { return nodeType; }
    public void setNodeType(String nodeType) { this.nodeType = nodeType; }
    
    public List<Dependency> getDependencies() { return dependencies; }
    public void setDependencies(List<Dependency> dependencies) { this.dependencies = dependencies; }
    
    public List<Dependency> getDependents() { return dependents; }
    public void setDependents(List<Dependency> dependents) { this.dependents = dependents; }
    
    public DependencySummary getSummary() { return summary; }
    public void setSummary(DependencySummary summary) { this.summary = summary; }
}