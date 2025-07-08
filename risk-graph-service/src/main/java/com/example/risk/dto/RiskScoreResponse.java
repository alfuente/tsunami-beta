package com.example.risk.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.LocalDateTime;
import java.util.Map;

public class RiskScoreResponse {
    
    @JsonProperty("node_id")
    private String nodeId;
    
    @JsonProperty("node_type")
    private String nodeType;
    
    @JsonProperty("risk_score")
    private Double riskScore;
    
    @JsonProperty("risk_tier")
    private String riskTier;
    
    @JsonProperty("last_calculated")
    private LocalDateTime lastCalculated;
    
    @JsonProperty("score_breakdown")
    private ScoreBreakdown scoreBreakdown;
    
    public static class ScoreBreakdown {
        @JsonProperty("base_score")
        private Double baseScore;
        
        @JsonProperty("third_party_score")
        private Double thirdPartyScore;
        
        @JsonProperty("incident_impact")
        private Double incidentImpact;
        
        @JsonProperty("context_boost")
        private Double contextBoost;
        
        @JsonProperty("weights")
        private Map<String, Double> weights;

        public ScoreBreakdown() {}

        public ScoreBreakdown(Double baseScore, Double thirdPartyScore, Double incidentImpact, Double contextBoost) {
            this.baseScore = baseScore;
            this.thirdPartyScore = thirdPartyScore;
            this.incidentImpact = incidentImpact;
            this.contextBoost = contextBoost;
            this.weights = Map.of(
                "base_score", 0.40,
                "third_party_score", 0.25,
                "incident_impact", 0.30,
                "context_boost", 0.05
            );
        }

        // Getters and setters
        public Double getBaseScore() { return baseScore; }
        public void setBaseScore(Double baseScore) { this.baseScore = baseScore; }
        
        public Double getThirdPartyScore() { return thirdPartyScore; }
        public void setThirdPartyScore(Double thirdPartyScore) { this.thirdPartyScore = thirdPartyScore; }
        
        public Double getIncidentImpact() { return incidentImpact; }
        public void setIncidentImpact(Double incidentImpact) { this.incidentImpact = incidentImpact; }
        
        public Double getContextBoost() { return contextBoost; }
        public void setContextBoost(Double contextBoost) { this.contextBoost = contextBoost; }
        
        public Map<String, Double> getWeights() { return weights; }
        public void setWeights(Map<String, Double> weights) { this.weights = weights; }
    }

    public RiskScoreResponse() {}

    public RiskScoreResponse(String nodeId, String nodeType, Double riskScore, String riskTier, LocalDateTime lastCalculated) {
        this.nodeId = nodeId;
        this.nodeType = nodeType;
        this.riskScore = riskScore;
        this.riskTier = riskTier;
        this.lastCalculated = lastCalculated;
    }

    // Getters and setters
    public String getNodeId() { return nodeId; }
    public void setNodeId(String nodeId) { this.nodeId = nodeId; }
    
    public String getNodeType() { return nodeType; }
    public void setNodeType(String nodeType) { this.nodeType = nodeType; }
    
    public Double getRiskScore() { return riskScore; }
    public void setRiskScore(Double riskScore) { this.riskScore = riskScore; }
    
    public String getRiskTier() { return riskTier; }
    public void setRiskTier(String riskTier) { this.riskTier = riskTier; }
    
    public LocalDateTime getLastCalculated() { return lastCalculated; }
    public void setLastCalculated(LocalDateTime lastCalculated) { this.lastCalculated = lastCalculated; }
    
    public ScoreBreakdown getScoreBreakdown() { return scoreBreakdown; }
    public void setScoreBreakdown(ScoreBreakdown scoreBreakdown) { this.scoreBreakdown = scoreBreakdown; }
}