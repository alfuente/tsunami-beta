package com.example.risk.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.LocalDateTime;
import java.util.List;

public class CalculationResponse {
    
    @JsonProperty("calculation_id")
    private String calculationId;
    
    @JsonProperty("status")
    private String status;
    
    @JsonProperty("message")
    private String message;
    
    @JsonProperty("started_at")
    private LocalDateTime startedAt;
    
    @JsonProperty("completed_at")
    private LocalDateTime completedAt;
    
    @JsonProperty("nodes_processed")
    private Integer nodesProcessed;
    
    @JsonProperty("calculation_type")
    private String calculationType;
    
    @JsonProperty("target_node")
    private String targetNode;
    
    @JsonProperty("errors")
    private List<String> errors;
    
    public CalculationResponse() {
        this.startedAt = LocalDateTime.now();
    }

    public CalculationResponse(String calculationId, String calculationType, String targetNode) {
        this();
        this.calculationId = calculationId;
        this.calculationType = calculationType;
        this.targetNode = targetNode;
        this.status = "STARTED";
        this.message = "Risk calculation initiated";
    }

    public static CalculationResponse success(String calculationId, String calculationType, String targetNode, Integer nodesProcessed) {
        CalculationResponse response = new CalculationResponse(calculationId, calculationType, targetNode);
        response.setStatus("COMPLETED");
        response.setMessage("Risk calculation completed successfully");
        response.setCompletedAt(LocalDateTime.now());
        response.setNodesProcessed(nodesProcessed);
        return response;
    }

    public static CalculationResponse error(String calculationId, String calculationType, String targetNode, String errorMessage) {
        CalculationResponse response = new CalculationResponse(calculationId, calculationType, targetNode);
        response.setStatus("FAILED");
        response.setMessage("Risk calculation failed");
        response.setCompletedAt(LocalDateTime.now());
        response.setErrors(List.of(errorMessage));
        return response;
    }

    // Getters and setters
    public String getCalculationId() { return calculationId; }
    public void setCalculationId(String calculationId) { this.calculationId = calculationId; }
    
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    
    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
    
    public LocalDateTime getStartedAt() { return startedAt; }
    public void setStartedAt(LocalDateTime startedAt) { this.startedAt = startedAt; }
    
    public LocalDateTime getCompletedAt() { return completedAt; }
    public void setCompletedAt(LocalDateTime completedAt) { this.completedAt = completedAt; }
    
    public Integer getNodesProcessed() { return nodesProcessed; }
    public void setNodesProcessed(Integer nodesProcessed) { this.nodesProcessed = nodesProcessed; }
    
    public String getCalculationType() { return calculationType; }
    public void setCalculationType(String calculationType) { this.calculationType = calculationType; }
    
    public String getTargetNode() { return targetNode; }
    public void setTargetNode(String targetNode) { this.targetNode = targetNode; }
    
    public List<String> getErrors() { return errors; }
    public void setErrors(List<String> errors) { this.errors = errors; }
}