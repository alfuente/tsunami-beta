package com.example.report.dto;

import com.example.report.entity.ReportPurchase.ReportType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public class ReportRequest {
    
    @NotBlank(message = "Client ID is required")
    public String clientId;
    
    @NotBlank(message = "Domain is required")
    public String domain;
    
    @NotNull(message = "Report type is required")
    public ReportType reportType;
    
    public String requestNotes;
    
    // Default constructor
    public ReportRequest() {}
    
    public ReportRequest(String clientId, String domain, ReportType reportType) {
        this.clientId = clientId;
        this.domain = domain;
        this.reportType = reportType;
    }
}