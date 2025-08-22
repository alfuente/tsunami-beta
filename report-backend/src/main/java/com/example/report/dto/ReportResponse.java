package com.example.report.dto;

import com.example.report.entity.ReportGeneration.ReportStatus;
import com.example.report.entity.ReportPurchase.ReportType;
import java.time.LocalDateTime;

public class ReportResponse {
    
    public String reportId;
    public String domain;
    public ReportType reportType;
    public ReportStatus status;
    public LocalDateTime requestedAt;
    public LocalDateTime generatedAt;
    public String fileName;
    public Double riskScore;
    public String riskGrade;
    public String riskSummary;
    public String downloadUrl;
    public String errorMessage;
    public Long fileSizeBytes;
    public Integer pageCount;
    
    // Default constructor
    public ReportResponse() {}
    
    public static ReportResponse fromEntity(com.example.report.entity.ReportGeneration report) {
        ReportResponse response = new ReportResponse();
        response.reportId = report.reportId;
        response.domain = report.domain;
        response.reportType = report.reportType;
        response.status = report.status;
        response.requestedAt = report.requestedAt;
        response.generatedAt = report.generatedAt;
        response.fileName = report.fileName;
        response.riskScore = report.riskScore;
        response.riskGrade = report.riskGrade;
        response.riskSummary = report.riskSummary;
        response.errorMessage = report.errorMessage;
        response.fileSizeBytes = report.fileSizeBytes;
        response.pageCount = report.pageCount;
        
        if (report.status == ReportStatus.COMPLETED && report.fileName != null) {
            response.downloadUrl = "/api/v1/reports/" + report.reportId + "/download";
        }
        
        return response;
    }
}