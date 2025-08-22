package com.example.report.dto;

import java.time.LocalDateTime;

public class ClientSummary {
    
    public String clientId;
    public String name;
    public String email;
    public String organization;
    public LocalDateTime createdAt;
    public int totalStandardReports;
    public int totalPremiumReports;
    public int usedStandardReports;
    public int usedPremiumReports;
    public int availableStandardReports;
    public int availablePremiumReports;
    public LocalDateTime lastReportGenerated;
    
    public static ClientSummary fromEntity(com.example.report.entity.Client client) {
        ClientSummary summary = new ClientSummary();
        summary.clientId = client.clientId;
        summary.name = client.name;
        summary.email = client.email;
        summary.organization = client.organization;
        summary.createdAt = client.createdAt;
        
        // Calculate report statistics
        summary.totalStandardReports = client.purchases.stream()
                .filter(p -> p.reportType == com.example.report.entity.ReportPurchase.ReportType.STANDARD)
                .mapToInt(p -> p.quantity)
                .sum();
                
        summary.totalPremiumReports = client.purchases.stream()
                .filter(p -> p.reportType == com.example.report.entity.ReportPurchase.ReportType.PREMIUM)
                .mapToInt(p -> p.quantity)
                .sum();
                
        summary.usedStandardReports = client.purchases.stream()
                .filter(p -> p.reportType == com.example.report.entity.ReportPurchase.ReportType.STANDARD)
                .mapToInt(p -> p.usedQuantity)
                .sum();
                
        summary.usedPremiumReports = client.purchases.stream()
                .filter(p -> p.reportType == com.example.report.entity.ReportPurchase.ReportType.PREMIUM)
                .mapToInt(p -> p.usedQuantity)
                .sum();
                
        summary.availableStandardReports = summary.totalStandardReports - summary.usedStandardReports;
        summary.availablePremiumReports = summary.totalPremiumReports - summary.usedPremiumReports;
        
        // Find last report generation date
        summary.lastReportGenerated = client.reports.stream()
                .filter(r -> r.generatedAt != null)
                .map(r -> r.generatedAt)
                .max(LocalDateTime::compareTo)
                .orElse(null);
        
        return summary;
    }
}