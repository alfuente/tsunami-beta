package com.example.report.service;

import com.example.report.dto.ReportRequest;
import com.example.report.dto.ReportResponse;
import com.example.report.entity.Client;
import com.example.report.entity.ReportGeneration;
import com.example.report.entity.ReportPurchase;
import com.example.report.entity.ReportGeneration.ReportStatus;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import java.util.logging.Logger;

@ApplicationScoped
public class ReportService {
    
    private static final Logger LOGGER = Logger.getLogger(ReportService.class.getName());
    
    @Inject
    DomainDataService domainDataService;
    
    @Inject
    PdfGenerationService pdfGenerationService;
    
    @Transactional
    public ReportResponse generateReport(ReportRequest request) {
        // Validate client exists
        Client client = Client.findByClientId(request.clientId);
        if (client == null) {
            throw new IllegalArgumentException("Client not found: " + request.clientId);
        }
        
        // Check if client has available reports
        ReportPurchase availablePurchase = ReportPurchase.findAvailableForClient(
            request.clientId, request.reportType);
        
        if (availablePurchase == null) {
            throw new IllegalStateException("No available reports of type " + request.reportType + 
                                          " for client " + request.clientId);
        }
        
        // Create report generation record
        ReportGeneration report = new ReportGeneration();
        report.reportId = UUID.randomUUID().toString();
        report.client = client;
        report.purchase = availablePurchase;
        report.domain = request.domain;
        report.reportType = request.reportType;
        report.status = ReportStatus.PENDING;
        
        report.persist();
        
        // Use one report from the purchase
        availablePurchase.useReport();
        availablePurchase.persist();
        
        LOGGER.info("Created report generation request: " + report.reportId + 
                   " for domain: " + request.domain);
        
        // Start async report generation
        generateReportAsync(report);
        
        return ReportResponse.fromEntity(report);
    }
    
    private void generateReportAsync(ReportGeneration report) {
        // In a real implementation, this would be handled by a background job
        // For now, we'll do it synchronously but mark it as async
        try {
            report.status = ReportStatus.GENERATING;
            report.persist();
            
            // Get domain data from Neo4j
            var domainData = domainDataService.getDomainRiskData(report.domain);
            
            // Generate PDF (simplified)
            var pdfResult = pdfGenerationService.generatePdf(domainData, report.reportType);
            
            // Update report with results (temporary simplified implementation)
            String reportFileName = "report_" + report.reportId + ".txt";
            report.markAsCompleted("/tmp/reports/" + reportFileName, reportFileName, (long)pdfResult.length);
            report.riskScore = domainData.riskScore;
            report.riskGrade = domainData.riskGrade;
            report.riskSummary = domainData.riskSummary;
            report.pageCount = 1; // Placeholder
            report.persist();
            
            LOGGER.info("Successfully generated report: " + report.reportId);
            
        } catch (Exception e) {
            LOGGER.severe("Failed to generate report " + report.reportId + ": " + e.getMessage());
            report.markAsFailed(e.getMessage());
            report.persist();
        }
    }
    
    public ReportResponse getReportStatus(String reportId) {
        ReportGeneration report = ReportGeneration.findByReportId(reportId);
        if (report == null) {
            throw new IllegalArgumentException("Report not found: " + reportId);
        }
        
        return ReportResponse.fromEntity(report);
    }
    
    public List<ReportResponse> getClientReports(String clientId, int page, int size) {
        Client client = Client.findByClientId(clientId);
        if (client == null) {
            throw new IllegalArgumentException("Client not found: " + clientId);
        }
        
        return ReportGeneration.find("client.clientId = ?1 order by requestedAt desc", clientId)
                .page(page, size)
                .list()
                .stream()
                .map(report -> ReportResponse.fromEntity((ReportGeneration) report))
                .toList();
    }
    
    public byte[] downloadReport(String reportId, String clientId) {
        ReportGeneration report = ReportGeneration.findByReportId(reportId);
        if (report == null) {
            throw new IllegalArgumentException("Report not found: " + reportId);
        }
        
        if (!report.client.clientId.equals(clientId)) {
            throw new IllegalArgumentException("Report does not belong to client: " + clientId);
        }
        
        if (report.status != ReportStatus.COMPLETED) {
            throw new IllegalStateException("Report is not ready for download");
        }
        
        if (report.isExpired()) {
            throw new IllegalStateException("Report has expired");
        }
        
        try {
            return pdfGenerationService.readPdfFile(report.filePath);
        } catch (IOException e) {
            throw new RuntimeException("Failed to read report file: " + e.getMessage(), e);
        }
    }
    
    public void cleanupExpiredReports() {
        LocalDateTime cutoff = LocalDateTime.now().minusDays(30);
        
        List<ReportGeneration> expiredReports = ReportGeneration.find(
            "status = ?1 and generatedAt < ?2", 
            ReportStatus.COMPLETED, cutoff).list();
        
        for (ReportGeneration report : expiredReports) {
            try {
                // Delete physical file
                pdfGenerationService.deletePdfFile(report.filePath);
                
                // Update status
                report.status = ReportStatus.EXPIRED;
                report.persist();
                
                LOGGER.info("Cleaned up expired report: " + report.reportId);
            } catch (Exception e) {
                LOGGER.warning("Failed to cleanup report " + report.reportId + ": " + e.getMessage());
            }
        }
    }
}