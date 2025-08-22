package com.example.report.service;

import com.example.report.entity.ReportPurchase.ReportType;
import com.example.report.service.DomainDataService.DomainRiskData;
import com.itextpdf.html2pdf.HtmlConverter;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.element.Table;
import com.itextpdf.layout.element.Cell;
import com.itextpdf.layout.property.TextAlignment;
import com.itextpdf.layout.property.UnitValue;
import com.itextpdf.kernel.colors.ColorConstants;
import com.itextpdf.kernel.font.PdfFont;
import com.itextpdf.kernel.font.PdfFontFactory;

import jakarta.enterprise.context.ApplicationScoped;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.logging.Logger;

@ApplicationScoped
public class PdfGenerationService {
    
    private static final Logger LOGGER = Logger.getLogger(PdfGenerationService.class.getName());
    private static final String REPORTS_DIR = "/tmp/reports";
    
    public PdfResult generatePdf(DomainRiskData data, ReportType reportType) {
        try {
            // Ensure reports directory exists
            Files.createDirectories(Paths.get(REPORTS_DIR));
            
            String fileName = generateFileName(data.domain, reportType);
            String filePath = REPORTS_DIR + "/" + fileName;
            
            if (reportType == ReportType.STANDARD) {
                return generateStandardReport(data, filePath, fileName);
            } else {
                return generatePremiumReport(data, filePath, fileName);
            }
            
        } catch (Exception e) {
            LOGGER.severe("Failed to generate PDF for domain " + data.domain + ": " + e.getMessage());
            throw new RuntimeException("PDF generation failed", e);
        }
    }
    
    private PdfResult generateStandardReport(DomainRiskData data, String filePath, String fileName) throws Exception {
        try (PdfWriter writer = new PdfWriter(filePath);
             PdfDocument pdf = new PdfDocument(writer);
             Document document = new Document(pdf)) {
            
            // Add header
            addReportHeader(document, data, "STANDARD SECURITY REPORT");
            
            // Risk Summary
            addRiskSummary(document, data);
            
            // Basic Technology Overview
            addBasicTechnologyOverview(document, data);
            
            // Provider Summary
            addProviderSummary(document, data);
            
            // Risk Recommendations
            addBasicRecommendations(document, data);
            
            // Footer
            addReportFooter(document);
            
            document.close();
            
            File file = new File(filePath);
            return new PdfResult(filePath, fileName, file.length(), pdf.getNumberOfPages());
        }
    }
    
    private PdfResult generatePremiumReport(DomainRiskData data, String filePath, String fileName) throws Exception {
        try (PdfWriter writer = new PdfWriter(filePath);
             PdfDocument pdf = new PdfDocument(writer);
             Document document = new Document(pdf)) {
            
            // Add header
            addReportHeader(document, data, "PREMIUM SECURITY REPORT");
            
            // Executive Summary
            addExecutiveSummary(document, data);
            
            // Detailed Risk Analysis
            addDetailedRiskAnalysis(document, data);
            
            // Subdomain Analysis
            if (!data.subdomains.isEmpty()) {
                addSubdomainAnalysis(document, data);
            }
            
            // Technology Deep Dive
            addTechnologyDeepDive(document, data);
            
            // Service Analysis
            addServiceAnalysis(document, data);
            
            // Provider Analysis
            addProviderAnalysis(document, data);
            
            // Vulnerability Assessment
            addVulnerabilityAssessment(document, data);
            
            // Remediation Plan
            addRemediationPlan(document, data);
            
            // Appendices
            addAppendices(document, data);
            
            // Footer
            addReportFooter(document);
            
            document.close();
            
            File file = new File(filePath);
            return new PdfResult(filePath, fileName, file.length(), pdf.getNumberOfPages());
        }
    }
    
    private void addReportHeader(Document document, DomainRiskData data, String reportType) throws Exception {
        PdfFont boldFont = PdfFontFactory.createFont();
        
        // Title
        Paragraph title = new Paragraph(reportType)
                .setFont(boldFont)
                .setFontSize(20)
                .setTextAlignment(TextAlignment.CENTER)
                .setMarginBottom(10);
        document.add(title);
        
        // Domain name
        Paragraph domainTitle = new Paragraph("Domain: " + data.domain)
                .setFont(boldFont)
                .setFontSize(16)
                .setTextAlignment(TextAlignment.CENTER)
                .setMarginBottom(20);
        document.add(domainTitle);
        
        // Report info table
        Table infoTable = new Table(UnitValue.createPercentArray(new float[]{1, 1}));
        infoTable.setWidth(UnitValue.createPercentValue(100));
        
        infoTable.addCell(new Cell().add(new Paragraph("Report Generated:")).setBold());
        infoTable.addCell(new Cell().add(new Paragraph(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")))));
        
        infoTable.addCell(new Cell().add(new Paragraph("Risk Score:")).setBold());
        infoTable.addCell(new Cell().add(new Paragraph(String.format("%.1f/100", data.riskScore))));
        
        infoTable.addCell(new Cell().add(new Paragraph("Risk Grade:")).setBold());
        infoTable.addCell(new Cell().add(new Paragraph(data.riskGrade)));
        
        infoTable.addCell(new Cell().add(new Paragraph("Risk Level:")).setBold());
        infoTable.addCell(new Cell().add(new Paragraph(data.riskLevel)));
        
        document.add(infoTable);
        document.add(new Paragraph("\\n"));
    }
    
    private void addRiskSummary(Document document, DomainRiskData data) throws Exception {
        document.add(new Paragraph("RISK SUMMARY").setBold().setFontSize(14));
        document.add(new Paragraph(data.riskSummary).setMarginBottom(15));
    }
    
    private void addBasicTechnologyOverview(Document document, DomainRiskData data) throws Exception {
        document.add(new Paragraph("TECHNOLOGY OVERVIEW").setBold().setFontSize(14));
        
        if (data.technologies.isEmpty() && data.technologyVersions.isEmpty()) {
            document.add(new Paragraph("No technologies detected.").setMarginBottom(15));
            return;
        }
        
        Table techTable = new Table(UnitValue.createPercentArray(new float[]{2, 1, 1}));
        techTable.setWidth(UnitValue.createPercentValue(100));
        
        // Headers
        techTable.addHeaderCell(new Cell().add(new Paragraph("Technology")).setBold());
        techTable.addHeaderCell(new Cell().add(new Paragraph("Category")).setBold());
        techTable.addHeaderCell(new Cell().add(new Paragraph("Version")).setBold());
        
        // Add technology versions first (more specific)
        for (var tech : data.technologyVersions) {
            techTable.addCell(new Cell().add(new Paragraph(tech.name)));
            techTable.addCell(new Cell().add(new Paragraph(tech.category)));
            techTable.addCell(new Cell().add(new Paragraph(tech.version != null ? tech.version : "N/A")));
        }
        
        // Add generic technologies if not already covered
        for (var tech : data.technologies) {
            boolean alreadyListed = data.technologyVersions.stream()
                    .anyMatch(tv -> tv.name.equals(tech.name));
            if (!alreadyListed) {
                techTable.addCell(new Cell().add(new Paragraph(tech.name)));
                techTable.addCell(new Cell().add(new Paragraph(tech.category)));
                techTable.addCell(new Cell().add(new Paragraph("N/A")));
            }
        }
        
        document.add(techTable);
        document.add(new Paragraph("\\n"));
    }
    
    private void addProviderSummary(Document document, DomainRiskData data) throws Exception {
        document.add(new Paragraph("THIRD-PARTY PROVIDERS").setBold().setFontSize(14));
        
        if (data.providers.isEmpty()) {
            document.add(new Paragraph("No third-party providers detected.").setMarginBottom(15));
            return;
        }
        
        Table providerTable = new Table(UnitValue.createPercentArray(new float[]{2, 1}));
        providerTable.setWidth(UnitValue.createPercentValue(100));
        
        providerTable.addHeaderCell(new Cell().add(new Paragraph("Provider")).setBold());
        providerTable.addHeaderCell(new Cell().add(new Paragraph("Type")).setBold());
        
        for (var provider : data.providers) {
            providerTable.addCell(new Cell().add(new Paragraph(provider.name)));
            providerTable.addCell(new Cell().add(new Paragraph(provider.type)));
        }
        
        document.add(providerTable);
        document.add(new Paragraph("\\n"));
    }
    
    private void addBasicRecommendations(Document document, DomainRiskData data) throws Exception {
        document.add(new Paragraph("BASIC RECOMMENDATIONS").setBold().setFontSize(14));
        
        if (data.riskScore > 60) {
            document.add(new Paragraph("• Immediate attention required - High risk detected"));
            document.add(new Paragraph("• Review all identified vulnerabilities"));
            document.add(new Paragraph("• Consider upgrading to Premium report for detailed remediation"));
        } else if (data.riskScore > 30) {
            document.add(new Paragraph("• Monitor identified issues"));
            document.add(new Paragraph("• Plan security improvements"));
        } else {
            document.add(new Paragraph("• Maintain current security posture"));
            document.add(new Paragraph("• Continue regular monitoring"));
        }
        
        document.add(new Paragraph("\\n"));
    }
    
    // Premium report sections
    private void addExecutiveSummary(Document document, DomainRiskData data) throws Exception {
        document.add(new Paragraph("EXECUTIVE SUMMARY").setBold().setFontSize(14));
        
        StringBuilder summary = new StringBuilder();
        summary.append(String.format("This comprehensive security assessment of %s reveals a risk score of %.1f (%s). ", 
                      data.domain, data.riskScore, data.riskLevel));
        
        summary.append(String.format("The analysis covers %d subdomains, %d technologies, %d services, and %d third-party providers.",
                      data.subdomains.size(), 
                      data.technologies.size() + data.technologyVersions.size(),
                      data.services.size(),
                      data.providers.size()));
        
        document.add(new Paragraph(summary.toString()).setMarginBottom(15));
    }
    
    private void addDetailedRiskAnalysis(Document document, DomainRiskData data) throws Exception {
        document.add(new Paragraph("DETAILED RISK ANALYSIS").setBold().setFontSize(14));
        
        // Risk breakdown
        long criticalTechs = data.technologyVersions.stream()
                .filter(t -> "critical".equals(t.riskLevel))
                .count();
        long highTechs = data.technologyVersions.stream()
                .filter(t -> "high".equals(t.riskLevel))
                .count();
        long mediumTechs = data.technologyVersions.stream()
                .filter(t -> "medium".equals(t.riskLevel))
                .count();
        
        Table riskTable = new Table(UnitValue.createPercentArray(new float[]{1, 1}));
        riskTable.setWidth(UnitValue.createPercentValue(100));
        
        riskTable.addCell(new Cell().add(new Paragraph("Critical Risk Technologies:")).setBold());
        riskTable.addCell(new Cell().add(new Paragraph(String.valueOf(criticalTechs))));
        
        riskTable.addCell(new Cell().add(new Paragraph("High Risk Technologies:")).setBold());
        riskTable.addCell(new Cell().add(new Paragraph(String.valueOf(highTechs))));
        
        riskTable.addCell(new Cell().add(new Paragraph("Medium Risk Technologies:")).setBold());
        riskTable.addCell(new Cell().add(new Paragraph(String.valueOf(mediumTechs))));
        
        document.add(riskTable);
        document.add(new Paragraph("\\n"));
    }
    
    private void addSubdomainAnalysis(Document document, DomainRiskData data) throws Exception {
        document.add(new Paragraph("SUBDOMAIN ANALYSIS").setBold().setFontSize(14));
        
        Table subdomainTable = new Table(UnitValue.createPercentArray(new float[]{3, 1, 2}));
        subdomainTable.setWidth(UnitValue.createPercentValue(100));
        
        subdomainTable.addHeaderCell(new Cell().add(new Paragraph("Subdomain")).setBold());
        subdomainTable.addHeaderCell(new Cell().add(new Paragraph("Risk Score")).setBold());
        subdomainTable.addHeaderCell(new Cell().add(new Paragraph("Last Analyzed")).setBold());
        
        for (var subdomain : data.subdomains) {
            subdomainTable.addCell(new Cell().add(new Paragraph(subdomain.fqdn)));
            subdomainTable.addCell(new Cell().add(new Paragraph(String.format("%.1f", subdomain.riskScore))));
            subdomainTable.addCell(new Cell().add(new Paragraph(subdomain.lastCalculated != null ? subdomain.lastCalculated : "Never")));
        }
        
        document.add(subdomainTable);
        document.add(new Paragraph("\\n"));
    }
    
    private void addTechnologyDeepDive(Document document, DomainRiskData data) throws Exception {
        document.add(new Paragraph("TECHNOLOGY DEEP DIVE").setBold().setFontSize(14));
        
        if (!data.technologyVersions.isEmpty()) {
            Table techTable = new Table(UnitValue.createPercentArray(new float[]{2, 1, 1, 1, 3}));
            techTable.setWidth(UnitValue.createPercentValue(100));
            
            techTable.addHeaderCell(new Cell().add(new Paragraph("Technology")).setBold());
            techTable.addHeaderCell(new Cell().add(new Paragraph("Version")).setBold());
            techTable.addHeaderCell(new Cell().add(new Paragraph("Category")).setBold());
            techTable.addHeaderCell(new Cell().add(new Paragraph("Risk")).setBold());
            techTable.addHeaderCell(new Cell().add(new Paragraph("Notes")).setBold());
            
            for (var tech : data.technologyVersions) {
                techTable.addCell(new Cell().add(new Paragraph(tech.name)));
                techTable.addCell(new Cell().add(new Paragraph(tech.version != null ? tech.version : "N/A")));
                techTable.addCell(new Cell().add(new Paragraph(tech.category)));
                techTable.addCell(new Cell().add(new Paragraph(tech.riskLevel)));
                techTable.addCell(new Cell().add(new Paragraph(tech.vulnerabilityNotes)));
            }
            
            document.add(techTable);
        }
        
        document.add(new Paragraph("\\n"));
    }
    
    private void addServiceAnalysis(Document document, DomainRiskData data) throws Exception {
        document.add(new Paragraph("SERVICE ANALYSIS").setBold().setFontSize(14));
        
        if (data.services.isEmpty()) {
            document.add(new Paragraph("No services detected.").setMarginBottom(15));
            return;
        }
        
        Table serviceTable = new Table(UnitValue.createPercentArray(new float[]{2, 1, 1, 1, 2}));
        serviceTable.setWidth(UnitValue.createPercentValue(100));
        
        serviceTable.addHeaderCell(new Cell().add(new Paragraph("Service")).setBold());
        serviceTable.addHeaderCell(new Cell().add(new Paragraph("Port")).setBold());
        serviceTable.addHeaderCell(new Cell().add(new Paragraph("Protocol")).setBold());
        serviceTable.addHeaderCell(new Cell().add(new Paragraph("State")).setBold());
        serviceTable.addHeaderCell(new Cell().add(new Paragraph("Product/Version")).setBold());
        
        for (var service : data.services) {
            serviceTable.addCell(new Cell().add(new Paragraph(service.serviceName)));
            serviceTable.addCell(new Cell().add(new Paragraph(String.valueOf(service.port))));
            serviceTable.addCell(new Cell().add(new Paragraph(service.protocol)));
            serviceTable.addCell(new Cell().add(new Paragraph(service.state)));
            serviceTable.addCell(new Cell().add(new Paragraph(
                String.format("%s %s", 
                    service.product != null ? service.product : "",
                    service.version != null ? service.version : "").trim())));
        }
        
        document.add(serviceTable);
        document.add(new Paragraph("\\n"));
    }
    
    private void addProviderAnalysis(Document document, DomainRiskData data) throws Exception {
        document.add(new Paragraph("THIRD-PARTY PROVIDER ANALYSIS").setBold().setFontSize(14));
        
        if (data.providers.isEmpty()) {
            document.add(new Paragraph("No third-party providers detected.").setMarginBottom(15));
            return;
        }
        
        Table providerTable = new Table(UnitValue.createPercentArray(new float[]{2, 1, 1}));
        providerTable.setWidth(UnitValue.createPercentValue(100));
        
        providerTable.addHeaderCell(new Cell().add(new Paragraph("Provider")).setBold());
        providerTable.addHeaderCell(new Cell().add(new Paragraph("Type")).setBold());
        providerTable.addHeaderCell(new Cell().add(new Paragraph("Confidence")).setBold());
        
        for (var provider : data.providers) {
            providerTable.addCell(new Cell().add(new Paragraph(provider.name)));
            providerTable.addCell(new Cell().add(new Paragraph(provider.type)));
            providerTable.addCell(new Cell().add(new Paragraph(String.format("%.1f%%", provider.confidence * 100))));
        }
        
        document.add(providerTable);
        document.add(new Paragraph("\\n"));
    }
    
    private void addVulnerabilityAssessment(Document document, DomainRiskData data) throws Exception {
        document.add(new Paragraph("VULNERABILITY ASSESSMENT").setBold().setFontSize(14));
        
        var vulnerableTechs = data.technologyVersions.stream()
                .filter(t -> !"unknown".equals(t.riskLevel) && !"low".equals(t.riskLevel))
                .toList();
        
        if (vulnerableTechs.isEmpty()) {
            document.add(new Paragraph("No significant vulnerabilities detected in technology versions.").setMarginBottom(15));
        } else {
            document.add(new Paragraph("The following technologies may have security vulnerabilities:").setMarginBottom(10));
            
            for (var tech : vulnerableTechs) {
                document.add(new Paragraph(String.format("• %s %s (%s risk): %s", 
                    tech.name, 
                    tech.version != null ? tech.version : "",
                    tech.riskLevel,
                    tech.vulnerabilityNotes)).setMarginLeft(20));
            }
        }
        
        document.add(new Paragraph("\\n"));
    }
    
    private void addRemediationPlan(Document document, DomainRiskData data) throws Exception {
        document.add(new Paragraph("REMEDIATION PLAN").setBold().setFontSize(14));
        
        document.add(new Paragraph("IMMEDIATE ACTIONS (0-30 days):").setBold());
        if (data.riskScore > 60) {
            document.add(new Paragraph("• Address all critical and high-risk vulnerabilities"));
            document.add(new Paragraph("• Update outdated software components"));
            document.add(new Paragraph("• Review and secure exposed services"));
        } else {
            document.add(new Paragraph("• Review medium-risk findings"));
            document.add(new Paragraph("• Plan technology updates"));
        }
        
        document.add(new Paragraph("\\n"));
        document.add(new Paragraph("SHORT-TERM ACTIONS (1-3 months):").setBold());
        document.add(new Paragraph("• Implement security monitoring"));
        document.add(new Paragraph("• Regular vulnerability scanning"));
        document.add(new Paragraph("• Review third-party provider security"));
        
        document.add(new Paragraph("\\n"));
        document.add(new Paragraph("LONG-TERM ACTIONS (3-12 months):").setBold());
        document.add(new Paragraph("• Establish continuous security assessment"));
        document.add(new Paragraph("• Implement security architecture improvements"));
        document.add(new Paragraph("• Regular penetration testing"));
        
        document.add(new Paragraph("\\n"));
    }
    
    private void addAppendices(Document document, DomainRiskData data) throws Exception {
        document.add(new Paragraph("APPENDICES").setBold().setFontSize(14));
        
        document.add(new Paragraph("APPENDIX A: Risk Scoring Methodology").setBold());
        document.add(new Paragraph("Risk scores are calculated based on:"));
        document.add(new Paragraph("• Technology vulnerabilities (weighted by severity)"));
        document.add(new Paragraph("• Service exposure and configuration"));
        document.add(new Paragraph("• Third-party provider risk assessment"));
        document.add(new Paragraph("• Historical threat intelligence data"));
        
        document.add(new Paragraph("\\n"));
        document.add(new Paragraph("APPENDIX B: Grade Definitions").setBold());
        document.add(new Paragraph("• Grade A (0-10): Excellent security posture"));
        document.add(new Paragraph("• Grade B (10-40): Good security with minor issues"));
        document.add(new Paragraph("• Grade C (40-60): Moderate security concerns"));
        document.add(new Paragraph("• Grade D (60-80): Significant security issues"));
        document.add(new Paragraph("• Grade E (80-100): Critical security vulnerabilities"));
        
        document.add(new Paragraph("\\n"));
    }
    
    private void addReportFooter(Document document) throws Exception {
        document.add(new Paragraph("\\n"));
        document.add(new Paragraph("Generated by Tsunami Security Platform")
                .setTextAlignment(TextAlignment.CENTER)
                .setFontSize(10)
                .setFontColor(ColorConstants.GRAY));
        document.add(new Paragraph("This report is confidential and proprietary")
                .setTextAlignment(TextAlignment.CENTER)
                .setFontSize(8)
                .setFontColor(ColorConstants.GRAY));
    }
    
    public byte[] readPdfFile(String filePath) {
        try {
            return Files.readAllBytes(Paths.get(filePath));
        } catch (IOException e) {
            throw new RuntimeException("Failed to read PDF file: " + filePath, e);
        }
    }
    
    public void deletePdfFile(String filePath) {
        try {
            Files.deleteIfExists(Paths.get(filePath));
        } catch (IOException e) {
            LOGGER.warning("Failed to delete PDF file: " + filePath + " - " + e.getMessage());
        }
    }
    
    private String generateFileName(String domain, ReportType reportType) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        return String.format("%s_%s_report_%s.pdf", 
                           domain.replace(".", "_"), 
                           reportType.toString().toLowerCase(), 
                           timestamp);
    }
    
    public static class PdfResult {
        public final String filePath;
        public final String fileName;
        public final long fileSize;
        public final int pageCount;
        
        public PdfResult(String filePath, String fileName, long fileSize, int pageCount) {
            this.filePath = filePath;
            this.fileName = fileName;
            this.fileSize = fileSize;
            this.pageCount = pageCount;
        }
    }
}