package com.example.report.service;

import com.example.report.entity.ReportPurchase.ReportType;
import com.example.report.service.DomainDataService.DomainRiskData;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.io.*;
import java.util.Date;

@ApplicationScoped
public class PdfGenerationService {
    
    @Inject
    DigitalSignatureService digitalSignatureService;
    
    public byte[] generatePdfReport(DomainRiskData data, ReportType reportType) throws IOException {
        return generatePdfReport(data, reportType, false);
    }
    
    public byte[] generatePdfReport(DomainRiskData data, ReportType reportType, boolean withDigitalSignature) throws IOException {
        try {
            // Generate the basic report content
            String reportContent = generateSimpleTextReport(data, reportType);
            byte[] pdfBytes = reportContent.getBytes("UTF-8");
            
            // Apply digital signature if requested
            if (withDigitalSignature) {
                try {
                    pdfBytes = digitalSignatureService.signPDFWithSelfSignedCertificate(pdfBytes);
                } catch (Exception e) {
                    // Log the error but continue with unsigned PDF
                    System.err.println("Failed to apply digital signature, continuing with unsigned PDF: " + e.getMessage());
                }
            }
            
            return pdfBytes;
            
        } catch (Exception e) {
            throw new IOException("Failed to generate PDF report: " + e.getMessage(), e);
        }
    }
    
    public byte[] generateSignedPdfReport(DomainRiskData data, ReportType reportType) throws IOException {
        return generatePdfReport(data, reportType, true);
    }
    
    // Métodos placeholder para compatibilidad
    public byte[] generatePdf(DomainRiskData data, ReportType reportType) throws IOException {
        return generatePdfReport(data, reportType);
    }
    
    public byte[] readPdfFile(String filename) throws IOException {
        // TODO: Implementar lectura de archivo PDF
        return ("PDF file: " + filename + " - Not implemented yet").getBytes("UTF-8");
    }
    
    public void deletePdfFile(String filename) {
        // TODO: Implementar eliminación de archivo PDF
        System.out.println("Deleting PDF file: " + filename + " - Not implemented yet");
    }
    
    private String generateSimpleTextReport(DomainRiskData data, ReportType reportType) {
        StringBuilder report = new StringBuilder();
        
        report.append("TSUNAMI SECURITY REPORT\n");
        report.append("======================\n\n");
        
        report.append("Report Type: ").append(reportType).append("\n");
        report.append("Domain: ").append(data.domain).append("\n");
        report.append("Generated: ").append(new Date()).append("\n\n");
        
        report.append("SUMMARY\n");
        report.append("-------\n");
        report.append("Risk Score: ").append(data.riskScore).append("\n");
        report.append("Risk Grade: ").append(data.riskGrade).append("\n");
        report.append("Risk Level: ").append(data.riskLevel).append("\n");
        report.append("Risk Tier: ").append(data.riskTier).append("\n");
        report.append("Business Criticality: ").append(data.businessCriticality).append("\n\n");
        
        if (data.subdomains != null && !data.subdomains.isEmpty()) {
            report.append("SUBDOMAINS (").append(data.subdomains.size()).append(")\n");
            report.append("----------\n");
            for (DomainDataService.SubdomainInfo subdomain : data.subdomains) {
                report.append("- ").append(subdomain.fqdn).append(" (Risk: ").append(subdomain.riskScore).append(")\n");
            }
            report.append("\n");
        }
        
        if (data.technologies != null && !data.technologies.isEmpty()) {
            report.append("TECHNOLOGIES (").append(data.technologies.size()).append(")\n");
            report.append("------------\n");
            for (DomainDataService.TechnologyInfo tech : data.technologies) {
                report.append("- ").append(tech.name);
                if (tech.version != null) {
                    report.append(" v").append(tech.version);
                }
                report.append(" [").append(tech.category).append("]");
                report.append(" - Risk: ").append(tech.riskLevel);
                if (tech.vulnerabilityNotes != null && !tech.vulnerabilityNotes.isEmpty()) {
                    report.append(" - ").append(tech.vulnerabilityNotes);
                }
                report.append("\n");
            }
            report.append("\n");
        }
        
        if (data.services != null && !data.services.isEmpty()) {
            report.append("SERVICES (").append(data.services.size()).append(")\n");
            report.append("--------\n");
            for (DomainDataService.ServiceInfo service : data.services) {
                report.append("- ").append(service.serviceName).append(" on port ").append(service.port);
                if (service.protocol != null) {
                    report.append("/").append(service.protocol);
                }
                if (service.version != null) {
                    report.append(" v").append(service.version);
                }
                if (service.product != null) {
                    report.append(" (").append(service.product).append(")");
                }
                report.append(" - State: ").append(service.state);
                report.append("\n");
            }
            report.append("\n");
        }
        
        if (data.providers != null && !data.providers.isEmpty()) {
            report.append("PROVIDERS (").append(data.providers.size()).append(")\n");
            report.append("---------\n");
            for (DomainDataService.ProviderInfo provider : data.providers) {
                report.append("- ").append(provider.name).append(" (").append(provider.type).append(")");
                report.append(" - Confidence: ").append(provider.confidence);
                report.append("\n");
            }
            report.append("\n");
        }
        
        report.append("NOTE: This is a simplified text report generated with Quarkus 3.15.1 LTS and Java 21.\n");
        report.append("PDF generation will be implemented using DSS (https://github.com/esig/dss) for digital signatures.\n");
        
        return report.toString();
    }
}