package com.example.report.entity;

import io.quarkus.hibernate.orm.panache.PanacheEntity;
import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "report_generations")
public class ReportGeneration extends PanacheEntity {
    
    @Column(nullable = false, unique = true)
    public String reportId;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "client_id", nullable = false)
    public Client client;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "purchase_id", nullable = false)
    public ReportPurchase purchase;
    
    @Column(nullable = false)
    public String domain;
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    public ReportPurchase.ReportType reportType;
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    public ReportStatus status = ReportStatus.PENDING;
    
    @Column(nullable = false)
    public LocalDateTime requestedAt = LocalDateTime.now();
    
    @Column
    public LocalDateTime generatedAt;
    
    @Column
    public String filePath;
    
    @Column
    public String fileName;
    
    @Column(columnDefinition = "TEXT")
    public String riskSummary;
    
    @Column
    public Double riskScore;
    
    @Column
    public String riskGrade;
    
    @Column(columnDefinition = "TEXT")
    public String errorMessage;
    
    @Column
    public Long fileSizeBytes;
    
    @Column
    public Integer pageCount;
    
    public enum ReportStatus {
        PENDING, GENERATING, COMPLETED, FAILED, EXPIRED
    }
    
    public static ReportGeneration findByReportId(String reportId) {
        return find("reportId", reportId).firstResult();
    }
    
    public static long countByClientAndPeriod(String clientId, LocalDateTime from, LocalDateTime to) {
        return count("client.clientId = ?1 and requestedAt between ?2 and ?3", clientId, from, to);
    }
    
    public static long countByClientAndStatus(String clientId, ReportStatus status) {
        return count("client.clientId = ?1 and status = ?2", clientId, status);
    }
    
    public boolean isExpired() {
        // Reports expire after 30 days
        return generatedAt != null && generatedAt.plusDays(30).isBefore(LocalDateTime.now());
    }
    
    public void markAsCompleted(String filePath, String fileName, long fileSizeBytes) {
        this.status = ReportStatus.COMPLETED;
        this.generatedAt = LocalDateTime.now();
        this.filePath = filePath;
        this.fileName = fileName;
        this.fileSizeBytes = fileSizeBytes;
    }
    
    public void markAsFailed(String errorMessage) {
        this.status = ReportStatus.FAILED;
        this.errorMessage = errorMessage;
    }
}