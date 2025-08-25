package com.example.report.entity;

import io.quarkus.hibernate.orm.panache.PanacheEntity;
import jakarta.persistence.*;
import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Table(name = "report_purchases")
public class ReportPurchase extends PanacheEntity {
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "client_id", nullable = false)
    public Client client;
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    public ReportType reportType;
    
    @Column(nullable = false)
    public Integer quantity;
    
    @Column(nullable = false)
    public Integer usedQuantity = 0;
    
    @Column(nullable = false, precision = 10, scale = 2)
    public BigDecimal unitPrice;
    
    @Column(nullable = false, precision = 10, scale = 2)
    public BigDecimal totalAmount;
    
    @Column
    public String paymentReference;
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    public PaymentStatus paymentStatus = PaymentStatus.PENDING;
    
    @Column(nullable = false)
    public LocalDateTime purchaseDate = LocalDateTime.now();
    
    @Column
    public LocalDateTime expirationDate;
    
    @Column
    public String notes;
    
    public enum ReportType {
        BASIC, STANDARD, PREMIUM, COMPREHENSIVE, COMPLIANCE, TECHNICAL
    }
    
    public enum PaymentStatus {
        PENDING, COMPLETED, FAILED, REFUNDED
    }
    
    public boolean hasAvailableReports() {
        return usedQuantity < quantity && 
               (expirationDate == null || expirationDate.isAfter(LocalDateTime.now()));
    }
    
    public int getAvailableQuantity() {
        if (!hasAvailableReports()) {
            return 0;
        }
        return quantity - usedQuantity;
    }
    
    public boolean useReport() {
        if (hasAvailableReports()) {
            usedQuantity++;
            return true;
        }
        return false;
    }
    
    public static ReportPurchase findAvailableForClient(String clientId, ReportType reportType) {
        return find("client.clientId = ?1 and reportType = ?2 and usedQuantity < quantity and paymentStatus = ?3 and (expirationDate is null or expirationDate > ?4)", 
                   clientId, reportType, PaymentStatus.COMPLETED, LocalDateTime.now())
               .firstResult();
    }
}