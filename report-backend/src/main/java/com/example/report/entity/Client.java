package com.example.report.entity;

import io.quarkus.hibernate.orm.panache.PanacheEntity;
import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "clients")
public class Client extends PanacheEntity {
    
    @Column(nullable = false, unique = true)
    public String clientId;
    
    @Column(nullable = false)
    public String name;
    
    @Column(nullable = false, unique = true)
    public String email;
    
    @Column
    public String organization;
    
    @Column
    public String contactPhone;
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    public ClientStatus status = ClientStatus.ACTIVE;
    
    @Column(nullable = false)
    public LocalDateTime createdAt = LocalDateTime.now();
    
    @Column
    public LocalDateTime updatedAt = LocalDateTime.now();
    
    @OneToMany(mappedBy = "client", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    public List<ReportPurchase> purchases;
    
    @OneToMany(mappedBy = "client", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    public List<ReportGeneration> reports;
    
    public enum ClientStatus {
        ACTIVE, SUSPENDED, INACTIVE
    }
    
    // Utility methods
    public static Client findByClientId(String clientId) {
        return find("clientId", clientId).firstResult();
    }
    
    public static Client findByEmail(String email) {
        return find("email", email).firstResult();
    }
    
    public int getTotalAvailableReports() {
        return purchases.stream()
                .mapToInt(purchase -> purchase.quantity - purchase.usedQuantity)
                .sum();
    }
    
    public int getTotalStandardReports() {
        return purchases.stream()
                .filter(p -> p.reportType == ReportPurchase.ReportType.STANDARD)
                .mapToInt(purchase -> purchase.quantity - purchase.usedQuantity)
                .sum();
    }
    
    public int getTotalPremiumReports() {
        return purchases.stream()
                .filter(p -> p.reportType == ReportPurchase.ReportType.PREMIUM)
                .mapToInt(purchase -> purchase.quantity - purchase.usedQuantity)
                .sum();
    }
}