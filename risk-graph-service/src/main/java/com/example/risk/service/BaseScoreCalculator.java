package com.example.risk.service;

import jakarta.enterprise.context.ApplicationScoped;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

@ApplicationScoped
public class BaseScoreCalculator {
    
    public double calculateBaseScore(Map<String, Object> domainData) {
        double score = 100.0;
        
        score += calculateDnsScore(domainData);
        score += calculateTlsScore(domainData);
        score += calculateObsoleteTechScore(domainData);
        score += calculateRedundancyScore(domainData);
        
        return Math.max(0, Math.min(100, score));
    }
    
    private double calculateDnsScore(Map<String, Object> domainData) {
        double dnsScore = 0;
        
        Boolean dnssecEnabled = (Boolean) domainData.get("dns_sec_enabled");
        if (dnssecEnabled != null && dnssecEnabled) {
            dnsScore += 20;
        }
        
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> nameServers = (List<Map<String, Object>>) domainData.get("name_servers");
        if (nameServers != null && !nameServers.isEmpty()) {
            boolean singleAsn = checkSingleAsnOrGeo(nameServers);
            if (singleAsn) {
                dnsScore -= 15;
            }
        }
        
        return Math.max(-35, Math.min(35, dnsScore));
    }
    
    private double calculateTlsScore(Map<String, Object> domainData) {
        String tlsGrade = (String) domainData.get("tls_grade");
        if (tlsGrade == null) {
            return 0;
        }
        
        switch (tlsGrade.toUpperCase()) {
            case "A+":
            case "A":
                return 0;
            case "B":
                return -5;
            case "C":
                return -15;
            case "D":
            case "E":
            case "F":
                return -30;
            default:
                return 0;
        }
    }
    
    private double calculateObsoleteTechScore(Map<String, Object> domainData) {
        Integer criticalCves = (Integer) domainData.get("critical_cves");
        Integer highCves = (Integer) domainData.get("high_cves");
        
        if (criticalCves == null) criticalCves = 0;
        if (highCves == null) highCves = 0;
        
        double cveScore = -(criticalCves * 5 + highCves * 3);
        return Math.max(-25, cveScore);
    }
    
    private double calculateRedundancyScore(Map<String, Object> domainData) {
        Boolean multiAz = (Boolean) domainData.get("multi_az");
        Boolean multiRegion = (Boolean) domainData.get("multi_region");
        
        if ((multiAz != null && multiAz) || (multiRegion != null && multiRegion)) {
            return 10;
        }
        
        return 0;
    }
    
    private boolean checkSingleAsnOrGeo(List<Map<String, Object>> nameServers) {
        if (nameServers.size() <= 1) {
            return true;
        }
        
        String firstAsn = null;
        String firstCountry = null;
        
        for (Map<String, Object> ns : nameServers) {
            String asn = (String) ns.get("asn");
            String country = (String) ns.get("country");
            
            if (firstAsn == null) {
                firstAsn = asn;
                firstCountry = country;
            } else {
                if (!firstAsn.equals(asn) || !firstCountry.equals(country)) {
                    return false;
                }
            }
        }
        
        return true;
    }
}