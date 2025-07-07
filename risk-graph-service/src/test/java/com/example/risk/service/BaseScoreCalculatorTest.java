package com.example.risk.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class BaseScoreCalculatorTest {

    @InjectMocks
    private BaseScoreCalculator baseScoreCalculator;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testCalculateBaseScore_Perfect() {
        Map<String, Object> domainData = new HashMap<>();
        domainData.put("dns_sec_enabled", true);
        domainData.put("tls_grade", "A+");
        domainData.put("critical_cves", 0);
        domainData.put("high_cves", 0);
        domainData.put("multi_az", true);
        domainData.put("name_servers", List.of(
            Map.of("asn", "AS1234", "country", "US"),
            Map.of("asn", "AS5678", "country", "CA")
        ));

        double score = baseScoreCalculator.calculateBaseScore(domainData);
        
        // Perfect score: 100 + 20 (DNSSEC) + 0 (TLS A+) + 0 (no CVEs) + 10 (multi-AZ) = 130, capped at 100
        assertEquals(100.0, score, 0.01);
    }

    @Test
    void testCalculateBaseScore_Poor() {
        Map<String, Object> domainData = new HashMap<>();
        domainData.put("dns_sec_enabled", false);
        domainData.put("tls_grade", "F");
        domainData.put("critical_cves", 5);
        domainData.put("high_cves", 10);
        domainData.put("multi_az", false);
        domainData.put("name_servers", List.of(
            Map.of("asn", "AS1234", "country", "US"),
            Map.of("asn", "AS1234", "country", "US")
        ));

        double score = baseScoreCalculator.calculateBaseScore(domainData);
        
        // Poor score: 100 + 0 (no DNSSEC) - 15 (single ASN) - 30 (TLS F) - 25 (CVEs) + 0 (single AZ) = 30
        assertEquals(30.0, score, 0.01);
    }

    @Test
    void testCalculateBaseScore_Average() {
        Map<String, Object> domainData = new HashMap<>();
        domainData.put("dns_sec_enabled", true);
        domainData.put("tls_grade", "B");
        domainData.put("critical_cves", 1);
        domainData.put("high_cves", 2);
        domainData.put("multi_az", false);
        domainData.put("name_servers", List.of(
            Map.of("asn", "AS1234", "country", "US"),
            Map.of("asn", "AS5678", "country", "US")
        ));

        double score = baseScoreCalculator.calculateBaseScore(domainData);
        
        // Average score: 100 + 20 (DNSSEC) - 5 (TLS B) - 11 (1 crit + 2 high CVEs) + 0 (single AZ) = 104, capped at 100
        assertEquals(100.0, score, 0.01);
    }

    @Test
    void testCalculateBaseScore_MinimumScore() {
        Map<String, Object> domainData = new HashMap<>();
        domainData.put("dns_sec_enabled", false);
        domainData.put("tls_grade", "F");
        domainData.put("critical_cves", 10);
        domainData.put("high_cves", 20);
        domainData.put("multi_az", false);
        domainData.put("name_servers", List.of(
            Map.of("asn", "AS1234", "country", "US")
        ));

        double score = baseScoreCalculator.calculateBaseScore(domainData);
        
        // Very poor score should be capped at 0
        assertEquals(0.0, score, 0.01);
    }

    @Test
    void testCalculateBaseScore_NullValues() {
        Map<String, Object> domainData = new HashMap<>();
        // All null values should result in base score of 100

        double score = baseScoreCalculator.calculateBaseScore(domainData);
        
        assertEquals(100.0, score, 0.01);
    }

    @Test
    void testDnsScoreCalculation() {
        Map<String, Object> domainData = new HashMap<>();
        
        // Test DNSSEC enabled
        domainData.put("dns_sec_enabled", true);
        domainData.put("name_servers", List.of(
            Map.of("asn", "AS1234", "country", "US"),
            Map.of("asn", "AS5678", "country", "CA")
        ));
        
        double score = baseScoreCalculator.calculateBaseScore(domainData);
        assertTrue(score > 100); // Should have positive DNS bonus
        
        // Test single ASN penalty
        domainData.put("dns_sec_enabled", false);
        domainData.put("name_servers", List.of(
            Map.of("asn", "AS1234", "country", "US"),
            Map.of("asn", "AS1234", "country", "US")
        ));
        
        score = baseScoreCalculator.calculateBaseScore(domainData);
        assertEquals(85.0, score, 0.01); // 100 - 15 for single ASN
    }

    @Test
    void testTlsGradeMapping() {
        Map<String, Object> domainData = new HashMap<>();
        
        String[] grades = {"A+", "A", "B", "C", "D", "E", "F"};
        double[] expectedPenalties = {0, 0, -5, -15, -30, -30, -30};
        
        for (int i = 0; i < grades.length; i++) {
            domainData.put("tls_grade", grades[i]);
            double score = baseScoreCalculator.calculateBaseScore(domainData);
            assertEquals(100 + expectedPenalties[i], score, 0.01, 
                "TLS grade " + grades[i] + " should result in penalty " + expectedPenalties[i]);
        }
    }

    @Test
    void testCveScoring() {
        Map<String, Object> domainData = new HashMap<>();
        
        // Test critical CVEs
        domainData.put("critical_cves", 3);
        domainData.put("high_cves", 0);
        double score = baseScoreCalculator.calculateBaseScore(domainData);
        assertEquals(85.0, score, 0.01); // 100 - (3 * 5)
        
        // Test high CVEs
        domainData.put("critical_cves", 0);
        domainData.put("high_cves", 5);
        score = baseScoreCalculator.calculateBaseScore(domainData);
        assertEquals(85.0, score, 0.01); // 100 - (5 * 3)
        
        // Test mixed CVEs
        domainData.put("critical_cves", 2);
        domainData.put("high_cves", 3);
        score = baseScoreCalculator.calculateBaseScore(domainData);
        assertEquals(81.0, score, 0.01); // 100 - (2 * 5 + 3 * 3)
        
        // Test CVE cap
        domainData.put("critical_cves", 10);
        domainData.put("high_cves", 10);
        score = baseScoreCalculator.calculateBaseScore(domainData);
        assertEquals(75.0, score, 0.01); // 100 - 25 (maximum penalty)
    }

    @Test
    void testRedundancyBonus() {
        Map<String, Object> domainData = new HashMap<>();
        
        // Test multi-AZ
        domainData.put("multi_az", true);
        double score = baseScoreCalculator.calculateBaseScore(domainData);
        assertEquals(110.0, score, 0.01); // 100 + 10
        
        // Test multi-region
        domainData.put("multi_az", false);
        domainData.put("multi_region", true);
        score = baseScoreCalculator.calculateBaseScore(domainData);
        assertEquals(110.0, score, 0.01); // 100 + 10
        
        // Test no redundancy
        domainData.put("multi_az", false);
        domainData.put("multi_region", false);
        score = baseScoreCalculator.calculateBaseScore(domainData);
        assertEquals(100.0, score, 0.01); // 100 + 0
    }
}