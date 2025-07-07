package com.example.risk.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.neo4j.driver.Driver;
import org.neo4j.driver.Session;
import org.neo4j.driver.Transaction;
import org.neo4j.driver.Result;
import org.neo4j.driver.Record;
import org.neo4j.driver.Value;

import java.util.Map;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class RiskCalculatorTest {

    @Mock
    private Driver driver;
    
    @Mock
    private Session session;
    
    @Mock
    private Transaction transaction;
    
    @Mock
    private Result result;
    
    @Mock
    private Record record;
    
    @Mock
    private Value value;
    
    @Mock
    private BaseScoreCalculator baseScoreCalculator;
    
    @Mock
    private ThirdPartyScoreCalculator thirdPartyScoreCalculator;
    
    @Mock
    private IncidentImpactCalculator incidentImpactCalculator;
    
    @Mock
    private ContextBoostCalculator contextBoostCalculator;

    @InjectMocks
    private RiskCalculator riskCalculator;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(driver.session()).thenReturn(session);
    }

    @Test
    void testCalculateCompleteRiskScore_NormalCase() {
        // Arrange
        String nodeId = "example.com";
        String nodeType = "domain";
        
        when(baseScoreCalculator.calculateBaseScore(any())).thenReturn(80.0);
        when(thirdPartyScoreCalculator.calculateThirdPartyScore(nodeId, nodeType)).thenReturn(60.0);
        when(incidentImpactCalculator.calculateIncidentImpact(nodeId, nodeType)).thenReturn(40.0);
        when(contextBoostCalculator.calculateContextBoost(nodeId, nodeType)).thenReturn(10.0);
        
        // Mock fetchDomainData
        when(session.run(anyString(), any(Map.class))).thenReturn(result);
        when(result.hasNext()).thenReturn(true);
        when(result.next()).thenReturn(record);
        when(record.get("dns_sec_enabled")).thenReturn(value);
        when(value.asBoolean(false)).thenReturn(true);
        when(record.get("multi_az")).thenReturn(value);
        when(value.asBoolean(false)).thenReturn(false);
        when(record.get("multi_region")).thenReturn(value);
        when(record.get("name_servers")).thenReturn(value);
        when(value.asList()).thenReturn(java.util.List.of());
        when(record.get("tls_grade")).thenReturn(value);
        when(value.asString("")).thenReturn("A");
        when(record.get("critical_cves")).thenReturn(value);
        when(value.asInt(0)).thenReturn(0);
        when(record.get("high_cves")).thenReturn(value);

        // Act
        double riskScore = riskCalculator.calculateCompleteRiskScore(nodeId, nodeType);

        // Assert
        // Expected: (80 * 0.40) + (60 * 0.25) + (40 * 0.30) - (10 * 0.05) = 32 + 15 + 12 - 0.5 = 58.5
        assertEquals(58.5, riskScore, 0.01);
    }

    @Test
    void testCalculateCompleteRiskScore_BoundaryValues() {
        // Test minimum score (should not go below 0)
        when(baseScoreCalculator.calculateBaseScore(any())).thenReturn(0.0);
        when(thirdPartyScoreCalculator.calculateThirdPartyScore(any(), any())).thenReturn(0.0);
        when(incidentImpactCalculator.calculateIncidentImpact(any(), any())).thenReturn(0.0);
        when(contextBoostCalculator.calculateContextBoost(any(), any())).thenReturn(100.0);
        
        mockFetchDomainData();
        
        double riskScore = riskCalculator.calculateCompleteRiskScore("test.com", "domain");
        assertTrue(riskScore >= 0.0);
        
        // Test maximum score (should not go above 100)
        when(baseScoreCalculator.calculateBaseScore(any())).thenReturn(100.0);
        when(thirdPartyScoreCalculator.calculateThirdPartyScore(any(), any())).thenReturn(100.0);
        when(incidentImpactCalculator.calculateIncidentImpact(any(), any())).thenReturn(100.0);
        when(contextBoostCalculator.calculateContextBoost(any(), any())).thenReturn(0.0);
        
        riskScore = riskCalculator.calculateCompleteRiskScore("test.com", "domain");
        assertTrue(riskScore <= 100.0);
    }

    @Test
    void testGetRiskTier() {
        // Use reflection to test private method or create test scenarios
        // Testing through calculateCompleteRiskScore which calls getRiskTier internally
        
        when(baseScoreCalculator.calculateBaseScore(any())).thenReturn(90.0);
        when(thirdPartyScoreCalculator.calculateThirdPartyScore(any(), any())).thenReturn(0.0);
        when(incidentImpactCalculator.calculateIncidentImpact(any(), any())).thenReturn(0.0);
        when(contextBoostCalculator.calculateContextBoost(any(), any())).thenReturn(0.0);
        
        mockFetchDomainData();
        
        // Score should be 90 * 0.40 = 36, which maps to "Low" tier
        double riskScore = riskCalculator.calculateCompleteRiskScore("test.com", "domain");
        assertEquals(36.0, riskScore, 0.01);
        
        // Test different score ranges
        // Critical: 80-100
        when(baseScoreCalculator.calculateBaseScore(any())).thenReturn(100.0);
        when(thirdPartyScoreCalculator.calculateThirdPartyScore(any(), any())).thenReturn(100.0);
        when(incidentImpactCalculator.calculateIncidentImpact(any(), any())).thenReturn(100.0);
        
        riskScore = riskCalculator.calculateCompleteRiskScore("test.com", "domain");
        assertTrue(riskScore >= 80); // Should be in Critical range
    }

    @Test
    void testRecalcForDomainTree() {
        // Mock the transaction execution
        when(session.executeWrite(any())).thenReturn(5);
        
        int result = riskCalculator.recalcForDomainTree("example.com");
        
        assertEquals(5, result);
        verify(session).executeWrite(any());
    }

    @Test
    void testRecalcForProvider() {
        // Mock components
        when(baseScoreCalculator.calculateBaseScore(any())).thenReturn(70.0);
        when(thirdPartyScoreCalculator.calculateThirdPartyScore(any(), any())).thenReturn(50.0);
        when(incidentImpactCalculator.calculateIncidentImpact(any(), any())).thenReturn(30.0);
        when(contextBoostCalculator.calculateContextBoost(any(), any())).thenReturn(5.0);
        
        mockFetchDomainData();
        
        when(session.executeWrite(any())).thenReturn(1);
        
        int result = riskCalculator.recalcForProvider("provider-123");
        
        assertEquals(1, result);
        verify(session).executeWrite(any());
    }

    @Test
    void testRecalcForService() {
        // Mock components
        when(baseScoreCalculator.calculateBaseScore(any())).thenReturn(60.0);
        when(thirdPartyScoreCalculator.calculateThirdPartyScore(any(), any())).thenReturn(40.0);
        when(incidentImpactCalculator.calculateIncidentImpact(any(), any())).thenReturn(20.0);
        when(contextBoostCalculator.calculateContextBoost(any(), any())).thenReturn(3.0);
        
        mockFetchDomainData();
        
        when(session.executeWrite(any())).thenReturn(1);
        
        int result = riskCalculator.recalcForService("service-456");
        
        assertEquals(1, result);
        verify(session).executeWrite(any());
    }

    @Test
    void testRecalcForOrganization() {
        when(session.executeWrite(any())).thenReturn(1);
        
        int result = riskCalculator.recalcForOrganization("org-789");
        
        assertEquals(1, result);
        verify(session).executeWrite(any());
    }

    @Test
    void testFormulaWeights() {
        // Test that the formula uses correct weights: 40%, 25%, 30%, -5%
        when(baseScoreCalculator.calculateBaseScore(any())).thenReturn(100.0);
        when(thirdPartyScoreCalculator.calculateThirdPartyScore(any(), any())).thenReturn(100.0);
        when(incidentImpactCalculator.calculateIncidentImpact(any(), any())).thenReturn(100.0);
        when(contextBoostCalculator.calculateContextBoost(any(), any())).thenReturn(100.0);
        
        mockFetchDomainData();
        
        double riskScore = riskCalculator.calculateCompleteRiskScore("test.com", "domain");
        
        // Expected: (100 * 0.40) + (100 * 0.25) + (100 * 0.30) - (100 * 0.05) = 40 + 25 + 30 - 5 = 90
        assertEquals(90.0, riskScore, 0.01);
    }

    private void mockFetchDomainData() {
        when(session.run(anyString(), any(Map.class))).thenReturn(result);
        when(result.hasNext()).thenReturn(true);
        when(result.next()).thenReturn(record);
        
        when(record.get("dns_sec_enabled")).thenReturn(value);
        when(value.asBoolean(false)).thenReturn(false);
        
        when(record.get("multi_az")).thenReturn(value);
        when(record.get("multi_region")).thenReturn(value);
        
        when(record.get("name_servers")).thenReturn(value);
        when(value.asList()).thenReturn(java.util.List.of());
        
        when(record.get("tls_grade")).thenReturn(value);
        when(value.asString("")).thenReturn("");
        
        when(record.get("critical_cves")).thenReturn(value);
        when(value.asInt(0)).thenReturn(0);
        
        when(record.get("high_cves")).thenReturn(value);
    }
}