package com.example.risk.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.neo4j.driver.Session;
import org.neo4j.driver.Result;
import org.neo4j.driver.Record;
import org.neo4j.driver.Value;

import java.time.LocalDateTime;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class IncidentImpactCalculatorTest {

    @Mock
    private Session neo4jSession;
    
    @Mock
    private Result result;
    
    @Mock
    private Record record;
    
    @Mock
    private Value value;

    @InjectMocks
    private IncidentImpactCalculator incidentImpactCalculator;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testCalculateIncidentImpact_NoIncidents() {
        // Arrange
        when(neo4jSession.run(anyString(), any(Map.class))).thenReturn(result);
        when(result.hasNext()).thenReturn(false);

        // Act
        double impact = incidentImpactCalculator.calculateIncidentImpact("test.com", "domain");

        // Assert
        assertEquals(0.0, impact, 0.01);
    }

    @Test
    void testCalculateIncidentImpact_DirectIncidents() {
        // Arrange - Mock direct incident
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime detected = now.minusDays(1); // 1 day ago
        
        when(neo4jSession.run(anyString(), any(Map.class)))
            .thenReturn(result) // Direct incidents
            .thenReturn(result); // Indirect incidents (empty)
        
        when(result.hasNext())
            .thenReturn(true, false) // Direct: has one incident, then no more
            .thenReturn(false); // Indirect: no incidents
        
        when(result.next()).thenReturn(record);
        
        when(record.get("severity")).thenReturn(value);
        when(value.asString()).thenReturn("Critical");
        
        when(record.get("detected")).thenReturn(value);
        when(value.asLocalDateTime()).thenReturn(detected);
        
        when(record.get("resolved")).thenReturn(value);
        when(value.asLocalDateTime(null)).thenReturn(null);
        
        when(record.get("failoverExists")).thenReturn(value);
        when(value.asBoolean(false)).thenReturn(false);

        // Act
        double impact = incidentImpactCalculator.calculateIncidentImpact("test.com", "domain");

        // Assert
        // Critical incident (100 points) * temporal decay for 1 day
        double expectedDecay = Math.exp(-0.015 * 1); // λ = 0.015, 1 day
        double expectedImpact = 100.0 * expectedDecay;
        
        assertEquals(expectedImpact, impact, 0.1);
        assertTrue(impact > 95 && impact < 100); // Should be close to 100 for recent critical incident
    }

    @Test
    void testCalculateIncidentImpact_WithFailover() {
        // Arrange
        LocalDateTime detected = LocalDateTime.now().minusDays(1);
        
        when(neo4jSession.run(anyString(), any(Map.class)))
            .thenReturn(result)
            .thenReturn(result);
        
        when(result.hasNext())
            .thenReturn(true, false)
            .thenReturn(false);
        
        when(result.next()).thenReturn(record);
        
        when(record.get("severity")).thenReturn(value);
        when(value.asString()).thenReturn("High");
        
        when(record.get("detected")).thenReturn(value);
        when(value.asLocalDateTime()).thenReturn(detected);
        
        when(record.get("resolved")).thenReturn(value);
        when(value.asLocalDateTime(null)).thenReturn(null);
        
        when(record.get("failoverExists")).thenReturn(value);
        when(value.asBoolean(false)).thenReturn(true); // Has failover

        // Act
        double impact = incidentImpactCalculator.calculateIncidentImpact("test.com", "domain");

        // Assert
        // High incident (70 points) * temporal decay * failover mitigation (0.6)
        double expectedDecay = Math.exp(-0.015 * 1);
        double expectedImpact = 70.0 * expectedDecay * 0.6;
        
        assertEquals(expectedImpact, impact, 0.1);
    }

    @Test
    void testCalculateIncidentImpact_TemporalDecay() {
        // Test different time periods to verify temporal decay
        LocalDateTime[] detectedTimes = {
            LocalDateTime.now().minusDays(0),   // Today
            LocalDateTime.now().minusDays(1),   // 1 day ago
            LocalDateTime.now().minusDays(46),  // Half-life period
            LocalDateTime.now().minusDays(100)  // Long time ago
        };
        
        double[] expectedDecayFactors = {
            1.0,                                // No decay for today
            Math.exp(-0.015 * 1),              // 1 day decay
            Math.exp(-0.015 * 46),             // Half-life decay (~0.5)
            Math.exp(-0.015 * 100)             // Significant decay
        };
        
        for (int i = 0; i < detectedTimes.length; i++) {
            // Arrange
            when(neo4jSession.run(anyString(), any(Map.class)))
                .thenReturn(result)
                .thenReturn(result);
            
            when(result.hasNext())
                .thenReturn(true, false)
                .thenReturn(false);
            
            when(result.next()).thenReturn(record);
            
            when(record.get("severity")).thenReturn(value);
            when(value.asString()).thenReturn("Medium");
            
            when(record.get("detected")).thenReturn(value);
            when(value.asLocalDateTime()).thenReturn(detectedTimes[i]);
            
            when(record.get("resolved")).thenReturn(value);
            when(value.asLocalDateTime(null)).thenReturn(null);
            
            when(record.get("failoverExists")).thenReturn(value);
            when(value.asBoolean(false)).thenReturn(false);

            // Act
            double impact = incidentImpactCalculator.calculateIncidentImpact("test.com", "domain");

            // Assert
            double expectedImpact = 40.0 * expectedDecayFactors[i]; // Medium severity = 40
            assertEquals(expectedImpact, impact, 0.5, 
                "Time period " + i + " should have correct decay factor");
        }
    }

    @Test
    void testCalculateIncidentImpact_ResolvedIncident() {
        // Arrange
        LocalDateTime detected = LocalDateTime.now().minusDays(5);
        LocalDateTime resolved = LocalDateTime.now().minusDays(3); // Resolved 3 days ago
        
        when(neo4jSession.run(anyString(), any(Map.class)))
            .thenReturn(result)
            .thenReturn(result);
        
        when(result.hasNext())
            .thenReturn(true, false)
            .thenReturn(false);
        
        when(result.next()).thenReturn(record);
        
        when(record.get("severity")).thenReturn(value);
        when(value.asString()).thenReturn("Low");
        
        when(record.get("detected")).thenReturn(value);
        when(value.asLocalDateTime()).thenReturn(detected);
        
        when(record.get("resolved")).thenReturn(value);
        when(value.asLocalDateTime(null)).thenReturn(resolved);
        
        when(record.get("failoverExists")).thenReturn(value);
        when(value.asBoolean(false)).thenReturn(false);

        // Act
        double impact = incidentImpactCalculator.calculateIncidentImpact("test.com", "domain");

        // Assert
        // Should use resolved time instead of current time for decay calculation
        // Low incident (10 points) from detection to resolution (2 days)
        double expectedDecay = Math.exp(-0.015 * 2);
        double expectedImpact = 10.0 * expectedDecay;
        
        assertEquals(expectedImpact, impact, 0.1);
    }

    @Test
    void testCalculateIncidentImpact_MultipleIncidents() {
        // Arrange
        LocalDateTime detected1 = LocalDateTime.now().minusDays(1);
        LocalDateTime detected2 = LocalDateTime.now().minusDays(5);
        
        when(neo4jSession.run(anyString(), any(Map.class)))
            .thenReturn(result)
            .thenReturn(result);
        
        when(result.hasNext())
            .thenReturn(true, true, false) // Two direct incidents
            .thenReturn(false); // No indirect incidents
        
        when(result.next())
            .thenReturn(record) // First incident
            .thenReturn(record); // Second incident
        
        // First incident - Critical, recent
        when(record.get("severity"))
            .thenReturn(value)
            .thenReturn(value);
        when(value.asString())
            .thenReturn("Critical")
            .thenReturn("Medium");
        
        when(record.get("detected"))
            .thenReturn(value)
            .thenReturn(value);
        when(value.asLocalDateTime())
            .thenReturn(detected1)
            .thenReturn(detected2);
        
        when(record.get("resolved"))
            .thenReturn(value)
            .thenReturn(value);
        when(value.asLocalDateTime(null))
            .thenReturn(null)
            .thenReturn(null);
        
        when(record.get("failoverExists"))
            .thenReturn(value)
            .thenReturn(value);
        when(value.asBoolean(false))
            .thenReturn(false)
            .thenReturn(false);

        // Act
        double impact = incidentImpactCalculator.calculateIncidentImpact("test.com", "domain");

        // Assert
        // Should be sum of both incidents with their respective decay
        double impact1 = 100.0 * Math.exp(-0.015 * 1); // Critical, 1 day
        double impact2 = 40.0 * Math.exp(-0.015 * 5);  // Medium, 5 days
        double expectedImpact = Math.min(100.0, impact1 + impact2);
        
        assertEquals(expectedImpact, impact, 0.5);
    }

    @Test
    void testCalculateIncidentImpact_MaxCapAt100() {
        // Arrange - Multiple high-impact incidents that would exceed 100
        when(neo4jSession.run(anyString(), any(Map.class)))
            .thenReturn(result)
            .thenReturn(result);
        
        when(result.hasNext())
            .thenReturn(true, true, true, false) // Three critical incidents
            .thenReturn(false);
        
        when(result.next())
            .thenReturn(record)
            .thenReturn(record)
            .thenReturn(record);
        
        when(record.get("severity")).thenReturn(value);
        when(value.asString()).thenReturn("Critical");
        
        when(record.get("detected")).thenReturn(value);
        when(value.asLocalDateTime()).thenReturn(LocalDateTime.now());
        
        when(record.get("resolved")).thenReturn(value);
        when(value.asLocalDateTime(null)).thenReturn(null);
        
        when(record.get("failoverExists")).thenReturn(value);
        when(value.asBoolean(false)).thenReturn(false);

        // Act
        double impact = incidentImpactCalculator.calculateIncidentImpact("test.com", "domain");

        // Assert
        assertEquals(100.0, impact, 0.01); // Should be capped at 100
    }

    @Test
    void testSeverityMapping() {
        String[] severities = {"Critical", "High", "Medium", "Low", "Unknown"};
        double[] expectedScores = {100.0, 70.0, 40.0, 10.0, 10.0}; // Unknown defaults to Low
        
        for (int i = 0; i < severities.length; i++) {
            // Arrange
            when(neo4jSession.run(anyString(), any(Map.class)))
                .thenReturn(result)
                .thenReturn(result);
            
            when(result.hasNext())
                .thenReturn(true, false)
                .thenReturn(false);
            
            when(result.next()).thenReturn(record);
            
            when(record.get("severity")).thenReturn(value);
            when(value.asString()).thenReturn(severities[i]);
            
            when(record.get("detected")).thenReturn(value);
            when(value.asLocalDateTime()).thenReturn(LocalDateTime.now());
            
            when(record.get("resolved")).thenReturn(value);
            when(value.asLocalDateTime(null)).thenReturn(null);
            
            when(record.get("failoverExists")).thenReturn(value);
            when(value.asBoolean(false)).thenReturn(false);

            // Act
            double impact = incidentImpactCalculator.calculateIncidentImpact("test.com", "domain");

            // Assert
            assertEquals(expectedScores[i], impact, 0.1, 
                "Severity " + severities[i] + " should map to score " + expectedScores[i]);
        }
    }
}