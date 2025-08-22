-- Domain Task Statistics Database Schema
-- PostgreSQL 15 initialization script

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Domain base table - stores information about base domains
CREATE TABLE domain_bases (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain_name VARCHAR(255) NOT NULL UNIQUE,
    tld VARCHAR(10) NOT NULL,
    is_financial BOOLEAN DEFAULT FALSE,
    industry VARCHAR(100),
    country_code CHAR(2),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Domain task executions - detailed statistics per task execution
CREATE TABLE domain_task_executions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain_base_id UUID REFERENCES domain_bases(id) ON DELETE CASCADE,
    task_type VARCHAR(50) NOT NULL, -- 'amass', 'dns_analysis', 'tls_scan', 'provider_detection', 'risk_calculation', 'complete_discovery'
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) DEFAULT 'running', -- 'running', 'completed', 'failed', 'timeout'
    duration_seconds INTEGER, -- calculated from started_at/completed_at
    error_message TEXT,
    
    -- Input parameters
    timeout_configured INTEGER,
    max_subdomains_limit INTEGER,
    include_providers BOOLEAN DEFAULT FALSE,
    include_services BOOLEAN DEFAULT FALSE,
    include_tls BOOLEAN DEFAULT FALSE,
    include_risk BOOLEAN DEFAULT FALSE,
    
    -- Results summary
    subdomains_found INTEGER DEFAULT 0,
    providers_found INTEGER DEFAULT 0,
    services_found INTEGER DEFAULT 0,
    certificates_found INTEGER DEFAULT 0,
    risks_found INTEGER DEFAULT 0,
    
    -- Performance metrics
    amass_timeout_occurred BOOLEAN DEFAULT FALSE,
    dns_queries_count INTEGER DEFAULT 0,
    network_requests_count INTEGER DEFAULT 0,
    neo4j_writes_count INTEGER DEFAULT 0,
    
    -- Resource usage (if available)
    max_memory_mb INTEGER,
    cpu_time_seconds FLOAT,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Task step details - granular timing for each step within a task
CREATE TABLE task_step_timings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    execution_id UUID REFERENCES domain_task_executions(id) ON DELETE CASCADE,
    step_name VARCHAR(100) NOT NULL, -- 'amass_execution', 'dns_resolution', 'provider_detection', 'tls_analysis', 'neo4j_save'
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE,
    duration_seconds INTEGER,
    step_result TEXT, -- JSON string with step-specific results
    error_message TEXT,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Historical performance aggregations - for quick time estimation queries
CREATE TABLE performance_aggregations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Grouping dimensions
    task_type VARCHAR(50) NOT NULL,
    domain_tld VARCHAR(10),
    is_financial BOOLEAN,
    has_many_subdomains BOOLEAN, -- TRUE if >50 subdomains typically found
    
    -- Time period
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    
    -- Aggregated statistics
    executions_count INTEGER NOT NULL,
    avg_duration_seconds INTEGER,
    median_duration_seconds INTEGER,
    p90_duration_seconds INTEGER,
    p95_duration_seconds INTEGER,
    p99_duration_seconds INTEGER,
    min_duration_seconds INTEGER,
    max_duration_seconds INTEGER,
    
    success_rate FLOAT, -- percentage of successful executions
    timeout_rate FLOAT, -- percentage of timeouts
    
    avg_subdomains_found FLOAT,
    avg_providers_found FLOAT,
    avg_services_found FLOAT,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(task_type, domain_tld, is_financial, has_many_subdomains, period_start)
);

-- Create indexes for better query performance
CREATE INDEX idx_domain_bases_domain_name ON domain_bases(domain_name);
CREATE INDEX idx_domain_bases_tld ON domain_bases(tld);
CREATE INDEX idx_domain_bases_is_financial ON domain_bases(is_financial);
CREATE INDEX idx_domain_bases_industry ON domain_bases(industry);

CREATE INDEX idx_task_executions_domain_base_id ON domain_task_executions(domain_base_id);
CREATE INDEX idx_task_executions_task_type ON domain_task_executions(task_type);
CREATE INDEX idx_task_executions_started_at ON domain_task_executions(started_at);
CREATE INDEX idx_task_executions_status ON domain_task_executions(status);
CREATE INDEX idx_task_executions_duration ON domain_task_executions(duration_seconds);

CREATE INDEX idx_step_timings_execution_id ON task_step_timings(execution_id);
CREATE INDEX idx_step_timings_step_name ON task_step_timings(step_name);
CREATE INDEX idx_step_timings_started_at ON task_step_timings(started_at);

CREATE INDEX idx_perf_aggregations_task_type ON performance_aggregations(task_type);
CREATE INDEX idx_perf_aggregations_period ON performance_aggregations(period_start, period_end);
CREATE INDEX idx_perf_aggregations_tld ON performance_aggregations(domain_tld);

-- Function to automatically calculate duration when completed_at is updated
CREATE OR REPLACE FUNCTION update_duration()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.completed_at IS NOT NULL AND OLD.completed_at IS NULL THEN
        NEW.duration_seconds = EXTRACT(EPOCH FROM (NEW.completed_at - NEW.started_at))::INTEGER;
    END IF;
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers
CREATE TRIGGER trigger_update_task_execution_duration
    BEFORE UPDATE ON domain_task_executions
    FOR EACH ROW EXECUTE FUNCTION update_duration();

CREATE TRIGGER trigger_update_step_timing_duration
    BEFORE UPDATE ON task_step_timings
    FOR EACH ROW EXECUTE FUNCTION update_duration();

-- Function to estimate task duration based on historical data
CREATE OR REPLACE FUNCTION estimate_task_duration(
    p_domain_name VARCHAR(255),
    p_task_type VARCHAR(50),
    p_confidence_level FLOAT DEFAULT 0.9
)
RETURNS TABLE (
    estimated_seconds INTEGER,
    confidence_level FLOAT,
    based_on_executions INTEGER,
    similar_domains_used BOOLEAN
) AS $$
DECLARE
    domain_tld VARCHAR(10);
    domain_is_financial BOOLEAN;
    executions_count INTEGER;
    duration_estimate INTEGER;
BEGIN
    -- Extract TLD and determine if financial
    SELECT 
        LOWER(SPLIT_PART(p_domain_name, '.', -1)),
        CASE WHEN industry IN ('Banking', 'Finance', 'Insurance') THEN TRUE ELSE FALSE END
    INTO domain_tld, domain_is_financial
    FROM domain_bases 
    WHERE domain_name = p_domain_name;
    
    -- If domain not found, use defaults
    IF domain_tld IS NULL THEN
        domain_tld := LOWER(SPLIT_PART(p_domain_name, '.', -1));
        domain_is_financial := FALSE;
    END IF;
    
    -- Try exact match first
    SELECT COUNT(*), 
           CASE 
               WHEN p_confidence_level >= 0.95 THEN PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_seconds)
               WHEN p_confidence_level >= 0.90 THEN PERCENTILE_CONT(0.90) WITHIN GROUP (ORDER BY duration_seconds)
               WHEN p_confidence_level >= 0.80 THEN PERCENTILE_CONT(0.80) WITHIN GROUP (ORDER BY duration_seconds)
               ELSE AVG(duration_seconds)
           END::INTEGER
    INTO executions_count, duration_estimate
    FROM domain_task_executions dte
    JOIN domain_bases db ON dte.domain_base_id = db.id
    WHERE dte.task_type = p_task_type 
      AND dte.status = 'completed'
      AND db.domain_name = p_domain_name
      AND dte.started_at > NOW() - INTERVAL '90 days';
    
    IF executions_count >= 3 THEN
        RETURN QUERY SELECT duration_estimate, p_confidence_level, executions_count, FALSE;
        RETURN;
    END IF;
    
    -- Try similar domains (same TLD and financial status)
    SELECT COUNT(*), 
           CASE 
               WHEN p_confidence_level >= 0.95 THEN PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_seconds)
               WHEN p_confidence_level >= 0.90 THEN PERCENTILE_CONT(0.90) WITHIN GROUP (ORDER BY duration_seconds)
               WHEN p_confidence_level >= 0.80 THEN PERCENTILE_CONT(0.80) WITHIN GROUP (ORDER BY duration_seconds)
               ELSE AVG(duration_seconds)
           END::INTEGER
    INTO executions_count, duration_estimate
    FROM domain_task_executions dte
    JOIN domain_bases db ON dte.domain_base_id = db.id
    WHERE dte.task_type = p_task_type 
      AND dte.status = 'completed'
      AND db.tld = domain_tld
      AND db.is_financial = domain_is_financial
      AND dte.started_at > NOW() - INTERVAL '180 days';
    
    IF executions_count >= 5 THEN
        RETURN QUERY SELECT duration_estimate, p_confidence_level * 0.8, executions_count, TRUE;
        RETURN;
    END IF;
    
    -- Fallback to global average for task type
    SELECT COUNT(*), 
           CASE 
               WHEN p_confidence_level >= 0.95 THEN PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_seconds)
               WHEN p_confidence_level >= 0.90 THEN PERCENTILE_CONT(0.90) WITHIN GROUP (ORDER BY duration_seconds)
               WHEN p_confidence_level >= 0.80 THEN PERCENTILE_CONT(0.80) WITHIN GROUP (ORDER BY duration_seconds)
               ELSE AVG(duration_seconds)
           END::INTEGER
    INTO executions_count, duration_estimate
    FROM domain_task_executions dte
    WHERE dte.task_type = p_task_type 
      AND dte.status = 'completed'
      AND dte.started_at > NOW() - INTERVAL '365 days';
    
    RETURN QUERY SELECT 
        COALESCE(duration_estimate, 300), -- 5 minute default
        p_confidence_level * 0.5, 
        COALESCE(executions_count, 0), 
        TRUE;
END;
$$ LANGUAGE plpgsql;

-- Insert some sample data for testing
INSERT INTO domain_bases (domain_name, tld, is_financial, industry, country_code) VALUES
('cooperativa.cl', 'cl', true, 'Banking', 'CL'),
('google.cl', 'cl', false, 'Technology', 'CL'),
('microsoft.com', 'com', false, 'Technology', 'US'),
('chase.com', 'com', true, 'Banking', 'US');

-- Create view for easy querying of execution statistics
CREATE VIEW domain_execution_stats AS
SELECT 
    db.domain_name,
    db.tld,
    db.is_financial,
    db.industry,
    dte.task_type,
    COUNT(*) as total_executions,
    COUNT(*) FILTER (WHERE dte.status = 'completed') as successful_executions,
    COUNT(*) FILTER (WHERE dte.status = 'failed') as failed_executions,
    COUNT(*) FILTER (WHERE dte.status = 'timeout') as timeout_executions,
    ROUND(AVG(dte.duration_seconds)::numeric, 2) as avg_duration_seconds,
    ROUND(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY dte.duration_seconds)::numeric, 2) as median_duration_seconds,
    ROUND(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY dte.duration_seconds)::numeric, 2) as p95_duration_seconds,
    AVG(dte.subdomains_found) as avg_subdomains_found,
    AVG(dte.providers_found) as avg_providers_found,
    MAX(dte.started_at) as last_execution
FROM domain_bases db
LEFT JOIN domain_task_executions dte ON db.id = dte.domain_base_id
WHERE dte.status IN ('completed', 'failed', 'timeout')
GROUP BY db.id, db.domain_name, db.tld, db.is_financial, db.industry, dte.task_type
ORDER BY db.domain_name, dte.task_type;

COMMENT ON TABLE domain_bases IS 'Base domains being monitored for security analysis';
COMMENT ON TABLE domain_task_executions IS 'Detailed execution logs for domain analysis tasks';
COMMENT ON TABLE task_step_timings IS 'Granular timing data for individual steps within tasks';
COMMENT ON TABLE performance_aggregations IS 'Pre-computed performance statistics for fast time estimation';
COMMENT ON FUNCTION estimate_task_duration IS 'Estimates task execution time based on historical data';