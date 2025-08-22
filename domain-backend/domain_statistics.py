"""
Domain Task Statistics Tracking Service

This module provides functionality to track detailed statistics about domain discovery tasks
and store them in PostgreSQL for performance analysis and time estimation.
"""

import asyncio
import asyncpg
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union
from contextlib import asynccontextmanager
from dataclasses import dataclass, asdict
from enum import Enum
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TaskStatus(Enum):
    """Task execution status"""
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class TaskType(Enum):
    """Types of domain analysis tasks"""
    AMASS = "amass"
    DNS_ANALYSIS = "dns_analysis"
    TLS_SCAN = "tls_scan"
    PROVIDER_DETECTION = "provider_detection"
    RISK_CALCULATION = "risk_calculation"
    COMPLETE_DISCOVERY = "complete_discovery"


@dataclass
class DomainBase:
    """Domain base information"""
    domain_name: str
    tld: str
    is_financial: bool = False
    industry: Optional[str] = None
    country_code: Optional[str] = None


@dataclass
class TaskExecution:
    """Task execution record"""
    id: Optional[str] = None
    domain_base_id: Optional[str] = None
    task_type: str = ""
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: str = TaskStatus.RUNNING.value
    duration_seconds: Optional[int] = None
    error_message: Optional[str] = None
    
    # Input parameters
    timeout_configured: Optional[int] = None
    max_subdomains_limit: Optional[int] = None
    include_providers: bool = False
    include_services: bool = False
    include_tls: bool = False
    include_risk: bool = False
    
    # Results summary
    subdomains_found: int = 0
    providers_found: int = 0
    services_found: int = 0
    certificates_found: int = 0
    risks_found: int = 0
    
    # Performance metrics
    amass_timeout_occurred: bool = False
    dns_queries_count: int = 0
    network_requests_count: int = 0
    neo4j_writes_count: int = 0
    
    # Resource usage
    max_memory_mb: Optional[int] = None
    cpu_time_seconds: Optional[float] = None


@dataclass
class TaskStep:
    """Individual step within a task execution"""
    execution_id: str
    step_name: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    step_result: Optional[str] = None  # JSON string
    error_message: Optional[str] = None


class DomainStatisticsService:
    """Service for tracking domain task statistics in PostgreSQL"""
    
    def __init__(self, connection_string: str = None):
        """Initialize the statistics service"""
        self.connection_string = connection_string or self._get_default_connection()
        self._pool: Optional[asyncpg.Pool] = None
    
    def _get_default_connection(self) -> str:
        """Get default PostgreSQL connection string"""
        host = os.getenv("POSTGRES_HOST", "localhost")
        port = os.getenv("POSTGRES_PORT", "5432")
        database = os.getenv("POSTGRES_DB", "domain_stats")
        user = os.getenv("POSTGRES_USER", "stats_user")
        password = os.getenv("POSTGRES_PASSWORD", "stats_password")
        
        return f"postgresql://{user}:{password}@{host}:{port}/{database}"
    
    async def initialize(self):
        """Initialize database connection pool"""
        try:
            self._pool = await asyncpg.create_pool(
                self.connection_string,
                min_size=2,
                max_size=10,
                command_timeout=30
            )
            logger.info("PostgreSQL connection pool initialized")
        except Exception as e:
            logger.error(f"Failed to initialize database pool: {e}")
            raise
    
    async def close(self):
        """Close database connection pool"""
        if self._pool:
            await self._pool.close()
            logger.info("PostgreSQL connection pool closed")
    
    @asynccontextmanager
    async def get_connection(self):
        """Get database connection from pool"""
        if not self._pool:
            await self.initialize()
        
        async with self._pool.acquire() as connection:
            yield connection
    
    async def ensure_domain_base(self, domain_base: DomainBase) -> str:
        """Ensure domain base exists and return its ID"""
        async with self.get_connection() as conn:
            # Check if domain already exists
            existing = await conn.fetchrow(
                "SELECT id FROM domain_bases WHERE domain_name = $1",
                domain_base.domain_name
            )
            
            if existing:
                return str(existing['id'])
            
            # Insert new domain base
            result = await conn.fetchrow("""
                INSERT INTO domain_bases (domain_name, tld, is_financial, industry, country_code)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING id
            """, 
                domain_base.domain_name,
                domain_base.tld,
                domain_base.is_financial,
                domain_base.industry,
                domain_base.country_code
            )
            
            domain_id = str(result['id'])
            logger.info(f"Created domain base record: {domain_base.domain_name} -> {domain_id}")
            return domain_id
    
    async def start_task_execution(self, 
                                   domain_name: str,
                                   task_type: TaskType,
                                   **kwargs) -> str:
        """Start tracking a new task execution"""
        # Extract TLD and determine if financial
        tld = domain_name.split('.')[-1].lower()
        is_financial = kwargs.get('is_financial', False)
        industry = kwargs.get('industry')
        country_code = kwargs.get('country_code')
        
        # Ensure domain base exists
        domain_base = DomainBase(
            domain_name=domain_name,
            tld=tld,
            is_financial=is_financial,
            industry=industry,
            country_code=country_code
        )
        domain_base_id = await self.ensure_domain_base(domain_base)
        
        # Create task execution record
        task_execution = TaskExecution(
            domain_base_id=domain_base_id,
            task_type=task_type.value,
            started_at=datetime.now(timezone.utc),
            status=TaskStatus.RUNNING.value,
            timeout_configured=kwargs.get('timeout_configured'),
            max_subdomains_limit=kwargs.get('max_subdomains_limit'),
            include_providers=kwargs.get('include_providers', False),
            include_services=kwargs.get('include_services', False),
            include_tls=kwargs.get('include_tls', False),
            include_risk=kwargs.get('include_risk', False)
        )
        
        async with self.get_connection() as conn:
            result = await conn.fetchrow("""
                INSERT INTO domain_task_executions (
                    domain_base_id, task_type, started_at, status,
                    timeout_configured, max_subdomains_limit,
                    include_providers, include_services, include_tls, include_risk
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                RETURNING id
            """,
                task_execution.domain_base_id,
                task_execution.task_type,
                task_execution.started_at,
                task_execution.status,
                task_execution.timeout_configured,
                task_execution.max_subdomains_limit,
                task_execution.include_providers,
                task_execution.include_services,
                task_execution.include_tls,
                task_execution.include_risk
            )
            
            execution_id = str(result['id'])
            logger.info(f"Started task execution: {domain_name} {task_type.value} -> {execution_id}")
            return execution_id
    
    async def complete_task_execution(self,
                                      execution_id: str,
                                      status: TaskStatus,
                                      results: Dict[str, Any] = None,
                                      error_message: str = None,
                                      performance_metrics: Dict[str, Any] = None):
        """Complete a task execution with results"""
        results = results or {}
        performance_metrics = performance_metrics or {}
        
        async with self.get_connection() as conn:
            await conn.execute("""
                UPDATE domain_task_executions 
                SET completed_at = $1,
                    status = $2,
                    error_message = $3,
                    subdomains_found = $4,
                    providers_found = $5,
                    services_found = $6,
                    certificates_found = $7,
                    risks_found = $8,
                    amass_timeout_occurred = $9,
                    dns_queries_count = $10,
                    network_requests_count = $11,
                    neo4j_writes_count = $12,
                    max_memory_mb = $13,
                    cpu_time_seconds = $14
                WHERE id = $15
            """,
                datetime.now(timezone.utc),
                status.value,
                error_message,
                results.get('subdomains_found', 0),
                results.get('providers_found', 0),
                results.get('services_found', 0),
                results.get('certificates_found', 0),
                results.get('risks_found', 0),
                performance_metrics.get('amass_timeout_occurred', False),
                performance_metrics.get('dns_queries_count', 0),
                performance_metrics.get('network_requests_count', 0),
                performance_metrics.get('neo4j_writes_count', 0),
                performance_metrics.get('max_memory_mb'),
                performance_metrics.get('cpu_time_seconds'),
                execution_id
            )
            
            logger.info(f"Completed task execution: {execution_id} -> {status.value}")
    
    async def track_step(self, 
                         execution_id: str,
                         step_name: str,
                         started_at: datetime = None) -> str:
        """Start tracking a step within a task execution"""
        started_at = started_at or datetime.now(timezone.utc)
        
        async with self.get_connection() as conn:
            result = await conn.fetchrow("""
                INSERT INTO task_step_timings (execution_id, step_name, started_at)
                VALUES ($1, $2, $3)
                RETURNING id
            """, execution_id, step_name, started_at)
            
            step_id = str(result['id'])
            logger.debug(f"Started step tracking: {step_name} -> {step_id}")
            return step_id
    
    async def complete_step(self,
                            step_id: str,
                            step_result: Dict[str, Any] = None,
                            error_message: str = None):
        """Complete a step with results"""
        step_result_json = json.dumps(step_result) if step_result else None
        
        async with self.get_connection() as conn:
            await conn.execute("""
                UPDATE task_step_timings 
                SET completed_at = $1,
                    step_result = $2,
                    error_message = $3
                WHERE id = $4
            """,
                datetime.now(timezone.utc),
                step_result_json,
                error_message,
                step_id
            )
            
            logger.debug(f"Completed step: {step_id}")
    
    async def estimate_task_duration(self,
                                     domain_name: str,
                                     task_type: TaskType,
                                     confidence_level: float = 0.9) -> Dict[str, Any]:
        """Estimate task duration based on historical data"""
        async with self.get_connection() as conn:
            result = await conn.fetchrow("""
                SELECT * FROM estimate_task_duration($1, $2, $3)
            """, domain_name, task_type.value, confidence_level)
            
            if result:
                return {
                    'estimated_seconds': result['estimated_seconds'],
                    'confidence_level': result['confidence_level'],
                    'based_on_executions': result['based_on_executions'],
                    'similar_domains_used': result['similar_domains_used']
                }
            
            return {
                'estimated_seconds': 300,  # 5 minute default
                'confidence_level': 0.5,
                'based_on_executions': 0,
                'similar_domains_used': True
            }
    
    async def get_domain_execution_stats(self, domain_name: str = None) -> List[Dict[str, Any]]:
        """Get execution statistics for domains"""
        async with self.get_connection() as conn:
            if domain_name:
                results = await conn.fetch("""
                    SELECT * FROM domain_execution_stats 
                    WHERE domain_name = $1
                    ORDER BY task_type
                """, domain_name)
            else:
                results = await conn.fetch("""
                    SELECT * FROM domain_execution_stats 
                    ORDER BY domain_name, task_type
                """)
            
            return [dict(row) for row in results]


# Context manager for easy task tracking
@asynccontextmanager
async def track_task(stats_service: DomainStatisticsService,
                     domain_name: str,
                     task_type: TaskType,
                     **kwargs):
    """Context manager for automatic task execution tracking"""
    execution_id = await stats_service.start_task_execution(
        domain_name=domain_name,
        task_type=task_type,
        **kwargs
    )
    
    task_tracker = TaskTracker(stats_service, execution_id)
    
    try:
        yield task_tracker
        await stats_service.complete_task_execution(
            execution_id=execution_id,
            status=TaskStatus.COMPLETED,
            results=task_tracker.results,
            performance_metrics=task_tracker.performance_metrics
        )
    except Exception as e:
        await stats_service.complete_task_execution(
            execution_id=execution_id,
            status=TaskStatus.FAILED,
            error_message=str(e),
            results=task_tracker.results,
            performance_metrics=task_tracker.performance_metrics
        )
        raise


class TaskTracker:
    """Helper class for tracking task progress"""
    
    def __init__(self, stats_service: DomainStatisticsService, execution_id: str):
        self.stats_service = stats_service
        self.execution_id = execution_id
        self.results = {}
        self.performance_metrics = {}
        self._active_steps = {}
    
    async def track_step(self, step_name: str):
        """Start tracking a step"""
        step_id = await self.stats_service.track_step(self.execution_id, step_name)
        self._active_steps[step_name] = step_id
        return StepTracker(self.stats_service, step_id)
    
    def update_results(self, **kwargs):
        """Update task results"""
        self.results.update(kwargs)
    
    def update_performance_metrics(self, **kwargs):
        """Update performance metrics"""
        self.performance_metrics.update(kwargs)


class StepTracker:
    """Helper class for tracking individual steps"""
    
    def __init__(self, stats_service: DomainStatisticsService, step_id: str):
        self.stats_service = stats_service
        self.step_id = step_id
    
    async def complete(self, step_result: Dict[str, Any] = None, error_message: str = None):
        """Complete the step"""
        await self.stats_service.complete_step(
            step_id=self.step_id,
            step_result=step_result,
            error_message=error_message
        )