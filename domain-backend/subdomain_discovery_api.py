#!/usr/bin/env python3
"""
subdomain_discovery_api.py - REST API for Unified Subdomain Discovery Engine

This service exposes the unified subdomain discovery functionality through a RESTful API
with configurable parameters, timeouts, and feature flags.

API Design:
- Base URL pattern: /api/v1/discovery/{domain}
- Feature flags as URL paths: /discoveryWithProviders, /discoveryWithServices, etc.
- Timeouts and limits as query parameters
- Boolean options as URL segments
- Swagger/OpenAPI documentation at /docs

Examples:
- GET /api/v1/discovery/example.com - Basic discovery
- GET /api/v1/discoveryWithProviders/example.com?timeout=300&maxSubdomains=500
- GET /api/v1/discoveryWithServices/example.com?amassTimeout=600&workers=5
- GET /api/v1/discoveryComplete/example.com - Full analysis (all features)
"""

from fastapi import FastAPI, HTTPException, Query, Path, BackgroundTasks, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import asyncio
import uvicorn
import logging
import time
from datetime import datetime, timedelta
import json
import subprocess
import os
from pathlib import Path

# Import our unified discovery engine
try:
    from subdomain_relationship_discovery_unified import (
        UnifiedSubdomainDiscoverer, 
        ProcessingConfig, 
        DiscoveryResult,
        ProviderInfo
    )
    HAS_DISCOVERY_ENGINE = True
except ImportError:
    HAS_DISCOVERY_ENGINE = False

 # Define dummy classes to prevent NameError
    class ProcessingConfig:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
    
    class DiscoveryResult:
        def __init__(self):
            self.domain = ""
            self.subdomains = []
            self.providers = []
            self.services = []
            self.certificates = []
            self.risks = []
            self.industry_classification = None
            self.processing_time = 0.0
            self.errors = []
            self.metadata = {}


# Import risk calculation functionality
try:
    from domain_risk_calculator import DomainRiskCalculator
    HAS_RISK_CALCULATOR = True
except ImportError:
    HAS_RISK_CALCULATOR = False

# Import statistics tracking functionality
try:
    from domain_statistics import (
        DomainStatisticsService, 
        TaskType, 
        TaskStatus, 
        track_task,
        DomainBase
    )
    HAS_STATISTICS = True
except ImportError:
    HAS_STATISTICS = False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Pydantic models for API documentation
class DiscoveryResponse(BaseModel):
    """Response model for discovery results"""
    domain: str
    subdomains: List[str]
    providers: List[Dict[str, Any]]
    services: List[Dict[str, Any]]
    certificates: List[Dict[str, Any]]
    risks: List[Dict[str, Any]]
    industry_classification: Optional[Dict[str, Any]]
    processing_time: float
    errors: List[str]
    metadata: Dict[str, Any] = {}

class DiscoveryStatus(BaseModel):
    """Status model for async discovery jobs"""
    job_id: str
    status: str  # pending, running, completed, failed
    domain: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    progress: int = 0  # 0-100
    result: Optional[DiscoveryResponse] = None
    error: Optional[str] = None

class ProviderResponse(BaseModel):
    """Response model for provider information"""
    name: str
    confidence: float
    source: str
    tld: Optional[str] = None
    country: Optional[str] = None
    metadata: Dict[str, Any] = {}
    risk_level: Optional[str] = None
    provider_type: Optional[str] = None

class ServiceResponse(BaseModel):
    """Response model for service information"""
    name: str
    service_type: str
    domain: str
    detection_method: str
    confidence: float
    metadata: Dict[str, Any] = {}

class RiskResponse(BaseModel):
    """Response model for risk information"""
    domain: str
    final_score: float
    tier: str
    base_tech_score: float
    third_party_score: float
    incident_impact_score: float
    context_boost_score: float
    calculation_details: Dict[str, Any] = {}
    calculated_at: datetime

class APIConfig(BaseModel):
    """Configuration for the API service"""
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_pass: str = "test.password"
    ipinfo_token: Optional[str] = None
    max_concurrent_jobs: int = 10
    job_timeout: int = 1800  # 30 minutes
    default_amass_timeout: int = 300
    default_max_subdomains: int = 1000
    default_workers: int = 10
    amass_cache_dir: str = "./amass_cache"
    amass_cache_duration_hours: int = 168  # 1 week default

# Global configuration
api_config = APIConfig()

# Statistics service instance
stats_service = None
if HAS_STATISTICS:
    stats_service = DomainStatisticsService()

# Job tracking for async operations
active_jobs: Dict[str, DiscoveryStatus] = {}

# FastAPI app instance
app = FastAPI(
    title="Subdomain Discovery API",
    description="REST API for comprehensive subdomain discovery and security analysis",
    version="6.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# App lifecycle events
@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    if stats_service:
        try:
            await stats_service.initialize()
            logger.info("Statistics service initialized")
        except Exception as e:
            logger.error(f"Failed to initialize statistics service: {e}")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    if stats_service:
        try:
            await stats_service.close()
            logger.info("Statistics service closed")
        except Exception as e:
            logger.error(f"Error closing statistics service: {e}")

# Utility functions
def create_processing_config(
    enable_amass: bool = True,
    enable_subdomain_enumeration: bool = True,
    enable_tls_analysis: bool = False,
    enable_service_detection: bool = False,
    enable_provider_detection: bool = False,
    enable_industry_classification: bool = False,
    enable_risk_calculation: bool = False,
    enable_mx_analysis: bool = False,
    amass_timeout: int = None,
    max_subdomains: int = None,
    max_workers: int = None,
    timeout_per_subdomain: int = 30,
    save_to_neo4j: bool = True,
    generate_report: bool = True
) -> ProcessingConfig:
    """Create processing configuration from parameters"""
    return ProcessingConfig(
        enable_amass=enable_amass,
        enable_subdomain_enumeration=enable_subdomain_enumeration,
        amass_timeout=amass_timeout or api_config.default_amass_timeout,
        max_subdomains=max_subdomains or api_config.default_max_subdomains,
        enable_tls_analysis=enable_tls_analysis,
        enable_service_detection=enable_service_detection,
        enable_provider_detection=enable_provider_detection,
        enable_industry_classification=enable_industry_classification,
        enable_risk_calculation=enable_risk_calculation,
        enable_mx_analysis=enable_mx_analysis,
        max_workers=max_workers or api_config.default_workers,
        timeout_per_subdomain=timeout_per_subdomain,
        save_to_neo4j=save_to_neo4j,
        generate_report=generate_report,
        amass_cache_dir=api_config.amass_cache_dir,
        amass_cache_duration_hours=api_config.amass_cache_duration_hours,
        enable_cache_check=True
    )

async def run_discovery_async(domain: str, config: ProcessingConfig, task_type: TaskType = TaskType.COMPLETE_DISCOVERY) -> DiscoveryResult:
    """Run discovery in a separate thread with statistics tracking"""
    if not HAS_DISCOVERY_ENGINE:
        raise HTTPException(status_code=500, detail="Discovery engine not available")
    
    # Determine domain properties for statistics
    tld = domain.split('.')[-1].lower()
    is_financial = False  # Will be updated after industry classification
    
    # Start statistics tracking if available
    if stats_service:
        try:
            async with track_task(
                stats_service=stats_service,
                domain_name=domain,
                task_type=task_type,
                timeout_configured=getattr(config, 'amass_timeout', None),
                max_subdomains_limit=getattr(config, 'max_subdomains', None),
                include_providers=getattr(config, 'enable_provider_detection', False),
                include_services=getattr(config, 'enable_service_detection', False),
                include_tls=getattr(config, 'enable_tls_analysis', False),
                include_risk=getattr(config, 'enable_risk_calculation', False),
                is_financial=is_financial,
                tld=tld
            ) as task_tracker:
                
                loop = asyncio.get_event_loop()
                
                def run_discovery():
                    discoverer = UnifiedSubdomainDiscoverer(
                        config=config,
                        neo4j_uri=api_config.neo4j_uri,
                        neo4j_user=api_config.neo4j_user,
                        neo4j_pass=api_config.neo4j_pass,
                        ipinfo_token=api_config.ipinfo_token
                    )
                    try:
                        result = discoverer.discover_and_analyze(domain)
                        return result
                    finally:
                        discoverer.close()
                
                result = await loop.run_in_executor(None, run_discovery)
                
                # Update statistics with results
                task_tracker.update_results(
                    subdomains_found=len(result.subdomains),
                    providers_found=len(result.providers),
                    services_found=len(result.services),
                    certificates_found=len(result.certificates),
                    risks_found=len(result.risks)
                )
                
                # Update performance metrics if available
                if hasattr(result, 'metadata') and result.metadata:
                    task_tracker.update_performance_metrics(
                        amass_timeout_occurred=result.metadata.get('amass_timeout_occurred', False),
                        dns_queries_count=result.metadata.get('dns_queries_count', 0),
                        network_requests_count=result.metadata.get('network_requests_count', 0),
                        neo4j_writes_count=result.metadata.get('neo4j_writes_count', 0)
                    )
                
                return result
                
        except Exception as e:
            logger.error(f"Statistics tracking failed for {domain}: {e}")
            # Continue without statistics if tracking fails
            pass
    
    # Fallback to original discovery without statistics
    loop = asyncio.get_event_loop()
    
    def run_discovery():
        discoverer = UnifiedSubdomainDiscoverer(
            config=config,
            neo4j_uri=api_config.neo4j_uri,
            neo4j_user=api_config.neo4j_user,
            neo4j_pass=api_config.neo4j_pass,
            ipinfo_token=api_config.ipinfo_token
        )
        try:
            result = discoverer.discover_and_analyze(domain)
            return result
        finally:
            discoverer.close()
    
    result = await loop.run_in_executor(None, run_discovery)
    return result

def discovery_result_to_response(result: DiscoveryResult) -> DiscoveryResponse:
    """Convert DiscoveryResult to API response model"""
    return DiscoveryResponse(
        domain=result.domain,
        subdomains=result.subdomains,
        providers=[
            {
                "name": p.name,
                "confidence": p.confidence,
                "source": p.source,
                "tld": p.tld,
                "country": p.country,
                "metadata": p.metadata,
                "risk_level": p.risk_level,
                "provider_type": p.provider_type
            } for p in result.providers
        ],
        services=result.services,
        certificates=result.certificates,
        risks=result.risks,
        industry_classification=result.industry_classification.__dict__ if result.industry_classification else None,
        processing_time=result.processing_time,
        errors=result.errors,
        metadata=result.metadata
    )

# Health and status endpoints
@app.get("/health", tags=["System"])
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "discovery_engine_available": HAS_DISCOVERY_ENGINE,
        "active_jobs": len(active_jobs)
    }

@app.get("/api/v1/status", tags=["System"])
async def api_status():
    """Get API status and configuration"""
    return {
        "version": "6.0.0",
        "discovery_engine": HAS_DISCOVERY_ENGINE,
        "statistics_service": HAS_STATISTICS,
        "active_jobs": len(active_jobs),
        "max_concurrent_jobs": api_config.max_concurrent_jobs,
        "default_config": {
            "amass_timeout": api_config.default_amass_timeout,
            "max_subdomains": api_config.default_max_subdomains,
            "workers": api_config.default_workers
        }
    }

# Basic Discovery Endpoints

@app.get("/api/v1/discovery/{domain}", 
         response_model=DiscoveryResponse,
         tags=["Discovery"],
         summary="Basic subdomain discovery",
         description="Perform basic subdomain enumeration using Amass only")
async def basic_discovery(
    domain: str = Path(..., description="Domain to analyze", example="example.com"),
    amass_timeout: int = Query(None, description="Amass timeout in seconds", ge=60, le=1800),
    max_subdomains: int = Query(None, description="Maximum subdomains to discover", ge=1, le=5000),
    max_workers: int = Query(None, description="Maximum worker threads", ge=1, le=50),
    save_to_neo4j: bool = Query(True, description="Save results to Neo4j"),
    timeout_per_subdomain: int = Query(30, description="Timeout per subdomain analysis", ge=5, le=300)
):
    """Basic subdomain discovery with Amass only"""
    config = create_processing_config(
        enable_amass=True,
        enable_subdomain_enumeration=True,
        amass_timeout=amass_timeout,
        max_subdomains=max_subdomains,
        max_workers=max_workers,
        timeout_per_subdomain=timeout_per_subdomain,
        save_to_neo4j=save_to_neo4j
    )
    
    try:
        result = await run_discovery_async(domain, config, TaskType.AMASS)
        return discovery_result_to_response(result)
    except Exception as e:
        logger.error(f"Discovery failed for {domain}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/discoveryWithProviders/{domain}",
         response_model=DiscoveryResponse,
         tags=["Discovery"],
         summary="Discovery with provider detection",
         description="Subdomain discovery with provider identification and MX analysis")
async def discovery_with_providers(
    domain: str = Path(..., description="Domain to analyze", example="example.com"),
    amass_timeout: int = Query(None, description="Amass timeout in seconds", ge=60, le=1800),
    max_subdomains: int = Query(None, description="Maximum subdomains to discover", ge=1, le=5000),
    max_workers: int = Query(None, description="Maximum worker threads", ge=1, le=50),
    save_to_neo4j: bool = Query(True, description="Save results to Neo4j"),
    timeout_per_subdomain: int = Query(30, description="Timeout per subdomain analysis", ge=5, le=300)
):
    """Discovery with provider detection and MX analysis"""
    config = create_processing_config(
        enable_amass=True,
        enable_subdomain_enumeration=True,
        enable_provider_detection=True,
        enable_mx_analysis=True,
        amass_timeout=amass_timeout,
        max_subdomains=max_subdomains,
        max_workers=max_workers,
        timeout_per_subdomain=timeout_per_subdomain,
        save_to_neo4j=save_to_neo4j
    )
    
    try:
        result = await run_discovery_async(domain, config)
        return discovery_result_to_response(result)
    except Exception as e:
        logger.error(f"Discovery with providers failed for {domain}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/discoveryWithServices/{domain}",
         response_model=DiscoveryResponse,
         tags=["Discovery"],
         summary="Discovery with service detection",
         description="Subdomain discovery with service identification and port scanning")
async def discovery_with_services(
    domain: str = Path(..., description="Domain to analyze", example="example.com"),
    amass_timeout: int = Query(None, description="Amass timeout in seconds", ge=60, le=1800),
    max_subdomains: int = Query(None, description="Maximum subdomains to discover", ge=1, le=5000),
    max_workers: int = Query(None, description="Maximum worker threads", ge=1, le=50),
    save_to_neo4j: bool = Query(True, description="Save results to Neo4j"),
    timeout_per_subdomain: int = Query(60, description="Timeout per subdomain analysis", ge=5, le=300)
):
    """Discovery with service detection"""
    config = create_processing_config(
        enable_amass=True,
        enable_subdomain_enumeration=True,
        enable_service_detection=True,
        amass_timeout=amass_timeout,
        max_subdomains=max_subdomains,
        max_workers=max_workers,
        timeout_per_subdomain=timeout_per_subdomain,
        save_to_neo4j=save_to_neo4j
    )
    
    try:
        result = await run_discovery_async(domain, config)
        return discovery_result_to_response(result)
    except Exception as e:
        logger.error(f"Discovery with services failed for {domain}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/discoveryWithServicesAndProviders/{domain}",
         response_model=DiscoveryResponse,
         tags=["Discovery"],
         summary="Discovery with services and providers",
         description="Comprehensive discovery with both service and provider detection")
async def discovery_with_services_and_providers(
    domain: str = Path(..., description="Domain to analyze", example="example.com"),
    amass_timeout: int = Query(None, description="Amass timeout in seconds", ge=60, le=1800),
    max_subdomains: int = Query(None, description="Maximum subdomains to discover", ge=1, le=5000),
    max_workers: int = Query(None, description="Maximum worker threads", ge=1, le=50),
    save_to_neo4j: bool = Query(True, description="Save results to Neo4j"),
    timeout_per_subdomain: int = Query(60, description="Timeout per subdomain analysis", ge=5, le=300)
):
    """Discovery with both service and provider detection"""
    config = create_processing_config(
        enable_amass=True,
        enable_subdomain_enumeration=True,
        enable_service_detection=True,
        enable_provider_detection=True,
        enable_mx_analysis=True,
        amass_timeout=amass_timeout,
        max_subdomains=max_subdomains,
        max_workers=max_workers,
        timeout_per_subdomain=timeout_per_subdomain,
        save_to_neo4j=save_to_neo4j
    )
    
    try:
        result = await run_discovery_async(domain, config)
        return discovery_result_to_response(result)
    except Exception as e:
        logger.error(f"Discovery with services and providers failed for {domain}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/discoveryWithTLS/{domain}",
         response_model=DiscoveryResponse,
         tags=["Discovery"],
         summary="Discovery with TLS analysis",
         description="Discovery with comprehensive TLS certificate analysis")
async def discovery_with_tls(
    domain: str = Path(..., description="Domain to analyze", example="example.com"),
    amass_timeout: int = Query(None, description="Amass timeout in seconds", ge=60, le=1800),
    max_subdomains: int = Query(None, description="Maximum subdomains to discover", ge=1, le=5000),
    max_workers: int = Query(None, description="Maximum worker threads", ge=1, le=50),
    save_to_neo4j: bool = Query(True, description="Save results to Neo4j"),
    timeout_per_subdomain: int = Query(60, description="Timeout per subdomain analysis", ge=5, le=300)
):
    """Discovery with TLS certificate analysis"""
    config = create_processing_config(
        enable_amass=True,
        enable_subdomain_enumeration=True,
        enable_tls_analysis=True,
        amass_timeout=amass_timeout,
        max_subdomains=max_subdomains,
        max_workers=max_workers,
        timeout_per_subdomain=timeout_per_subdomain,
        save_to_neo4j=save_to_neo4j
    )
    
    try:
        result = await run_discovery_async(domain, config)
        return discovery_result_to_response(result)
    except Exception as e:
        logger.error(f"Discovery with TLS failed for {domain}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/discoveryWithRisk/{domain}",
         response_model=DiscoveryResponse,
         tags=["Discovery"],
         summary="Discovery with risk analysis",
         description="Discovery with comprehensive security risk assessment")
async def discovery_with_risk(
    domain: str = Path(..., description="Domain to analyze", example="example.com"),
    amass_timeout: int = Query(None, description="Amass timeout in seconds", ge=60, le=1800),
    max_subdomains: int = Query(None, description="Maximum subdomains to discover", ge=1, le=5000),
    max_workers: int = Query(None, description="Maximum worker threads", ge=1, le=50),
    save_to_neo4j: bool = Query(True, description="Save results to Neo4j"),
    timeout_per_subdomain: int = Query(60, description="Timeout per subdomain analysis", ge=5, le=300)
):
    """Discovery with risk analysis"""
    config = create_processing_config(
        enable_amass=True,
        enable_subdomain_enumeration=True,
        enable_risk_calculation=True,
        enable_provider_detection=True,  # Risk analysis needs provider info
        enable_mx_analysis=True,
        amass_timeout=amass_timeout,
        max_subdomains=max_subdomains,
        max_workers=max_workers,
        timeout_per_subdomain=timeout_per_subdomain,
        save_to_neo4j=save_to_neo4j
    )
    
    try:
        result = await run_discovery_async(domain, config)
        return discovery_result_to_response(result)
    except Exception as e:
        logger.error(f"Discovery with risk failed for {domain}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/discoveryComplete/{domain}",
         response_model=DiscoveryResponse,
         tags=["Discovery"],
         summary="Complete discovery analysis",
         description="Full comprehensive analysis with all features enabled")
async def discovery_complete(
    domain: str = Path(..., description="Domain to analyze", example="example.com"),
    amass_timeout: int = Query(None, description="Amass timeout in seconds", ge=60, le=1800),
    max_subdomains: int = Query(None, description="Maximum subdomains to discover", ge=1, le=5000),
    max_workers: int = Query(None, description="Maximum worker threads", ge=1, le=50),
    save_to_neo4j: bool = Query(True, description="Save results to Neo4j"),
    timeout_per_subdomain: int = Query(90, description="Timeout per subdomain analysis", ge=5, le=300)
):
    """Complete discovery with all features enabled"""
    config = create_processing_config(
        enable_amass=True,
        enable_subdomain_enumeration=True,
        enable_tls_analysis=True,
        enable_service_detection=True,
        enable_provider_detection=True,
        enable_industry_classification=True,
        enable_risk_calculation=True,
        enable_mx_analysis=True,
        amass_timeout=amass_timeout,
        max_subdomains=max_subdomains,
        max_workers=max_workers,
        timeout_per_subdomain=timeout_per_subdomain,
        save_to_neo4j=save_to_neo4j
    )
    
    try:
        result = await run_discovery_async(domain, config, TaskType.COMPLETE_DISCOVERY)
        return discovery_result_to_response(result)
    except Exception as e:
        logger.error(f"Complete discovery failed for {domain}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Async Job Management Endpoints

@app.post("/api/v1/jobs/discovery/{domain}",
          response_model=Dict[str, str],
          tags=["Async Jobs"],
          summary="Start async discovery job",
          description="Start an asynchronous discovery job and return job ID")
async def start_discovery_job(
    domain: str,
    background_tasks: BackgroundTasks,
    enable_providers: bool = Query(False, description="Enable provider detection"),
    enable_services: bool = Query(False, description="Enable service detection"),
    enable_tls: bool = Query(False, description="Enable TLS analysis"),
    enable_risk: bool = Query(False, description="Enable risk analysis"),
    enable_industry: bool = Query(False, description="Enable industry classification"),
    enable_mx: bool = Query(False, description="Enable MX analysis"),
    amass_timeout: int = Query(None, description="Amass timeout in seconds", ge=60, le=1800),
    max_subdomains: int = Query(None, description="Maximum subdomains to discover", ge=1, le=5000),
    max_workers: int = Query(None, description="Maximum worker threads", ge=1, le=50),
    save_to_neo4j: bool = Query(True, description="Save results to Neo4j")
):
    """Start an asynchronous discovery job"""
    if len(active_jobs) >= api_config.max_concurrent_jobs:
        raise HTTPException(status_code=429, detail="Too many concurrent jobs")
    
    import uuid
    job_id = str(uuid.uuid4())
    
    # Create job status
    job_status = DiscoveryStatus(
        job_id=job_id,
        status="pending",
        domain=domain,
        started_at=datetime.now()
    )
    active_jobs[job_id] = job_status
    
    # Create configuration
    config = create_processing_config(
        enable_amass=True,
        enable_subdomain_enumeration=True,
        enable_provider_detection=enable_providers,
        enable_service_detection=enable_services,
        enable_tls_analysis=enable_tls,
        enable_risk_calculation=enable_risk,
        enable_industry_classification=enable_industry,
        enable_mx_analysis=enable_mx,
        amass_timeout=amass_timeout,
        max_subdomains=max_subdomains,
        max_workers=max_workers,
        save_to_neo4j=save_to_neo4j
    )
    
    # Start background task
    background_tasks.add_task(run_discovery_job, job_id, domain, config)
    
    return {"job_id": job_id, "status": "started", "domain": domain}

async def run_discovery_job(job_id: str, domain: str, config: ProcessingConfig):
    """Run discovery job in background"""
    try:
        # Update status
        active_jobs[job_id].status = "running"
        active_jobs[job_id].progress = 10
        
        # Run discovery
        result = await run_discovery_async(domain, config)
        
        # Update status with results
        active_jobs[job_id].status = "completed"
        active_jobs[job_id].progress = 100
        active_jobs[job_id].completed_at = datetime.now()
        active_jobs[job_id].result = discovery_result_to_response(result)
        
    except Exception as e:
        # Update status with error
        active_jobs[job_id].status = "failed"
        active_jobs[job_id].error = str(e)
        active_jobs[job_id].completed_at = datetime.now()
        logger.error(f"Job {job_id} failed: {e}")

@app.get("/api/v1/jobs/{job_id}",
         response_model=DiscoveryStatus,
         tags=["Async Jobs"],
         summary="Get job status",
         description="Get the status and results of an async discovery job")
async def get_job_status(job_id: str = Path(..., description="Job ID")):
    """Get job status and results"""
    if job_id not in active_jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    
    return active_jobs[job_id]

@app.get("/api/v1/jobs",
         tags=["Async Jobs"],
         summary="List all jobs",
         description="List all active and completed jobs")
async def list_jobs(limit: int = Query(50, description="Maximum number of jobs to return", ge=1, le=200)):
    """List all jobs"""
    jobs = list(active_jobs.values())
    jobs.sort(key=lambda j: j.started_at, reverse=True)
    return {"jobs": jobs[:limit], "total": len(jobs)}

@app.delete("/api/v1/jobs/{job_id}",
           tags=["Async Jobs"],
           summary="Delete job",
           description="Delete a completed or failed job")
async def delete_job(job_id: str = Path(..., description="Job ID")):
    """Delete a job"""
    if job_id not in active_jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    
    job = active_jobs[job_id]
    if job.status == "running":
        raise HTTPException(status_code=400, detail="Cannot delete running job")
    
    del active_jobs[job_id]
    return {"message": "Job deleted successfully"}

# Specialized Analysis Endpoints

@app.get("/api/v1/analysis/providers/{domain}",
         tags=["Analysis"],
         summary="Provider analysis only",
         description="Analyze providers without full subdomain discovery")
async def analyze_providers_only(
    domain: str = Path(..., description="Domain to analyze", example="example.com"),
    include_mx: bool = Query(True, description="Include MX record analysis"),
    timeout: int = Query(60, description="Analysis timeout in seconds", ge=10, le=300)
):
    """Analyze providers for a domain without full discovery"""
    config = create_processing_config(
        enable_amass=False,
        enable_subdomain_enumeration=False,
        enable_provider_detection=True,
        enable_mx_analysis=include_mx,
        timeout_per_subdomain=timeout,
        save_to_neo4j=False
    )
    
    try:
        result = await run_discovery_async(domain, config)
        return {
            "domain": domain,
            "providers": [
                {
                    "name": p.name,
                    "confidence": p.confidence,
                    "source": p.source,
                    "country": p.country,
                    "provider_type": p.provider_type
                } for p in result.providers
            ],
            "processing_time": result.processing_time
        }
    except Exception as e:
        logger.error(f"Provider analysis failed for {domain}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/analysis/services/{domain}",
         tags=["Analysis"],
         summary="Service analysis only",
         description="Analyze services without full subdomain discovery")
async def analyze_services_only(
    domain: str = Path(..., description="Domain to analyze", example="example.com"),
    include_port_scan: bool = Query(False, description="Include port scanning"),
    timeout: int = Query(60, description="Analysis timeout in seconds", ge=10, le=300)
):
    """Analyze services for a domain without full discovery"""
    config = create_processing_config(
        enable_amass=False,
        enable_subdomain_enumeration=False,
        enable_service_detection=True,
        timeout_per_subdomain=timeout,
        save_to_neo4j=False
    )
    
    try:
        result = await run_discovery_async(domain, config)
        return {
            "domain": domain,
            "services": result.services,
            "processing_time": result.processing_time
        }
    except Exception as e:
        logger.error(f"Service analysis failed for {domain}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/analysis/tls/{domain}",
         tags=["Analysis"],
         summary="TLS analysis only",
         description="Analyze TLS certificates without full subdomain discovery")
async def analyze_tls_only(
    domain: str = Path(..., description="Domain to analyze", example="example.com"),
    timeout: int = Query(30, description="Analysis timeout in seconds", ge=5, le=120)
):
    """Analyze TLS certificates for a domain without full discovery"""
    config = create_processing_config(
        enable_amass=False,
        enable_subdomain_enumeration=False,
        enable_tls_analysis=True,
        timeout_per_subdomain=timeout,
        save_to_neo4j=False
    )
    
    try:
        result = await run_discovery_async(domain, config)
        return {
            "domain": domain,
            "certificates": result.certificates,
            "processing_time": result.processing_time
        }
    except Exception as e:
        logger.error(f"TLS analysis failed for {domain}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/analysis/risk/{domain}",
         response_model=RiskResponse,
         tags=["Analysis"],
         summary="Risk analysis only",
         description="Calculate security risk score according to Risk.md definitions")
async def analyze_risk_only(
    domain: str = Path(..., description="Domain to analyze", example="example.com"),
    timeout: int = Query(60, description="Analysis timeout in seconds", ge=10, le=300),
    update_neo4j: bool = Query(True, description="Update risk scores in Neo4j database")
):
    """Calculate security risk score for a domain according to Risk.md specifications"""
    if not HAS_RISK_CALCULATOR:
        raise HTTPException(status_code=500, detail="Risk calculator not available")
    
    try:
        # Initialize risk calculator
        risk_calculator = DomainRiskCalculator(
            neo4j_uri=api_config.neo4j_uri,
            neo4j_user=api_config.neo4j_user,
            neo4j_pass=api_config.neo4j_pass
        )
        
        # Calculate risk scores
        start_time = time.time()
        risk_components = risk_calculator.calculate_domain_risks(domain)
        processing_time = time.time() - start_time
        
        # Update Neo4j if requested
        if update_neo4j:
            risk_calculator.update_domain_risk_score(domain, risk_components)
        
        return RiskResponse(
            domain=domain,
            final_score=risk_components.final_score,
            tier=risk_components.tier,
            base_tech_score=risk_components.base_tech_score,
            third_party_score=risk_components.third_party_score,
            incident_impact_score=risk_components.incident_impact_score,
            context_boost_score=risk_components.context_boost_score,
            calculation_details={
                "base_tech_details": risk_components.base_tech_details,
                "third_party_details": risk_components.third_party_details,
                "incident_details": risk_components.incident_details,
                "context_details": risk_components.context_details,
                "processing_time": processing_time
            },
            calculated_at=datetime.now()
        )
        
    except Exception as e:
        logger.error(f"Risk analysis failed for {domain}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Configuration and admin endpoints

@app.post("/api/v1/config", tags=["Admin"])
async def update_config(
    neo4j_uri: Optional[str] = None,
    neo4j_user: Optional[str] = None,
    neo4j_pass: Optional[str] = None,
    ipinfo_token: Optional[str] = None,
    max_concurrent_jobs: Optional[int] = None,
    default_amass_timeout: Optional[int] = None,
    default_max_subdomains: Optional[int] = None,
    amass_cache_dir: Optional[str] = None,
    amass_cache_duration_hours: Optional[int] = None
):
    """Update API configuration"""
    global api_config
    
    if neo4j_uri:
        api_config.neo4j_uri = neo4j_uri
    if neo4j_user:
        api_config.neo4j_user = neo4j_user
    if neo4j_pass:
        api_config.neo4j_pass = neo4j_pass
    if ipinfo_token:
        api_config.ipinfo_token = ipinfo_token
    if max_concurrent_jobs:
        api_config.max_concurrent_jobs = max_concurrent_jobs
    if default_amass_timeout:
        api_config.default_amass_timeout = default_amass_timeout
    if default_max_subdomains:
        api_config.default_max_subdomains = default_max_subdomains
    if amass_cache_dir:
        api_config.amass_cache_dir = amass_cache_dir
    if amass_cache_duration_hours:
        api_config.amass_cache_duration_hours = amass_cache_duration_hours
    
    return {"message": "Configuration updated successfully"}

@app.get("/api/v1/config", tags=["Admin"])
async def get_config():
    """Get current API configuration (excluding sensitive data)"""
    return {
        "neo4j_uri": api_config.neo4j_uri,
        "neo4j_user": api_config.neo4j_user,
        "max_concurrent_jobs": api_config.max_concurrent_jobs,
        "default_amass_timeout": api_config.default_amass_timeout,
        "default_max_subdomains": api_config.default_max_subdomains,
        "default_workers": api_config.default_workers,
        "amass_cache_dir": api_config.amass_cache_dir,
        "amass_cache_duration_hours": api_config.amass_cache_duration_hours,
        "ipinfo_configured": bool(api_config.ipinfo_token)
    }

# Cache management endpoints

@app.get("/api/v1/cache/stats", tags=["Cache Management"])
async def get_cache_stats():
    """Get cache statistics"""
    try:
        cache_stats_file = Path(api_config.amass_cache_dir) / "cache_stats.json"
        if cache_stats_file.exists():
            with open(cache_stats_file, 'r') as f:
                stats = json.load(f)
            return stats
        else:
            return {
                "hits": 0,
                "misses": 0,
                "evictions": 0,
                "total_domains_cached": 0,
                "message": "Cache stats file not found"
            }
    except Exception as e:
        logger.error(f"Failed to get cache stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/v1/cache/clear", tags=["Cache Management"])
async def clear_cache():
    """Clear all cache entries"""
    try:
        cache_dir = Path(api_config.amass_cache_dir)
        metadata_dir = cache_dir / "metadata"
        data_dir = cache_dir / "data"
        
        cleared_count = 0
        
        # Clear metadata files
        if metadata_dir.exists():
            for file in metadata_dir.glob("*.json"):
                file.unlink()
                cleared_count += 1
        
        # Clear data files
        if data_dir.exists():
            for file in data_dir.glob("*.json.gz"):
                file.unlink()
        
        # Reset cache stats
        cache_stats_file = cache_dir / "cache_stats.json"
        with open(cache_stats_file, 'w') as f:
            json.dump({
                "hits": 0,
                "misses": 0,
                "evictions": 0,
                "total_domains_cached": 0
            }, f)
        
        return {
            "message": f"Cache cleared successfully",
            "entries_removed": cleared_count
        }
    except Exception as e:
        logger.error(f"Failed to clear cache: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/v1/cache/{domain}", tags=["Cache Management"])
async def clear_domain_cache(domain: str = Path(..., description="Domain to clear from cache")):
    """Clear cache for a specific domain"""
    try:
        from subdomain_relationship_discovery_unified import UnifiedSubdomainDiscoverer
        import hashlib
        
        # Generate hash for domain
        hash_key = hashlib.sha256(domain.encode()).hexdigest()[:16]
        
        cache_dir = Path(api_config.amass_cache_dir)
        metadata_file = cache_dir / "metadata" / f"{hash_key}.json"
        data_file = cache_dir / "data" / f"{hash_key}.json.gz"
        
        removed_files = []
        if metadata_file.exists():
            metadata_file.unlink()
            removed_files.append("metadata")
        if data_file.exists():
            data_file.unlink()
            removed_files.append("data")
        
        if removed_files:
            return {
                "message": f"Cache cleared for domain {domain}",
                "files_removed": removed_files
            }
        else:
            return {
                "message": f"No cache found for domain {domain}"
            }
    except Exception as e:
        logger.error(f"Failed to clear cache for {domain}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/cache/cleanup", tags=["Cache Management"])
async def cleanup_expired_cache():
    """Clean up expired cache entries"""
    try:
        # Use the standalone script's cleanup functionality
        standalone_script = Path(api_config.amass_cache_dir).parent / "standalone_amass_executor.sh"
        
        if standalone_script.exists():
            env = {
                **dict(os.environ),
                'AMASS_CACHE_DIR': api_config.amass_cache_dir,
                'CACHE_DURATION_HOURS': str(api_config.amass_cache_duration_hours)
            }
            
            # Run the script with a dummy domain just to trigger cleanup
            result = subprocess.run(
                [str(standalone_script), "--help"],
                capture_output=True,
                text=True,
                env=env
            )
        
        # Manual cleanup implementation
        cache_dir = Path(api_config.amass_cache_dir)
        metadata_dir = cache_dir / "metadata"
        data_dir = cache_dir / "data"
        
        cleaned_count = 0
        current_time = datetime.now()
        max_age = timedelta(hours=api_config.amass_cache_duration_hours)
        
        if metadata_dir.exists():
            for metadata_file in metadata_dir.glob("*.json"):
                try:
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)
                    
                    timestamp_str = metadata.get('timestamp', '')
                    if timestamp_str:
                        cache_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        cache_age = current_time - cache_time
                        
                        if cache_age > max_age:
                            # Remove both metadata and data files
                            hash_key = metadata_file.stem
                            data_file = data_dir / f"{hash_key}.json.gz"
                            
                            metadata_file.unlink()
                            if data_file.exists():
                                data_file.unlink()
                            cleaned_count += 1
                except Exception as e:
                    logger.debug(f"Failed to process cache file {metadata_file}: {e}")
        
        return {
            "message": f"Cache cleanup completed",
            "expired_entries_removed": cleaned_count
        }
    except Exception as e:
        logger.error(f"Failed to cleanup cache: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "timestamp": datetime.now().isoformat(),
            "path": str(request.url)
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "timestamp": datetime.now().isoformat(),
            "path": str(request.url)
        }
    )

# Statistics and Time Estimation Endpoints

@app.get("/api/v1/estimate/{domain}",
         tags=["Statistics"],
         summary="Estimate task duration",
         description="Get time estimation for domain analysis based on historical data")
async def estimate_task_duration(
    domain: str = Path(..., description="Domain to estimate", example="example.com"),
    task_type: str = Query("complete_discovery", description="Task type to estimate"),
    confidence_level: float = Query(0.9, description="Confidence level (0.0-1.0)", ge=0.0, le=1.0)
):
    """Estimate how long a domain analysis task will take"""
    if not stats_service:
        raise HTTPException(status_code=503, detail="Statistics service not available")
    
    try:
        # Map string task type to enum
        task_type_map = {
            "amass": TaskType.AMASS,
            "dns_analysis": TaskType.DNS_ANALYSIS,
            "tls_scan": TaskType.TLS_SCAN,
            "provider_detection": TaskType.PROVIDER_DETECTION,
            "risk_calculation": TaskType.RISK_CALCULATION,
            "complete_discovery": TaskType.COMPLETE_DISCOVERY
        }
        
        if task_type not in task_type_map:
            raise HTTPException(status_code=400, detail=f"Invalid task type: {task_type}")
        
        estimation = await stats_service.estimate_task_duration(
            domain_name=domain,
            task_type=task_type_map[task_type],
            confidence_level=confidence_level
        )
        
        return {
            "domain": domain,
            "task_type": task_type,
            "estimation": estimation,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Time estimation failed for {domain}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/statistics/{domain}",
         tags=["Statistics"],
         summary="Get domain execution statistics",
         description="Get historical execution statistics for a domain")
async def get_domain_statistics(
    domain: str = Path(..., description="Domain to get statistics for", example="example.com")
):
    """Get execution statistics for a specific domain"""
    if not stats_service:
        raise HTTPException(status_code=503, detail="Statistics service not available")
    
    try:
        stats = await stats_service.get_domain_execution_stats(domain_name=domain)
        
        return {
            "domain": domain,
            "statistics": stats,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get statistics for {domain}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/statistics",
         tags=["Statistics"],
         summary="Get all execution statistics",
         description="Get historical execution statistics for all domains")
async def get_all_statistics():
    """Get execution statistics for all domains"""
    if not stats_service:
        raise HTTPException(status_code=503, detail="Statistics service not available")
    
    try:
        stats = await stats_service.get_domain_execution_stats()
        
        return {
            "statistics": stats,
            "total_domains": len(set(stat["domain_name"] for stat in stats)),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get all statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/statistics/summary",
         tags=["Statistics"],
         summary="Get statistics summary",
         description="Get aggregated statistics summary for dashboard")
async def get_statistics_summary():
    """Get aggregated statistics summary"""
    if not stats_service:
        return {
            "available": False,
            "message": "Statistics service not available"
        }
    
    try:
        # Get all statistics
        stats = await stats_service.get_domain_execution_stats()
        
        if not stats:
            return {
                "available": True,
                "total_domains": 0,
                "total_executions": 0,
                "avg_processing_time": 0,
                "success_rate": 0,
                "most_analyzed_tlds": [],
                "recent_activity": [],
                "timestamp": datetime.now().isoformat()
            }
        
        # Calculate summary statistics
        total_domains = len(set(stat["domain_name"] for stat in stats))
        total_executions = sum(stat["total_executions"] for stat in stats)
        successful_executions = sum(stat["successful_executions"] for stat in stats)
        
        # Calculate average processing time (weighted by executions)
        total_time = sum(stat["avg_duration_seconds"] * stat["total_executions"] 
                        for stat in stats if stat["avg_duration_seconds"])
        avg_processing_time = total_time / total_executions if total_executions > 0 else 0
        
        # Calculate success rate
        success_rate = (successful_executions / total_executions * 100) if total_executions > 0 else 0
        
        # Get TLD distribution
        tld_stats = {}
        for stat in stats:
            tld = stat["tld"]
            if tld not in tld_stats:
                tld_stats[tld] = {"count": 0, "domains": set()}
            tld_stats[tld]["count"] += stat["total_executions"]
            tld_stats[tld]["domains"].add(stat["domain_name"])
        
        most_analyzed_tlds = sorted(
            [{"tld": tld, "executions": data["count"], "unique_domains": len(data["domains"])} 
             for tld, data in tld_stats.items()],
            key=lambda x: x["executions"],
            reverse=True
        )[:5]
        
        # Get recent activity (last executions)
        recent_activity = sorted(
            [{"domain": stat["domain_name"], 
              "task_type": stat["task_type"],
              "last_execution": stat["last_execution"],
              "success_rate": stat["successful_executions"] / stat["total_executions"] * 100 if stat["total_executions"] > 0 else 0}
             for stat in stats if stat["last_execution"]],
            key=lambda x: x["last_execution"],
            reverse=True
        )[:10]
        
        return {
            "available": True,
            "total_domains": total_domains,
            "total_executions": total_executions,
            "avg_processing_time": round(avg_processing_time, 2),
            "success_rate": round(success_rate, 2),
            "most_analyzed_tlds": most_analyzed_tlds,
            "recent_activity": recent_activity,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get statistics summary: {e}")
        return {
            "available": False,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

@app.get("/api/v1/domains/{domain}/performance",
         tags=["Statistics"],
         summary="Get domain performance metrics",
         description="Get detailed performance metrics for a specific domain")
async def get_domain_performance(
    domain: str = Path(..., description="Domain to get performance for", example="example.com")
):
    """Get detailed performance metrics for a domain"""
    if not stats_service:
        return {
            "available": False,
            "message": "Statistics service not available"
        }
    
    try:
        # Get domain statistics
        stats = await stats_service.get_domain_execution_stats(domain_name=domain)
        
        if not stats:
            return {
                "available": True,
                "domain": domain,
                "has_data": False,
                "message": "No performance data available for this domain"
            }
        
        # Calculate performance metrics
        total_executions = sum(stat["total_executions"] for stat in stats)
        successful_executions = sum(stat["successful_executions"] for stat in stats)
        failed_executions = sum(stat["failed_executions"] for stat in stats)
        timeout_executions = sum(stat["timeout_executions"] for stat in stats)
        
        # Get task type breakdown
        task_breakdown = []
        for stat in stats:
            task_breakdown.append({
                "task_type": stat["task_type"],
                "total_executions": stat["total_executions"],
                "success_rate": stat["successful_executions"] / stat["total_executions"] * 100 if stat["total_executions"] > 0 else 0,
                "avg_duration": stat["avg_duration_seconds"],
                "median_duration": stat["median_duration_seconds"],
                "p95_duration": stat["p95_duration_seconds"],
                "avg_subdomains_found": stat["avg_subdomains_found"],
                "avg_providers_found": stat["avg_providers_found"],
                "last_execution": stat["last_execution"]
            })
        
        # Get time estimations for different task types
        estimations = {}
        task_types = ["amass", "complete_discovery", "provider_detection", "tls_scan"]
        
        for task_type in task_types:
            try:
                task_type_enum = {
                    "amass": TaskType.AMASS,
                    "complete_discovery": TaskType.COMPLETE_DISCOVERY,
                    "provider_detection": TaskType.PROVIDER_DETECTION,
                    "tls_scan": TaskType.TLS_SCAN
                }.get(task_type)
                
                if task_type_enum:
                    estimation = await stats_service.estimate_task_duration(
                        domain_name=domain,
                        task_type=task_type_enum,
                        confidence_level=0.9
                    )
                    estimations[task_type] = estimation
            except Exception as e:
                logger.warning(f"Failed to get estimation for {task_type}: {e}")
        
        return {
            "available": True,
            "domain": domain,
            "has_data": True,
            "summary": {
                "total_executions": total_executions,
                "successful_executions": successful_executions,
                "failed_executions": failed_executions,
                "timeout_executions": timeout_executions,
                "success_rate": successful_executions / total_executions * 100 if total_executions > 0 else 0
            },
            "task_breakdown": task_breakdown,
            "time_estimations": estimations,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get domain performance for {domain}: {e}")
        return {
            "available": False,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    logger.info("Subdomain Discovery API starting up...")
    logger.info(f"Discovery engine available: {HAS_DISCOVERY_ENGINE}")
    logger.info(f"Max concurrent jobs: {api_config.max_concurrent_jobs}")

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Subdomain Discovery API shutting down...")
    # Clean up any remaining jobs
    active_jobs.clear()

if __name__ == "__main__":
    import os
    
    # Configuration from environment variables
    if os.getenv("NEO4J_URI"):
        api_config.neo4j_uri = os.getenv("NEO4J_URI")
    if os.getenv("NEO4J_USER"):
        api_config.neo4j_user = os.getenv("NEO4J_USER")
    if os.getenv("NEO4J_PASS"):
        api_config.neo4j_pass = os.getenv("NEO4J_PASS")
    if os.getenv("IPINFO_TOKEN"):
        api_config.ipinfo_token = os.getenv("IPINFO_TOKEN")
    
    # Run the server
    uvicorn.run(
        "subdomain_discovery_api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )