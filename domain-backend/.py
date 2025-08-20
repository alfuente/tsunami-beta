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

from fastapi import FastAPI, HTTPException, Query, Path, BackgroundTasks
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import asyncio
import uvicorn
import logging
import time
from datetime import datetime
import json

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

# Import risk calculation functionality
try:
    from risk_score_updater import RiskScoreUpdater, RiskScoreComponents
    HAS_RISK_CALCULATOR = True
except ImportError:
    HAS_RISK_CALCULATOR = False

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

# Global configuration
api_config = APIConfig()

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
        generate_report=generate_report
    )

async def run_discovery_async(domain: str, config: ProcessingConfig) -> DiscoveryResult:
    """Run discovery in a separate thread"""
    if not HAS_DISCOVERY_ENGINE:
        raise HTTPException(status_code=500, detail="Discovery engine not available")
    
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
        industry_classification=result.industry_classification,
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
        result = await run_discovery_async(domain, config)
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
        result = await run_discovery_async(domain, config)
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
    domain: str = Path(..., description="Domain to analyze", example="example.com"),
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
        risk_calculator = RiskScoreUpdater(
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
    default_max_subdomains: Optional[int] = None
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
        "ipinfo_configured": bool(api_config.ipinfo_token)
    }

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