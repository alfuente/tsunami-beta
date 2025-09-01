"""
Task models for Risk Analysis async system
"""

from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from enum import Enum
import json

class RiskTaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"

class RiskTaskType(str, Enum):
    ACCS_ANALYSIS = "accs_analysis"
    ACP_ANALYSIS = "acp_analysis"
    APR_ANALYSIS = "apr_analysis"
    AECS_ANALYSIS = "aecs_analysis"
    AEPC_ANALYSIS = "aepc_analysis"
    APRN_ANALYSIS = "aprn_analysis"
    BATCH_RISK_CALCULATION = "batch_risk_calculation"
    PROPAGATION_SIMULATION = "propagation_simulation"

class RiskTaskInfo(BaseModel):
    task_id: str
    task_type: RiskTaskType
    parameters: Dict[str, Any] = Field(default_factory=dict)
    status: RiskTaskStatus = RiskTaskStatus.PENDING
    created_at: datetime = Field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    progress: int = 0
    logs: str = ""
    error: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    execution_time: Optional[float] = None

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class RiskTaskRequest(BaseModel):
    """Base request model for risk analysis tasks"""
    task_type: RiskTaskType
    parameters: Dict[str, Any] = Field(default_factory=dict)

class ACCSTaskRequest(BaseModel):
    """Request for ACCS algorithm task"""
    node_types: Optional[List[str]] = ["Organization", "Domain"]
    sectors: Optional[List[str]] = None
    include_critical_bonus: bool = True

class ACPTaskRequest(BaseModel):
    """Request for ACP algorithm task"""
    provider_types: Optional[List[str]] = ["Provider"]
    include_hhi_modified: bool = True

class APRTaskRequest(BaseModel):
    """Request for APR algorithm task"""
    initial_node: str
    max_time: int = 50
    base_contagion_rate: float = 0.1
    incubation_rate: float = 0.3
    recovery_rate: float = 0.05

class AECSTaskRequest(BaseModel):
    """Request for AECS algorithm task"""
    target_organization: str
    max_levels: int = 5
    include_transitives: bool = True

class AEPCTaskRequest(BaseModel):
    """Request for AEPC algorithm task"""
    provider_ids: Optional[List[str]] = None
    include_iisp: bool = True

class APRNTaskRequest(BaseModel):
    """Request for APRN algorithm task"""
    entity_ids: Optional[List[str]] = None
    include_national_security: bool = True

class BatchRiskTaskRequest(BaseModel):
    """Request for batch risk calculation task"""
    node_ids: Optional[List[str]] = None
    node_types: Optional[List[str]] = None
    sectors: Optional[List[str]] = None
    save_to_neo4j: bool = True

class PropagationSimulationTaskRequest(BaseModel):
    """Request for propagation simulation task"""
    initial_node: str
    max_time: int = 50
    node_types: Optional[List[str]] = None