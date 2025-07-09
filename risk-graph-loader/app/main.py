from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel, Field
from uuid import uuid4
import asyncio, datetime, subprocess, os, json, shutil, pathlib

from typing import List, Dict, Literal, Optional

app = FastAPI(title="Risk Graph Loader API")

DATA_DIR = pathlib.Path("/tmp/risk_tasks")
DATA_DIR.mkdir(exist_ok=True)

class TaskStatus(str):
    PENDING="PENDING"
    RUNNING="RUNNING"
    SUCCESS="SUCCESS"
    FAILED="FAILED"

class Task(BaseModel):
    id: str
    type: Literal["bulk","single","export","stale_update","migration"]
    submitted: datetime.datetime
    status: TaskStatus = TaskStatus.PENDING
    params: Dict
    log: Optional[str] = None
    result: Optional[str] = None

TASKS: Dict[str, Task] = {}
QUEUE: asyncio.Queue[str] = asyncio.Queue()

LOADER_SCRIPT = os.getenv("LOADER_SCRIPT","/opt/risk/bin/risk_loader_improved.py")
EXPORT_SCRIPT = os.getenv("EXPORT_SCRIPT","/opt/risk/bin/full_graph_model_to_iceberg.py")
STALE_UPDATER_SCRIPT = os.getenv("STALE_UPDATER_SCRIPT","/opt/risk/bin/update_stale_nodes.py")

async def worker():
    while True:
        task_id = await QUEUE.get()
        task = TASKS.get(task_id)
        if not task:
            continue
        task.status = TaskStatus.RUNNING
        cmd=[]
        if task.type=="bulk":
            domains_file = DATA_DIR/f"{task_id}.txt"
            domains_file.write_text("\n".join(task.params["domains"]))
            cmd = ["python3", LOADER_SCRIPT,
                   "--domains", str(domains_file),
                   "--depth", str(task.params.get("depth",2)),
                   "--max-depth", str(task.params.get("max_depth",4)),
                   "--workers", str(task.params.get("workers",4)),
                   "--amass-workers", str(task.params.get("amass_workers",2)),
                   "--bolt", task.params.get("bolt","bolt://localhost:7687"),
                   "--user", task.params.get("user","neo4j"),
                   "--password", task.params.get("password","test")]
            
            # Add parallel processing flags
            if task.params.get("parallel_amass"):
                cmd.append("--parallel-amass")
            elif task.params.get("parallel", True):  # Default to parallel for bulk
                cmd.append("--parallel")
            elif task.params.get("sequential"):
                cmd.append("--sequential")
                
            if task.params.get("ipinfo_token"):
                cmd.extend(["--ipinfo-token", task.params["ipinfo_token"]])
                
        elif task.type=="single":
            domains_file = DATA_DIR/f"{task_id}.txt"
            domains_file.write_text(task.params["domain"])
            cmd = ["python3", LOADER_SCRIPT,
                   "--domains", str(domains_file),
                   "--depth", str(task.params.get("depth",2)),
                   "--max-depth", str(task.params.get("max_depth",4)),
                   "--workers", str(task.params.get("workers",4)),
                   "--amass-workers", str(task.params.get("amass_workers",2)),
                   "--bolt", task.params.get("bolt","bolt://localhost:7687"),
                   "--user", task.params.get("user","neo4j"),
                   "--password", task.params.get("password","test")]
            
            # Add parallel processing flags (single domain usually sequential)
            if task.params.get("parallel"):
                cmd.append("--parallel")
            elif task.params.get("parallel_amass"):
                cmd.append("--parallel-amass")
            else:
                cmd.append("--sequential")  # Default for single domain
                
            if task.params.get("ipinfo_token"):
                cmd.extend(["--ipinfo-token", task.params["ipinfo_token"]])
        elif task.type=="stale_update":
            cmd = ["python3", STALE_UPDATER_SCRIPT,
                   "--bolt", task.params.get("bolt","bolt://localhost:7687"),
                   "--user", task.params.get("user","neo4j"),
                   "--password", task.params.get("password","test"),
                   "--analysis-days", str(task.params.get("analysis_days",7)),
                   "--risk-days", str(task.params.get("risk_days",7)),
                   "--depth", str(task.params.get("depth",2)),
                   "--max-depth", str(task.params.get("max_depth",4))]
            if task.params.get("ipinfo_token"):
                cmd.extend(["--ipinfo-token", task.params["ipinfo_token"]])
            if task.params.get("stats_only"):
                cmd.append("--stats-only")
        elif task.type=="migration":
            cmd = ["python3", "migrate_to_enhanced_model.py",
                   "--bolt", task.params.get("bolt","bolt://localhost:7687"),
                   "--user", task.params.get("user","neo4j"),
                   "--password", task.params.get("password","test")]
            if task.params.get("validate_only"):
                cmd.append("--validate-only")
        elif task.type=="export":
            cmd = ["python3", EXPORT_SCRIPT,
                   "--bolt", task.params.get("bolt","bolt://localhost:7687"),
                   "--user", task.params.get("user","neo4j"),
                   "--password", task.params.get("password","test"),
                   "--iceberg-uri", task.params["iceberg_uri"],
                   "--warehouse", task.params["warehouse"],
                   "--s3-endpoint", task.params["s3_endpoint"],
                   "--s3-key", task.params["s3_key"],
                   "--s3-secret", task.params["s3_secret"]]
        else:
            task.status=TaskStatus.FAILED
            task.log="unknown task type"
            continue
        try:
            proc = await asyncio.create_subprocess_exec(*cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT)
            out, _ = await proc.communicate()
            task.log = out.decode()
            if proc.returncode==0:
                task.status = TaskStatus.SUCCESS
            else:
                task.status = TaskStatus.FAILED
        except Exception as e:
            task.status=TaskStatus.FAILED
            task.log=str(e)
        finally:
            QUEUE.task_done()

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(worker())

# ---- API models ----
class BulkLoadRequest(BaseModel):
    domains: List[str]
    depth: int = Field(2, gt=0)
    max_depth: int = Field(4, gt=0)
    workers: int = Field(4, gt=0, le=16)
    amass_workers: int = Field(2, gt=0, le=8)
    parallel: bool = True
    parallel_amass: bool = False
    sequential: bool = False
    ipinfo_token: Optional[str] = None
    bolt: str="bolt://localhost:7687"
    user: str="neo4j"
    password: str="test"

class SingleLoadRequest(BaseModel):
    domain: str
    depth: int = Field(2, gt=0)
    max_depth: int = Field(4, gt=0)
    workers: int = Field(4, gt=0, le=16)
    amass_workers: int = Field(2, gt=0, le=8)
    parallel: bool = False  # Single domain defaults to sequential
    parallel_amass: bool = False
    ipinfo_token: Optional[str] = None
    bolt: str="bolt://localhost:7687"
    user: str="neo4j"
    password: str="test"

class StaleUpdateRequest(BaseModel):
    analysis_days: int = Field(7, gt=0)
    risk_days: int = Field(7, gt=0)
    depth: int = Field(2, gt=0)
    max_depth: int = Field(4, gt=0)
    stats_only: bool = False
    ipinfo_token: Optional[str] = None
    bolt: str="bolt://localhost:7687"
    user: str="neo4j"
    password: str="test"

class MigrationRequest(BaseModel):
    validate_only: bool = False
    bolt: str="bolt://localhost:7687"
    user: str="neo4j"
    password: str="test"

class ExportRequest(BaseModel):
    iceberg_uri: str
    warehouse: str
    s3_endpoint: str
    s3_key: str
    s3_secret: str
    bolt: str="bolt://localhost:7687"
    user: str="neo4j"
    password: str="test"

# endpoints
@app.post("/tasks/bulk")
async def create_bulk(req: BulkLoadRequest):
    tid=str(uuid4())
    task=Task(id=tid,type="bulk",submitted=datetime.datetime.utcnow(),params=req.model_dump())
    TASKS[tid]=task
    await QUEUE.put(tid)
    return {"task_id":tid}

@app.post("/tasks/single")
async def create_single(req: SingleLoadRequest):
    tid=str(uuid4())
    TASKS[tid]=Task(id=tid,type="single",submitted=datetime.datetime.utcnow(),params=req.model_dump())
    await QUEUE.put(tid)
    return {"task_id":tid}

@app.post("/tasks/stale-update")
async def create_stale_update(req: StaleUpdateRequest):
    tid=str(uuid4())
    TASKS[tid]=Task(id=tid,type="stale_update",submitted=datetime.datetime.utcnow(),params=req.model_dump())
    await QUEUE.put(tid)
    return {"task_id":tid}

@app.post("/tasks/migration")
async def create_migration(req: MigrationRequest):
    tid=str(uuid4())
    TASKS[tid]=Task(id=tid,type="migration",submitted=datetime.datetime.utcnow(),params=req.model_dump())
    await QUEUE.put(tid)
    return {"task_id":tid}

@app.post("/tasks/export")
async def create_export(req: ExportRequest):
    tid=str(uuid4())
    TASKS[tid]=Task(id=tid,type="export",submitted=datetime.datetime.utcnow(),params=req.model_dump())
    await QUEUE.put(tid)
    return {"task_id":tid}

@app.get("/tasks")
def list_tasks():
    return list(TASKS.values())

@app.get("/tasks/{task_id}")
def get_task(task_id:str):
    task=TASKS.get(task_id)
    if not task: raise HTTPException(404,"Not found")
    return task
