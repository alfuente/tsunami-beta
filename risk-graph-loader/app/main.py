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
    type: Literal["bulk","single","export"]
    submitted: datetime.datetime
    status: TaskStatus = TaskStatus.PENDING
    params: Dict
    log: Optional[str] = None
    result: Optional[str] = None

TASKS: Dict[str, Task] = {}
QUEUE: asyncio.Queue[str] = asyncio.Queue()

LOADER_SCRIPT = os.getenv("LOADER_SCRIPT","/opt/risk/bin/risk_loader_advanced.py")
EXPORT_SCRIPT = os.getenv("EXPORT_SCRIPT","/opt/risk/bin/full_graph_model_to_iceberg.py")

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
                   "--seeds", str(domains_file),
                   "--depth", str(task.params.get("depth",1))]
        elif task.type=="single":
            cmd = ["python3", LOADER_SCRIPT,
                   "--seeds", task.params["domain"],
                   "--depth", str(task.params.get("depth",1))]
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
    depth: int = Field(1, gt=0)

class SingleLoadRequest(BaseModel):
    domain: str
    depth: int = Field(1, gt=0)

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
