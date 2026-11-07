"""FastAPI backend: upload -> plan chunks -> sequential local-model calls -> merge. Resumable."""
import json, os, threading, time, uuid
from fastapi import FastAPI, UploadFile, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import psutil
import analyzer as A
from logparse import plan_chunks, read_chunk, parse, compact, Entities, est_tokens

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data"); os.makedirs(DATA, exist_ok=True)
LOGF, STATE = os.path.join(DATA, "upload.log"), os.path.join(DATA, "job.json")
LOG_BUDGET = int(os.environ.get("LOG_BUDGET", "850"))      # est. tokens of log text per call
MAX_BYTES = 5 * 1024 * 1024
app = FastAPI(); lock = threading.Lock(); worker = None
job = dict(status="idle", filename=None, chunks=[], done=0, nlines=0, raw=[], calls=[], report=None, summary=None, error=None)

def save():
    tmp = STATE + ".tmp"
    with open(tmp, "w") as f: json.dump(job, f)
    os.replace(tmp, STATE)

if os.path.exists(STATE):                       # resume after restart
    try:
        job.update(json.load(open(STATE)))
        if job["status"] == "running": job["status"] = "interrupted"
    except Exception: pass

def rebuild_entities(upto):
    ents = Entities()
    for c in job["chunks"][:upto]:
        for no, raw in read_chunk(LOGF, tuple(c)): ents.update(parse(raw), no)
    return ents

def run(resume_from):
    try:
        ents = rebuild_entities(resume_from)
        for i in range(resume_from, len(job["chunks"])):
            c = tuple(job["chunks"][i]); lines = read_chunk(LOGF, c)
            text = "\n".join(compact(parse(r), n, r) for n, r in lines)
            for n, r in lines: ents.update(parse(r), n)       # facts include this chunk
            facts = ents.summary()
            try:
                out, stats = A.call_model(facts, text)
                found, repaired = A.parse_findings(out)
                stats["json_repaired"] = repaired
            except Exception as ex:
                found, stats = [], dict(error=str(ex)[:200])   # keep going; report the failed part
            clean = [x for x in (A.sanitize(f, job["nlines"]) for f in found) if x]
            with lock:
                job["raw"] += clean
                job["calls"].append(dict(chunk=i + 1, lines=f"{c[2]}-{c[3]}", est_prompt_tokens=est_tokens(A.SYSTEM + facts + text),
                                         findings=len(clean), **stats))
                job["done"] = i + 1; save()
            if job["status"] == "stopped": return
        lookup = {}
        need = {n for f in job["raw"] for n in f["lines"]} | {n for e in ents.ips.values() for k in ("ok", "fail", "inj", "scan", "exports", "sqli", "rl") for n in e[k]}
        with open(LOGF, encoding="utf-8", errors="replace") as f:
            for n, l in enumerate(f, 1):
                if n in need: lookup[n] = l
        job["report"] = A.merge(job["raw"], ents, lookup, job["nlines"])
        job["status"] = "done"; save()
    except Exception as ex:
        job["status"], job["error"] = "error", str(ex)[:300]; save()

def start(resume_from):
    global worker
    if worker and worker.is_alive(): raise HTTPException(409, "analysis already running")
    job["status"], job["error"] = "running", None
    worker = threading.Thread(target=run, args=(resume_from,), daemon=True); worker.start()

@app.post("/api/upload")
async def upload(file: UploadFile):
    if worker and worker.is_alive(): raise HTTPException(409, "analysis running")
    name = file.filename or ""
    if not name.lower().endswith((".log", ".txt")): raise HTTPException(400, "Only .log or .txt files are accepted")
    n = 0
    with open(LOGF, "wb") as out:
        while chunk := await file.read(1 << 20):
            n += len(chunk)
            if n > MAX_BYTES: out.close(); raise HTTPException(413, "File too large (max 5 MB)")
            out.write(chunk)
    if n == 0: raise HTTPException(400, "Empty file")
    with open(LOGF, "rb") as f:
        head = f.read(4096)
    if b"\x00" in head: raise HTTPException(400, "Binary file rejected")
    chunks = plan_chunks(LOGF, LOG_BUDGET)
    nlines = sum(1 for _ in open(LOGF, "rb"))
    job.update(status="ready", filename=name, chunks=chunks, done=0, nlines=nlines, raw=[], calls=[], report=None, summary=None, error=None)
    save()
    return dict(filename=name, lines=nlines, chunks=len(chunks))

@app.post("/api/start")
def api_start():
    if job["status"] not in ("ready", "done", "error", "interrupted", "stopped"): raise HTTPException(400, "Upload a log first")
    if job["status"] in ("done", "error"): job.update(done=0, raw=[], calls=[], report=None)
    start(job["done"] if job["status"] in ("interrupted", "stopped") else 0)
    return dict(ok=True)

@app.post("/api/stop")
def api_stop():
    job["status"] = "stopped"; return dict(ok=True)

@app.get("/api/status")
def status():
    vm, p = psutil.virtual_memory(), psutil.Process()
    return dict(status=job["status"], filename=job["filename"], total=len(job["chunks"]), done=job["done"], error=job["error"],
                model=A.MODEL, calls=job["calls"][-12:], ram_app_mb=round(p.memory_info().rss / 2**20),
                ram_system_pct=vm.percent, report=job["report"], lines=job["nlines"])

app.mount("/", StaticFiles(directory=os.path.join(BASE, "static"), html=True), name="static")
