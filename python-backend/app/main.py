from __future__ import annotations
import os, re, sqlite3, time, uuid
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from fastapi import FastAPI, File, HTTPException, UploadFile, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from app.analyzer import analyze

BASE = Path(__file__).resolve().parent
DB = Path(os.getenv("DATABASE_PATH", "./data/verity.sqlite3"))
MAX_BYTES = int(os.getenv("MAX_UPLOAD_MB", "15")) * 1024 * 1024
TEMP_ROOT = Path(os.getenv("UPLOAD_TEMP_DIR", "./work/tmp")).resolve()
TEMP_ROOT.mkdir(parents=True, exist_ok=True)
ALLOWED = {".pdf", ".png", ".jpg", ".jpeg", ".doc", ".docx"}
app = FastAPI(title="Verity Document Review", version="0.1.0", docs_url="/api/docs")
cors_origins = [origin.strip().rstrip("/") for origin in os.getenv("CORS_ALLOW_ORIGINS", "http://127.0.0.1:8080,http://localhost:8080").split(",") if origin.strip()]
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
hits = {}

def db():
    DB.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    con.execute("CREATE TABLE IF NOT EXISTS history (id TEXT PRIMARY KEY, filename TEXT, status TEXT, document_type TEXT, created INTEGER, report TEXT)")
    cutoff = int(time.time()) - int(os.getenv("RETENTION_HOURS", "24")) * 3600
    con.execute("DELETE FROM history WHERE created < ?", (cutoff,)); con.commit()
    return con

def magic_ok(ext, b):
    if ext == ".pdf": return b.startswith(b"%PDF-")
    if ext == ".png": return b.startswith(b"\x89PNG\r\n\x1a\n")
    if ext in {".jpg", ".jpeg"}: return b.startswith(b"\xff\xd8\xff")
    if ext == ".doc": return b.startswith(bytes.fromhex("D0CF11E0A1B11AE1"))
    if ext == ".docx": return b.startswith(b"PK\x03\x04")
    return False

@app.get("/", response_class=HTMLResponse)
async def home():
    return (BASE / "static/index.html").read_text(encoding="utf-8")

@app.get("/api/health")
async def health(): return {"ok": True, "max_upload_bytes": MAX_BYTES}

@app.post("/api/analyze")
async def upload(request: Request, file: UploadFile = File(...)):
    ip = request.client.host if request.client else "unknown"
    now = time.time(); hits[ip] = [x for x in hits.get(ip, []) if now - x < 60]
    if len(hits[ip]) >= 10: raise HTTPException(429, "Upload limit reached. Wait a minute and try again.")
    hits[ip].append(now)
    name = Path(file.filename or "upload").name
    ext = Path(name).suffix.lower()
    if ext not in ALLOWED:
        hint = "Supported types: PDF, JPG, PNG, DOC and DOCX."
        raise HTTPException(415, hint)
    data = await file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES: raise HTTPException(413, f"File exceeds the {MAX_BYTES // (1024*1024)} MB limit.")
    if not magic_ok(ext, data): raise HTTPException(415, "File content does not match its filename type or is invalid.")
    # Process a temporary copy: bytes are removed as soon as analysis ends.
    with TemporaryDirectory(prefix="verity-", dir=TEMP_ROOT) as tmp:
        tmp_file = Path(tmp) / (uuid.uuid4().hex + ext)
        tmp_file.write_bytes(data)
        result = analyze(name, tmp_file.read_bytes())
        tmp_file.unlink(missing_ok=True)
    result.update({"filename": name, "file_size": len(data), "id": uuid.uuid4().hex, "created": int(time.time())})
    con = db(); con.execute("INSERT INTO history VALUES (?,?,?,?,?,?)", (result["id"], name[:240], result["status"], result["document_type"], result["created"], __import__("json").dumps(result))); con.commit(); con.close()
    return result

@app.get("/api/history")
async def history():
    con = db(); rows = con.execute("SELECT id, filename, status, document_type, created FROM history ORDER BY created DESC LIMIT 30").fetchall(); con.close()
    return [dict(x) for x in rows]

@app.delete("/api/history/{item_id}")
async def delete_history(item_id: str):
    con = db(); cur = con.execute("DELETE FROM history WHERE id=?", (item_id,)); con.commit(); con.close()
    if not cur.rowcount: raise HTTPException(404, "History entry not found.")
    return {"deleted": True}

@app.get("/api/report/{item_id}.pdf")
async def report(item_id: str):
    con = db(); row = con.execute("SELECT report,filename FROM history WHERE id=?", (item_id,)).fetchone(); con.close()
    if not row: raise HTTPException(404, "Report not found. It may have expired.")
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        from io import BytesIO
        import json
        d = json.loads(row["report"]); out = BytesIO(); c = canvas.Canvas(out, pagesize=letter); w,h=letter; y=h-48
        def line(s):
            nonlocal y
            if y < 55: c.showPage(); y=h-48
            clean = str(s).encode("latin-1", "replace").decode("latin-1")
            c.setFont("Helvetica", 9); c.drawString(42,y,clean[:120]); y-=15
        c.setFont("Helvetica-Bold",16); c.drawString(42,y,"Verity | Document Review Report"); y-=28
        lines = [f"File: {d['filename']}",f"Type: {d['document_type']}",f"Status: {d['status']}","Confidence: Not calibrated", "", "Extracted fields:"]
        for key, values in d.get("fields", {}).items(): lines.append(f"{key}: {', '.join(values) if values else 'No values extracted'}")
        lines += ["", "Metadata analysis:"]
        for key, value in d.get("metadata_analysis", {}).items():
            if key not in {"metadata_present", "metadata_keys", "metadata_details"}: lines.append(f"{key}: {value}")
        for item in d.get("metadata_analysis", {}).get("metadata_details", []): lines.append(f"Metadata tag {item.get('field', '')}: {item.get('value', '')}")
        lines += ["", "Findings:"]
        for x in d["findings"]:
            lines.append(f"{x['status']} | {x['name']}: {x['message']}")
            lines.extend(f"Evidence: {e}" for e in x.get("evidence", []))
        lines += ["", "Limitations:"] + d["limitations"]
        for s in lines: line(s)
        c.save(); return Response(out.getvalue(), media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=verity-report.pdf"})
    except ImportError: raise HTTPException(503, "PDF report support is unavailable. Install reportlab.")

# Keep CORS outside FastAPI's error middleware so even unhandled 500 responses
# include the allow-origin header. Without this, browsers mask server errors as
# generic CORS/network failures, which makes upload failures hard to diagnose.
app = CORSMiddleware(
    app,
    allow_origins=cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)
