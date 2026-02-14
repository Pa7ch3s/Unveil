"""
Unveil daemon: local-only API for running scans.
SECURITY: Binds to 127.0.0.1 only (no auth). Do not expose to the network.
"""
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import uvicorn

from unveil.engine import run

app = FastAPI()


class ScanRequest(BaseModel):
    target: str
    extended: bool = False
    offensive: bool = True
    max_files: Optional[int] = None
    max_size_mb: Optional[int] = None
    max_per_type: Optional[int] = None


def _validate_target(target: str) -> str:
    """Resolve and validate target path; reject path traversal and non-existent paths."""
    if not target or not target.strip():
        raise HTTPException(status_code=400, detail="target is required")
    p = Path(target.strip()).resolve()
    if not p.exists():
        raise HTTPException(status_code=400, detail=f"target does not exist: {p}")
    if not (p.is_file() or p.is_dir()):
        raise HTTPException(status_code=400, detail="target must be a file or directory")
    return str(p)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan")
def scan(req: ScanRequest):
    """Run Unveil on target path; returns full report JSON."""
    try:
        target = _validate_target(req.target)
        report = run(
            target,
            extended=req.extended,
            offensive=req.offensive,
            max_files=req.max_files,
            max_size_mb=req.max_size_mb,
            max_per_type=req.max_per_type,
        )
        return report
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def main():
    # Bind localhost only; no TLS or auth. Do not expose this server to the network.
    uvicorn.run("unveil.daemon:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()
