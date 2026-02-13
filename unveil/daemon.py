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


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan")
def scan(req: ScanRequest):
    """Run Unveil on target path; returns full report JSON."""
    try:
        report = run(
            req.target,
            extended=req.extended,
            offensive=req.offensive,
            max_files=req.max_files,
            max_size_mb=req.max_size_mb,
            max_per_type=req.max_per_type,
        )
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def main():
    uvicorn.run("unveil.daemon:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()
