from __future__ import annotations

import json
import mimetypes
import shutil
import uuid
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse

from file_analyser.config import ProjectPaths
from file_analyser.pipeline import analyse_file

APP_NAME = "pdf-analiser-api"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RUNTIME_ROOT = Path(__file__).resolve().parent / "runtime_jobs"
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
ALLOWED_EXTENSIONS = {".pdf", ".jpg", ".jpeg"}

app = FastAPI(title=APP_NAME)


def build_job_paths(job_root: Path) -> ProjectPaths:
    return ProjectPaths(
        root=PROJECT_ROOT,
        incoming=job_root / "incoming",
        accepted=job_root / "accepted",
        rejected=job_root / "rejected",
        reports=job_root / "reports",
        pdfid_script=PROJECT_ROOT / "triage" / "pdfid.py",
        sandbox_compose=PROJECT_ROOT / "docker-compose.yml",
    )


def normalize_filename(filename: str | None) -> str:
    if not filename:
        return "upload.bin"
    return Path(filename).name.replace("\x00", "") or "upload.bin"


def validate_extension(filename: str) -> None:
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=415,
            detail={
                "status": "error",
                "reason": "Tipo de ficheiro não suportado. Envie PDF, JPG ou JPEG.",
                "code": "UNSUPPORTED_FILE_TYPE",
            },
        )


async def save_upload(upload: UploadFile, destination: Path) -> int:
    total = 0
    with destination.open("wb") as handle:
        while True:
            chunk = await upload.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_UPLOAD_BYTES:
                handle.close()
                destination.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=413,
                    detail={
                        "status": "error",
                        "reason": f"Arquivo excede o limite de {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.",
                        "code": "FILE_TOO_LARGE",
                    },
                )
            handle.write(chunk)
    await upload.close()
    return total


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": APP_NAME}


@app.post("/scan")
async def scan(file: UploadFile = File(...)):
    filename = normalize_filename(file.filename)
    validate_extension(filename)

    job_id = str(uuid.uuid4())
    job_root = RUNTIME_ROOT / job_id
    paths = build_job_paths(job_root)
    paths.ensure_output_dirs()

    input_path = paths.incoming / filename
    await save_upload(file, input_path)

    try:
        outcome = analyse_file(input_path, paths)
    except HTTPException:
        raise
    except Exception as exc:
        error_report = paths.reports / f"{Path(filename).stem}_error.json"
        payload = {
            "status": "error",
            "reason": "Falha interna na análise.",
            "detail": str(exc),
            "job_id": job_id,
        }
        error_report.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return JSONResponse(status_code=500, content=payload)

    verdict = outcome.verdict
    status = verdict.get("status", "rejected")
    report_path = outcome.verdict_path

    if status == "accepted":
        media_type, _ = mimetypes.guess_type(outcome.destination_path.name)
        return FileResponse(
            path=str(outcome.destination_path),
            filename=outcome.destination_path.name,
            media_type=media_type or "application/octet-stream",
            headers={
                "X-Scan-Status": "accepted",
                "X-Scan-Job": job_id,
                "X-Scan-Report": str(report_path.name),
            },
        )

    try:
        input_path.unlink(missing_ok=True)
    except OSError:
        pass

    return JSONResponse(
        status_code=422,
        content={
            "status": "rejected",
            "reason": "; ".join(verdict.get("reasons", [])) or "Arquivo rejeitado",
            "job_id": job_id,
            "report": verdict,
        },
    )
