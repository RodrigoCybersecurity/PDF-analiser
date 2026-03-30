from __future__ import annotations

import hashlib
import json
import mimetypes
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from file_analyser.config import ProjectPaths
from file_analyser.pipeline import analyse_file

APP_NAME = "pdf-analiser-api"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RUNTIME_ROOT = Path(__file__).resolve().parent / "runtime_jobs"
STATIC_ROOT = Path(__file__).resolve().parent / "static"
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
ALLOWED_EXTENSIONS = {".pdf", ".jpg", ".jpeg"}

app = FastAPI(
    title=APP_NAME,
    docs_url=None,
    redoc_url=None,
)

if STATIC_ROOT.exists():
    app.mount("/static", StaticFiles(directory=STATIC_ROOT), name="static")


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


def get_hashes(file_path: Path) -> dict[str, str]:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    with file_path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            md5.update(chunk)
            sha256.update(chunk)

    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


def map_reason_to_indicator(reason: str) -> dict[str, str]:
    lowered = reason.lower()
    if "pdfid_clean" in lowered:
        return {"severity": "info", "title": "Sem sinais críticos", "detail": reason}
    if "pdfid_execution_failed" in lowered:
        return {"severity": "warning", "title": "Verificação incompleta", "detail": reason}
    if "suspicious_syscalls_detected" in lowered:
        return {"severity": "critical", "title": "Comportamento malicioso em execução", "detail": reason}
    if "syscall" in lowered or "privilege" in lowered:
        return {"severity": "critical", "title": "Comportamento de alto risco", "detail": reason}
    if "javascript" in lowered or "js" in lowered:
        return {"severity": "warning", "title": "Conteúdo ativo detectado", "detail": reason}
    if "obfus" in lowered:
        return {"severity": "warning", "title": "Possível obfuscação", "detail": reason}
    return {"severity": "info", "title": "Sinal de análise", "detail": reason}


def build_risk_profile(verdict: dict) -> dict:
    status = verdict.get("status", "rejected")
    reasons = verdict.get("reasons", [])
    checks = verdict.get("checks", {})

    indicators = [map_reason_to_indicator(reason) for reason in reasons]

    pdfid_hits = checks.get("pdfid", {}).get("hits", [])
    for hit in pdfid_hits:
        indicators.append(
            {
                "severity": "warning",
                "title": "Indicador estático suspeito",
                "detail": f"pdfid hit: {hit}",
            }
        )

    suspicious_syscalls = checks.get("strace", {}).get("suspicious_syscalls", [])
    for call in suspicious_syscalls:
        indicators.append(
            {
                "severity": "critical",
                "title": "Syscall suspeita em sandbox",
                "detail": call,
            }
        )

    reason_weights = {
        "pdfid_clean": -10,
        "pdfid_execution_failed": 28,
        "suspicious_syscalls_detected": 45,
    }

    static_hit_weights = {
        "javascript": 18,
        "js": 18,
        "openaction": 20,
        "launch": 24,
        "aa": 14,
        "richmedia": 16,
    }

    critical_syscall_tokens = {
        "connect(",
        "socket(",
        "execve(",
        "ptrace(",
        "mprotect(",
        "setuid(",
        "setgid(",
    }

    score = 5 if status == "accepted" else 30

    # 1) Peso por razões agregadas do pipeline
    reason_score = 0
    for reason in reasons:
        lowered = reason.lower()
        if lowered in reason_weights:
            reason_score += reason_weights[lowered]
            continue
        if "javascript" in lowered or "obfus" in lowered:
            reason_score += 16
        elif "syscall" in lowered or "privilege" in lowered:
            reason_score += 24
        else:
            reason_score += 10

    # 2) Peso por hits estáticos (pdfid)
    static_score = 0
    for hit in pdfid_hits:
        lowered_hit = str(hit).lower()
        static_score += static_hit_weights.get(lowered_hit, 10)
    static_score = min(static_score, 40)

    # 3) Peso por comportamento em sandbox (syscalls)
    syscall_score = 0
    critical_syscalls = 0
    for call in suspicious_syscalls:
        lowered_call = str(call).lower()
        if any(token in lowered_call for token in critical_syscall_tokens):
            syscall_score += 20
            critical_syscalls += 1
        else:
            syscall_score += 12
    syscall_score = min(syscall_score, 55)

    score += reason_score + static_score + syscall_score

    # Guardrails por estado final do pipeline
    has_critical = any(item["severity"] == "critical" for item in indicators)
    if status == "accepted":
        score = min(score, 35)
    else:
        if has_critical:
            score = max(score, 72)
        else:
            score = max(score, 45)

    score = max(0, min(100, score))

    if score >= 70:
        label = "Malicious"
        summary = "Foram detetados sinais fortes de comportamento malicioso. Recomendado bloquear e notificar a equipa de segurança."
    elif score >= 30:
        label = "Suspicious"
        summary = "O ficheiro apresenta sinais de risco e deve ser tratado com cautela antes de utilização."
    else:
        label = "Safe"
        summary = "Não foram encontrados sinais relevantes de ameaça nesta análise."

    evidence_count = len(reasons) + len(pdfid_hits) + len(suspicious_syscalls)
    if has_critical and evidence_count >= 2:
        confidence = "High"
    elif evidence_count >= 2:
        confidence = "Medium"
    else:
        confidence = "Low"

    signatures = []
    for reason in reasons:
        normalized = reason.replace("_", " ").strip().title()
        if normalized:
            signatures.append(normalized)

    if not signatures and status == "accepted":
        signatures.append("Clean.Static")

    return {
        "status_label": label,
        "risk_score": score,
        "confidence": confidence,
        "summary": summary,
        "indicators": indicators,
        "signatures": signatures,
    }


def find_verdict_report(job_id: str) -> Path:
    reports_dir = RUNTIME_ROOT / job_id / "reports"
    if not reports_dir.exists():
        raise HTTPException(status_code=404, detail="Job não encontrado.")

    candidates = sorted(reports_dir.glob("*_verdict.json"))
    if not candidates:
        raise HTTPException(status_code=404, detail="Relatório não encontrado.")
    return candidates[0]


def find_output_file(job_id: str) -> Path:
    job_root = RUNTIME_ROOT / job_id
    accepted_files = sorted((job_root / "accepted").glob("*")) if (job_root / "accepted").exists() else []
    if accepted_files:
        return accepted_files[0]

    rejected_files = sorted((job_root / "rejected").glob("*")) if (job_root / "rejected").exists() else []
    if rejected_files:
        return rejected_files[0]

    raise HTTPException(status_code=404, detail="Ficheiro do job não encontrado.")


@app.get("/", include_in_schema=False)
def index():
    index_file = STATIC_ROOT / "index.html"
    if index_file.exists():
        return FileResponse(path=str(index_file), media_type="text/html")
    return {"service": APP_NAME, "docs": "/docs"}


@app.get("/docs", include_in_schema=False)
def api_docs():
    docs_file = STATIC_ROOT / "docs.html"
    if docs_file.exists():
        return FileResponse(path=str(docs_file), media_type="text/html")

    return {
        "service": APP_NAME,
        "documentation": {
            "health": {"method": "GET", "path": "/health"},
            "scan": {
                "method": "POST",
                "path": "/scan",
                "query": {"response_mode": ["file", "json"]},
                "multipart_field": "file",
            },
            "job_report": {"method": "GET", "path": "/jobs/{job_id}/report"},
            "job_download": {"method": "GET", "path": "/jobs/{job_id}/download"},
        },
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": APP_NAME}


@app.post("/scan")
async def scan(
    file: UploadFile = File(...),
    response_mode: str = Query(default="file", pattern="^(file|json)$"),
):
    filename = normalize_filename(file.filename)
    validate_extension(filename)

    job_id = str(uuid.uuid4())
    job_root = RUNTIME_ROOT / job_id
    paths = build_job_paths(job_root)
    paths.ensure_output_dirs()

    input_path = paths.incoming / filename
    await save_upload(file, input_path)
    hashes = get_hashes(input_path)
    uploaded_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

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
    risk_profile = build_risk_profile(verdict)

    payload = {
        "job_id": job_id,
        "status": status,
        "source": verdict.get("source", "unknown"),
        "file": {
            "name": filename,
            "size_bytes": input_path.stat().st_size,
            "uploaded_at": uploaded_at,
            "md5": hashes["md5"],
            "sha256": hashes["sha256"],
        },
        "risk": risk_profile,
        "report": verdict,
        "links": {
            "report": f"/jobs/{job_id}/report",
            "file": f"/jobs/{job_id}/download",
        },
    }

    if status == "accepted" and response_mode == "file":
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

    if status == "accepted" and response_mode == "json":
        return JSONResponse(status_code=200, content=payload)

    try:
        input_path.unlink(missing_ok=True)
    except OSError:
        pass

    return JSONResponse(
        status_code=422,
        content=payload,
    )


@app.get("/jobs/{job_id}/report")
def download_report(job_id: str):
    report_path = find_verdict_report(job_id)
    return FileResponse(
        path=str(report_path),
        filename=report_path.name,
        media_type="application/json",
    )


@app.get("/jobs/{job_id}/download")
def download_output(job_id: str):
    output_path = find_output_file(job_id)
    media_type, _ = mimetypes.guess_type(output_path.name)
    return FileResponse(
        path=str(output_path),
        filename=output_path.name,
        media_type=media_type or "application/octet-stream",
    )
