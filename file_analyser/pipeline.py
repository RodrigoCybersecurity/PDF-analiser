from __future__ import annotations

import json
from pathlib import Path
import shutil

from .config import ProjectPaths
from .jpeg_analysis import JPEG_EXTENSIONS, sanitize_for_pipeline
from .models import AnalysisOutcome
from .sandbox_runner import run_in_sandbox
from .static_analysis import run_pdfid


def build_static_verdict(input_pdf: Path, static_check: dict) -> dict:
    return {
        "file": input_pdf.name,
        "status": "accepted",
        "source": "static",
        "reasons": ["pdfid_clean"],
        "checks": {"pdfid": static_check},
    }


def write_verdict(verdict_path: Path, verdict: dict) -> None:
    verdict_path.write_text(
        json.dumps(verdict, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def copy_to_destination(input_pdf: Path, destination_dir: Path) -> Path:
    destination = destination_dir / input_pdf.name
    shutil.copy2(input_pdf, destination)
    return destination


def detect_file_kind(input_path: Path) -> str | None:
    suffix = input_path.suffix.lower()
    if suffix == ".pdf":
        return "pdf"
    if suffix in JPEG_EXTENSIONS:
        return "jpeg"

    try:
        header = input_path.read_bytes()[:4]
    except OSError:
        return None

    if header.startswith(b"%PDF"):
        return "pdf"
    if header.startswith(b"\xFF\xD8"):
        return "jpeg"
    return None


def analyse_pdf(input_pdf: Path, paths: ProjectPaths) -> AnalysisOutcome:
    paths.ensure_output_dirs()
    input_pdf = input_pdf.resolve()
    if not input_pdf.exists():
        raise FileNotFoundError(f"Ficheiro não encontrado: {input_pdf}")

    verdict_path = paths.reports / f"{input_pdf.stem}_verdict.json"
    static_scan = run_pdfid(paths, input_pdf)
    static_check = static_scan.to_check()

    if static_scan.return_code != 0:
        verdict = {
            "file": input_pdf.name,
            "status": "rejected",
            "source": "static",
            "reasons": ["pdfid_execution_failed"],
            "checks": {"pdfid": static_check},
        }
    elif not static_scan.suspicious:
        verdict = build_static_verdict(input_pdf, static_check)
    else:
        verdict = run_in_sandbox(paths, input_pdf, verdict_path)
        verdict.setdefault("checks", {})
        verdict["checks"]["pdfid"] = static_check

    verdict["file"] = input_pdf.name

    destination_dir = paths.accepted if verdict.get("status") == "accepted" else paths.rejected
    destination_path = copy_to_destination(input_pdf, destination_dir)

    verdict["artifacts"] = {
        "pdfid_report": str(static_scan.report_path),
        "verdict_report": str(verdict_path),
        "copied_to": str(destination_path),
    }
    write_verdict(verdict_path, verdict)

    return AnalysisOutcome(
        input_pdf=input_pdf,
        verdict_path=verdict_path,
        destination_path=destination_path,
        verdict=verdict,
    )


def analyse_jpeg(input_image: Path, paths: ProjectPaths) -> AnalysisOutcome:
    paths.ensure_output_dirs()
    input_image = input_image.resolve()
    if not input_image.exists():
        raise FileNotFoundError(f"Ficheiro não encontrado: {input_image}")

    suffix = input_image.suffix.lower() if input_image.suffix.lower() in JPEG_EXTENSIONS else ".jpg"
    destination_path = paths.accepted / f"{input_image.stem}{suffix}"
    verdict_path = paths.reports / f"{input_image.stem}_verdict.json"

    verdict = sanitize_for_pipeline(
        input_path=input_image,
        output_path=destination_path,
    )

    if verdict["status"] == "rejected":
        destination_path = copy_to_destination(input_image, paths.rejected)

    verdict["artifacts"] = {
        "verdict_report": str(verdict_path),
        "copied_to": str(destination_path),
    }

    write_verdict(verdict_path, verdict)
    return AnalysisOutcome(
        input_pdf=input_image,
        verdict_path=verdict_path,
        destination_path=destination_path,
        verdict=verdict,
    )


def analyse_file(input_path: Path, paths: ProjectPaths) -> AnalysisOutcome:
    file_kind = detect_file_kind(input_path)
    if file_kind == "pdf":
        return analyse_pdf(input_path, paths)
    if file_kind == "jpeg":
        return analyse_jpeg(input_path, paths)
    raise ValueError(f"Tipo de ficheiro não suportado: {input_path}")


def discover_inputs(paths: ProjectPaths, targets: list[str], use_incoming: bool) -> list[Path]:
    if use_incoming:
        return [
            candidate
            for candidate in sorted(paths.incoming.iterdir())
            if candidate.is_file() and detect_file_kind(candidate) is not None
        ]

    return [Path(target) for target in targets]


def analyse_files(targets: list[str], use_incoming: bool = False) -> list[AnalysisOutcome]:
    paths = ProjectPaths.discover()
    inputs = discover_inputs(paths, targets, use_incoming)
    if not inputs:
        raise FileNotFoundError("Nenhum ficheiro suportado encontrado para analisar.")

    return [analyse_file(input_path, paths) for input_path in inputs]
