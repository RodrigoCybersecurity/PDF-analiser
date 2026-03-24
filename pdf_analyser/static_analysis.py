from __future__ import annotations

from pathlib import Path
import subprocess
import sys

from .config import ProjectPaths, SUSPICIOUS_RULES
from .models import StaticScanResult


def run_pdfid(paths: ProjectPaths, input_pdf: Path) -> StaticScanResult:
    report_path = paths.reports / f"{input_pdf.stem}_pdfid.txt"
    cmd = [sys.executable, str(paths.pdfid_script), str(input_pdf)]
    completed = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    report_path.write_text(completed.stdout, encoding="utf-8")
    hits = [rule.key for rule in SUSPICIOUS_RULES if rule.pattern.search(completed.stdout)]
    return StaticScanResult(
        input_pdf=input_pdf,
        report_path=report_path,
        command=cmd,
        return_code=completed.returncode,
        output=completed.stdout,
        hits=hits,
    )
