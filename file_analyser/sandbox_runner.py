from __future__ import annotations

import json
from pathlib import Path
import subprocess

from .config import ProjectPaths


def run_in_sandbox(paths: ProjectPaths, input_pdf: Path, verdict_path: Path) -> dict:
    if verdict_path.exists():
        verdict_path.unlink()
    verdict_path.touch()
    verdict_path.chmod(0o666)

    cmd = [
        "docker",
        "compose",
        "run",
        "--rm",
        "-v",
        f"{input_pdf.resolve()}:/input.pdf:ro",
        "-v",
        f"{verdict_path.resolve()}:/output/{verdict_path.name}",
        "sandbox",
        "/input.pdf",
        f"/output/{verdict_path.name}",
    ]
    completed = subprocess.run(
        cmd,
        cwd=paths.root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )

    runner_check = {
        "command": cmd,
        "rc": completed.returncode,
        "stdout": completed.stdout[-12000:],
        "stderr": completed.stderr[-12000:],
    }

    if completed.returncode != 0:
        return {
            "file": input_pdf.name,
            "status": "rejected",
            "source": "sandbox",
            "reasons": ["sandbox_execution_failed"],
            "checks": {"sandbox_runner": runner_check},
        }

    if not verdict_path.exists():
        return {
            "file": input_pdf.name,
            "status": "rejected",
            "source": "sandbox",
            "reasons": ["sandbox_verdict_missing"],
            "checks": {"sandbox_runner": runner_check},
        }

    try:
        verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "file": input_pdf.name,
            "status": "rejected",
            "source": "sandbox",
            "reasons": ["sandbox_verdict_invalid"],
            "checks": {"sandbox_runner": runner_check},
        }

    verdict.setdefault("checks", {})
    verdict["checks"]["sandbox_runner"] = runner_check
    return verdict
