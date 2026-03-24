from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re


@dataclass(frozen=True)
class SuspiciousRule:
    key: str
    pattern: re.Pattern[str]
    description: str


@dataclass(frozen=True)
class ProjectPaths:
    root: Path
    incoming: Path
    accepted: Path
    rejected: Path
    reports: Path
    pdfid_script: Path
    sandbox_compose: Path

    @classmethod
    def discover(cls) -> "ProjectPaths":
        root = Path(__file__).resolve().parent.parent
        return cls(
            root=root,
            incoming=root / "incoming",
            accepted=root / "accepted",
            rejected=root / "rejected",
            reports=root / "reports",
            pdfid_script=root / "triage" / "pdfid.py",
            sandbox_compose=root / "docker-compose.yml",
        )

    def ensure_output_dirs(self) -> None:
        for directory in (self.incoming, self.accepted, self.rejected, self.reports):
            directory.mkdir(parents=True, exist_ok=True)
        self.reports.chmod(0o777)


SUSPICIOUS_RULES = (
    SuspiciousRule("javascript", re.compile(r"/JavaScript\s+[1-9]"), "JavaScript embutido"),
    SuspiciousRule("js", re.compile(r"/JS\s+[1-9]"), "Referência JS embutida"),
    SuspiciousRule("open_action", re.compile(r"/OpenAction\s+[1-9]"), "Ação automática ao abrir"),
    SuspiciousRule("additional_actions", re.compile(r"/AA\s+[1-9]"), "Ações adicionais"),
    SuspiciousRule("launch", re.compile(r"/Launch\s+[1-9]"), "Tentativa de lançamento externo"),
    SuspiciousRule("embedded_file", re.compile(r"/EmbeddedFile\s+[1-9]"), "Ficheiros anexos"),
    SuspiciousRule("uri", re.compile(r"/URI\s+[1-9]"), "Links/URIs embutidos"),
)
