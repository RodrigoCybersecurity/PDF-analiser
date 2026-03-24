from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


JsonDict = dict[str, Any]


@dataclass
class StaticScanResult:
    input_pdf: Path
    report_path: Path
    command: list[str]
    return_code: int
    output: str
    hits: list[str] = field(default_factory=list)

    @property
    def suspicious(self) -> bool:
        return bool(self.hits)

    def to_check(self) -> JsonDict:
        return {
            "command": self.command,
            "rc": self.return_code,
            "report_path": str(self.report_path),
            "hits": self.hits,
            "suspicious": self.suspicious,
        }


@dataclass
class AnalysisOutcome:
    input_pdf: Path
    verdict_path: Path
    destination_path: Path
    verdict: JsonDict
