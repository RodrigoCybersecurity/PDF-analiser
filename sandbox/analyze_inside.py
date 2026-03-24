#!/usr/bin/env python3
import json
from pathlib import Path
import subprocess
import sys


TRACE_PREFIX = "/tmp/trace"
SUSPICIOUS_SYSCALLS = ("socket(", "connect(", "ptrace(")
VIEWER_ERROR_MARKERS = ("segmentation fault", "crash", "trace/breakpoint trap")


def run(cmd, timeout=20):
    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "cmd": cmd,
            "rc": completed.returncode,
            "stdout": completed.stdout[-12000:],
            "stderr": completed.stderr[-12000:],
        }
    except subprocess.TimeoutExpired:
        return {
            "cmd": cmd,
            "rc": 124,
            "stdout": "",
            "stderr": "timeout",
        }


def cleanup_old_traces():
    for trace_file in Path("/tmp").glob("trace*"):
        try:
            trace_file.unlink()
        except OSError:
            continue


def inspect_syscalls():
    hits = set()
    trace_files = []
    for trace_file in Path("/tmp").glob("trace*"):
        trace_files.append(str(trace_file))
        try:
            content = trace_file.read_text(errors="ignore")
        except OSError:
            continue

        for marker in SUSPICIOUS_SYSCALLS:
            if marker in content:
                hits.add(marker)

    return sorted(hits), sorted(trace_files)


def build_report(input_pdf: Path):
    return {
        "file": input_pdf.name,
        "status": "accepted",
        "source": "sandbox",
        "reasons": [],
        "checks": {},
    }


def main():
    if len(sys.argv) != 3:
        print("usage: analyze_inside.py /input.pdf /output/verdict.json", file=sys.stderr)
        sys.exit(2)

    input_pdf = Path(sys.argv[1])
    out_json = Path(sys.argv[2])
    out_json.parent.mkdir(parents=True, exist_ok=True)

    cleanup_old_traces()
    report = build_report(input_pdf)

    report["checks"]["pdfinfo"] = run(["pdfinfo", str(input_pdf)], timeout=10)
    report["checks"]["mutool"] = run(["mutool", "show", str(input_pdf), "trailer"], timeout=10)

    open_cmd = [
        "timeout",
        "12s",
        "xvfb-run",
        "-a",
        "strace",
        "-ff",
        "-o",
        TRACE_PREFIX,
        "evince",
        str(input_pdf),
    ]
    report["checks"]["open_test"] = run(open_cmd, timeout=20)

    suspicious = False
    pdfinfo_err = report["checks"]["pdfinfo"]["stderr"].lower()
    open_err = report["checks"]["open_test"]["stderr"].lower()
    open_rc = report["checks"]["open_test"]["rc"]

    if "syntax error" in pdfinfo_err:
        suspicious = True
        report["reasons"].append("pdf_syntax_error")

    if open_rc not in (0, 124):
        suspicious = True
        report["reasons"].append(f"unexpected_viewer_exit:{open_rc}")

    for marker in VIEWER_ERROR_MARKERS:
        if marker in open_err:
            suspicious = True
            report["reasons"].append(f"viewer_error:{marker}")

    syscall_hits, trace_files = inspect_syscalls()
    report["checks"]["strace"] = {
        "trace_prefix": TRACE_PREFIX,
        "trace_files": trace_files,
        "suspicious_syscalls": syscall_hits,
    }
    if syscall_hits:
        suspicious = True
        report["reasons"].append("suspicious_syscalls_detected")

    if suspicious:
        report["status"] = "rejected"

    if not report["reasons"]:
        report["reasons"].append("no_anomalies_detected")

    with out_json.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
