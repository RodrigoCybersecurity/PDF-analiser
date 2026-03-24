#!/usr/bin/env python3
import json
import subprocess
import sys
from pathlib import Path

def run(cmd, timeout=20):
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "cmd": cmd,
            "rc": p.returncode,
            "stdout": p.stdout[-12000:],
            "stderr": p.stderr[-12000:],
        }
    except subprocess.TimeoutExpired:
        return {
            "cmd": cmd,
            "rc": 124,
            "stdout": "",
            "stderr": "timeout",
        }

def main():
    if len(sys.argv) != 3:
        print("usage: analyze_inside.py /input.pdf /output/verdict.json", file=sys.stderr)
        sys.exit(2)

    input_pdf = Path(sys.argv[1])
    out_json = Path(sys.argv[2])
    out_json.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "file": input_pdf.name,
        "status": "accepted",
        "source": "sandbox",
        "reasons": [],
        "checks": {}
    }

    report["checks"]["pdfinfo"] = run(["pdfinfo", str(input_pdf)], timeout=10)
    report["checks"]["mutool"] = run(["mutool", "show", str(input_pdf), "trailer"], timeout=10)

    open_cmd = [
        "timeout", "12s",
        "xvfb-run", "-a",
        "strace", "-ff", "-o", "/tmp/trace",
        "evince", str(input_pdf)
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

    for marker in ("segmentation fault", "crash", "trace/breakpoint trap"):
        if marker in open_err:
            suspicious = True
            report["reasons"].append(f"viewer_error:{marker}")

    syscall_hits = set()
    for trace_file in Path("/tmp").glob("trace*"):
        try:
            content = trace_file.read_text(errors="ignore")
        except Exception:
            continue

        for marker in ("socket(", "connect(", "execve(", "ptrace("):
            if marker in content:
                syscall_hits.add(marker)

    if syscall_hits:
        suspicious = True
        report["reasons"].append(f"suspicious_syscalls:{sorted(syscall_hits)}")

    if suspicious:
        report["status"] = "rejected"

    if not report["reasons"]:
        report["reasons"].append("no_anomalies_detected")

    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

if __name__ == "__main__":
    main()