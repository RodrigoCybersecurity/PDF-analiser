from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

try:
    from PIL import Image, ImageFile, ImageOps
except ImportError as exc:  # pragma: no cover - depends on local environment
    Image = None
    ImageFile = None
    ImageOps = None
    PIL_IMPORT_ERROR = exc
else:
    PIL_IMPORT_ERROR = None


if ImageFile is not None:
    ImageFile.LOAD_TRUNCATED_IMAGES = False

SOI = b"\xFF\xD8"
EOI = b"\xFF\xD9"

MARKER_NAMES = {
    0xC0: "SOF0", 0xC1: "SOF1", 0xC2: "SOF2", 0xC3: "SOF3",
    0xC4: "DHT", 0xC5: "SOF5", 0xC6: "SOF6", 0xC7: "SOF7",
    0xC9: "SOF9", 0xCA: "SOF10", 0xCB: "SOF11",
    0xCC: "DAC", 0xCD: "SOF13", 0xCE: "SOF14", 0xCF: "SOF15",
    0xD0: "RST0", 0xD1: "RST1", 0xD2: "RST2", 0xD3: "RST3",
    0xD4: "RST4", 0xD5: "RST5", 0xD6: "RST6", 0xD7: "RST7",
    0xD8: "SOI", 0xD9: "EOI", 0xDA: "SOS", 0xDB: "DQT",
    0xDC: "DNL", 0xDD: "DRI", 0xDE: "DHP", 0xDF: "EXP",
    0xE0: "APP0", 0xE1: "APP1", 0xE2: "APP2", 0xE3: "APP3",
    0xE4: "APP4", 0xE5: "APP5", 0xE6: "APP6", 0xE7: "APP7",
    0xE8: "APP8", 0xE9: "APP9", 0xEA: "APP10", 0xEB: "APP11",
    0xEC: "APP12", 0xED: "APP13", 0xEE: "APP14", 0xEF: "APP15",
    0xFE: "COM",
}
STANDALONE_MARKERS = {0xD8, 0xD9, 0x01, *range(0xD0, 0xD8)}

DEFAULT_MAX_PIXELS = 40_000_000
DEFAULT_MAX_METADATA_SEGMENT = 16_384
DEFAULT_QUALITY = 90
JPEG_EXTENSIONS = {".jpg", ".jpeg"}


def ensure_pillow() -> None:
    if PIL_IMPORT_ERROR is not None:
        raise RuntimeError(
            "Pillow is required for JPEG sanitization. Install it with 'pip install Pillow'."
        ) from PIL_IMPORT_ERROR


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def is_jpeg_magic(data: bytes) -> bool:
    return len(data) >= 2 and data[:2] == SOI


def find_last_eoi(data: bytes) -> int:
    return data.rfind(EOI)


def parse_segments_before_sos(
    data: bytes,
    max_metadata_segment: int,
) -> tuple[list[dict[str, Any]], list[str]]:
    segments: list[dict[str, Any]] = []
    suspicious: list[str] = []
    if not is_jpeg_magic(data):
        return segments, suspicious

    position = 2
    while position < len(data):
        if data[position] != 0xFF:
            suspicious.append(f"unexpected_byte_before_next_marker_at:{position}")
            break

        while position < len(data) and data[position] == 0xFF:
            position += 1
        if position >= len(data):
            break

        marker = data[position]
        marker_name = MARKER_NAMES.get(marker, f"MARKER_0x{marker:02X}")
        marker_offset = position - 1
        position += 1

        if marker in STANDALONE_MARKERS:
            segments.append(
                {"marker": marker_name, "offset": marker_offset, "payload_bytes": 0}
            )
            if marker == 0xD9:
                break
            continue

        if position + 2 > len(data):
            suspicious.append(f"truncated_segment_length_at:{marker_name}:{marker_offset}")
            break

        segment_length = int.from_bytes(data[position:position + 2], "big")
        if segment_length < 2:
            suspicious.append(f"invalid_segment_length:{marker_name}:{segment_length}")
            break

        payload_length = segment_length - 2
        payload_start = position + 2
        payload_end = payload_start + payload_length
        if payload_end > len(data):
            suspicious.append(f"declared_segment_past_eof:{marker_name}:{payload_length}")
            break

        segments.append(
            {
                "marker": marker_name,
                "offset": marker_offset,
                "payload_bytes": payload_length,
            }
        )
        if (marker_name.startswith("APP") or marker_name == "COM") and payload_length > max_metadata_segment:
            suspicious.append(f"large_metadata_segment:{marker_name}:{payload_length}")

        position = payload_end
        if marker == 0xDA:
            break

    return segments, suspicious


def json_dump(data: dict[str, Any], path: Path | None, emit_stdout: bool = True) -> None:
    text = json.dumps(data, indent=2, ensure_ascii=False)
    if path is None:
        if emit_stdout:
            print(text)
        return
    path.write_text(text + "\n", encoding="utf-8")


def sanitize_one(
    input_path: Path,
    output_path: Path | None,
    report_path: Path | None,
    max_pixels: int,
    max_metadata_segment: int,
    quality: int,
    progressive: bool,
    emit_report: bool = True,
) -> dict[str, Any]:
    try:
        ensure_pillow()
    except RuntimeError as exc:
        result = {
            "status": "rejected",
            "reason": str(exc),
            "input": str(input_path),
        }
        json_dump(result, report_path, emit_stdout=emit_report)
        return result

    try:
        raw = input_path.read_bytes()
    except Exception as exc:
        result = {
            "status": "rejected",
            "reason": f"Could not read input: {exc}",
            "input": str(input_path),
        }
        json_dump(result, report_path, emit_stdout=emit_report)
        return result

    if not is_jpeg_magic(raw):
        result = {
            "status": "rejected",
            "reason": "Input is not a JPEG by content (missing SOI magic).",
            "input": str(input_path),
        }
        json_dump(result, report_path, emit_stdout=emit_report)
        return result

    eoi = find_last_eoi(raw)
    if eoi == -1:
        result = {
            "status": "rejected",
            "reason": "JPEG appears invalid: EOI marker not found.",
            "input": str(input_path),
        }
        json_dump(result, report_path, emit_stdout=emit_report)
        return result

    trailing_bytes = max(0, len(raw) - (eoi + 2))
    segments, suspicious_flags = parse_segments_before_sos(raw, max_metadata_segment)
    if trailing_bytes:
        suspicious_flags.append(f"trailing_bytes_after_eoi:{trailing_bytes}")

    report: dict[str, Any] = {
        "input": {
            "path": str(input_path.resolve()),
            "size_bytes": input_path.stat().st_size,
            "sha256": sha256_file(input_path),
            "extension": input_path.suffix.lower(),
        },
        "scan": {
            "is_jpeg_magic": True,
            "last_eoi_offset": eoi,
            "trailing_bytes": trailing_bytes,
            "suspicious_flags": suspicious_flags,
            "segments_before_sos": segments,
        },
    }

    try:
        with Image.open(input_path) as image:
            image.verify()

        with Image.open(input_path) as image:
            image.load()
            width, height = image.size
            if width <= 0 or height <= 0:
                raise ValueError("Invalid image dimensions.")
            if width * height > max_pixels:
                raise ValueError(
                    f"Image too large by policy ({width}x{height} > {max_pixels} pixels)."
                )

            transposed = ImageOps.exif_transpose(image)
            applied_exif_transpose = transposed is not image

            clean_rgb = Image.new("RGB", transposed.size)
            clean_rgb.paste(transposed.convert("RGB"))

            if output_path is None:
                raise ValueError("No output path available for sanitized image.")

            safe_mkdir(output_path.parent)
            clean_rgb.save(
                output_path,
                format="JPEG",
                quality=quality,
                optimize=True,
                progressive=progressive,
            )

    except Exception as exc:
        result = {
            "status": "rejected",
            "reason": f"Image decode/rebuild failed: {exc}",
            "input": str(input_path),
            "scan": report["scan"],
        }
        json_dump(result, report_path, emit_stdout=emit_report)
        return result

    report["sanitization"] = {
        "status": "sanitized",
        "applied_exif_transpose": applied_exif_transpose,
        "stripped_metadata": True,
        "reencoded_from_pixels": True,
        "output_quality": quality,
        "output_progressive": progressive,
        "output_subsampling": "4:2:0",
        "policy": "Any decodable JPEG is rewritten to a new JPEG. Non-JPEG or undecodable files are rejected.",
    }
    report["output"] = {
        "path": str(output_path.resolve()),
        "size_bytes": output_path.stat().st_size,
        "sha256": sha256_file(output_path),
        "extension": output_path.suffix.lower(),
    }
    json_dump(report, report_path, emit_stdout=emit_report)
    return report


def build_jpeg_verdict(
    input_path: Path,
    output_path: Path,
    report: dict[str, Any],
) -> dict[str, Any]:
    if report.get("status") == "rejected":
        return {
            "file": input_path.name,
            "status": "rejected",
            "source": "jpeg_sanitizer",
            "reasons": [report.get("reason", "jpeg_rejected")],
            "checks": {
                "jpeg_scan": report.get("scan", {}),
            },
        }

    suspicious_flags = report.get("scan", {}).get("suspicious_flags", [])
    return {
        "file": input_path.name,
        "status": "accepted",
        "source": "jpeg_sanitizer",
        "reasons": suspicious_flags or ["jpeg_reencoded_cleanly"],
        "checks": {
            "jpeg_input": report.get("input", {}),
            "jpeg_scan": report.get("scan", {}),
            "jpeg_sanitization": report.get("sanitization", {}),
            "jpeg_output": report.get("output", {}),
        },
    }


def sanitize_for_pipeline(
    input_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    report = sanitize_one(
        input_path=input_path,
        output_path=output_path,
        report_path=None,
        max_pixels=DEFAULT_MAX_PIXELS,
        max_metadata_segment=DEFAULT_MAX_METADATA_SEGMENT,
        quality=DEFAULT_QUALITY,
        progressive=False,
        emit_report=False,
    )
    verdict = build_jpeg_verdict(input_path, output_path, report)
    if verdict["status"] == "rejected" and output_path.exists():
        output_path.unlink()
    return verdict


def iter_input_files(path: Path, recursive: bool) -> list[Path]:
    if path.is_file():
        return [path]
    if not path.is_dir():
        return []
    pattern = "**/*" if recursive else "*"
    return sorted([candidate for candidate in path.glob(pattern) if candidate.is_file()])


def summarize_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    sanitized = 0
    rejected = 0
    reasons: dict[str, int] = {}
    for result in results:
        if result.get("status") == "rejected":
            rejected += 1
            reason = result.get("reason", "unknown")
            reasons[reason] = reasons.get(reason, 0) + 1
        elif result.get("sanitization", {}).get("status") == "sanitized":
            sanitized += 1
        else:
            reasons["unknown_result_shape"] = reasons.get("unknown_result_shape", 0) + 1
    return {
        "total": len(results),
        "sanitized": sanitized,
        "rejected": rejected,
        "rejection_reasons": reasons,
    }


def print_batch_table(results: list[dict[str, Any]]) -> None:
    rows: list[tuple[str, str, str]] = []
    for result in results:
        if result.get("status") == "rejected":
            rows.append(
                (Path(result.get("input", "")).name, "rejected", result.get("reason", ""))
            )
            continue
        input_name = Path(result["input"]["path"]).name
        flags = ", ".join(result["scan"]["suspicious_flags"]) or "-"
        rows.append((input_name, "sanitized", flags))

    width_file = max([len("file")] + [len(row[0]) for row in rows]) if rows else 4
    width_status = max([len("status")] + [len(row[1]) for row in rows]) if rows else 6
    print(f"{'file'.ljust(width_file)}  {'status'.ljust(width_status)}  details")
    print(f"{'-' * width_file}  {'-' * width_status}  {'-' * 24}")
    for file_name, status, details in rows:
        print(f"{file_name.ljust(width_file)}  {status.ljust(width_status)}  {details}")


def main() -> int:
    try:
        ensure_pillow()
    except RuntimeError as exc:
        raise SystemExit(str(exc))

    parser = argparse.ArgumentParser(
        description="Sanitize one JPEG or batch-process a directory."
    )
    parser.add_argument("input", help="Input JPEG file or directory")
    parser.add_argument("output", nargs="?", help="Output JPEG file (single-file mode only)")
    parser.add_argument("--report", help="Single-file JSON report path")
    parser.add_argument("--batch", action="store_true", help="Treat input as a directory and batch-process files")
    parser.add_argument("--recursive", action="store_true", help="Recurse into subdirectories in batch mode")
    parser.add_argument("--clean-dir", default="clean", help="Directory for sanitized outputs in batch mode")
    parser.add_argument("--reject-dir", default="rejected", help="Directory for rejected originals copied aside in batch mode")
    parser.add_argument("--report-dir", default="reports", help="Directory for per-file JSON reports in batch mode")
    parser.add_argument("--manifest", default="", help="Optional path to write batch summary JSON")
    parser.add_argument("--max-pixels", type=int, default=DEFAULT_MAX_PIXELS, help="Reject images above this pixel count")
    parser.add_argument("--max-metadata-segment", type=int, default=DEFAULT_MAX_METADATA_SEGMENT, help="Flag APP/COM segments above this size")
    parser.add_argument("--quality", type=int, default=DEFAULT_QUALITY, help="JPEG output quality")
    parser.add_argument("--progressive", action="store_true", help="Write progressive JPEG output instead of baseline")
    parser.add_argument("--only-jpeg-ext", action="store_true", help="In batch mode, only attempt files with .jpg/.jpeg extensions")
    args = parser.parse_args()

    input_path = Path(args.input)

    if not args.batch and input_path.is_file():
        if not args.output:
            parser.error("Single-file mode requires an output path.")
        result = sanitize_one(
            input_path=input_path,
            output_path=Path(args.output),
            report_path=Path(args.report) if args.report else None,
            max_pixels=args.max_pixels,
            max_metadata_segment=args.max_metadata_segment,
            quality=args.quality,
            progressive=args.progressive,
        )
        return 0 if result.get("sanitization", {}).get("status") == "sanitized" else 2

    if not input_path.is_dir():
        parser.error("Batch mode requires the input path to be a directory.")

    clean_dir = Path(args.clean_dir)
    reject_dir = Path(args.reject_dir)
    report_dir = Path(args.report_dir)
    safe_mkdir(clean_dir)
    safe_mkdir(reject_dir)
    safe_mkdir(report_dir)

    files = iter_input_files(input_path, args.recursive)
    if args.only_jpeg_ext:
        files = [file_path for file_path in files if file_path.suffix.lower() in JPEG_EXTENSIONS]

    results: list[dict[str, Any]] = []
    for src in files:
        out_path = clean_dir / f"{src.stem}_clean.jpg"
        report_path = report_dir / f"{src.stem}.json"
        result = sanitize_one(
            input_path=src,
            output_path=out_path,
            report_path=report_path,
            max_pixels=args.max_pixels,
            max_metadata_segment=args.max_metadata_segment,
            quality=args.quality,
            progressive=args.progressive,
        )
        if result.get("status") == "rejected":
            reject_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, reject_dir / src.name)
        results.append(result)

    summary = summarize_results(results)
    print_batch_table(results)
    print()
    print(json.dumps(summary, indent=2, ensure_ascii=False))

    if args.manifest:
        Path(args.manifest).write_text(
            json.dumps({"summary": summary, "files": results}, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    return 0 if summary["rejected"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
