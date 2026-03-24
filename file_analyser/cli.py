from __future__ import annotations

import argparse

from .pipeline import analyse_files


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="file-analyser",
        description="Pipeline de triagem de PDFs e JPEGs.",
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="Ficheiro(s) PDF/JPEG a analisar. Se omitido, usa --incoming.",
    )
    parser.add_argument(
        "--incoming",
        action="store_true",
        help="Analisa todos os ficheiros suportados na pasta incoming/.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.targets and not args.incoming:
        parser.error("indica um PDF ou usa --incoming")

    outcomes = analyse_files(args.targets, use_incoming=args.incoming)
    for outcome in outcomes:
        status = outcome.verdict.get("status", "unknown")
        source = outcome.verdict.get("source", "unknown")
        print(
            f"{outcome.input_pdf.name}: {status} via {source} -> {outcome.destination_path}"
        )
    return 0
