from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import tempfile
from typing import Sequence

from .evidence import run_pipeline
from .renderer import render_markdown
from .validator import MissingDependencyError


class QuietArgumentParser(argparse.ArgumentParser):
    """Argument parser that does not echo invalid argument inputs and exits with code 1."""

    def error(self, message: str) -> None:
        sys.stderr.write("Error: Invalid arguments.\n")
        sys.exit(1)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = QuietArgumentParser(
        prog="trivy-remediation-evidence",
        description="Deterministic vulnerability remediation evidence collector and comparator.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    compare_parser = subparsers.add_parser(
        "compare",
        help="Compare before and after scan reports and manifests.",
    )
    compare_parser.add_argument(
        "--before",
        required=True,
        help="Path to before scan report JSON.",
    )
    compare_parser.add_argument(
        "--after",
        required=True,
        help="Path to after scan report JSON.",
    )
    compare_parser.add_argument(
        "--before-manifest",
        required=True,
        help="Path to before manifest JSON.",
    )
    compare_parser.add_argument(
        "--after-manifest",
        required=True,
        help="Path to after manifest JSON.",
    )
    compare_parser.add_argument(
        "--out-dir",
        required=True,
        help="Directory to write output files (evidence.json, report.ja.md, report.en.md).",
    )

    return parser.parse_args(argv)


def _check_conflicts_and_existence(
    input_paths: list[Path],
    output_files: list[Path],
) -> bool:
    """Check if any output file exists or conflicts with input files.

    Returns False if there is a conflict or existing output file, True otherwise.
    """
    # 1. Output file must not already exist
    for out_p in output_files:
        if out_p.exists():
            return False

    # 2. Input file and output file must not be identical (path or same file)
    resolved_inputs: list[Path] = []
    for inp in input_paths:
        try:
            resolved_inputs.append(inp.resolve())
        except Exception:
            resolved_inputs.append(inp)

    for out_p in output_files:
        try:
            res_out = out_p.resolve()
        except Exception:
            res_out = out_p

        for inp in resolved_inputs:
            if inp == res_out:
                return False
            if inp.exists() and out_p.exists():
                try:
                    if os.path.samefile(inp, out_p):
                        return False
                except (OSError, ValueError):
                    pass

    return True


def run_compare(args: argparse.Namespace) -> int:
    before_report = Path(args.before)
    after_report = Path(args.after)
    before_manifest = Path(args.before_manifest)
    after_manifest = Path(args.after_manifest)
    out_dir = Path(args.out_dir)

    input_paths = [before_report, after_report, before_manifest, after_manifest]
    out_evidence = out_dir / "evidence.json"
    out_ja = out_dir / "report.ja.md"
    out_en = out_dir / "report.en.md"
    output_files = [out_evidence, out_ja, out_en]

    # Pre-check existence and path conflict
    if not _check_conflicts_and_existence(input_paths, output_files):
        sys.stderr.write("Error: Output already exists or path conflict.\n")
        return 1

    # Run pipeline in memory
    try:
        evidence_dict, exit_code, json_bytes = run_pipeline(
            before_report_path=before_report,
            after_report_path=after_report,
            before_manifest_path=before_manifest,
            after_manifest_path=after_manifest,
        )
    except MissingDependencyError:
        sys.stderr.write("Error: Missing required dependency: jsonschema.\n")
        return 1
    except Exception:
        sys.stderr.write("Error: Failed to process inputs due to I/O or schema error.\n")
        return 1

    # Render Markdown in memory
    try:
        ja_md = render_markdown(evidence_dict, language="ja")
        en_md = render_markdown(evidence_dict, language="en")
        ja_bytes = ja_md.encode("utf-8")
        en_bytes = en_md.encode("utf-8")
    except Exception:
        sys.stderr.write("Error: Failed to render markdown reports.\n")
        return 1

    # Staging in temporary directory, then publish to final output directory
    artifacts = [
        ("evidence.json", json_bytes),
        ("report.ja.md", ja_bytes),
        ("report.en.md", en_bytes),
    ]

    published_files: list[Path] = []
    try:
        with tempfile.TemporaryDirectory() as tmp_dir_str:
            stage_dir = Path(tmp_dir_str)

            # 1. Staging: Write, flush, and close all 3 files completely in temporary directory
            for fname, data_bytes in artifacts:
                stg_path = stage_dir / fname
                with open(stg_path, "wb") as f_stg:
                    f_stg.write(data_bytes)
                    f_stg.flush()

            # 2. Publish: Transfer each file to final path exclusively (no-overwrite)
            out_dir.mkdir(parents=True, exist_ok=True)
            for fname, _ in artifacts:
                stg_path = stage_dir / fname
                target_path = out_dir / fname

                # Exclusive creation: prevents overwriting even under race conditions
                fd = os.open(target_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o666)
                # Track ownership immediately upon creation on disk
                published_files.append(target_path)
                try:
                    payload = stg_path.read_bytes()
                    with open(fd, "wb", closefd=True) as f_out:
                        f_out.write(payload)
                        f_out.flush()
                except Exception:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                    raise
    except Exception:
        # Rollback: delete only files created in this invocation
        for p in published_files:
            try:
                if p.is_file():
                    p.unlink()
            except OSError:
                pass
        sys.stderr.write("Error: Failed to write outputs.\n")
        return 1

    return exit_code


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        if args.command == "compare":
            return run_compare(args)
        sys.stderr.write("Error: Invalid command.\n")
        return 1
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 1
    except Exception:
        sys.stderr.write("Error: Unexpected runtime error.\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
