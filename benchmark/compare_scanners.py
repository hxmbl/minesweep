#!/usr/bin/env python3
"""Best-effort comparative harness for MineSweep vs Gitleaks on a local corpus.

This script is designed for reproducible local comparisons when tools are
installed and pinned by the operator. It records tool versions/commands and raw
outputs. Span-level metrics require a span-labelled ground-truth dataset; if not
provided, file-level proxies are reported with explicit limitations.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def run(cmd, cwd=None):
    p = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    return p.returncode, p.stdout, p.stderr


def tool_version(cmd):
    for args in ([cmd, "version"], [cmd, "--version"], [cmd, "-v"]):
        try:
            rc, out, err = run(args)
        except Exception:
            continue
        if rc == 0:
            return (out.strip() or err.strip()).splitlines()[0]
    return "unknown"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--minesweep", default=None)
    ap.add_argument("--gitleaks", default=None)
    ap.add_argument("--manifest", default=None)
    args = ap.parse_args()

    corpus = Path(args.corpus)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    ms = args.minesweep or shutil.which("minesweep") or "./minesweep"
    gl = args.gitleaks or shutil.which("gitleaks")

    report = {"corpus": str(corpus), "tools": {}, "runs": {}, "limitations": []}

    # MineSweep
    ms_cmd = [ms, "--json", str(corpus)]
    rc, stdout, stderr = run(ms_cmd)
    (out / "minesweep.stdout.json").write_text(stdout, encoding="utf-8")
    (out / "minesweep.stderr.txt").write_text(stderr, encoding="utf-8")
    report["tools"]["minesweep"] = {"path": ms, "version": tool_version(ms), "command": ms_cmd, "exit_code": rc}

    # Gitleaks (optional)
    if gl:
        gl_report = out / "gitleaks.report.json"
        gl_cmd = [gl, "detect", "--source", str(corpus), "--report-format", "json", "--report-path", str(gl_report), "--no-git"]
        rc, stdout, stderr = run(gl_cmd)
        (out / "gitleaks.stdout.txt").write_text(stdout, encoding="utf-8")
        (out / "gitleaks.stderr.txt").write_text(stderr, encoding="utf-8")
        report["tools"]["gitleaks"] = {"path": gl, "version": tool_version(gl), "command": gl_cmd, "exit_code": rc, "report": str(gl_report)}
    else:
        report["tools"]["gitleaks"] = {"available": False}
        report["limitations"].append("Gitleaks not installed; comparative detection metrics not produced.")

    if args.manifest and Path(args.manifest).exists():
        manifest = json.loads(Path(args.manifest).read_text())
        report["manifest"] = {"path": args.manifest, "seed": manifest.get("seed"), "file_count": len(manifest.get("files", []))}
    else:
        report["limitations"].append("No manifest provided; file-level proxy scoring unavailable.")

    report["limitations"].extend([
        "Span-level precision/recall/F1 require a span-labelled ground truth dataset (e.g. CredDetX) mapped to scanner outputs.",
        "Scan modes/configs must be aligned and pinned for fair comparison; this script does not claim equivalence automatically.",
    ])

    (out / "comparison-metadata.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"out": str(out), "gitleaks_available": bool(gl)}, indent=2))


if __name__ == "__main__":
    main()
