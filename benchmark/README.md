# MineSweep benchmark harness (STRM-649 progress)

This directory contains a **reproducible baseline harness** for MineSweep performance and file-level detection proxies on a deterministic synthetic corpus.

## What this provides now

- Deterministic MineSweep-owned synthetic corpus generator: `generate_synthetic_corpus.py`
  - Includes provider-like credentials, generic assignments, PEM/SSH material, placeholders, hashes, UUID-like values, and documentation examples/hard negatives.
  - Generated deterministically from a fixed seed; no real credentials.
- One-command MineSweep baseline run: `run_minesweep_baseline.sh [results_dir]`
  - Generates/refreshes corpus at `benchmark/corpus/synthetic-v1`
  - Runs `minesweep --benchmark --runs 3 --json` and `minesweep --json`
  - Produces `minesweep-benchmark.json`, `minesweep-findings.json`, `minesweep-summary.json`
- Memory reporting in `--benchmark` distinguishes total allocation/run, retained heap (mean/max), and process peak RSS when available.

## Reproduce

```bash
# from repo root
go build -o minesweep ./cmd/minesweep
./benchmark/run_minesweep_baseline.sh ./benchmark/results
```

## Limitations (important)

This is **not yet** the full STRM-649 acceptance target:
- No pinned head-to-head comparison against Gitleaks/TruffleHog in this harness yet.
- No CredDetX integration and no span-level precision/recall/F1, per-category recall, or FP-per-10k-files reporting.
- No separately evaluated reviewed real-repository corpus or injected-canary evaluation.
- File-level TP/FN/FP in `minesweep-summary.json` are proxies only and must not be presented as proof of superiority.

## Planned extensions

- Add pinned tool runners for Gitleaks (and optionally TruffleHog) with version/config capture.
- Integrate a span-labelled corpus (e.g. CredDetX) with recorded revision/hash/licensing.
- Compute span-level metrics, per-category recall, hard-negative FP rates, confidence intervals/repeated runs where justified.
- Preserve raw per-finding outputs and full provenance/environment metadata.
