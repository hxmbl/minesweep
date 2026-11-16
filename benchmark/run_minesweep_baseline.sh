#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$ROOT/benchmark/results}"
CORPUS_DIR="$ROOT/benchmark/corpus/synthetic-v1"
mkdir -p "$OUT_DIR"

python3 "$ROOT/benchmark/generate_synthetic_corpus.py" --out "$CORPUS_DIR" >/dev/null

if command -v minesweep >/dev/null 2>&1; then
  MS=(minesweep)
elif [[ -x "$ROOT/minesweep" ]]; then
  MS=("$ROOT/minesweep")
else
  echo "minesweep binary not found; build with: go build -o minesweep ./cmd/minesweep" >&2
  exit 2
fi

# Performance benchmark (existing CLI benchmark mode)
"${MS[@]}" --benchmark --runs 3 --json "$CORPUS_DIR" > "$OUT_DIR/minesweep-benchmark.json"

# Detection output (JSON report) for quality analysis
"${MS[@]}" --json "$CORPUS_DIR" > "$OUT_DIR/minesweep-findings.json" || true

python3 "$ROOT/benchmark/summarize_minesweep.py" \
  --manifest "$CORPUS_DIR/manifest.json" \
  --findings "$OUT_DIR/minesweep-findings.json" \
  --benchmark "$OUT_DIR/minesweep-benchmark.json" \
  --out "$OUT_DIR/minesweep-summary.json"

echo "Wrote benchmark artifacts to $OUT_DIR"
