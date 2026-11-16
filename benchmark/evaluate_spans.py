#!/usr/bin/env python3
"""Compute span-level detection metrics when ground truth and predictions are provided.

Inputs are JSONL files with objects containing at least:
  {"file": "path", "line": 1, "value": "secret"} (value optional but improves matching)

This is a generic evaluator to support STRM-649 workflows (e.g. CredDetX-derived
exports). It does not fetch datasets; provenance/revision must be tracked by caller.
"""
from __future__ import annotations

import argparse, json
from pathlib import Path


def load_jsonl(path):
    items = []
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line:
            continue
        items.append(json.loads(line))
    return items


def key(obj):
    # normalize path-ish keys and line numbers; value match optional/soft in caller
    f = str(obj.get('file') or obj.get('path') or '')
    f = f.replace('\\', '/')
    line = obj.get('line') or obj.get('start_line') or 0
    try:
        line = int(line)
    except Exception:
        line = 0
    val = obj.get('value')
    return (f, line, str(val) if val is not None else None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--truth', required=True)
    ap.add_argument('--pred', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--match-value', action='store_true', help='Require value equality in addition to file+line')
    args = ap.parse_args()

    truth = load_jsonl(args.truth)
    pred = load_jsonl(args.pred)

    def norm(items):
        out = set()
        for o in items:
            f,l,v = key(o)
            if not args.match_value:
                v = None
            # compare by basename+line fallback too by storing both? keep simple normalized suffixes
            out.add((f, l, v))
            if '/' in f:
                out.add((f.split('/')[-1], l, v))
        return out

    tset = norm(truth)
    pset = norm(pred)
    # approximate matching on full normalized tuples (includes basename duplicates)
    # compute on primary tuples only
    def primary(items):
        s=set()
        for o in items:
            f,l,v=key(o)
            if not args.match_value: v=None
            s.add((f,l,v))
        return s
    T=primary(truth); P=primary(pred)
    tp = len(T & P)
    fp = len(P - T)
    fn = len(T - P)
    prec = tp/(tp+fp) if (tp+fp) else 0.0
    rec = tp/(tp+fn) if (tp+fn) else 0.0
    f1 = (2*prec*rec/(prec+rec)) if (prec+rec) else 0.0
    out = {
        'truth_count': len(T), 'pred_count': len(P), 'tp': tp, 'fp': fp, 'fn': fn,
        'precision': prec, 'recall': rec, 'f1': f1,
        'match_value': bool(args.match_value),
        'note': 'Generic span/file-line evaluator; mapping/normalization must match dataset conventions for authoritative results.'
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True)+'\n')
    print(json.dumps(out, indent=2))

if __name__ == '__main__':
    main()
