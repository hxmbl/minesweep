#!/usr/bin/env python3
import argparse, json
from pathlib import Path


def _norm_path(p):
    p = str(p or '').replace('\\', '/')
    return p


def _rel_match(finding_path, rel):
    p = _norm_path(finding_path)
    rel = _norm_path(rel)
    return p == rel or p.endswith('/' + rel) or p.endswith(rel)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--manifest', required=True)
    ap.add_argument('--findings', required=True)
    ap.add_argument('--benchmark', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--ground-truth', required=False)
    args = ap.parse_args()

    manifest = json.loads(Path(args.manifest).read_text())
    findings_doc = json.loads(Path(args.findings).read_text()) if Path(args.findings).exists() else {}
    bench = json.loads(Path(args.benchmark).read_text()) if Path(args.benchmark).exists() else {}
    findings = findings_doc.get('findings', []) if isinstance(findings_doc, dict) else []

    files = manifest.get('files', [])
    pos_files = [f for f in files if str(f.get('path','')).startswith('positives/')]
    neg_files = [f for f in files if str(f.get('path','')).startswith('negatives/') or str(f.get('path','')).startswith('docs/')]
    files_with_findings = set(f.get('file') for f in findings if isinstance(f, dict) and f.get('file'))
    norm_hit = set()
    for p in files_with_findings:
        for f in files:
            rel = f['path']
            if _rel_match(p, rel):
                norm_hit.add(rel)

    tp_files = [f['path'] for f in pos_files if f['path'] in norm_hit]
    fn_files = [f['path'] for f in pos_files if f['path'] not in norm_hit]
    fp_files = [f['path'] for f in neg_files if f['path'] in norm_hit]

    span_metrics = None
    gt_path = Path(args.ground_truth) if args.ground_truth else Path(args.manifest).with_name('ground_truth.jsonl')
    if gt_path.exists():
        truth = []
        for line in gt_path.read_text(encoding='utf-8').splitlines():
            if line.strip():
                truth.append(json.loads(line))
        T=set(); P=set()
        for t in truth:
            T.add((_norm_path(t.get('file')), int(t.get('line') or 0)))
        for f in findings:
            if not isinstance(f, dict):
                continue
            fpath = _norm_path(f.get('file'))
            line = int(f.get('line') or 0)
            # map to corpus-relative file if possible
            rel = None
            for mf in files:
                if _rel_match(fpath, mf['path']):
                    rel = mf['path']
                    break
            if rel is not None:
                P.add((rel, line))
            else:
                P.add((fpath, line))
        tp=len(T&P); fp=len(P-T); fn=len(T-P)
        prec=tp/(tp+fp) if (tp+fp) else 0.0
        rec=tp/(tp+fn) if (tp+fn) else 0.0
        f1=(2*prec*rec/(prec+rec)) if (prec+rec) else 0.0
        span_metrics = {
            'truth_spans': len(T), 'pred_spans': len(P), 'tp': tp, 'fp': fp, 'fn': fn,
            'precision': prec, 'recall': rec, 'f1': f1,
            'note': 'Line-level span proxy metrics on MineSweep synthetic corpus (ground_truth.jsonl). Not a substitute for external span-labelled corpora like CredDetX or cross-tool normalized comparisons.'
        }

    summary = {
        'corpus': {
            'seed': manifest.get('seed'),
            'total_files': len(files),
            'positive_files': len(pos_files),
            'negative_or_hard_negative_files': len(neg_files),
        },
        'detection_proxy_file_level': {
            'tp_files': len(tp_files),
            'fn_files': len(fn_files),
            'fp_files': len(fp_files),
            'tp_file_paths': tp_files,
            'fn_file_paths': fn_files,
            'fp_file_paths': fp_files,
            'total_findings': len(findings),
        },
        'performance': bench,
        'limitations': [
            'Synthetic MineSweep-owned corpus only; no CredDetX integration or pinned gitleaks/TruffleHog comparison in this baseline run.',
            'Real-repository corpus and injected-canary evaluation are not included.',
            'Results should not be presented as proof of superiority over other scanners.',
        ],
    }
    if span_metrics:
        summary['detection_span_proxy'] = span_metrics
    Path(args.out).write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
