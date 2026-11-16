#!/usr/bin/env python3
import argparse, json
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--manifest', required=True)
    ap.add_argument('--findings', required=True)
    ap.add_argument('--benchmark', required=True)
    ap.add_argument('--out', required=True)
    args = ap.parse_args()

    manifest = json.loads(Path(args.manifest).read_text())
    findings_doc = json.loads(Path(args.findings).read_text()) if Path(args.findings).exists() else {}
    bench = json.loads(Path(args.benchmark).read_text()) if Path(args.benchmark).exists() else {}
    findings = findings_doc.get('findings', []) if isinstance(findings_doc, dict) else []

    files = manifest.get('files', [])
    pos_files = [f for f in files if str(f.get('path','')).startswith('positives/')]
    neg_files = [f for f in files if str(f.get('path','')).startswith('negatives/') or str(f.get('path','')).startswith('docs/')]
    files_with_findings = set(f.get('file') for f in findings if isinstance(f, dict) and f.get('file'))
    # normalize to corpus-relative where possible
    norm_hit = set()
    for p in files_with_findings:
        p = str(p).replace('\\', '/')
        for f in files:
            rel = f['path']
            if p.endswith('/' + rel) or p == rel or p.endswith(rel):
                norm_hit.add(rel)

    tp_files = [f['path'] for f in pos_files if f['path'] in norm_hit]
    fn_files = [f['path'] for f in pos_files if f['path'] not in norm_hit]
    fp_files = [f['path'] for f in neg_files if f['path'] in norm_hit]

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
            'note': 'File-level proxy only; not span-level precision/recall/F1. Use as a reproducible baseline until span-labelled comparative harness is complete.',
        },
        'performance': bench,
        'limitations': [
            'Synthetic MineSweep-owned corpus only; no CredDetX integration or pinned gitleaks/TruffleHog comparison yet.',
            'Metrics are file-level proxies, not span-level P/R/F1.',
            'Real-repository corpus and injected-canary evaluation are not included.',
            'Results should not be presented as proof of superiority over other scanners.',
        ],
    }
    Path(args.out).write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
