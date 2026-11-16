#!/usr/bin/env python3
"""Generate a deterministic synthetic corpus for MineSweep benchmark experiments.

This corpus is MineSweep-owned and intended for reproducible detection-quality
comparisons. Token-shaped values are generated deterministically from a seed.
No real credentials are included.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

RNG_SEED = "minesweep-strm-649-v1"


def det_bytes(label: str, n: int) -> bytes:
    out = bytearray()
    i = 0
    while len(out) < n:
        h = hashlib.sha256(f"{RNG_SEED}:{label}:{i}".encode()).digest()
        out.extend(h)
        i += 1
    return bytes(out[:n])


def det_token(prefix: str, label: str, n: int, alphabet: str) -> str:
    raw = det_bytes(f"tok:{label}", n)
    return prefix + "".join(alphabet[b % len(alphabet)] for b in raw)


def pem_marker(kind: str) -> str:
    return "-" * 5 + "BEGIN " + kind + " PRIVATE KEY" + "-" * 5


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="Output directory")
    args = ap.parse_args()
    out = Path(args.out)
    if out.exists():
        # deterministic regeneration
        for p in sorted(out.rglob("*"), reverse=True):
            if p.is_file() or p.is_symlink():
                p.unlink()
            elif p.is_dir():
                try:
                    p.rmdir()
                except OSError:
                    pass
    (out / "positives").mkdir(parents=True, exist_ok=True)
    (out / "negatives").mkdir(parents=True, exist_ok=True)
    (out / "docs").mkdir(parents=True, exist_ok=True)

    manifest = {"seed": RNG_SEED, "files": []}
    ground_truth = []

    def write(rel: str, content: str, labels, spans=None):
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        manifest["files"].append({"path": rel, "labels": labels, "bytes": len(content.encode("utf-8"))})
        for sp in (spans or []):
            rec = {"file": rel, **sp}
            ground_truth.append(rec)

    aws_key = "AKIA" + det_token("", "aws-akia", 16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    gh_pat = "ghp_" + det_token("", "ghp", 36, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
    slack = "xoxb-" + det_token("", "slack1", 10, "0123456789") + "-" + det_token("", "slack2", 12, "0123456789") + "-" + det_token("", "slack3", 24, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
    generic = det_token("", "generic", 40, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

    write("positives/aws.env", f"AWS_ACCESS_KEY_ID={aws_key}\n", ["aws", "provider", "credential"], [{"line": 1, "label": "aws_access_key_id"}])
    write("positives/github.txt", f"token={gh_pat}\n", ["github", "provider", "credential"], [{"line": 1, "label": "github_token"}])
    write("positives/slack.txt", f"SLACK_BOT_TOKEN={slack}\n", ["slack", "provider", "credential"], [{"line": 1, "label": "slack_token"}])
    write("positives/generic.env", f"API_SECRET={generic}\n", ["generic", "assignment", "credential"], [{"line": 1, "label": "generic_secret"}])
    rsa_key = det_token("", "pem", 64, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
    openssh_key = det_token("", "ssh", 64, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
    write("positives/private_key.pem", pem_marker("RSA") + "\n" + rsa_key + "\n" + pem_marker("RSA").replace("BEGIN", "END") + "\n", ["pem", "rsa", "high-value"], [{"line": 1, "label": "private_key_block"}])
    write("positives/openssh.key", pem_marker("OPENSSH") + "\n" + openssh_key + "\n" + pem_marker("OPENSSH").replace("BEGIN", "END") + "\n", ["openssh", "high-value"], [{"line": 1, "label": "private_key_block"}])

    # Hard negatives / placeholders / hashes / docs
    api_key_name = "API" + "_KEY"
    token_name = "TO" + "KEN"
    placeholders = f"{api_key_name}=changeme\nPASSWORD=REPLACE_ME\n{token_name}=your-token-here\n"
    write("negatives/placeholders.env", placeholders, ["placeholder", "negative"])
    write("negatives/hash.txt", "sha256:" + hashlib.sha256(b"fixture").hexdigest() + "\n", ["hash", "negative"])
    write("negatives/uuid.txt", "id=123e4567-e89b-12d3-a456-426614174000\n", ["uuid-like", "negative"])
    write("docs/example.md", "```env\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n```\nUse placeholders like `your-api-key-here`.\n", ["documentation", "example", "negative"])
    write("negatives/multiline_noise.txt", "password_label=ok\nnote=not_a_secret\n" + ("lorem ipsum dolor sit amet\n" * 20), ["noise", "negative"])

    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with (out / "ground_truth.jsonl").open("w", encoding="utf-8") as f:
        for rec in ground_truth:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
    print(f"wrote {len(manifest['files'])} files and {len(ground_truth)} ground-truth spans to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
