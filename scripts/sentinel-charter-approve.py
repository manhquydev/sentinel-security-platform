#!/usr/bin/env python3
"""Human-facing signer; it displays the immutable request before signing any decision."""
import argparse, json
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from agent.charter_requests import CharterRequestError, load_spec
from agent.charter_approval import sign, digest

parser = argparse.ArgumentParser()
parser.add_argument("spec"); parser.add_argument("--key-file", required=True)
parser.add_argument("--decision", choices=("approve", "reject", "revoke")); parser.add_argument("--out", required=True)
args = parser.parse_args()
try:
    spec = load_spec(json.loads(Path(args.spec).read_text(encoding="utf-8")))
except (CharterRequestError, OSError, ValueError, json.JSONDecodeError):
    raise SystemExit(2)
print(f"Request {spec.request_id}\n  {spec.method} {spec.path}{'?' + spec.query if spec.query else ''}\n"
      f"  body: {spec.body!r}\n  purpose: {spec.purpose}\n  expiry: {spec.expires_at}\n"
      f"  immutable digest: {digest(spec)}")
decision = args.decision or ("approve" if input("Approve this fixed request? [y/N] ").lower() in {"y", "yes"} else "reject")
key = serialization.load_pem_private_key(Path(args.key_file).read_bytes(), password=None)
Path(args.out).write_text(json.dumps(sign(spec, key, decision=decision).__dict__, sort_keys=True) + "\n")
