"""agent/approve.py — the HUMAN-run, OUT-OF-PROCESS HITL approval CLI (Week-8 PR1, RD1).

This is the ONLY module in the repository that loads an Ed25519 PRIVATE signing key or calls
`.sign()`. It is never imported by `agent/supervisor.py` (the graph runtime) or any other
graph-side module — the private key path is a REQUIRED `--key-file` argument a human types at
invocation time, never a default, never read from an agent-owned config path, so nothing running
as the agent's own process (including a prompt-injected exploit/recon node) can reach it. See
`agent/approval.py`'s module docstring for the verify-only side the graph actually runs, and the
honest single-shared-user-host residual documented there.

There is no private key committed anywhere in this repository, including `agent/keys/` (which
holds ONLY the public verify key) — see `agent/keys/README.md` for how to generate your own
approver keypair out-of-band and point `--key-file` at it.

Usage (interactive):
    rag/.venv/bin/python -m agent.approve --proposal-file proposal.json \\
        --key-file /path/to/approver-private.pem --approver "j.doe"

Usage (scripted, e.g. tests):
    rag/.venv/bin/python -m agent.approve --proposal-file proposal.json \\
        --key-file /path/to/approver-private.pem --approver "j.doe" --decision approve --out token.json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import approval


def load_private_key(path: str) -> Ed25519PrivateKey:
    """Load the approver's PRIVATE signing key. Called ONLY from this module — see the module
    docstring for why that boundary is the load-bearing part of RD1."""
    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return key


def sign_token(proposal: dict[str, Any], private_key: Ed25519PrivateKey, *,
               ttl_seconds: int = approval.DEFAULT_TTL_SECONDS) -> approval.ApprovalToken:
    """Mint a signed ApprovalToken bound to `proposal`'s EXACT current content (endpoint/vuln_class
    facts + technique/justification narrative — the same fields a human just read above). A fresh
    random nonce makes the token single-use once `agent.approval.verify_approval` consumes it."""
    payload = {
        "proposal_id": approval.proposal_id(proposal),
        "proposal_hash": approval.proposal_content_hash(proposal),
        "issued_at": time.time(),
        "ttl_seconds": ttl_seconds,
        "nonce": uuid.uuid4().hex,
    }
    signature = private_key.sign(approval.canonical_payload(payload)).hex()
    return approval.ApprovalToken(signature=signature, **payload)


def _read_proposal(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a single JSON object (one ExploitProposal)")
    return data


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(
        "Human-run HITL approval CLI (Week-8 PR1). Reads one pending ExploitProposal, records an "
        "Approve/Reject decision in the audit ledger, and — on Approve — mints a signed, "
        "single-use, proposal-bound token the Supervisor graph's state_change_node will verify."))
    ap.add_argument("--proposal-file", required=True,
                    help="path to one ExploitProposal JSON object")
    ap.add_argument("--key-file", required=True,
                    help="path to the approver's Ed25519 PRIVATE signing key (PEM), supplied "
                         "out-of-band — there is no default; the agent never reads this path")
    ap.add_argument("--approver", required=True,
                    help="human approver identity recorded in the audit trail")
    ap.add_argument("--decision", choices=("approve", "reject"),
                    help="non-interactive decision; omit to be prompted")
    ap.add_argument("--ttl", type=int, default=approval.DEFAULT_TTL_SECONDS,
                    help=f"token validity window in seconds (default {approval.DEFAULT_TTL_SECONDS})")
    ap.add_argument("--out", help="write the minted token JSON here (default: stdout)")
    ap.add_argument("--db", default=approval.DEFAULT_DB_PATH, help="audit ledger sqlite path")
    args = ap.parse_args(argv)

    proposal = _read_proposal(args.proposal_file)
    pid = approval.proposal_id(proposal)
    print(f"Pending proposal {pid!r}: {proposal.get('endpoint')} [{proposal.get('vuln_class')}]")
    print(f"  technique: {proposal.get('technique')}")
    print(f"  justification: {proposal.get('justification')}")
    print(f"  expected_impact: {proposal.get('expected_impact')}")

    decision = args.decision
    if decision is None:
        answer = input("Approve this proposal? [y/N] ").strip().lower()
        decision = "approve" if answer in ("y", "yes") else "reject"

    ledger = approval.ApprovalLedger(args.db)
    try:
        if decision == "reject":
            ledger.record(proposal_id=pid, decision="reject", action="none", approver=args.approver)
            print("Recorded: REJECT — no token minted.")
            return 0

        private_key = load_private_key(args.key_file)
        token = sign_token(proposal, private_key, ttl_seconds=args.ttl)
        ledger.record(proposal_id=pid, decision="approve", action="token-issued",
                      approver=args.approver)
        token_json = json.dumps(token.to_dict(), indent=2)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(token_json)
            print(f"Recorded: APPROVE — token written to {args.out}")
        else:
            print("Recorded: APPROVE — token:")
            print(token_json)
        return 0
    finally:
        ledger.close()


if __name__ == "__main__":
    sys.exit(main())
