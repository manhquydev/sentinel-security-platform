#!/usr/bin/env python3
"""Evaluate comparative corpus admission gates for an inventory (never auto-admits)."""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from workbench.corpus_gates import CorpusGateViolation, evaluate_inventory_admission


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument(
        "--gate-evidence",
        type=Path,
        help="optional JSON object of gate evidence (truth/license/contamination/control_audit/calibration)",
    )
    parser.add_argument("--output", type=Path, help="exclusive write path for the admission ledger")
    args = parser.parse_args()
    try:
        inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
        evidence = None
        if args.gate_evidence is not None:
            evidence = json.loads(args.gate_evidence.read_text(encoding="utf-8"))
        ledger = evaluate_inventory_admission(inventory, gate_evidence=evidence)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, CorpusGateViolation) as error:
        print(f"FATAL: {error}", file=sys.stderr)
        return 2
    text = json.dumps(ledger, indent=2, sort_keys=True)
    print(text)
    if args.output is not None:
        if args.output.exists() or args.output.is_symlink():
            print("FATAL: refusing to replace existing ledger", file=sys.stderr)
            return 2
        args.output.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{args.output.name}.", dir=args.output.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
                handle.write("\n")
            os.chmod(temporary, 0o600)
            os.link(temporary, args.output)
            os.chmod(args.output, 0o600)
        finally:
            Path(temporary).unlink(missing_ok=True)
    return 0 if ledger["admission_decision"] == "not-admitted" or ledger["admission_decision"] == "admitted-ready-for-catalog" else 2


if __name__ == "__main__":
    raise SystemExit(main())
