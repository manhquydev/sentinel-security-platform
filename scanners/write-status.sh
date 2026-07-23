#!/usr/bin/env bash
# Write a scanner's status sidecar next to its report.
#
#   write-status.sh <tool> <raw_report> <status> <contact_proven> <exit> <detail>
#
# The four wrappers overload their exit-code namespace — the same integer means
# "target rejected" in one and "scanner error" in another — so an orchestrator
# cannot key on exit codes. It keys on this sidecar instead: a fixed JSON schema
# written atomically to `<raw_report>.status.json`, so a reader never sees a half
# file.
#
# `reported` is counted from the RAW report, before redaction, because that is
# the ground truth a completeness gate compares DefectDojo's accounting against.
# A missing or unparseable report yields -1, which the schema treats as an error
# regardless of the status argument.
#
# This is shared rather than inlined so the four wrappers cannot drift in how they
# count or serialise. It is the contract, in one place.
set -euo pipefail

tool="${1:?tool required}"
raw="${2:?raw report path required}"
status="${3:?status required (ok|error)}"
contact="${4:?contact_proven required (true|false)}"
exit_code="${5:?exit code required}"
detail="${6:-}"

sidecar="$raw.status.json"
tmp="$(mktemp "$(dirname "$sidecar")/.status.XXXXXX")"

python3 - "$tool" "$raw" "$status" "$contact" "$exit_code" "$detail" "$tmp" <<'PY'
import json, os, sys

tool, raw, status, contact, exit_code, detail, tmp = sys.argv[1:8]


def count(tool, path):
    """Findings in the RAW report. -1 if it is missing or unparseable."""
    try:
        if tool == "nuclei":
            with open(path) as fh:
                return sum(1 for line in fh if line.strip())
        with open(path) as fh:
            doc = json.load(fh)
        if tool == "semgrep":
            return len(doc.get("results") or [])
        if tool == "trivy":
            n = 0
            for result in doc.get("Results") or []:
                for key in ("Secrets", "Misconfigurations", "Vulnerabilities"):
                    n += len(result.get(key) or [])
            return n
        if tool == "zap":
            # ZAP is XML, not JSON — handled below, this path is unreachable.
            return -1
    except Exception:
        return -1
    return -1


def count_zap(path):
    import xml.etree.ElementTree as ET
    try:
        root = ET.parse(path).getroot()
    except Exception:
        return -1
    return sum(1 for _ in root.iter("alertitem"))


reported = count_zap(raw) if tool == "zap" else count(tool, raw)

# A report that cannot be counted is not a success no matter what the caller says:
# a scanner that produced no readable output did not run cleanly.
if reported < 0:
    status = "error"

doc = {
    "tool": tool,
    "status": status if status in ("ok", "error") else "error",
    "exit": int(exit_code),
    "reported": reported,
    "contact_proven": contact == "true",
    "detail": detail,
}
with open(tmp, "w") as fh:
    json.dump(doc, fh)
PY

# Atomic publish: a reader either sees the previous sidecar or this one, never a
# partial write.
mv -f "$tmp" "$sidecar"
