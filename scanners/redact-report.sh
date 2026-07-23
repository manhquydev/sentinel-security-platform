#!/usr/bin/env bash
# Parser-aware secret redaction for native scanner reports (phase-03).
#
#   redact-report.sh <scan_type> <input_file> <output_file>
#   scan_type ∈ zap | nuclei | semgrep | trivy
#
# WHITELIST design (corrected after code review 2026-07-23). Earlier versions
# blacklisted known secret-bearing fields and leaked through un-enumerated ones
# (ZAP evidence/otherinfo, Nuclei curl-command/meta, Semgrep message/fix/
# dataflow_trace, Trivy misconfig code). The rule now is the inverse and the only
# one that can satisfy "no value we did not enumerate leaks": emit ONLY the
# locator/metadata fields DefectDojo needs to parse + dedup, and DROP everything
# else. A new secret-bearing field added upstream is dropped by default, not kept.
#
# Preserved locators (what endpoint/file dedup hashes on):
#   ZAP     uri, method, param, name, riskcode, cweid, pluginid
#   Nuclei  template-id, type, host, matched-at, info.{name,severity,tags,description}
#   Semgrep check_id, path, start, end, extra.{severity,metadata}
#   Trivy   Target, Class, Type + per-finding id/severity/title/line (NO Match/Code)
#
# For Nuclei this MUST run BEFORE any JSONL→JSON conversion.
set -euo pipefail

scan_type="${1:?scan_type required (zap|nuclei|semgrep|trivy)}"
input="${2:?input file required}"
output="${3:?output file required}"

[ -r "$input" ] || { echo "redact: cannot read $input" >&2; exit 2; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "redact: missing dependency: $1" >&2; exit 3; }; }

case "$scan_type" in
  zap)
    # XML whitelist rebuild: keep only safe alert/instance locator elements,
    # drop request/response/evidence/otherinfo/attack and anything else.
    need python3
    python3 - "$input" "$output" <<'PY'
import sys, xml.etree.ElementTree as ET
inp, outp = sys.argv[1], sys.argv[2]
# Elements safe to keep at each level (locators + classification only).
ALERT_KEEP = {"pluginid","alertRef","alert","name","riskcode","confidence",
              "riskdesc","cweid","wascid","sourceid"}
INST_KEEP  = {"uri","method","param"}  # NOT attack/evidence/otherinfo/req/resp
try:
    tree = ET.parse(inp); root = tree.getroot()
except Exception as e:
    print(f"redact(zap): unparseable XML: {e}", file=sys.stderr); sys.exit(5)
for alertitem in root.iter("alertitem"):
    for child in list(alertitem):
        if child.tag == "instances":
            for inst in child.iter("instance"):
                for f in list(inst):
                    if f.tag not in INST_KEEP:
                        inst.remove(f)
        elif child.tag not in ALERT_KEEP:
            alertitem.remove(child)
tree.write(outp, encoding="utf-8", xml_declaration=True)
PY
    ;;
  nuclei)
    need jq
    # Build a NEW object per JSONL line with only whitelisted keys.
    jq -c '{
      "template-id": .["template-id"],
      "template": .template,
      "type": .type,
      "host": .host,
      "matched-at": .["matched-at"],
      "info": (if .info then {name: .info.name, severity: .info.severity,
                              tags: .info.tags, description: .info.description} else null end),
      "timestamp": .timestamp
    }' "$input" >"$output"
    ;;
  semgrep)
    need jq
    # message + lines can interpolate the matched secret, but the DefectDojo
    # parser requires them — so keep the KEYS with a constant redacted VALUE
    # (not pass-through content) and DROP metavars/fix/rendered_fix/dataflow_trace
    # (secret-bearing and not needed to parse). Locators (check_id/path/start/end)
    # pass through.
    jq '{
      version: .version,
      results: [ .results[]? | {
        check_id: .check_id,
        path: .path,
        start: .start,
        end: .end,
        extra: {
          message: "[REDACTED — see check_id]",
          lines: "[REDACTED]",
          severity: .extra.severity,
          metadata: .extra.metadata
        }
      } ],
      errors: []
    }' "$input" >"$output"
    ;;
  trivy)
    need jq
    # Keep Target/Class/Type + per-finding locators/classification; drop every
    # code/match/context field across Vulnerabilities, Secrets, Misconfigurations.
    jq '{
      SchemaVersion: .SchemaVersion,
      ArtifactName: .ArtifactName,
      ArtifactType: .ArtifactType,
      Results: [ .Results[]? | {
        Target: .Target,
        Class: .Class,
        Type: .Type,
        Vulnerabilities: [ (.Vulnerabilities // [])[] | {
          VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Severity, Title } ],
        Secrets: [ (.Secrets // [])[] | {
          RuleID, Category, Severity, Title, StartLine, EndLine } ],
        Misconfigurations: [ (.Misconfigurations // [])[] | {
          ID, AVDID, Title, Description, Severity, Resolution, Message } ]
      } ]
    }' "$input" >"$output"
    ;;
  *)
    echo "unknown scan_type: $scan_type" >&2; exit 2 ;;
esac
