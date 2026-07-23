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
# Preserved locators (what endpoint/file dedup hashes on) and the fields the
# DefectDojo parsers dereference unconditionally:
#   ZAP     uri (userinfo/query/fragment stripped), method, param, name, riskcode,
#           cweid, pluginid + desc/solution/reference (parser calls html2text on
#           these and None raises)
#   Nuclei  template-id, type, host, matched-at, matcher-name (-> component_name,
#           a hash field) and info.{name,severity,tags,description,classification}
#           (classification -> cwe, also a hash field)
#   Semgrep check_id, path, start, end, extra.{severity,metadata}
#   Trivy   Target, Class, Type + per-finding id/severity/title/line (NO Match/Code,
#           and NO CweIDs — see the note on the Trivy branch)
#
# For Nuclei this MUST run BEFORE any JSONL→JSON conversion.
set -euo pipefail

scan_type="${1:?scan_type required (zap|nuclei|semgrep|trivy)}"
input="${2:?input file required}"
output="${3:?output file required}"

[ -r "$input" ] || { echo "redact: cannot read $input" >&2; exit 2; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "redact: missing dependency: $1" >&2; exit 3; }; }

# jq object construction emits an EXPLICIT null for a whitelisted key whose
# source field is absent. Python's dict.get(key, default) does not apply the
# default when the key exists holding null, so that null reaches the DefectDojo
# parser as None — and `misc_message += "\n" + table` on None raises TypeError,
# rejecting the whole report. Strip null-valued keys so an absent source field
# stays absent rather than becoming an explicit null.
DROP_NULLS='walk(if type == "object" then with_entries(select(.value != null)) else . end)'

case "$scan_type" in
  zap)
    # DOCUMENT-level whitelist REBUILD. The earlier version pruned children of
    # <alertitem> in place, which left three whole classes untouched: XML
    # attributes anywhere, elements outside <alertitem>, and credentials inside
    # the <uri> query string. Pruning can only remove what it enumerates; only a
    # rebuild can drop what it does not.
    need python3
    python3 - "$input" "$output" <<'PY'
import sys, xml.etree.ElementTree as ET
from urllib.parse import urlsplit, urlunsplit

inp, outp = sys.argv[1], sys.argv[2]

# Elements the DefectDojo ZAP parser dereferences (dojo/tools/zap/parser.py):
# alert, desc, riskcode, solution, reference, pluginid, cweid per alertitem;
# uri/method/param per instance. desc/solution/reference are static plugin text,
# not target data — omitting them made html2text(None) raise, so a perfectly
# redacted report could never import at all.
ALERT_KEEP = ("pluginid", "alertRef", "alert", "name", "riskcode", "confidence",
              "riskdesc", "desc", "solution", "reference", "cweid", "wascid", "sourceid")
# The parser calls html2text() on these unconditionally, so they must always be
# emitted — an absent element yields None and raises.
ALERT_REQUIRED = ("desc", "solution", "reference")
INST_KEEP = ("uri", "method", "param")  # NOT attack/evidence/otherinfo/req/resp
SITE_ATTR_KEEP = ("name", "host", "port", "ssl")

def clean_uri(u):
    """Drop userinfo, query and fragment from an http(s) URL.

    Costs nothing for deduplication: the ZAP parser strips query and fragment when
    it builds the endpoint, so the hash is computed over scheme/host/port/path
    either way.

    RESIDUAL, stated rather than asserted away: the PATH is preserved, so a
    credential embedded in a path segment survives — a matrix parameter such as
    `/shop;jsessionid=<token>` (exactly what ZAP pluginid 3 "Session ID in URL
    Rewrite" reports) or a reset token at `/reset/<token>`. The path is the
    locator dedup hashes on, so it cannot simply be dropped. Anything that is not
    http/https is emptied rather than guessed at, because non-hierarchical schemes
    (mailto:, javascript:) put their whole payload in `path`.
    """
    try:
        p = urlsplit(u)
        host, port = p.hostname, p.port  # .port validates lazily and can raise
    except ValueError:
        return ""
    if p.scheme not in ("http", "https"):
        return ""
    netloc = host or ""
    if ":" in netloc:  # IPv6 literal — urlsplit strips the brackets, put them back
        netloc = f"[{netloc}]"
    if port:
        netloc = f"{netloc}:{port}"
    return urlunsplit((p.scheme, netloc, p.path, "", ""))

try:
    src = ET.parse(inp).getroot()
except Exception as e:
    print(f"redact(zap): unparseable XML: {e}", file=sys.stderr); sys.exit(5)

out = ET.Element("OWASPZAPReport")
if src.get("version"):
    out.set("version", src.get("version"))

for site in src.iter("site"):
    new_site = ET.SubElement(out, "site")
    for attr in SITE_ATTR_KEEP:
        if site.get(attr) is not None:
            new_site.set(attr, site.get(attr))
    alerts = ET.SubElement(new_site, "alerts")
    for item in site.findall("alerts/alertitem"):
        new_item = ET.SubElement(alerts, "alertitem")
        for tag in ALERT_KEEP:
            text = item.findtext(tag)
            if text is None and tag in ALERT_REQUIRED:
                text = ""
            if text is not None:
                ET.SubElement(new_item, tag).text = text
        instances = ET.SubElement(new_item, "instances")
        for inst in item.findall("instances/instance"):
            new_inst = ET.SubElement(instances, "instance")
            for tag in INST_KEEP:
                text = inst.findtext(tag)
                if text is None:
                    continue
                ET.SubElement(new_inst, tag).text = clean_uri(text) if tag == "uri" else text

ET.ElementTree(out).write(outp, encoding="utf-8", xml_declaration=True)
PY
    ;;
  nuclei)
    need jq
    # Build a NEW object per JSONL line with only whitelisted keys.
    #
    # matcher-name and info.classification are NOT secret-bearing and are both
    # DEDUP INPUTS: the parser derives cwe from classification["cwe-id"] and
    # component_name from matcher-name, and the configured hash_code fields
    # include cwe. Dropping them made every reimport re-key its findings — four
    # were auto-closed as remediated and re-created with cwe=0, and eight
    # security-header findings collapsed into one because matcher-name is part
    # of the parser's own de-duplication key.
    jq -c '{
      "template-id": .["template-id"],
      "template": .template,
      "type": .type,
      "host": .host,
      "matched-at": .["matched-at"],
      "matcher-name": .["matcher-name"],
      "info": (if .info then {name: .info.name, severity: .info.severity,
                              tags: .info.tags, description: .info.description,
                              classification: .info.classification} else null end),
      "timestamp": .timestamp
    } | '"$DROP_NULLS" "$input" >"$output"
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
          # Defaulted, not passed through: the parser subscripts
          # item["extra"]["metadata"] unconditionally, so DROP_NULLS removing an
          # absent metadata key would trade the old TypeError for a KeyError.
          # Same guarantee ALERT_REQUIRED gives the ZAP branch.
          metadata: (.extra.metadata // {})
        }
      } ],
      errors: []
    } | '"$DROP_NULLS" "$input" >"$output"
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
        # CweIDs is deliberately NOT whitelisted. The parser does
        # int(vuln["CweIDs"][0].split("-")[1]), and Trivy passes NVD placeholders
        # through verbatim: "NVD-CWE-noinfo".split("-")[1] is "CWE", so int() raises
        # ValueError outside the KeyError guard in the parser, and ONE such CVE rejects the
        # whole report. Nothing needs it here — cwe is not in the Trivy hash fields
        # and HASHCODE_ALLOWS_NULL_CWE is True, so cwe=0 is harmless.
        Vulnerabilities: [ (.Vulnerabilities // [])[] | {
          VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Severity, Title } ],
        Secrets: [ (.Secrets // [])[] | {
          RuleID, Category, Severity, Title, StartLine, EndLine } ],
        Misconfigurations: [ (.Misconfigurations // [])[] | {
          ID, AVDID, Title, Description, Severity, Resolution, Message } ]
      } ]
    } | '"$DROP_NULLS" "$input" >"$output"
    ;;
  *)
    echo "unknown scan_type: $scan_type" >&2; exit 2 ;;
esac
