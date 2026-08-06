#!/usr/bin/env bash
# Sync allowlisted Markdown from docs/ into the Starlight content tree.
# Edit source in docs/; never hand-edit website/src/content/docs/reports after sync.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${ROOT}/website/src/content/docs"
REPORTS_SRC="${ROOT}/docs/reports"

# Exact allowlist (v1 reports only). Product/as-built stay in monorepo Markdown
# so monorepo-relative links are not published as 404s on the static site.
ALLOWLIST_REPORTS=(index.md week-01.md week-02.md week-03.md)

die() { echo "website-sync-docs: $*" >&2; exit 1; }

[[ -d "$REPORTS_SRC" ]] || die "missing $REPORTS_SRC"
[[ -d "${ROOT}/website" ]] || die "missing website/ — scaffold Starlight first"

write_page() {
  local src="$1"
  local dest="$2"
  local title="$3"
  local description="$4"
  [[ -f "$src" ]] || die "missing source $src"
  mkdir -p "$(dirname "$dest")"
  {
    printf '%s\n' '---'
    # Quote YAML scalars — titles often contain "—" and ":"
    printf 'title: "%s"\n' "${title//\"/\\\"}"
    printf 'description: "%s"\n' "${description//\"/\\\"}"
    printf '%s\n' '---'
    printf '\n'
    # Drop a leading H1 from source to avoid double titles in Starlight.
    if head -n1 "$src" | grep -qE '^# '; then
      tail -n +2 "$src"
    else
      cat "$src"
    fi
  } >"$dest"
  echo "wrote $dest"
}

rm -rf "${DEST}/reports" "${DEST}/product" "${DEST}/architecture" "${DEST}/guides" "${DEST}/reference"
mkdir -p "${DEST}/reports"

write_page "${REPORTS_SRC}/index.md" "${DEST}/reports/index.md" \
  "Báo cáo tuần" "Index of Project Sentinel weekly mentor reports"
write_page "${REPORTS_SRC}/week-01.md" "${DEST}/reports/week-01.md" \
  "Tuần 1 — Baseline scan" "Week 1 mentor report: SAST/DAST baseline and redaction"
write_page "${REPORTS_SRC}/week-02.md" "${DEST}/reports/week-02.md" \
  "Tuần 2 — Normalize + knowledge" "Week 2 mentor report: aggregate findings and offline knowledge"
write_page "${REPORTS_SRC}/week-03.md" "${DEST}/reports/week-03.md" \
  "Tuần 3 — Analysis agent" "Week 3 mentor report: evidence-bound security analysis agent"

# Ensure allowlist files exist (guards against silent drift of ALLOWLIST_REPORTS).
for name in "${ALLOWLIST_REPORTS[@]}"; do
  [[ -f "${REPORTS_SRC}/${name}" ]] || die "allowlist missing ${name}"
done

# Landing page
cat >"${DEST}/index.mdx" <<'EOF'
---
title: Project Sentinel
description: Mentor-facing docs and weekly reports for the Sentinel security lab.
template: splash
hero:
  title: Project Sentinel
  tagline: Weekly reports and product docs for the VinUni × VinSOC security lab — evidence-bound, loopback-only.
  actions:
    - text: Báo cáo tuần
      link: /reports/
      icon: right-arrow
      variant: primary
    - text: Repo monorepo
      link: https://github.com/manhquydev/sentinel-security-platform
      icon: external
      variant: minimal
---

import { Card, CardGrid } from '@astrojs/starlight/components';

## Start here

<CardGrid>
  <Card title="Tuần 1" icon="seti:json">
    Baseline scanners, redaction, Juice Shop loopback — [week-01](/reports/week-01/).
  </Card>
  <Card title="Tuần 2" icon="seti:db">
    Normalize 36 findings + offline knowledge — [week-02](/reports/week-02/).
  </Card>
  <Card title="Tuần 3" icon="seti:notebook">
    Evidence-bound analysis agent (JSONL) — [week-03](/reports/week-03/).
  </Card>
</CardGrid>

Personal internship assignment texts and presentation scripts are **not** published here.
EOF

echo "website-sync-docs: ok"
