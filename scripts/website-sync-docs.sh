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
  "Báo cáo tuần" "Mục lục báo cáo tuần Project Sentinel (VINSOC × VINUNI)"
write_page "${REPORTS_SRC}/week-01.md" "${DEST}/reports/week-01.md" \
  "Tuần 1 — Quét bảo mật nền" "Báo cáo Tuần 1: quét SAST/DAST nền và che secret"
write_page "${REPORTS_SRC}/week-02.md" "${DEST}/reports/week-02.md" \
  "Tuần 2 — Chuẩn hóa và kho tri thức" "Báo cáo Tuần 2: gộp cảnh báo và tra cứu offline"
write_page "${REPORTS_SRC}/week-03.md" "${DEST}/reports/week-03.md" \
  "Tuần 3 — Agent phân tích bảo mật" "Báo cáo Tuần 3: agent phân tích bám bằng chứng (JSONL)"

# Ensure allowlist files exist (guards against silent drift of ALLOWLIST_REPORTS).
for name in "${ALLOWLIST_REPORTS[@]}"; do
  [[ -f "${REPORTS_SRC}/${name}" ]] || die "allowlist missing ${name}"
done

# Landing page (tiếng Việt, giọng mentor-facing tự nhiên)
cat >"${DEST}/index.mdx" <<'EOF'
---
title: Project Sentinel
description: Báo cáo tuần đồ án Project Sentinel — TTS Nguyễn Mạnh Quý (VINSOC × VINUNI).
template: splash
hero:
  title: Project Sentinel
  tagline: Báo cáo tuần 1–3 / 6 của đồ án bảo mật AI (VINSOC × VINUNI) — bám bằng chứng, lab nội bộ (loopback).
  actions:
    - text: Xem báo cáo tuần
      link: /reports/
      icon: right-arrow
      variant: primary
    - text: Mã nguồn monorepo
      link: https://github.com/manhquydev/sentinel-security-platform
      icon: external
      variant: minimal
---

import { Card, CardGrid } from '@astrojs/starlight/components';

## Bắt đầu từ đây

<CardGrid>
  <Card title="Tuần 1" icon="seti:json">
    Quét bảo mật nền, che secret, Juice Shop loopback — [tuần 1](/reports/week-01/).
  </Card>
  <Card title="Tuần 2" icon="seti:db">
    Chuẩn hóa 36 cảnh báo + kho tri thức offline — [tuần 2](/reports/week-02/).
  </Card>
  <Card title="Tuần 3" icon="seti:notebook">
    Agent phân tích bảo mật, báo cáo JSONL bám bằng chứng — [tuần 3](/reports/week-03/).
  </Card>
</CardGrid>

## Ai thực hiện

**TTS (Thực tập sinh) Nguyễn Mạnh Quý** · **VINSOC** × **VINUNI**

Văn bản assignment đầy đủ và kịch bản trình bày cá nhân **không** đăng trên site này.
EOF

echo "website-sync-docs: ok"
