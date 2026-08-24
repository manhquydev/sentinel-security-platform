#!/usr/bin/env bash
# Flatten docs/*.md into notebooklm/ for NotebookLM import.
# Does not change the canonical docs/ tree (website sync, relative links, agents).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCS="${ROOT}/docs"
DEST="${ROOT}/notebooklm"
PACKS_ONLY=0

usage() {
  cat <<'EOF'
Flatten docs markdown into notebooklm/ (no subfolders) for NotebookLM.

Usage:
  bash scripts/export-notebooklm.sh
  bash scripts/export-notebooklm.sh --packs-only

Default: one file per document, plus 00-pack-*.md bundles (under the
free 50-source cap). --packs-only writes only the bundles and the guide.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --packs-only) PACKS_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown flag: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ! -d "$DOCS" ]]; then
  echo "docs/ not found: $DOCS" >&2
  exit 1
fi

rm -rf "$DEST"
mkdir -p "$DEST"

flat_name() {
  local rel="$1"
  printf '%s' "${rel//\//--}"
}

pack_init() {
  local dest="$1"
  local title="$2"
  cat >"$dest" <<EOF
# ${title}

Bản gộp từ \`docs/\` để import NotebookLM. Mỗi phần dưới đây là một tài liệu gốc.

EOF
}

pack_append() {
  local dest="$1"
  local src="$2"
  local rel="$3"
  {
    printf '\n\n---\n\n<!-- source: %s -->\n\n# %s\n\n' "$rel" "$rel"
    cat "$src"
    printf '\n'
  } >>"$dest"
}

is_skipped() {
  local rel="$1"
  case "$rel" in
    templates/*) return 0 ;;
    reports/artifacts/*) return 0 ;;
    *) return 1 ;;
  esac
}

pack_for() {
  local rel="$1"
  case "$rel" in
    decisions/*) printf '%s' "00-pack-02-decisions.md" ;;
    reports/*) printf '%s' "00-pack-03-bao-cao-tuan.md" ;;
    operations/*) printf '%s' "00-pack-04-van-hanh.md" ;;
    research/*|research-protocol.md|ai-sast-*.md) printf '%s' "00-pack-05-research.md" ;;
    journal/*) printf '%s' "00-pack-06-journal.md" ;;
    plans/active/*) printf '%s' "00-pack-07-plans-active.md" ;;
    plans/completed/*) printf '%s' "00-pack-08-plans-completed.md" ;;
    plans/reports/*) printf '%s' "00-pack-09-plans-reports.md" ;;
    personal/*|*_NguyenManhQuy_*|Project_Sentinel*|*-kich-ban-trinh-bay.md)
      printf '%s' "00-pack-10-bai-tap-ca-nhan.md"
      ;;
    *) printf '%s' "00-pack-01-gioi-thieu-va-product.md" ;;
  esac
}

declare -A PACK_TITLE=(
  ["00-pack-01-gioi-thieu-va-product.md"]="Giới thiệu, product, kiến trúc"
  ["00-pack-02-decisions.md"]="Decisions"
  ["00-pack-03-bao-cao-tuan.md"]="Báo cáo tuần"
  ["00-pack-04-van-hanh.md"]="Vận hành"
  ["00-pack-05-research.md"]="Research và protocol"
  ["00-pack-06-journal.md"]="Journal"
  ["00-pack-07-plans-active.md"]="Plans — active"
  ["00-pack-08-plans-completed.md"]="Plans — completed"
  ["00-pack-09-plans-reports.md"]="Plans — reports"
  ["00-pack-10-bai-tap-ca-nhan.md"]="Bài tập / assignment cá nhân (local)"
)

copied=0
packed=0

if [[ -f "${ROOT}/README.md" ]]; then
  pack_init "${DEST}/00-pack-01-gioi-thieu-va-product.md" \
    "${PACK_TITLE[00-pack-01-gioi-thieu-va-product.md]}"
  pack_append "${DEST}/00-pack-01-gioi-thieu-va-product.md" \
    "${ROOT}/README.md" "README.md"
  packed=$((packed + 1))
  if [[ "$PACKS_ONLY" -eq 0 ]]; then
    cp "${ROOT}/README.md" "${DEST}/project-README.md"
    copied=$((copied + 1))
  fi
fi

while IFS= read -r -d '' src; do
  rel="${src#"${DOCS}/"}"
  if is_skipped "$rel"; then
    continue
  fi

  pack="$(pack_for "$rel")"
  if [[ ! -f "${DEST}/${pack}" ]]; then
    pack_init "${DEST}/${pack}" "${PACK_TITLE[$pack]}"
  fi
  pack_append "${DEST}/${pack}" "$src" "$rel"
  packed=$((packed + 1))

  if [[ "$PACKS_ONLY" -eq 0 ]]; then
    cp "$src" "${DEST}/$(flat_name "$rel")"
    copied=$((copied + 1))
  fi
done < <(find "$DOCS" -type f -name '*.md' -print0 | sort -z)

cat >"${DEST}/00-HUONG-DAN-IMPORT.md" <<'EOF'
# Import tài liệu Sentinel vào NotebookLM

Thư mục này là bản sao **phẳng** (không có thư mục con) của markdown trong `docs/`,
cộng `README.md` gốc. Cây `docs/` trong repo **không** bị đổi — đó vẫn là tài liệu
làm việc (website, link tương đối, agent).

Tạo lại thư mục này từ root repo:

```bash
bash scripts/export-notebooklm.sh
bash scripts/export-notebooklm.sh --packs-only
```

## Cách nhanh (khuyến nghị)

NotebookLM gói miễn phí tối đa **50 nguồn** / notebook; mỗi nguồn tối đa 500.000 từ.
Chọn đúng 10 file `00-pack-*.md` — chúng đã gồm toàn bộ nội dung markdown.

| File | Nội dung |
|---|---|
| `00-pack-01-gioi-thieu-va-product.md` | README dự án, product, kiến trúc, workflow |
| `00-pack-02-decisions.md` | Mọi decision |
| `00-pack-03-bao-cao-tuan.md` | Báo cáo tuần mentor |
| `00-pack-04-van-hanh.md` | Runbook / deploy / demo |
| `00-pack-05-research.md` | Protocol, research log, AI-SAST |
| `00-pack-06-journal.md` | Nhật ký lab |
| `00-pack-07-plans-active.md` | Kế hoạch đang mở |
| `00-pack-08-plans-completed.md` | Kế hoạch đã xong |
| `00-pack-09-plans-reports.md` | Báo cáo / review trong plans |
| `00-pack-10-bai-tap-ca-nhan.md` | Assignment / báo cáo cá nhân (chỉ máy local) |

Trong NotebookLM: **Add source → Upload → chọn 10 file pack**.

## Cách chọn từng tài liệu

Mỗi file còn lại là một tài liệu gốc. Dấu `/` trong đường dẫn được đổi thành `--`:

`docs/decisions/0001-….md` → `decisions--0001-….md`

Gói miễn phí: chọn tối đa 50 file. Không chọn đồng thời pack và file lẻ nếu không muốn trùng nội dung.

## Không có trong thư mục này

- `docs/templates/` (mẫu rỗng)
- `docs/reports/artifacts/` (JSON/JSONL, không phải tài liệu học)
- Secret / `infra/.env` / raw scan

File cá nhân bị gitignore vẫn được copy vào đây khi chúng có trên đĩa — chỉ dùng local,
không commit thư mục `notebooklm/`.
EOF

pack_count="$(find "$DEST" -maxdepth 1 -type f -name '00-pack-*.md' | wc -l)"
file_count="$(find "$DEST" -maxdepth 1 -type f | wc -l)"
subdir_count="$(find "$DEST" -mindepth 1 -type d | wc -l)"

echo "notebooklm/ ready: ${file_count} files, ${subdir_count} subdirs (want 0)"
echo "  copied documents: ${copied}"
echo "  documents folded into packs: ${packed}"
echo "  pack files: ${pack_count}"
echo "  path: ${DEST}"
