#!/usr/bin/env bash
# Week-3 RAG retrieval contract. Two layers, matching the repo's other suites.
#
# UNIT (no services): RRF fusion is correct and rewards cross-retriever agreement — the property
# that makes hybrid beat either retriever alone. LIVE (skips if the store is down, unless
# REQUIRE_RAG=1): the schema exists, chunk insertion is idempotent (the "continuously updating"
# guarantee that a re-ingest adds nothing), and hybrid retrieval is no worse than dense-only or
# lexical-only on the committed eval set — the claim the whole pipeline exists to make.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$REPO_ROOT/rag/.venv/bin/python"
ENV_FILE="${ENV_FILE:-$REPO_ROOT/infra/.env}"
REQUIRE_RAG="${REQUIRE_RAG:-0}"

PASS=0; FAIL=0; SKIP=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
skip() { printf '  \033[33mSKIP\033[0m %s\n' "$1"; SKIP=$((SKIP+1)); }
sect() { printf '\n== %s ==\n' "$1"; }

[ -x "$PY" ] || { echo "missing rag venv at $PY (python -m venv rag/.venv && pip install -r rag/requirements.txt)"; exit 2; }

# ---------------------------------------------------------------------------
sect "unit: RRF fusion (no services)"

run_py() { "$PY" - "$@"; }

if run_py <<'PY'
import sys
from rag.retrieve import rrf_fuse
from rag.store import Hit
def h(cid): return Hit(cid, cid, "s", str(cid), None, "c", 0.0)
# dense ranks 1,2,3 ; lexical ranks 3,1,4 -> id 3 appears in both, high in lexical, present in dense
dense   = [h(1), h(2), h(3)]
lexical = [h(3), h(1), h(4)]
fused = rrf_fuse([dense, lexical])
order = [x.chunk_id for x in fused]
# id 1 (ranks 1 and 2) and id 3 (ranks 3 and 1) are the two that appear in BOTH lists; they must
# outrank ids 2 and 4 which appear in only one. That is the agreement-reward property of RRF.
both = {1, 3}
top2 = set(order[:2])
sys.exit(0 if top2 == both else 1)
PY
then ok "RRF ranks cross-retriever agreement above single-list items"
else bad "RRF fusion does not reward agreement"
fi

if run_py <<'PY'
import sys
from rag.retrieve import rrf_fuse
from rag.store import Hit
def h(cid): return Hit(cid, cid, "s", str(cid), None, "c", 0.0)
# A single list must come back in its original order and scores must be descending.
fused = rrf_fuse([[h(10), h(20), h(30)]])
ids = [x.chunk_id for x in fused]
scores = [x.score for x in fused]
sys.exit(0 if ids == [10,20,30] and scores == sorted(scores, reverse=True) else 1)
PY
then ok "RRF preserves single-list order and emits descending scores"
else bad "RRF single-list ordering wrong"
fi

# ---------------------------------------------------------------------------
sect "live: store + hybrid accuracy"

[ -f "$ENV_FILE" ] && { set -a; . "$ENV_FILE"; set +a; }

if ! "$PY" -c 'from rag import store; c=store.connect().__enter__()' >/dev/null 2>&1; then
  msg="RAG store not reachable"
  if [ "$REQUIRE_RAG" = "1" ]; then bad "$msg (REQUIRE_RAG=1)"; else skip "$msg"; fi
else
  # Schema present.
  if run_py <<'PY'
import sys
from rag import store
with store.connect() as c, c.cursor() as cur:
    cur.execute("SELECT to_regclass('public.documents'), to_regclass('public.chunks')")
    a,b = cur.fetchone()
    sys.exit(0 if a and b else 1)
PY
  then ok "schema has documents + chunks tables"; else bad "schema missing tables"; fi

  # Idempotent insert: the same content inserts once, a second time is a no-op. Done inside a
  # transaction that is rolled back, so the store is not mutated by the test.
  if run_py <<'PY'
import sys
from rag import store
with store.connect() as c:
    did = store.upsert_document(c, "test", "rag-selftest", "selftest")
    v = [0.0]*768
    first  = store.insert_chunk(c, did, 0, None, "rag idempotency probe content", v)
    second = store.insert_chunk(c, did, 0, None, "rag idempotency probe content", v)
    c.rollback()  # leave the store untouched
    sys.exit(0 if (first and not second) else 1)
PY
  then ok "chunk insert is idempotent (dedup on content hash)"; else bad "chunk insert not idempotent"; fi

  # Reconcile prune (the 'continuously updating' guarantee): re-ingesting a document with changed
  # content removes the chunks that are gone, but an empty parse must NOT wipe the document.
  if run_py <<'PY'
import sys
from rag import store
from rag.store import sha256
with store.connect() as c:
    did = store.upsert_document(c, "test", "rag-prune-selftest", "selftest")
    v = [0.0]*768
    store.insert_chunk(c, did, 0, None, "prune keep A", v)
    store.insert_chunk(c, did, 1, None, "prune drop B", v)
    empty_guard = store.delete_stale_chunks(c, did, [])            # must delete nothing
    pruned = store.delete_stale_chunks(c, did, [sha256("prune keep A")])  # drops only B
    with c.cursor() as cur:
        cur.execute("SELECT count(*) FROM chunks WHERE document_id=%s", (did,))
        remaining = cur.fetchone()[0]
    c.rollback()  # leave the store untouched
    sys.exit(0 if (empty_guard == 0 and pruned == 1 and remaining == 1) else 1)
PY
  then ok "re-ingest prunes stale chunks; empty parse does not wipe the document"; else bad "reconcile prune incorrect"; fi

  # Corpus present? hybrid-accuracy check needs an ingested corpus.
  NCHUNKS="$("$PY" -c 'from rag import store
with store.connect() as c: print(store.count_chunks(c))' 2>/dev/null)"
  if [ "${NCHUNKS:-0}" -lt 50 ]; then
    m="corpus not ingested (${NCHUNKS:-0} chunks); run: rag/.venv/bin/python -m rag.ingest"
    if [ "$REQUIRE_RAG" = "1" ]; then bad "$m"; else skip "$m"; fi
  else
    if run_py <<'PY'
import sys
from rag import evaluate
r = evaluate.evaluate(k=10)["modes"]
hyb, den, lex = r["hybrid"], r["dense"], r["lexical"]
rk = "recall@10"
# The core claim: hybrid is no worse than either single retriever, and actually retrieves.
ok = hyb[rk] >= den[rk] and hyb[rk] >= lex[rk] and hyb[rk] > 0.0
print(f"  recall@10  hybrid={hyb[rk]} dense={den[rk]} lexical={lex[rk]}")
sys.exit(0 if ok else 1)
PY
    then ok "hybrid recall@10 >= dense and >= lexical (and > 0)"; else bad "hybrid did not beat single retrievers"; fi
  fi
fi

# ---------------------------------------------------------------------------
printf '\n%d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ]
