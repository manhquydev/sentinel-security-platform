#!/usr/bin/env bash
# Shared LLM gateway contract, enforced so a future edit cannot quietly break it.
#
# The benchmark's own 95 tests cannot prove the gateway relocation: they are config-only
# and parse the YAML they are asserting about, so they pass whether or not the move
# preserved anything. These are the assertions that actually cover it — alias parity
# against the file the gateway was moved from, the deliberate ABSENCE of fabricated
# pricing, the guardrail's fail-closed default, and the deployment properties that keep
# the router credential off the network.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFG="$REPO_ROOT/infra/litellm/config.yaml"
COMPOSE="$REPO_ROOT/infra/litellm/docker-compose.yml"
LEGACY="$REPO_ROOT/benchmark/litellm-config.yaml"
GUARDRAILS="$REPO_ROOT/infra/litellm/guardrails"

PASS=0; FAIL=0
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
sect(){ printf '\n== %s ==\n' "$1"; }

[ -f "$CFG" ]     || { echo "missing $CFG" >&2; exit 2; }
[ -f "$COMPOSE" ] || { echo "missing $COMPOSE" >&2; exit 2; }

py() { python3 -c "$1" "$@"; }

sect "config parses and declares every alias the gateway is expected to serve"
if ! python3 -c "import yaml,sys;yaml.safe_load(open(sys.argv[1]))" "$CFG" 2>/dev/null; then
  bad "config.yaml does not parse as YAML"
else
  ok "config.yaml parses"
fi

# The frozen DeepSeek scorecard is reproducible only through the cheap-sast alias, so a
# rename here is silent data loss with no error at the point of failure.
for alias in cheap-sast sast-sol sast-terra sast-gpt55 judge embed; do
  if python3 - "$CFG" "$alias" <<'PY'
import sys, yaml
cfg = yaml.safe_load(open(sys.argv[1]))
names = {m["model_name"] for m in cfg.get("model_list", [])}
sys.exit(0 if sys.argv[2] in names else 1)
PY
  then ok "alias present: $alias"
  else bad "alias missing: $alias"
  fi
done

sect "parity with the config the gateway was moved from"
if [ -f "$LEGACY" ]; then
  python3 - "$LEGACY" "$CFG" <<'PY'
import sys, yaml
old = yaml.safe_load(open(sys.argv[1])) or {}
new = yaml.safe_load(open(sys.argv[2])) or {}
def params(doc):
    return {m["model_name"]: m.get("litellm_params", {}) for m in doc.get("model_list", [])}
o, n = params(old), params(new)
drift = []
for name, p in o.items():
    if name not in n:
        drift.append(f"alias dropped: {name}")
    elif n[name] != p:
        drift.append(f"litellm_params changed for {name}")
for key in ("general_settings", "litellm_settings"):
    for k, v in (old.get(key) or {}).items():
        if (new.get(key) or {}).get(k) != v:
            drift.append(f"{key}.{k} changed or dropped")
print("\n".join(drift))
sys.exit(1 if drift else 0)
PY
  if [ $? -eq 0 ]; then ok "no alias or settings drift from the legacy config"
  else bad "the move changed model params or settings"
  fi
else
  # Parity was asserted against the legacy file at the moment of the move. Once that
  # file is gone the check would be vacuous, so it is replaced by the property that
  # made removing it safe: exactly one config exists, and the benchmark reads it.
  ok "legacy config retired"
  if [ -n "$(find "$REPO_ROOT/benchmark" -maxdepth 1 -name 'litellm*.yaml' -print -quit)" ]; then
    bad "a second gateway config reappeared under benchmark/ and will drift"
  else
    ok "no duplicate gateway config under benchmark/"
  fi
  if grep -q 'infra" / "litellm" / "config.yaml"' "$REPO_ROOT/benchmark/tests/test_litellm_routing.py"; then
    ok "benchmark routing test reads the shared config"
  else
    bad "benchmark routing test no longer points at the shared config"
  fi
fi

sect "no credential is committed"
# Every credential must arrive through os.environ. A literal key in this file would be
# published: the repository is public.
if grep -Eq '(api_key|master_key|database_url):[[:space:]]*["'"'"']?(sk-|ghp_|github_pat_|postgres://|postgresql://)' "$CFG"; then
  bad "config.yaml contains a literal credential"
else
  ok "no literal credential in config.yaml"
fi
# -q would suppress the output this pipeline depends on, making the check vacuously pass.
if grep -E '^[[:space:]]*(api_key|master_key|database_url):' "$CFG" | grep -qv 'os\.environ/'; then
  bad "a credential field bypasses os.environ"
else
  ok "credential fields read from the environment"
fi

sect "no hand-written pricing is added on top of what LiteLLM computes"
# LiteLLM already prices these models from its own cost map — measured live, a call
# recorded exactly the backing tier's public list price. Spend is therefore not absent,
# and this assertion does not make it absent. What it guards is narrower and still worth
# guarding: nobody may add a hand-written rate, which would swap one unverified number
# for another while looking like a correction. The README labels what the figure means.
if grep -Eq '^\s*(input_cost_per_token|output_cost_per_token|model_info):' "$CFG"; then
  bad "pricing is set for a tier whose real rate is unknown"
else
  ok "no hand-written per-token pricing"
fi

sect "guardrail is wired and fails closed by default"
python3 - "$CFG" <<'PY'
import sys, yaml
cfg = yaml.safe_load(open(sys.argv[1])) or {}
guards = {g["guardrail_name"]: g.get("litellm_params", {}) for g in cfg.get("guardrails", [])}
problems = []
default = guards.get("sentinel")
if not default:
    problems.append("no 'sentinel' guardrail declared")
else:
    if default.get("guardrail") != "sentinel_guardrail.SentinelGuardrail":
        problems.append("sentinel guardrail does not point at SentinelGuardrail")
    if default.get("mode") != "pre_call":
        problems.append("sentinel guardrail must run pre_call, before the upstream request")
    if default.get("default_on") is not True:
        problems.append("sentinel guardrail is not on by default")
    if default.get("require_provenance") is not True:
        problems.append("sentinel guardrail does not require provenance")
# No exemption entry may exist. LiteLLM refuses to let a caller disable a default_on
# guardrail from the request body, so such an entry is unreachable config that reads like
# a working control — probed against the deployment in all three forms and refused each
# time. A caller that cannot declare must be taught to, not exempted.
for name, params in guards.items():
    if params.get("require_provenance") is False:
        problems.append(f"'{name}' declares an exemption that no caller can reach")
print("\n".join(problems))
sys.exit(1 if problems else 0)
PY
if [ $? -eq 0 ]; then ok "guardrail on by default, provenance required, exemptions opt-in"
else bad "guardrail configuration is not fail-closed"
fi

sect "guardrail modules are present and importable as a package directory"
for mod in provenance.py egress_redaction.py sentinel_guardrail.py provenance-label.schema.json; do
  [ -f "$GUARDRAILS/$mod" ] && ok "present: $mod" || bad "missing: $mod"
done
grep -q 'PYTHONPATH: "/app/guardrails"' "$COMPOSE" \
  && ok "guardrails directory is on PYTHONPATH" \
  || bad "guardrail modules import each other by name and need their directory on the path"

sect "deployment keeps the gateway off the network"
grep -Eq 'image:.*@sha256:[0-9a-f]{64}' "$COMPOSE" \
  && ok "image pinned by digest" || bad "image is not digest-pinned"
if grep -Eq '^\s*-\s*"127\.0\.0\.1:4000:4000"' "$COMPOSE"; then
  ok "bound to loopback only"
else
  bad "port binding is not loopback-only"
fi
if grep -Eq '^[[:space:]]*-[[:space:]]*"[0-9]+:[0-9]+"' "$COMPOSE"; then
  bad "a port is published on all interfaces"
else
  ok "no port published on all interfaces"
fi

# The key store mints and validates every virtual key, and it holds them at rest. It has
# no business being reachable from anywhere but the proxy, so it publishes no port at all.
# The inherited configuration had this exactly backwards: the store lived in an unrelated
# project's test database bound to 0.0.0.0.
if python3 - "$COMPOSE" <<'PY'
import sys, yaml
services = (yaml.safe_load(open(sys.argv[1])) or {}).get("services", {})
sys.exit(1 if (services.get("postgres") or {}).get("ports") else 0)
PY
then ok "key store publishes no port"
else bad "key store publishes a port"
fi
grep -Eq 'image: postgres:[0-9.]+-alpine@sha256:[0-9a-f]{64}' "$COMPOSE" \
  && ok "key store image pinned by digest" || bad "key store image is not digest-pinned"
# The proxy also joins the tracing stack's network, and that stack has its own service
# called `postgres`. From a container on both networks the bare service name resolves to
# two addresses, the proxy reached the wrong database, and startup died on an
# authentication error that said nothing about the collision. Container names are unique
# across networks, so the store must be addressed by one.
grep -Eq 'DATABASE_URL:.*@sentinel-litellm-db:5432/litellm' "$COMPOSE" \
  && ok "store addressed by its unique container name" \
  || bad "proxy does not reach its own bundled store by a collision-free name"
if grep -Eq 'DATABASE_URL:.*@postgres:5432' "$COMPOSE"; then
  bad "store addressed by the bare service name, which collides on the tracing network"
else
  ok "store not addressed by a name shared with another stack"
fi
grep -q './guardrails:/app/guardrails:ro' "$COMPOSE" \
  && ok "guardrails mounted read-only" \
  || bad "guardrails must be mounted read-only"
grep -q './config.yaml:/app/config.yaml:ro' "$COMPOSE" \
  && ok "config mounted read-only" || bad "config must be mounted read-only"

sect "the measured operational settings survived the move"
grep -Eq '^\s*request_timeout:\s*120' "$CFG" \
  && ok "request_timeout kept at the measured 120s" \
  || bad "request_timeout changed (sol run 1 lost 49.6 min to an unbounded read)"
grep -Eq '^\s*fail_closed_budget_enforcement:\s*true' "$CFG" \
  && ok "budget enforcement fails closed" || bad "budget enforcement no longer fails closed"
grep -Eq '^\s*redact_user_api_key_info:\s*true' "$CFG" \
  && ok "virtual key values kept out of logs" || bad "virtual key values may reach logs"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
