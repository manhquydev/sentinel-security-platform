#!/usr/bin/env bash
# Fail-closed target allowlist + readiness gate for active DAST (phase-03).
#
#   target-allowlist.sh validate <url>   → prints the PINNED resolved IP on
#       stdout and exits 0 iff every A/AAAA the host resolves to is permitted;
#       exits 1 (fail-closed) otherwise.
#   target-allowlist.sh ready <url>      → polls until the target answers HTTP
#       or TARGET_READY_TIMEOUT elapses; exits 0/1.
#
# Rule (matches the reviewed phase-03 decision): a resolved IP that is loopback,
# link-local, cloud-metadata, RFC1918, or ULA is REJECTED unless it is
# explicitly permitted in ALLOWLIST. Public IPs pass. If a host resolves to
# MULTIPLE IPs and ANY one is rejected, the whole target is rejected (a
# rebind/round-robin cannot smuggle one bad answer through).
#
# PRECONDITION, not a TODO. The validated IP is emitted so that a caller can pin
# the scanner to it, which matters only when the target is a HOSTNAME: validation
# resolves once and the scanner would resolve again, and those two answers can
# differ. This harness targets the literal `127.0.0.1:13000`, so there is no
# second resolution and nothing to rebind — forcing here would be a no-op, and it
# is deliberately not implemented. If a hostname target is ever introduced, the
# caller MUST pin the scanner to this IP before that change ships.
#
# Do not reach for nuclei's `-resolvers` to do it: that flag supplies a list of
# DNS *servers*, not a hostname→IP mapping, and nuclei has no host-override flag
# at all. The mechanisms that actually pin are a container-local /etc/hosts entry
# (`docker run --add-host`, which requires dropping `--network host`) or
# constraining the scanner's network namespace to the pinned address.
#
# ALLOWLIST: space-separated entries, each `IP`, `IP:PORT`, or `CIDR`.
#   Port is enforced only when the matching entry specifies one.
set -euo pipefail

sub="${1:?usage: validate|ready <url>}"
url="${2:?url required}"
ALLOWLIST="${ALLOWLIST:-}"

command -v python3 >/dev/null 2>&1 || { echo "target-allowlist: python3 required" >&2; exit 3; }

# Emit pinned IP on stdout / diagnostics on stderr; exit 0 allow, 1 reject.
_validate() {
  ALLOWLIST="$ALLOWLIST" python3 - "$url" <<'PY'
import ipaddress, os, socket, sys
from urllib.parse import urlsplit

url = sys.argv[1]
parts = urlsplit(url)
host = parts.hostname
if not host:
    print(f"no host in url: {url}", file=sys.stderr); sys.exit(1)
port = parts.port or (443 if parts.scheme == "https" else 80)

# Parse the allowlist into (network, optional_port) entries.
entries = []
for tok in os.environ.get("ALLOWLIST", "").split():
    p = None
    body = tok
    # IPv6 with port is bracketed; keep it simple — support IP, IP:PORT, CIDR.
    if "/" in tok:                      # CIDR, no port
        body = tok
    elif tok.count(":") == 1 and "." in tok:   # IPv4:PORT
        body, ps = tok.rsplit(":", 1); p = int(ps)
    try:
        net = ipaddress.ip_network(body, strict=False)
    except ValueError:
        print(f"bad ALLOWLIST entry: {tok}", file=sys.stderr); continue
    entries.append((net, p))

def permitted(ip):
    ipobj = ipaddress.ip_address(ip)
    for net, p in entries:
        if ipobj.version == net.version and ipobj in net and (p is None or p == port):
            return True
    return False

def dangerous(ip):
    o = ipaddress.ip_address(ip)
    return (o.is_loopback or o.is_link_local or o.is_private
            or o.is_reserved or o.is_multicast
            or o == ipaddress.ip_address("169.254.169.254")
            or o == ipaddress.ip_address("fd00:ec2::254"))

# Resolve ALL A/AAAA answers.
try:
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
except socket.gaierror as e:
    print(f"cannot resolve {host}: {e}", file=sys.stderr); sys.exit(1)
ips = sorted({i[4][0] for i in infos})
if not ips:
    print(f"no addresses for {host}", file=sys.stderr); sys.exit(1)

for ip in ips:
    if dangerous(ip) and not permitted(ip):
        print(f"REJECT {host} -> {ip}:{port} (dangerous range, not in ALLOWLIST)", file=sys.stderr)
        sys.exit(1)

# All answers acceptable. Pin the first (deterministic sorted order).
print(ips[0])
PY
}

case "$sub" in
  validate) _validate ;;
  ready)
    # Validate + pin first; never poll a target that failed the allowlist.
    pin="$(_validate)" || { echo "target-allowlist: refusing readiness poll on rejected target" >&2; exit 1; }
    timeout="${TARGET_READY_TIMEOUT:-60}"
    deadline=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
      # Host already validated+pinned above; a plain probe is sufficient for
      # readiness (host already validated+pinned above).
      if curl -s -o /dev/null --max-time 5 "$url" 2>/dev/null; then
        echo "$pin"; exit 0
      fi
      sleep 2
    done
    echo "target-allowlist: $url not ready within ${timeout}s" >&2; exit 1 ;;
  *) echo "unknown subcommand: $sub (validate|ready)" >&2; exit 2 ;;
esac
