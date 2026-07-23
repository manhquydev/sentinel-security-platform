#!/usr/bin/env bash
# Seed the DefectDojo data model and issue the CI service-account token.
#
# Creates Product_Type -> Product -> Engagement with stable IDs so that P3/P4 can
# import against them without relying on auto_create_context.
#
# The CI account is deliberately NOT the admin. It is a non-superuser holding the
# Product-scoped `Writer` role, which is the minimum DefectDojo role that can call
# Import_Scan_Result. Be honest about what that buys: DefectDojo has no
# import-only role, so `Writer` can also READ and DELETE every finding in the
# Product it is scoped to. Product-scoping caps the blast radius to one Product;
# the actual control against secret exposure is the P3 redaction stage, because
# this token can read findings by design.
#
# The token is printed exactly once, to stdout, and never written to disk.
#
# Usage: scripts/dd-bootstrap.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ENV_FILE:-$REPO_ROOT/infra/.env}"
DD_URL="${DD_URL:-http://localhost:8080}"

[ -r "$ENV_FILE" ] || { echo "FATAL: $ENV_FILE not readable" >&2; exit 1; }
# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a

: "${DD_ADMIN_USER:?}" "${DD_ADMIN_PASSWORD:?}"
: "${DD_PRODUCT_TYPE:?}" "${DD_PRODUCT:?}" "${DD_ENGAGEMENT:?}"
: "${DD_SERVICE_ACCOUNT_USER:?}" "${DD_SERVICE_ACCOUNT_PASSWORD:?}"

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

# Parse a field out of a JSON document on stdin. Kept tiny on purpose: jq is not
# guaranteed to exist on a fresh host, python3 is (the benchmark harness needs it).
jfield() { python3 -c "import sys,json;d=json.load(sys.stdin);print(d$1)"; }

api() {
    local method="$1" path="$2" body="${3:-}"
    if [ -n "$body" ]; then
        curl -sS -X "$method" "$DD_URL$path" \
            -H "Authorization: Token $ADMIN_TOKEN" \
            -H "Content-Type: application/json" \
            -d "$body"
    else
        curl -sS -X "$method" "$DD_URL$path" -H "Authorization: Token $ADMIN_TOKEN"
    fi
}

# Return the id of an existing object matching a name, or empty. Makes the whole
# script rerunnable without creating duplicates.
find_id_by_name() {
    local path="$1" name="$2"
    api GET "${path}?name=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$name")" \
        | python3 -c "
import sys,json
d=json.load(sys.stdin)
r=[x for x in d.get('results',[]) if x.get('name')==sys.argv[1]]
print(r[0]['id'] if r else '')
" "$name"
}

echo "==> waiting for DefectDojo API at $DD_URL"
for i in $(seq 1 60); do
    if curl -sf -o /dev/null "$DD_URL/login"; then echo "    up after ${i}s"; break; fi
    [ "$i" -eq 60 ] && { echo "FATAL: API not reachable after 60s" >&2; exit 1; }
    sleep 1
done

echo "==> authenticating as admin"
ADMIN_TOKEN=$(curl -sS -X POST "$DD_URL/api/v2/api-token-auth/" \
    -H "Content-Type: application/json" \
    -d "$(python3 -c "
import json,os
print(json.dumps({'username':os.environ['DD_ADMIN_USER'],'password':os.environ['DD_ADMIN_PASSWORD']}))")" \
    | jfield "['token']")
[ -n "$ADMIN_TOKEN" ] || { echo "FATAL: admin auth failed" >&2; exit 1; }

# ---------------------------------------------------------------------------
# hierarchy
# ---------------------------------------------------------------------------

# Deduplication is OFF in every fresh DefectDojo install: System_Settings.
# enable_deduplication defaults to False and no DD_* environment variable can
# change it. Without this, DD_DEDUPLICATION_ALGORITHM_PER_PARSER and
# DD_HASHCODE_FIELDS_PER_SCANNER are loaded and validated but never consulted -
# every reimport stacks duplicate findings and the lake inflates silently.
# Verified: 4 identical findings, 0 flagged duplicate, until this was turned on.
echo "==> enabling deduplication (off by default, no env var exists for it)"
docker exec "${APP_CONTAINER:-dd-uwsgi}" python manage.py shell --no-imports -c "
from dojo.models import System_Settings
s = System_Settings.objects.get()
if not s.enable_deduplication:
    s.enable_deduplication = True
    s.save()
print('    enable_deduplication =', System_Settings.objects.get(no_cache=True).enable_deduplication)
" 2>&1 | tail -1

echo "==> product type: $DD_PRODUCT_TYPE"
PT_ID=$(find_id_by_name /api/v2/product_types/ "$DD_PRODUCT_TYPE")
if [ -z "$PT_ID" ]; then
    PT_ID=$(api POST /api/v2/product_types/ \
        "$(python3 -c "import json,os;print(json.dumps({'name':os.environ['DD_PRODUCT_TYPE'],'description':'Project Sentinel week-1 data lake'}))")" \
        | jfield "['id']")
fi
echo "    product_type id=$PT_ID"

echo "==> product: $DD_PRODUCT"
P_ID=$(find_id_by_name /api/v2/products/ "$DD_PRODUCT")
if [ -z "$P_ID" ]; then
    P_ID=$(api POST /api/v2/products/ \
        "$(PT="$PT_ID" python3 -c "
import json,os
print(json.dumps({'name':os.environ['DD_PRODUCT'],
                  'description':'Juice Shop harness target (swappable to VinSOC replica)',
                  'prod_type':int(os.environ['PT'])}))")" \
        | jfield "['id']")
fi
echo "    product id=$P_ID"

echo "==> engagement: $DD_ENGAGEMENT"
E_ID=$(find_id_by_name /api/v2/engagements/ "$DD_ENGAGEMENT")
if [ -z "$E_ID" ]; then
    E_BODY=$(P="$P_ID" python3 -c "
import json,os,datetime
today=datetime.date.today()
print(json.dumps({'name':os.environ['DD_ENGAGEMENT'],
                  'product':int(os.environ['P']),
                  'target_start':today.isoformat(),
                  'target_end':(today+datetime.timedelta(days=365)).isoformat(),
                  'status':'In Progress',
                  'engagement_type':'CI/CD',
                  'deduplication_on_engagement':False}))")
    E_ID=$(api POST /api/v2/engagements/ "$E_BODY" | jfield "['id']")
fi
echo "    engagement id=$E_ID"

# ---------------------------------------------------------------------------
# service account
# ---------------------------------------------------------------------------

echo "==> service account: $DD_SERVICE_ACCOUNT_USER (non-superuser)"
U_ID=$(api GET "/api/v2/users/?username=$DD_SERVICE_ACCOUNT_USER" \
    | python3 -c "
import sys,json
d=json.load(sys.stdin)
r=[x for x in d.get('results',[]) if x.get('username')==sys.argv[1]]
print(r[0]['id'] if r else '')
" "$DD_SERVICE_ACCOUNT_USER")

if [ -z "$U_ID" ]; then
    U_ID=$(api POST /api/v2/users/ \
        "$(python3 -c "
import json,os
print(json.dumps({'username':os.environ['DD_SERVICE_ACCOUNT_USER'],
                  'password':os.environ['DD_SERVICE_ACCOUNT_PASSWORD'],
                  'first_name':'CI','last_name':'Importer',
                  'email':'ci-importer@defectdojo.local',
                  'is_active':True,
                  'is_superuser':False,
                  'is_staff':False}))")" \
        | jfield "['id']")
fi
echo "    user id=$U_ID"

# Authorization on open-source DefectDojo is NOT role-based. dojo/authorization/
# authorization.py states it plainly: the hierarchical roles (Reader/Writer/
# Maintainer/Owner/API_Importer) moved to the dojo-pro plugin, and OS-only
# deployments resolve permissions as:
#
#   superuser                        -> everything
#   Delete / StaffOnly action        -> requires is_staff
#   View / Edit / Add / Import       -> is_staff, else membership in the
#                                       authorized_users chain of the object
#
# The Role and Product_Member tables still exist but are never consulted, and
# /api/v2/roles/ and /api/v2/product_members/ do not exist in the OS API at all
# (both 404 on 3.1.200). So scoping is done through Product.authorized_users.
#
# The upside over the role model: because Delete requires is_staff, a non-staff
# service account cannot delete findings at all - a strictly smaller residual
# than a Product-scoped Writer would have had.
echo "==> authorizing $DD_SERVICE_ACCOUNT_USER on product $P_ID only (OS authorized_users model)"
docker exec dd-uwsgi python manage.py shell --no-imports -c "
from dojo.models import Product, Dojo_User
u = Dojo_User.objects.get(username='$DD_SERVICE_ACCOUNT_USER')
p = Product.objects.get(pk=$P_ID)

if u.is_superuser or u.is_staff:
    raise SystemExit('FATAL: service account must be neither superuser nor staff')

p.authorized_users.add(u)

# Scoping is only real if this is the account's ONLY grant. A Product_Type
# membership would silently widen it to every product of that type.
from dojo.models import Product_Type
wider = [pt.name for pt in Product_Type.objects.filter(authorized_users=u)]
if wider:
    raise SystemExit(f'FATAL: account also authorized on product types {wider}')

others = [x.name for x in Product.objects.filter(authorized_users=u).exclude(pk=$P_ID)]
if others:
    raise SystemExit(f'FATAL: account also authorized on products {others}')

print('    authorized on:', [x.name for x in Product.objects.filter(authorized_users=u)])
" || { echo "FATAL: could not scope the service account" >&2; exit 1; }

SERVICE_TOKEN=$(curl -sS -X POST "$DD_URL/api/v2/api-token-auth/" \
    -H "Content-Type: application/json" \
    -d "$(python3 -c "
import json,os
print(json.dumps({'username':os.environ['DD_SERVICE_ACCOUNT_USER'],'password':os.environ['DD_SERVICE_ACCOUNT_PASSWORD']}))")" \
    | jfield "['token']")
[ -n "$SERVICE_TOKEN" ] || { echo "FATAL: service account auth failed" >&2; exit 1; }

cat <<EOF

------------------------------------------------------------------
Seeded IDs (record these; P3/P4 import against them)
  product_type : $PT_ID  ($DD_PRODUCT_TYPE)
  product      : $P_ID  ($DD_PRODUCT)
  engagement   : $E_ID  ($DD_ENGAGEMENT)
  service user : $U_ID  ($DD_SERVICE_ACCOUNT_USER, non-superuser, non-staff,
                 authorized on product $P_ID only)

CI token (shown once, not written to disk - copy to your secret store now):

  $SERVICE_TOKEN

Residual, stated honestly for the open-source authorization model:
  CAN     import, view, add and edit within product $P_ID
  CANNOT  delete anything (Delete requires is_staff), and cannot see any
          other product
Reading findings is inherent to the grant, so redaction (P3) remains the
control that keeps secrets out of what this token can read.
------------------------------------------------------------------
EOF
