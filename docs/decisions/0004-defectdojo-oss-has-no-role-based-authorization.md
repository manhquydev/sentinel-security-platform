# 0004 DefectDojo OSS has no role-based authorization; CI scoping uses authorized_users

Date: 2026-07-23

## Status

Accepted

## Context

The Week-1 data-lake plan specified a Product-scoped `Writer` role for the CI import
account, and its red-team review recorded the residual as "Writer can read AND delete
every finding in the scoped Product". Both assume DefectDojo's hierarchical RBAC.

That assumption does not hold on the open-source build. `dojo/authorization/
authorization.py` in 3.1.200 states it directly: the hierarchical roles (Reader / Writer /
Maintainer / Owner / API_Importer) were moved to the `dojo-pro` plugin. The `Role` and
`Product_Member` tables still exist and can still be written, but nothing consults them —
assigning `Product_Member` leaves every permission check returning `False`. The endpoints
the plan implied (`/api/v2/roles/`, `/api/v2/product_members/`) return **404**.

Open-source resolution order is:

| Condition | Result |
|---|---|
| superuser | everything |
| `Delete` or `StaffOnly` action | requires `is_staff` |
| `View` / `Edit` / `Add` / `Import` | `is_staff`, else membership in the object's `authorized_users` chain |

## Decision

The CI account is a **non-superuser, non-staff** user added to `Product.authorized_users`
for exactly one product. `scripts/dd-bootstrap.sh` fails closed if the account is staff or
superuser, or if it holds any grant beyond that single product (including a Product_Type
grant, which would silently widen it).

Measured behaviour of the resulting token:

| Action | Result |
|---|---|
| `POST /api/v2/import-scan/` | 201 |
| `GET` product / engagement / findings in scope | 200 |
| `DELETE` a finding | **403** |
| `DELETE` the product | **403** |
| any other product | invisible (404, verified against a real second product) |

## Alternatives Considered

1. **Adopt `dojo-pro` to obtain the RBAC the plan assumed.** Rejected for Week 1: it adds
   a dependency and probable licensing for granularity the measured model already exceeds
   on the dimension that matters (delete).
2. **Keep the plan's `Writer` wording and configure `Product_Member` anyway.** Rejected:
   it was tried and produced an account with *no* permissions at all, while reading as
   correctly configured.

## Consequences

Positive:

- The residual is **smaller** than the plan intended. Delete requires `is_staff`, so a
  leaked CI token cannot destroy lake contents — the Writer model would have allowed it.

Tradeoffs:

- Reading findings is inherent to the import grant. **Redaction remains the control that
  keeps secrets out of what this token can read**, not RBAC.
- Scoping is enforced by a bootstrap assertion rather than by a role, so it is only as
  strong as that script. Adding a grant by hand in the UI would not trip it until the next
  bootstrap run.
- The Week-1 plan text and its red-team finding on this point are superseded and must be
  corrected; they currently describe a mechanism that does not exist in this build.

## Follow-Up

- Re-evaluate if the deployment ever moves to `dojo-pro`, which restores role checks and
  changes this residual.
- If `authorized_users` scoping needs to hold against manual UI changes, it needs a
  periodic assertion rather than a one-time bootstrap check.
