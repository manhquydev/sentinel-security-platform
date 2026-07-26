# Audit — authored-unseen control (`_b`) variants

**Date:** 2026-07-26
**Scope:** all 12 `_b` modules in `evaluation/authored-unseen/`, judged against the full
absence-of-control list (CWE-306/307/200/209/284/285/620/639/862/863/915), not only each pair's own
planted class.
**Out of scope by instruction:** presence-class issues (injection, XSS, crypto, secrets), style,
non-security validation, missing tests, unresolvable imports.
**Auditor did not author these files.**

## Verdict table

| file | planted control | verdict | unplanted class |
|---|---|---|---|
| `invoices_b.py` | `org_id` filter | CLEAN | — |
| `reset_b.py` | `@limiter.limit` both routes | CLEAN | — |
| `exports_b.py` | role check | CLEAN | — |
| `webhooks_b.py` | HMAC verify | CLEAN (one noted limit) | — |
| `profile_b.py` | field allowlist | CLEAN | — |
| `bulk_b.py` | `tenant_id` filter | CLEAN | — |
| `internal_b.py` | `before_request` token | CLEAN | — |
| **`email_b.py`** | current-password check | **DEFECT FOUND** | CWE-307 |
| `attachments_b.py` | ownership via dependency (subtle) | CLEAN — control PRESENT | — |
| **`lookup_b.py`** | generic error, server-side log | **DEFECT FOUND** | CWE-306 + CWE-200 |
| `reports_b.py` | scope inside `base()` (subtle) | CLEAN — control PRESENT | — |
| `download_b.py` | `org_id` in lookup | CLEAN | — |

**2 of 12 control variants carry an unplanted absence-class defect.**

---

## DEFECT FOUND

### `email_b.py` — CWE-307, no rate limit on a password-checking endpoint

Lines 9-16:

```python
@login_required
@require_POST
def change_email(request):
    ...
    if not request.user.check_password(request.POST.get("current_password") or ""):
        return JsonResponse({"ok": False, "error": "password required"}, status=403)
```

The planted control (CWE-620 re-authentication) is present and correct. But `check_password` on line 15
is an **unthrottled password oracle**: the handler has no `@ratelimit`, no attempt counter, no lockout,
and no backoff, and the 403-vs-200 split is a clean true/false signal.

**Attack.** An attacker holding a hijacked or borrowed session (stolen cookie, unlocked device, XSS,
shared browser) does not know the account password. They POST to this endpoint in a loop with a fixed
`email=` and a candidate `current_password`. Response status alone distinguishes a correct guess.
Unlimited attempts, online, no alerting. Recovering the password escalates a session-only foothold into
full credential compromise — password reuse elsewhere, and passing every *other* re-auth gate in the
product (MFA disable, account delete, payout change). Django's own login throttling (axes / a login
view limiter) does not cover this view.

**Secondary:** the same absence lets an attacker spam `send_confirmation` at line 18 to an
attacker-chosen address once the password is known, but the brute-force oracle is the exploitable core.

**Why this is unplanted, not a judgment call.** The same author rate-limited the equivalent surface in
`reset_b.py` (lines 14 and 30) because CWE-307 was the *planted* class there. The control was applied
where it was the answer key and omitted where it was not. This confirms the already-disclosed finding in
`docs/ai-sast-research-log.md` (E34) and in ADR-0027 — the model's "No rate limit. Brute password / spam
confirmations." was a true positive scored as a false positive.

**Note:** `email_a.py` shares this absence, so the pair's *contrast* still isolates CWE-620 correctly.
The damage is entirely to the control arm's "clean" label.

### `lookup_b.py` — CWE-306 (no authentication) + CWE-200 (account existence and internal id disclosure)

Lines 11-19, complete handler:

```python
@bp.get("/account")
def account():
    ref = request.args.get("ref", "")
    try:
        acct = session.query(Account).filter(Account.external_ref == ref).one()
        return jsonify({"id": acct.id, "status": acct.status})
    except Exception:
        log.exception("account lookup failed for ref=%s", ref)
        return jsonify({"error": "lookup failed"}), 500
```

The planted control (CWE-209) is present: the trace and echoed query are gone. But the endpoint has
**no authentication of any kind** — no `current_user()`, no decorator, no `before_request`, no principal
dependency — and no throttle, while it performs an object lookup keyed on a fully user-supplied
identifier and returns per-account data.

**Attack.** An **unauthenticated, anonymous** internet client iterates or guesses `?ref=` values and
receives, for every hit, the account's internal database primary key (`acct.id`) and its lifecycle
`status`. That is a customer-existence and customer-state oracle over the whole `Account` table with no
account required: confirm a competitor/target is a customer, map external refs to sequential internal
ids (which feed IDOR attempts against every other id-keyed endpoint in the app), and track which
accounts are suspended, delinquent or cancelled. `.one()` raising on a miss also makes hit/miss
distinguishable by status code (200 vs 500) even before reading the body.

**Contrast establishing this is unplanted:** every other Flask module in the set gates access —
`invoices_b`/`exports_b` call `current_user()` and `abort(401)`, `internal_b` uses a blueprint
`before_request` token check. `lookup_b` alone has nothing, and the README records the pair as testing
only CWE-209.

**Extra impact on ground truth:** unlike `email`, this absence exists in **both** `lookup_a` and
`lookup_b`. So it corrupts two labels at once — the control arm is not clean, *and* `lookup_a`'s
"one defect, CWE-209" annotation is incomplete. Note the model's stored `lookup_b` response already
observed this and deferred it ("→ skipped: auth/rate-limit, add when endpoint public"); that is a
near-miss the current scoring did not credit either way.

---

## CLEAN — with the reasoning that mattered

**`invoices_b.py`** — both routes call `current_user()` and `abort(401)`; `detail` scopes by
`Invoice.org_id == user.org_id` (line 26), `index` likewise (line 40). Serialiser exposes only the
invoice's own fields. No writes, so no mass assignment. The unguarded `int(request.args.get("page"))`
on line 38 is a 500-on-bad-input bug, not an absence-of-control.

**`reset_b.py`** — rate limits on both routes (lines 14, 30). Tokens are 256-bit `token_urlsafe(32)`
with a 30-minute TTL, so the IP-keyed-only limit is not a meaningful weakness against distributed
guessing. The response is identical whether or not the email exists (line 26), so no enumeration.
Password reset legitimately does not require re-authentication — CWE-620 does not apply. Not
invalidating the user's other sessions or sibling reset tokens after a reset is CWE-613-adjacent
hygiene, outside the audited list; recorded here only so it is not mistaken for an omission.

**`exports_b.py`** — authentication (lines 19-21) *and* authorization (`role not in ("hr_admin",
"finance_admin")` → 403, lines 22-23), and the query is org-scoped via `_rows(user.org_id)`. Identity
and permission are both checked, which is the specific pairing this file most needed given it emits
`salary_cents` and `national_id`.

**`webhooks_b.py`** — HMAC-SHA256 over the **raw** body, verified with `hmac.compare_digest` *before*
any parsing (lines 18-20). Signature computed on `request.get_data()`, not on a re-serialised payload,
so there is no canonicalisation gap. CWE-306 control present.
*Noted, not scored as a defect:* there is no timestamp/nonce, so a captured valid request can be
replayed (CWE-294). That falls outside the audited absence list, and the attacker precondition
(possession of a previously signed request) does not meet the "any authenticated user could X" bar this
audit uses. Flagging it would be the kind of near-miss the set exists to penalise.

**`profile_b.py`** — `EDITABLE` allowlist enforced on line 17, so the CWE-915 control is present.
Authentication via `@login_required`; ownership is structural — `Profile.objects.get(user=request.user)`
takes no user-supplied identifier, so there is no BOLA surface at all.

**`bulk_b.py`** — `Ticket.tenant_id == principal.tenant_id` (line 14) scopes the `in_()` fetch, so
supplied ids cannot cross tenants; `principal=Depends(current_principal)` supplies authentication. No
per-object ACL below tenant level, but tenant scope is the stated boundary for this feature and no
cross-boundary read is reachable.

**`internal_b.py`** — **control present, applied indirectly.** No route body contains a check; the gate
is `@bp.before_request` (lines 13-17), which Flask runs for every request routed to this blueprint,
covering both `/internal/queue/depth` and `/internal/queue/redrive`. `hmac.compare_digest` against
`INTERNAL_API_TOKEN`, `abort(401)` on mismatch. CWE-306 closed.

**`attachments_b.py`** — **control present, deliberately subtle.** `current_principal` is gone from the
handler; ownership is enforced by `att: Attachment = Depends(owned_attachment)` (line 12). The
dependency resolves the path id to an object the caller owns, or fails, so the handler body never sees
an unvalidated `attachment_id` — the object is *already* authorized by the time line 14 runs. Stating
explicitly: this is PRESENT, not missing. The `attachment_id` path parameter no longer being a handler
argument is the tell.

**`reports_b.py`** — **control present, deliberately subtle.** `ReportService.__init__` takes the
principal (line 11) and `base()` applies `SavedReport.workspace_id == self.principal.workspace_id`
(lines 16-17). `get()` composes on top of `base()`, so the id filter can never widen the scope. The
`{"error": "not found"}` returned with HTTP 200 (line 29) is an API-correctness bug, not a control gap —
it discloses nothing.

**`download_b.py`** — `@login_required` plus `Document.objects.get(pk=doc_id, org_id=request.user.org_id)`
(line 11); a foreign pk raises `DoesNotExist` → 404, so the not-found and not-authorized paths are
indistinguishable. CWE-639 closed at org granularity, which is the pair's stated boundary.

---

## Consequences for the measured results

1. **The `email_b` false positive is confirmed a true positive.** Already disclosed in the research log
   and ADR-0027; this audit independently reaches the same conclusion from the source.
2. **`lookup_b` is a second, undisclosed instance** — and it is worse than `email_b` because the absence
   is in *both* arms of the pair, so `lookup_a`'s ground truth is incomplete too. The model's stored
   response for `lookup_b` mentions missing auth in its skipped list. Whether the classifier treated
   that as a flag determines whether the reported specificity for this pair is also affected; that
   should be re-checked directly rather than assumed.
3. **Both defects are in the same shape:** the author applied a control class only where it was the
   answer key. That is a systematic authoring bias, not two accidents, and it predicts the same
   omission in any future set authored the same way.
4. Recommended before any further use of this set: re-score with corrected labels for `email_b` and
   `lookup_a`/`lookup_b`, and make "audit every variant against the full absence list" a preregistered
   authoring step rather than a post-hoc fix.

## Unresolved questions

- Is `Account.external_ref` intended to be a public, unguessable reference (making `lookup_b`'s exposure
  a design choice) or an ordinary customer identifier? Nothing in the repo settles it. The absence of
  *any* auth on the endpoint makes the defect reading the stronger one either way, since even a public
  lookup should not return the internal primary key.
- Did the classifier score `lookup_b`'s "→ skipped: auth/rate-limit" as a finding? That determines
  whether the corrected label changes the reported FP rate or only the TP count.
- Should the corrected labels be applied to `evaluation/sast-fp-discrimination/authored-unseen-v2-260726.json`
  in place, or should a superseding artefact be written? Not actioned here — no files were modified.
