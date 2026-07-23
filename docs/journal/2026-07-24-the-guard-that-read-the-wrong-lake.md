# The guard that read the wrong lake

Date: 2026-07-24

Closing the lake-integrity work: land the Week-1 build on `main` under a branch name that
had stopped describing it, give the public repo a README, and reconcile the 11 WebGoat
findings the scanner had learned to spell differently. The reconciliation was the careful
part and went cleanly. The guard protecting it did not — and its failure was yesterday's
failure wearing a new mask.

## The reconciliation

The 11 rows carried absolute host paths (`/home/<user>/.../webgoat-src/...`) and a
directory-prefixed rule id; the wrapper now emits repository-relative paths and a bare id.
DefectDojo keys a Semgrep finding on `file_path + line + vuln_id_from_tool`, so the two
spellings are two different findings. Left to a plain reimport, the lake would have closed
all 11 as "remediated" and recreated them — a fabricated remediation, invisible to a
count-based check because the count never moves.

Done as an in-place API patch of the three identity fields, values derived deterministically
from the stored ones, current values written to a rollback file before the first write, and
the first PATCH used as the permission probe so a refusal would change nothing. Eleven 200s,
zero findings closed, the host-path/username leak gone as a side benefit. The record of what
the lake holds stayed true throughout.

## The guard that named a scan type it never selected

Verifying afterward, the shipped `verify-lake.sh --locator-scheme` probe reported `absolute`
for a Semgrep lake whose every row was now relative. It queried findings with
`test__test_type__name=Semgrep JSON Report`. DefectDojo does not register that lookup as a
finding filter, and an unregistered filter is not an error — it is **ignored**. The query
returned every active finding of every scan type, and a single absolute Trivy path
(`/juice-shop/...`) decided the answer for a scanner it had nothing to do with.

This is the exact shape from the day before: a check reporting a confident answer about
something it never isolated. Yesterday it was `grep -q` asserting nothing and a restore drill
that restored nothing. Today it was a filter that filtered nothing. The tell is identical —
the code names the thing it means to inspect, and never confirms it inspected only that.

The re-key guard consumes this probe. Had it shipped, the guard would have read `absolute`
forever (Trivy never leaves the lake), suppressing legitimate close-on-remediation for
Semgrep permanently — the reconciliation's whole point, silently undone by a guard that
could not see the scan type it was named for.

Fixed by resolving the type name to its `test_type` id and filtering on `test__test_type=<id>`.
Confirmed against the live lake three ways, because one reading proves nothing here: Semgrep
reads `relative`, Trivy reads `absolute`, an unknown type reads `unknown`.

## What not to repeat

A filter you did not verify narrows nothing. The API answers an unknown lookup by returning
everything, and code that trusts the query string believes it asked a narrow question. Verify
a filter the way you verify a guard: by counting what it returns against what it should, not
by reading the field name and trusting it means what it says.
