"""Synthetic mock user-dump fixture for the Week-9 simulated state-changing action (decision 0017).

PROVENANCE — every value below is SYNTHETIC and hand-authored solely to exercise the PII redactor
(`agent/pii.py`). Nothing here is scraped from a running target or a real person:

- **Card numbers** are the well-known PUBLIC Luhn-valid TEST PANs (Visa/Mastercard test ranges) that
  authorize no real transaction. One row deliberately stores the PAN as a JSON *number* (not a
  string) to prove the capture scrub covers int-typed fields (decision 0017, H1).
- **Emails** use OWASP Juice Shop's PUBLIC `@juice-sh.op` teaching domain.
- **Password hashes** are unsalted MD5 of throwaway strings — the crackable-value shape the redactor
  removes via the credential-assignment pass while the weak-hashing finding survives (W9-D2a). One
  row embeds an email inside a free-text `security_answer` column to prove whole-row scrubbing, not
  named-column scrubbing (H2).
- **Sessions** are a synthetic JWT and a synthetic UUID.

This module exists so the simulated dump node has genuine PII SHAPES to redact WITHOUT ever touching
real data. The `assert_synthetic()` guard is called by the test suite to fail closed if a real value
is ever introduced here.
"""

from __future__ import annotations

# A small "users table" the simulated (dry-run) action would have returned. Mixed field types on
# purpose: str PAN, int PAN, a free-text column carrying an email, a JWT, and a UUID session id.
SIMULATED_USER_DUMP: list[dict[str, object]] = [
    {
        "id": 1,
        "email": "admin@juice-sh.op",
        # Juice Shop's real Users column is `password` (unsalted MD5). The credential-assignment
        # pass removes this crackable VALUE (W9-D2a); the "weak hashing" finding survives via the
        # class label + column + endpoint, which never needed the literal digest.
        "password": "0192023a7bbd73250516f069df18b500",
        "card_number": "4532015112830366",
        "session": "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoxLCJyb2xlIjoiYWRtaW4ifQ.c2lnbmF0dXJlX3N0dWI",
        "security_answer": "my first pet lived at rsa_lord@juice-sh.op",
    },
    {
        "id": 2,
        "email": "jim@juice-sh.op",
        "password": "e10adc3949ba59abbe56e057f20f883e",
        "card_number": 4111111111111111,  # int-typed PAN on purpose (H1)
        "session_uuid": "7d3f2a1b-4c5d-6e7f-8a9b-0c1d2e3f4a5b",
    },
]

# Every synthetic PII token the redactor is expected to remove, for the recall oracle. Kept in one
# place so the test proves recall against exactly what the fixture plants (no more, no less).
EXPECTED_PII_CLASSES = {"email", "card", "jwt", "uuid"}


def assert_synthetic() -> None:
    """Fail closed if a value that could be real data is introduced. The card numbers must be the
    known public test PANs; the domain must be the public teaching domain. Called from the test
    suite so a future edit that pastes real data trips the guard."""
    allowed_test_pans = {"4532015112830366", "4111111111111111"}
    allowed_domain = "@juice-sh.op"
    for row in SIMULATED_USER_DUMP:
        for key, val in row.items():
            if "card" in key:
                assert str(val) in allowed_test_pans, f"non-test PAN in fixture: {key}"
            if isinstance(val, str) and "@" in val:
                assert allowed_domain in val, f"non-teaching-domain email in fixture: {key}"
