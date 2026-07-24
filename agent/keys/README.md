# agent/keys/ — Week-8 HITL approval keys

This directory holds ONLY the Ed25519 **public** verify key the graph runtime
(`agent/supervisor.py` / `agent/approval.py`) reads by default:

- `approver.pub` — the public key `state_change_node` uses to verify a signed
  `ApprovalToken` (RD1). This is safe to commit and to keep on the
  agent-readable path: a verify-only key cannot mint an approval.

## No private key lives here — by design

There is deliberately **no** private signing key in this directory, and there
never should be one. RD1's whole self-approval defense is that the agent's
own runtime physically cannot mint a valid approval token — it only ever
loads a public key (`agent.approval.load_public_key`). Placing a private key
anywhere the agent process can read (this directory included) breaks that
guarantee.

To approve a real proposal:

1. Generate your own Ed25519 keypair **out-of-band**, on a path the agent
   never reads (e.g. your home directory, a hardware key, a separate
   approval host) — not inside this repository or `agent/keys/`:

   ```bash
   rag/.venv/bin/python - <<'PY'
   from cryptography.hazmat.primitives import serialization
   from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

   priv = Ed25519PrivateKey.generate()
   with open("/path/outside/repo/approver-private.pem", "wb") as f:
       f.write(priv.private_bytes(serialization.Encoding.PEM,
                                   serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
   with open("/path/outside/repo/approver.pub", "wb") as f:
       f.write(priv.public_key().public_bytes(
           serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
   PY
   ```

2. Replace this directory's `approver.pub` with the matching public key you
   just generated (commit the public key; never the private one).
3. Run `agent/approve.py` yourself, passing the private key's path via the
   required `--key-file` argument — there is no default, and nothing in the
   agent's own code path ever reads it:

   ```bash
   rag/.venv/bin/python -m agent.approve --proposal-file proposal.json \
       --key-file /path/outside/repo/approver-private.pem --approver "j.doe" \
       --decision approve --out token.json
   ```

The committed `approver.pub` in this directory today is a demo/placeholder
key with **no** matching private key checked in anywhere — it verifies
nothing until you generate your own keypair and swap it in as above.
