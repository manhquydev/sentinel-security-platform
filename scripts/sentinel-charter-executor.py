#!/usr/bin/env python3
"""Trusted local executor. It is the only Phase-3 process permitted to read its OAuth secret."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import requests
from cryptography.hazmat.primitives import serialization

from agent.charter_requests import CharterRequestError, RequestSpec, RequestStore, ResponseObservation, execute, load_spec


class RequestsTransport:
    def mint(self, origin: str, client_secret: str) -> str:
        response = requests.post(origin + "/oauth/oauth2/token", json={
            "client_id": "sentinel-charter-executor", "client_secret": client_secret,
            "grant_type": "client_credentials"}, timeout=5, verify=False, allow_redirects=False)
        response.raise_for_status()
        token = response.json().get("access_token")
        if not isinstance(token, str) or not token: raise RuntimeError("OAuth response lacked access token")
        return token

    def request(self, url, method, headers, body, timeout, cap):
        response = requests.request(method, url, headers=headers, data=body, timeout=timeout, verify=False,
                                    allow_redirects=False, stream=True)
        data = bytearray()
        for chunk in response.iter_content(8192):
            data.extend(chunk)
            if len(data) > cap: raise RuntimeError("response exceeds charter cap")
        raw_headers = getattr(getattr(response, "raw", None), "headers", None)
        getlist = getattr(raw_headers, "getlist", None)
        values = getlist("Content-Type") if callable(getlist) else []
        return ResponseObservation(response.status_code, bytes(data), tuple(values))


def _spec(path: str) -> RequestSpec:
    return load_spec(json.loads(Path(path).read_text(encoding="utf-8")))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("spec"); parser.add_argument("approval")
    parser.add_argument("--state", required=True); parser.add_argument("--public-key", required=True)
    args = parser.parse_args(argv)
    try:
        spec = _spec(args.spec)
    except (CharterRequestError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"refused": "invalid persisted request spec"}), file=sys.stderr)
        return 2
    secret = os.environ.get("SENTINEL_CHARTER_EXECUTOR_SECRET")
    api_key = os.environ.get("SENTINEL_CHARTER_EXECUTOR_API_KEY")
    if not secret or not api_key:
        print(json.dumps({"refused": "executor-credential-required"}), file=sys.stderr); return 2
    store = None
    try:
        store = RequestStore(args.state)
        approval = json.loads(Path(args.approval).read_text(encoding="utf-8"))
        public = serialization.load_pem_public_key(Path(args.public_key).read_bytes())
        result = execute(spec, approval, public_key=public, store=store,
                         transport=RequestsTransport(), executor_secret=secret, executor_api_key=api_key)
        print(json.dumps(result, sort_keys=True)); return 0
    except CharterRequestError as exc:
        print(json.dumps({"refused": str(exc)}), file=sys.stderr); return 2
    finally:
        if store is not None:
            store.close()


if __name__ == "__main__": raise SystemExit(main())
