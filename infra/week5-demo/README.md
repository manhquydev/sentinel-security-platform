# Week-5 demo facade

Loopback HTTP sidecar for IPI / HITL preview / labeled PII. It does **not**
send traffic to Kong or Juice Shop. Real Charter HITL remains
`scripts/sentinel-charter-approve.py`.

Host only: `http://127.0.0.1:18055`

```bash
# without Docker
PYTHONPATH=. python3 scripts/sentinel-week5-demo.py

# with Docker (publish stays 127.0.0.1)
docker compose -f infra/week5-demo/docker-compose.yml up --build -d --wait
bash scripts/week5-demo-curl.sh
PYTHON=.venv/bin/python bash tests/week5-demo-facade-test.sh
```

Postman from **this laptop** into that URL. Do not bind `0.0.0.0` on the host.
Do not import `infra/.env`.
