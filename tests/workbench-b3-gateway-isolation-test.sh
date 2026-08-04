#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$ROOT/infra/workbench/b3-litellm-config.yaml"
COMPOSE="$ROOT/infra/workbench/b3-litellm-compose.yml"

python3 - "$CONFIG" "$COMPOSE" <<'PY'
import pathlib
import sys
import yaml

config = yaml.safe_load(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
compose = yaml.safe_load(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))

settings = config["litellm_settings"]
assert settings["turn_off_message_logging"] is True
assert settings["success_callback"] == []
assert settings["failure_callback"] == []
assert config["model_list"][0]["litellm_params"]["stream"] is False
assert "langfuse" not in repr(config).lower()
assert "infra/litellm" not in repr(compose).lower()

service = compose["services"]["b3-litellm"]
assert service["ports"] == ["127.0.0.1:4013:4013"]
assert service["volumes"] == ["./b3-litellm-config.yaml:/app/b3-litellm-config.yaml:ro"]
assert set(service["networks"]) == {"b3-control", "b3-provider"}
assert service["read_only"] is True
assert "docker.sock" not in repr(compose).lower()
assert "source" not in repr(compose).lower()
assert "B3_LITELLM_VIRTUAL_KEY" not in repr(compose)
PY
