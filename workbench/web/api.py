"""Typed metadata-only browser API facade."""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Mapping

from ..contracts import ContractViolation
from ..fixture_transport import command_envelope
from .schemas import validate_launch_payload
from .state import build_view_state


@dataclass(frozen=True)
class ProfileRegistry:
    profiles: Mapping[str, Mapping[str, str]]

    def get(self, profile_id: str) -> Mapping[str, str]:
        profile = self.profiles.get(profile_id)
        if profile is None or profile.get("profile_id") != profile_id:
            raise ContractViolation("profile is not registered")
        return profile


class WorkbenchAPI:
    def __init__(
        self,
        *,
        registry: ProfileRegistry,
        cmc_gate: Mapping[str, object],
        broker_origin: str | None = None,
    ) -> None:
        if broker_origin is not None and (
            not isinstance(broker_origin, str)
            or re.fullmatch(r"http://127\.0\.0\.1:\d+", broker_origin) is None
        ):
            raise ContractViolation("browser API broker origin must be a literal loopback origin")
        self._registry = registry
        self._cmc_gate = dict(cmc_gate)
        self._broker_origin = broker_origin
        self._research = {"kind": "not-measured", "reason_code": "no-eligible-corpus"}

    def view(self) -> dict[str, object]:
        view = build_view_state(research=self._research, cmc_gate=self._cmc_gate)
        if self._broker_origin is not None:
            view["broker"] = {"origin": self._broker_origin}
            view["fixture_transport"] = {
                "enabled": True,
                "command": command_envelope(),
                "detail": "This proves only the local broker/worker refusal path. It never scans source while scanner policy is not ready.",
            }
        return view

    def launch(self, payload: object) -> dict[str, object]:
        data = validate_launch_payload(payload)
        profile = self._registry.get(data["profile_id"])
        if data["comparison_id"] != profile.get("comparison_id"):
            raise ContractViolation("comparison is not registered for the profile")
        if data["mode"] == "research" and self._research["kind"] != "named-contrast":
            raise ContractViolation("research launch is disabled until its corpus/evidence gates pass")
        return {
            "status": "queued",
            "profile_id": profile["profile_id"],
            "comparison_id": profile["comparison_id"],
            "config_digest": profile["config_digest"],
        }
