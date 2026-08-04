"""Host-owned B3 dispatcher: route health, exactly-once state, and quarantine."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tempfile
from typing import Callable, Iterable, Mapping, Protocol

from .analysis_population import SelectionManifest
from .b3_attempt_store import AttemptStoreViolation, B3AttemptStore
from .egress import (
    B3Route,
    EgressViolation,
    _ROUTE_AUTHORITY,
    _read_scoped_key,
    prepare_b3_request,
    quarantine_response,
)


class B3DispatcherViolation(ValueError):
    """Raised when a B3 call cannot satisfy the frozen host boundary."""


class _B3HostTransport(Protocol):
    def complete(
        self,
        prompt: str,
        *,
        route_id: str,
        parameters: Mapping[str, object],
    ) -> object:
        ...


@dataclass(frozen=True)
class B3DispatchReceipt:
    attempt_id: str
    run_id: str
    reading: int
    unit_id: str
    status: str
    proposal_ids: tuple[str, ...]
    response_digest: str | None


class _FixtureTransport:
    """Deterministic no-network response source for fixture-only tests."""

    def __init__(self, responses: Iterable[object]) -> None:
        self._responses = iter(responses)
        self.calls = 0

    def complete(
        self,
        _prompt: str,
        *,
        route_id: str,
        parameters: Mapping[str, object],
    ) -> object:
        if route_id != "workbench-b3-no-trace" or parameters.get("tools") is not False:
            raise B3DispatcherViolation("fixture B3 transport received an invalid frozen request")
        self.calls += 1
        return next(self._responses)


class _DisabledHostTransport:
    """Credential-bearing host transport kept inert until worker integration exists."""

    __slots__ = ("_scoped_key",)

    def __init__(self, scoped_key: str) -> None:
        self._scoped_key = scoped_key

    def __repr__(self) -> str:
        return "<DisabledHostB3Transport>"

    def complete(
        self,
        _prompt: str,
        *,
        route_id: str,
        parameters: Mapping[str, object],
    ) -> object:
        del route_id, parameters
        raise B3DispatcherViolation(
            "live B3 dispatch is disabled until a host worker owns the no-trace provider transport"
        )


_DISPATCHER_AUTHORITY = object()


class B3Dispatcher:
    """The only accepted B3 dispatch boundary.

    A fixture dispatcher is deterministic and has no credential. A host
    dispatcher owns the scoped virtual key in a non-serializable private
    transport and fails closed until the host B3 worker is wired in.
    """

    def __init__(
        self,
        *,
        route: B3Route,
        attempt_store: B3AttemptStore,
        transport: _B3HostTransport,
        healthcheck: Callable[[B3Route], bool],
        config_digest: str,
        _authority_token: object = None,
        _fixture_directory: tempfile.TemporaryDirectory[str] | None = None,
    ) -> None:
        if _authority_token is not _DISPATCHER_AUTHORITY:
            raise B3DispatcherViolation("B3 dispatchers must be issued by the host transport factory")
        if not isinstance(route, B3Route) or not isinstance(attempt_store, B3AttemptStore):
            raise B3DispatcherViolation("B3 dispatcher requires host-issued route and attempt store")
        if not callable(healthcheck) or not callable(getattr(transport, "complete", None)) or not isinstance(config_digest, str) or len(config_digest) != 64:
            raise B3DispatcherViolation("B3 dispatcher requires a health check and frozen config digest")
        self._route = route
        self._attempts = attempt_store
        self._transport = transport
        self._healthcheck = healthcheck
        self._config_digest = config_digest
        self._fixture_directory = _fixture_directory

    @classmethod
    def for_fixture(
        cls,
        responses: Iterable[object],
        *,
        route: B3Route | None = None,
        attempt_store: B3AttemptStore | None = None,
        healthcheck: Callable[[B3Route], bool] | None = None,
        config_digest: str = "0" * 64,
    ) -> "B3Dispatcher":
        """Construct a deterministic no-network fixture dispatcher with no key."""
        fixture_route = route or B3Route("workbench-b3-no-trace", _ROUTE_AUTHORITY)
        fixture_directory = None
        if attempt_store is None:
            fixture_directory = tempfile.TemporaryDirectory(prefix="sentinel-workbench-b3-fixture-")
            attempt_store = B3AttemptStore(Path(fixture_directory.name) / "attempts.sqlite")
        return cls(
            route=fixture_route,
            attempt_store=attempt_store,
            transport=_FixtureTransport(responses),
            healthcheck=healthcheck or (lambda _route: True),
            config_digest=config_digest,
            _authority_token=_DISPATCHER_AUTHORITY,
            _fixture_directory=fixture_directory,
        )

    @classmethod
    def from_host_config(
        cls,
        *,
        route_id: str,
        key_path: Path | str,
        attempt_store: B3AttemptStore,
        healthcheck: Callable[[B3Route], bool],
        config_digest: str,
        expected_config_digest: str,
    ) -> "B3Dispatcher":
        """Issue a key-owning dispatcher only for the host B3 worker process."""
        route = B3Route.from_host_config(
            route_id=route_id,
            key_path=key_path,
            config_digest=config_digest,
            expected_config_digest=expected_config_digest,
        )
        return cls(
            route=route,
            attempt_store=attempt_store,
            transport=_DisabledHostTransport(_read_scoped_key(key_path)),
            healthcheck=healthcheck,
            config_digest=config_digest,
            _authority_token=_DISPATCHER_AUTHORITY,
        )

    @property
    def fixture_calls(self) -> int:
        return self._transport.calls if isinstance(self._transport, _FixtureTransport) else 0

    def dispatch(
        self,
        *,
        run_id: str,
        selection: SelectionManifest,
        reading: int,
        unit_id: str,
    ) -> B3DispatchReceipt:
        if not selection.is_authorized() or reading not in (1, 2, 3):
            raise B3DispatcherViolation("B3 dispatch requires an authorized selection and one of three readings")
        if not self._healthcheck(self._route):
            raise B3DispatcherViolation("B3 route health check failed closed")
        try:
            attempt = self._attempts.reserve(
                run_id=run_id,
                arm="B3",
                replication=reading,
                selection_manifest_digest=selection.digest,
                profile=self._route.route_id,
                unit_id=unit_id,
            )
        except AttemptStoreViolation as error:
            raise B3DispatcherViolation("B3 attempt reservation is not unique") from error
        try:
            prepared = prepare_b3_request(selection=selection, unit_id=unit_id, route=self._route)
        except EgressViolation as error:
            self._attempts.mark_rejected(attempt.attempt_id, reason="egress-admission-failed")
            raise B3DispatcherViolation("B3 egress admission failed before provider I/O") from error
        try:
            self._attempts.mark_dispatched(attempt.attempt_id, profile=self._route.route_id)
        except AttemptStoreViolation as error:
            try:
                self._attempts.mark_rejected(attempt.attempt_id, reason="revoked-or-invalid-before-provider-dispatch")
            except AttemptStoreViolation:
                pass
            raise B3DispatcherViolation("B3 dispatch was rejected before provider I/O") from error
        try:
            response = self._transport.complete(
                prepared.prompt,
                route_id=self._route.route_id,
                parameters={
                    "stream": False,
                    "temperature": 0,
                    "top_p": 1,
                    "max_output_tokens": 2048,
                    "tools": False,
                    "config_digest": self._config_digest,
                },
            )
            quarantined = quarantine_response(response, admitted_unit_ids=selection.unit_ids)
            self._attempts.mark_terminal(attempt.attempt_id, status="succeeded")
            return B3DispatchReceipt(
                attempt.attempt_id,
                run_id,
                reading,
                unit_id,
                "succeeded",
                quarantined.proposal_ids,
                str(quarantined.record["response_digest"]),
            )
        except Exception as error:
            try:
                self._attempts.mark_unknown(attempt.attempt_id, reason="provider-transport-or-quarantine-failed")
            except AttemptStoreViolation:
                pass
            raise B3DispatcherViolation("B3 provider outcome is unknown and non-retryable") from error
