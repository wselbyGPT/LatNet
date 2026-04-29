from __future__ import annotations

import argparse
import json
import time
import uuid
from pathlib import Path
from typing import Any

from .authority import (
    export_authority_pub_file,
    init_authority_file,
    make_bundle_file,
    sign_relay_file,
)
from .client import (
    ClientTrustConfig,
    CircuitSession,
    HopSession,
    NO_DESCRIPTOR_ERROR,
    build_circuit,
    destroy_circuit,
    end_stream,
    fetch_bundle_from_directory,
    fetch_bundle_to_file,
    fetch_hidden_service_descriptor_from_directory,
    fetch_verified_relays_from_directory,
    load_client_trust_config,
    publish_hidden_service_descriptor_to_directory,
    open_stream,
    send_stream_data,
    select_intro_point_for_phase1,
)
from .models.hidden_service_descriptor import verify_hidden_service_descriptor_v2
from .directory import run_directory_server
from .hidden_service_runtime import (
    DEFAULT_RELIABILITY_CONFIG,
    HiddenServiceRuntimeError,
    ReliabilityConfig,
    ServiceCircuit,
    build_intro_circuits,
    build_service_circuit,
    error_to_dict,
    handle_intro_request_with_echo,
    load_service_material,
    poll_intro_requests,
    rendezvous_close,
    rendezvous_recv,
    rendezvous_send,
)
from .relay import RelayServer, init_relay_file, run_relay_server
from .observability import EventEmitter, Metrics
from .util import atomic_write_json, b64d, b64e, load_json
from .selection.policy import select_path


def _load_relays(paths: list[str]) -> list[dict[str, Any]]:
    return [load_json(path) for path in paths]


def _session_to_json(circuit: CircuitSession) -> dict[str, Any]:
    return {
        "circuit_id": circuit.circuit_id,
        "guard_host": circuit.guard_host,
        "guard_port": circuit.guard_port,
        "hops": [
            {
                "name": hop.name,
                "host": hop.host,
                "port": hop.port,
                "forward_key": b64e(hop.forward_key),
                "reverse_key": b64e(hop.reverse_key),
            }
            for hop in circuit.hops
        ],
        "stream_next_seq": circuit.stream_next_seq,
    }


def _session_from_json(data: dict[str, Any]) -> CircuitSession:
    return CircuitSession(
        circuit_id=str(data["circuit_id"]),
        guard_host=str(data["guard_host"]),
        guard_port=int(data["guard_port"]),
        hops=[
            HopSession(
                name=str(hop["name"]),
                host=str(hop["host"]),
                port=int(hop["port"]),
                forward_key=b64d(hop["forward_key"]),
                reverse_key=b64d(hop["reverse_key"]),
            )
            for hop in data["hops"]
        ],
        stream_next_seq={int(k): int(v) for k, v in dict(data.get("stream_next_seq", {})).items()},
    )


def _load_session(path: str) -> CircuitSession:
    return _session_from_json(load_json(path))


def _save_session(path: str, circuit: CircuitSession) -> None:
    atomic_write_json(path, _session_to_json(circuit))


def _print_json(data: dict[str, Any]) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


def _hs_circuit_to_json(circuit: ServiceCircuit) -> dict[str, Any]:
    return {
        "circuit_id": circuit.circuit_id,
        "guard_host": circuit.guard_host,
        "guard_port": circuit.guard_port,
        "forward_keys": [b64e(key) for key in circuit.forward_keys],
        "reverse_keys": [b64e(key) for key in circuit.reverse_keys],
    }


def _hs_circuit_from_json(data: dict[str, Any]) -> ServiceCircuit:
    return ServiceCircuit(
        circuit_id=str(data["circuit_id"]),
        guard_host=str(data["guard_host"]),
        guard_port=int(data["guard_port"]),
        forward_keys=[b64d(item) for item in data["forward_keys"]],
        reverse_keys=[b64d(item) for item in data["reverse_keys"]],
    )


def _save_hs_session(path: str, data: dict[str, Any]) -> None:
    atomic_write_json(path, data)


def _load_hs_session(path: str) -> dict[str, Any]:
    return load_json(path)




def _reliability_config_from_args(args: argparse.Namespace) -> ReliabilityConfig:
    return ReliabilityConfig(
        join_timeout_s=max(0.0, float(getattr(args, "join_timeout", DEFAULT_RELIABILITY_CONFIG.join_timeout_s))),
        poll_interval_s=max(0.0, float(getattr(args, "poll_interval", DEFAULT_RELIABILITY_CONFIG.poll_interval_s))),
        max_retries=max(1, int(getattr(args, "max_retries", DEFAULT_RELIABILITY_CONFIG.max_retries))),
        retry_backoff_base_s=max(0.0, float(getattr(args, "retry_backoff_base", DEFAULT_RELIABILITY_CONFIG.retry_backoff_base_s))),
        retry_backoff_max_s=max(0.0, float(getattr(args, "retry_backoff_max", DEFAULT_RELIABILITY_CONFIG.retry_backoff_max_s))),
    )


def _runtime_error_output(error: Exception, **extra: Any) -> dict[str, Any]:
    payload = {"ok": False, "error": error_to_dict(error)}
    payload.update(extra)
    return payload


def _error_code(error: Exception) -> str:
    details = error_to_dict(error)
    return str(details.get("code") or "unknown_error")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="latnet", description="LatNet operational CLI")
    subparsers = parser.add_subparsers(dest="top_cmd", required=True)

    circuit = subparsers.add_parser("circuit", help="Circuit lifecycle operations")
    circuit_sub = circuit.add_subparsers(dest="circuit_cmd", required=True)

    circuit_build = circuit_sub.add_parser("build", help="Build a circuit and persist its session")
    circuit_build.add_argument("relays", nargs="*", help="Relay descriptor JSON paths in guard->exit order")
    circuit_build.add_argument("--session", default=".latnet-circuit.json", help="Circuit session output file")
    circuit_build.add_argument("--circuit-id", default=None, help="Optional circuit ID override")
    circuit_build.add_argument("--directory-host", default=None, help="Directory host for verified relay discovery")
    circuit_build.add_argument("--directory-port", type=int, default=9200, help="Directory port for verified relay discovery")
    circuit_build.add_argument("--relay-names", nargs="+", default=None, help="Relay names from verified snapshot in guard->exit order")
    circuit_build.add_argument("--policy", choices=["ordered", "first_valid"], default="ordered", help="Path selection policy for verified relays")
    circuit_build.add_argument("--middle-count", type=int, default=1, help="Number of middle hops when using policy selection mode")
    circuit_build.add_argument("--guard-weight-multiplier", type=float, default=1.0, help="Guard role effective-weight multiplier")
    circuit_build.add_argument("--middle-weight-multiplier", type=float, default=1.0, help="Middle role effective-weight multiplier")
    circuit_build.add_argument("--exit-weight-multiplier", type=float, default=1.0, help="Exit role effective-weight multiplier")
    circuit_build.add_argument("--min-reliability-cutoff", type=float, default=0.0, help="Minimum relay reliability score to receive non-zero effective weight")
    circuit_build.add_argument("--selection-seed", type=int, default=None, help="Optional deterministic seed for policy-based relay selection")
    circuit_build.add_argument("--guard-state", default=".latnet-guards.json", help="Persistent guard state JSON path")
    circuit_build.add_argument("--trust-config", default=None, help="Trust config JSON file path")
    circuit_build.add_argument("--trusted-authority", action="append", default=[], help="Trusted authority as authority_id=public_key")
    circuit_build.add_argument("--min-signers", type=int, default=None, help="Threshold min_signers policy override")
    circuit_build.add_argument("--authority-set-version", type=int, default=None, help="Optional authority set epoch/version")
    circuit_build.add_argument("--allow-legacy-single-authority", action="store_true", help="Lab-only escape hatch for unsigned legacy bundle")

    circuit_destroy = circuit_sub.add_parser("destroy", help="Destroy a persisted circuit")
    circuit_destroy.add_argument("--session", default=".latnet-circuit.json", help="Circuit session file")

    stream = subparsers.add_parser("stream", help="Stream operations over an existing circuit")
    stream_sub = stream.add_subparsers(dest="stream_cmd", required=True)

    stream_open = stream_sub.add_parser("open", help="Open a stream")
    stream_open.add_argument("--session", default=".latnet-circuit.json", help="Circuit session file")
    stream_open.add_argument("--stream-id", type=int, required=True, help="Stream ID")
    stream_open.add_argument("--target", default="", help="Target string (e.g. example:443)")

    stream_send = stream_sub.add_parser("send", help="Send stream DATA payload")
    stream_send.add_argument("--session", default=".latnet-circuit.json", help="Circuit session file")
    stream_send.add_argument("--stream-id", type=int, required=True, help="Stream ID")
    stream_send.add_argument("payload", help="Payload string")

    stream_end = stream_sub.add_parser("end", help="End a stream")
    stream_end.add_argument("--session", default=".latnet-circuit.json", help="Circuit session file")
    stream_end.add_argument("--stream-id", type=int, required=True, help="Stream ID")
    stream_end.add_argument("--payload", default="", help="Optional END payload")

    hs = subparsers.add_parser("hs", help="Hidden service operations")
    hs_sub = hs.add_subparsers(dest="hs_cmd", required=True)

    hs_fetch = hs_sub.add_parser("fetch", help="Fetch hidden service descriptor from directory")
    hs_fetch.add_argument("service_name", help="Service name (*.lettuce)")
    hs_fetch.add_argument("--host", default="127.0.0.1", help="Directory host")
    hs_fetch.add_argument("--port", type=int, default=9200, help="Directory port")
    hs_fetch.add_argument("--out", default=None, help="Optional output file path")

    hs_serve = hs_sub.add_parser("serve", help="Start hidden service runtime process mode")
    hs_serve.add_argument("--service-master", required=True, help="Hidden service master key JSON")
    hs_serve.add_argument("--descriptor", required=True, help="Hidden service descriptor JSON")
    hs_serve.add_argument("relays", nargs="+", help="Relay descriptor JSON paths")
    hs_serve.add_argument("--poll-interval", type=float, default=DEFAULT_RELIABILITY_CONFIG.poll_interval_s, help="Poll interval seconds")
    hs_serve.add_argument("--join-timeout", type=float, default=DEFAULT_RELIABILITY_CONFIG.join_timeout_s, help="Join timeout seconds")
    hs_serve.add_argument("--max-retries", type=int, default=DEFAULT_RELIABILITY_CONFIG.max_retries, help="Max retries for retriable relay errors")
    hs_serve.add_argument("--retry-backoff-base", type=float, default=DEFAULT_RELIABILITY_CONFIG.retry_backoff_base_s, help="Retry backoff base seconds")
    hs_serve.add_argument("--retry-backoff-max", type=float, default=DEFAULT_RELIABILITY_CONFIG.retry_backoff_max_s, help="Retry backoff max seconds")
    hs_serve.add_argument("--once", action="store_true", help="Run a single poll cycle and exit")

    hs_connect = hs_sub.add_parser("connect", help="Build rendezvous flow and open HS stream")
    hs_connect.add_argument("service_name", help="Service name (*.lettuce)")
    hs_connect.add_argument("relay", help="Rendezvous relay descriptor JSON path")
    hs_connect.add_argument("--host", default="127.0.0.1", help="Directory host")
    hs_connect.add_argument("--port", type=int, default=9200, help="Directory port")
    hs_connect.add_argument("--session", default=".latnet-hs.json", help="HS session output file")
    hs_connect.add_argument("--trust-config", default=None, help="Trust config JSON file path")
    hs_connect.add_argument("--trusted-authority", action="append", default=[], help="Trusted authority as authority_id=public_key")
    hs_connect.add_argument("--min-signers", type=int, default=None, help="Threshold min_signers policy override")
    hs_connect.add_argument("--authority-set-version", type=int, default=None, help="Optional authority set epoch/version")
    hs_connect.add_argument("--allow-legacy-single-authority", action="store_true", help="Lab-only escape hatch for unsigned legacy bundle")

    hs_send = hs_sub.add_parser("send", help="Relay a message payload over persisted HS session")
    hs_send.add_argument("--session", default=".latnet-hs.json", help="HS session file")
    hs_send.add_argument("payload", help="Payload string")

    hs_recv = hs_sub.add_parser("recv", help="Receive message payload from persisted HS session")
    hs_recv.add_argument("--session", default=".latnet-hs.json", help="HS session file")
    hs_recv.add_argument("--follow", action="store_true", help="Keep polling for messages until timeout or interruption")
    hs_recv.add_argument("--timeout", type=float, default=5.0, help="Timeout in seconds for receive loop")
    hs_recv.add_argument("--max-retries", type=int, default=DEFAULT_RELIABILITY_CONFIG.max_retries, help="Max retries for retriable relay errors")
    hs_recv.add_argument("--retry-backoff-base", type=float, default=DEFAULT_RELIABILITY_CONFIG.retry_backoff_base_s, help="Retry backoff base seconds")
    hs_recv.add_argument("--retry-backoff-max", type=float, default=DEFAULT_RELIABILITY_CONFIG.retry_backoff_max_s, help="Retry backoff max seconds")

    hs_end = hs_sub.add_parser("end", help="Close/finalize HS session")
    hs_end.add_argument("--session", default=".latnet-hs.json", help="HS session file")
    hs_end.add_argument("--payload", default="", help="Optional END payload")

    hs_publish = hs_sub.add_parser("publish", help="Publish hidden service descriptor to directory")
    hs_publish.add_argument("--service-master", required=True, help="Hidden service master key JSON")
    hs_publish.add_argument("--descriptor", required=True, help="Hidden service descriptor JSON")
    hs_publish.add_argument("--host", default="127.0.0.1", help="Directory host")
    hs_publish.add_argument("--port", type=int, default=9200, help="Directory port")
    hs_publish.add_argument("--expected-revision", type=int, default=None, help="Expected previous descriptor revision")
    hs_publish.add_argument("--idempotency-key", default=None, help="Optional idempotency key")

    hs_rotate = hs_sub.add_parser("rotate", help="Rotate hidden service descriptor with read-after-write verification")
    hs_rotate.add_argument("--service-master", required=True, help="Hidden service master key JSON")
    hs_rotate.add_argument("--descriptor", required=True, help="Hidden service descriptor JSON")
    hs_rotate.add_argument("--host", default="127.0.0.1", help="Directory host")
    hs_rotate.add_argument("--port", type=int, default=9200, help="Directory port")
    hs_rotate.add_argument("--idempotency-key", default=None, help="Optional idempotency key")
    hs_rotate.add_argument(
        "--verify-timeout",
        type=float,
        default=5.0,
        help="Timeout in seconds for read-after-write verification",
    )
    hs_rotate.add_argument(
        "--print-rollback-hints",
        action="store_true",
        help="Include rollback hints in output",
    )


    admin = subparsers.add_parser("admin", help="Administrative operations")
    admin_sub = admin.add_subparsers(dest="admin_cmd", required=True)

    admin_guard = admin_sub.add_parser("guard-state", help="View or reset guard state")
    admin_guard.add_argument("operation", choices=["view", "reset"])
    admin_guard.add_argument("--guard-state", default=".latnet-guards.json", help="Persistent guard state JSON path")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    def _parse_authority_flags(values: list[str]) -> list[dict[str, str]]:
        authorities: list[dict[str, str]] = []
        for item in values:
            authority_id, sep, public_key = item.partition("=")
            if not sep or not authority_id or not public_key:
                raise ValueError("trusted authority must use authority_id=public_key")
            authorities.append({"authority_id": authority_id, "public_key": public_key})
        return authorities

    def _trust_from_args(ns: argparse.Namespace) -> ClientTrustConfig | None:
        trusted = _parse_authority_flags(getattr(ns, "trusted_authority", []))
        has_explicit = bool(trusted) or getattr(ns, "trust_config", None) or getattr(ns, "min_signers", None) is not None
        has_explicit = has_explicit or getattr(ns, "authority_set_version", None) is not None
        if not has_explicit and not getattr(ns, "allow_legacy_single_authority", False):
            return load_client_trust_config()
        if not has_explicit:
            return None
        return load_client_trust_config(
            trust_config_path=getattr(ns, "trust_config", None),
            trusted_authorities=trusted or None,
            min_signers=getattr(ns, "min_signers", None),
            authority_set_version=getattr(ns, "authority_set_version", None),
        )

    if args.top_cmd == "circuit" and args.circuit_cmd == "build":
        if args.directory_host:
            trust = _trust_from_args(args)
            verified_relays = fetch_verified_relays_from_directory(
                host=args.directory_host,
                port=args.directory_port,
                trust=trust,
                allow_legacy_single_authority=bool(args.allow_legacy_single_authority),
            )
            candidate_relays = list(verified_relays.values())
            policy = args.policy
            if args.relay_names:
                policy = "ordered"
            selection_state = {
                "relay_names": args.relay_names,
                "middle_count": args.middle_count,
                "rng_seed": args.selection_seed,
                "policy_config": {
                    "guard_weight_multiplier": args.guard_weight_multiplier,
                    "middle_weight_multiplier": args.middle_weight_multiplier,
                    "exit_weight_multiplier": args.exit_weight_multiplier,
                    "min_reliability_cutoff": args.min_reliability_cutoff,
                },
                "guard_state_path": args.guard_state,
            }
            selected_relays = select_path(candidate_relays, policy=policy, state=selection_state)
            circuit = build_circuit(selected_relays, circuit_id=args.circuit_id)
        else:
            if not args.relays:
                raise ValueError("provide relay descriptors or --directory-host")
            selected_relays = _load_relays(args.relays)
            selected_relays = select_path(
                selected_relays,
                policy="ordered",
                state={"relay_names": [str(relay.get("name", "")) for relay in selected_relays]},
            )
            circuit = build_circuit(selected_relays, circuit_id=args.circuit_id)
        _save_session(args.session, circuit)
        _print_json({"ok": True, "session": str(Path(args.session)), "circuit_id": circuit.circuit_id})
        return 0

    if args.top_cmd == "circuit" and args.circuit_cmd == "destroy":
        circuit = _load_session(args.session)
        response = destroy_circuit(circuit)
        _save_session(args.session, circuit)
        _print_json(response)
        return 0

    if args.top_cmd == "stream" and args.stream_cmd == "open":
        circuit = _load_session(args.session)
        reply = open_stream(circuit, stream_id=args.stream_id, target=args.target)
        _save_session(args.session, circuit)
        _print_json(reply)
        return 0

    if args.top_cmd == "stream" and args.stream_cmd == "send":
        circuit = _load_session(args.session)
        reply = send_stream_data(circuit, stream_id=args.stream_id, payload=args.payload)
        _save_session(args.session, circuit)
        _print_json(reply)
        return 0

    if args.top_cmd == "stream" and args.stream_cmd == "end":
        circuit = _load_session(args.session)
        reply = end_stream(circuit, stream_id=args.stream_id, payload=args.payload)
        _save_session(args.session, circuit)
        _print_json(reply)
        return 0

    if args.top_cmd == "admin" and args.admin_cmd == "guard-state":
        from .selection.policy import _guard_state_defaults

        guard_file = Path(args.guard_state)
        if args.operation == "reset":
            data = _guard_state_defaults(int(time.time()))
            atomic_write_json(str(guard_file), data)
            _print_json({"ok": True, "operation": "reset", "guard_state": str(guard_file)})
            return 0

        if guard_file.exists():
            _print_json(load_json(str(guard_file)))
        else:
            _print_json(_guard_state_defaults(int(time.time())))
        return 0

    if args.top_cmd == "hs" and args.hs_cmd == "fetch":
        descriptor = fetch_hidden_service_descriptor_from_directory(
            host=args.host,
            port=args.port,
            service_name=args.service_name,
        )
        if args.out:
            atomic_write_json(args.out, descriptor)
        _print_json(descriptor)
        return 0

    if args.top_cmd == "hs" and args.hs_cmd == "serve":
        service_material = load_service_material(args.service_master, args.descriptor)
        parsed_descriptor = service_material["parsed_descriptor"]
        emitter = EventEmitter(component="hs.service", service_name=parsed_descriptor.service_name)
        metrics = Metrics()
        relays = _load_relays(args.relays)
        relays_by_name = {str(relay["name"]): relay for relay in relays}
        intro_circuits = build_intro_circuits(service_material["descriptor"], relays_by_name)
        emitter.emit("hs.runtime_started", status="ok", mode="service", intro_circuits=len(intro_circuits))

        reliability = _reliability_config_from_args(args)
        while True:
            handled = 0
            for intro in intro_circuits:
                try:
                    items = poll_intro_requests(intro["circuit"], config=reliability)
                    emitter.emit("hs.intro_polled", status="ok", mode="service", poll_count=len(items))
                    for item in items:
                        result = handle_intro_request_with_echo(item, config=reliability)
                        metrics.record_intro_request()
                        emitter.emit("hs.intro_request_handled", status="ok", mode="service", result=result)
                        handled += 1
                except Exception as exc:
                    error_code = _error_code(exc)
                    metrics.record_relay_failure(error_code)
                    emitter.emit("hs.error", status="error", mode="service", error_code=error_code, error=error_to_dict(exc))

            if args.once:
                emitter.emit(
                    "hs.runtime_stopped",
                    status="ok",
                    mode="service",
                    handled=handled,
                    metrics=metrics.as_dict(),
                )
                return 0
            time.sleep(max(0.01, reliability.poll_interval_s))

    if args.top_cmd == "hs" and args.hs_cmd == "connect":
        metrics = Metrics()
        verified_relays = None
        trust = _trust_from_args(args)
        if trust is not None:
            verified_relays = fetch_verified_relays_from_directory(
                host=args.host,
                port=args.port,
                trust=trust,
            )
        descriptor = fetch_hidden_service_descriptor_from_directory(
            host=args.host,
            port=args.port,
            service_name=args.service_name,
        )
        intro = select_intro_point_for_phase1(descriptor)
        relay_doc = load_json(args.relay)
        rendezvous_cookie = uuid.uuid4().hex

        if verified_relays is not None:
            relay_name = str(relay_doc.get("name"))
            verified_rdv = verified_relays.get(relay_name)
            if verified_rdv is None:
                raise ValueError(f"rendezvous relay {relay_name} missing from verified snapshot")
            relay_doc = verified_rdv
            intro_name = str(intro["relay_name"])
            verified_intro = verified_relays.get(intro_name)
            if verified_intro is None:
                raise ValueError(f"introduction relay {intro_name} missing from verified snapshot")

        intro_relay = {
            "name": intro["relay_name"],
            "host": verified_intro["host"] if verified_relays is not None else intro["relay_addr"]["host"],
            "port": verified_intro["port"] if verified_relays is not None else intro["relay_addr"]["port"],
            "kemalg": verified_intro["kemalg"] if verified_relays is not None else relay_doc["kemalg"],
            "public_key": verified_intro["public_key"] if verified_relays is not None else relay_doc["public_key"],
        }

        intro_circuit = build_service_circuit([intro_relay], terminal_cmd="INTRO_READY")
        rendezvous_circuit = build_service_circuit([relay_doc], terminal_cmd="RENDEZVOUS_READY")
        emitter = EventEmitter(
            component="hs.client",
            service_name=args.service_name,
            circuit_id=rendezvous_circuit.circuit_id,
            rendezvous_cookie=rendezvous_cookie,
        )
        from .hidden_service_runtime import _send_circuit_cmd

        join_started = time.monotonic()
        emitter.emit("hs.rdv_join_attempt", status="ok", side="client")
        try:
            intro_reply = _send_circuit_cmd(
                intro_circuit,
                {
                    "cmd": "INTRODUCE",
                    "rendezvous_cookie": rendezvous_cookie,
                    "introduction": {
                        "service_name": args.service_name,
                        "rendezvous_relay": relay_doc,
                    },
                },
            )
            establish_reply = _send_circuit_cmd(
                rendezvous_circuit,
                {
                    "cmd": "RENDEZVOUS_ESTABLISH",
                    "rendezvous_cookie": rendezvous_cookie,
                    "side": "client",
                },
            )
        except Exception as exc:
            join_latency_ms = (time.monotonic() - join_started) * 1000.0
            error_code = _error_code(exc)
            metrics.record_join(success=False, latency_ms=join_latency_ms)
            metrics.record_relay_failure(error_code)
            emitter.emit(
                "hs.rdv_joined",
                status="error",
                side="client",
                join_latency_ms=join_latency_ms,
                error_code=error_code,
            )
            emitter.emit("hs.error", status="error", error_code=error_code, error=error_to_dict(exc), metrics=metrics.as_dict())
            return 1
        join_latency_ms = (time.monotonic() - join_started) * 1000.0
        metrics.record_join(success=True, latency_ms=join_latency_ms)
        emitter.emit("hs.rdv_joined", status="ok", side="client", join_latency_ms=join_latency_ms)

        session = {
            "mode": "client",
            "service_name": args.service_name,
            "rendezvous_cookie": rendezvous_cookie,
            "circuit": _hs_circuit_to_json(rendezvous_circuit),
            "stream_next_seq": {"0": 2},
        }
        _save_hs_session(args.session, session)
        emitter.emit(
            "hs.runtime_stopped",
            status="ok",
            mode="client",
            session=str(Path(args.session)),
            intro=intro_reply,
            rendezvous=establish_reply,
            metrics=metrics.as_dict(),
        )
        return 0

    if args.top_cmd == "hs" and args.hs_cmd == "send":
        metrics = Metrics()
        session = _load_hs_session(args.session)
        emitter = EventEmitter(
            component="hs.client",
            service_name=session.get("service_name"),
            rendezvous_cookie=session.get("rendezvous_cookie"),
            circuit_id=session.get("circuit", {}).get("circuit_id"),
        )
        if session.get("ended_at"):
            emitter.emit("hs.error", status="error", error_code="session_ended", error="session already ended")
            return 1
        circuit = _hs_circuit_from_json(session["circuit"])
        try:
            reply = rendezvous_send(circuit, str(session["rendezvous_cookie"]), args.payload)
        except Exception as exc:
            error_code = _error_code(exc)
            metrics.record_relay_failure(error_code)
            emitter.emit("hs.error", status="error", error_code=error_code, error=error_to_dict(exc), metrics=metrics.as_dict())
            return 1
        _save_hs_session(args.session, session)
        emitter.emit("hs.message_sent", status="ok", command_reply=reply, metrics=metrics.as_dict())
        return 0

    if args.top_cmd == "hs" and args.hs_cmd == "recv":
        metrics = Metrics()
        session = _load_hs_session(args.session)
        circuit = _hs_circuit_from_json(session["circuit"])
        cookie = str(session["rendezvous_cookie"])
        emitter = EventEmitter(
            component="hs.client",
            service_name=session.get("service_name"),
            rendezvous_cookie=cookie,
            circuit_id=session.get("circuit", {}).get("circuit_id"),
        )

        reliability = ReliabilityConfig(
            join_timeout_s=max(0.0, float(args.timeout)),
            poll_interval_s=0.1,
            max_retries=max(1, int(args.max_retries)),
            retry_backoff_base_s=max(0.0, float(args.retry_backoff_base)),
            retry_backoff_max_s=max(0.0, float(args.retry_backoff_max)),
        )
        deadline = time.monotonic() + max(0.0, float(args.timeout))
        try:
            while True:
                payload = rendezvous_recv(circuit, cookie, config=reliability)
                if payload is not None:
                    emitter.emit("hs.message_received", status="ok", payload=payload, received_at=int(time.time()))
                    return 0
                if not args.follow or time.monotonic() >= deadline:
                    timeout_error = HiddenServiceRuntimeError("timeout waiting for rendezvous payload")
                    error_code = _error_code(timeout_error)
                    metrics.record_relay_failure(error_code)
                    emitter.emit(
                        "hs.error",
                        status="error",
                        error_code=error_code,
                        error=error_to_dict(timeout_error),
                        payload=None,
                        received_at=int(time.time()),
                        metrics=metrics.as_dict(),
                    )
                    return 1
                time.sleep(reliability.poll_interval_s)
        except HiddenServiceRuntimeError as exc:
            error_code = _error_code(exc)
            metrics.record_relay_failure(error_code)
            emitter.emit(
                "hs.error",
                status="error",
                error_code=error_code,
                error=error_to_dict(exc),
                payload=None,
                received_at=int(time.time()),
                metrics=metrics.as_dict(),
            )
            return 1
        except Exception as exc:
            error_code = _error_code(exc)
            metrics.record_relay_failure(error_code)
            emitter.emit(
                "hs.error",
                status="error",
                error_code=error_code,
                error=error_to_dict(exc),
                payload=None,
                received_at=int(time.time()),
                metrics=metrics.as_dict(),
            )
            return 1
        except KeyboardInterrupt:
            emitter.emit("hs.error", status="error", error_code="interrupted", payload=None, received_at=int(time.time()))
            return 130

    if args.top_cmd == "hs" and args.hs_cmd == "end":
        metrics = Metrics()
        session = _load_hs_session(args.session)
        emitter = EventEmitter(
            component="hs.client",
            service_name=session.get("service_name"),
            rendezvous_cookie=session.get("rendezvous_cookie"),
            circuit_id=session.get("circuit", {}).get("circuit_id"),
        )
        if session.get("ended_at"):
            emitter.emit("hs.error", status="error", error_code="session_ended", error="session already ended")
            return 1
        circuit = _hs_circuit_from_json(session["circuit"])
        try:
            reply = rendezvous_close(circuit, str(session["rendezvous_cookie"]), args.payload)
        except Exception as exc:
            error_code = _error_code(exc)
            metrics.record_relay_failure(error_code)
            emitter.emit("hs.error", status="error", error_code=error_code, error=error_to_dict(exc), metrics=metrics.as_dict())
            return 1
        session["ended_at"] = int(time.time())
        session["end_reason"] = "user_end"
        session["final_payload"] = args.payload
        _save_hs_session(args.session, session)
        emitter.emit("hs.runtime_stopped", status="ok", mode="client", command_reply=reply, metrics=metrics.as_dict())
        return 0

    if args.top_cmd == "hs" and args.hs_cmd == "publish":
        service_master = load_json(args.service_master)
        service_name = str(service_master["service_name"])
        descriptor = load_json(args.descriptor)
        response = publish_hidden_service_descriptor_to_directory(
            host=args.host,
            port=args.port,
            service_name=service_name,
            descriptor=descriptor,
            expected_previous_revision=args.expected_revision,
            idempotency_key=args.idempotency_key,
        )
        _print_json(response)
        return 0

    if args.top_cmd == "hs" and args.hs_cmd == "rotate":
        now = int(time.time())
        service_master = load_json(args.service_master)
        descriptor = load_json(args.descriptor)
        service_name = str(service_master["service_name"])

        proposed = verify_hidden_service_descriptor_v2(descriptor, now=now)
        if proposed.service_name != service_name:
            raise ValueError("descriptor service_name does not match service master service_name")
        if proposed.valid_until <= now:
            raise ValueError("proposed descriptor is expired")

        current_descriptor: dict[str, Any] | None = None
        current_revision: int | None = None
        try:
            current_descriptor = fetch_hidden_service_descriptor_from_directory(
                host=args.host,
                port=args.port,
                service_name=service_name,
            )
            current_revision = verify_hidden_service_descriptor_v2(current_descriptor, now=now).revision
        except ValueError as exc:
            if str(exc) != NO_DESCRIPTOR_ERROR:
                raise

        if current_revision is not None and proposed.revision <= current_revision:
            raise ValueError(
                f"proposed descriptor revision must be strictly higher than current revision ({current_revision})"
            )

        publish_result = publish_hidden_service_descriptor_to_directory(
            host=args.host,
            port=args.port,
            service_name=service_name,
            descriptor=descriptor,
            expected_previous_revision=current_revision,
            idempotency_key=args.idempotency_key,
        )

        verify_deadline = time.monotonic() + max(0.0, float(args.verify_timeout))
        visible_revision: int | None = None
        while True:
            visible = fetch_hidden_service_descriptor_from_directory(
                host=args.host,
                port=args.port,
                service_name=service_name,
            )
            visible_revision = verify_hidden_service_descriptor_v2(visible).revision
            if visible_revision == proposed.revision:
                break
            if time.monotonic() >= verify_deadline:
                raise TimeoutError(
                    f"descriptor revision {proposed.revision} not visible before verify timeout; "
                    f"last visible revision was {visible_revision}"
                )
            time.sleep(0.1)

        out: dict[str, Any] = {
            "ok": True,
            "rotation_status": "published_and_visible",
            "service_name": service_name,
            "accepted_revision": publish_result.get("accepted_revision"),
            "visible_revision": visible_revision,
            "expected_previous_revision": current_revision,
            "idempotency_key": args.idempotency_key,
        }
        if args.print_rollback_hints:
            out["rollback_hints"] = {
                "previous_revision": current_revision,
                "recommended_action": "publish a freshly signed descriptor with a higher revision if rollback is needed",
            }
        _print_json(out)
        return 0

    parser.error("unsupported command")
    return 2


__all__ = [
    "init_authority_file",
    "export_authority_pub_file",
    "sign_relay_file",
    "make_bundle_file",
    "init_relay_file",
    "run_relay_server",
    "run_directory_server",
    "fetch_bundle_from_directory",
    "fetch_bundle_to_file",
    "fetch_hidden_service_descriptor_from_directory",
    "publish_hidden_service_descriptor_to_directory",
    "build_circuit",
    "open_stream",
    "send_stream_data",
    "end_stream",
    "destroy_circuit",
    "main",
    "RelayServer",
]


if __name__ == "__main__":
    raise SystemExit(main())
