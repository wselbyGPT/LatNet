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
    CircuitSession,
    HopSession,
    build_circuit,
    destroy_circuit,
    end_stream,
    fetch_bundle_from_directory,
    fetch_bundle_to_file,
    fetch_hidden_service_descriptor_from_directory,
    publish_hidden_service_descriptor_to_directory,
    open_stream,
    send_stream_data,
    select_intro_point_for_phase1,
)
from .directory import run_directory_server
from .hidden_service_runtime import (
    ServiceCircuit,
    build_intro_circuits,
    build_service_circuit,
    handle_intro_request_with_echo,
    load_service_material,
    poll_intro_requests,
    rendezvous_send,
)
from .relay import RelayServer, init_relay_file, run_relay_server
from .util import atomic_write_json, b64d, b64e, load_json


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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="latnet", description="LatNet operational CLI")
    subparsers = parser.add_subparsers(dest="top_cmd", required=True)

    circuit = subparsers.add_parser("circuit", help="Circuit lifecycle operations")
    circuit_sub = circuit.add_subparsers(dest="circuit_cmd", required=True)

    circuit_build = circuit_sub.add_parser("build", help="Build a circuit and persist its session")
    circuit_build.add_argument("relays", nargs="+", help="Relay descriptor JSON paths in guard->exit order")
    circuit_build.add_argument("--session", default=".latnet-circuit.json", help="Circuit session output file")
    circuit_build.add_argument("--circuit-id", default=None, help="Optional circuit ID override")

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
    hs_serve.add_argument("--poll-interval", type=float, default=0.25, help="Poll interval seconds")
    hs_serve.add_argument("--once", action="store_true", help="Run a single poll cycle and exit")

    hs_connect = hs_sub.add_parser("connect", help="Build rendezvous flow and open HS stream")
    hs_connect.add_argument("service_name", help="Service name (*.lettuce)")
    hs_connect.add_argument("relay", help="Rendezvous relay descriptor JSON path")
    hs_connect.add_argument("--host", default="127.0.0.1", help="Directory host")
    hs_connect.add_argument("--port", type=int, default=9200, help="Directory port")
    hs_connect.add_argument("--session", default=".latnet-hs.json", help="HS session output file")

    hs_send = hs_sub.add_parser("send", help="Send HS payload over persisted HS session")
    hs_send.add_argument("--session", default=".latnet-hs.json", help="HS session file")
    hs_send.add_argument("payload", help="Payload string")

    hs_end = hs_sub.add_parser("end", help="End HS stream")
    hs_end.add_argument("--session", default=".latnet-hs.json", help="HS session file")
    hs_end.add_argument("--payload", default="", help="Optional END payload")

    hs_publish = hs_sub.add_parser("publish", help="Publish hidden service descriptor to directory")
    hs_publish.add_argument("--service-master", required=True, help="Hidden service master key JSON")
    hs_publish.add_argument("--descriptor", required=True, help="Hidden service descriptor JSON")
    hs_publish.add_argument("--host", default="127.0.0.1", help="Directory host")
    hs_publish.add_argument("--port", type=int, default=9200, help="Directory port")
    hs_publish.add_argument("--expected-revision", type=int, default=None, help="Expected previous descriptor revision")
    hs_publish.add_argument("--idempotency-key", default=None, help="Optional idempotency key")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.top_cmd == "circuit" and args.circuit_cmd == "build":
        circuit = build_circuit(_load_relays(args.relays), circuit_id=args.circuit_id)
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
        relays = _load_relays(args.relays)
        relays_by_name = {str(relay["name"]): relay for relay in relays}
        intro_circuits = build_intro_circuits(service_material["descriptor"], relays_by_name)
        _print_json(
            {
                "ok": True,
                "mode": "service",
                "service_name": parsed_descriptor.service_name,
                "intro_circuits": len(intro_circuits),
                "status": "runtime_started",
            }
        )

        while True:
            handled = 0
            for intro in intro_circuits:
                items = poll_intro_requests(intro["circuit"])
                for item in items:
                    result = handle_intro_request_with_echo(item)
                    _print_json({"ok": True, "mode": "service", "event": "intro_request", "result": result})
                    handled += 1

            if args.once:
                _print_json({"ok": True, "mode": "service", "status": "runtime_stopped", "handled": handled})
                return 0
            time.sleep(max(0.01, args.poll_interval))

    if args.top_cmd == "hs" and args.hs_cmd == "connect":
        descriptor = fetch_hidden_service_descriptor_from_directory(
            host=args.host,
            port=args.port,
            service_name=args.service_name,
        )
        intro = select_intro_point_for_phase1(descriptor)
        relay_doc = load_json(args.relay)
        rendezvous_cookie = uuid.uuid4().hex

        intro_relay = {
            "name": intro["relay_name"],
            "host": intro["relay_addr"]["host"],
            "port": intro["relay_addr"]["port"],
            "kemalg": relay_doc["kemalg"],
            "public_key": relay_doc["public_key"],
        }

        intro_circuit = build_service_circuit([intro_relay], terminal_cmd="INTRO_READY")
        rendezvous_circuit = build_service_circuit([relay_doc], terminal_cmd="RENDEZVOUS_READY")
        from .hidden_service_runtime import _send_circuit_cmd

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

        session = {
            "mode": "client",
            "service_name": args.service_name,
            "rendezvous_cookie": rendezvous_cookie,
            "circuit": _hs_circuit_to_json(rendezvous_circuit),
            "stream_next_seq": {"0": 2},
        }
        _save_hs_session(args.session, session)
        _print_json(
            {
                "ok": True,
                "session": str(Path(args.session)),
                "service_name": args.service_name,
                "rendezvous_cookie": rendezvous_cookie,
                "intro": intro_reply,
                "rendezvous": establish_reply,
            }
        )
        return 0

    if args.top_cmd == "hs" and args.hs_cmd == "send":
        session = _load_hs_session(args.session)
        circuit = _hs_circuit_from_json(session["circuit"])
        reply = rendezvous_send(circuit, str(session["rendezvous_cookie"]), args.payload)
        _save_hs_session(args.session, session)
        _print_json(reply)
        return 0

    if args.top_cmd == "hs" and args.hs_cmd == "end":
        session = _load_hs_session(args.session)
        circuit = _hs_circuit_from_json(session["circuit"])
        reply = rendezvous_send(circuit, str(session["rendezvous_cookie"]), args.payload)
        session["ended_at"] = int(time.time())
        _save_hs_session(args.session, session)
        _print_json(reply)
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
