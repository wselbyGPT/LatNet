from __future__ import annotations

import argparse
import json
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
    open_stream,
    send_stream_data,
)
from .directory import run_directory_server
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
