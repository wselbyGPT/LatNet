from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path
from typing import Any

import oqs

from .constants import CELL_PAYLOAD_BYTES, DEFAULT_TIMEOUT, KEMALG
from .crypto import decrypt_layer, derive_hop_keys, encrypt_layer
from .exit_connector import DemoOutboundConnector, EgressPolicyError, ExitPolicy, OutboundConnector, PolicyEnforcedTcpConnector, TcpOutboundConnector
from .models.protocol import encode_stream_cell_payload, parse_build_envelope, parse_cell_envelope, parse_destroy_envelope, parse_exit_cell_layer, parse_layer
from .util import atomic_write_json, b64d, b64e, load_json
from .wire import recv_msg, send_msg


def init_relay_file(name: str, host: str, port: int, out_path: str | Path) -> dict[str, Any]:
    with oqs.KeyEncapsulation(KEMALG) as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()

    relay_doc = {
        "name": name,
        "host": host,
        "port": port,
        "kemalg": KEMALG,
        "public_key": b64e(public_key),
        "secret_key": b64e(secret_key),
    }
    atomic_write_json(out_path, relay_doc)
    return relay_doc


class RelayServer:
    def __init__(
        self,
        relay_doc: dict[str, Any],
        *,
        use_persistent_channels: bool = False,
        circuit_ttl_seconds: float = 900.0,
        circuit_idle_seconds: float = 300.0,
        stream_idle_seconds: float = 120.0,
        outbound_connector: OutboundConnector | None = None,
        enable_real_egress: bool = False,
        outbound_connect_timeout: float = DEFAULT_TIMEOUT,
        outbound_recv_timeout: float = DEFAULT_TIMEOUT,
        exit_policy: ExitPolicy | None = None,
        stream_queue_high_water_bytes: int = 64 * 1024,
        stream_queue_low_water_bytes: int = 16 * 1024,
        connector_io_timeout_seconds: float = 0.25,
    ):
        self.relay_doc = relay_doc
        self.circuits: dict[str, dict[str, Any]] = {}
        self.lock = threading.Lock()
        self.use_persistent_channels = use_persistent_channels
        self.circuit_ttl_seconds = max(float(circuit_ttl_seconds), 1.0)
        self.circuit_idle_seconds = max(float(circuit_idle_seconds), 1.0)
        self.stream_idle_seconds = max(float(stream_idle_seconds), 1.0)
        self.channel_pool: dict[tuple[str, int], socket.socket] = {}
        self.channel_pool_lock = threading.Lock()
        self.pending_introductions: dict[str, dict[str, Any]] = {}
        self.pending_rendezvous: dict[str, dict[str, Any]] = {}
        self.rendezvous_links: dict[str, dict[str, Any]] = {}
        self.stream_queue_high_water_bytes = max(int(stream_queue_high_water_bytes), 1024)
        self.stream_queue_low_water_bytes = min(max(int(stream_queue_low_water_bytes), 0), self.stream_queue_high_water_bytes)
        self.connector_io_timeout_seconds = max(float(connector_io_timeout_seconds), 0.01)
        self.outbound_connector = outbound_connector or (
            PolicyEnforcedTcpConnector(connect_timeout=outbound_connect_timeout, recv_timeout=outbound_recv_timeout, policy=exit_policy)
            if enable_real_egress
            else DemoOutboundConnector()
        )

    @staticmethod
    def _touch_state(state: dict[str, Any], now: float | None = None) -> None:
        state["last_activity_at"] = time.time() if now is None else now

    @staticmethod
    def _init_lifecycle_state(state: dict[str, Any], lifecycle_state: str, now: float | None = None) -> None:
        ts = time.time() if now is None else now
        state["lifecycle_state"] = lifecycle_state
        state["created_at"] = ts
        state["last_activity_at"] = ts
        state.setdefault("streams", {})

    @staticmethod
    def _transition_lifecycle_state(state: dict[str, Any], target: str, now: float | None = None) -> None:
        valid_transitions = {
            "building": {"ready", "destroying", "closed"},
            "ready": {"destroying", "closed"},
            "destroying": {"closed"},
            "closed": set(),
        }
        current = str(state.get("lifecycle_state", "building"))
        if target not in valid_transitions.get(current, set()) and target != current:
            raise ValueError(f"invalid lifecycle transition: {current} -> {target}")
        ts = time.time() if now is None else now
        state["lifecycle_state"] = target
        if target == "ready":
            state["ready_at"] = ts
        elif target == "destroying":
            state["destroying_at"] = ts
        elif target == "closed":
            state["closed_at"] = ts
        state["last_activity_at"] = ts

    def circuit_snapshot(self, circuit_id: str) -> dict[str, Any] | None:
        with self.lock:
            state = self.circuits.get(circuit_id)
            if state is None:
                return None
            return json.loads(json.dumps(state))

    def set_circuit_state(self, circuit_id: str, state: dict[str, Any]) -> None:
        with self.lock:
            self.circuits[circuit_id] = state

    def update_stream_state(self, circuit_id: str, stream_id: int, stream_state: dict[str, Any] | None) -> None:
        with self.lock:
            circuit = self.circuits[circuit_id]
            streams = circuit.setdefault("streams", {})
            sid = str(stream_id)
            if stream_state is None:
                streams.pop(sid, None)
            else:
                streams[sid] = stream_state

    @staticmethod
    def _advance_seq_window(stream_state: dict[str, Any], seq: int, window_size: int = 32) -> None:
        window = list(stream_state.get("seen_window", []))
        window.append(seq)
        if len(window) > window_size:
            window = window[-window_size:]
        stream_state["seen_window"] = window
        stream_state["last_seq"] = seq
        stream_state["next_seq"] = seq + 1

    @staticmethod
    def _validate_monotonic_seq(stream_state: dict[str, Any], seq: int) -> str | None:
        window = stream_state.get("seen_window", [])
        if seq in window:
            return f"duplicate seq {seq} for stream {stream_state['stream_id']}"
        last_seq = int(stream_state.get("last_seq", -1))
        expected = int(stream_state.get("next_seq", last_seq + 1))
        if seq < expected:
            return (
                f"stale/out-of-order seq {seq} for stream {stream_state['stream_id']}; "
                f"expected {expected}"
            )
        if seq > expected:
            return (
                f"skipped seq {seq} for stream {stream_state['stream_id']}; "
                f"expected {expected}"
            )
        return None



    @staticmethod
    def _stream_metrics_template() -> dict[str, Any]:
        return {
            "queue_depth_samples": 0,
            "queue_depth_sum": 0,
            "queue_depth_max": 0,
            "throttled_events": 0,
            "write_stalls": 0,
            "read_stalls": 0,
            "bytes_in": 0,
            "bytes_out": 0,
            "service_time_ms_total": 0.0,
            "service_events": 0,
        }

    def _record_queue_depth(self, stream_state: dict[str, Any]) -> None:
        metrics = stream_state.setdefault("metrics", self._stream_metrics_template())
        depth = int(stream_state.get("outbound_queue_bytes", 0)) + int(stream_state.get("inbound_queue_bytes", 0))
        metrics["queue_depth_samples"] += 1
        metrics["queue_depth_sum"] += depth
        metrics["queue_depth_max"] = max(int(metrics.get("queue_depth_max", 0)), depth)

    def _service_stream_queues(self, stream_state: dict[str, Any]) -> bytes | None:
        start = time.time()
        out_q = stream_state.setdefault("outbound_queue", [])
        in_q = stream_state.setdefault("inbound_queue", [])
        metrics = stream_state.setdefault("metrics", self._stream_metrics_template())
        produced = None
        if out_q:
            data = b64d(out_q.pop(0))
            stream_state["outbound_queue_bytes"] = max(0, int(stream_state.get("outbound_queue_bytes", 0)) - len(data))
            try:
                self.outbound_connector.send(stream_state["stream_id"], data)
            except TimeoutError:
                metrics["write_stalls"] += 1
                out_q.insert(0, b64e(data))
                stream_state["outbound_queue_bytes"] += len(data)
            recv_start = time.time()
            try:
                produced = self.outbound_connector.recv(stream_state["stream_id"])
                if produced:
                    in_q.append(b64e(produced))
                    stream_state["inbound_queue_bytes"] = int(stream_state.get("inbound_queue_bytes", 0)) + len(produced)
                    metrics["bytes_out"] += len(produced)
            except TimeoutError:
                metrics["read_stalls"] += 1
            if (time.time() - recv_start) >= self.connector_io_timeout_seconds:
                metrics["read_stalls"] += 1
        metrics["service_events"] += 1
        metrics["service_time_ms_total"] += (time.time() - start) * 1000.0
        self._record_queue_depth(stream_state)
        if in_q:
            data = b64d(in_q.pop(0))
            stream_state["inbound_queue_bytes"] = max(0, int(stream_state.get("inbound_queue_bytes", 0)) - len(data))
            return data
        return produced
    def relay_decap_and_keys(self, ct_b64: str, circuit_id: str, isolation_context: bytes = b"") -> tuple[bytes, bytes]:
        with oqs.KeyEncapsulation(self.relay_doc["kemalg"], b64d(self.relay_doc["secret_key"])) as kem:
            shared_secret = kem.decap_secret(b64d(ct_b64))
        return derive_hop_keys(shared_secret, circuit_id, self.relay_doc["name"], isolation_context=isolation_context)

    def wrap_reverse_hop(self, reverse_key: bytes, next_response: dict[str, Any]) -> dict[str, Any]:
        if not next_response.get("ok"):
            return next_response
        return {
            "ok": True,
            "reply_layer": encrypt_layer(
                reverse_key,
                {
                    "cmd": "RELAY_BACK",
                    "inner": next_response["reply_layer"],
                },
            ),
        }

    def handle_exit_cell(self, circuit_id: str, state: dict[str, Any], cell: dict[str, Any]) -> dict[str, Any]:
        def _parse_target_metadata(raw_target: str) -> dict[str, Any]:
            text = str(raw_target or "").strip()
            if not text:
                raise ValueError("missing target")
            if ":" not in text:
                raise ValueError("target must be host:port")
            host, port_s = text.rsplit(":", 1)
            if not host:
                raise ValueError("target host is empty")
            try:
                port = int(port_s)
            except ValueError as exc:
                raise ValueError("target port must be an integer") from exc
            if port < 1 or port > 65535:
                raise ValueError("target port out of range")
            return {"host": host, "port": port}

        parsed_cell = parse_exit_cell_layer({"cmd": "EXIT_CELL", "cell": cell}).cell
        stream_id = parsed_cell.stream_id
        seq = parsed_cell.seq
        cell_type = parsed_cell.cell_type
        payload = parsed_cell.payload
        if cell_type == "PADDING":
            reply_cell = {
                "stream_id": stream_id,
                "seq": seq,
                "cell_type": "PADDING",
                "payload": "",
                "is_padding": True,
            }
            reply_payload_b64, reply_padding_b64 = encode_stream_cell_payload(b"", padded_len=CELL_PAYLOAD_BYTES)
            reply_cell["padded_len"] = CELL_PAYLOAD_BYTES
            reply_cell["payload_b64"] = reply_payload_b64
            reply_cell["padding_b64"] = reply_padding_b64
            return {
                "ok": True,
                "reply_layer": encrypt_layer(
                    b64d(state["reverse_key"]),
                    {
                        "cmd": "REPLY_CELL",
                        "cell": reply_cell,
                    },
                ),
            }

        streams = state.setdefault("streams", {})
        sid = str(stream_id)
        stream_state = streams.get(sid)

        if cell_type == "BEGIN":
            if stream_state is not None:
                reply_cell = {
                    "stream_id": stream_id,
                    "seq": seq,
                    "cell_type": "ERROR",
                    "payload": f"stream {stream_id} already exists",
                }
            elif seq != 1:
                reply_cell = {
                    "stream_id": stream_id,
                    "seq": seq,
                    "cell_type": "ERROR",
                    "payload": f"invalid initial seq {seq} for stream {stream_id}; expected 1",
                }
            else:
                try:
                    target = _parse_target_metadata(payload)
                    target["stream_id"] = stream_id
                    session = self.outbound_connector.connect(target)
                    now = time.time()
                    stream_state = {
                        "stream_id": stream_id,
                        "open": True,
                        "opened_at": now,
                        "last_activity_at": now,
                        "last_seq": 0,
                        "next_seq": 1,
                        "seen_window": [],
                        "target": f"{target['host']}:{target['port']}",
                        "target_host": target["host"],
                        "target_port": target["port"],
                        "connector_session_handle": repr(session.handle),
                        "connector_connected_at": session.created_at,
                        "connector_last_activity_at": session.last_activity_at,
                        "outbound_queue": [],
                        "inbound_queue": [],
                        "outbound_queue_bytes": 0,
                        "inbound_queue_bytes": 0,
                        "queue_high_water_bytes": self.stream_queue_high_water_bytes,
                        "queue_low_water_bytes": self.stream_queue_low_water_bytes,
                        "blocked_since": None,
                        "dropped_bytes": 0,
                        "metrics": self._stream_metrics_template(),
                    }
                    self._advance_seq_window(stream_state, seq)
                    self.update_stream_state(circuit_id, stream_id, stream_state)
                    reply_cell = {
                        "stream_id": stream_id,
                        "seq": seq,
                        "cell_type": "CONNECTED",
                        "payload": f"stream {stream_id} opened to {target['host']}:{target['port']} at exit {self.relay_doc['name']}",
                    }
                except Exception as exc:
                    code = exc.code if isinstance(exc, EgressPolicyError) else "connect_failed"
                    reply_cell = {"stream_id": stream_id, "seq": seq, "cell_type": "ERROR", "payload": {"code": code, "message": f"connect failed: {exc}"}}
        elif cell_type == "DATA":
            if not stream_state:
                reply_cell = {
                    "stream_id": stream_id,
                    "seq": seq,
                    "cell_type": "ERROR",
                    "payload": f"stream {stream_id} is not open",
                }
            else:
                seq_error = self._validate_monotonic_seq(stream_state, seq)
                if seq_error:
                    reply_cell = {
                        "stream_id": stream_id,
                        "seq": seq,
                        "cell_type": "ERROR",
                        "payload": seq_error,
                    }
                elif not stream_state.get("open"):
                    reply_cell = {
                        "stream_id": stream_id,
                        "seq": seq,
                        "cell_type": "ERROR",
                        "payload": f"stream {stream_id} is not open",
                    }
                else:
                    try:
                        payload_bytes = str(payload).encode("utf-8")
                        next_depth = int(stream_state.get("outbound_queue_bytes", 0)) + len(payload_bytes)
                        if next_depth >= int(stream_state.get("queue_high_water_bytes", self.stream_queue_high_water_bytes)):
                            metrics = stream_state.setdefault("metrics", self._stream_metrics_template())
                            metrics["throttled_events"] += 1
                            stream_state["blocked_since"] = stream_state.get("blocked_since") or time.time()
                            stream_state["dropped_bytes"] = int(stream_state.get("dropped_bytes", 0)) + len(payload_bytes)
                            self._record_queue_depth(stream_state)
                            reply_cell = {
                                "stream_id": stream_id,
                                "seq": seq,
                                "cell_type": "ERROR",
                                "payload": {"code": "stream_flow_control_retry", "retryable": True, "message": f"stream {stream_id} queue is full"},
                            }
                        else:
                            stream_state.setdefault("outbound_queue", []).append(b64e(payload_bytes))
                            stream_state["outbound_queue_bytes"] = next_depth
                            stream_state.setdefault("metrics", self._stream_metrics_template())["bytes_in"] += len(payload_bytes)
                            serviced = self._service_stream_queues(stream_state)
                            self._advance_seq_window(stream_state, seq)
                            now = time.time()
                            stream_state["last_activity_at"] = now
                            stream_state["connector_last_activity_at"] = now
                            if int(stream_state.get("outbound_queue_bytes", 0)) <= int(stream_state.get("queue_low_water_bytes", self.stream_queue_low_water_bytes)):
                                stream_state["blocked_since"] = None
                            self.update_stream_state(circuit_id, stream_id, stream_state)
                            recv_payload = (serviced or b"").decode("utf-8", errors="replace")
                            reply_cell = {
                                "stream_id": stream_id,
                                "seq": seq,
                                "cell_type": "DATA",
                                "payload": recv_payload,
                                "flow_control": {
                                    "outbound_queue_bytes": stream_state.get("outbound_queue_bytes", 0),
                                    "inbound_queue_bytes": stream_state.get("inbound_queue_bytes", 0),
                                    "blocked_since": stream_state.get("blocked_since"),
                                },
                            }
                    except Exception as exc:
                        reply_cell = {
                            "stream_id": stream_id,
                            "seq": seq,
                            "cell_type": "ERROR",
                            "payload": f"data relay failed: {exc}",
                        }
        elif cell_type == "END":
            if not stream_state:
                reply_cell = {
                    "stream_id": stream_id,
                    "seq": seq,
                    "cell_type": "ENDED",
                    "payload": f"stream {stream_id} was already closed",
                }
            else:
                seq_error = self._validate_monotonic_seq(stream_state, seq)
                if seq_error:
                    reply_cell = {
                        "stream_id": stream_id,
                        "seq": seq,
                        "cell_type": "ERROR",
                        "payload": seq_error,
                    }
                elif not stream_state.get("open"):
                    reply_cell = {
                        "stream_id": stream_id,
                        "seq": seq,
                        "cell_type": "ENDED",
                        "payload": f"stream {stream_id} was already closed",
                    }
                else:
                    self._advance_seq_window(stream_state, seq)
                    stream_state["open"] = False
                    stream_state["closed_at"] = time.time()
                    stream_state["last_activity_at"] = time.time()
                    stream_state["connector_last_activity_at"] = stream_state["last_activity_at"]
                    self.outbound_connector.close(stream_id)
                    self.update_stream_state(circuit_id, stream_id, stream_state)
                    reply_cell = {
                        "stream_id": stream_id,
                        "seq": seq,
                        "cell_type": "ENDED",
                        "payload": f"stream {stream_id} closed at exit {self.relay_doc['name']}",
                    }
        else:
            reply_cell = {
                "stream_id": stream_id,
                "seq": seq,
                "cell_type": "ERROR",
                "payload": f"unknown cell_type {cell_type}",
            }

        print()
        print(
            f"[EXIT {self.relay_doc['name']}] circuit={circuit_id} "
            f"stream={stream_id} seq={seq} type={cell_type} payload={payload!r}"
        )
        print(
            f"[EXIT {self.relay_doc['name']}] reply "
            f"stream={reply_cell['stream_id']} seq={reply_cell['seq']} "
            f"type={reply_cell['cell_type']} payload={reply_cell['payload']!r}"
        )
        print()

        reply_payload = str(reply_cell.get("payload", "")).encode("utf-8")
        if len(reply_payload) > CELL_PAYLOAD_BYTES:
            raise ValueError("reply payload exceeds cell budget")
        reply_payload_b64, pad_b64 = encode_stream_cell_payload(reply_payload, padded_len=CELL_PAYLOAD_BYTES)
        reply_cell["padded_len"] = CELL_PAYLOAD_BYTES
        reply_cell["payload_b64"] = reply_payload_b64
        reply_cell["padding_b64"] = pad_b64
        reply_cell["is_padding"] = False

        return {
            "ok": True,
            "reply_layer": encrypt_layer(
                b64d(state["reverse_key"]),
                {
                    "cmd": "REPLY_CELL",
                    "cell": reply_cell,
                },
            ),
        }

    def forward_to_next(self, state: dict[str, Any], msg: dict[str, Any]) -> dict[str, Any]:
        next_hop = state["next"]
        addr = (next_hop["host"], next_hop["port"])

        if not self.use_persistent_channels:
            with socket.create_connection(addr, timeout=DEFAULT_TIMEOUT) as sock:
                send_msg(sock, msg)
                return recv_msg(sock)

        def _connect() -> socket.socket:
            return socket.create_connection(addr, timeout=DEFAULT_TIMEOUT)

        with self.channel_pool_lock:
            pooled = self.channel_pool.get(addr)
            if pooled is None:
                pooled = _connect()
                self.channel_pool[addr] = pooled

        try:
            send_msg(pooled, msg)
            return recv_msg(pooled)
        except Exception:
            with self.channel_pool_lock:
                try:
                    pooled.close()
                except Exception:
                    pass
                self.channel_pool.pop(addr, None)
                replacement = _connect()
                self.channel_pool[addr] = replacement
            send_msg(replacement, msg)
            return recv_msg(replacement)

    def cleanup_stale_state(self, now: float | None = None) -> None:
        ts = time.time() if now is None else now
        with self.lock:
            remove_circuits: list[str] = []
            for circuit_id, state in self.circuits.items():
                streams = state.setdefault("streams", {})
                stale_streams = []
                for sid, stream_state in streams.items():
                    stream_last = float(stream_state.get("last_activity_at", stream_state.get("opened_at", ts)))
                    if (ts - stream_last) >= self.stream_idle_seconds:
                        stale_streams.append(sid)
                for sid in stale_streams:
                    try:
                        self.outbound_connector.close(int(sid))
                    except Exception:
                        pass
                    streams.pop(sid, None)

                created = float(state.get("created_at", ts))
                last_activity = float(state.get("last_activity_at", created))
                expired_ttl = (ts - created) >= self.circuit_ttl_seconds
                expired_idle = (ts - last_activity) >= self.circuit_idle_seconds
                if expired_ttl or expired_idle:
                    remove_circuits.append(circuit_id)

            for circuit_id in remove_circuits:
                self.circuits.pop(circuit_id, None)

            stale_intro = [
                cookie
                for cookie, intro in self.pending_introductions.items()
                if (ts - float(intro.get("last_activity_at", intro.get("created_at", ts)))) >= self.circuit_idle_seconds
            ]
            for cookie in stale_intro:
                self.pending_introductions.pop(cookie, None)

            stale_rendezvous = [
                cookie
                for cookie, rdv in self.pending_rendezvous.items()
                if (ts - float(rdv.get("last_activity_at", rdv.get("created_at", ts)))) >= self.circuit_idle_seconds
            ]
            for cookie in stale_rendezvous:
                entry = self.pending_rendezvous.pop(cookie, None)
                if not entry:
                    continue
                relay_map = entry.get("relay_map", {})
                for side in relay_map.values():
                    peer_circuit_id = side.get("peer_circuit_id")
                    if peer_circuit_id:
                        self.rendezvous_links.pop(peer_circuit_id, None)

    def handle_build(self, msg: dict[str, Any]) -> dict[str, Any]:
        self.cleanup_stale_state()
        env = parse_build_envelope(msg)
        circuit_id = env.circuit_id
        kdf_ctx_b64 = msg.get("kdf_ctx_b64", "")
        kdf_ctx = b64d(kdf_ctx_b64) if isinstance(kdf_ctx_b64, str) and kdf_ctx_b64 else b""
        forward_key, reverse_key = self.relay_decap_and_keys(env.ct, circuit_id, isolation_context=kdf_ctx)
        layer = parse_layer(decrypt_layer(forward_key, env.layer))

        if layer.cmd == "FORWARD_BUILD":
            state = {
                "role": "forward",
                "forward_key": b64e(forward_key),
                "reverse_key": b64e(reverse_key),
                "next": {"host": layer.next.host, "port": layer.next.port},
                "streams": {},
            }
            self._init_lifecycle_state(state, "building")
            self.set_circuit_state(circuit_id, state)

            next_build = {
                "type": "BUILD",
                "circuit_id": circuit_id,
                "ct": layer.next_ct,
                "layer": layer.inner,
                "kdf_ctx_b64": kdf_ctx_b64,
            }
            response = self.forward_to_next(state, next_build)
            if response.get("ok"):
                self._transition_lifecycle_state(state, "ready")
                self.set_circuit_state(circuit_id, state)
            else:
                self._transition_lifecycle_state(state, "destroying")
                self._transition_lifecycle_state(state, "closed")
                with self.lock:
                    self.circuits.pop(circuit_id, None)
            return response

        if layer.cmd == "EXIT_READY":
            state = {
                "role": "exit",
                "forward_key": b64e(forward_key),
                "reverse_key": b64e(reverse_key),
                "streams": {},
            }
            self._init_lifecycle_state(state, "building")
            self._transition_lifecycle_state(state, "ready")
            self.set_circuit_state(circuit_id, state)
            print(f"[{self.relay_doc['name']}] circuit {circuit_id} ready as exit")
            return {"ok": True, "status": "circuit_built", "role": "exit"}

        if layer.cmd == "INTRO_READY":
            state = {
                "role": "intro",
                "forward_key": b64e(forward_key),
                "reverse_key": b64e(reverse_key),
                "streams": {},
            }
            self._init_lifecycle_state(state, "building")
            self._transition_lifecycle_state(state, "ready")
            self.set_circuit_state(circuit_id, state)
            print(f"[{self.relay_doc['name']}] circuit {circuit_id} ready as intro")
            return {"ok": True, "status": "circuit_built", "role": "intro"}

        if layer.cmd == "RENDEZVOUS_READY":
            state = {
                "role": "rendezvous",
                "forward_key": b64e(forward_key),
                "reverse_key": b64e(reverse_key),
                "streams": {},
            }
            self._init_lifecycle_state(state, "building")
            self._transition_lifecycle_state(state, "ready")
            self.set_circuit_state(circuit_id, state)
            print(f"[{self.relay_doc['name']}] circuit {circuit_id} ready as rendezvous")
            return {"ok": True, "status": "circuit_built", "role": "rendezvous"}

        return {"ok": False, "error": f"unknown build cmd: {layer.cmd}"}

    def handle_cell(self, msg: dict[str, Any]) -> dict[str, Any]:
        self.cleanup_stale_state()
        env = parse_cell_envelope(msg)
        circuit_id = env.circuit_id
        state = self.circuit_snapshot(circuit_id)
        if state is None:
            return {"ok": False, "error": f"unknown circuit_id {circuit_id}"}
        if state.get("lifecycle_state") != "ready":
            return {"ok": False, "error": f"circuit {circuit_id} is not ready"}

        self._touch_state(state)
        self.set_circuit_state(circuit_id, state)

        forward_key = b64d(state["forward_key"])
        reverse_key = b64d(state["reverse_key"])
        decoded_layer = decrypt_layer(forward_key, env.layer)
        layer_cmd = decoded_layer.get("cmd") if isinstance(decoded_layer, dict) else None

        if layer_cmd == "KEEPALIVE":
            return {
                "ok": True,
                "reply_layer": encrypt_layer(
                    reverse_key,
                    {"cmd": "KEEPALIVE_ACK", "ts": time.time()},
                ),
            }

        if state["role"] == "intro":
            if layer_cmd == "INTRODUCE":
                cookie = decoded_layer.get("rendezvous_cookie")
                if not isinstance(cookie, str) or not cookie:
                    return {"ok": False, "error": "missing or invalid field: rendezvous_cookie"}
                now = time.time()
                with self.lock:
                    self.pending_introductions[cookie] = {
                        "intro_circuit_id": circuit_id,
                        "intro_payload": decoded_layer.get("introduction"),
                        "created_at": now,
                        "last_activity_at": now,
                    }
                return {
                    "ok": True,
                    "reply_layer": encrypt_layer(
                        reverse_key,
                        {
                            "cmd": "INTRO_STORED",
                            "rendezvous_cookie": cookie,
                        },
                    ),
                }

            if layer_cmd == "INTRO_POLL":
                with self.lock:
                    pending = [
                        {
                            "rendezvous_cookie": cookie,
                            "introduction": intro.get("intro_payload"),
                        }
                        for cookie, intro in self.pending_introductions.items()
                    ]
                    for entry in pending:
                        self.pending_introductions.pop(entry["rendezvous_cookie"], None)
                return {
                    "ok": True,
                    "reply_layer": encrypt_layer(
                        reverse_key,
                        {
                            "cmd": "INTRO_PENDING",
                            "items": pending,
                        },
                    ),
                }

            return {"ok": False, "error": f"unknown intro cmd {layer_cmd}"}

        if state["role"] == "rendezvous":
            if layer_cmd == "RENDEZVOUS_ESTABLISH":
                cookie = decoded_layer.get("rendezvous_cookie")
                side = decoded_layer.get("side")
                if not isinstance(cookie, str) or not cookie:
                    return {"ok": False, "error": "missing or invalid field: rendezvous_cookie"}
                if side not in {"client", "service"}:
                    return {"ok": False, "error": "missing or invalid field: side"}
                now = time.time()
                with self.lock:
                    entry = self.pending_rendezvous.setdefault(
                        cookie,
                        {
                            "created_at": now,
                            "last_activity_at": now,
                            "client_circuit_id": None,
                            "service_circuit_id": None,
                            "joined": False,
                            "relay_map": {},
                            "mailboxes": {"client": [], "service": []},
                        },
                    )
                    entry.setdefault("mailboxes", {"client": [], "service": []})
                    entry[f"{side}_circuit_id"] = circuit_id
                    entry["last_activity_at"] = now
                    if entry.get("client_circuit_id") and entry.get("service_circuit_id"):
                        entry["joined"] = True
                        entry["joined_at"] = now
                        relay_map = {
                            "client": {
                                "circuit_id": entry["client_circuit_id"],
                                "peer_circuit_id": entry["service_circuit_id"],
                            },
                            "service": {
                                "circuit_id": entry["service_circuit_id"],
                                "peer_circuit_id": entry["client_circuit_id"],
                            },
                        }
                        entry["relay_map"] = relay_map
                        self.rendezvous_links[entry["client_circuit_id"]] = {
                            "cookie": cookie,
                            "peer_circuit_id": entry["service_circuit_id"],
                            "last_activity_at": now,
                        }
                        self.rendezvous_links[entry["service_circuit_id"]] = {
                            "cookie": cookie,
                            "peer_circuit_id": entry["client_circuit_id"],
                            "last_activity_at": now,
                        }
                return {
                    "ok": True,
                    "reply_layer": encrypt_layer(
                        reverse_key,
                        {
                            "cmd": "RENDEZVOUS_STATE",
                            "rendezvous_cookie": cookie,
                            "joined": bool(
                                self.pending_rendezvous.get(cookie, {}).get("joined")
                            ),
                        },
                    ),
                }

            if layer_cmd == "RENDEZVOUS_RELAY":
                cookie = decoded_layer.get("rendezvous_cookie")
                if not isinstance(cookie, str) or not cookie:
                    return {"ok": False, "error": "missing or invalid field: rendezvous_cookie"}
                with self.lock:
                    link = self.rendezvous_links.get(circuit_id)
                    if not link or link.get("cookie") != cookie:
                        return {"ok": False, "error": f"rendezvous not joined for cookie {cookie}"}
                    peer_circuit_id = link["peer_circuit_id"]
                    entry = self.pending_rendezvous.get(cookie)
                    if not entry:
                        return {"ok": False, "error": f"rendezvous not joined for cookie {cookie}"}
                    sender_side = "client" if entry.get("client_circuit_id") == circuit_id else "service"
                    peer_side = "service" if sender_side == "client" else "client"
                    mailboxes = entry.setdefault("mailboxes", {"client": [], "service": []})
                    mailboxes.setdefault(peer_side, []).append(decoded_layer.get("payload", ""))
                    link["last_activity_at"] = time.time()
                    peer_link = self.rendezvous_links.get(peer_circuit_id)
                    if peer_link:
                        peer_link["last_activity_at"] = time.time()
                return {
                    "ok": True,
                    "reply_layer": encrypt_layer(
                        reverse_key,
                        {
                            "cmd": "RENDEZVOUS_RELAYED",
                            "rendezvous_cookie": cookie,
                            "peer_circuit_id": peer_circuit_id,
                            "queued_for": peer_side,
                        },
                    ),
                }

            if layer_cmd == "RENDEZVOUS_RECV":
                cookie = decoded_layer.get("rendezvous_cookie")
                if not isinstance(cookie, str) or not cookie:
                    return {"ok": False, "error": "missing or invalid field: rendezvous_cookie"}
                with self.lock:
                    link = self.rendezvous_links.get(circuit_id)
                    if not link or link.get("cookie") != cookie:
                        return {"ok": False, "error": f"rendezvous not joined for cookie {cookie}"}
                    entry = self.pending_rendezvous.get(cookie)
                    if not entry:
                        return {"ok": False, "error": f"rendezvous not joined for cookie {cookie}"}
                    side = "client" if entry.get("client_circuit_id") == circuit_id else "service"
                    mailboxes = entry.setdefault("mailboxes", {"client": [], "service": []})
                    queue = mailboxes.setdefault(side, [])
                    payload = queue.pop(0) if queue else None
                    entry["last_activity_at"] = time.time()
                return {
                    "ok": True,
                    "reply_layer": encrypt_layer(
                        reverse_key,
                        {
                            "cmd": "RENDEZVOUS_MESSAGE",
                            "rendezvous_cookie": cookie,
                            "payload": payload,
                        },
                    ),
                }

            return {"ok": False, "error": f"unknown rendezvous cmd {layer_cmd}"}

        layer = parse_layer(decoded_layer)

        if state["role"] == "forward":
            if layer.cmd != "FORWARD_CELL":
                return {"ok": False, "error": f"expected FORWARD_CELL, got {layer.cmd}"}
            if not isinstance(layer.inner, dict) or set(layer.inner.keys()) != {"nonce", "ct"}:
                return {"ok": False, "error": "invalid FORWARD_CELL inner layer"}

            next_msg = {
                "type": "CELL",
                "circuit_id": circuit_id,
                "layer": layer.inner,
            }
            parse_cell_envelope(next_msg)
            next_response = self.forward_to_next(state, next_msg)
            return self.wrap_reverse_hop(reverse_key, next_response)

        if state["role"] == "exit":
            if layer.cmd != "EXIT_CELL":
                return {"ok": False, "error": f"expected EXIT_CELL, got {layer.cmd}"}
            return self.handle_exit_cell(circuit_id, state, {
                "stream_id": layer.cell.stream_id,
                "seq": layer.cell.seq,
                "cell_type": layer.cell.cell_type,
                "payload": layer.cell.payload,
                "padded_len": layer.cell.padded_len,
                "payload_b64": layer.cell.payload_b64,
                "is_padding": layer.cell.is_padding,
            })

        return {"ok": False, "error": f"unknown circuit role {state['role']}"}

    def handle_destroy(self, msg: dict[str, Any]) -> dict[str, Any]:
        self.cleanup_stale_state()
        env = parse_destroy_envelope(msg)
        circuit_id = env.circuit_id
        state = self.circuit_snapshot(circuit_id)
        if state is None:
            return {"ok": True, "status": "already_gone"}

        state["streams"] = {}
        self._transition_lifecycle_state(state, "destroying")
        self.set_circuit_state(circuit_id, state)

        if state["role"] == "forward":
            try:
                self.forward_to_next(state, {"type": "DESTROY", "circuit_id": circuit_id})
            except Exception:
                pass

        with self.lock:
            remove_intro = [
                cookie
                for cookie, intro in self.pending_introductions.items()
                if intro.get("intro_circuit_id") == circuit_id
            ]
            for cookie in remove_intro:
                self.pending_introductions.pop(cookie, None)

            link = self.rendezvous_links.pop(circuit_id, None)
            if link:
                cookie = link.get("cookie")
                peer_circuit_id = link.get("peer_circuit_id")
                if peer_circuit_id:
                    self.rendezvous_links.pop(peer_circuit_id, None)
                if isinstance(cookie, str):
                    entry = self.pending_rendezvous.pop(cookie, None)
                    if entry:
                        for side in ("client_circuit_id", "service_circuit_id"):
                            side_circuit_id = entry.get(side)
                            if side_circuit_id:
                                self.rendezvous_links.pop(side_circuit_id, None)

        self._transition_lifecycle_state(state, "closed")
        with self.lock:
            self.circuits.pop(circuit_id, None)

        print(f"[{self.relay_doc['name']}] circuit {circuit_id} destroyed")
        return {"ok": True, "status": "destroyed"}

    def handle_cell_batch(self, msg: dict[str, Any]) -> dict[str, Any]:
        circuit_id = msg.get("circuit_id")
        layers = msg.get("layers")
        if not isinstance(circuit_id, str) or not circuit_id:
            return {"ok": False, "error": "missing or invalid field: circuit_id"}
        if not isinstance(layers, list) or not layers:
            return {"ok": False, "error": "missing or invalid field: layers"}
        replies: list[dict[str, Any]] = []
        for layer in layers:
            reply = self.handle_cell({"type": "CELL", "circuit_id": circuit_id, "layer": layer})
            replies.append(reply)
            if not reply.get("ok"):
                break
        return {"ok": all(item.get("ok") for item in replies), "replies": replies}

    def handle_conn(self, conn: socket.socket) -> None:
        try:
            msg = recv_msg(conn)
            msg_type = msg.get("type")

            if msg_type == "BUILD":
                response = self.handle_build(msg)
            elif msg_type == "CELL":
                response = self.handle_cell(msg)
            elif msg_type == "CELL_BATCH":
                response = self.handle_cell_batch(msg)
            elif msg_type == "DESTROY":
                response = self.handle_destroy(msg)
            else:
                response = {"ok": False, "error": f"unknown message type {msg_type}"}

            send_msg(conn, response)
        except Exception as exc:
            try:
                send_msg(conn, {"ok": False, "error": str(exc)})
            except Exception:
                pass
        finally:
            try:
                conn.close()
            except Exception:
                pass


def run_relay_server(relay_path: str) -> None:
    relay_doc = load_json(relay_path)
    host = relay_doc["host"]
    port = relay_doc["port"]
    policy_doc = relay_doc.get("exit_policy") or {}
    exit_policy = ExitPolicy(
        allow_ports=[int(p) for p in policy_doc.get("allow_ports", [])],
        deny_ports=[int(p) for p in policy_doc.get("deny_ports", [])],
        allow_domains=[str(p) for p in policy_doc.get("allow_domains", ["*"])],
        deny_domains=[str(p) for p in policy_doc.get("deny_domains", [])],
        dns_server=policy_doc.get("dns_server"),
        deny_private_addresses=bool(policy_doc.get("deny_private_addresses", True)),
        max_concurrent_streams=int(policy_doc.get("max_concurrent_streams", 128)),
        max_new_connections_per_window=int(policy_doc.get("max_new_connections_per_window", 256)),
        rate_window_seconds=float(policy_doc.get("rate_window_seconds", 60.0)),
        max_attempts_per_destination=policy_doc.get("max_attempts_per_destination"),
    )
    server = RelayServer(
        relay_doc,
        use_persistent_channels=bool(relay_doc.get("use_persistent_channels", False)),
        circuit_ttl_seconds=float(relay_doc.get("circuit_ttl_seconds", 900.0)),
        circuit_idle_seconds=float(relay_doc.get("circuit_idle_seconds", 300.0)),
        stream_idle_seconds=float(relay_doc.get("stream_idle_seconds", 120.0)),
        exit_policy=exit_policy,
    )

    print(f"Starting relay {relay_doc['name']} on {host}:{port} using {relay_doc['kemalg']}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(128)

        while True:
            conn, _addr = srv.accept()
            server.handle_conn(conn)
