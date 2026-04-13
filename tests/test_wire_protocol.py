from __future__ import annotations

import json
import socket
import struct

import pytest


def test_send_recv_msg_round_trip_over_socketpair(latnet_modules):
    wire = latnet_modules["wire"]

    left, right = socket.socketpair()
    try:
        payload = {"type": "PING", "seq": 7, "payload": {"k": "v"}}
        wire.send_msg(left, payload)
        received = wire.recv_msg(right)
        assert received == payload
    finally:
        left.close()
        right.close()


def test_recv_msg_raises_on_malformed_length_longer_than_payload(latnet_modules):
    wire = latnet_modules["wire"]

    left, right = socket.socketpair()
    try:
        blob = b'{"type":"PING"}'
        left.sendall(struct.pack("!I", len(blob) + 5))
        left.sendall(blob)
        left.shutdown(socket.SHUT_WR)

        with pytest.raises(ConnectionError, match="socket closed"):
            wire.recv_msg(right)
    finally:
        left.close()
        right.close()


def test_recv_msg_raises_on_invalid_json_payload(latnet_modules):
    wire = latnet_modules["wire"]

    left, right = socket.socketpair()
    try:
        bad = b"not-json"
        left.sendall(struct.pack("!I", len(bad)))
        left.sendall(bad)

        with pytest.raises(json.JSONDecodeError):
            wire.recv_msg(right)
    finally:
        left.close()
        right.close()
