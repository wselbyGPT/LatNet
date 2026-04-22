from __future__ import annotations

import argparse
import json

from .client import demo_circuit_echo
from .util import load_json


def main() -> None:
    parser = argparse.ArgumentParser(description="Demo end-to-end circuit client flow")
    parser.add_argument("relay_paths", nargs="+", help="Relay JSON files in path order (guard ... exit)")
    parser.add_argument("--stream-id", type=int, default=1)
    parser.add_argument("--target", default="demo:443")
    parser.add_argument("--payload", default="hello")
    args = parser.parse_args()

    path = [load_json(p) for p in args.relay_paths]
    result = demo_circuit_echo(path, stream_id=args.stream_id, target=args.target, payload=args.payload)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
