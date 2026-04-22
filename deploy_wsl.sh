#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

PID_DIR="deploy/pids"
LOG_DIR="deploy/logs"
mkdir -p deploy/{authority,relays,descriptors,bundle} "$PID_DIR" "$LOG_DIR"

if [[ -f "$PID_DIR/guard1.pid" || -f "$PID_DIR/middle1.pid" || -f "$PID_DIR/exit1.pid" || -f "$PID_DIR/directory.pid" ]]; then
  echo "Existing PID files found in $PID_DIR. Run ./teardown_wsl.sh first."
  exit 1
fi

python3 - <<'PY'
import pathlib
import sys
import types

root = pathlib.Path('.').resolve()
pkg = types.ModuleType('latnet')
pkg.__path__ = [str(root)]
sys.modules['latnet'] = pkg

from latnet.authority import (
    export_authority_pub_file,
    init_authority_file,
    make_bundle_file,
    sign_relay_file,
)
from latnet.relay import init_relay_file

init_authority_file('lab-authority', 'deploy/authority/authority.json')
export_authority_pub_file('deploy/authority/authority.json', 'deploy/authority/authority_pub.json')

init_relay_file('guard1', '127.0.0.1', 9101, 'deploy/relays/guard1.json')
init_relay_file('middle1', '127.0.0.1', 9102, 'deploy/relays/middle1.json')
init_relay_file('exit1', '127.0.0.1', 9103, 'deploy/relays/exit1.json')

sign_relay_file('deploy/relays/guard1.json', 'deploy/authority/authority.json', 3600, 'deploy/descriptors/guard1.desc.json')
sign_relay_file('deploy/relays/middle1.json', 'deploy/authority/authority.json', 3600, 'deploy/descriptors/middle1.desc.json')
sign_relay_file('deploy/relays/exit1.json', 'deploy/authority/authority.json', 3600, 'deploy/descriptors/exit1.desc.json')

make_bundle_file(
    'deploy/authority/authority_pub.json',
    [
        'deploy/descriptors/guard1.desc.json',
        'deploy/descriptors/middle1.desc.json',
        'deploy/descriptors/exit1.desc.json',
    ],
    'deploy/bundle/bundle.json',
)
PY

run_bg() {
  local name="$1"
  local pycode="$2"
  nohup python3 - <<PY >"$LOG_DIR/${name}.log" 2>&1 &
import pathlib
import sys
import types
root = pathlib.Path('.').resolve()
pkg = types.ModuleType('latnet')
pkg.__path__ = [str(root)]
sys.modules['latnet'] = pkg
$pycode
PY
  local pid=$!
  echo "$pid" > "$PID_DIR/${name}.pid"
}

run_bg "guard1" $'from latnet.relay import run_relay_server\nrun_relay_server("deploy/relays/guard1.json")'
run_bg "middle1" $'from latnet.relay import run_relay_server\nrun_relay_server("deploy/relays/middle1.json")'
run_bg "exit1" $'from latnet.relay import run_relay_server\nrun_relay_server("deploy/relays/exit1.json")'
run_bg "directory" $'from latnet.directory import run_directory_server\nrun_directory_server("deploy/bundle/bundle.json", host="127.0.0.1", port=9200)'

sleep 1

echo "Deployment started. Logs: $LOG_DIR"
echo "PIDs written to: $PID_DIR"
echo "Try client flow:"
echo "  python3 - <<'PY'"
echo "  import pathlib, sys, types"
echo "  root = pathlib.Path('.').resolve()"
echo "  pkg = types.ModuleType('latnet'); pkg.__path__ = [str(root)]; sys.modules['latnet'] = pkg"
echo "  from latnet import cli"
echo "  cli.main(['circuit','build','deploy/relays/guard1.json','deploy/relays/middle1.json','deploy/relays/exit1.json','--session','deploy/session.json'])"
echo "  PY"
