#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

PID_DIR="deploy/pids"

if [[ ! -d "$PID_DIR" ]]; then
  echo "No PID directory at $PID_DIR"
  exit 0
fi

for svc in directory exit1 middle1 guard1; do
  pid_file="$PID_DIR/${svc}.pid"
  if [[ -f "$pid_file" ]]; then
    pid="$(cat "$pid_file")"
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" || true
      sleep 0.2
      if kill -0 "$pid" 2>/dev/null; then
        kill -9 "$pid" || true
      fi
      echo "Stopped $svc (pid $pid)"
    else
      echo "$svc not running (stale pid $pid)"
    fi
    rm -f "$pid_file"
  fi
done

echo "Teardown complete."
