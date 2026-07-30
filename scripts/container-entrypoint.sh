#!/bin/sh

set -u

interval="${SECOPS_POLL_INTERVAL_SECONDS:-300}"
case "$interval" in
  ''|*[!0-9]*)
    printf 'SECOPS_POLL_INTERVAL_SECONDS must be a positive integer.\n' >&2
    exit 2
    ;;
  0)
    printf 'SECOPS_POLL_INTERVAL_SECONDS must be greater than zero.\n' >&2
    exit 2
    ;;
esac

stopping=0
child_pid=""

stop_runtime() {
  stopping=1
  if [ -n "$child_pid" ]; then
    kill -TERM "$child_pid" 2>/dev/null || true
  fi
}

trap stop_runtime TERM INT

while [ "$stopping" -eq 0 ]; do
  python -u run_openclaw_live.py &
  child_pid=$!
  wait "$child_pid"
  status=$?
  child_pid=""

  if [ "$stopping" -eq 1 ]; then
    exit 0
  fi
  if [ "$status" -ne 0 ]; then
    printf 'SecOpsAI pipeline exited with status %s; retrying after %s seconds.\n' "$status" "$interval" >&2
  fi

  sleep "$interval" &
  child_pid=$!
  wait "$child_pid" || true
  child_pid=""
done

exit 0
