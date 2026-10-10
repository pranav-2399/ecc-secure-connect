#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
PORT="${PORT:-5198}"
TEMP_DIR="$(mktemp -d)"
SERVER_PID=""

cleanup() {
    if [[ -n "$SERVER_PID" ]]; then kill "$SERVER_PID" 2>/dev/null || true; fi
    if [[ -n "${ALICE_PID:-}" ]]; then kill "$ALICE_PID" 2>/dev/null || true; fi
    if [[ -n "${BOB_PID:-}" ]]; then kill "$BOB_PID" 2>/dev/null || true; fi
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

cd "$PROJECT_DIR"
cmake -S host -B host/build
cmake --build host/build -j2
(
    cd communication
    "$PYTHON_BIN" communication_server.py --host 127.0.0.1 --port "$PORT"
) >"$TEMP_DIR/relay.log" 2>&1 &
SERVER_PID=$!

for attempt in $(seq 1 40); do
    if curl --silent --fail "http://127.0.0.1:$PORT/health" >/dev/null; then break; fi
    sleep 0.25
done
if ! curl --silent --fail "http://127.0.0.1:$PORT/health" >/dev/null; then
    cat "$TEMP_DIR/relay.log"
    echo "Relay did not start" >&2
    exit 1
fi

(
    sleep 5
    printf 'hello from Alice\n'
    sleep 3
    printf '/quit\n'
) | host/build/ecc_client Alice Bob "http://127.0.0.1:$PORT" >"$TEMP_DIR/alice.log" 2>&1 &
ALICE_PID=$!
(
    sleep 5
    printf 'hello from Bob\n'
    sleep 3
    printf '/quit\n'
) | host/build/ecc_client Bob Alice "http://127.0.0.1:$PORT" >"$TEMP_DIR/bob.log" 2>&1 &
BOB_PID=$!

wait "$ALICE_PID"
ALICE_PID=""
wait "$BOB_PID"
BOB_PID=""

if ! grep -q 'Bob: hello from Bob' "$TEMP_DIR/alice.log"; then
    cat "$TEMP_DIR/alice.log" "$TEMP_DIR/bob.log"
    echo "Alice did not receive Bob's message" >&2
    exit 1
fi
if ! grep -q 'Alice: hello from Alice' "$TEMP_DIR/bob.log"; then
    cat "$TEMP_DIR/alice.log" "$TEMP_DIR/bob.log"
    echo "Bob did not receive Alice's message" >&2
    exit 1
fi

echo "Two-client Flask relay smoke test passed."
echo "Alice and Bob exchanged and decrypted messages in both directions."
