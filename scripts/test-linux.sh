#!/usr/bin/env bash
# Run the test suite (incl. Linux-only supervisor + lifecycle tests) inside a
# Linux container. Usage:
#   ./scripts/test-linux.sh            # full suite: cargo test --all-targets
#   ./scripts/test-linux.sh --lib      # just the library unit tests
#   ./scripts/test-linux.sh --no-run   # compile only
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE=draug-test
docker build -f Dockerfile.test -t "$IMAGE" .

# Default to all targets when no cargo args are passed.
if [ "$#" -eq 0 ]; then
  set -- --all-targets
fi

exec docker run --rm \
  -v "$PWD":/app:ro \
  -e CARGO_TARGET_DIR=/tmp/target \
  -e CARGO_HOME=/tmp/cargo \
  "$IMAGE" \
  cargo test --features _test_support "$@"
