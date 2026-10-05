#!/usr/bin/env bash
set -e

# Find suitable node binary
if command -v node >/dev/null 2>&1; then
    NODE_CMD="node"
elif [ -f "/usr/share/code/code" ]; then
    NODE_CMD="env ELECTRON_RUN_AS_NODE=1 /usr/share/code/code"
elif [ -f "/usr/share/antigravity/antigravity" ]; then
    NODE_CMD="env ELECTRON_RUN_AS_NODE=1 /usr/share/antigravity/antigravity"
else
    echo "Error: Node.js runtime not found." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Using Node runtime: $($NODE_CMD -v)"
$NODE_CMD --test tests/*.test.js "$@"
