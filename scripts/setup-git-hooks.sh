#!/bin/sh

HOOKS_DIR=$(git rev-parse --git-dir)/hooks
PRE_COMMIT_SCRIPT=$(pwd)/scripts/pre-commit

echo "Setting up pre-commit hook..."
ln -sf "$PRE_COMMIT_SCRIPT" "$HOOKS_DIR/pre-commit"
chmod +x "$HOOKS_DIR/pre-commit"

echo "Pre-commit hook installed."
