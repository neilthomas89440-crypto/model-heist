#!/usr/bin/env bash
# Copy both skills into the user's agent skills directory.
set -euo pipefail
DEST="${HOME}/.agents/skills"
mkdir -p "$DEST"
for skill in model-heist autoreg-pools; do
  src="$(cd "$(dirname "$0")" && pwd)/skills/$skill"
  rm -rf "$DEST/$skill"
  cp -R "$src" "$DEST/$skill"
  echo "installed $skill -> $DEST/$skill"
done
echo
echo "Verify: python \"$DEST/model-heist/scripts/doctor.py\""
