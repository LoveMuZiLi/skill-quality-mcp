#!/usr/bin/env bash
# Install the skill-quality plugin (MCP server + skill) into Cursor and/or Codex.
#   Local:  ./install.sh [--cursor-only|--codex-only]
#   Remote: curl -fsSL https://raw.githubusercontent.com/LoveMuZiLi/skill-quality-mcp/main/install.sh | bash
set -euo pipefail
REPO="${REPO:-LoveMuZiLi/skill-quality-mcp}"; REF="${REF:-main}"; MODE="${1:-all}"
PLUGIN=skill-quality; MARKETPLACE=skill-quality-mcp

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
LOCAL=0
if [ -n "$ROOT" ] && [ -f "$ROOT/plugins/$PLUGIN/server.py" ]; then LOCAL=1; else
  case "$REPO" in *LoveMuZiLi/skill-quality-mcp*) echo "Set REPO=owner/name"; exit 1;; esac
  TMP="$(mktemp -d)"; echo "Downloading $REPO@$REF ..."
  curl -fsSL "https://codeload.github.com/$REPO/tar.gz/refs/heads/$REF" | tar -xz -C "$TMP"
  ROOT="$(find "$TMP" -mindepth 1 -maxdepth 1 -type d | head -n1)"
fi

PY="$(command -v python3 || command -v python || true)"
[ -n "$PY" ] || { echo "Python 3.10+ not found"; exit 1; }
"$PY" -m pip install --user --quiet --disable-pip-version-check 'mcp>=2.3' || "$PY" -m pip install --user --quiet --break-system-packages 'mcp>=2.3'

if [ "$MODE" != "--codex-only" ]; then
  DEST="$HOME/.cursor/plugins/local/$PLUGIN"
  rm -rf "$DEST"; mkdir -p "$DEST"
  cp -R "$ROOT/plugins/$PLUGIN/." "$DEST/"; find "$DEST" -name __pycache__ -prune -exec rm -rf {} +
  # Cursor launches "python"; point it at the interpreter that actually exists here.
  sed -i.bak "s#\"command\": \"python\"#\"command\": \"$PY\"#" "$DEST/mcp.json" && rm -f "$DEST/mcp.json.bak"
  echo "Cursor: installed to $DEST -> run 'Developer: Reload Window'"
fi

if [ "$MODE" != "--cursor-only" ]; then
  if command -v codex >/dev/null 2>&1; then
    SRC="$REPO"; [ "$LOCAL" = 1 ] && SRC="$ROOT"
    codex plugin marketplace remove "$MARKETPLACE" >/dev/null 2>&1 || true
    codex plugin marketplace add "$SRC"
    codex plugin add "$PLUGIN@$MARKETPLACE"
    echo "Codex: plugin installed -> open a NEW Codex thread"
  else
    echo "Codex CLI not found; skipped Codex."
  fi
fi
echo "Done. Optional: export SONAR_HOST_URL / SONAR_TOKEN / SONAR_PROJECT_KEY for SonarQube."
