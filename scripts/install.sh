#!/usr/bin/env bash
# One-shot install: CLI (pipx/pip) + Burp JAR from latest release.
# Usage: curl -sL https://raw.githubusercontent.com/Pa7ch3s/Unveil/main/scripts/install.sh | bash
#    or: ./scripts/install.sh   (from repo root)
set -e
REPO="Pa7ch3s/Unveil"
INSTALL_DIR="${UNVEIL_INSTALL_DIR:-$HOME/.local/share/unveil}"
API="https://api.github.com/repos/$REPO/releases/latest"

echo "[Unveil] One-shot install (CLI + Burp extension)"
echo ""

# 1) Install CLI
if command -v pipx &>/dev/null; then
  echo "[1/3] Installing CLI with pipx..."
  pipx install "git+https://github.com/$REPO.git" || true
  if pipx list | grep -q unveil; then
    echo "      CLI: $(which unveil 2>/dev/null || pipx run unveil --version 2>/dev/null | head -1)"
  fi
elif command -v pip3 &>/dev/null; then
  echo "[1/3] Installing CLI with pip..."
  pip3 install --user "git+https://github.com/$REPO.git" || true
  echo "      CLI: unveil (from Python scripts dir)"
else
  echo "[1/3] No pipx or pip3 found. Install Python 3 and pip, then re-run."
  exit 1
fi

# 2) Resolve latest JAR URL
echo "[2/3] Fetching latest release info..."
JSON=$(curl -sL "$API" 2>/dev/null || true)
if [ -z "$JSON" ]; then
  echo "      Fallback: using fixed JAR URL (v0.10.7)"
  JAR_URL="https://github.com/$REPO/releases/download/v0.10.7/unveil-burp-0.7.5.jar"
else
  JAR_URL=$(echo "$JSON" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for a in d.get('assets', []):
        n = a.get('name', '')
        if 'unveil-burp' in n and n.endswith('.jar'):
            print(a.get('browser_download_url', ''))
            break
except Exception:
    pass
" 2>/dev/null)
  if [ -z "$JAR_URL" ]; then
    JAR_URL="https://github.com/$REPO/releases/download/v0.10.7/unveil-burp-0.7.5.jar"
  fi
fi

# 3) Download JAR
echo "[3/3] Downloading Burp extension JAR..."
mkdir -p "$INSTALL_DIR"
JAR_PATH="$INSTALL_DIR/unveil-burp.jar"
if curl -sL -o "$JAR_PATH" "$JAR_URL" 2>/dev/null && [ -f "$JAR_PATH" ]; then
  echo "      JAR: $JAR_PATH"
else
  echo "      Download failed. Get the JAR manually from: https://github.com/$REPO/releases"
  exit 1
fi

echo ""
echo "Done. Next steps:"
echo "  • CLI:  run 'unveil -h'"
echo "  • Burp: Extensions → Add → Java → select: $JAR_PATH"
echo "  • Daemon (for Burp): run 'unveil' or 'python3 -m unveil.daemon' and keep 'Use daemon' checked in the Unveil tab."
echo ""
