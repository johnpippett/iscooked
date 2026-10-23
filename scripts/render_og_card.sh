#!/usr/bin/env bash
# Render scripts/og-card.html to the 1200x630 social preview image.
# Usage: scripts/render_og_card.sh [output.png]
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="${1:-$root/site/assets/og-card-v2.png}"
browser="${CHROMIUM:-$(command -v chromium || command -v chromium-browser || command -v google-chrome)}"

"$browser" --headless --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --window-size=1200,630 --virtual-time-budget=2000 \
    --screenshot="$out" "file://$root/scripts/og-card.html" 2>/dev/null
echo "$out"
