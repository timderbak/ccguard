#!/usr/bin/env bash
# Rebuild the self-hosted web UI assets under
# src/ccguard/server/web/static/vendor/ (Tailwind build, htmx, fonts).
#
# The console loads these locally — NO runtime CDN — so it renders fully in an
# air-gapped / on-prem install. Run this in a networked environment (needs
# node + npm + the npm registry) whenever you add new Tailwind utility classes
# to a template, bump htmx, or change the fonts. Commit the regenerated
# static/vendor/ tree.
#
# Requires: node >= 18, npm. No global installs — everything is local to a
# throwaway build dir.
set -euo pipefail

HTMX_VERSION="1.9.12"
TAILWIND_VERSION="3.4.17"
JAKARTA_WEIGHTS=(400 500 600 700 800)   # display / sans
MONO_WEIGHTS=(400 500 600)              # IBM Plex Mono
# Plus Jakarta Sans has no basic-cyrillic subset (Russian display text falls
# back to system-ui, same as with the old Google CDN); the mono face does.
JAKARTA_SUBSETS=(latin latin-ext cyrillic-ext)
MONO_SUBSETS=(latin latin-ext cyrillic cyrillic-ext)

REPO="$(cd "$(dirname "$0")/.." && pwd)"
DST="$REPO/src/ccguard/server/web/static/vendor"
TEMPLATES="$REPO/src/ccguard/server/web/templates"
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT
cd "$BUILD"

echo "[1/4] Tailwind static build (theme mirrors the former inline config)…"
cat > tailwind.config.js <<JS
module.exports = {
  content: ['$TEMPLATES/**/*.html'],
  theme: { extend: {
    fontFamily: {
      sans: ['"Plus Jakarta Sans"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
      mono: ['"IBM Plex Mono"', 'ui-monospace', 'monospace'],
      display: ['"Plus Jakarta Sans"', 'ui-sans-serif', 'sans-serif'],
    },
    colors: {
      ink: { 900: '#0b0810', 850: '#0e0b14', 800: '#16121f', 700: '#1b1626', 600: '#241d31' },
      signal: '#34d399',
      accent: { DEFAULT: '#a855f7', 2: '#c45cff', mag: '#e455c8' },
    },
    keyframes: {
      ccRise: { '0%': { opacity: '0', transform: 'translateY(10px)' }, '100%': { opacity: '1', transform: 'translateY(0)' } },
      ccPulse: { '0%,100%': { opacity: '1' }, '50%': { opacity: '.35' } },
    },
    animation: { ccRise: 'ccRise .5s cubic-bezier(.22,1,.36,1) both', ccPulse: 'ccPulse 2.4s ease-in-out infinite' },
  } },
};
JS
printf '@tailwind base;\n@tailwind components;\n@tailwind utilities;\n' > input.css
npm install --no-save "tailwindcss@${TAILWIND_VERSION}" >/dev/null 2>&1
mkdir -p "$DST/fonts"
npx tailwindcss -c tailwind.config.js -i input.css -o "$DST/tailwind.css" --minify >/dev/null 2>&1

echo "[2/4] htmx ${HTMX_VERSION}…"
npm pack "htmx.org@${HTMX_VERSION}" >/dev/null 2>&1
tar xzf "htmx.org-${HTMX_VERSION}.tgz"
cp package/dist/htmx.min.js "$DST/htmx.min.js"

echo "[3/4] fonts (@fontsource, normal weights, woff2)…"
npm install --no-save @fontsource/plus-jakarta-sans@5 @fontsource/ibm-plex-mono@5 >/dev/null 2>&1
JK=node_modules/@fontsource/plus-jakarta-sans
PM=node_modules/@fontsource/ibm-plex-mono
rm -f "$DST"/fonts/*.woff2
for w in "${JAKARTA_WEIGHTS[@]}"; do for s in "${JAKARTA_SUBSETS[@]}"; do
  f="$JK/files/plus-jakarta-sans-$s-$w-normal.woff2"; [ -f "$f" ] && cp "$f" "$DST/fonts/"
done; done
for w in "${MONO_WEIGHTS[@]}"; do for s in "${MONO_SUBSETS[@]}"; do
  f="$PM/files/ibm-plex-mono-$s-$w-normal.woff2"; [ -f "$f" ] && cp "$f" "$DST/fonts/"
done; done

echo "[4/4] fonts.css (@font-face with unicode-range, woff2-only, local paths)…"
: > "$DST/fonts.css"
for w in "${JAKARTA_WEIGHTS[@]}"; do cat "$JK/$w.css" >> "$DST/fonts.css"; done
for w in "${MONO_WEIGHTS[@]}"; do cat "$PM/$w.css" >> "$DST/fonts.css"; done
sed -i -E "s#url\(\./files/#url(/static/vendor/fonts/#g; s#, url\(/static/vendor/fonts/[^)]*\.woff\) format\('woff'\)##g" "$DST/fonts.css"

echo "Done → $DST"
ls -la "$DST"
