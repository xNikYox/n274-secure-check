#!/usr/bin/env bash
# Neue Version veröffentlichen: Tests, bei Mozilla signieren (unlisted), GitHub-Release mit .xpi, updates.json aktualisieren.
# Installierte Addons holen sich die neue Version dann selbst (update_url im Manifest).
#   1. Version in manifest.json und package.json erhöhen
#   2. scripts/release.sh
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="xNikYox/n274-secure-check"
VERSION=$(node -p 'require("./manifest.json").version')
ID=$(node -p 'require("./manifest.json").browser_specific_settings.gecko.id')
TAG="v$VERSION"
FILE="n274-secure-check-$VERSION.xpi"
IGNORE=(test package.json package-lock.json node_modules web-ext-artifacts README.md scripts updates.json .amo-upload-uuid)

gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1 && { echo "Release $TAG gibt es schon – Version erhöhen."; exit 1; }
npm test >/dev/null
npx web-ext lint --ignore-files "${IGNORE[@]}" --output json | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const j=JSON.parse(s);if(j.summary.errors){console.error(j.errors);process.exit(1)}})'

set -a; . ~/.config/amo/keys; set +a
npx web-ext sign --channel unlisted --api-key "$AMO_JWT_ISSUER" --api-secret "$AMO_JWT_SECRET" --approval-timeout 900000 --timeout 900000 \
  --ignore-files "${IGNORE[@]}" 2>&1 | sed -E "s/${AMO_JWT_ISSUER}/[ISSUER]/g" | tail -3
SIGNED=$(ls -t web-ext-artifacts/*-"$VERSION".xpi | grep -v n274-secure-check | head -1)
cp "$SIGNED" "web-ext-artifacts/$FILE"
unzip -l "web-ext-artifacts/$FILE" | grep -q META-INF/mozilla.rsa || { echo "Nicht signiert!"; exit 1; }

# 1) Code + Tag hochladen und Release mit der .xpi anlegen
git add -A
git -c user.name=xNikYox -c user.email=202981923+xNikYox@users.noreply.github.com commit -q -m "Version $VERSION" || true
git tag "$TAG"
git push -q origin main "$TAG"
gh release create "$TAG" "web-ext-artifacts/$FILE" --repo "$REPO" --title "n274 Secure Check $VERSION" \
  --notes "Installieren: Datei in Firefox öffnen. Installierte Versionen aktualisieren sich automatisch."

# 2) Erst danach updates.json – sonst zeigt Firefox kurz auf eine Datei, die es noch nicht gibt
node -e '
const fs = require("fs");
const [id, version, link, hash] = process.argv.slice(1);
let u = { addons: {} };
try { u = JSON.parse(fs.readFileSync("updates.json", "utf8")); } catch {}
const list = (u.addons[id] ||= { updates: [] }).updates.filter((x) => x.version !== version);
list.push({ version, update_link: link, update_hash: "sha256:" + hash, browser_specific_settings: { gecko: { strict_min_version: "115.0" } } });
u.addons[id].updates = list;
fs.writeFileSync("updates.json", JSON.stringify(u, null, 2) + "\n");
' "$ID" "$VERSION" "https://github.com/$REPO/releases/download/$TAG/$FILE" "$(sha256sum "web-ext-artifacts/$FILE" | cut -d" " -f1)"
git add updates.json
git -c user.name=xNikYox -c user.email=202981923+xNikYox@users.noreply.github.com commit -q -m "updates.json: $VERSION"
git push -q origin main
echo "Fertig: $TAG veröffentlicht."
