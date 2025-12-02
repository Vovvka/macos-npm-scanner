#!/bin/bash
# NPM Compromise Scanner (macOS)
# Finds compromised packages/versions globally & in projects.
# Output: /Library/Logs/npm_compromise_scan.csv and .json

set -u  # treat unset vars as error
# set -o pipefail  # optional: uncomment if you prefer failure-on-pipeline

# Make unmatched globs expand to nothing (bash 3.2-compatible)
shopt -s nullglob 2>/dev/null || true

LOGDIR="/Library/Logs"
CSV="${LOGDIR}/npm_compromise_scan.csv"
JSON="${LOGDIR}/npm_compromise_scan.json"
HOST="$(hostname -s)"
DATE_ISO="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# IoC list: "name|bad_version"
IOC_LIST=$(cat <<'EOF'
backslash|0.2.1
chalk-template|1.1.1
supports-hyperlinks|4.1.1
has-ansi|6.0.1
simple-swizzle|0.2.3
color-string|2.1.1
error-ex|1.3.3
color-name|2.0.1
is-arrayish|0.3.3
slice-ansi|7.1.1
color-convert|3.1.1
wrap-ansi|9.0.1
ansi-regex|6.2.1
supports-color|10.2.1
strip-ansi|7.1.1
chalk|5.6.1
debug|4.4.2
ansi-styles|6.2.2
EOF
)

mkdir -p "$LOGDIR"
echo "timestamp,host,scope,user_or_owner,location,package,found_version,indicator_version,match,type" > "$CSV"
printf '{\n  "timestamp": "%s",\n  "host": "%s",\n  "findings": [\n' "$DATE_ISO" "$HOST" > "$JSON"
FIRST_JSON=1

append_row() {
  local ts="$DATE_ISO" host="$HOST" scope="$1" owner="$2" loc="$3" pkg="$4" fver="${5:-}" iver="$6" match="$7" type="$8"
  echo "$ts,$host,$scope,$owner,$loc,$pkg,${fver},$iver,$match,$type" >> "$CSV"
  # JSON
  [ $FIRST_JSON -eq 0 ] && printf ',\n' >> "$JSON"
  FIRST_JSON=0
  printf '    {"scope":"%s","user_or_owner":"%s","location":"%s","package":"%s","found_version":"%s","indicator_version":"%s","match":%s,"type":"%s"}' \
    "$scope" "$owner" "$loc" "$pkg" "${fver}" "$iver" "$match" "$type" >> "$JSON"
}

read_pkgjson_version() {
  # Read "version" from a package.json without jq
  # $1 = path/to/package.json
  awk -F'"' '/"version"[[:space:]]*:/ {print $4; exit}' "$1" 2>/dev/null
}

# --- 1) GLOBAL SCAN: known Node global module roots ---
GLOBAL_ROOTS=()

# Homebrew
[ -d /opt/homebrew/lib/node_modules ] && GLOBAL_ROOTS+=("/opt/homebrew/lib/node_modules")
[ -d /usr/local/lib/node_modules ] && GLOBAL_ROOTS+=("/usr/local/lib/node_modules")

# Homebrew Cellar Node (captures versioned lib dirs)
for d in /opt/homebrew/Cellar/node/*/lib/node_modules /usr/local/Cellar/node/*/lib/node_modules; do
  [ -d "$d" ] && GLOBAL_ROOTS+=("$d")
done

# System-wide (common Apple pkg locations)
[ -d /usr/local/lib/node ] && GLOBAL_ROOTS+=("/usr/local/lib/node")

# per-user nvm / asdf / Node installs
for U in /Users/*; do
  [ -d "$U" ] || continue
  # nvm
  for d in "$U"/.nvm/versions/node/*/lib/node_modules; do
    [ -d "$d" ] && GLOBAL_ROOTS+=("$d")
  done
  # asdf
  for d in "$U"/.asdf/installs/nodejs/*/lib/node_modules; do
    [ -d "$d" ] && GLOBAL_ROOTS+=("$d")
  done
  # legacy user-global
  [ -d "$U/.node_modules" ] && GLOBAL_ROOTS+=("$U/.node_modules")
  [ -d "$U/.node/lib/node_modules" ] && GLOBAL_ROOTS+=("$U/.node/lib/node_modules")
done

# Deduplicate roots
uniq_roots=()
for r in "${GLOBAL_ROOTS[@]-}"; do
  skip=0
  for e in "${uniq_roots[@]-}"; do
    [ "$r" = "$e" ] && { skip=1; break; }
  done
  [ $skip -eq 0 ] && uniq_roots+=("$r")
done

# Scan global roots
while IFS='|' read -r PKG BADVER; do
  [ -z "${PKG:-}" ] && continue
  for ROOT in "${uniq_roots[@]-}"; do
    CAND="$ROOT/$PKG/package.json"
    if [ -f "$CAND" ]; then
      FVER="$(read_pkgjson_version "$CAND")"
      MATCH=false
      [ "${FVER:-}" = "$BADVER" ] && MATCH=true
      append_row "global" "global" "$CAND" "$PKG" "${FVER:-unknown}" "$BADVER" "$MATCH" "node_modules"
    fi
  done
done <<< "$IOC_LIST"

# --- 2) PROJECT SCAN: local node_modules across user homes ---
# (limits scope to user homes to avoid huge traversals)
find /Users -type d -name "node_modules" -prune 2>/dev/null | while read -r NMDIR; do
  OWNER="$(echo "$NMDIR" | awk -F/ '{print $3}')"
  while IFS='|' read -r PKG BADVER; do
    PJSON="$NMDIR/$PKG/package.json"
    if [ -f "$PJSON" ]; then
      FVER="$(read_pkgjson_version "$PJSON")"
      MATCH=false
      [ "${FVER:-}" = "$BADVER" ] && MATCH=true
      append_row "project" "$OWNER" "$PJSON" "$PKG" "${FVER:-unknown}" "$BADVER" "$MATCH" "node_modules"
    fi
  done <<< "$IOC_LIST"
done

# --- 3) LOCKFILE SCAN: package-lock.json / yarn.lock / pnpm-lock.yaml ---
LOCK_ROOTS="/Users"
while IFS='|' read -r PKG BADVER; do
  # package-lock.json: search for the version; also record file if package name exists
  grep -R -n --include="package-lock.json" -e "\"version\"[[:space:]]*:[[:space:]]*\"${BADVER}\"" $LOCK_ROOTS 2>/dev/null \
    | cut -d: -f1 | sort -u | while read -r F; do
      if grep -q "\"${PKG}\"" "$F" 2>/dev/null; then
        OWNER="$(echo "$F" | awk -F/ '{print $3}')"
        append_row "lockfile" "$OWNER" "$F" "$PKG" "lockfile:${BADVER}" "$BADVER" true "package-lock.json"
      fi
    done

  # yarn.lock & pnpm-lock.yaml often have "pkg@version" tokens
  for LF in yarn.lock pnpm-lock.yaml; do
    grep -R -n --include="$LF" -e "${PKG}@${BADVER}" $LOCK_ROOTS 2>/dev/null \
      | while read -r LINE; do
          F="$(echo "$LINE" | cut -d: -f1)"
          OWNER="$(echo "$F" | awk -F/ '{print $3}')"
          append_row "lockfile" "$OWNER" "$F" "$PKG" "lockref:${BADVER}" "$BADVER" true "$LF"
        done
  done
done <<< "$IOC_LIST"

# Close JSON
printf '\n  ]\n}\n' >> "$JSON"

echo "Scan complete."
echo "CSV:  $CSV"
echo "JSON: $JSON"
exit 0
