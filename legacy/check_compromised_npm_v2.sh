#!/bin/bash
# NPM Compromise Scanner (macOS) - console-user + time-window + MDM-friendly exit
# - Scans global node roots + console user's home ONLY
# - Considers files modified between Sep 8–9, 2025 (local time; end-exclusive)
# - Exit 1 if any compromised version is found (so MDM alerts), else 0
# Outputs:
#   /Library/Logs/npm_compromise_scan.csv
#   /Library/Logs/npm_compromise_scan.json

set -u
shopt -s nullglob 2>/dev/null || true

LOGDIR="/Library/Logs"
CSV="${LOGDIR}/npm_compromise_scan.csv"
JSON="${LOGDIR}/npm_compromise_scan.json"
HOST="$(hostname -s)"
DATE_ISO="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
FOUND=0  # flipped to 1 when any compromised version is detected

# ======= INCIDENT WINDOW (LOCAL TIME) =======
# Include files modified >= WINDOW_START and < WINDOW_END
WINDOW_START_YmdHM="202509080000"  # 2025-09-08 00:00
WINDOW_END_YmdHM="202509100000"    # 2025-09-10 00:00 (exclusive)

# Reference files for portable -newer tests on macOS/BSD find
REF_START="/tmp/npm_scan_ref_start.$$"
REF_END="/tmp/npm_scan_ref_end.$$"
/usr/bin/touch -t "${WINDOW_START_YmdHM}" "$REF_START"
/usr/bin/touch -t "${WINDOW_END_YmdHM}" "$REF_END"

# --- determine actual console user (even when running under sudo/root) ---
get_console_user() {
  local cu
  cu=$(/usr/bin/stat -f%Su /dev/console 2>/dev/null || true)
  if [ -z "${cu:-}" ] || [ "$cu" = "root" ] || [ "$cu" = "loginwindow" ]; then
    if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
      cu="$SUDO_USER"
    else
      local h="${HOME:-/var/root}"
      local huser
      huser="$(/usr/bin/stat -f%Su "$h" 2>/dev/null || true)"
      if [ -n "${huser:-}" ] && [ "$huser" != "root" ]; then
        cu="$huser"
      fi
    fi
  fi
  echo "$cu"
}

CONSOLE_USER="$(get_console_user)"
if [ -z "${CONSOLE_USER:-}" ] || [ "$CONSOLE_USER" = "root" ]; then
  echo "WARN: No non-root console user detected; scanning only global roots within time window."
fi

get_home_for_user() {
  local u="$1"
  [ -z "${u:-}" ] && return 1
  dscl . -read "/Users/$u" NFSHomeDirectory 2>/dev/null | awk '{print $2}'
}

USER_HOME=""
if [ -n "${CONSOLE_USER:-}" ] && [ "$CONSOLE_USER" != "root" ]; then
  USER_HOME="$(get_home_for_user "$CONSOLE_USER")"
  [ -z "${USER_HOME:-}" ] && USER_HOME="/Users/$CONSOLE_USER"
  [ -d "$USER_HOME" ] || USER_HOME=""
fi

# ===== IoC list: "name|bad_version" =====
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

# ===== Output init =====
mkdir -p "$LOGDIR"
echo "timestamp,host,scope,user_or_owner,location,package,found_version,indicator_version,match,type" > "$CSV"
printf '{\n  "timestamp": "%s",\n  "host": "%s",\n  "findings": [\n' "$DATE_ISO" "$HOST" > "$JSON"
FIRST_JSON=1

append_row() {
  local ts="$DATE_ISO" host="$HOST" scope="$1" owner="$2" loc="$3" pkg="$4" fver="${5:-}" iver="$6" match="$7" type="$8"
  echo "$ts,$host,$scope,$owner,$loc,$pkg,${fver},$iver,$match,$type" >> "$CSV"
  [ $FIRST_JSON -eq 0 ] && printf ',\n' >> "$JSON"
  FIRST_JSON=0
  printf '    {"scope":"%s","user_or_owner":"%s","location":"%s","package":"%s","found_version":"%s","indicator_version":"%s","match":%s,"type":"%s"}' \
    "$scope" "$owner" "$loc" "$pkg" "${fver}" "$iver" "$match" "$type" >> "$JSON"
  # Flip exit flag only if version truly matches the malicious one
  if [ "$match" = "true" ]; then
    FOUND=1
  fi
}

read_pkgjson_version() {
  awk -F'"' '/"version"[[:space:]]*:/ {print $4; exit}' "$1" 2>/dev/null
}

# ============= 1) GLOBAL SCAN (time-window filtered) =============
GLOBAL_ROOTS=()

# Homebrew globals
[ -d /opt/homebrew/lib/node_modules ] && GLOBAL_ROOTS+=("/opt/homebrew/lib/node_modules")
[ -d /usr/local/lib/node_modules ] && GLOBAL_ROOTS+=("/usr/local/lib/node_modules")

# Homebrew Cellar Node (captures versioned lib dirs)
for d in /opt/homebrew/Cellar/node/*/lib/node_modules /usr/local/Cellar/node/*/lib/node_modules; do
  [ -d "$d" ] && GLOBAL_ROOTS+=("$d")
done

# System-wide (common Apple pkg locations)
[ -d /usr/local/lib/node ] && GLOBAL_ROOTS+=("/usr/local/lib/node")

# Current user's toolchains (nvm/asdf/legacy)
if [ -n "${USER_HOME:-}" ]; then
  for d in "$USER_HOME"/.nvm/versions/node/*/lib/node_modules; do
    [ -d "$d" ] && GLOBAL_ROOTS+=("$d")
  done
  for d in "$USER_HOME"/.asdf/installs/nodejs/*/lib/node_modules; do
    [ -d "$d" ] && GLOBAL_ROOTS+=("$d")
  done
  [ -d "$USER_HOME/.node_modules" ] && GLOBAL_ROOTS+=("$USER_HOME/.node_modules")
  [ -d "$USER_HOME/.node/lib/node_modules" ] && GLOBAL_ROOTS+=("$USER_HOME/.node/lib/node_modules")
fi

# Deduplicate roots
uniq_roots=()
for r in "${GLOBAL_ROOTS[@]-}"; do
  skip=0
  for e in "${uniq_roots[@]-}"; do [ "$r" = "$e" ] && { skip=1; break; }; done
  [ $skip -eq 0 ] && uniq_roots+=("$r")
done

# For each root, only package.json modified in window
for ROOT in "${uniq_roots[@]-}"; do
  [ -d "$ROOT" ] || continue
  while IFS= read -r PJSON; do
    PKG="$(basename "$(dirname "$PJSON")")"
    while IFS='|' read -r NAME BADVER; do
      [ -z "${NAME:-}" ] && continue
      if [ "$NAME" = "$PKG" ]; then
        FVER="$(read_pkgjson_version "$PJSON")"
        MATCH=false
        [ "${FVER:-}" = "$BADVER" ] && MATCH=true
        append_row "global" "global" "$PJSON" "$PKG" "${FVER:-unknown}" "$BADVER" "$MATCH" "node_modules"
      fi
    done <<< "$IOC_LIST"
  done < <( /usr/bin/find "$ROOT" -type f -name "package.json" -newer "$REF_START" ! -newer "$REF_END" 2>/dev/null )
done

# ========== 2) PROJECT SCAN (console user's home, time-window) ==========
if [ -n "${USER_HOME:-}" ] && [ -d "$USER_HOME" ]; then
  while IFS= read -r PJSON; do
    PKG="$(basename "$(dirname "$PJSON")")"
    while IFS='|' read -r NAME BADVER; do
      [ -z "${NAME:-}" ] && continue
      if [ "$NAME" = "$PKG" ]; then
        FVER="$(read_pkgjson_version "$PJSON")"
        MATCH=false
        [ "${FVER:-}" = "$BADVER" ] && MATCH=true
        append_row "project" "$CONSOLE_USER" "$PJSON" "$PKG" "${FVER:-unknown}" "$BADVER" "$MATCH" "node_modules"
      fi
    done <<< "$IOC_LIST"
  done < <(
    /usr/bin/find "$USER_HOME" -maxdepth 8 \
      \( -path "*/Library" -o -path "*/.git" -o -path "*/.cache" -o -path "*/.Trash" \) -prune -o \
      -type f -name "package.json" -path "*/node_modules/*/package.json" \
      -newer "$REF_START" ! -newer "$REF_END" -print 2>/dev/null
  )
else
  echo "INFO: No non-root user home detected; skipping per-project scan."
fi

# ======= 3) LOCKFILES (console user's home only, time-window) =======
if [ -n "${USER_HOME:-}" ] && [ -d "$USER_HOME" ]; then
  LOCKFILES=$(
    /usr/bin/find "$USER_HOME" -maxdepth 8 \
      \( -path "*/Library" -o -path "*/.git" -o -path "*/.cache" -o -path "*/.Trash" \) -prune -o \
      -type f \( -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" \) \
      -newer "$REF_START" ! -newer "$REF_END" -print 2>/dev/null
  )

  while IFS='|' read -r PKG BADVER; do
    # package-lock.json: require version AND package name present
    echo "$LOCKFILES" | /usr/bin/grep -E 'package-lock\.json$' | while read -r F; do
      if /usr/bin/grep -q "\"version\"[[:space:]]*:[[:space:]]*\"${BADVER}\"" "$F" 2>/dev/null \
         && /usr/bin/grep -q "\"${PKG}\"" "$F" 2>/dev/null; then
        append_row "lockfile" "$CONSOLE_USER" "$F" "$PKG" "lockfile:${BADVER}" "$BADVER" true "package-lock.json"
      fi
    done

    # yarn.lock / pnpm-lock.yaml: look for "pkg@version"
    for LF in yarn.lock pnpm-lock.yaml; do
      echo "$LOCKFILES" | /usr/bin/grep -E "/${LF}$" | while read -r F; do
        if /usr/bin/grep -q "${PKG}@${BADVER}" "$F" 2>/dev/null; then
          append_row "lockfile" "$CONSOLE_USER" "$F" "$PKG" "lockref:${BADVER}" "$BADVER" true "$LF"
        fi
      done
    done
  done <<< "$IOC_LIST"
fi

# ===== Close JSON and exit for MDM =====
printf '\n  ]\n}\n' >> "$JSON"
rm -f "$REF_START" "$REF_END"

echo "Console user: ${CONSOLE_USER:-none}"
[ -n "${USER_HOME:-}" ] && echo "Scanned home: $USER_HOME"
echo "Time window (local): from ${WINDOW_START_YmdHM} to ${WINDOW_END_YmdHM} (end exclusive)"
echo "CSV:  $CSV"
echo "JSON: $JSON"
echo "Scan complete."

exit $FOUND
