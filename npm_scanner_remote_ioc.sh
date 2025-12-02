#!/bin/bash
# NPM Compromise Scanner (macOS) - console-user scoped, NO time window
# - Scans global node roots + console user's home ONLY
# - Uses provided IoC list (package|version), supports scoped names (@scope/name)
# - Exit 1 if ANY compromised version is found, else 0
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
  echo "WARN: No non-root console user detected; scanning only global roots."
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

# ===== IoC list: "name|bad_version" (repeat lines for packages with multiple versions) =====

# ===== IoC list: Fetch from URLs and parse =====
# List of URLs to fetch CSV IOCs from
IOC_URLS=(
  "https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/shai-hulud-2-packages.csv"
)

fetch_and_parse_iocs() {
  for url in "${IOC_URLS[@]}"; do
    local content
    # Use curl to fetch. Fail silently or warn?
    if ! content=$(/usr/bin/curl -sL "$url"); then
        echo "WARN: Failed to fetch $url" >&2
        continue
    fi
    
    # Parse CSV: Skip header, split versions by ||
    echo "$content" | tail -n +2 | while IFS=, read -r pkg ver_str; do
        [ -z "$pkg" ] && continue
        # Use awk to split by '||'
        echo "$ver_str" | awk -F '\\|\\|' '{for(i=1;i<=NF;i++) print $i}' | while read -r v; do
            # Clean v: remove =, spaces, quotes
            v_clean=$(echo "$v" | tr -d '= "')
            if [ -n "$v_clean" ]; then
                echo "$pkg|$v_clean"
            fi
        done
    done
  done
}

IOC_LIST="$(fetch_and_parse_iocs)"

# Build a quick exact-match check for "name|version"
ioc_hit() {
  # usage: ioc_hit "name" "version"
  local key="${1}|${2}"
  # -F fixed strings, -x exact line match, quiet
  grep -Fqx -- "$key" <<< "$IOC_LIST"
}

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
  if [ "$match" = "true" ]; then
    FOUND=1
  fi
}

# Lightweight JSON field readers (no jq)
read_pkgjson_field() {
  # $1=path $2=fieldname ("name" or "version")
  awk -v fld="$2" -F'"' '$2==fld{print $4; exit}' "$1" 2>/dev/null
}
read_pkgjson_name()   { read_pkgjson_field "$1" "name"; }
read_pkgjson_version(){ read_pkgjson_field "$1" "version"; }

# --- 1) GLOBAL SCAN: search package.json inside known global module roots ---
GLOBAL_ROOTS=()

# Homebrew globals
[ -d /opt/homebrew/lib/node_modules ] && GLOBAL_ROOTS+=("/opt/homebrew/lib/node_modules")
[ -d /usr/local/lib/node_modules ] && GLOBAL_ROOTS+=("/usr/local/lib/node_modules")

# Homebrew Cellar Node (captures versioned lib dirs)
for d in /opt/homebrew/Cellar/node/*/lib/node_modules /usr/local/Cellar/node/*/lib/node_modules; do
  [ -d "$d" ] && GLOBAL_ROOTS+=("$d")
done

# System-wide (some packages install here)
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

# Walk each global root: find ALL package.json under node_modules (handles scoped)
for ROOT in "${uniq_roots[@]-}"; do
  [ -d "$ROOT" ] || continue
  /usr/bin/find "$ROOT" -type f -name "package.json" -print 2>/dev/null | while read -r PJSON; do
    PNAME="$(read_pkgjson_name "$PJSON")"
    PVERS="$(read_pkgjson_version "$PJSON")"
    [ -z "${PNAME:-}" ] || [ -z "${PVERS:-}" ] && continue
    if ioc_hit "$PNAME" "$PVERS"; then
      append_row "global" "global" "$PJSON" "$PNAME" "$PVERS" "$PVERS" true "node_modules"
    fi
  done
done

# --- 2) PROJECT SCAN: console user's home only (node_modules trees) ---
if [ -n "${USER_HOME:-}" ] && [ -d "$USER_HOME" ]; then
  /usr/bin/find "$USER_HOME" -maxdepth 8 \
    \( -path "*/Library" -o -path "*/.git" -o -path "*/.cache" -o -path "*/.Trash" \) -prune -o \
    -type f -name "package.json" -path "*/node_modules/*/package.json" -print 2>/dev/null | \
  while read -r PJSON; do
    PNAME="$(read_pkgjson_name "$PJSON")"
    PVERS="$(read_pkgjson_version "$PJSON")"
    [ -z "${PNAME:-}" ] || [ -z "${PVERS:-}" ] && continue
    if ioc_hit "$PNAME" "$PVERS"; then
      append_row "project" "$CONSOLE_USER" "$PJSON" "$PNAME" "$PVERS" "$PVERS" true "node_modules"
    fi
  done
else
  echo "INFO: No non-root user home detected; skipping per-project scan."
fi

# --- 3) LOCKFILES: console user's home only (package-lock.json, yarn.lock, pnpm-lock.yaml) ---
if [ -n "${USER_HOME:-}" ] && [ -d "$USER_HOME" ]; then
  LOCKFILES=$(
    /usr/bin/find "$USER_HOME" -maxdepth 8 \
      \( -path "*/Library" -o -path "*/.git" -o -path "*/.cache" -o -path "*/.Trash" \) -prune -o \
      -type f \( -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" \) -print 2>/dev/null
  )

  # package-lock.json: require "name" and "version" both present
  while IFS='|' read -r PKG BADVER; do
    echo "$LOCKFILES" | /usr/bin/grep -E 'package-lock\.json$' | while read -r F; do
      if /usr/bin/grep -q "\"${PKG}\"" "$F" 2>/dev/null \
         && /usr/bin/grep -q "\"version\"[[:space:]]*:[[:space:]]*\"${BADVER}\"" "$F" 2>/dev/null; then
        append_row "lockfile" "$CONSOLE_USER" "$F" "$PKG" "lockfile:${BADVER}" "$BADVER" true "package-lock.json"
      fi
    done
    # yarn.lock / pnpm-lock.yaml: look for "pkg@version" (works with scoped names too)
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

echo "Console user: ${CONSOLE_USER:-none}"
[ -n "${USER_HOME:-}" ] && echo "Scanned home: $USER_HOME"
echo "CSV:  $CSV"
echo "JSON: $JSON"
echo "Scan complete."

if [ -f "$CSV" ] && [ $(wc -l < "$CSV") -gt 1 ]; then exit 1; else exit 0; fi