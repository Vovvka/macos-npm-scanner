#!/bin/bash
# NPM Compromise Scanner - console user + time window
# Root / MDM friendly.
#
# Behavior:
#   - Uses remote IoCs if IOC_URLS contains valid URLs.
#   - Falls back to embedded IoCs if remote fetch fails or returns no valid IoCs.
#   - Scans:
#       1. Global node_modules
#       2. Console user's project node_modules
#       3. Console user's lockfiles
#
# Time-window behavior:
#   - package.json files are checked only if modified within the window.
#   - lockfiles are checked only if modified within the window.
#
# Output:
#   /Library/Logs/npm_compromise_scan.csv
#   /Library/Logs/npm_compromise_scan.json
#
# Exit:
#   0 = no finding
#   1 = finding found
#   2 = scanner/config error

set -u
shopt -s nullglob 2>/dev/null || true

DEBUG=0

LOGDIR="/Library/Logs"
CSV="${LOGDIR}/npm_compromise_scan.csv"
JSON="${LOGDIR}/npm_compromise_scan.json"
HOST="$(hostname -s 2>/dev/null || hostname)"
DATE_ISO="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
FOUND=0

log_debug() {
  [ "$DEBUG" -eq 1 ] && echo "$1" >&2
}

# ------------------------------------------------------------
# Incident window - local time
# ------------------------------------------------------------
#
# Format:
#   YYYYMMDDHHMM
#
# macOS/BSD find -newer is strict:
#   -newer REF_START    = modified after start
#   ! -newer REF_END    = not newer than end
#
# Effective logic:
#   modified > WINDOW_START and <= WINDOW_END

WINDOW_START_YmdHM="202604100000"
WINDOW_END_YmdHM="202604270000"

REF_START="/tmp/npm_scan_ref_start.$$"
REF_END="/tmp/npm_scan_ref_end.$$"

/usr/bin/touch -t "${WINDOW_START_YmdHM}" "$REF_START"
/usr/bin/touch -t "${WINDOW_END_YmdHM}" "$REF_END"

cleanup() {
  rm -f "$REF_START" "$REF_END"
}

trap cleanup EXIT

# ------------------------------------------------------------
# IoC list configuration
# ------------------------------------------------------------
#
# Root/MDM execution:
#   Script runs as root and without parameters.
#
# Remote IoCs:
#   Add one or multiple URLs into IOC_URLS.
#
# Embedded fallback:
#   If all remote URLs fail or return no valid IoCs, embedded IoCs are used.
#
# To disable remote IoCs:
#   IOC_URLS=("")

IOC_URLS=(
  "https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/shai-hulud-2-packages.csv"
  # "https://example.com/another-ioc-list.csv"
)

EMBEDDED_IOC_LIST=$(cat <<'EOF'
@automagik/genie|4.260421.33
@automagik/genie|4.260421.34
@automagik/genie|4.260421.35
@automagik/genie|4.260421.36
@automagik/genie|4.260421.37
@automagik/genie|4.260421.38
@automagik/genie|4.260421.39
pgserve|1.1.11
pgserve|1.1.12
pgserve|1.1.13
@fairwords/websocket|1.0.38
@fairwords/websocket|1.0.39
@fairwords/loopback-connector-es|1.4.3
@fairwords/loopback-connector-es|1.4.4
@openwebconcept/design-tokens|1.0.3
@openwebconcept/theme-owc|1.0.3
EOF
)

fetch_and_parse_iocs() {
  local url
  local content
  local line
  local lower
  local pkg
  local ver
  local ver_str
  local v
  local v_clean

  for url in "${IOC_URLS[@]}"; do
    [ -z "${url:-}" ] && continue

    log_debug "INFO: Fetching IoCs from: $url"

    if ! content=$(/usr/bin/curl -sL --connect-timeout 10 --max-time 30 "$url" 2>/dev/null); then
      log_debug "WARN: Failed to fetch IoCs from: $url"
      continue
    fi

    if [ -z "${content:-}" ]; then
      log_debug "WARN: Empty IoC response from: $url"
      continue
    fi

    printf '%s\n' "$content" | while IFS= read -r line; do
      line="$(printf '%s' "$line" | /usr/bin/sed 's/\r//g')"
      [ -z "${line:-}" ] && continue

      lower="$(printf '%s' "$line" | /usr/bin/tr '[:upper:]' '[:lower:]')"

      case "$lower" in
        package,version*|name,version*|package\|version*|name\|version*)
          continue
          ;;
      esac

      # Format 1:
      #   package|version
      if printf '%s' "$line" | /usr/bin/grep -q '|' && ! printf '%s' "$line" | /usr/bin/grep -q '||'; then
        pkg="$(printf '%s' "$line" | /usr/bin/awk -F'|' '{print $1}' | /usr/bin/tr -d '" ')"
        ver="$(printf '%s' "$line" | /usr/bin/awk -F'|' '{print $2}' | /usr/bin/tr -d '= "')"

        if [ -n "${pkg:-}" ] && [ -n "${ver:-}" ]; then
          printf '%s|%s\n' "$pkg" "$ver"
        fi

        continue
      fi

      # Format 2:
      #   package,version
      #   package,=1.0.1||=1.0.2
      if printf '%s' "$line" | /usr/bin/grep -q ','; then
        pkg="$(printf '%s' "$line" | /usr/bin/awk -F',' '{print $1}' | /usr/bin/tr -d '" ')"
        ver_str="$(printf '%s' "$line" | /usr/bin/cut -d',' -f2-)"

        [ -z "${pkg:-}" ] && continue
        [ -z "${ver_str:-}" ] && continue

        printf '%s\n' "$ver_str" | /usr/bin/awk -F '\\|\\|' '{for(i=1;i<=NF;i++) print $i}' | while IFS= read -r v; do
          v_clean="$(printf '%s' "$v" | /usr/bin/tr -d '= "' | /usr/bin/sed 's/\r//g')"

          if [ -n "${v_clean:-}" ]; then
            printf '%s|%s\n' "$pkg" "$v_clean"
          fi
        done

        continue
      fi
    done
  done
}

REMOTE_IOCS="$(fetch_and_parse_iocs | /usr/bin/awk -F'|' '$1 != "" && $2 != "" && !seen[$0]++ {print $0}')"

if [ -n "${REMOTE_IOCS:-}" ]; then
  IOC_SOURCE="remote"
  IOC_LIST="$REMOTE_IOCS"
else
  IOC_SOURCE="embedded"
  IOC_LIST="$(printf '%s\n' "$EMBEDDED_IOC_LIST" | /usr/bin/awk -F'|' '$1 != "" && $2 != "" && !seen[$0]++ {print $0}')"
fi

if [ -z "${IOC_LIST:-}" ]; then
  echo "ERROR: IoC list is empty. Aborting scan."
  exit 2
fi

IOC_COUNT="$(printf '%s\n' "$IOC_LIST" | /usr/bin/wc -l | /usr/bin/tr -d ' ')"

# ------------------------------------------------------------
# Console user helpers
# ------------------------------------------------------------

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

get_home_for_user() {
  local u="$1"

  [ -z "${u:-}" ] && return 1

  /usr/bin/dscl . -read "/Users/$u" NFSHomeDirectory 2>/dev/null | /usr/bin/awk '{print $2}'
}

CONSOLE_USER="$(get_console_user)"
USER_HOME=""

if [ -n "${CONSOLE_USER:-}" ] && [ "$CONSOLE_USER" != "root" ]; then
  USER_HOME="$(get_home_for_user "$CONSOLE_USER")"

  [ -z "${USER_HOME:-}" ] && USER_HOME="/Users/$CONSOLE_USER"
  [ -d "$USER_HOME" ] || USER_HOME=""
fi

# ------------------------------------------------------------
# Output helpers
# ------------------------------------------------------------

mkdir -p "$LOGDIR"

csv_escape() {
  printf '"%s"' "$(printf '%s' "$1" | /usr/bin/sed 's/"/""/g')"
}

json_escape() {
  # macOS/BSD sed-safe JSON escaping.
  # Scanner fields should not contain literal newlines.
  printf '%s' "$1" \
    | /usr/bin/sed \
      -e 's/\\/\\\\/g' \
      -e 's/"/\\"/g' \
      -e 's/	/\\t/g'
}

write_csv_header() {
  {
    csv_escape "timestamp"; printf ','
    csv_escape "host"; printf ','
    csv_escape "scope"; printf ','
    csv_escape "user_or_owner"; printf ','
    csv_escape "project_dir"; printf ','
    csv_escape "location"; printf ','
    csv_escape "package"; printf ','
    csv_escape "found_version"; printf ','
    csv_escape "indicator_version"; printf ','
    csv_escape "evidence_type"; printf ','
    csv_escape "source_type"
    printf '\n'
  } > "$CSV"
}

FIRST_JSON=1

write_json_header() {
  {
    printf '{\n'
    printf '  "timestamp": "%s",\n' "$(json_escape "$DATE_ISO")"
    printf '  "host": "%s",\n' "$(json_escape "$HOST")"
    printf '  "ioc_source": "%s",\n' "$(json_escape "$IOC_SOURCE")"
    printf '  "ioc_count": %s,\n' "$IOC_COUNT"
    printf '  "window_start_local": "%s",\n' "$(json_escape "$WINDOW_START_YmdHM")"
    printf '  "window_end_local": "%s",\n' "$(json_escape "$WINDOW_END_YmdHM")"
    printf '  "console_user": "%s",\n' "$(json_escape "${CONSOLE_USER:-}")"
    printf '  "user_home": "%s",\n' "$(json_escape "${USER_HOME:-}")"
    printf '  "findings": [\n'
  } > "$JSON"
}

write_json_footer() {
  printf '\n  ]\n}\n' >> "$JSON"
}

append_row() {
  local scope="$1"
  local owner="$2"
  local project_dir="$3"
  local location="$4"
  local pkg="$5"
  local found_version="$6"
  local indicator_version="$7"
  local evidence_type="$8"
  local source_type="$9"

  {
    csv_escape "$DATE_ISO"; printf ','
    csv_escape "$HOST"; printf ','
    csv_escape "$scope"; printf ','
    csv_escape "$owner"; printf ','
    csv_escape "$project_dir"; printf ','
    csv_escape "$location"; printf ','
    csv_escape "$pkg"; printf ','
    csv_escape "$found_version"; printf ','
    csv_escape "$indicator_version"; printf ','
    csv_escape "$evidence_type"; printf ','
    csv_escape "$source_type"
    printf '\n'
  } >> "$CSV"

  if [ "$FIRST_JSON" -eq 0 ]; then
    printf ',\n' >> "$JSON"
  fi

  FIRST_JSON=0

  {
    printf '    {'
    printf '"scope":"%s",' "$(json_escape "$scope")"
    printf '"user_or_owner":"%s",' "$(json_escape "$owner")"
    printf '"project_dir":"%s",' "$(json_escape "$project_dir")"
    printf '"location":"%s",' "$(json_escape "$location")"
    printf '"package":"%s",' "$(json_escape "$pkg")"
    printf '"found_version":"%s",' "$(json_escape "$found_version")"
    printf '"indicator_version":"%s",' "$(json_escape "$indicator_version")"
    printf '"evidence_type":"%s",' "$(json_escape "$evidence_type")"
    printf '"source_type":"%s"' "$(json_escape "$source_type")"
    printf '}'
  } >> "$JSON"

  FOUND=1
}

# ------------------------------------------------------------
# Package helpers
# ------------------------------------------------------------

get_unique_ioc_packages() {
  printf '%s\n' "$IOC_LIST" \
    | /usr/bin/awk -F'|' '
        NF >= 2 && $1 != "" {
          if (!seen[$1]++) print $1
        }
      '
}

ioc_hit() {
  local pkg="$1"
  local ver="$2"
  local key="${pkg}|${ver}"

  [ -z "${pkg:-}" ] && return 1
  [ -z "${ver:-}" ] && return 1

  /usr/bin/grep -Fqx -- "$key" <<< "$IOC_LIST"
}

read_pkgjson_name() {
  /usr/bin/awk -F'"' '
    /"name"[[:space:]]*:/ {
      print $4
      exit
    }
  ' "$1" 2>/dev/null
}

read_pkgjson_version() {
  /usr/bin/awk -F'"' '
    /"version"[[:space:]]*:/ {
      print $4
      exit
    }
  ' "$1" 2>/dev/null
}

owner_from_path() {
  local path="$1"

  case "$path" in
    /Users/*)
      printf '%s' "$path" | /usr/bin/awk -F/ '{print $3}'
      ;;
    *)
      printf 'unknown'
      ;;
  esac
}

ioc_package_to_package_json_path() {
  local root="$1"
  local pkg="$2"

  printf '%s/%s/package.json' "$root" "$pkg"
}

file_in_window() {
  local file="$1"

  [ -f "$file" ] || return 1

  /usr/bin/find "$file" \
    -type f \
    -newer "$REF_START" \
    ! -newer "$REF_END" \
    -print 2>/dev/null \
    | /usr/bin/grep -q .
}

scan_installed_package_json() {
  local scope="$1"
  local owner="$2"
  local project_dir="$3"
  local source_type="$4"
  local pjson="$5"
  local expected_pkg="$6"
  local actual_name
  local found_version

  [ -f "$pjson" ] || return 0
  file_in_window "$pjson" || return 0

  actual_name="$(read_pkgjson_name "$pjson")"
  found_version="$(read_pkgjson_version "$pjson")"

  [ -z "${actual_name:-}" ] && actual_name="$expected_pkg"

  if [ "$actual_name" != "$expected_pkg" ]; then
    return 0
  fi

  if ioc_hit "$actual_name" "$found_version"; then
    append_row \
      "$scope" \
      "$owner" \
      "$project_dir" \
      "$pjson" \
      "$actual_name" \
      "$found_version" \
      "$found_version" \
      "installed_node_modules" \
      "$source_type"
  fi
}

# ------------------------------------------------------------
# Lockfile helpers
# ------------------------------------------------------------

package_lock_has_version() {
  local file="$1"
  local pkg="$2"
  local badver="$3"

  /usr/bin/awk -v pkg="$pkg" -v badver="$badver" '
    BEGIN {
      in_pkg = 0
      lines_left = 0
      found = 0
      needle1 = "\"node_modules/" pkg "\""
      needle2 = "\"" pkg "\""
      version_needle = "\"version\""
      badver_needle = "\"" badver "\""
    }

    index($0, needle1) || index($0, needle2) {
      in_pkg = 1
      lines_left = 50
    }

    in_pkg && index($0, version_needle) && index($0, badver_needle) {
      found = 1
      exit
    }

    in_pkg {
      lines_left--
      if (lines_left <= 0) in_pkg = 0
    }

    END {
      exit(found ? 0 : 1)
    }
  ' "$file" 2>/dev/null
}

yarn_lock_has_version() {
  local file="$1"
  local pkg="$2"
  local badver="$3"

  /usr/bin/awk -v pkg="$pkg" -v badver="$badver" '
    BEGIN {
      in_pkg = 0
      found = 0
      version_needle1 = "version \"" badver "\""
      version_needle2 = "version: " badver
    }

    /^[^[:space:]]/ {
      if (index($0, pkg)) in_pkg = 1
      else in_pkg = 0
    }

    in_pkg && (index($0, version_needle1) || index($0, version_needle2)) {
      found = 1
      exit
    }

    END {
      exit(found ? 0 : 1)
    }
  ' "$file" 2>/dev/null
}

pnpm_lock_has_version() {
  local file="$1"
  local pkg="$2"
  local badver="$3"

  /usr/bin/awk -v pkg="$pkg" -v badver="$badver" '
    BEGIN {
      in_pkg = 0
      found = 0
      direct1 = "/" pkg "@" badver
      direct2 = pkg "@" badver
      version_needle1 = "version: " badver
      version_needle2 = "version " badver
    }

    index($0, direct1) || index($0, direct2) {
      found = 1
      exit
    }

    /^[^[:space:]]/ {
      if (index($0, pkg)) in_pkg = 1
      else in_pkg = 0
    }

    in_pkg && (index($0, version_needle1) || index($0, version_needle2)) {
      found = 1
      exit
    }

    END {
      exit(found ? 0 : 1)
    }
  ' "$file" 2>/dev/null
}

lockfile_has_ioc() {
  local file="$1"
  local pkg="$2"
  local badver="$3"
  local base

  base="$(basename "$file")"

  case "$base" in
    package-lock.json)
      package_lock_has_version "$file" "$pkg" "$badver"
      ;;
    yarn.lock)
      yarn_lock_has_version "$file" "$pkg" "$badver"
      ;;
    pnpm-lock.yaml)
      pnpm_lock_has_version "$file" "$pkg" "$badver"
      ;;
    *)
      return 1
      ;;
  esac
}

# ------------------------------------------------------------
# Find helpers
# ------------------------------------------------------------

dedupe_roots() {
  /usr/bin/awk 'NF && !seen[$0]++ { print }'
}

find_project_node_modules() {
  local home="$1"

  [ -d "$home" ] || return 0

  /usr/bin/find "$home" -maxdepth 8 \
    \( \
      -path "$home/Library" -o \
      -path "$home/Library/*" -o \
      -path "*/Library/Caches" -o \
      -path "*/Library/Caches/*" -o \
      -path "*/Library/Containers" -o \
      -path "*/Library/Containers/*" -o \
      -path "*/Library/Group Containers" -o \
      -path "*/Library/Group Containers/*" -o \
      -path "*/Library/Application Support" -o \
      -path "*/Library/Application Support/*" -o \
      -path "*/.git" -o \
      -path "*/.git/*" -o \
      -path "*/.cache" -o \
      -path "*/.cache/*" -o \
      -path "*/.Trash" -o \
      -path "*/.Trash/*" \
    \) -prune -o \
    -type d -name "node_modules" -print -prune 2>/dev/null
}

find_lockfiles() {
  local home="$1"

  [ -d "$home" ] || return 0

  /usr/bin/find "$home" -maxdepth 8 \
    \( \
      -path "$home/Library" -o \
      -path "$home/Library/*" -o \
      -path "*/Library/Caches" -o \
      -path "*/Library/Caches/*" -o \
      -path "*/Library/Containers" -o \
      -path "*/Library/Containers/*" -o \
      -path "*/Library/Group Containers" -o \
      -path "*/Library/Group Containers/*" -o \
      -path "*/Library/Application Support" -o \
      -path "*/Library/Application Support/*" -o \
      -path "*/.git" -o \
      -path "*/.git/*" -o \
      -path "*/.cache" -o \
      -path "*/.cache/*" -o \
      -path "*/.Trash" -o \
      -path "*/.Trash/*" \
    \) -prune -o \
    \( \
      -name "package-lock.json" -o \
      -name "yarn.lock" -o \
      -name "pnpm-lock.yaml" \
    \) -type f \
    -newer "$REF_START" \
    ! -newer "$REF_END" \
    -print 2>/dev/null
}

# ------------------------------------------------------------
# Start scan
# ------------------------------------------------------------

write_csv_header
write_json_header

IOC_PACKAGES="$(get_unique_ioc_packages)"

# ------------------------------------------------------------
# 1. Global node_modules scan
# ------------------------------------------------------------

GLOBAL_ROOTS_TMP="$(mktemp "/tmp/npm_global_roots.XXXXXX")"

[ -d /opt/homebrew/lib/node_modules ] && printf '%s\n' "/opt/homebrew/lib/node_modules" >> "$GLOBAL_ROOTS_TMP"
[ -d /usr/local/lib/node_modules ] && printf '%s\n' "/usr/local/lib/node_modules" >> "$GLOBAL_ROOTS_TMP"

for d in /opt/homebrew/Cellar/node/*/lib/node_modules /usr/local/Cellar/node/*/lib/node_modules; do
  [ -d "$d" ] && printf '%s\n' "$d" >> "$GLOBAL_ROOTS_TMP"
done

[ -d /usr/local/lib/node ] && printf '%s\n' "/usr/local/lib/node" >> "$GLOBAL_ROOTS_TMP"

if [ -n "${USER_HOME:-}" ]; then
  for d in "$USER_HOME"/.nvm/versions/node/*/lib/node_modules; do
    [ -d "$d" ] && printf '%s\n' "$d" >> "$GLOBAL_ROOTS_TMP"
  done

  for d in "$USER_HOME"/.asdf/installs/nodejs/*/lib/node_modules; do
    [ -d "$d" ] && printf '%s\n' "$d" >> "$GLOBAL_ROOTS_TMP"
  done

  [ -d "$USER_HOME/.node_modules" ] && printf '%s\n' "$USER_HOME/.node_modules" >> "$GLOBAL_ROOTS_TMP"
  [ -d "$USER_HOME/.node/lib/node_modules" ] && printf '%s\n' "$USER_HOME/.node/lib/node_modules" >> "$GLOBAL_ROOTS_TMP"
fi

while IFS= read -r ROOT; do
  [ -d "$ROOT" ] || continue

  while IFS= read -r PKG; do
    [ -z "${PKG:-}" ] && continue

    PJSON="$(ioc_package_to_package_json_path "$ROOT" "$PKG")"

    scan_installed_package_json \
      "global" \
      "global" \
      "" \
      "global_node_modules" \
      "$PJSON" \
      "$PKG"

  done <<< "$IOC_PACKAGES"

done < <(dedupe_roots < "$GLOBAL_ROOTS_TMP")

rm -f "$GLOBAL_ROOTS_TMP"

# ------------------------------------------------------------
# 2. Console user's project node_modules scan
# ------------------------------------------------------------

if [ -n "${USER_HOME:-}" ] && [ -d "$USER_HOME" ]; then
  while IFS= read -r NMDIR; do
    [ -d "$NMDIR" ] || continue

    PROJECT_DIR="$(dirname "$NMDIR")"
    OWNER="$(owner_from_path "$NMDIR")"

    while IFS= read -r PKG; do
      [ -z "${PKG:-}" ] && continue

      PJSON="$(ioc_package_to_package_json_path "$NMDIR" "$PKG")"

      scan_installed_package_json \
        "project" \
        "$OWNER" \
        "$PROJECT_DIR" \
        "project_node_modules" \
        "$PJSON" \
        "$PKG"

    done <<< "$IOC_PACKAGES"

  done < <(find_project_node_modules "$USER_HOME")
else
  log_debug "INFO: No non-root user home detected. Skipping project node_modules scan."
fi

# ------------------------------------------------------------
# 3. Console user's lockfile scan
# ------------------------------------------------------------

if [ -n "${USER_HOME:-}" ] && [ -d "$USER_HOME" ]; then
  while IFS= read -r LOCKFILE; do
    [ -f "$LOCKFILE" ] || continue

    PROJECT_DIR="$(dirname "$LOCKFILE")"
    OWNER="$(owner_from_path "$LOCKFILE")"
    SOURCE_TYPE="$(basename "$LOCKFILE")"

    while IFS='|' read -r PKG BADVER; do
      [ -z "${PKG:-}" ] && continue
      [ -z "${BADVER:-}" ] && continue

      if lockfile_has_ioc "$LOCKFILE" "$PKG" "$BADVER"; then
        append_row \
          "lockfile" \
          "$OWNER" \
          "$PROJECT_DIR" \
          "$LOCKFILE" \
          "$PKG" \
          "$BADVER" \
          "$BADVER" \
          "lockfile_resolved_version" \
          "$SOURCE_TYPE"
      fi
    done <<< "$IOC_LIST"

  done < <(find_lockfiles "$USER_HOME")
else
  log_debug "INFO: No non-root user home detected. Skipping lockfile scan."
fi

# ------------------------------------------------------------
# Finish
# ------------------------------------------------------------

write_json_footer

if [ "$FOUND" -eq 1 ]; then
  echo "Compromised npm package IoC match found."
  echo "Console user: ${CONSOLE_USER:-none}"
  echo "User home:    ${USER_HOME:-none}"
  echo "Time window:  ${WINDOW_START_YmdHM} to ${WINDOW_END_YmdHM}"
  echo "IoC source:   $IOC_SOURCE"
  echo "IoC count:    $IOC_COUNT"
  echo "CSV:          $CSV"
  echo "JSON:         $JSON"
else
  echo "No compromised npm package IoC matches found."
fi

exit "$FOUND"