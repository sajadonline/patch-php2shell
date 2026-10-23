#!/usr/bin/env bash
#
# patch-php2shell.sh
# -----------------------------------------------------------------------------
# Remediation helper for the PHP "PHP2Shell" vulnerabilities:
#     CVE-2026-109618 and CVE-2026-109619
#     (unauthenticated remote code execution, disclosed 2026-10-21)
#
# What it does, in order of preference:
#   1. Detects every PHP you have (CLI + any SAPIs it can see) and tells you,
#      per the official advisory, whether it is fixed, vulnerable, or an
#      end-of-life branch that can only be fixed by a vendor backport.
#   2. If your distro / control panel ships a fixed package, it uses the
#      package manager to install it (the safe, supported path).
#   3. ONLY for end-of-life PHP (7.4 / 8.0 / 8.1) that has no packaged fix,
#      and ONLY when you explicitly pass --build-from-source, it compiles the
#      OFFICIAL php-src security branch as a drop-in replacement, after backing
#      up the existing binaries so you can roll back.
#
# It never installs an exploit and never weakens the system. The source path
# applies only the upstream security team's own patch.
#
# Fixed versions (per php.net advisory):
#     8.5.x -> 8.5.12   8.4.x -> 8.4.27   8.3.x -> 8.3.36   8.2.x -> 8.2.35
#     8.1 / 8.0 / 7.4 and older: END OF LIFE, no upstream release.
#     Official source-only backport branches exist for 7.4, 8.0 and 8.1.
#
# Usage:
#     sudo ./patch-php2shell.sh                 # check + packaged fix (recommended)
#     sudo ./patch-php2shell.sh --check         # report only, change nothing
#     sudo ./patch-php2shell.sh --build-from-source   # last resort for stuck EOL
#     sudo ./patch-php2shell.sh --rollback      # undo a source build
#
# This touches PHP on a production server. Read the README, take a snapshot,
# and test on staging first. No warranty.
# -----------------------------------------------------------------------------

# No `set -e`: this tool deliberately probes several PHP binaries that may each
# fail or be absent, and must not abort the whole scan on the first one.
# Build/swap steps below guard their own failures explicitly with `|| die`.
set -uo pipefail

# --- fixed versions table -----------------------------------------------------
declare -A FIXED=( [8.5]=8.5.12 [8.4]=8.4.27 [8.3]=8.3.36 [8.2]=8.2.35 )
EOL_BRANCHES="8.1 8.0 7.4 7.3 7.2 7.1 7.0 5.6"
# php-src branches that carry the official security backport (source only)
OFFICIAL_BACKPORT_BRANCHES="7.4 8.0 8.1"

BACKUP_ROOT="/var/backups/php2shell-patch"
MODE="packaged"   # packaged | check | build | rollback

C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_BLU=$'\033[34m'; C_OFF=$'\033[0m'
log()  { printf '%s[*]%s %s\n'  "$C_BLU" "$C_OFF" "$*"; }
ok()   { printf '%s[ok]%s %s\n' "$C_GRN" "$C_OFF" "$*"; }
warn() { printf '%s[!]%s %s\n'  "$C_YEL" "$C_OFF" "$*" >&2; }
err()  { printf '%s[x]%s %s\n'  "$C_RED" "$C_OFF" "$*" >&2; }
die()  { err "$*"; exit 1; }

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

# --- arg parsing --------------------------------------------------------------
for a in "$@"; do
  case "$a" in
    --check)             MODE="check" ;;
    --build-from-source) MODE="build" ;;
    --rollback)          MODE="rollback" ;;
    -h|--help)           usage ;;
    *) die "unknown argument: $a (try --help)" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)."

# --- helpers ------------------------------------------------------------------
# version compare: returns 0 if $1 >= $2
ver_ge() { [ "$1" = "$2" ] && return 0; [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]; }

branch_of() { echo "$1" | awk -F. '{print $1"."$2}'; }

# version of a php binary, safe for every SAPI (cli/fpm/cgi):
# parse `-v` output rather than running `-r`, which only CLI accepts.
# Parsing `-v` (not `-r`) works on php-fpm and php-cgi too. The binary call is
# wrapped so a non-zero/absent SAPI can never abort the surrounding pipeline.
php_version_of() {
  { "$1" -v 2>/dev/null || true; } | sed -n '1s/^PHP \([0-9][0-9.]*\).*/\1/p' | head -1
}

# classify a full version string -> echoes: FIXED | VULN | EOL
classify() {
  local v="$1" b; b="$(branch_of "$v")"
  if [ -n "${FIXED[$b]:-}" ]; then
    ver_ge "$v" "${FIXED[$b]}" && { echo FIXED; return; }
    echo VULN; return
  fi
  # branch not in the supported table -> end of life
  echo EOL
}

detect_php_bins() {
  # print unique resolved paths of php / php-fpm / php-cgi on PATH and common spots
  { command -v php php-fpm php-cgi 2>/dev/null
    ls /usr/sbin/php-fpm /usr/local/sbin/php-fpm 2>/dev/null
    ls /opt/cpanel/ea-php*/root/usr/bin/php 2>/dev/null
    ls /opt/remi/php*/root/usr/bin/php 2>/dev/null
  } | sort -u
}

# Compute a drop-in ./configure line when the real options are unavailable.
# Strategy: a minimal core (--disable-all) that re-enables only the SAPIs you
# run and the extensions your PHP has compiled-in statically (everything else
# on your system is a shared .so and loads into the new binary unchanged,
# because the PHP version — and thus the extension ABI — does not change).
derive_configure() {
  local php_bin="$1"
  local extdir inipath scandir libdir trim='s/^[[:space:]]*//;s/[[:space:]]*$//'
  inipath="$("$php_bin" -i 2>/dev/null | awk -F'=> ' '/^Configuration File \(php.ini\) Path/{print $2; exit}' | sed "$trim")"
  scandir="$("$php_bin" -i 2>/dev/null | awk -F'=> ' '/Scan this dir for additional \.ini files/{print $2; exit}' | sed "$trim")"
  extdir="$("$php_bin" -r 'echo ini_get("extension_dir");' 2>/dev/null)"
  # absolute libdir, matching where the distro keeps the extension modules
  libdir=/usr/lib; case "$extdir" in */lib64/*) libdir=/usr/lib64;; esac

  # statically built-in modules = loaded modules that have no matching .so file
  local shared static mod flags=""
  shared="$(ls "$extdir" 2>/dev/null | sed 's/\.so$//' | tr 'A-Z' 'a-z' | sort -u)"
  static="$("$php_bin" -m 2>/dev/null | grep -v '^\[' | grep -v ' ' | tr 'A-Z' 'a-z' | sort -u \
            | comm -23 - <(echo "$shared"))"
  for mod in $static; do
    case "$mod" in
      openssl)  flags="$flags --with-openssl" ;;
      zlib)     flags="$flags --with-zlib" ;;
      readline) flags="$flags --with-readline" ;;
      libxml)   flags="$flags --with-libxml" ;;
      pcntl)    flags="$flags --enable-pcntl" ;;
      session)  flags="$flags --enable-session" ;;
      filter)   flags="$flags --enable-filter" ;;
      sodium)   flags="$flags --with-sodium" ;;
      bz2)      flags="$flags --with-bz2" ;;
      # Core/standard/spl/pcre/date/reflection/hash/json are always built in.
      core|standard|spl|pcre|date|reflection|hash|json|ctype|tokenizer) ;;
      *) warn "built-in module '$mod' has no known configure flag; skipping (verify after)" ;;
    esac
  done
  local sapis="--enable-cli"
  command -v php-fpm >/dev/null && sapis="$sapis --enable-fpm"
  command -v php-cgi >/dev/null && sapis="$sapis --enable-cgi"

  # Modern distros (Remi, Debian, RHEL8+) build PHP 7.4+ against the SYSTEM
  # pcre2 (--with-external-pcre). Their shared extensions — notably opcache —
  # then reference external pcre2_*_8 symbols, so the rebuilt core must use the
  # same external pcre2 or those .so fail with "undefined symbol: pcre2_...".
  # Use external pcre2 whenever it is available; otherwise fall back to bundled.
  if pkg-config --exists libpcre2-8 2>/dev/null || ls /usr/include/pcre2.h >/dev/null 2>&1; then
    flags="$flags --with-external-pcre"
  fi

  printf -- '--prefix=/usr --libdir=%s --disable-all %s %s --with-config-file-path=%s --with-config-file-scan-dir=%s' \
    "$libdir" "$sapis" "$flags" "${inipath:-/etc}" "${scandir:-/etc/php.d}"
}

restart_php_services() {
  log "restarting PHP / web services that are active ..."
  local svc
  for svc in php-fpm php*-php-fpm 'ea-php*-php-fpm' httpd apache2 nginx litespeed lsws; do
    for unit in $(systemctl list-units --type=service --state=active --no-legend 2>/dev/null \
                  | awk '{print $1}' | grep -E "${svc//\*/.*}" || true); do
      systemctl restart "$unit" 2>/dev/null && ok "restarted $unit" || warn "could not restart $unit"
    done
  done
}

# -----------------------------------------------------------------------------
# REPORT
# -----------------------------------------------------------------------------
report() {
  local any_vuln=0 any_eol=0
  log "scanning PHP binaries ..."
  while read -r bin; do
    [ -x "$bin" ] || continue
    local v st; v="$(php_version_of "$bin")"
    [ -n "$v" ] || continue
    st="$(classify "$v")"
    case "$st" in
      FIXED) ok   "$bin -> $v  (patched)";;
      VULN)  err  "$bin -> $v  (VULNERABLE: upgrade to ${FIXED[$(branch_of "$v")]})"; any_vuln=1;;
      EOL)   warn "$bin -> $v  (END OF LIFE branch $(branch_of "$v") - needs vendor backport or --build-from-source)"; any_eol=1;;
    esac
  done < <(detect_php_bins)
  echo
  [ "$any_vuln" = 1 ] && warn "At least one PHP is a supported branch below the fixed version."
  [ "$any_eol"  = 1 ] && warn "At least one PHP is end-of-life: a version string alone cannot prove it is patched; confirm the build date against your vendor's advisory."
  [ "$any_vuln$any_eol" = "00" ] && ok "Every PHP found is at or above the fixed version."
  return 0
}

# -----------------------------------------------------------------------------
# PACKAGED REMEDIATION
# -----------------------------------------------------------------------------
packaged_fix() {
  if command -v whmapi1 >/dev/null 2>&1 || [ -d /opt/cpanel ]; then
    log "cPanel/EasyApache detected: updating ea-php packages via the system package manager."
  fi
  if command -v apt-get >/dev/null 2>&1; then
    log "apt: refreshing and upgrading php packages ..."
    apt-get update
    # upgrade only installed php* and ea-php* packages, keep everything else pinned
    local pkgs; pkgs="$(dpkg -l | awk '/^ii  (ea-)?php/{print $2}' | tr '\n' ' ')"
    [ -n "$pkgs" ] && DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade $pkgs || warn "no php packages found via dpkg"
  elif command -v dnf >/dev/null 2>&1; then
    log "dnf: upgrading php packages ..."
    dnf -y upgrade 'php*' 'ea-php*' 2>/dev/null || dnf -y upgrade 'php*'
  elif command -v yum >/dev/null 2>&1; then
    log "yum: upgrading php packages ..."
    yum -y update 'php*' 'ea-php*' 2>/dev/null || yum -y update 'php*'
  else
    die "no supported package manager (apt/dnf/yum) found; use --build-from-source if this is a stuck EOL system."
  fi
  restart_php_services
  echo; log "re-checking ..."; report
}

# -----------------------------------------------------------------------------
# SOURCE BUILD (last resort, EOL only) — applies the OFFICIAL php-src patch
# -----------------------------------------------------------------------------
build_from_source() {
  local php_bin; php_bin="$(command -v php || true)"
  [ -n "$php_bin" ] || die "no php on PATH to model the build on."
  local v b; v="$(php_version_of "$php_bin")"; b="$(branch_of "$v")"

  case " $OFFICIAL_BACKPORT_BRANCHES " in
    *" $b "*) : ;;
    *) die "branch $b has no official source backport. For supported branches use the package manager; for <7.4 there is no vetted upstream patch." ;;
  esac

  command -v git  >/dev/null || die "git is required to fetch the official patch."
  command -v gcc  >/dev/null || die "a C toolchain and PHP core build deps are required. Install them first:
    RHEL/Rocky 8:  dnf install -y epel-release dnf-plugins-core && dnf config-manager --set-enabled powertools &&
                   dnf install -y git gcc make autoconf bison re2c pkgconf-pkg-config openssl-devel zlib-devel libxml2-devel readline-devel pcre2-devel
    Debian/Ubuntu: apt-get install -y git build-essential autoconf bison re2c pkg-config libssl-dev zlib1g-dev libxml2-dev libreadline-dev libpcre2-dev"

  # We deliberately build a MINIMAL core (cli + your SAPIs + only the
  # statically-built-in extensions), NOT a full clone of the distro's configure.
  # Why: the CVE fix lives in PHP core, which is compiled into every SAPI
  # binary. Every other extension on your system is a shared .so that loads into
  # the new binary unchanged, because the PHP version — and thus the extension
  # ABI — does not change. A minimal build needs only a handful of -devel libs
  # and avoids the fragile, dependency-heavy job of reproducing flags like
  # --enable-dtrace / --with-external-pcre / --enable-embed that distro builds use.
  local cfgopts; cfgopts="$(derive_configure "$php_bin")"
  log "minimal drop-in configure (your shared extensions are preserved as-is):"
  echo "    $cfgopts"

  # Where your current PHP keeps its shared extensions and scans for .ini files.
  # The rebuilt core's compiled-in default may differ, so we pin extension_dir
  # afterwards to keep every existing .so loading from the same place.
  local scan_dir ext_dir trim='s/^[[:space:]]*//;s/[[:space:]]*$//'
  scan_dir="$("$php_bin" -i 2>/dev/null | awk -F'=> ' '/Scan this dir for additional \.ini files/{print $2; exit}' | sed "$trim")"
  ext_dir="$("$php_bin" -r 'echo ini_get("extension_dir");' 2>/dev/null)"

  warn "This will compile PHP from the official security branch and replace the SAPI binaries in place."
  warn "The SAME version string ($v) keeps your extension ABI, so ionCube/OPcache keep working."
  read -r -p "Type YES to continue: " c; [ "$c" = "YES" ] || die "aborted."

  local work; work="$(mktemp -d)"; trap 'rm -rf "${work:-}"' EXIT
  local branch="PHP-${b}-CVE-2026-109618-109619"
  log "cloning official php-src branch $branch ..."
  git clone --depth 1 --branch "$branch" https://github.com/php/php-src.git "$work/php-src" \
    || die "could not fetch the official patch branch $branch from php-src."

  ( cd "$work/php-src"
    ./buildconf --force
    eval ./configure $cfgopts
    make -j"$(nproc)"
  ) || die "build failed; nothing on the system was changed."

  # back up and swap only the SAPI binaries that carry the vulnerable core code
  local stamp; stamp="$(date +%Y%m%d-%H%M%S)"; local bdir="$BACKUP_ROOT/$stamp"
  mkdir -p "$bdir"
  for tgt in "$(command -v php)" "$(command -v php-fpm || true)" "$(command -v php-cgi || true)"; do
    [ -n "$tgt" ] && [ -f "$tgt" ] || continue
    cp -a "$tgt" "$bdir/$(basename "$tgt")"
    local src=""
    case "$(basename "$tgt")" in
      php)     src="$work/php-src/sapi/cli/php" ;;
      php-fpm) src="$work/php-src/sapi/fpm/php-fpm" ;;
      php-cgi) src="$work/php-src/sapi/cgi/php-cgi" ;;
    esac
    [ -n "$src" ] && [ -f "$src" ] || { warn "built binary for $(basename "$tgt") not found, skipping"; continue; }
    install -m "$(stat -c '%a' "$tgt")" "$src" "$tgt"
    ok "replaced $tgt (backup: $bdir/$(basename "$tgt"))"
  done
  echo "$bdir" > "$BACKUP_ROOT/.last"

  # Pin extension_dir so the rebuilt core finds your existing shared .so files.
  if [ -n "$ext_dir" ] && [ -n "$scan_dir" ] && [ -d "$scan_dir" ]; then
    local pin="$scan_dir/00-php2shell-extension-dir.ini"
    printf '; added by patch-php2shell: keep the rebuilt PHP looking where your extensions already live\nextension_dir=%s\n' "$ext_dir" > "$pin"
    echo "$pin" > "$bdir/.added_ini"
    ok "pinned extension_dir=$ext_dir ($pin)"
  fi

  restart_php_services

  log "verifying ..."
  if ! "$(command -v php)" -v >/dev/null 2>&1; then
    err "patched PHP failed to run — rolling back automatically."; MODE=rollback; rollback; die "rolled back."
  fi
  local extfail; extfail="$("$(command -v php)" -r ';' 2>&1 | grep -c -iE 'Unable to load dynamic library|Failed loading' || true)"
  if [ "${extfail:-0}" -gt 0 ]; then
    err "$extfail extension(s) fail to load under the rebuilt PHP — rolling back automatically."
    "$(command -v php)" -r ';' 2>&1 | grep -iE 'Unable to load|Failed loading' | head -5 >&2
    MODE=rollback; rollback; die "rolled back (your extensions must keep loading)."
  fi
  ok "patched PHP runs and all extensions load. Keep the backup at $bdir until you have tested your application."
}

rollback() {
  local bdir; bdir="$(cat "$BACKUP_ROOT/.last" 2>/dev/null || true)"
  [ -n "$bdir" ] && [ -d "$bdir" ] || die "no backup recorded under $BACKUP_ROOT."
  log "restoring binaries from $bdir ..."
  # remove the extension_dir pin we added, if any
  if [ -f "$bdir/.added_ini" ]; then
    local ini; ini="$(cat "$bdir/.added_ini")"
    [ -n "$ini" ] && [ -f "$ini" ] && rm -f "$ini" && ok "removed $ini"
  fi
  local f
  for f in "$bdir"/*; do
    local name; name="$(basename "$f")"; local tgt; tgt="$(command -v "$name" || true)"
    [ -n "$tgt" ] && install -m "$(stat -c '%a' "$f")" "$f" "$tgt" && ok "restored $tgt" || warn "could not restore $name"
  done
  restart_php_services
  ok "rollback complete."
}

# -----------------------------------------------------------------------------
case "$MODE" in
  check)    report ;;
  packaged) report; echo; packaged_fix ;;
  build)    report; echo; build_from_source ;;
  rollback) rollback ;;
esac
