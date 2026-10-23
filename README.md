# patch-php2shell

A small, defensive remediation helper for the **PHP2Shell** vulnerabilities:

| CVE | Type | Severity |
|-----|------|----------|
| **CVE-2026-109618** | Unauthenticated remote code execution in PHP request processing | CVSS 9.8 (Critical) |
| **CVE-2026-109619** | Unauthenticated RCE / server-memory disclosure | CVSS 9.8 (Critical) |

Disclosed **2026-10-21**. PHP states that **no configuration change fully mitigates these flaws — you must update PHP.** All SAPIs serving web requests are affected (PHP-FPM, mod_php, php-cgi, FrankenPHP, LiteSpeed), and exploitation needs no authentication.

> This script does **not** contain or demonstrate any exploit. It only *detects* exposure and *applies the official fix*. It is a patching tool, nothing else.

## Fixed versions

| Branch | Fixed in |
|--------|----------|
| 8.5.x | **8.5.12** |
| 8.4.x | **8.4.27** |
| 8.3.x | **8.3.36** |
| 8.2.x | **8.2.35** |
| 8.1 / 8.0 / 7.4 and older | **End of life** — no upstream release. Fixed only via a vendor backport (cPanel `ea-php*`, Remi, CloudLinux `alt-php`, your distro) or the official source-only patch branch. |

## What it does

1. **Detects** every PHP binary it can find (CLI and any SAPI) and reports, per the advisory, whether each is *patched*, *vulnerable*, or an *end-of-life branch*.
2. **Fixes via the package manager** when your distro / control panel ships a fixed package (`apt`, `dnf`, `yum`; cPanel EasyApache packages are picked up automatically). **This is the recommended path and the default.**
3. **Last resort for stuck EOL systems only** (`--build-from-source`): compiles the **official `php-src` security branch** (`PHP-7.4-CVE-2026-109618-109619`, and the 8.0 / 8.1 equivalents) and installs it as a drop-in replacement for the SAPI binaries. Because the version string is unchanged, your existing extension ABI — including **ionCube** and **OPcache** — keeps working. The old binaries are backed up and can be restored with `--rollback`.

## Usage

```bash
sudo ./patch-php2shell.sh                  # check, then apply the packaged fix (recommended)
sudo ./patch-php2shell.sh --check          # report only; change nothing
sudo ./patch-php2shell.sh --build-from-source   # EOL 7.4/8.0/8.1 with no vendor package
sudo ./patch-php2shell.sh --rollback       # undo a source build
```

## Before you run it on production

- **Take a snapshot / backup** and test on staging first. This changes PHP on a live server.
- The `--build-from-source` path needs a C toolchain and a few `-devel` libraries. Install them first:
  - **RHEL / Rocky / Alma 8:** `dnf install -y epel-release dnf-plugins-core && dnf config-manager --set-enabled powertools && dnf install -y git gcc make autoconf bison re2c pkgconf-pkg-config openssl-devel zlib-devel libxml2-devel readline-devel pcre2-devel libacl-devel systemd-devel`
  - **Debian / Ubuntu:** `apt-get install -y git build-essential autoconf bison re2c pkg-config libssl-dev zlib1g-dev libxml2-dev libreadline-dev libpcre2-dev libacl1-dev libsystemd-dev`
  - It builds a **minimal core** (CLI + your SAPIs + the statically-built-in extensions) and swaps only the `php` / `php-fpm` / `php-cgi` binaries. Every extension your distro ships as a shared `.so` keeps working untouched, because the PHP version — and the extension ABI — do not change.
- The official patch **disables PHP's upload-progress feature** and makes out-of-memory
  conditions exit immediately. This is intentional and harmless for the vast majority of apps.
- End-of-life PHP cannot be *proven* patched from its version string alone — confirm the
  package build date against your vendor's advisory, or prefer moving to a supported branch.

## The real fix

Updating PHP is the only complete remediation. If you are on an end-of-life branch,
treat the backport as a bridge and plan a move to a supported PHP version.

## References

- PHP.net security advisories for CVE-2026-109618 / CVE-2026-109619 (2026-10-21)
- Official patch branch: `php/php-src` → `PHP-7.4-CVE-2026-109618-109619`
- CISA urged immediate patching; active exploitation attempts were reported in the wild.

## License

MIT. No warranty — use at your own risk.
