# WP Perf Shield

WP Perf Shield is a focused WordPress security plugin for blocking, scanning, investigating, and remediating wp-perf-analytics / session-manager style malware and related ClickFix render-hijacker variants, including native-render-toolkit, total-render-profiler, total-render-toolkit, pro-font-optimizer, site-speed-insights, advanced-asset-insights, page-seo-toolkit, starter-image-guard, auto-content-profiler, and pro-cache-scanner.

It is built for incident response and post-compromise hardening rather than broad, generic antivirus coverage.

## Features

- Real-time activation blocking for known malicious slugs, renamed patterns, and file hashes.
- Site-policy plugin denylist, separate from malware blocking: ordinary plugins the operator refuses to run (WP File Manager and FileBird by default) cannot be uploaded or activated, and are deactivated if already present. Recorded as policy decisions, never as malware, and the uploader's address is never added to the hostile-IP list. A banned plugin found installed on disk is quarantined and removed on the next scan (reversible, and gated on both the banned-plugins and auto-delete switches).
- Built-in MD5 indicators plus custom MD5/SHA-256 hash support.
- Normal and multisite network-active plugin scrubbing.
- Detection for wp-content drop-in persistence loaders that restore `mu-plugins/session-manager.php` from `wp_session_tokens_config`.
- Temporal drop-in integrity guard that baselines `wp-content` drop-ins (`db.php`, `object-cache.php`, `advanced-cache.php`, and others) and records the exact time any of them appear, change, or are removed.
- On-chain EtherHiding detection: flags malicious option payloads that fetch their next stage from a Binance Smart Chain or Polygon smart contract via `eth_call`.
- Structural detection of XOR-plus-base64 self-decoding ClickFix loaders, matched by code shape rather than variable names, with base64-and-XOR payload recovery that reports the key, contract, and chain RPC hosts.
- Plugin metadata-camouflage detection for fake plugins whose header carries a placeholder `example.com` Plugin or Author URI.
- Server access-log inspection with an automated-login signature that flags IPs posting to `wp-login.php` with no preceding page load (credential stuffing).
- Hourly scheduled scanning with rate-limited admin email alerts for critical findings.
- Scans plugins, themes, uploads, cache directories, language directories, MU plugins, `wp-login.php`, `wp-cron.php`, `wp-config.php`, `.htaccess`, cron hooks, and suspicious database options.
- One-click remediation for known credential harvesters, exfil files, malicious database options, tampered files, suspicious users, attachments, plugin folders, and theme files.
- Targeted `wp-config.php` malware cleanup for known removable executable payloads, suspicious local/remote includes, option-loader restorers, and ClickFix markers.
- Forensics report for media uploads, admin accounts, timestamps, theme tampering, options, PHP backdoors, and WordPress core integrity.
- Hardening helpers for `wp-config.php` constants, `.htaccess` marker blocks, transient cleanup, session invalidation, and auth salt rotation.
- Opt-in Content-Security-Policy, off by default and report-only first, whose `connect-src` directive can block the injected ClickFix script from reaching its C2 or on-chain stage; reports collect in the Hardening tab so the policy can be tuned before enforcing.
- Detection of plugins that keep their payload in a WordPress option and re-seed it when deleted, so removal covers the database as well as the folder.
- A plugin roster that reports any plugin appearing without an installation recorded through the dashboard or WP-CLI, whatever its code contains — the tool an intruder brings.
- Detection of hidden administrator backdoors: code that creates an administrator account and conceals it from the Users screen and REST API, recreating it after deletion.
- Detection of code obfuscated by junk comments wedged between tokens, and of tiny typosquat plugins whose only behaviour is loading a remote script into every page.
- Detection of packed fake plugins that keep their payload in an opaque data file rather than in PHP, including self-reconstructing droppers that rebuild their own code after deletion, and of identifiers split across concatenation to defeat searching.
- Detection of self-concealing plugins: any plugin that removes its own entry from the Plugins list, or serves its front-end output to visitors while withholding it from administrators, caught structurally so a rewritten payload is still found.
- Detection of web-shell persistence written into `.htaccess`: rules that block PHP while allowlisting filenames WordPress does not ship, caught structurally so a renamed shell is still found, without flagging ordinary deny-PHP hardening.
- Detection of a web shell disguised as the root index.php of a genuine plugin or theme folder, by its own signature and, independently, by the size gap against the near-empty index.php stubs WordPress ships at every other folder level.
- Detection of injected casino/gambling/SEO-spam content in posts and comments, at scan time and in real time as a post is saved, tuned so it flags SEO-spam signatures without flagging legitimate writing that merely mentions gambling. Detection only — it never deletes content.
- PHP-guarded structured event log under `wp-perf-shield/logs/events.php`.
- Tamper-evident event chain with a concurrency-safe append, and an in-plugin Event-chain self-test in Diagnostics that verifies the chain against the live database on the host — including that its append lock excludes across two connections — without external tooling.
- Modern minimalist admin UI with rounded panels, gradient accents, clean tabs, and responsive layout behavior.
- Enqueued admin assets in `assets/css/admin.css` and `assets/js/admin.js` instead of large inline CSS/JavaScript blocks.
- Hostile IP auto-blocking for sources that attempt known malware uploads or renamed ZIPs containing known malicious folders, hashes, option keys, handler classes, or payload markers.
- Diagnostics tab for attacks, hostile IPs, clearance actions, scan outcomes, Source Trace timeline, and event mix.
- Upload-pathway diagnostics and a strict ZIP upload guard for closing unsafe upload routes.
- Doorway and backdoor kit detection that identifies a kit by what it carries rather than by what it is called. The folder name, the payload file names and the marker key inside the cloaking configuration are all things an attacker can change freely; the configuration's own vocabulary and the code that reads it are not, because neither works without the other. WP Perf Shield matches on the second kind. Bundled file-manager shells and cloaking configuration files are reported alongside the kit root.
- Obfuscated packer detection for goto-flattened payloads with reconstructed function names, and anomalous `index.php` stubs carrying executable code where WordPress expects a one-line placeholder.
- File-operation web shell detection by capability cluster: files that browse, write, delete and accept uploads straight from request parameters. These contain no `eval` and no `shell_exec`, so execution-focused scanning is structurally blind to them.
- Detection of `php.ini` and `.user.ini` files that switch PHP hardening back off, clearing `disable_functions`, removing `open_basedir`, re-enabling shell execution, or setting `auto_prepend_file`.
- Cloaked content injector detection: malware that hides from logged-in administrators and from search-engine, SEO and page-speed crawlers while serving injected content to ordinary visitors, so neither the site owner nor an external scanner sees anything wrong.
- Identifier-splitting evasion defeated by normalising source before matching, so indicators written as glued fragments are found again. This restores every existing indicator list against a technique that had otherwise switched content matching off silently.
- Runtime blocking of outbound requests carrying WordPress session cookies to external hosts, refused before the request leaves.
- Optional blocking of external post creation, editing and deletion through the REST API (`/wp/v2/posts`) and the post-writing XML-RPC methods — the injection route behind auto-blogging and doorway/SEO-spam posts — allowing only genuine administrator dashboard publishing, with blocked attempts logged. Off by default, since it breaks headless, mobile-app and integration publishing.
- Behavioural monitoring: sign-ins, failed sign-ins, account creation, role elevation, plugin and theme activity, uploads and sensitive admin screen views, grouped into incidents by actor and time window with a cumulative risk score and severity band.
- Class autoloading, so an ordinary front-end request parses about 36 KB of WP Perf Shield rather than the whole codebase.

## What WP Perf Shield detects

WP Perf Shield describes malware by **technique** rather than by name, because the names change on every build and the techniques do not. Each detection below came from a live sample that defeated everything already in place.

### Code that hides what it is

| Technique | What WP Perf Shield looks for |
|---|---|
| **Control-flow flattening** | Logic scattered behind hundreds of `goto` jumps. Measured by density — real code scores zero. |
| **Decoder chains** | `eval` wrapped around two or more of `base64_decode`, `gzinflate`, `str_rot13` plus a large encoded blob. |
| **Hidden identifiers** | Names written in fragments joined at runtime, so searching for `HTTP_USER_AGENT` finds nothing. |
| **Character-built identifiers** | Names spelled out of an innocuous sentence by position, or assembled with `chr()`. |
| **Self-extracting payloads** | A file that reads itself, splits on its own closing tag, and runs what follows. |
| **Obfuscated JavaScript in PHP** | The hexadecimal renaming automated obfuscators leave behind. |

> **Minified assets are never flagged.** Minifiers shorten names; obfuscators rename everything to hex. A legitimate 80 KB single-line bundle scores zero.

### Code that does not bother to hide

| Technique | What clears a file |
|---|---|
| **Unauthenticated file managers** | It loads WordPress, **or** checks authorisation, **or** takes no request input. Any one is enough. |
| **Executable PHP in a data directory** | Uploads, fonts and upgrade are strict. Caches and logs need a second signal, because plugins write there legitimately. |

> Files that are **inert by construction** — those beginning `<?php exit(...); __halt_compiler();`, as security plugins store their logs — are never reported.

### Code that changes the ground rules

| Technique | Why it matters |
|---|---|
| **Hardening-bypass configuration** | A `php.ini` or `.user.ini` re-enabling `shell_exec` or removing `open_basedir`. Not a payload — what makes the next payload work. |
| **Search-engine cloaking** | Different content served to crawlers than to visitors, so spam reaches your search results while your pages look untouched. |

### Code that steals

**Credentials and session cookies sent off-site** is the most consequential detection in WP Perf Shield, and the hardest to see: short, readable, unobfuscated PHP that waits for an administrator, collects their session cookies, and posts them elsewhere.

Whoever receives them is signed in as that administrator — **no password, and no failed login for any security plugin to notice.**

WP Perf Shield handles this in three ways:

1. **Blocks** the outbound request before it leaves, through WordPress's HTTP functions.
2. **Quarantines** the file responsible, recoverable for thirty days.
3. **Tells you the part neither of those fixes.**

> ### ⚠ Removing the file is not sufficient
>
> Sessions already taken stay valid until you rotate the authentication salts in `wp-config.php`.
> Get fresh values from <https://api.wordpress.org/secret-key/1.1/salt/> and replace the eight `define()` lines.
>
> **Do this after removal, not before** — rotate first and the file still present captures your replacement session.

The runtime block covers `wp_remote_*` calls. It **cannot** see `curl_exec`, `fsockopen` or raw streams, which bypass the WordPress HTTP API entirely. It closes the common case, not the category.

### How WP Perf Shield presents findings

Attack kits plant the same payload across a dozen directories under randomly generated names, so that finding one and deleting it changes nothing.

Copies with identical content flagged by the same check **collapse into one finding listing every location**. Grouping is by content, not filename — the filename is the part the attacker regenerates. One file flagged by two different checks stays as two findings, because they tell you different things.

## Sign-in protection

| Rule | Threshold |
|---|---|
| Failed sign-ins per address | 5 within 15 minutes |
| Escalation for repeat offenders (address) | 15 min → 1 hour → 6 hours → 1 day → 1 week |
| Attempt on a non-existent account (`admin`, `root`) | **Permanent**, on the first attempt |
| Rotation across an address range | Five distinct failing addresses in one /24 within an hour blocks the range, however slowly the attempts are paced — low-and-slow rotation cannot slip under the per-address limit |
| Escalation for repeat offenders (range) | 6 hours → 1 day → 3 days → 1 week, over a 14-day memory |
| Manual permanent range ban | Operator can permanently deny an address or a whole subnet from **Diagnostics**; refused if it holds the operator or is broader than a /16 |
| XML-RPC | `system.multicall` stripped by default so one request cannot carry many credential guesses, without breaking Jetpack or the mobile apps; full XML-RPC sign-in disable is a separate opt-in |
| Akismet, when present | Adjusts **duration only** — never whether to block, so the sign-in path never waits on the network. Optionally reports blocked addresses back to Akismet (never a CDN/proxy address, never a whole range) |

WP Perf Shield will not lock you out:

- Your own address is never blocked while signed in as an administrator.
- Addresses you have signed in from are protected for thirty days.
- Every block expires, and permanent entries are removable from **Diagnostics**.
- If all else fails, add this over FTP — no database access required:

```php
define( 'WPS_DISABLE_LOGIN_GUARD', true );
```

## Requirements

- WordPress 5.8 or newer.
- PHP 7.4 or newer.
- PHP ZipArchive extension recommended for renamed-ZIP content inspection.
- Administrator access to WordPress.
- Filesystem write access for remediation and hardening actions.
- Write access to `wp-content/plugins/wp-perf-shield/logs/` for the event log.

Some recovery actions may require SSH, WP-CLI, SFTP, or hosting-panel access.

## Installation

1. Upload the `wp-perf-shield` folder to `/wp-content/plugins/`.
2. Activate **WP Perf Shield** from the WordPress Plugins screen.
3. Go to **Tools > WP Perf Shield**.
4. Run a manual scan from the Overview tab.
5. Review findings and apply remediation or hardening actions as needed.

## The WP Perf Shield admin

Tabs follow the incident-response workflow, grouped into an action band, an observability band, and a configuration band:

- **Overview**: scan status, manual scan action, readiness checks, findings table, and recent events.
- **Forensics**: incident trace report and manual SSH commands for deeper investigation.
- **Remediation**: targeted cleanup actions for known malware artifacts.
- **Hardening**: post-compromise checklist, one-click server or WordPress hardening actions, and the opt-in Content-Security-Policy controls and violation-report viewer.
- **Diagnostics**: attack attempts, hostile IPs, clearance actions, scan outcomes, daily activity, Source Trace, and operational status; the permanent sign-in denylist with a field to permanently block an address or range by hand; and the Event-chain self-test.
- **Events**: incident summaries with cumulative risk and severity band, above the structured security event history.
- **Logs**: read-only inspection of server access and error logs, with campaign-indicator and automated-login scans.
- **Settings**: custom blocked slugs, the site-policy banned-plugins list, custom MD5/SHA-256 hashes, sign-in protection including XML-RPC and Akismet reporting controls, appearance, and behaviour toggles.
- **Docs**: the plugin's own documentation rendered inside wp-admin, so this reference, the changelog and the upgrade notes are readable without leaving the site.

## Logging

Events are stored at:

```text
wp-content/plugins/wp-perf-shield/logs/events.php
```

The file lives inside the plugin folder and includes a PHP guard to prevent direct web exposure. The plugin-local `logs/` directory also ships with an `index.php` and `.htaccess`, and the logger migrates the previous `wp-content/wps-security/events.php` file on first run when present.

## Custom indicators

Use the Settings tab to add:

- One plugin slug or slug fragment per line.
- One MD5 or SHA-256 file hash per line.

Custom entries are normalized and validated before saving.

## Remediation policy

Mark any finding Safe from the findings list, or protect a path directly from
Diagnostics before it is ever flagged. Protected targets are never removed
automatically by any check, while still being reported.


Automatic removal is mediated by `WPS_Remediation_Policy`. Marking a target Safe
is a permanent veto on automatic remediation, checked immediately before any
destructive action and keyed by canonical path so it cannot be defeated by a
different detector or a different spelling of the path. The policy fails closed
when trust state cannot be read, never lets a behavioural finding remove an
entire plugin or a WordPress core file, and halts all automatic removal if a
Safe target ever reaches the destructive gate.

## Safety notes

- Destructive actions require WordPress admin capability checks and nonces.
- Deletion paths are resolved and checked against expected WordPress directories.
- Core file replacement uses the WordPress HTTP API and validates the downloaded content before writing.
- Some suspicious files should be reviewed manually before deletion if they are outside known malicious patterns.

## Version

Current plugin version: `1.4.91`

Author: [MENJ](https://github.com/menj)

## License

GPL-2.0-or-later.
