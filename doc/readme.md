# WP Perf Shield

WP Perf Shield is a focused WordPress security plugin for blocking, scanning, investigating, and remediating wp-perf-analytics / session-manager style malware and related ClickFix render-hijacker variants, including native-render-toolkit, total-render-profiler, total-render-toolkit, pro-font-optimizer, site-speed-insights, advanced-asset-insights, page-seo-toolkit, starter-image-guard, auto-content-profiler, and pro-cache-scanner.

It is built for incident response and post-compromise hardening rather than broad, generic antivirus coverage.

## Features

- Real-time activation blocking for known malicious slugs, renamed patterns, and file hashes.
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
- PHP-guarded structured event log under `wp-perf-shield/logs/events.php`.
- Modern minimalist admin UI with rounded panels, gradient accents, clean tabs, and responsive layout behavior.
- Enqueued admin assets in `assets/css/admin.css` and `assets/js/admin.js` instead of large inline CSS/JavaScript blocks.
- Hostile IP auto-blocking for sources that attempt known malware uploads or renamed ZIPs containing known malicious folders, hashes, option keys, handler classes, or payload markers.
- Diagnostics tab for attacks, hostile IPs, clearance actions, scan outcomes, Source Trace timeline, and event mix.
- Upload-pathway diagnostics and a strict ZIP upload guard for closing unsafe upload routes.
- Doorway and backdoor kit detection with rename-proof matching that no longer depends on a fixed folder name, plus bundled file-manager shells and cloaking configuration files.
- Obfuscated packer detection for goto-flattened payloads with reconstructed function names, and anomalous `index.php` stubs carrying executable code where WordPress expects a one-line placeholder.
- File-operation web shell detection by capability cluster: files that browse, write, delete and accept uploads straight from request parameters. These contain no `eval` and no `shell_exec`, so execution-focused scanning is structurally blind to them.
- Detection of `php.ini` and `.user.ini` files that switch PHP hardening back off, clearing `disable_functions`, removing `open_basedir`, re-enabling shell execution, or setting `auto_prepend_file`.
- Cloaked content injector detection: malware that hides from logged-in administrators and from search-engine, SEO and page-speed crawlers while serving injected content to ordinary visitors, so neither the site owner nor an external scanner sees anything wrong.
- Identifier-splitting evasion defeated by normalising source before matching, so indicators written as glued fragments are found again. This restores every existing indicator list against a technique that had otherwise switched content matching off silently.
- Tamper protection through a must-use guard that restores the plugin if something removes it from the active plugin list, reports a deleted plugin directory, and notices a plugin listed as active that never loaded. Deliberate deactivation is respected through a signed consent record.
- Behavioural monitoring: sign-ins, failed sign-ins, account creation, role elevation, plugin and theme activity, uploads and sensitive admin screen views, grouped into incidents by actor and time window with a cumulative risk score and severity band.
- Class autoloading, so an ordinary front-end request parses about 36 KB of this plugin rather than the whole codebase.

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

## Admin Tabs

Tabs follow the incident-response workflow, grouped into an action band, an observability band, and a configuration band:

- **Overview**: scan status, manual scan action, readiness checks, findings table, and recent events.
- **Forensics**: incident trace report and manual SSH commands for deeper investigation.
- **Remediation**: targeted cleanup actions for known malware artifacts.
- **Hardening**: post-compromise checklist, one-click server or WordPress hardening actions, and the opt-in Content-Security-Policy controls and violation-report viewer.
- **Diagnostics**: attack attempts, hostile IPs, clearance actions, scan outcomes, daily activity, Source Trace, and operational status.
- **Events**: incident summaries with cumulative risk and severity band, above the structured security event history.
- **Logs**: read-only inspection of server access and error logs, with campaign-indicator and automated-login scans.
- **Settings**: custom blocked slugs, custom MD5/SHA-256 hashes, and behavior toggles.
- **Docs**: the plugin's own documentation rendered inside wp-admin, so this reference, the changelog and the upgrade notes are readable without leaving the site.

## Logging

Events are stored at:

```text
wp-content/plugins/wp-perf-shield/logs/events.php
```

The file lives inside the plugin folder and includes a PHP guard to prevent direct web exposure. The plugin-local `logs/` directory also ships with an `index.php` and `.htaccess`, and the logger migrates the previous `wp-content/wps-security/events.php` file on first run when present.

## Custom Indicators

Use the Settings tab to add:

- One plugin slug or slug fragment per line.
- One MD5 or SHA-256 file hash per line.

Custom entries are normalized and validated before saving.

## Safety Notes

- Destructive actions require WordPress admin capability checks and nonces.
- Deletion paths are resolved and checked against expected WordPress directories.
- Core file replacement uses the WordPress HTTP API and validates the downloaded content before writing.
- Some suspicious files should be reviewed manually before deletion if they are outside known malicious patterns.

## Version

Current plugin version: `1.4.30`

Author: [MENJ](https://github.com/menj)

## License

GPL-2.0-or-later.
