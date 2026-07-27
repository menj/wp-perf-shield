=== WP Perf Shield ===
Contributors: menj
Author URI: https://github.com/menj
Tags: security, malware, scanner, hardening, remediation
Requires at least: 5.8
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 1.4.30
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Blocks wp-perf-analytics traffic-hijacking malware and renamed variants with activation blocking, scheduled scanning, forensics, hardening, and remediation tools.

== Description ==

WP Perf Shield is a focused WordPress security plugin built to detect and disrupt the wp-perf-analytics / session-manager malware family and related ClickFix render-hijacker variants such as native-render-toolkit, total-render-profiler, total-render-toolkit, pro-font-optimizer, site-speed-insights, advanced-asset-insights, page-seo-toolkit, starter-image-guard, auto-content-profiler, pro-cache-scanner, and total-database-optimizer.

It has grown well past that starting point. Detection now covers doorway kits, obfuscated packers, file-operation web shells that contain no executable code at all, PHP configuration files that switch hardening back off, and cloaked injectors that hide from administrators and crawlers alike while serving content to ordinary visitors. Source is normalised before matching, so malware that splits its identifiers across concatenated fragments to defeat scanners is caught anyway.

Beyond scanning, the plugin protects itself with a must-use guard that restores it if something disables it, and records what happens on the site - sign-ins, account creation, role elevation, plugin and theme activity, uploads - grouping related activity into incidents with a cumulative risk score.

It combines real-time plugin activation blocking, hourly malware scanning, behavioural monitoring, a tamper-evident event log, one-click remediation actions, forensic reporting, and hardening helpers for common post-compromise cleanup tasks.

= Key features =

* Blocks known malicious plugin slugs and renamed plugin patterns from activation.
* Checks plugin file hashes using built-in MD5 indicators and custom MD5/SHA-256 hashes.
* Scrubs blocked plugins from both normal active plugin lists and multisite network-active plugin lists.
* Detects wp-content drop-in persistence loaders that restore `mu-plugins/session-manager.php` from `wp_session_tokens_config`.
* Scans plugins, themes, uploads, cache directories, language directories, MU plugins, wp-login.php, wp-cron.php, wp-config.php, .htaccess, cron hooks, and suspicious database options.
* Runs an hourly scheduled scan and sends rate-limited email alerts for critical findings.
* Provides one-click cleanup actions for known credential harvesters, exfil files, malicious options, tampered wp-cron.php, suspicious users, attachments, plugin folders, and theme files.
* Detects and cleans known removable malware patterns from wp-config.php with a pre-write backup and clean-baseline reset.
* Includes forensic reporting for media uploads, admin accounts, plugin timestamps, theme tampering, option anomalies, PHP backdoors, and WordPress core file integrity.
* Includes hardening actions for wp-config.php constants, .htaccess marker blocks, transient cleanup, session invalidation, and auth salt rotation.
* Stores structured logs in a PHP-guarded file under wp-content/plugins/wp-perf-shield/logs.
* Uses a modern minimalist admin UI with rounded panels, gradient accents, and mobile-friendly layout behavior.
* Enqueues admin CSS and JavaScript from assets/css/admin.css and assets/js/admin.js.
* Auto-deletes confirmed malware artifacts by default, with a Settings tab control for detect-only operation.
* Auto-blocks IP addresses that attempt to upload known malware ZIPs or renamed ZIPs containing known malicious folders, hashes, or payload markers.
* Detects file-operation web shells by capability cluster - browsing, writing, deleting and uploading driven by raw request parameters - which contain no eval or shell_exec and so evade execution-focused scanning.
* Detects php.ini and .user.ini files that re-enable shell execution or remove open_basedir and disable_functions restrictions.
* Detects cloaked injectors that serve content to visitors while hiding from logged-in administrators and from search-engine, SEO and page-speed crawlers.
* Normalises split-literal obfuscation before matching, so identifiers written as glued fragments are found and every existing indicator keeps working.
* Protects itself with a must-use guard that restores the plugin if something removes it from the active plugin list, while respecting deliberate deactivation through a signed consent record.
* Records behaviour and groups related activity into incidents with cumulative risk scoring.
* Renders its own documentation inside wp-admin.
* Autoloads its classes, so an ordinary front-end page view parses a fraction of the codebase.
* Includes a Diagnostics tab for attack attempts, hostile IPs, clearances, scan outcomes, Source Trace timeline, and operational status.
* Records upload-pathway diagnostics and restricts ZIP uploads to trusted administrator upload routes.

== Installation ==

1. Upload the `wp-perf-shield` folder to `/wp-content/plugins/`.
2. Activate WP Perf Shield from the WordPress Plugins screen.
3. Open Tools > WP Perf Shield.
4. Run a manual scan from the Overview tab.
5. Review the Diagnostics, Forensics, Remediation, Hardening, Events, and Settings tabs as needed.

The plugin logs directory, `wp-content/plugins/wp-perf-shield/logs/`, must be writable by WordPress for event logging.

The PHP ZipArchive extension is recommended so WP Perf Shield can inspect inside renamed ZIP uploads before WordPress accepts them.

Additional project documentation is stored in the plugin `doc/` folder. The root `readme.txt` remains in place for WordPress plugin metadata.

== Frequently Asked Questions ==

= Is this a general-purpose antivirus plugin? =

No. WP Perf Shield is intentionally focused on known wp-perf-analytics / session-manager style malware, related backdoors, suspicious persistence options, and common post-compromise cleanup workflows.

= Does deactivating the plugin remove protection? =

Deactivation stops the normal plugin hooks and scheduled scan. The plugin intentionally does not remove protective artifacts that may need to survive deactivation unless removed through the admin UI or full uninstall.

= Where are logs stored? =

Security events are stored in `wp-content/plugins/wp-perf-shield/logs/events.php`. The file is PHP-guarded to prevent direct web exposure, and the log directory includes an `index.php` and `.htaccess` to block direct access.

= Can I add custom indicators? =

Yes. Use the Settings tab to add custom blocked slugs and custom MD5 or SHA-256 file hashes.

= Does this support multisite? =

The blocker checks and scrubs both normal active plugins and network-active plugins. Site-specific behavior should still be tested in your own multisite environment before relying on it broadly.

= Can the plugin repair every infected file automatically? =

No. Some repairs require SSH, WP-CLI, SFTP, or hosting-panel access. The plugin provides manual commands and targeted actions where automatic cleanup would be unsafe.

== Screenshots ==

1. Overview with scan status, issue summary, readiness checks, and recent events.
2. Diagnostics tab with attack, clearance, scan, IP, Source Trace, and operational summaries.
3. Forensics report with trace data and manual SSH commands.
4. Remediation tab with targeted cleanup actions.
5. Hardening checklist for post-compromise security controls.
6. Events tab for the full retained security log.

== Changelog ==

= 1.4.30 =
Finishes the Settings screen work. Field labels were still picking up a data-table heading treatment - small capitals, letter spacing and a hardcoded grey that ignored dark mode - because an older global rule reached every heading in the plugin. Labels now read as labels, in sentence case, and follow your colour scheme. Also fixes the wp-config.php snippet breaking across two lines mid-expression, and an oversized test button. Stylesheet only; no functional changes.

= 1.4.29 =
Fixes the security event log filling with duplicate diagnostic entries. The scanner notes when it suppresses a batch of files modified at the same moment; that note was being written on every scan rather than once, and because the log is capped, the repetition could push genuine security events out of retention within hours. Each batch is now noted once, and again only if it grows. No change to what the scanner detects or suppresses.

= 1.4.28 =
Rebuilds the Settings screen, which was the only screen still inheriting WordPress's default form styling rather than the plugin's own. The label column now lines up across every section, all checkbox rows use one layout, and descriptions, text boxes and dropdowns follow the plugin's colour scheme including dark mode, which previously they did not at all. Also fixes a real bug: the Akismet reporting checkbox rendered as off while the feature was actually on, so saving any other setting would have silently switched it off.

= 1.4.27 =
Automatic reporting of confirmed attackers to Akismet is now on by default, so every install contributes to the shared spam database out of the box. To keep that safe on sites behind a CDN, automatic reporting stands down when the blocked address is in a known Cloudflare or private range, where it may be the proxy rather than the attacker. A new "Report spam" button on each blocked address in Diagnostics lets you report one by hand; because a person has looked first, the button works even on those proxy-range addresses. Blocked-address expiry times now show in your site timezone.

= 1.4.26 =
Makes the login protection stronger and smarter about duration. The site's own evidence now decides how long a block lasts, and Akismet can only lengthen it, never shorten it below what the local evidence warrants - fixing a case where an address that tried twenty usernames was let go after fifteen minutes because Akismet had not catalogued it yet. Repeat offenders who wait out a block and return now face escalating blocks: fifteen minutes, an hour, six hours, a day, a week. An address trying five or more different usernames is blocked for a day outright. And you can now opt in to reporting confirmed attackers back to Akismet, so every site using it benefits - off by default, and only ever reporting addresses your own site has proven to be attacking.

= 1.4.25 =
Detects search-engine cloaking, also called doorway spam: a file that serves spam pages to search crawlers and the real site to everyone else, so the owner never sees it while their search results fill with pages they did not write. Also detects control-flow-flattened PHP by measuring goto density, which obfuscators cannot escape or rename away. Most importantly, string signatures are now matched after resolving hex and octal escapes - a recovered live sample hid every one of its cloaking strings that way and slipped past every content check in the scanner.

= 1.4.24 =
Rebuilds the server log inspection screen. The repeated log-type column is gone, row actions are links rather than full-weight buttons, and file sizes are right-aligned with tabular figures so a large file stands out. Files over fifty megabytes are now marked as slow to scan, since scanning one can exceed the host's execution limit. The hosting caveat moved beneath the table, where it is useful, instead of above the controls.

= 1.4.23 =
Closes an evasion in the login protection. Attempts spread across many addresses in one range, so that no single address reaches the limit, are now counted together: twelve failures from at least three different addresses in the same range within fifteen minutes blocks sign-ins from that range for thirty minutes. Twelve failures from one address still blocks only that address, because one noisy host is not the same as rotation. Ranges containing an address you have signed in from, or one on your allowlist, are never blocked, and the whole behaviour has its own off switch for sites whose visitors share a mobile carrier or corporate network.

= 1.4.22 =
Timezone headings now use the same wording as the WordPress Settings screen - UTC+8 rather than GMT+8 - so the plugin and the dashboard describe your timezone the same way. Times were already correct; only the label changed.

= 1.4.21 =
Timestamps now display in your site's timezone rather than UTC, with the column heading naming the zone. Events are still stored in UTC, which is deliberate - only the display changed. The events tables were rebuilt again: detail text no longer renders as monospaced terminal output across three lines, repeated steps in an incident collapse to a count rather than repeating the same words across the screen, and the column widths were rebalanced.

= 1.4.20 =
Shows monthly Akismet API usage for the configured key in Diagnostics and Settings: calls used, plan limit, percentage, and a warning if the key is being throttled for exceeding its plan. Cached for an hour so viewing the page does not consume the allowance it reports. Note that most of this figure is Akismet checking comments rather than anything to do with login protection, which adds roughly one call per blocked address.

= 1.4.19 =
Documentation correction. The Akismet integration was documented before its published API specification was to hand, and hedged where the specification is explicit: custom comment types are documented, and comment-check requires only the key, the blog URL and the address. The integration itself is unchanged and was always correct.

= 1.4.18 =
Makes the login protection visible. Diagnostics now shows whether it is active, whether Akismet was detected, how many failed sign-ins have been seen today and this week, and how many addresses were blocked. Blocks record which logic chose their duration, so an Akismet-informed block is no longer indistinguishable from the default. Settings gains a button that tests the Akismet connection on demand, so you get a definite answer without waiting to be attacked.

= 1.4.17 =
Blocks automated sign-in attempts. Five failures from one address within fifteen minutes blocks it temporarily, and bot-favourite usernames such as admin and root are blocked on the first attempt when no such account exists. Optionally disables XML-RPC authentication, which is how one request can carry hundreds of credential guesses. If the Akismet plugin is active and configured, its key is detected automatically and used to set how long a block lasts - never whether to block, so nothing on the sign-in path ever waits on the network. Your own address cannot be blocked, every block expires, and a wp-config.php constant switches the whole thing off if you are ever locked out.

= 1.4.16 =
The security events tables are rebuilt. Severity now drives the display - a rail on the row and a dot beside the label - so a wp-config.php change no longer looks like an admin screen being viewed. Event names read as English instead of raw identifiers. The overview, events and incidents tables share one severity source, replacing two hand-written lists that had drifted from the codebase, and column widths move from inline styles into tokenised CSS with proper dark scheme support. This also fixed a real bug: the severity map named an event type that is never emitted, so the most serious event a site can raise was being classified as routine.

= 1.4.15 =
The must-use tamper protection is withdrawn after causing two outages, and upgrading actively removes it - the files are deleted from wp-content/mu-plugins and the options cleared, because a must-use plugin keeps loading whether or not this plugin installs it. Only its own three files are touched. Where the directory is read-only the file is made inert instead and reported. This does mean malware that deactivates the plugin will now succeed silently; the reasoning for accepting that is documented in the upgrade notes, along with what would have to be true before the feature returns.

= 1.4.14 =
Completes the 1.4.13 fix. A worst-case measurement - 200,000 requests with the guard in its failure state - showed the event spool still growing to 52 MB, because the size check read a cached file size and only one of four recording paths was throttled. The throttle now sits at the single point every record passes through, and the stat cache is cleared before the size check. Re-measured under the same conditions: the 256 KB ceiling holds. Existing installs regenerate the fixed guard automatically on upgrade.

= 1.4.13 =
Fixes a fault in this plugin that could white-screen a site. The must-use guard recorded an event on every request when its signing key was missing - which is what happens after a backup or migration that skips dot-files - and the plugin then tried to import all of them at once, exhausting memory. The record is now throttled, the spool is capped at both ends, and a missing key is regenerated instead of being reported for ever. Existing installs regenerate the fixed guard automatically on upgrade.

= 1.4.12 =
Fail-safe bootstrap. A fatal error anywhere in this plugin can no longer take the site down with it: the crash is recorded, the next request loads a passive core only, and an admin notice reports the file, line and message with a button to clear it. Scanning and admin screens stay off until you do, because a security plugin should never quietly appear to be working when it is not. Crashes in other plugins are never claimed as ours. A missing class file no longer causes a fatal either.

= 1.4.11 =
Two fixes found by reading a real scan report. Cron findings no longer tell you to delete WordPress core scheduled events - that would have stopped update checks without removing anything. And a scheduled job whose handler exists only in eval()'d code is now its own high-severity finding rather than being filed as an ordinary resolution failure, because a handler with no file behind it is how persistence survives a file scan. Also adds a setting for plugins you wrote yourself: they stop being reported as lacking a wordpress.org baseline, and are fingerprinted instead so a change without a version bump is reported.

= 1.4.10 =
Detects the account factory: WordPress settings that let an attacker keep creating accounts without leaving a single file behind. Covers a new-user default role raised to administrator, open registration being switched on when it was off, and roles quietly granted capabilities they do not ship with - the last of which makes the Users screen look perfectly normal. Also records these changes as they happen, so the timeline shows when it was done and who was signed in. Built from an operator report of new accounts appearing while registration was switched off.

= 1.4.9 =
Documentation. The forward notes in the upgrade guide were describing releases that had already shipped; they now cover what is actually next - scanner restructuring, internationalisation, and the remaining EDR phases - plus the decisions still open around geolocation, session fingerprinting and deception, and why the features depending on them stay dormant. No code changed.

= 1.4.8 =
Performance and architecture. Classes are now autoloaded, so an ordinary front-end page view parses about 36 KB of this plugin instead of the entire codebase - roughly 96 percent less work on every request an anonymous visitor makes, which matters most on shared hosting without OPcache. No detection logic changed. The bundled documentation has also been brought up to date, having described an older version of the plugin for several releases.

= 1.4.7 =
First behavioural release. The plugin now watches what happens on the site rather than only what is left on disk: sign-ins, failed sign-ins, account creation, role elevation, plugin activation and installation, theme switches, uploads, and visits to sensitive admin screens. Related activity is grouped into incidents by who did it and when, each carrying a cumulative risk score - so a sign-in followed by the user editor and a new administrator account reads as one high-risk incident rather than three unrelated log lines. An Incidents card in the Events tab shows the sequence. Behavioural findings are observations: nothing is ever removed automatically on the strength of them.

= 1.4.6 =
Tamper protection. Installs a small must-use plugin that keeps WP Perf Shield running: if something removes it from the active plugin list - a backdoor writing straight to the database, for instance - the guard restores it and records the attempt in the tamper-evident log. Must-use plugins load before regular plugins and cannot be deactivated from the dashboard, so the usual ways of disabling a security plugin do not reach them. Deactivating from the Plugins screen still works normally: the guard only restores when the plugin was not turned off deliberately, and that consent is cryptographically signed so it cannot be forged from the database alone.

= 1.4.5 =
Detects cloaked content injectors: malware that hides from logged-in administrators and from search-engine and SEO crawlers while serving injected content to ordinary visitors, so neither you nor an external scanner sees anything wrong. Also defeats identifier-splitting evasion - source is now normalised before matching, so indicators written as glued fragments are found again, which restores every existing detection against that technique. Built from a live sample that passed all sixteen previous checks despite its indicators already being catalogued.

= 1.4.4 =
Detection release built from four live samples. Adds detection of file-operation web shells - shells that contain no eval, no shell_exec and no encoded payload, and instead browse, write, delete and accept uploads directly from request parameters, which made them invisible to execution-focused scanning. Also adds detection of php.ini and .user.ini files that switch PHP hardening back off (disable_functions cleared, open_basedir removed, shell execution re-enabled), a technique with no previous coverage.

= 1.4.3 =
Detects packed, control-flow-obfuscated PHP backdoors that carry no matchable strings, and payloads hidden in directory index.php stubs. Built from a live sample that defeated every existing detector: a genuine GPL plugin used as camouflage with a 19 KB obfuscated loader in its root index.php. Packed loaders in stub position are removed to quarantine; elsewhere they are reported for review, since some commercial plugins ship obfuscated.

= 1.4.2 =
Adds a Docs tab: the readme, upgrade notes, changelog, and reference document are now readable inside WordPress, rendered from the markdown bundled in the release with no internet connection needed. Parsedown 1.8.0 is vendored under a prefixed class name so it cannot collide with the copy other plugins bundle. Documents are chosen from a fixed whitelist, rendered in markdown safe mode, filtered through the WordPress content sanitiser, and cached; doc files also joined the plugin's self-integrity baseline.

= 1.4.1 =
Doorway-kit resilience release, built from a live sample. Kit detection no longer depends on the kit keeping its original folder name - renaming one directory previously defeated it entirely. Adds detection of the kit's cloaking configuration (the allow/deny lists that decide who is shown spam), which survives any amount of renaming, and detection of browser-based file managers used as web shells, which carry no obfuscation and so slipped past the existing web-shell check. Both new checks are review-only.

= 1.4.0 =
Hardening completion release. Destructive actions are rate-limited per user (30s for heavyweight irreversibles, 10s per-item) with refusals recorded; plugin actions carry enriched audit records (who, what, original value or its quarantine snapshot, new value, reason, risk) in the tamper-evident store; the plugin baselines and verifies its own files every scan, flagging modification, deletion, or planted files inside its folder; and diagnostics exports are signed so tampering is provable. Completes the security audit's high-priority list.

= 1.3.99 =
Platform release: tamper-evident event log. Events now live in a dedicated table carrying the full EDR schema, with every record HMAC-chained to its predecessor and the chain head anchored outside the table, so direct edits, deletions, and truncation of the log are detected and named on the Events tab. The old file log is imported once as pre-chain evidence and kept as the no-database fallback; the log_event API is unchanged. No action needed on upgrade.

= 1.3.98 =
Tier-2 detection release. Removal is now verify-then-report (a target that persists after a claimed removal is flagged as a live re-dropper lead, never as a clean remediation); a unified C2 sweep catches any catalogued campaign domain in PHP content regardless of loader shape (review-only); redirect injections in any theme's functions.php are detected when a redirect primitive pairs with a cloaking or obfuscation tell; and scans run on a 45-second wall-clock budget with skipped checks named honestly instead of dying silently on slow hosts. No schema changes.

= 1.3.97 =
Detection and removal release. Closes six gaps: .htaccess referer/UA-cloaked external redirects (previously no coverage, review-only); consistent executable-extension filtering across every walker so .phtml/.phar/.php3-7/.pht payloads can't slip a literal '.php' test; signature scanning now covers inactive themes, not just plugins; malicious wp_options rows are snapshotted into quarantine before deletion so evidence survives and can be restored; pre-clean backups now go into the protected store instead of sitting infected in the webroot; and the re-drop tripwire now watches the web root, not only wp-content. Quarantine manifests also gained sha256, stored-by user, and detection reason. No schema changes.

The full per-version history lives in `doc/changelog.md`. Entries here are condensed, and closely related older releases are grouped.

= 1.3.96 =
Colour restoration release. 1.3.95's tokenisation altered colour values it should only have routed; this release restores the original 1.3.94 appearance exactly - legacy stylesheet byte-identical, component classes re-pinned to the precise original values (verified 56/56), events zebra striping back, warm-yellow callouts back. Appearance now defaults to Light; the dark scheme is opt-in.

= 1.3.95 =
UI and structure release driven by the workspace design preferences. Complete design-token layer with a dark scheme and a new Appearance setting (Auto / Light / Dark, following the OS when set to Auto). Settings reorganised into four sectioned cards: Detection rules, Remediation, Blocking & uploads, Appearance. 95% of inline styles replaced by tokenised component classes (survivors are sizing and JS state only). All inline onclick handlers and the self-block notice inline script replaced by delegated, CSP-friendly listeners using data attributes. Emoji icons replaced with Dashicons; focus-visible outlines and an aria-live status region added. No detection changes.

= 1.3.94 =
* Quarantine: confirmed threats are now moved to a hardened, non-executable store instead of being destroyed. Restorable for 30 days from the Forensics tab; auto-purged after that. Untick "Quarantine removed threats" in Settings to keep hard deletion.
* Fixed: kits planted at the site root (outside wp-content) were flagged for automatic removal but never actually removed, because the delete routine refused paths outside wp-content. Quarantine handles the site root safely, so root-level kits are now neutralised.
* Forensics tab: new Quarantine card lists every stored entry with Restore and Delete actions, plus Empty quarantine.
* Scanners skip the quarantine store, so neutralised evidence is never re-flagged.

= 1.3.93 =
* Re-dropper hunt. Two more drops of the doorway/backdoor kit (trioxide_c0b61d, moulted_fdd902) confirmed the same kit as pacifiers/donation (identical core.php fingerprint); the 1.3.91 recurrence-awareness counts them as re-drops 3 and 4 and escalates correctly. Since the re-dropper is still live and its likely vectors (system crontab, a dropper outside the WordPress install) are not PHP-readable, added a new Forensics "Re-dropper hunt" card with read-only SSH commands: list user+system cron, isolate cron that runs PHP/curl/wget, search the whole account for the kit and its reused stub files (canaryspillsdinky.php, unmadesuerscorker.php), find kit-shaped directories, grep for the re-dropper script, and list account-wide recently-modified PHP. Indicator lists unchanged (`1.3.81-1`).

= 1.3.92 =
* Log-forensics panel moved toward in-plugin. The plugin already greps every readable log in PHP in the Logs tab (no SSH); the "SSH required" panel overstated it. The attack-window file find (pure filesystem, no logs) is now an in-plugin card, "Recently-modified executable files", listing PHP under plugins/mu-plugins/uploads newest-first. The fallback commands' wp_<hex>_cfg pattern is now sourced from the indicator catalogue instead of a hardcoded list that had drifted six variants behind, and the panel is reworded to point at the Logs tab first and frame SSH as the fallback for logs PHP genuinely cannot read (root-owned /var/log, open_basedir, disabled shell). Indicator lists unchanged (`1.3.81-1`).

= 1.3.91 =
* Doorway-kit re-drop awareness. Two fresh root samples (pacifiers_e83dd2, donation_c9385e) are the same annealing/resweep doorway+backdoor kit re-dropped under different random names. The kit was already detected and auto-deleted at webroot, but it kept reappearing because an external re-dropper re-plants it. check_doorway_backdoor_kit() now fingerprints the kit by its byte-stable core.php and, when it returns under a new name, escalates the finding to "RE-DROPPED Nx - active re-dropper present" and redirects guidance from "delete the directory" to "hunt the dropper" (cron, mu-plugins, wp-config/auto_prepend, co-resident shells). Counting is by distinct name, so a lingering single instance does not inflate it. Indicator lists unchanged (`1.3.81-1`).

= 1.3.90 =
* Supply-chain blind-spot awareness: check_plugin_integrity() now lists the installed plugins it cannot checksum-verify (premium/custom plugins .org has no baseline for) as a single low-severity note, so the gap that the June 2026 ShapedPlugin Pro backdoor exploited is visible rather than silent. Low severity, so it never triggers the critical-only scan email. Also fixed a caching bug where a transient .org failure was negative-cached for a week (and could mislabel a plugin as premium); only a definitive 404/410 is now cached, transient failures retry next scan. Indicator lists unchanged (`1.3.81-1`).

= 1.3.89 =
* Second anticipatory measure: plugin file integrity against wordpress.org. check_plugin_integrity() verifies each installed repo plugin against the official plugin-checksums API and flags PHP files that were modified (injection into a real plugin) or planted (extra PHP not in the distribution) - critical, review-only. Catches what the 1.3.87 new-file tripwire cannot (in-place modifications) and works with no clean baseline. sha256 with md5 fallback, hash-whitelist match-any, non-PHP soft changes ignored, premium/custom plugins skipped, checksums cached a week with per-scan fetch cap. Themes out of scope for now. Indicator lists unchanged (`1.3.81-1`).

= 1.3.88 =
* Validated a new externalized-payload fake plugin (ultra-layout-scanner-15c8, author "Net IO", developer.wordpress.org placeholder, app/class-init.php + storage/config.bin). It is caught critical/auto-delete by the 1.3.83 shape detector with no change required - the technique-level detection generalised to the renamed variant. Also extended check_plugin_metadata_camouflage to flag the developer.wordpress.org/plugins placeholder URI as a backstop (it previously matched only example.*), FP-guarded so a legitimate wordpress.org/plugins/<slug>/ link is never flagged. Indicator lists unchanged (`1.3.81-1`).

= 1.3.87 =
* New anticipatory detector: a PHP-inventory drift tripwire. WP Perf Shield now baselines the PHP files in uploads and mu-plugins and, on every scan, flags any PHP file that appeared (critical) or changed (high) since that baseline  family- and payload-agnostic, so a novel strain dropping code into those directories is caught on first appearance, before it is catalogued. Establishes itself on first scan and only reports drift afterwards; anomalies are surfaced for review, never auto-deleted. A "Reset PHP-inventory baseline" button on the Hardening tab re-captures the clean set after cleanup. Indicator lists unchanged (`1.3.81-1`).

= 1.3.86 =
* Known-bad DB options and malicious cron hooks now auto-clean through the existing auto-remediation toggle, like files and the 1.3.85 base64 options. Previously these highest-confidence items were detect-only and removable only via the manual "Delete malicious DB options" button. Also unified the detection and deletion lists onto WPS_Indicators::malware_option_keys() (the scanner had a stale private copy missing several catalogued _cfg variants). The manual button stays as the off-toggle fallback; the wp-config/wp-login/functions/wp-cron repair buttons are unchanged. Indicator lists not edited (`1.3.81-1`).

= 1.3.85 =
* Confirmed base64 payload options (clickfix_js / php_payload) are now handled like every other confirmed artefact. When auto-remediation is enabled (default) the scan auto-cleans them, re-validating each live option before deletion; when it is off, a single "Delete all flagged options" button on the Forensics tab replaces clicking Delete-now dozens of times. One validated delete path across the scanner auto-clean and both buttons; the scan-results dead-end that only pointed to the Forensics tab is gone. Core options are always refused. Indicator lists unchanged (`1.3.81-1`).

= 1.3.84 =
* Bugfix: sequential deletion of suspicious base64-encoded options on the Forensics tab. The first "Delete now" succeeded but discarded the whole cached forensics report, so every subsequent deletion on the same page failed with "not in the current forensics report". The handler now splices only the deleted option out of the cached report instead of discarding it, so batch deletion works and the report stays in sync. Server-side only; safety gates (report membership, core-option refusal) unchanged. Indicator lists unchanged (`1.3.81-1`).

= 1.3.83 =
* Two-threat detection release. Adds `check_external_payload_loader()` for a new ClickFix delivery shape (a thin obfuscated loader that reads + decodes a bundled non-PHP payload blob, e.g. page-image-scanner / storage/state.pkg -> critical/auto-delete), and, by request, brings a co-residing non-ClickFix backdoor family into scope: `check_doorway_backdoor_kit()` detects and removes the annealing/resweep doorway-spam + backdoor panel kit by its `core/` structural tells (misspelled `backdor`, hex-suffixed panel_/filemanager_ files, ipManager/linkManager/settingsManager modules), with a protected-path removal guard. Both verified against the malware and against legitimate plugins (including a gzinflate-of-data plugin). Indicator lists unchanged (`1.3.81-1`).

= 1.3.82 =
* Persistence-layer detection release. Closes a renamed-copy gap: the `rest-api-compat` kit (an obfuscated MU-plugin RAT plus `db.php`/`advanced-cache.php` re-droppers, renamed off the `session-manager` lineage) was only flagged review-only by 1.3.81. Adds a structural re-dropper branch to `check_wp_content_dropins()` (decode + payload-write + `mu-plugins` target -> critical/auto-delete) and a structural obfuscation branch to `check_mu_plugins()` (rolling-XOR deobfuscation-guard shape -> critical/auto-delete), both with false-positive guards and both verified against the malware kit and legitimate drop-in/MU fixtures. Indicator lists unchanged (`1.3.81-1`).

= 1.3.81 =
* Branch-reconciliation release. Merges two divergent `1.3.79` detection branches onto the `1.3.80` safety base. Adds structural admin-cookie-stealer detection (`check_admin_cookie_stealer`, closing the renamed `.wp-config-cache.php` gap) and theme-modifying loader-plugin detection (`check_theme_loader_plugin`, the `Plugin-<hex>` / css.js family) from the parallel branch, alongside the existing RC4 JS-injector detection and every `1.3.80` safety guard. Catalogue: two new ClickFix option keys (`wp_1f20bc3f7f_cfg`, `wp_8447aa87d2_cfg`) and two new shell-company authors (`Cache Solutions`, `WP Solutions`). Indicator version `1.3.81-1`.

= 1.3.80 =
* Safety release for auto-delete and remediation guardrails. Removes broad `addons`/`scr` plugin-folder substring deletion, skips harmless uploads `index.php` stubs, auto-deletes uploads PHP only when a known malware signature is confirmed, blocks generic deletion of active-theme critical files, fixes css.js severity/delete threshold handling, versions core-checksum cache keys by WordPress version and locale, restricts log viewing to log-like files, and creates timestamped backups before core/theme cleaner writes. Indicator version remains `1.3.79-1`.

= 1.3.79 =
* Structural detection for the obfuscated JS injector / theme-css.js dropper family. Scores plugin PHP droppers and planted theme `css.js` payloads by co-occurring structural signals; critical matches can be auto-deleted while lower-confidence matches require review. Indicator version `1.3.79-1`.

= 1.3.78 =
* Structural detection of the XOR+base64 ClickFix loader, from a live sample (rembat.my). `check_obfuscated_loader()` matches the loader by code shape rather than variable names, then base64-decodes and XOR-brute-forces the blob to recover the payload, key, contract, and chain RPC hosts. Proof-by-recovery is critical; structure-only is high. Does not auto-delete (the block may sit inside a legitimate file). Polygon EtherHiding hosts added to `etherhiding_indicators()` and `eth_call` matched regardless of quote style. Indicator version `1.3.78-1`.

= 1.3.77 =
* Bug fix: the wp-config.php hardening toggles (`DISALLOW_FILE_MODS`, `DISALLOW_FILE_EDIT`, `FORCE_SSL_ADMIN`) always reported "not in the allowed list" because the constant name was lowercased before the allowlist check; fixed with `strtoupper()`.

= 1.3.76 =
* Opt-in Content-Security-Policy (`WPS_Csp`), off by default and report-only first. `connect-src` can block the injected ClickFix script from reaching its C2 or on-chain stage; `object-src`/`base-uri`/`frame-ancestors` add low-risk hardening. Three modes (Off / Report-only / Enforce), front-end only, with a hardened public report endpoint and a report viewer in the Hardening tab.

= 1.3.75 =
* Research-driven detection trio (from public GoDaddy / Silent Push reporting): EtherHiding detection for option payloads that fetch their next stage from a Binance Smart Chain contract via `eth_call`; an example.com placeholder-URI camouflage check for fake plugins; and an automated-login signature in the Logs tab that flags IPs posting to wp-login.php with no preceding page load. Indicator version `1.3.75-1`.

= 1.3.74 =
* New `check_writable_dirs_for_php()` flags PHP staged in writable WP-managed directories (wp-content/fonts/, upgrade/, upgrade-temp-backup/), a predicted next staging spot. Signature matches auto-delete; other PHP gets a delete button. Residual gap stated openly: PHP injected inside a legitimate plugin/theme folder still needs per-plugin manifests.

= 1.3.73 =
* New read-only Logs tab surfacing server access/error and debug logs in the admin, with one-click "Scan all logs for campaign indicators" (C2 hosts, the static campaign token, and delivery fingerprints) plus per-log tail and IOC scan.

= 1.3.72 =
* A second clipboard-PowerShell sample (downloading from comicstar.lat) decrypted and verified, confirming a static 64-hex campaign token that survives host and victim rotation; the token and the new C2 host were added to the indicators.

= 1.3.71 =
* Temporal drop-in integrity guard (`WPS_Dropin_Guard`) that baselines the wp-content drop-ins (db.php, object-cache.php, advanced-cache.php, and the rest) and reports any created, modified, or removed since baseline, catching a self-healing drop-in backdoor.

= 1.3.70 =
* "Delete this path" now works on directory findings; `delete_file()` deletes a directory recursively (CHILD_FIRST), reusing the plugin-folder deletion pattern. The single-file path is unchanged.

= 1.3.69 =
* Built on 1.3.68; adds a tenth ClickFix family entry, fixes a heuristic evasion gap, and adds a server-side C2-in-options recovery signal (`check_clickfix_c2_in_options()`).

= 1.3.68 =
* IoC catalogue: added the pro-cache-scanner ClickFix family at every layer (slug, suffix patterns, hashes, ZIP content signature, persistence option key, shell-author list) and closed pre-existing signature-layer gaps for the Auto Content Profiler family.

= 1.3.57 - 1.3.67 =
* Detection, remediation, and UI hardening between formal audit cycles: 1.3.57 first formal security audit; 1.3.58 structural shape heuristic for fake-plugin ClickFix variants; 1.3.59 RAT hash (defence-in-depth); 1.3.60 documentation-only redaction; 1.3.61 inline "Delete this path" button, later fixed in 1.3.65 (a malformed onclick attribute had left it inert); 1.3.62 selective uptake of a third-party code review with JS-escaping fixes; 1.3.63 - 1.3.64 admin header pill redesign (rendered correctly only after the 1.3.64 CSS fix) plus the "Forensic WordPress malware defence" tagline; 1.3.66 tab regrouping into action / observability / configuration bands with hover and active styling; 1.3.67 surgical "Clean injection" buttons for the auto_prepend_file hijack chain (wordfence-waf.php and .user.ini).

= 1.3.1 - 1.3.56 =
* Earlier 1.3.x releases: incremental IoC catalogue growth, scanner and forensics coverage, remediation and hardening actions, hostile-IP blocking, structured logging, and admin-UI improvements. See `doc/changelog.md` for the complete per-version detail.

== Upgrade Notice ==

= 1.4.30 =
Appearance only. Completes the Settings screen fixes from 1.4.28, including dark-mode label colours. No functional or detection changes.

= 1.4.29 =
Important if you scan often: duplicate diagnostic entries were consuming the event log and could push real security events out of retention. Recommended for everyone.

= 1.4.28 =
Settings screen layout and dark-mode fixes, plus a correction where the Akismet reporting checkbox displayed the wrong state and could be switched off by accident when saving. Recommended if you are on 1.4.27.

= 1.4.27 =
Akismet attacker-reporting is now on by default, with a guard that avoids reporting CDN/proxy addresses automatically, plus a manual report button per blocked address. You can turn automatic reporting off in Settings.

= 1.4.26 =
Stronger login blocking: local evidence outranks Akismet, repeat offenders face escalating blocks, and many-username attacks get a full-day block. Optional opt-in reporting of confirmed attackers to Akismet. Your own address is still protected and the gentle path for a mistyped password is unchanged.

= 1.4.25 =
Important detection update. Closes an evasion where hex-escaped strings bypassed every content signature, and adds detection for search-engine cloaking and control-flow-flattened PHP. Recommended for everyone.

= 1.4.24 =
Readability rebuild of the server log inspection screen, plus a warning on log files large enough that scanning them may time out. No detection changes.

= 1.4.23 =
Blocks attackers who rotate across an address range to stay under the per-address limit. Your own range is protected. Turn it off in Settings if your visitors share one network.

= 1.4.22 =
Cosmetic: timezone column headings now match WordPress's own wording. Safe to skip if you are on 1.4.21 and unbothered by it.

= 1.4.21 =
Timestamps now respect your site timezone instead of showing UTC. Events table readability fixes. No detection changes.

= 1.4.20 =
Adds an Akismet API usage panel. No behaviour changes to login protection or detection.

= 1.4.19 =
Documentation only. No code changes, no behaviour changes. Safe to skip if you are on 1.4.18.

= 1.4.18 =
Adds visibility for the login protection added in 1.4.17: activity counts in Diagnostics, an Akismet connection test in Settings, and block records that say which logic set their duration.

= 1.4.17 =
Adds login protection against automated credential guessing. On by default; your own address is protected and every block expires. Akismet, if active, is used to set block duration automatically.

= 1.4.16 =
Rebuilt security events tables: severity is now visible at a glance, and event names read as English. No detection changes.

= 1.4.15 =
Removes the must-use tamper guard, which caused two outages. Upgrading deletes it from mu-plugins automatically. Recommended for everyone on 1.4.6 or later.

= 1.4.14 =
Completes the 1.4.13 guard fix; a worst-case measurement showed the spool could still grow unbounded. Recommended for everyone on 1.4.6 or later.

= 1.4.13 =
Important fix: the must-use guard could grow an unbounded event spool and white-screen the site when it was imported. Upgrade recommended for everyone. Existing installs regenerate the fixed guard automatically.

= 1.4.12 =
Adds a fail-safe bootstrap so a plugin fatal cannot white-screen your site, and reports the error instead. Recommended for everyone. Upload and activate as usual.

= 1.4.11 =
Fixes cron findings that advised deleting WordPress core scheduled events, and adds high-severity detection for cron handlers that exist only in eval()'d code. Upload and activate as usual.

= 1.4.10 =
Adds detection for registration and role settings that let attackers create accounts with no file left behind. Findings are review-only; no settings are changed for you. Upload and activate as usual.

= 1.4.9 =
Documentation-only release; no code or detection changes. Upload and activate as usual.

= 1.4.8 =
Performance release: classes are autoloaded, cutting per-request PHP loading by about 96 percent on front-end pages. No detection changes. Upload and activate as usual.

= 1.4.7 =
Adds behavioural monitoring: session timelines, incident grouping, and risk scoring. No configuration needed. Upload and activate as usual.

= 1.4.6 =
Adds tamper protection via a must-use guard that restores the plugin if something disables it. Deactivating from the Plugins screen works as normal. Upload and activate as usual.

= 1.4.5 =
Adds cloaked-injector detection and defeats identifier-splitting evasion across all content matching. Indicator version moves to 1.4.5-1. Upload and activate as usual.

= 1.4.4 =
Adds file-operation web shell detection and PHP configuration override detection. Upload and activate as usual.

= 1.4.3 =
New detection for obfuscated PHP packers and backdoors hidden in index.php placeholder files. Upload and activate as usual.

= 1.4.2 =
New Docs tab for reading the bundled documentation inside the admin. No schema changes; upload and activate as usual.

= 1.4.1 =
Stronger doorway-kit detection: no longer defeated by renaming the kit folder, plus new cloaking-config and file-manager web-shell checks. Indicator version moves to 1.4.1-1. Upload and activate as usual.

= 1.4.0 =
Rate limiting on destructive actions, enriched audit records, plugin self-integrity verification, and signed exports. Repeating the same destructive action now has a short cooldown. Upload and activate as usual.

= 1.3.99 =
The event log becomes a tamper-evident, HMAC-chained store with a verification banner on the Events tab. Existing entries are imported as pre-chain evidence. Upload and activate as usual.

= 1.3.98 =
Detection improvements: verified removals, unified C2 domain sweep, theme functions.php redirect-injection detection, and a scan time budget for constrained hosts. No schema changes; upload and activate as usual.

= 1.3.97 =
Detection and removal improvements: cloaked .htaccess redirects, .phtml/.phar coverage across all walkers, inactive-theme scanning, evidence-preserving option deletion, safer pre-clean backups, and web-root re-drop detection. No schema changes; upload and activate as usual.

= 1.3.96 =
Restores the original 1.3.94 colours exactly; Appearance now defaults to Light with dark opt-in. No detection or data changes.

= 1.3.95 =
UI release: new Appearance colour-scheme setting (Auto/Light/Dark), sectioned Settings cards, tokenised styling with dark-mode support. No detection or data changes.

= 1.3.94 =

Removal is now reversible: threats are quarantined (neutralised, restorable for 30 days) instead of destroyed, and root-level kits that previously escaped deletion are now actually removed. Recommended for all users.

= 1.3.93 =

Adds a Re-dropper hunt card to Forensics for kits that keep reappearing (system cron and off-webroot dropper search, which PHP cannot do itself). Recommended if you see RE-DROPPED findings.

= 1.3.92 =

The attack-window file query now runs inside the plugin, and the SSH log panel is honest about what actually needs SSH (and keeps its patterns current from the catalogue). Recommended.

= 1.3.91 =

Makes the doorway/backdoor kit recurrence-aware: re-drops under new random names are flagged as active re-infection with guidance to hunt the dropper. Recommended if a kit keeps reappearing.

= 1.3.90 =

Makes the premium-plugin integrity blind spot visible (low-severity awareness note) and fixes a checksum-cache bug around transient network failures. Recommended.

= 1.3.89 =

Adds wordpress.org checksum verification for installed plugins, flagging modified or planted PHP inside legitimate plugins. Strong coverage for injection that has no baseline. Recommended.

= 1.3.88 =

Validates a new externalized-payload variant (already caught) and adds the developer.wordpress.org placeholder URI as a camouflage backstop. Recommended.

= 1.3.87 =

Adds a baseline drift tripwire for uploads and mu-plugins that catches new or changed PHP files by deviation, regardless of payload. Strong early warning for novel strains. Recommended.

= 1.3.86 =

Known-bad DB options and malicious cron hooks now auto-clean with auto-remediation on, and detection no longer uses a stale option list that missed several variants. Recommended.

= 1.3.85 =

Confirmed base64 payload options now auto-clean when auto-remediation is on, and a "Delete all" button handles manual mode in one click instead of one-by-one. Recommended.

= 1.3.84 =

Bugfix. Lets you delete more than one flagged base64 option per page on the Forensics tab without re-running forensics between each. Recommended.

= 1.3.83 =

Detection update. Catches a new externalized-payload ClickFix variant and adds detection + removal for a co-residing doorway-spam / backdoor panel kit. Recommended.

= 1.3.82 =

Detection update. Catches a renamed persistence kit (obfuscated MU-plugin RAT with drop-in re-droppers) that earlier versions only flagged for review. Recommended.

= 1.3.81 =

Reconciliation update. Combines both 1.3.79 detection lineages (admin-cookie-stealer and theme-loader, plus the RC4 JS-injector) on top of the 1.3.80 safety guards. Recommended for anyone running either 1.3.79 build or 1.3.80.

= 1.3.80 =

Recommended safety update. Narrows automatic deletion to confirmed malware evidence and adds stronger file-write backups and deletion guards.

= 1.3.37 =

Recommended update. Adds confirmed advanced-asset-insights render-hijacker detection and cleanup coverage.

= 1.3.36 =

Recommended update. Adds generic ABSPATH scanning and detection for standalone wp-default.php webshells.

= 1.3.35 =

Recommended update. Reorganises admin tabs so destructive actions live directly with their corresponding data.

= 1.3.34 =

Recommended update. Adds detection for auto_prepend_file persistence patterns in .user.ini, .htaccess, and core files.

= 1.3.33 =

Recommended update. Adds detection for cookie-exfil toolkits and related ClickFix RAT rebuilds.

= 1.3.32 =

Recommended update. Adds a self-block recovery banner to prevent administrators from locking themselves out.

= 1.3.31 =

Recommended update. Centralises malware indicators and adds a redacted diagnostics export tool for support.

= 1.3.30 =

Recommended update. Splits the admin tab UI into discrete renderer classes for better maintainability.

= 1.3.29 =

Recommended update. Extracts all remediation handlers into a unified controller and slims the bootstrap file.

= 1.3.28 =

Recommended update. Adds tighter capability checks, path-containment validation, and pre-edit sanity checks for destructive actions.
= 1.3.27 =

Recommended update. Adds a Diagnostics Source Trace timeline for correlating upload attempts, file timestamps, database persistence findings, active hostile IPs, and SSH grep follow-up.

= 1.3.26 =

Recommended update. Adds confirmed site-speed-insights render-hijacker detection and wp-locale-handler language-directory RAT detection/removal.

= 1.3.25 =

Recommended update. Fixes a false positive that could label a legitimate long-standing admin account as a known attacker.

= 1.3.24 =

Recommended update. Fixes hardening actions that appeared to do nothing after confirmation.

= 1.3.23 =

Recommended update. Improves the Overview findings layout so scan results render cleanly.

= 1.3.22 =

Recommended update. Fixes .htaccess hardening Remove actions that could still display as Applied.

= 1.3.21 =

Recommended update. Fixes WP Perf Shield update ZIPs being blocked by the plugin's own indicator database.

= 1.3.20 =

Recommended update. Adds confirmed total-render-toolkit and pro-font-optimizer indicators, upload blocking, cleanup, and tracing coverage.

= 1.3.19 =

Recommended update. Blocks renamed malware ZIP uploads by inspecting ZIP contents, not just the outer filename.

= 1.3.18 =

Recommended update. Fixes Forensics delete buttons and clears stale database-anomaly rows after option cleanup.

= 1.3.17 =

Recommended update. Adds confirmed native-render-toolkit and total-render-profiler malware indicators, database-option cleanup, and broader source tracing.

= 1.3.16 =

Recommended update. Improves Hardening tab action feedback and spacing for a cleaner admin UI.

= 1.3.15 =

Recommended update. Adds targeted wp-config.php malware cleanup with backup, audit logging, and baseline reset after successful cleaning.

= 1.3.14 =

Recommended update. Reorganizes the admin tabs around the incident-response workflow and moves hostile-IP diagnostics out of Settings.

= 1.3.13 =

Recommended update. Adds upload-pathway tracing and a strict ZIP upload pathway guard to identify and close the route used by hostile upload attempts.

= 1.3.12 =

Recommended update. Adds an Analytics tab for tracking attacks, clearances, hostile IPs, scan outcomes, and diagnostics from the retained event log.

= 1.3.11 =

Recommended update. Turns confirmed malware upload attempts into temporary IP blocks with visible tracking in Settings.

= 1.3.10 =

Recommended update. Fixes wp-cron.php integrity status for current WordPress versions by using official WordPress checksums.

= 1.3.9 =

Recommended update. Adds explicit control and clearer logging for automatic deletion of confirmed malware artifacts.

= 1.3.8 =

Recommended update. Adds runtime readiness checks and creates a wp-cron.php backup before replacement.

= 1.3.7 =

Recommended update. Fixes one-click wp-cron.php replacement for valid WordPress source downloads.

= 1.3.6 =

Documentation layout update. WordPress readme.txt remains at root; project Markdown files now live under doc/.

= 1.3.5 =

Recommended update. Stores WP Perf Shield event logs inside the plugin folder and migrates the old wp-content log on first run.

= 1.3.4 =

Recommended update. Moves the admin UI CSS and JavaScript into enqueued asset files and cleans visible status text.

= 1.3.3 =

Recommended update. Adds sample-derived wp-perf-analytics hashes and detects self-healing wp-content drop-in persistence loaders.

= 1.3.2 =

Release package refreshed for version 1.3.2.

= 1.3.1 =

Recommended update. Improves logging safety, deletion boundary checks, custom indicator validation, multisite blocking coverage, and the admin user experience.
