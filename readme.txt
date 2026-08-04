=== WP Perf Shield ===
Contributors: menj
Author URI: https://github.com/menj
Tags: security, malware, scanner, hardening, remediation
Requires at least: 5.8
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 1.4.73
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Blocks wp-perf-analytics traffic-hijacking malware and renamed variants with activation blocking, scheduled scanning, forensics, hardening, and remediation tools.

== Description ==

WP Perf Shield is a focused WordPress security plugin built to detect and disrupt the wp-perf-analytics / session-manager malware family and related ClickFix render-hijacker variants such as native-render-toolkit, total-render-profiler, total-render-toolkit, pro-font-optimizer, site-speed-insights, advanced-asset-insights, page-seo-toolkit, starter-image-guard, auto-content-profiler, pro-cache-scanner, and total-database-optimizer.

It has grown well past that starting point. Detection now covers doorway kits, obfuscated packers, file-operation web shells that contain no executable code at all, PHP configuration files that switch hardening back off, and cloaked injectors that hide from administrators and crawlers alike while serving content to ordinary visitors. Source is normalised before matching, so malware that splits its identifiers across concatenated fragments to defeat scanners is caught anyway.

Beyond scanning, the plugin records what happens on the site - sign-ins, account creation, role elevation, plugin and theme activity, uploads - grouping related activity into incidents with a cumulative risk score.

It combines real-time plugin activation blocking, hourly malware scanning, behavioural monitoring, a tamper-evident event log, one-click remediation actions, forensic reporting, and hardening helpers for common post-compromise cleanup tasks.

= Key features =

* Blocks known malicious plugin slugs and renamed plugin patterns from activation.
* Enforces a site-policy banned-plugins list, separate from malware blocking, for ordinary plugins you choose not to run (WP File Manager and FileBird by default): refused on upload and activation, and deactivated if already present.
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
* Protects sign-in against brute-force and low-and-slow subnet rotation: per-address and per-range thresholds with escalating repeat-offender blocks, permanent bans for attempts on non-existent accounts, a manual permanent range ban, XML-RPC multicall stripping, and optional Akismet reputation input and reporting — all without ever making the sign-in path wait on the network.
* Detects file-operation web shells by capability cluster - browsing, writing, deleting and uploading driven by raw request parameters - which contain no eval or shell_exec and so evade execution-focused scanning.
* Detects php.ini and .user.ini files that re-enable shell execution or remove open_basedir and disable_functions restrictions.
* Detects cloaked injectors that serve content to visitors while hiding from logged-in administrators and from search-engine, SEO and page-speed crawlers.
* Normalises split-literal obfuscation before matching, so identifiers written as glued fragments are found and every existing indicator keeps working.
* Blocks outbound requests carrying WordPress session cookies to external hosts, and quarantines the files responsible.
* Optionally blocks external post creation, editing and deletion through the REST API and XML-RPC (the auto-blogging and doorway-spam injection route), allowing only genuine dashboard publishing; off by default.
* Records behaviour and groups related activity into incidents with cumulative risk scoring.
* Renders its own documentation inside wp-admin.
* Autoloads its classes, so an ordinary front-end page view parses a fraction of the codebase.
* Includes a Diagnostics tab for attack attempts, hostile IPs, clearances, scan outcomes, Source Trace timeline, and operational status.
* Records upload-pathway diagnostics and restricts ZIP uploads to trusted administrator upload routes.


Detection is described by technique rather than by malware name, because names change on every build and techniques do not: obfuscated and self-extracting payloads, identifiers spelled character by character to keep them out of the file, unauthenticated file managers, executable PHP in directories that should hold only data, configuration dropped to weaken the server, and credentials or session cookies being sent off-site. That last one is also blocked at runtime, before the request leaves.

Findings from a kit that plants the same file in many directories collapse into one entry listing every location, so an intrusion reads as one problem rather than a dozen.
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

= 1.4.73 =
Adds detection of injected casino/gambling/SEO-spam content in posts and comments - the content side of an auto-blogging/injection compromise, which the file and option checks miss. A shared signature matcher flags SEO-spam tokens (slot gacor, rtp live, maxwin, togel) outright, and ordinary gambling words only in bulk with hidden markup or a link wall, so it does not flag legitimate writing that mentions gambling. A new scanner check finds spam already published (with sample IDs, detection-only - it never deletes), and a real-time save_post hook flags new injections whatever the vector. Includes entry-point-first guidance so removing content does not simply invite republication.

= 1.4.72 =
Extends Akismet reputation-weighted block duration to the other guards. A malware-uploading address that Akismet also knows as bad is now held 30 days instead of 7 (a clean answer never shortens it, since a malware upload is already conclusive). A sustained external-post-injection campaign (10+ blocked writes from one address within an hour) escalates from a per-request refusal to a persistent hostile-IP block, 1 day or 7 when known-bad; the high threshold, an infrastructure-address exemption, and the hostile-IP auto-block switch keep it from misfiring. The reputation lookup is shared and cached; enrichment remains a duration input only, never consulted on the request path. Also generalises the blocked-request message so it is accurate for every block reason.

= 1.4.71 =
Extends Akismet reporting to the other conclusive-abuse guards: an address caught uploading malware or injecting posts through the REST API is now reported to Akismet, alongside failed sign-ins, through one shared safeguarded path (never a CDN/proxy address, never a range, once per address). Governed by the existing Report attackers to Akismet switch. Also a full tightening pass across the merged codebase.

= 1.4.70 =
Merges the standalone Block External Posting plugin as a new module: blocks external post creation, editing and deletion through the REST API (/wp/v2/posts) and the post-writing XML-RPC methods unless the request is a genuine administrator dashboard session, which no Application Password, Basic Auth, JWT, OAuth or unauthenticated client can pass. This is the injection route behind auto-blogging and doorway/SEO-spam posts. Adds logging of blocked attempts (throttled per address), which the standalone lacked. Off by default because it breaks headless, mobile-app and Zapier-style publishing; enable under Settings only if nothing legitimately posts from outside the dashboard. Gutenberg, Classic Editor and scheduled posts are unaffected.

= 1.4.69 =
Documentation sync, no code change. Brought doc/readme.md and the readme.txt Description forward to cover the features added since 1.4.61 (banned-plugins denylist, event-chain self-test, subnet-rotation trigger and range escalation ladder, XML-RPC multicall stripping, manual permanent range ban, report-every-blocked-address); their content had drifted while only the version line moved.

= 1.4.68 =
Adds a one-click permanent range ban (Diagnostics) for permanently denying an address or whole subnet, refused if it holds your own or an admin address or is broader than a /16. Also adds a default-on control to report every blocked address to Akismet, not only conclusive ones, and to report the individual attacking members of a blocked range — never a CDN/proxy address and never a whole range, so innocent neighbours are not flagged; each address is reported at most once, and it has an off switch. The posture panel's blocks-by-rule line now attributes single-address blocks so the totals reconcile.

= 1.4.67 =
Repeat attacking ranges now escalate. A rotating /24 was previously held for a flat six hours and could return the moment it lifted; range blocks now climb a repeat-offender ladder (6 hours, 24 hours, 3 days, 7 days) over a 14-day memory, in a store separate from the per-address one, so a persistent subnet locks itself out for longer each time. It caps at seven days — a permanent ban of a whole range stays a manual decision, since a /24 can hold people who are not the attacker — and the allowlist and remembered admin addresses are never blocked. Also fixes the Security posture panel, which showed only range-rotation blocks and hid the hundreds of single-address blocks; the "blocks by rule" line now attributes all four categories so the totals reconcile.

= 1.4.66 =
Closes the XML-RPC credential-amplification vector without breaking normal XML-RPC sign-in. Failed XML-RPC sign-ins were already counted by the login guard and blocked addresses were already rejected on xmlrpc.php, but system.multicall — which lets one request carry many credential guesses — was only removed when XML-RPC sign-in was disabled wholesale (off by default, to protect Jetpack and the mobile apps). Since those clients use direct methods rather than system.multicall, the plugin now strips system.multicall on its own, on by default, closing the vector while leaving Jetpack and the apps working. Switchable under Settings for the rare tool that batches through system.multicall on purpose.

= 1.4.65 =
Stops low-and-slow subnet brute-force. When an attacker rotates a /24 — one failed sign-in every several minutes from a different address each time — no single address reached the per-address threshold, no short window reached the network threshold, and the old tally reset between attempts. The network guard now treats rotation itself as the trigger: five distinct failing addresses in one /24 within a one-hour rolling window blocks the range, whatever the pacing, and holds it for six hours. Every safeguard is intact — a range holding the allowlist or a remembered administrator address is never blocked, and a single address failing repeatedly (a real user mistyping a password) never causes a range block. On-by-default with its existing off switch.

= 1.4.64 =
Adds an in-plugin Event-chain self-test (Diagnostics) that verifies the CRIT-005 concurrency fix against the live database on the host, with no WP-CLI or shell scripts. It runs the real append path over an isolated scratch table that is dropped afterwards (the real chain is never touched, and isolation is asserted), and opens a second database connection to prove the append advisory lock excludes across connections. Reviewed as third-party code before inclusion: no execution or network primitives, the scratch namespace is validated so it cannot inject SQL, and the teardown can only drop a scratch table, never the real one. Run it once on staging after upgrading.

= 1.4.63 =
Fixes CRIT-005: the tamper-evident event log's append was not concurrency-safe, so two simultaneous requests could fork the hash chain and the verifier would report the fork as tampering — a false alarm from ordinary traffic. The append is now serialised with a database advisory lock (with a transaction fallback), and the chain head is read from the table rather than a cached value, which closes the race and self-heals a previously-forked cached head. Preventive, not retroactive: it stops new forks but does not repair a chain already forked before upgrade; re-run chain verification after upgrading. Build-time logic checks pass; real-database concurrency should be verified on staging before production.

= 1.4.62 =
Adds a site-policy plugin denylist, separate from malware blocking, for refusing ordinary plugins an operator does not want running. Two plugins ship banned by default: WP File Manager, which grants full dashboard filesystem access and carries a history of critical remote-code-execution holes, and FileBird. A banned plugin cannot be uploaded or activated while WP Perf Shield is active, and is deactivated if already running. These are recorded as policy decisions, not malware detections, so the tamper-evident event log stays honest, and a policy refusal never adds the uploader's address to the hostile-IP block list. Manage the list, and add your own slugs, under Settings and then Banned plugins; the whole list has an on/off switch and is on by default.

= 1.4.61 =
Adds a remediation roadmap covering the outstanding security-review work, readable in the Docs tab. It states which of the twenty findings are fixed, which remain, what to do next with acceptance criteria, and the conventions and pitfalls someone resuming the work would otherwise have to rediscover. The roadmap is checked against the code by the test suite: anything it claims is fixed must genuinely be present, and anything it lists as outstanding must genuinely still be absent, so the document cannot drift from reality unnoticed. Two overstatements in the 1.4.60 notes are corrected - per-check execution status was added to one function rather than across the scanner, and a misleading message about manual scans is still present. No functional code changed.

= 1.4.60 =
Phase one of an external security review. Fixes a defect that made the WordPress.org plugin-integrity check dead on arrival - it iterated an undefined variable, so a tampered plugin file and a planted backdoor both reported clean. Every result from that check now states whether it actually ran, because a silent failure and a clean result were previously indistinguishable. Stops automatic remediation deleting a file when quarantine fails: a quarantine failure means the machine is misbehaving, not that destroying the file is safe, so the threat is now left in place and reported instead. Adds a proper single-flight lock so scheduled, manual and post-upgrade scans can no longer run simultaneously and remediate each other's findings. Akismet reporting remains enabled by default as intended; an inaccurate comment describing it as opt-in is corrected, and a second Akismet control that was read but could never be set now has a real settings row. Two further critical findings remain outstanding and are next.

= 1.4.59 =
Documentation only; no code changed. A supplied sample confirmed an existing catalogue entry exactly - both fingerprints already held and both matching the file - so the entry is promoted from recorded to verified. Auditing the hash list to check it turned up that 17 of 34 fingerprinted samples carry an MD5 with no SHA-256 companion, and one carries no fingerprint at all. The variant catalogue now publishes exactly where that coverage is thin, generated from the blocking list and checked against it by the test suite. This is a corroboration gap rather than an evasion hole: altering a file changes both hashes, so a single fingerprint is no easier to evade than a pair.

= 1.4.58 =
Adds file fingerprints for the fourth member of the theme-loader JavaScript injector family, supplied after 1.4.57 identified it as documented in code comments but never catalogued. Its size matches the byte count recorded during the original analysis exactly. Three of the four known members are now verified from files in hand. Blocking and detection are unchanged - this family has been blocked by folder shape rather than by name since 1.4.50, and the sample was already blocked at activation and upload before this release.

= 1.4.57 =
Adds fingerprints for a newly supplied sample of the theme-loader JavaScript injector family, and corrects the bundled variant catalogue, which listed two members of that family where the source knew four. The two missing members were recorded in code comments during the original analysis and never reached the catalogue. Blocking was never affected - since 1.4.50 this family is blocked by its folder shape rather than by name, and the new sample was blocked at activation and upload by a plugin that had never seen it. The completeness check that should have caught the documentation gap only read values from indicator lists, so it could not see a sample named in a comment; it now extracts sample identifiers from the source too, and that change was verified by injecting an undocumented identifier and confirming the check fails.

= 1.4.56 =
Identifies the plugin's founding target. Sekoia's analysis of the ErrTraffic malware-as-a-service framework names a Polygon smart contract that WP Perf Shield has carried in its source since the original wp-perf-analytics work - the same address, confirming that the campaign this plugin was written against is a commercially sold framework rather than an anonymous operation. Adds detection for on-chain command-and-control by technique rather than by endpoint list, which matters because one cluster uses per-customer RPC subdomains and per-affiliate contracts that cannot be enumerated in advance. Also fixes a false positive found while testing it: public blockchain RPC hostnames and the eth_call method name were single-match malware signatures, so any legitimate NFT, wallet or web3 plugin would have been reported as malware and offered for deletion. Detection of real samples is unchanged.

= 1.4.55 =
Fixes two security defects found in an external review. Until now, every wp-config.php edit wrote a backup named wp-config.php.wps.bak beside the original - a file the web server hands out as plain text, exposing database credentials and authentication salts to anyone who requested it. Backups now go to quarantine, and the edit is refused rather than performed unsafely if quarantine is unavailable. Because upgrading cannot remove copies already written, a new critical check reports any readable wp-config backup in the web root, including ones left by editors, hosts and other tools. Separately, saving the Settings tab replaced the whole options record and silently reverted Content-Security-Policy to off; it now merges, so settings owned by other tabs survive. If you have used the Hardening tab before, scan after upgrading and treat any reported backup as a disclosed credential.

= 1.4.54 =
Adds a brand mark. WP Perf Shield had no icon of its own, which blocked the technology-profiler submission prepared in 1.4.52 and left the plugin header unadorned. The mark is a shield containing three ascending bars - the shield for the category, the bars for the plugin's origin in performance tooling that malware impersonates. It is a 442-byte SVG using the interface's existing accent colour, drawn and checked at 16 pixels because that is the size directory listings actually render, and asserted free of scripts, event handlers and external references since browsers fetch it from wp-content. It now appears beside the title on the plugin screen. No detection or blocking behaviour changed.

= 1.4.53 =
Completes the blocking coverage for the auto-asset-helper malware variant. Releases 1.4.49 added its name and folder patterns but deliberately left out its file fingerprints, because the sample was not available to hash and a fingerprint written from memory matches nothing while looking like protection. The sample has now been supplied, so the fingerprints are computed from the file and the variant is covered across all five blocking layers. Detection is unchanged - it was already found by six separate checks - and no other behaviour changed.

= 1.4.52 =
Adds an optional way to let technology profilers such as Wappalyzer recognise WP Perf Shield. Until now the plugin was invisible from outside - its admin assets load only on its own screen - so no profiler could detect it. A new setting emits a single generator meta tag on front-end pages. It is off by default and never includes the version number: releases regularly close specific evasion techniques, so publishing which one you run would tell an attacker which bypasses still work against your site. The tag can be removed with remove_action or filtered away. No detection or blocking behaviour changed.

= 1.4.51 =
Adds a malware variant catalogue for analysts and incident responders. Every family WP Perf Shield recognises is now documented in one place - mechanism, indicators, detection, blocking and remediation - readable in the Docs tab alongside the changelog. Completeness is enforced by the test suite rather than by review: every indicator and hash the plugin carries must appear in the catalogue, which on the first run found fourteen undocumented indicators, thirty-three undocumented hashes and two families that existed only as code comments. It also found a blocklist entry 65 characters long where a SHA-256 is 64, meaning it could never match anything; that entry is removed and hash hygiene is now asserted. No detection or blocking behaviour changed.

= 1.4.50 =
Blocks the theme-loader JavaScript injector family at installation. This malware was already detected at critical severity by five separate checks, but nothing stopped it being uploaded or activated first. It is awkward to block because it has no fixed name - it calls itself "Plugin-" followed by eight random hex digits - so WP Perf Shield now blocks the form rather than a name, plus the file hashes and the distinctive heredoc marker it carries. Because a pattern is a wider net than a name, the edges are tested: seven or nine hex digits, non-hex characters, and ordinary slugs such as plugin-directory are all confirmed unaffected. Genuine plugins that ship JavaScript are unaffected.

= 1.4.49 =
Closes a blocking gap on two known malware variants. Both were catalogued in 1.3.79 and both were detected correctly - six separate checks, four critical - but neither slug was ever added to the activation-blocking, upload-blocking or hash lists, so WP Perf Shield would find them after the fact without preventing either being installed. Both are now wired in across all five layers, including the randomised folder-name patterns that match how they actually arrive. Detection is unchanged; what is new is that they are stopped rather than only reported. No hash was added for the variant whose file was not available for verification, and the shell-company author strings were deliberately kept out of the single-match upload blocklist.

= 1.4.48 =
Makes doorway-kit detection survive renaming. An operator sample was detected correctly, then renamed - folder, payload file names, and one marker key inside its configuration - and two of the three detections went silent while the kit carried on working. The individual web shells were still found, but the finding that says "these files are one kit and here is its root" was lost. Kits are now identified by their cloaking configuration's own vocabulary and by the code that reads it, neither of which can be renamed independently. Two false positives in this release's own first draft were caught by measurement and fixed before release: it named the site's web root as a kit, and it reported one intrusion three times over. Added cost was measured and bounded at roughly fifty milliseconds across seven hundred directories.

= 1.4.47 =
Makes scans finish rather than merely stop safely. Six detections were each normalising every file independently - stripping comments and rejoining split strings, both character-level operations costing around fifty milliseconds on a large file. Each file is now processed once per scan and the result shared, cutting a full pass over a four-hundred-kilobyte file from 0.236s to 0.058s. Detection is unchanged and the cached result is verified identical to computing it fresh. If you saw safe mode or partial scans, upgrade and clear safe mode from the admin notice.

= 1.4.46 =
Fixes scans timing out and putting the plugin into safe mode. The scan's internal time budget was a flat 45 seconds, which is longer than the 30 seconds many hosts allow - so on those hosts the scan could never stop itself before PHP killed it, and every scan ended in a fatal. The budget is now worked out from your host's actual limit, leaving headroom to finish the request, and it is checked inside the long-running file checks rather than only between them. If you have been seeing the safe mode notice, this is the fix.

= 1.4.45 =
Documentation presentation. The detection reference is now laid out as tables rather than prose, with the salt-rotation warning set apart as a callout and the lockout escape hatch as a copyable code block. WP Perf Shield is named throughout instead of "the plugin". The bundled renderer was tested for each markdown feature before use rather than assumed. No code changes.

= 1.4.44 =
Documentation. Nine detections added over the previous eleven releases were missing from the reference document entirely; they are now described by technique, along with what clears a file in each case. Also corrects two claims that had been false since 1.4.15: the plugin no longer protects itself with a must-use guard, that feature having been withdrawn after it caused outages, and saying otherwise invited readers to assume a protection they did not have. No code changes.

= 1.4.43 =
Blocks and removes session-cookie theft. Any outbound request carrying WordPress login sessions to an external host is now refused before it is sent, logged, and raised as critical - so theft stops immediately rather than at the next scan. Files found stealing sessions are moved to quarantine automatically, where they stay recoverable for thirty days. Requests to your own site, and to WordPress.org, Akismet and Gravatar, are never affected, and neither is any request that carries no session data. Note the limitation, which is stated in the plugin as well as here: this covers WordPress's own HTTP functions and cannot see raw cURL or socket calls. Neither blocking nor removal invalidates sessions already stolen - only rotating the authentication salts in wp-config.php does that, and the plugin says so at the moment it blocks.

= 1.4.42 =
Groups duplicate findings. Attack kits plant the same file in many directories under random names so that finding one and deleting it changes nothing; the scanner was reporting each copy separately, which buried everything else and never said they were one intrusion. Copies with identical content flagged by the same check now collapse into a single finding listing every location. One file flagged by two different checks still produces two findings, and nothing is dropped - grouping affects how results are shown, not which are found.

= 1.4.41 =
Detects credentials and session cookies being sent off-site. A file recovered from a live installation waited for an administrator to load a page, collected their WordPress session cookies and posted them to an external host - handing over full account access with no password, and leaving nothing for a login guard to see because no login ever failed. It was clean, readable PHP with a proper security guard, so every other check here passed it. The new check requires both halves: an outbound call to a hardcoded host, and session cookies or credentials in what is sent. Ordinary API calls are unaffected. Findings explain that deleting the file is not sufficient - the authentication salts must be rotated to invalidate sessions already taken.

= 1.4.40 =
Adds two detections from a recovered live implant. Function names built with chr() are now caught alongside those spelled out of a string by position - the same evasion through a different mechanism, and one that scored zero on the previous release's measure. And executable PHP is now reported by where it sits: a .php file in the media library, the fonts directory or the upgrade scratch space is wrong before it is read, which catches back doors that stay silent unless a request carries a secret token. Files that are inert by construction are excluded, so security plugins storing logs as guarded .php files are not reported.

= 1.4.39 =
Detects function names assembled one character at a time out of an ordinary-looking sentence. A recovered sample spelled base64_decode and gzuncompress by position out of the string "I could not have a more welcome visitor 64 group of zain bani", built the call as text and ran it - so those names never appear in the file and searching for them finds nothing. Five earlier checks were each blind to it for a different reason. The detection is the construction itself: spelling a name costs one indexing expression per character, twenty-eight of them in the sample, against a worst case of three in any genuine theme or plugin file measured.

= 1.4.38 =
Improves detection of unauthenticated write endpoints. Two gaps are closed: data taken from the raw request body rather than from a query or form field now counts as request input, and a single filesystem write is now enough on its own where previously two were required. Both were found by measuring against a recovered sixty-three file attacker framework, in which a component its own author had named "backdor" used exactly those two properties to pass unnoticed. Findings are still graded - a file manager with six capabilities is reported as critical, a single write endpoint as high - and files that load WordPress, check authorisation, or take no request input are still ignored.

= 1.4.37 =
Detects PHP files that read themselves and execute whatever follows their own closing tag - a way of carrying a payload that is not in any string or variable, and so invisible to checks that look for encoded text. Also repairs a general evasion: PHP allows a comment between a function name and its bracket, so writing eval with comments around it defeated every pattern in this scanner that looked for a function call. Comments are now removed before matching. Note that this detection is rated high rather than critical and asks you to check with your host first, because commercial security products protect their own code the same way and the technique alone cannot tell the two apart.

= 1.4.36 =
Detects obfuscated JavaScript carried inside PHP files. A sample calling itself a "simple js plugin" had entirely clean, readable PHP and a hundred and eleven thousand bytes of obfuscated script in a heredoc, which it printed into every page - invisible to every check here, because they all reason about PHP and the PHP was honest. The detection is the hexadecimal renaming that automated JavaScript obfuscators leave behind: four thousand nine hundred such names in the sample, none at all across eighty-three files of genuine theme and plugin code, including a legitimate eighty-kilobyte minified bundle. Minified code is not flagged; minifiers shorten names rather than renaming everything to hex.

= 1.4.35 =
Detects malware that hides its own function names. A sample styled as an image optimisation plugin - correct header, security guard, uninstall routine - produced no findings at all: its payload lived in a binary file rather than in any PHP, and it skipped administrators and search engines so nobody who might report it ever saw its behaviour. What it could not hide was that every significant name in it was written in fragments joined at runtime, so that searching the file for them finds nothing. Sixteen names were concealed that way in the sample, against zero across seventy-nine files of genuine theme and plugin code.

= 1.4.34 =
Measured against a recovered attacker toolkit of twelve planted directories, the scanner found four. It now finds eleven of the eleven that contain malware, leaving the twelfth - a genuine plugin planted as a decoy - alone. Fixes two mistakes in the previous release: a file was wrongly cleared for requiring wp-load.php, which is what a standalone shell does rather than evidence of legitimacy, and wrongly cleared for containing a session, which a shell uses to remember its own login. Adds detection for payloads hidden behind chains of decoders with their function names split to defeat searching, and for php.ini files dropped to re-enable shell execution and remove the directory restriction your host set - the latter being a third of the kit and invisible to any scanner that reads only PHP.

= 1.4.33 =
Detects unauthenticated file managers - web shells written in plain, readable PHP. Every content check in this plugin until now looked for concealment: encodings, hex escapes, obfuscated control flow. A shell recovered from an infected site used none of those and was completely invisible, because it did not need to hide. This release looks for the thing itself: a file that does not load WordPress, checks no password or capability of any kind, and can still upload, overwrite, rename and delete files on request. Any one of three properties clears a file, so ordinary plugin and theme code stays quiet.

= 1.4.32 =
The Security posture panel now reports permanently blocked addresses, how many have been reported to Akismet as spam, and which rule decided recent blocks. Four counters had been recorded since earlier releases and shown nowhere, and most of them were being discarded at midnight rather than kept for the seven-day figures; both are fixed. Also removes the permanent "Tamper protection - withdrawn in 1.4.15" row, which reported the absence of a feature withdrawn seventeen releases ago and offered nothing to act on. A row now appears only if a leftover file actually needs deleting.

= 1.4.31 =
An address that tries to sign in as an account that does not exist on your site - admin, root, administrator and similar - is now blocked permanently on the first attempt, and reported to Akismet. These blocks prevent signing in only; the site stays readable to that address. They cannot be triggered by any username that actually exists, so your own account can never put your address on the list, and every entry can be removed from Diagnostics if an address is reassigned.

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

= 1.4.47 =
Scans are roughly four times faster, so they complete instead of running out of time. Recommended if you have seen safe mode or partial scan results.

= 1.4.46 =
Important if you have seen the safe mode notice. The scan's time budget exceeded what many hosts allow, so scans could not stop before PHP killed them. Fixed.

= 1.4.45 =
Documentation presentation only. No code changes.

= 1.4.44 =
Documentation only. Adds a full description of what the scanner detects, and corrects a claim about self-protection that had been inaccurate since 1.4.15.

= 1.4.43 =
Blocks outbound requests carrying WordPress session cookies, and quarantines the files responsible. Recommended for everyone.

= 1.4.42 =
Presentation improvement: identical files found in many locations now collapse into one finding listing them all. No detection changes.

= 1.4.41 =
Important. Detects session cookies and credentials being sent to external hosts - a technique that grants full administrator access without any password and defeats login protection entirely. Recommended for everyone.

= 1.4.40 =
Detects executable PHP in directories that should hold only data, and function names built with chr(). Recommended for everyone.

= 1.4.39 =
Detects malware that spells function names character by character to keep them out of the file entirely. Recommended for everyone.

= 1.4.38 =
Detects unauthenticated write endpoints that use the raw request body, or a single write primitive. Measured to add no false positives on ordinary plugin and theme code.

= 1.4.37 =
Detects self-extracting PHP payloads, and closes a general evasion where comments between a function name and its bracket hid calls from every check. Findings of this type ask you to confirm with your host before deleting.

= 1.4.36 =
Detects obfuscated JavaScript hidden inside PHP files and injected into your pages. Minified assets are not affected. Recommended for everyone.

= 1.4.35 =
Detects malware that splits its function names across string joins to defeat scanning - a technique that made a recent sample invisible to every other check. Recommended for everyone.

= 1.4.34 =
Significant detection improvement measured against a real attacker toolkit: coverage went from four of twelve to eleven of eleven. Fixes two exclusions that let shells through. Recommended for everyone.

= 1.4.33 =
Important detection update. Adds detection for plain-text web shells - unauthenticated file managers that earlier obfuscation checks could not see. Recommended for everyone.

= 1.4.32 =
Adds permanent-block and Akismet-report statistics to the Security posture panel, and removes a stale row about a feature withdrawn long ago. No functional changes.

= 1.4.31 =
Bot sign-in attempts on non-existent accounts are now blocked permanently rather than temporarily, and reported to Akismet. Removable from Diagnostics.

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
