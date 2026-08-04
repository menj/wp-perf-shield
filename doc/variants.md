# WP Perf Shield — Malware Variant Catalogue

Reference for analysts and incident responders. Every malware family WP Perf Shield recognises, what it does, how it is identified, and what stops it.

This document exists because the detail was scattered. Indicators lived in `includes/class-wps-indicators.php`, blocking lists in `includes/class-blocker.php`, forensic reasoning in `doc/ssot.md`, and the story of each discovery in `doc/changelog.md`. None of those is a catalogue. This is.

## How to read this

Every family record carries the same fields, and the coverage table means the same thing throughout.

| Field | Meaning |
| --- | --- |
| **Classification** | What the malware is for, not what it is called |
| **Delivery** | How it arrives and what it is named on disk |
| **Mechanism** | What it does once it runs |
| **Indicators** | Strings, keys, paths and hashes that identify it |
| **Detection** | Which WP Perf Shield checks find it |
| **Blocking** | Whether it is stopped before it runs, and by which layer |
| **Remediation** | What removing it actually requires |

### Confidence

Attribution is marked, because a catalogue that does not distinguish what was measured from what was recorded is a catalogue that will eventually mislead somebody.

| Marker | Meaning |
| --- | --- |
| **Verified** | A sample was examined directly and its hashes computed from the file |
| **Catalogued** | Recorded from earlier analysis and carried in the indicator lists; the file was not re-examined for this document |
| **Structural** | No fixed indicator; identified by shape, so no hash exists to quote |

### A note on the blocking columns

Three independent layers can stop a plugin-shaped payload, and they fail in different circumstances:

- **Activation** — the folder or file name matches a slug or pattern, so WordPress refuses to run it.
- **Upload** — the ZIP is rejected. Three nets in sequence: entry name, then the hash of each PHP entry, then a content signature. A renamed folder carrying a modified build still gets caught by the third.
- **Hash** — an exact file fingerprint. The least durable layer, since a single byte defeats it, and the reason none of the others depend on it.

A family marked *detect only* is found by scanning after it is already installed. That is not nothing, but the window between arrival and the next scan is time the payload spends working.

---

## Index

| # | Family | Classification | Coverage |
| --- | --- | --- | --- |
| 1 | [ClickFix render hijacker](#1-clickfix-render-hijacker) | Visitor-facing JavaScript injection | Activation, upload, hash, detect |
| 2 | [Second-stage PHP backdoors](#2-second-stage-php-backdoors) | RCE and credential harvesting | Upload, hash, detect |
| 3 | [RAT family v1.7](#3-rat-family-v17) | Remote access, polymorphic per victim | Upload, hash, detect |
| 4 | [Cookie-exfiltration toolkit](#4-cookie-exfiltration-and-persistent-admin-toolkit) | Session theft and admin persistence | Upload, hash, detect |
| 5 | [Standalone file-manager shells](#5-standalone-file-manager-shells) | Filesystem control | Upload, hash, detect |
| 6 | [Theme-loader JS injector](#6-theme-loader-javascript-injector) | Obfuscated JS written into the theme | Activation, upload, hash, detect |
| 7 | [Doorway and TDS framework](#7-doorway-and-tds-framework) | Traffic distribution and cloaking | Detect |
| 8 | [Japanese SEO doorway cloak](#8-japanese-seo-doorway-cloak) | Search-engine spam | Detect |
| 9 | [Multi-shell attacker toolkit](#9-multi-shell-attacker-toolkit) | Staged intrusion kit | Detect |
| 10 | [EtherHiding loaders](#10-etherhiding-loaders) | Blockchain-hosted payload delivery | Detect |
| 11 | [Persistence implants](#11-persistence-implants) | Survival across cleanup | Detect |
| 12 | [Other tracked slugs](#12-other-tracked-slugs) | Assorted fake plugins | Activation, upload, detect |

---
## 1. ClickFix render hijacker

The family WP Perf Shield was originally written against, and still the largest. Seventeen catalogued members.

**Classification.** Visitor-facing JavaScript injection. The site's own pages are used to serve a lure to ordinary visitors while the owner sees nothing wrong.

**Delivery.** A fake plugin folder, named plausibly and given a random hex or alphanumeric suffix — `wp-perf-analytics-8760`, `pro-cache-scanner-6d52`, `site-security-toolkit-1f30`. The plugin header names an invented vendor ("Cache Software", "Cache Solutions", "WP Solutions") and frequently carries a placeholder `Plugin URI` pointing at `developer.wordpress.org`, which no real published plugin does.

**Mechanism.** The payload is not in the file. The file is a loader: it reads a base64 blob out of a `wp_options` row keyed `wp_<10 hex>_cfg`, XOR-decodes it, and echoes the result into a `<script>` tag hooked on `wp_footer` at a deliberately late priority. Selection decides who sees it — administrators, bots, crawlers and anyone carrying the `_cf_verified` or `_wp_perf_ok` dismissal cookie are skipped. Everyone else gets the lure.

Deleting the plugin file alone is insufficient. The option row survives and re-seeds the payload when the loader returns.

**Naming and evasion history.** Each catalogued member represents a defeated evasion rather than merely a new name: XOR key rotation across builds, variable-concatenation of function names (`auto-content-profiler`, 1.3.58), array-callback arguments that broke a `[^)]+` span in the trait matcher (`total-database-optimizer`, 1.3.69), and character-built identifiers spelled out of a haystack string (1.4.39).

### Known members

| Slug | Sample file | MD5 | First catalogued | Confidence |
| --- | --- | --- | --- | --- |
| `wp-perf-analytics` | XOR 60, v1.2.4 | `75d1b8c91600379dea5791920c192b0c` | 1.2.x | Catalogued |
| `wp-perf-analytics` | XOR 84, v1.2.66 (8760) | `cdec71647d65e4e6542c19848e07e7bd` | 1.2.x | Catalogued |
| `wp-perf-analytics` | XOR 113, v1.2.19 (91c6/9b4c) | `cefca0da4afd2816bfada89236e5011a` | 1.2.x | Catalogued |
| `wp-perf-analytics` | XOR 114, v1.2.97 (d2e9) | `cf0c1086cca734bbb7038f5ad9e907d5` | 1.2.x | Catalogued |
| `wp-perf-analytics` | XOR 237, v1.2.83 | `c1783b8b92b0a53a65f888af75a1d688` | 1.2.x | Catalogued |
| `native-render-toolkit` | `native-render-toolkit-9401.php` | `678899f67c9561f4b88d28952189467c` | 1.3.x | Catalogued |
| `total-render-profiler` | `total-render-profiler-3753.php` | `06b7dc4813bdd9575bab106451b015de` | 1.3.x | Catalogued |
| `total-render-toolkit` | `total-render-toolkit-adae.php` | `0e34f31fac8662886303225484dd648a` | 1.3.x | Catalogued |
| `pro-font-optimizer` | `pro-font-optimizer-c88b.php` | `99c53e189239269f0197802306af236a` | 1.3.x | Catalogued |
| `site-speed-insights` | `site-speed-insights-d6e7.php` | `6f6b4854cb0d71f81796ead56132c89a` | 1.3.x | **Verified** |
| `advanced-asset-insights` | `advanced-asset-insights-ec06.php` | `7dbc51fa960a74a79bd2cb475a2dfd04` | 1.3.37 | Catalogued |
| `page-seo-toolkit` | `page-seo-toolkit-a937.php` | `a23f9c0fb1eb85247d0f4a8264bd9c18` | 1.3.39 | Catalogued |
| `starter-image-guard` | `starter-image-guard-e9a2.php` | `bb398fb4783c7fc3647a633b51811099` | 1.3.39 | Catalogued |
| `auto-content-profiler` | `auto-content-profiler-0b8d.php` | `c87d8c472f827704a2ef6beb997729ff` | 1.3.58 | Catalogued |
| `pro-cache-scanner` | `pro-cache-scanner-6d52.php` | `15e17041c615dc272d5cd5ac3bcd5d6f` | 1.3.68 | Catalogued |
| `total-database-optimizer` | `total-database-optimizer-9a95.php` | `80322b56aaec6af92d392f8daa36aee7` | 1.3.69 | **Verified** |
| `site-security-toolkit` | `site-security-toolkit-1f30.php` | `608576a9322aab3585fe7e7eb109f368` | 1.3.79 | **Verified** |
| `auto-asset-helper` | `auto-asset-helper-2763.php` | `7bbf81ab731b59b3c0fed628c1f3cf3d` | 1.3.79 | **Verified** |
| `wp-performance-analytics` | — | covered by the XOR-build hashes | 1.2.x | Catalogued |
| `wp-perf-monitor` | — | covered by the XOR-build hashes | 1.2.x | Catalogued |
| `wp-site-analytics` | — | covered by the XOR-build hashes | 1.2.x | Catalogued |
| `wp-page-analytics` | — | covered by the XOR-build hashes | 1.2.x | Catalogued |
| `wp-perf-stats` | — | covered by the XOR-build hashes | 1.2.x | Catalogued |

Four members were verified directly for this catalogue. `total-database-optimizer-9a95.php` is 9,808 bytes, SHA-256 `1e599220…6adb3`, class `WP_Manager_abc5`, author "Cache Software", option `wp_d4b340aceb_cfg`. `site-security-toolkit-1f30.php` is 9,674 bytes, SHA-256 `3bb3738a…5ae9`, class `Core_Loader_c8fc`, author "Cache Solutions", option `wp_1f20bc3f7f_cfg`. `auto-asset-helper-2763.php` is 10,739 bytes, SHA-256 `de3bc67f…a451`, class `Res_Helper_ad74`, author "WP Solutions", option `wp_8447aa87d2_cfg`.

`auto-asset-helper` was carried without a hash from 1.4.49 until 1.4.53, because the sample was not available and a hash written from memory silently matches nothing while looking like protection. The operator supplied the file, so the entry is now computed from it rather than remembered.

### Indicators

| Type | Values |
| --- | --- |
| Option keys | `wp_94d4678186_cfg`, `wp_a26c00cc40_cfg`, `wp_0b05838858_cfg`, `wp_e3ef2393dd_cfg`, `wp_204acd2d43_cfg`, `wp_fe99c06901_cfg`, `wp_b6786d21cb_cfg`, `wp_a326b31e44_cfg`, `wp_e07ded4e61_cfg`, `wp_3093c104e2_cfg`, `wp_d4b340aceb_cfg`, `wp_1f20bc3f7f_cfg`, `wp_8447aa87d2_cfg` |
| Option key shape | `wp_<10 hex>_cfg` — matched structurally, so unknown keys are still inspected |
| Dismissal cookies | `_cf_verified`, `cf_verified_token`, `_wp_perf_ok`, `wp_perf_ok` |
| Download C2 | `biletors.cfd`, `comicstar.lat` |
| Campaign token | `8caaf953d89478b8a7191eb32295c117a310b53ac9059d4ad69a1e397ec3b2d4` |
| Shell-company authors | "Cache Software", "Cache Solutions", "WP Solutions" |
| Crawler user agents checked for evasion | `googlebot`, `bingbot`, `bingpreview`, `yandex`, `duckduck`, `slurp`, `facebookexternalhit`, `twitterbot`, `whatsapp`, `telegram`, `semrush`, `ahrefs`, `mj12`, `dotbot`, `lighthouse`, `pagespeed`, `spider`, `crawl` |
| Cache-suppression constants | `DONOTCACHEPAGE`, `DONOTCACHEOBJECT`, `DONOTCACHEDB`, `DONOTMINIFY` — set to guarantee the payload is not cached away |
| Cron hook fragments | `perf_analytics`, `native_render`, `total_render`, `site_speed`, `pro_font`, `font_optimizer`, `wp_perf_ok` |

### Detection and blocking

| Layer | Status |
| --- | --- |
| Activation | Blocked — 18 slugs plus randomised-suffix patterns |
| Upload | Blocked — entry name, hash, and content signature |
| Hash | 17 MD5 and 17 SHA-256 entries |
| Detection | `check_plugin_folders`, `check_php_signatures`, `check_clickfix_shape_heuristic` (6-trait score), `check_plugin_metadata_camouflage`, `check_malicious_db_options`, `check_clickfix_c2_in_options`, `check_obfuscated_loader`, `check_cloaked_injector`, `check_hidden_identifiers`, `check_character_built_identifiers`, `check_split_literal_obfuscation` |

The shape heuristic stands down for any slug already on the blocklist, so a known member is reported by exact identification at critical rather than by inference at high.

**Remediation.** Remove the plugin directory *and* the `wp_<10 hex>_cfg` option row. Removing only the file leaves the payload in the database.

---
## 2. Second-stage PHP backdoors

**Classification.** Remote code execution and credential harvesting. Dropped after initial access, not used to obtain it.

**Delivery.** Single PHP files with maintenance-flavoured names, placed where a plausible file might live. Two build generations are catalogued, the second sharing the family's behaviour with new hashes.

**Mechanism.** Command execution from request parameters, with credential harvesting alongside. The naming is the camouflage: an administrator scanning a file listing reads `wp-backup-verify.php` as something WordPress or a backup plugin left behind.

### Known members

| Filename | Build | MD5 | Confidence |
| --- | --- | --- | --- |
| `wp-backup-verify.php` | v1 | `9c77bbb0998b95f0562800b6086dd11e` | Catalogued |
| `wc-report-handler.php` | v1 | `e76d6d119445032e72e85ad52a6d83ef` | Catalogued |
| `wp-locale-handler.php` | v1 | `d2c9540df466434c7658d7956c5c833d` | Catalogued |
| `wp-backup-verify.php` | v2 | `7d67b8a2edff4735d5dce83b7bfe3eee` | Catalogued |
| `wc-report-handler.php` | v2 | `3013ade690ede0070a4b028bec82bb6b` | Catalogued |
| `wp-locale-handler.php` | 2026-05 variant | `70358bb32a2cf6fcbfc9edfe2848a579` | Catalogued |
| `ms-file-router.php` | "Multisite File Router" | `bede133bf2bd823b6b3c14c19db482ea` | Catalogued |
| `wp-cache-stats.php` | "Cache Statistics Handler" | `d5eae8a8a0b9dc9099a92b5aceae883f` | Catalogued |

**Detection.** `check_root_file_signatures`, `check_generic_webshell_patterns`, `check_languages_for_php`, `check_uploads_for_php`, `check_core_extra_files`.

**Blocking.** Upload and hash. No activation entry, because these are not plugins — they are files dropped into an existing directory, so there is no activation step to intercept.

**Remediation.** Remove the file, then rotate credentials. A harvester that has already run has already sent what it collected.

---

## 3. RAT family v1.7

The most operationally interesting family in this catalogue, because it is built per victim.

**Classification.** Remote access trojan with a credential-harvester payload.

**Delivery.** Two locations are catalogued. `cert-check.php` under `.well-known/pki-validation/` at the web root, and `wp-locale-handler.php` under `wp-content/languages/`.

The `.well-known/` placement is a deliberate choice against defenders rather than against users. Most security tooling excludes that directory to avoid breaking ACME certificate challenges, so a payload parked there is skipped by the scanner rather than cleared by it.

**Mechanism and the polymorphism.** The wrapper is byte-identical across builds. What differs is roughly twelve bytes: the XOR seed in the credential-harvester payload is derived from the victim site's own domain. Each site receives a binary keyed to itself.

That defeats hash-based detection by construction — a new victim means a new hash, with no attacker effort. It is why this family is matched on structure (`a3f8b2c1d4e5f607`, the HMAC tail, and `Ci8v…` encoded harvester strings) rather than on fingerprints, and why the hash entries below are a record of what has been seen rather than a defence.

Two of the builds share a victim domain (`bestofislam.com`) across two different filenames and locations, which confirms one operator reusing a binary rather than separate intrusions.

### Known builds

| Filename | Location | Keyed to | MD5 | First catalogued |
| --- | --- | --- | --- | --- |
| `cert-check.php` | `.well-known/pki-validation/` | themuslimapologist.online | `d75140a8db6edc1147f826b7eec30812` | 1.3.44 |
| `cert-check.php` | `.well-known/pki-validation/` | bestofislam.com | `3e92c07fa807bcc3a1754c9ba3d1c142` | 1.3.45 |
| `cert-check.php` | `.well-known/pki-validation/` | bismikaallahuma.org | `a667e49c601d874cbacc40e158bb56c1` | 1.3.45 |
| `cert-check.php` | `.well-known/pki-validation/` | compelling-evidence.com | `8203c5bb61b21777519bef3af299842d` | 1.3.45 |
| `cert-check.php` | `.well-known/pki-validation/` | muslim-apologetic-borneo.com | `c053446a3916beb41df3e3428c085a3c` | 1.3.59 |
| `wp-locale-handler.php` | `wp-content/languages/` | bestofislam.com | `a4f6a499ea1c34ae15dcf108e0fa197b` | 1.3.49 |
| `wp-locale-handler.php` | `wp-content/languages/` | — | `6c862aabe3680ec9f4b03fbad7313f1a57b1c9d7a6f199f2ab503b28319cafab` (SHA-256) | 1.3.x |

The domains in the "keyed to" column are the maintainer's own properties, recovered from captured builds. They are listed because the keying is the family's defining property and an analyst needs to see it. Anyone republishing this catalogue elsewhere should consider whether naming them is appropriate in that context.

**Detection.** `check_well_known_php` (no IETF protocol using `.well-known` is PHP, so any PHP file there is wrong before it is read), `check_languages_for_php`, `check_root_file_signatures`, `check_generic_webshell_patterns`.

**Blocking.** Upload and hash. Structural signatures carry the detection for unseen builds.

**Remediation.** Remove the file and rotate every credential the site holds. Then look for the dropper: a RAT keyed to your domain was built for you specifically, which implies a delivery mechanism that is still present.

---
## 4. Cookie-exfiltration and persistent-admin toolkit

**Classification.** Session theft and administrator persistence. Shipped as a container, `.wp-config-cache.zip`, though each component also arrives alone.

**Delivery.** Dot-prefixed and cache-flavoured filenames at or near the web root. The leading dot on `.wp-config-cache.php` hides it from ordinary directory listings and from the backup and sync tooling that skips dot-files by default.

**Mechanism.** Three components with three jobs.

`.wp-config-cache.php` is 972 bytes and carries a fake "WordPress Object Cache v2.1" header. It exits if requested directly, requires `ABSPATH`, and registers a shutdown function that waits for a logged-in administrator. On finding one it harvests every `wordpress_*` and `wp-*` cookie and posts them to `webanalytics-cdn.sbs/k` with `blocking=false`, rate-limited to once per administrator per twelve hours by a transient so the traffic stays quiet.

This is complete account takeover with no password, and it is invisible to any login protection because no login ever fails. It accounts for symptoms that otherwise look unexplained: administrator accounts appearing with registration disabled, `wp-config.php` changing, and a tamper-evident log failing chain verification — because the attacker holds a legitimate administrator session and edits the database legitimately.

`wp-security-cache.php` creates the hardcoded administrator `a7f3e9b2c4d1e5f6`. `wp-phpunit.php` is a five-fallback web shell taking base64 commands on `?c=`.

### Known components

| Filename | Role | MD5 | Confidence |
| --- | --- | --- | --- |
| `.wp-config-cache.php` | Cookie exfiltration to `webanalytics-cdn.sbs` | `2d746471df530568e76e280c6dec8c2d` | Catalogued |
| `wp-security-cache.php` | Creates admin `a7f3e9b2c4d1e5f6` | `54b60e56a90d0ed4b8a4de79c0916193` | Catalogued |
| `wp-phpunit.php` | Five-fallback web shell, `?c=<base64>` | `cd35f8c14a03fecba0b72e67804dd337` | Catalogued |

**Indicators.** C2 `webanalytics-cdn.sbs`; hardcoded administrators `a7f3e9b2c4d1e5f6` and `adminbackup561801`; secondary filenames `.wp-config-cache.php`, `wp-security-cache.php`, `wp-phpunit.php`, `wp-default.php`, `cert-check.php`, `tji-site-js.php`, `wp-security-helper.php`; container pattern `wp-config-cache`.

**Detection.** `check_credential_exfiltration` (requires both an outbound call to a hardcoded host *and* genuinely sensitive payload — either half alone does not fire), `check_admin_cookie_stealer`, `check_hidden_admin_users`, `check_exfil_file`, `check_dropper_cache`.

**Blocking.** Upload and hash. Outbound requests carrying session material to a non-allowlisted host are refused at runtime on `pre_http_request`, which closes the common case but not the category — `curl_exec` and raw sockets bypass the WordPress HTTP API entirely.

**Remediation, and the order matters.** Remove the file **first**, then rotate the `wp-config.php` salts. Sessions already stolen stay valid until the salts change, and rotating before removal means the new session is captured too. This is the one instruction in the whole catalogue that fails silently when missed.

---

## 5. Standalone file-manager shells

**Classification.** Full filesystem control through a browser, with no code execution required.

**Delivery.** A single large PHP file, or a genuine GPL file manager copied under an unremarkable name.

**Mechanism.** These are complete, readable applications rather than obfuscated payloads, which is exactly why signature and obfuscation checks missed them for so long. `wp-default.php` runs its own session (`UMSESSID`) with hardcoded credentials `admin`/`adminpass`, scoped to `DOCUMENT_ROOT`.

It also carries a `setmtime` action, present for one reason: forensic-timeline evasion. **When this file or a rename of it is present, treat on-disk modification times across the whole site as untrustworthy.**

| Filename | MD5 | Confidence |
| --- | --- | --- |
| `wp-default.php` | `8a92828554a087c46cc21c87fd1b15d4` | Catalogued |

**Indicators.** Tiny File Manager constants — `FM_ROOT_PATH`, `FM_SELF_URL`, `FM_USE_AUTH`, `FM_READONLY`, `FM_EXCLUDE_ITEMS`, `FM_UPLOAD_EXTENSION`, `FM_SESSION_ID`, `FM_Zipper`. Matched as a cluster, never singly, since operators do legitimately install file managers.

**Detection.** `check_file_manager_shell` (severity driven by location — inside uploads, a kit folder, mu-plugins or the web root it is treated as a shell; elsewhere it is a review item), `check_unauthenticated_file_manager`, `check_file_operation_shell`.

**Blocking.** Upload and hash.

**Remediation.** Remove it, then re-examine any conclusion you drew from file timestamps.

---
## 6. Theme-loader JavaScript injector

**Classification.** Obfuscated JavaScript injection, written into the active theme so it survives removal of the plugin that placed it.

**Delivery.** A plugin folder named `Plugin-` followed by eight hexadecimal digits, regenerated per drop. Header description: `simple js plugin`.

This family has no fixed name, which is the point. `Plugin-7e4eb3ff` and `Plugin-390a770b` are the two catalogued members, and the next one will be neither.

**Mechanism.** The PHP is genuinely clean — correct header, valid `ABSPATH` guard, readable functions, no `eval`, no split literals. It is an envelope. A heredoc terminated `ENDPLUGINJS` holds a single line of roughly 121 KB of `javascript-obfuscator` output, which is written to the active theme directory as `css.js` via `file_put_contents` and injected with a `<script>` tag built from `get_template_directory_uri()`.

Because the PHP reasons about nothing suspicious, every content check that looks for concealment passed it. What identifies it is the JavaScript: `javascript-obfuscator` renames every identifier to a hex token, and the sample carried 4,911 of them against zero across a corpus of real theme and plugin code.

**Line length was considered as a signal and rejected.** The payload is one 111 KB line, which looks damning until you notice that a legitimate minified vendor bundle is one 80 KB line. Minification shortens names; obfuscation renames everything to hex. Measuring the wrong one would flag every minified asset on every site.

### Known members

| Folder | Size | MD5 | First catalogued | Confidence |
| --- | --- | --- | --- | --- |
| `Plugin-7e4eb3ff` | 130,672 bytes | `73f07f1438b9a710b5bf1893186d1e67` | 1.3.79 | **Verified** |
| `Plugin-b45b652c` | 129,503 bytes | `ab86726bb8ed4527cb6ea787f9a12c1a` | 1.3.79 | **Verified** |
| `Plugin-45e0930c` | 127,542 bytes | `748f6d05c328364ebf6a0cec1aec350d` | 1.3.79 | **Verified** |
| `Plugin-390a770b` | 120,983 bytes | not held | 1.4.36 | Catalogued |

SHA-256 for the verified samples: `Plugin-7e4eb3ff` is `eb45ec5c…3e642`, `Plugin-b45b652c` is `ee72a3a0…8d31e`. The latter carries 5,248 hex identifiers in a single 119,998-byte line, and the constant `IB45B652C_PLUGIN_VERSION` — the `IB<8HEX-UPPER>_PLUGIN_VERSION` naming holds across every member.

`Plugin-b45b652c` and `Plugin-45e0930c` were confirmed samples from the original 1.3.79 analysis, recorded in code comments and absent from this catalogue until 1.4.57. Blocking was never affected — the shape pattern covers any member — but the catalogue claimed two members where the source knew four. Both were supplied and hashed in 1.4.57 and 1.4.58, and each matched the byte count recorded during that original analysis exactly.

Three of the four members are now verified. `Plugin-390a770b` is the only one still carried without a fingerprint.

The naming convention is consistent across all four: folder `Plugin-<8 hex>`, description `simple js plugin`, and an internal constant `I<8 HEX UPPERCASE>_PLUGIN_VERSION`. Payload sizes cluster tightly — 118,037 to 121,167 bytes on a single line, 4,911 to 5,248 hex identifiers — which suggests one builder emitting per-victim copies rather than separately authored variants.

**Indicators.** Heredoc terminators `ENDPLUGINJS` and `ENDPLUGINFN`; PHP function fragments `_get_css_js_content`, `_header_has_css_js_script`, `_find_closing_tag_position`, `_get_script_tag`; the literal `get_template_directory_uri() . '/css.js'`; header string `Description: simple js plugin`; payload markers `a0_0x`, `(function(_0x`, `while(!![]){try{`, a bot-exclusion list naming `mj12bot|semrush|facebookexternalhit|facebot|ia_archiver|yandex|phantomjs`, and a WordPress-path exclusion `wp-login\.php|wp-cron\.php|xmlrpc\.php|wp-admin` so admin, cron and XML-RPC requests never receive the payload.

**Detection.** `check_theme_loader_plugin`, `check_obfuscated_js_injector`, `check_obfuscated_js_payload`, `check_php_signatures`, `check_plugin_folders`.

**Blocking.** Activation and upload, by pattern on the `Plugin-<8 hex>` shape — the only entry in WP Perf Shield that blocks a form rather than a string, because there is no string to block. Exactly eight hex digits; `Plugin-scheduler` and `plugin-directory` are unaffected. Plus hash, and `ENDPLUGINJS` as an upload content signature.

`Description: simple js plugin` is deliberately **not** an upload signature. That list rejects on a single match and the phrase is plausible in a real plugin.

**Remediation.** Remove the plugin folder **and** delete `css.js` from the active and parent theme directories. Removing only the plugin leaves the injected script in place and still loading.

---

## 7. Doorway and TDS framework

**Classification.** Traffic distribution with anti-analysis cloaking. Sold as a product — the samples carry their own version numbers.

**Delivery.** A self-contained directory, unpacked anywhere web-reachable, with short entry stubs at the top level that do nothing but `define('IS_INCLUDED', true)` and include the engine. Folder names are random words: `annealing_1af540`, `syringas_b01e44`, `qhwvuag`.

**Mechanism.** A visitor arrives with a query parameter. The engine looks its MD5 up in `urlLinks.json`, geolocates the visitor through `ip-api.com`, tests them against layered allow and deny lists, and either redirects them to the campaign target or serves a 404 fetched from the real site.

The deny lists are the operation's working capital. The `annealing_1af540` sample carried **111,088 blocked IP addresses**, 87 blocked organisations (VPN providers and hosting networks), 569 blocked user agents, and blocked referers including `google.com`. Blocking by ASN, ISP and organisation is anti-analysis: it keeps security vendors, sandboxes and researchers on the clean path while ordinary visitors are redirected.

Alongside the redirector sits a control panel, a 231 KB file manager, and `core/backdor_<12 hex>.php` — misspelled by its own author — which accepts POSTed JSON and appends the `code` field to an included file. That is unauthenticated remote code deployment, in ninety lines.

**Structural components.** `core/core.php` (engine), `core/panel_<hex>.php` (control panel), `core/filemanager_<hex>.php`, `core/backdor_<hex>.php`, `core/include/{login,logs,settings,backdor}.php`, `core/modules/{ipManager,linkManager,settingsManager}.php`, `config/settings.json`, `config/urlLinks.json`, `config/imgLinks.json`, word lists under `core/template/files/`, and a Composer `vendor/` tree carrying genuine GPL libraries.

**Indicators.** Configuration keys `panel_kee`, `black_ip_array`, `black_userag_array`, `black_org_array`, `black_country_array`, `white_list_only_ip`, `white_list_referer`, `url_param_array`; the switch vocabulary the engine reads as literal subscripts (`black_ip`, `black_org`, `black_userag`, `black_referer`, `white_list_only_ip`, `white_list_only_agent`, `white_list_referer`, and the matching list names `whitelist_ip_array`, `whitelist_agent_array`, `whitelist_referer_array`, `black_ip_array`, `black_country_array`, `black_org_array`, `black_userag_array`, `black_referer_array`).

The `ntdnewtds.shop` and `dnsnewtds.shop` hosts are **not** part of this family, despite both being traffic distribution. They belong to the drive-by injector in section 13.

**Verified sample.** `annealing_1af540`, 126 files, kit version `1.10.7`, `config/settings.json` at 2,830,773 bytes.

**Detection.** `check_doorway_backdoor_kit`, `check_doorway_cloak_config`, `check_unauthenticated_file_manager`, `check_file_manager_shell`, `check_file_operation_shell`, `check_doorway_cloaking`.

Identification is deliberately not keyed on the folder or file names. Renaming `core` to `lib`, giving the hex-suffixed files ordinary names, and changing `panel_kee` was measured to silence two of three detections while the kit kept working. The cues now used are the configuration's key vocabulary and the code that reads it, neither of which can be renamed independently of the other.

**Blocking.** Detect only. These kits are not plugins and do not arrive as plugin ZIPs, so there is no activation or upload step to intercept.

**Remediation.** Remove the whole directory, not individual files, then find what planted it. These kits are re-dropped; WP Perf Shield tracks recurrence by fingerprinting the engine and counting distinct folder names seen for the same fingerprint.

---
## 8. Japanese SEO doorway cloak

**Classification.** Search-engine spam. The damage lands in search results rather than on the page, so the owner sees nothing.

**Delivery.** The site's root `index.php` is replaced or prepended to, hijacking every request through WordPress's own `.htaccess` rewrite and `DirectoryIndex`.

**Mechanism.** The user agent is tested against `googlebot|baiduspider|bingbot|google|baidu|aol|bing|yahoo|yandex` and the referer against `google.co.jp|yahoo.co.jp|bing|baidu|google.com`. Crawlers and search-referred visitors are served spam doorway pages under `products/<word>/`, fetched by cURL with the custom user agent `WHR` from a seed host and cached in a random hex directory under `wp-content/`. `error_reporting(0)` and `ini_set('error_log', NULL)` keep it quiet.

Audience selection is inverted from most cloaking here: this one *shows* content to crawlers rather than hiding from them.

**The evasion that mattered.** Every cloaking string was present but hex-escaped — `\x48\x54\x54\x50_USER_AGENT` — and the scanner matched raw bytes, so the entire content-detection layer walked past it. This is why escape resolution now happens in a shared normalisation step before any content matching anywhere in WP Perf Shield.

**Indicators.** Observed seed `jan06.ofu5563ytu/wowmajp`; cache directory `wp-content/<8 hex>/` holding an opaque blob; goto density of 16–18 per KB against zero across clean theme and plugin corpora.

**Detection.** `check_doorway_cloaking` (requires two independent signals, since a crawler list alone is ordinary bot-detection code), `check_control_flow_flattening`, `check_htaccess_redirects`, `check_functions_redirect_injection`, `check_index_stub_anomaly`.

**Blocking.** Detect only — it modifies an existing core file rather than arriving as one.

**Remediation.** Restore `index.php` from a clean WordPress release, remove the cache directory, and check `.htaccess`. Then request re-indexing, because the spam is in the search index rather than on the site.

---

## 9. Multi-shell attacker toolkit

**Classification.** A staged intrusion kit rather than a single payload. Catalogued from a 309-file sample, `qhwvuag`.

**Delivery.** Twelve directories, each a genuine GPL plugin — Protect Uploads by alticreation.com, Simple Maintenance Mode — copied under a random seven-letter name, with the payload dropped in as `index.php`. That filename is chosen because WordPress convention puts a 26-byte "Silence is golden" stub there, so it is the least remarkable name in a plugin folder.

Re-drop persistence is the design: removing one directory achieves nothing.

**Payload families within the kit.** "Dark X7ROOT File Manager" (plain, 21,584 and 10,434 bytes), a layered-decoder loader (19,513 bytes), a 324-byte upload dropper, and a character-built-identifier variant at 19,779 bytes that spells `base64_decode` and `gzuncompress` out of an innocuous sentence by character position.

**The configuration component.** Six identical `php.ini` files and seven `.htaccess` files. The `php.ini` sets `disable_functions = NONE`, `open_basedir = OFF`, `exec = ON`, `shell_exec = ON`. On CGI and FastCGI a per-directory `php.ini` is honoured, so this re-enables precisely the functions a host disables to contain a break-in. It is not a payload — it is what makes the next payload work, and until 1.4.34 the scanner only ever read PHP.

**Detection.** `check_unauthenticated_file_manager`, `check_encoded_payload_loader`, `check_hardening_bypass_config`, `check_php_config_override`, `check_character_built_identifiers`, `check_index_stub_anomaly`, `check_obfuscated_goto_backdoor`.

**Blocking.** Detect only.

**Remediation.** Remove every directory, not the one that was reported, and check for a re-dropper outside them all.

---

## 10. EtherHiding loaders

**Classification.** Payload delivery through public blockchain RPC endpoints, so the C2 has no domain to seize and no host to complain to.

**Mechanism.** The loader calls `eth_call` or `eth_getStorageAt` against a public BSC or Polygon RPC endpoint and reads the next stage out of contract storage. Blocking the endpoint is awkward because the endpoints are legitimate infrastructure with legitimate users.

### ErrTraffic (attributed 1.4.56)

Sekoia TDR published an analysis of a ClickFix distribution framework sold as a service under the name ErrTraffic, operated by a seller using the handle LenAI and advertised on Exploit.IN since December 2025. Subscriptions run at $380 a month; source code reached $4,500 with lifetime updates.

Their report names the Polygon contract used by its "Analytics" cluster: `0x08207B087F61d7e95E441E15fd6d40BEfd6eD308`.

**That is the contract recorded in this plugin's scanner class since the original `wp-perf-analytics` work.** The family in section 1 of this catalogue and the ErrTraffic "Analytics" cluster are the same operation. Corroborating: Sekoia lists that cluster's preferred TLDs as `.cfd`, `.club`, `.click`, `.cyou`, `.lat`, `.sbs`, `.shop`, `.xyz`; the C2 hosts catalogued here from captured samples are `biletors.cfd`, `comicstar.lat` and `webanalytics-cdn.sbs`.

Two clusters are documented. **Analytics** uses a single stable contract and distributes Vidar. **Beer** is the rental infrastructure used by multiple affiliates, each assigned its own contract, resolving through Quicknode, and favouring `.beer` and `.monster` domains. On WordPress the delivery observed is a PHP backdoor installed as an mu-plugin, which harvests administrator credentials, injects the loader, opens a web shell, and pauses when it detects a security scanner.

**Indicators.** `bsc-dataseed.binance.org`, `bsc-dataseed1.binance.org`, `bsc-dataseed.bnbchain.org`, `bsc-dataseed1.bnbchain.org`, `bsc.publicnode.com`, `binance.llamarpc.com`, `bsc-rpc.publicnode.com`, `polygon.drpc.org`, `polygon-bor-rpc.publicnode.com`, `polygon.lava.build`, `polygon.rpc.subquery.network`, `polygon-public.nodies.app`, `polygon-pokt.nodies.app`, `polygod.network`, the Quicknode registrable domains `quiknode.pro` and `quicknode.pro`, the JSON-RPC method names `eth_call` and `eth_getStorageAt`, and the request-path markers `/cf.js`, `/api/css.js`, `a=ctx` and `src=cloudflare`.

The request paths matter more than the domains. Both clusters rotate their C2 daily through the contract, so the domain is the least durable thing about them; the paths stay constant across that rotation.

**None of these is a finding on its own — and that was a defect until 1.4.56.** Seven RPC hostnames and `eth_call` sat in a single-match signature list, so a legitimate NFT or wallet plugin calling a public endpoint was reported as critical malware. Every consumer now requires corroboration.

**Detection.** `check_etherhiding_resolver` (1.4.56, technique-level: a JSON-RPC read primitive plus a contract address plus a third independent signal), `check_c2_references`, `check_obfuscated_loader`, `check_php_signatures`, `check_clickfix_c2_in_options`.

The technique-level check exists because the endpoint list has a structural limit. Quicknode issues per-customer subdomains and the Beer cluster assigns each affiliate its own contract, so neither value can be enumerated ahead of time and an unseen affiliate defeats any list. What cannot be varied is the shape: something must read an address from somewhere. The third signal — obfuscation, a clipboard-execution lure, a known request path, or a location no self-declaring plugin would choose — is what separates it from a genuine web3 plugin, which does the first two on purpose.

**Blocking.** Detect only, and deliberately so. These hosts are not blocked outright; a site with a genuine reason to reach a blockchain RPC endpoint exists, and the signal is the combination of the endpoint with a loader shape.

---

## 11. Persistence implants

**Classification.** Components whose only job is to survive cleanup and restore the rest.

**Coordinated implant (catalogued 1.4.40).** Two files verified as linked: `mu-plugins/db-connection-pool.php` (66 KB, fake header naming "Post Format Handler" by "WP Infrastructure" — the filename and the internal name disagree) assembles the token `d58ce737fcc9690ccfb6` from 295 `chr()` calls, while `fonts/role-validator.php` returns immediately unless `$_GET['_cache_token']` starts with `d58ce737fcc9690c`. Same token, confirmed by decoding.

The `mu-plugins` placement matters on its own: those files auto-load and cannot be deactivated from the dashboard. The `fonts/` placement matters differently — a PHP file in a data directory is wrong before it is read, which is why location became evidence in its own right.

**Externalised-payload plugins.** `page-image-scanner` and similar read, decode and execute a bundled non-PHP blob (`storage/state.pkg`), keeping no executable payload in any PHP file.

**Container-behind-magic-bytes.** `native-image-optimizer-2b8f` keeps its payload in `resources/config.bin` behind a four-byte magic `WH68`, a campaign byte, a two-byte key length, and a body that is reversed then XOR'd. The PHP carries a genuine, correct `ABSPATH` guard and produced zero findings against every check that existed before 1.4.35.

**Self-extracting payloads.** `f4590eb5` reads its own file, splits on its own closing tag — `explode(base64_decode('Pz4='), file_get_contents(__FILE__))` — and executes what follows. Nothing is in a string or a variable, so checks requiring a long encoded literal find nothing. Rated high rather than critical, deliberately: commercial security and licensing products (Monarx, ionCube, SourceGuardian, Zend Guard, PHPShield, SiteLock, Imunify) protect their own code with the same technique, and the check cannot tell them apart. A scanner that removes the host's own security agent has done more harm than the thing it hunted.

**Indicators.** mu-plugins option keys `wp_session_tokens_config`, `session_tokens_config`; exfil filename `Stained_Heart_Red-600x500.png`; hardcoded administrators `adminbackup561801`, `a7f3e9b2c4d1e5f6`.

**Detection.** `check_mu_plugins`, `check_php_in_data_directory`, `check_external_payload_loader`, `check_self_extracting_payload`, `check_dropper_persistence`, `check_redrop`, `check_cron_tampering`, `check_registration_settings`, `check_drop_ins`, `WPS_Dropin_Guard::check`.

**Blocking.** Detect only.

---

## 12. Other tracked slugs

Families carried on the blocking lists whose full analysis lives in `doc/changelog.md` rather than here.

| Slug | Notes |
| --- | --- |
| `session-manager` | Drop-in re-dropper; randomised suffix patterns; option keys `wp_session_tokens_config`, `session_tokens_config` |
| `wp-antymalwary` | Fake anti-malware plugin; option keys `wp_antymalwary_bot`, `malwary_pass`; cron fragments `antymalwary`, `malwary` |
| `wpconsole` | Option key `wpconsole_key`; cron fragment `wpconsole` |
| `wp-security-helper` | Also appears as a secondary backdoor filename |
| `wp-performance-booster` | ClickFix-adjacent naming |
| `trim` | Legacy entry retained from early releases |

Emergency-access option keys `wps_emergency_pass` and `malwary_pass` are catalogued because malware in this family plants its own recovery credential.

---
## 13. TDS drive-by injector

**Classification.** Front-end JavaScript injection routed through traffic-distribution infrastructure. A separate operator chain from every other family here.

**Delivery.** A must-use plugin, `tji-site-js.php`, disguised as "Theme JS Injector / TJI Site JavaScript". The `mu-plugins` placement means it auto-loads and cannot be deactivated from the dashboard.

**Mechanism.** Injects JavaScript on every front-end pageview and routes the visitor through `ntdnewtds.shop/jsrepo` and `dnsnewtds.shop/jsrepo`. Admin, AJAX, cron and JSON requests are skipped, which is stealth rather than compatibility — the owner never sees the injected script.

**A note on attribution.** This was found co-resident with the RAT v1.7 family on the same victim site and is **not** related to it. Either a second operator reached the same site independently, or one operator is running several monetisation streams. Co-residence is not evidence of a shared operator, and the catalogue does not treat it as such.

| Filename | MD5 | SHA-256 | First catalogued |
| --- | --- | --- | --- |
| `tji-site-js.php` | `47ff560f2c1096757cbfad5291ccc959` | `1d2699149bbb1f523cd914cbe2025de77e00dd58dedd11eaded9a04b01246d50` | 1.3.49 |

**Indicators.** `ntdnewtds.shop`, `dnsnewtds.shop`, the `/jsrepo` path, and the filename itself.

**Detection.** `check_mu_plugins`, `check_c2_references`, `check_obfuscated_js_injector`.

**Blocking.** Upload and hash.

**Remediation.** Remove the file from `mu-plugins`. Nothing in the dashboard will do it for you, which is the property that made the location attractive.

---

## 14. User-hiding filter installer

**Classification.** Visibility suppression. It does not steal anything; it makes the theft invisible.

**Delivery.** `wp-security-helper.php`, presenting as "WP Security Helper" by "WordPress Security Team" — the same fake author as `wp-security-cache.php`, which places both in one operator chain.

**Mechanism.** Installs five WordPress filters that hide every user except the currently logged-in administrator from the dashboard, and hides the plugin itself from the Plugins page unless `?sp` is present in the query string. Filter names are hex and octal obfuscated, with goto-flow obfuscation over the top, to defeat static analysis.

The effect is that a compromised site looks clean from inside. An administrator reviewing the user list sees only themselves; an administrator reviewing installed plugins does not see the thing doing it.

| Filename | MD5 | SHA-256 | First catalogued |
| --- | --- | --- | --- |
| `wp-security-helper.php` | `50c02424e0e723c019b4d2bf849f2a9b` | `0a26e477951896659dbc5b0b18929995303a9ab4e071288b40691e0b366b96a1` | 1.3.53 |

**Detection.** `check_hidden_admin_users` walks `wp_users` directly with `$wpdb`, bypassing `get_users()` and therefore bypassing the filters entirely. That catches the *symptom* whichever installer produced it, which matters because this build is one of an unknown number. The hash and signature entries catch this specific build.

**Blocking.** Upload and hash. The slug is on the activation blocklist.

**Remediation.** Remove the file, then re-audit the user list — from the database rather than the dashboard, since the dashboard is what was being lied to.

---

## 15. Credential exfiltration staging file

**Classification.** Not malware in itself. Harvested credentials waiting for collection.

`Stained_Heart_Red-600x500.png` carries an image extension and holds captured logins in plain text. Two builds are catalogued, differing in size.

| Build | MD5 |
| --- | --- |
| 416-line | `b466fa4c2fac736d65b343d47fd0e1d1` |
| 63-line, observed live | `09a86e4696b21391d3911b0b64a50c48` |

**Detection.** `check_exfil_file`, `check_uploads_for_php`.

**Finding this file means the credentials in it are already gone.** Treat every account it names as compromised and rotate accordingly. Removing the file changes nothing about that.

---

## Cross-family techniques

Grouped by what the technique is *for*, because the same trick recurs across unrelated families and detection targets the technique rather than the instance.

| Technique | What it looks like | Families | Detection |
| --- | --- | --- | --- |
| Split-string identifiers | `'bas'.'e64_decode'`, `'HTTP'.'_USER_A'.'GENT'` | ClickFix, cloaked injectors | `check_hidden_identifiers`, `check_split_literal_obfuscation` |
| Character-built identifiers | `$y[15].$y[14].$y[13]` spelled from a haystack string; or 295 `chr()` calls | ClickFix, attacker toolkit, persistence implants | `check_character_built_identifiers` |
| Hex and octal escapes | `\x48\x54\x54\x50_USER_AGENT` | Japanese SEO cloak | Resolved in shared normalisation before any matching |
| Comment between name and bracket | `/**\/@eval/**\/(` | Self-extracting payloads | `WPS_Utils::strip_php_comments` before call matching |
| Control-flow flattening | goto density above 5 per KB, floor of 20 statements | Japanese SEO cloak, packers | `check_control_flow_flattening`, `check_obfuscated_goto_backdoor` |
| Decoder chains | `eval(strrev(str_rot13(gzinflate(base64_decode($blob)))))` with split names | Attacker toolkit | `check_encoded_payload_loader` |
| Self-extraction | File reads itself, splits on its own `?>` | `f4590eb5` | `check_self_extracting_payload` |
| Payload outside PHP | Blob in `.bin`, `.pkg`, `.dat` behind a custom container | `native-image-optimizer`, `page-image-scanner` | `check_external_payload_loader` |
| Obfuscated JS in a PHP envelope | Thousands of `_0x` hex identifiers in a heredoc | Theme-loader injector | `check_obfuscated_js_payload` |
| Audience cloaking — hide | Early return for admins, crawlers, cache-suppression constants | ClickFix, cloaked injectors | `check_cloaked_injector` |
| Audience cloaking — show | Serve spam *to* crawlers, clean pages to everyone else | Japanese SEO cloak, doorway kits | `check_doorway_cloaking` |
| Anti-analysis blocklists | Tens of thousands of IPs, plus ASN and organisation deny lists | Doorway and TDS framework | `check_doorway_cloak_config` |
| Hardening bypass | `php.ini` with `disable_functions = NONE`, `exec = ON` | Attacker toolkit | `check_hardening_bypass_config`, `check_php_config_override` |
| Location as camouflage | PHP under `.well-known/`, `fonts/`, `uploads/`, `languages/` | RAT v1.7, persistence implants | `check_well_known_php`, `check_php_in_data_directory`, `check_languages_for_php` |
| Unauthenticated write endpoint | `php://input` or a superglobal written straight to disk | Doorway kits, attacker toolkit | `check_unauthenticated_file_manager` |
| Credential exfiltration | Outbound call to a hardcoded host carrying session material | Cookie-exfil toolkit | `check_credential_exfiltration` |
| Timestamp tampering | A `setmtime` action in a file manager | File-manager shells | Treat on-disk mtimes as untrustworthy |
| Per-victim polymorphism | XOR seed derived from the victim's own domain | RAT v1.7 | Structural signatures, not hashes |

---

## Appendix A — Command and control

| Host | Role | Family |
| --- | --- | --- |
| `webanalytics-cdn.sbs` | Session-cookie exfiltration endpoint (`/k`) | Cookie-exfil toolkit |
| `ntdnewtds.shop` | Traffic distribution | Doorway and TDS |
| `dnsnewtds.shop` | Traffic distribution | Doorway and TDS |
| `biletors.cfd` | Lure download source | ClickFix |
| `comicstar.lat` | Lure download source | ClickFix |
| `ip-api.com` | Visitor geolocation (legitimate service, abused) | Doorway and TDS |
| BSC and Polygon RPC endpoints | Payload storage | EtherHiding |

Note that `ip-api.com` and the RPC endpoints are legitimate infrastructure. They are indicators in combination with a loader shape, never on their own.

## Appendix B — Option keys

Thirteen ClickFix payload keys of the form `wp_<10 hex>_cfg` are catalogued individually, and the shape is matched structurally so an uncatalogued key is still inspected.

`wp_94d4678186_cfg` · `wp_a26c00cc40_cfg` · `wp_0b05838858_cfg` · `wp_e3ef2393dd_cfg` · `wp_204acd2d43_cfg` · `wp_fe99c06901_cfg` · `wp_b6786d21cb_cfg` · `wp_a326b31e44_cfg` · `wp_e07ded4e61_cfg` · `wp_3093c104e2_cfg` · `wp_d4b340aceb_cfg` · `wp_1f20bc3f7f_cfg` · `wp_8447aa87d2_cfg`

Non-ClickFix keys: `wp_session_tokens_config`, `session_tokens_config`, `wp_antymalwary_bot`, `wpconsole_key`, `wps_emergency_pass`, `malwary_pass`, `wp_perf_ok`, `_wp_perf_ok`, `_cf_verified`, `cf_verified_token`.

## Appendix C — Filenames

**Secondary backdoors.** `.wp-config-cache.php` · `wp-security-cache.php` · `wp-phpunit.php` · `wp-default.php` · `cert-check.php` · `tji-site-js.php` · `wp-security-helper.php`

**Also catalogued.** `wp-backup-verify.php` · `wc-report-handler.php` · `wp-locale-handler.php` · `ms-file-router.php` · `wp-cache-stats.php` · `db-connection-pool.php` · `role-validator.php`

**Exfiltration staging.** `Stained_Heart_Red-600x500.png` — an image extension carrying non-image content.

**Kit components.** `core/core.php` · `core/panel_<hex>.php` · `core/filemanager_<hex>.php` · `core/backdor_<hex>.php` · `config/settings.json`

## Appendix D — Hardcoded accounts

`adminbackup561801` · `a7f3e9b2c4d1e5f6`

Both are administrator accounts created by malware. Their presence means the site was fully compromised, regardless of what else is found.

## Appendix E — Cron hook fragments

`antymalwary` · `perf_analytics` · `native_render` · `native-render` · `total_render` · `total-render` · `site_speed` · `site-speed` · `pro_font` · `pro-font` · `font_optimizer` · `font-optimizer` · `wpconsole` · `malwary` · `wp_perf_ok`

Matched as substrings against scheduled hook names, since the surrounding name varies per build.

---

## Appendix F — Complete hash reference

Every fingerprint WP Perf Shield carries, with the attribution recorded alongside it in `includes/class-blocker.php`. Hashes are the least durable layer in this catalogue — one byte defeats any of them — so they are published for corroboration rather than as a defence.

### MD5

| Hash | Attribution |
| --- | --- |
| `75d1b8c91600379dea5791920c192b0c` | XOR 60, v1.2.4 |
| `cdec71647d65e4e6542c19848e07e7bd` | XOR 84, v1.2.66 (8760 variant) |
| `cefca0da4afd2816bfada89236e5011a` | XOR 113, v1.2.19 (91c6 / 9b4c variants) |
| `cf0c1086cca734bbb7038f5ad9e907d5` | XOR 114, v1.2.97 (d2e9 variant) |
| `c1783b8b92b0a53a65f888af75a1d688` | XOR 237, v1.2.83 (latest variant) |
| `678899f67c9561f4b88d28952189467c` | native-render-toolkit-9401.php |
| `06b7dc4813bdd9575bab106451b015de` | total-render-profiler-3753.php |
| `0e34f31fac8662886303225484dd648a` | total-render-toolkit-adae.php |
| `99c53e189239269f0197802306af236a` | pro-font-optimizer-c88b.php |
| `6f6b4854cb0d71f81796ead56132c89a` | site-speed-insights-d6e7.php |
| `7dbc51fa960a74a79bd2cb475a2dfd04` | advanced-asset-insights-ec06.php (1.3.37) |
| `a23f9c0fb1eb85247d0f4a8264bd9c18` | page-seo-toolkit-a937.php (1.3.39) |
| `bb398fb4783c7fc3647a633b51811099` | starter-image-guard-e9a2.php (1.3.39) |
| `c87d8c472f827704a2ef6beb997729ff` | auto-content-profiler-0b8d.php (1.3.58, variable-concat evasion variant) |
| `15e17041c615dc272d5cd5ac3bcd5d6f` | pro-cache-scanner-6d52.php (1.3.68) |
| `80322b56aaec6af92d392f8daa36aee7` | total-database-optimizer-9a95.php (1.3.69, array-callback evasion variant) |
| `608576a9322aab3585fe7e7eb109f368` | site-security-toolkit-1f30.php (1.4.49, 9,674 bytes, hashed from the sample in hand) |
| `73f07f1438b9a710b5bf1893186d1e67` | Plugin-7e4eb3ff.php (1.4.50, 130,672 bytes, hashed from the sample in hand) |
| `7bbf81ab731b59b3c0fed628c1f3cf3d` | auto-asset-helper-2763.php (1.4.53, 10,739 bytes, hashed from the sample in hand - the entry 1.4.49 deliberately left out) |
| `ab86726bb8ed4527cb6ea787f9a12c1a` | Plugin-b45b652c.php (1.4.57, 129,503 bytes, hashed from the sample in hand) |
| `748f6d05c328364ebf6a0cec1aec350d` | Plugin-45e0930c.php (1.4.58, 127,542 bytes, hashed from the sample in hand) |
| `9c77bbb0998b95f0562800b6086dd11e` | wp-backup-verify.php |
| `e76d6d119445032e72e85ad52a6d83ef` | wc-report-handler.php |
| `d2c9540df466434c7658d7956c5c833d` | wp-locale-handler.php |
| `7d67b8a2edff4735d5dce83b7bfe3eee` | wp-backup-verify.php (v2) |
| `3013ade690ede0070a4b028bec82bb6b` | wc-report-handler.php (v2) |
| `70358bb32a2cf6fcbfc9edfe2848a579` | wp-locale-handler.php (variant 2026-05, muslim-apologetic-borneo XOR seed) |
| `2d746471df530568e76e280c6dec8c2d` | .wp-config-cache.php (cookie exfil to webanalytics-cdn.sbs) |
| `54b60e56a90d0ed4b8a4de79c0916193` | wp-security-cache.php (creates admin a7f3e9b2c4d1e5f6) |
| `cd35f8c14a03fecba0b72e67804dd337` | wp-phpunit.php (5-fallback webshell, ?c=<base64>) |
| `8a92828554a087c46cc21c87fd1b15d4` | wp-default.php |
| `bede133bf2bd823b6b3c14c19db482ea` | ms-file-router.php  (Multisite File Router) |
| `d5eae8a8a0b9dc9099a92b5aceae883f` | wp-cache-stats.php  (Cache Statistics Handler) |
| `d75140a8db6edc1147f826b7eec30812` | cert-check.php (RAT v1.7, themuslimapologist.online build) |
| `3e92c07fa807bcc3a1754c9ba3d1c142` | cert-check.php (RAT v1.7, bestofislam.com build) |
| `a667e49c601d874cbacc40e158bb56c1` | cert-check.php (RAT v1.7, bismikaallahuma.org build) |
| `8203c5bb61b21777519bef3af299842d` | cert-check.php (RAT v1.7, compelling-evidence.com build) |
| `c053446a3916beb41df3e3428c085a3c` | cert-check.php (RAT v1.7, muslim-apologetic-borneo.com build, added 1.3.59) |
| `a4f6a499ea1c34ae15dcf108e0fa197b` | wp-locale-handler.php (RAT v1.7, bestofislam.com build, languages/ location) |
| `47ff560f2c1096757cbfad5291ccc959` | tji-site-js.php (TDS injector mu-plugin) |
| `50c02424e0e723c019b4d2bf849f2a9b` | wp-security-helper.php |
| `b466fa4c2fac736d65b343d47fd0e1d1` | Stained_Heart_Red-600x500.png (416-line) |
| `09a86e4696b21391d3911b0b64a50c48` | Stained_Heart_Red-600x500.png (63-line, live) |

### SHA-256

| Hash | Attribution |
| --- | --- |
| `b86b46e36620c041a5033a8191b05f1fb744f0451beb5b9d639463de1d46d664` | SHA-256, XOR 60 |
| `2a5b7a6602bc5bace45131153d665554b36404d7c40b72e7c56e06c9a6f7d15d` | SHA-256, XOR 113 |
| `8effe4bd104ee4716ae3fb975b6b6e37069f347dfe09c0569f9aea0c77c8a789` | SHA-256, XOR 114 |
| `0df2fa44c40cc0ae76fa32ebf756cfe3c4614f80a90dd8290b061d433dedc27b` | SHA-256 native-render-toolkit-9401.php |
| `c403d603a0345e904d8c6bc27565905817f602647a86eab205713e0cb849a37c` | SHA-256 total-render-profiler-3753.php |
| `c22bbb5144d71de9ece4c8cf52db0e9f79b70f7e77f0064fa9e06753b340f541` | SHA-256 total-render-toolkit-adae.php |
| `751b9848b645f5e7ab72eab015ea6743284657cfdcfc844a9c06081400ded3b6` | SHA-256 pro-font-optimizer-c88b.php |
| `9b5cc2de2e2cd968c5f69a0a6d561b37d31424f3f8c814d11a7404cc4a5bcaa8` | SHA-256 site-speed-insights-d6e7.php |
| `ff96b828b345755c728cebbf3fc041290f14f12a535f693d06b520d89d106e3b` | SHA-256 advanced-asset-insights-ec06.php (1.3.37) |
| `ee4b899d93655e4fc15b6ed8692a25e3b4052a005f85c5460d22a444e4245b9e` | SHA-256 page-seo-toolkit-a937.php (1.3.39) |
| `acf2aaf34ceac250b03c77ab2afa221f3290508b7f876209ab332830d0ae4105` | SHA-256 starter-image-guard-e9a2.php (1.3.39) |
| `d7ec2991f822bc9d8811526f83e84dad6002d8ca8471fd3a763f40252e59ea32` | SHA-256 auto-content-profiler-0b8d.php (1.3.58) |
| `894108561a3b5be93a76ce2bda74602ed5b5305649aae65b43460565ca220201` | SHA-256 pro-cache-scanner-6d52.php (1.3.68) |
| `1e5992209203641e6b12b309596c1eb87a46c985eded099214ea036eb316adb3` | SHA-256 total-database-optimizer-9a95.php (1.3.69) |
| `3bb3738a66d94f5b5020fab817afd4fd94bbe6e11cbdaa477eec49d27a555ae9` | SHA-256 site-security-toolkit-1f30.php (1.4.49) |
| `eb45ec5c13b35b4589047550e41656f5395aeb3e33b610fdd60d1473f0f3e642` | SHA-256 Plugin-7e4eb3ff.php (1.4.50) |
| `de3bc67ff123719c1fa36e6d86b960f007290d84f23d4b79d39610c177cda451` | SHA-256 auto-asset-helper-2763.php (1.4.53) |
| `ee72a3a0c968e3248df20d48e0c2d954e184c37fa7c283bb0625c5249448d31e` | SHA-256 Plugin-b45b652c.php (1.4.57) |
| `dfe3321053f7577873b4b15d03ad40318656096c9d0280ce4aebc3cef192da66` | SHA-256 Plugin-45e0930c.php (1.4.58) |
| `2860c80dac6f04344f9f29e306e3c88ceee14a97bb2d96bddeba83846da361f7` | SHA-256, same variant |
| `3d945139f3c530f3dc872c6be10cc092fded2f92e77d3af9f4be76186197d277` | SHA-256 |
| `4e7fb5e61f8c0f1bdfbbb32d755706f81b55dda49ef7cacca87c9f5afaf002b0` | SHA-256 |
| `15144ebc1baaf5a46466cc2dfe7ca1e18f2c20363cf15b4ff73861648cc62efe` | SHA-256 |
| `673806e0aadc67be107217cc0e3dcf12486022fe39150ee09494236d317ee02d` | SHA-256 |
| `6c862aabe3680ec9f4b03fbad7313f1a57b1c9d7a6f199f2ab503b28319cafab` | SHA-256 wp-locale-handler.php |
| `7e1f7a9b622f3cc7941cf6a36c6f23682e02191ae430ccd24cb3ac5cb1d8eb82` | SHA-256 |
| `95f0ad704e7e163b288373a94520d881b830e9d127ea1f75d72e281d56711c23` | SHA-256 |
| `c374f8f34b136a5021cbf0da1e1e760c5b29c430c4c49a6722c863eabfedf583` | SHA-256 |
| `fba50e891764d1b8a6f7e7e2887df1d568fd818ff2e22b8db8372ffd32bfcd53` | SHA-256 |
| `0c1d67c3d5036b5ced4f761d05326b8a3e98946ca89fb5fc0bd276c0b095cff0` | SHA-256 |
| `bae6d2e4f396b9610c11a839a9ffc9740033c7d7a482d5310af63cc45351979b` | SHA-256 |
| `1d2699149bbb1f523cd914cbe2025de77e00dd58dedd11eaded9a04b01246d50` | SHA-256 |
| `0a26e477951896659dbc5b0b18929995303a9ab4e071288b40691e0b366b96a1` | SHA-256 |

43 MD5 and 33 SHA-256 entries, verified well-formed: every value is exactly 32 or 64 hexadecimal characters.

---
## Appendix G — Where the fingerprint coverage is thin

Published because a catalogue that only shows what is known invites the reader to assume the rest is covered.

### Carried with an MD5 but no SHA-256

17 of 34 fingerprinted samples. These were catalogued from analysis notes before SHA-256 was recorded alongside, and the files have not since been re-examined.

| Sample | MD5 |
| --- | --- |
| `.wp-config-cache.php` | `2d746471df530568e76e280c6dec8c2d` |
| `Stained_Heart_Red-600x500.png` | `09a86e4696b21391d3911b0b64a50c48` |
| `XOR 113, v1.2.19` | `cefca0da4afd2816bfada89236e5011a` |
| `XOR 114, v1.2.97` | `cf0c1086cca734bbb7038f5ad9e907d5` |
| `XOR 237, v1.2.83` | `c1783b8b92b0a53a65f888af75a1d688` |
| `XOR 60, v1.2.4` | `75d1b8c91600379dea5791920c192b0c` |
| `XOR 84, v1.2.66` | `cdec71647d65e4e6542c19848e07e7bd` |
| `cert-check.php` | `c053446a3916beb41df3e3428c085a3c` |
| `ms-file-router.php` | `bede133bf2bd823b6b3c14c19db482ea` |
| `tji-site-js.php` | `47ff560f2c1096757cbfad5291ccc959` |
| `wc-report-handler.php` | `3013ade690ede0070a4b028bec82bb6b` |
| `wp-backup-verify.php` | `7d67b8a2edff4735d5dce83b7bfe3eee` |
| `wp-cache-stats.php` | `d5eae8a8a0b9dc9099a92b5aceae883f` |
| `wp-default.php` | `8a92828554a087c46cc21c87fd1b15d4` |
| `wp-phpunit.php` | `cd35f8c14a03fecba0b72e67804dd337` |
| `wp-security-cache.php` | `54b60e56a90d0ed4b8a4de79c0916193` |
| `wp-security-helper.php` | `50c02424e0e723c019b4d2bf849f2a9b` |

**What this does and does not mean.** It is not an evasion hole: altering a file changes both hashes, so an MD5-only entry is no easier to slip past than a pair. What it costs is corroboration — a single MD5 is weaker evidence when an analyst is confirming an identification, and MD5 is no longer collision-resistant, so a file deliberately crafted to collide could provoke a false match. Neither is urgent. Both close the moment a sample is supplied.

### Carried without any fingerprint

| Sample | Status |
| --- | --- |
| `Plugin-390a770b` | recorded from analysis; file not held |

No hash in this catalogue was ever written from memory. Where a file has not been examined, the entry says so rather than carrying a plausible-looking value that would match nothing.

This appendix is generated from `includes/class-blocker.php` and asserted against it by the test suite, so it cannot quietly fall out of date.

---
## Contributing a sample

WP Perf Shield's detection has been extended by samples more often than by planning. The releases that closed real blind spots — 1.4.33 through 1.4.50 — each began with a file from a compromised site.

If you have a sample this catalogue does not cover, the useful things to capture are: the full directory as it sat on disk, file modification times before anything touches them, the `wp_options` rows the payload reads, and any server log lines around the drop. A payload alone tells you what it does; the surrounding tree tells you how it arrived, which is the part that stops it happening again.

## Maintenance

This catalogue is generated from analysis, not from the code, so it can drift from the indicator lists it describes. When a family is added to `includes/class-wps-indicators.php` or `includes/class-blocker.php`, add it here in the same release.

The layers a family must be wired through are: activation blocking, upload blocking by entry name, hash, upload content signature, option-key remediation, and scanner detection. Three consecutive releases — 1.4.49 and 1.4.50 among them — were spent discovering families that had been catalogued for detection years earlier and never wired for blocking. Cataloguing a variant is not the same as covering it.
