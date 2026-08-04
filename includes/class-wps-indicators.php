<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * WPS_Indicators  versioned indicator data (Phase 4).
 *
 * Centralises the malware indicator lists that were previously duplicated
 * across `class-remediation-controller.php`, `class-forensics.php`, and
 * `class-scanner.php`. The loader is read-only and deterministic: every
 * accessor returns a fresh array literal, so no mutable state is exposed.
 *
 * Only indicators with multiple existing call sites have been extracted in
 * Phase 4. Hash lists, suffix patterns, and regex catalogues that are
 * tightly coupled to specific scanner or hardening logic stay in their
 * owning class until a parity-test harness exists to validate the move.
 *
 * Confidence classes (per the controlled development roadmap):
 *
 *   confirmed_malware  Indicators we have reverse-engineered from confirmed
 *                      campaign samples. Safe to act on (delete the option,
 *                      delete the file).
 *
 *   mu_persistence     The subset of confirmed indicators that, if present,
 *                      means the malware can re-create itself across requests
 *                      via the MU-plugin restore loop. Always investigate
 *                      first; deleting the file without removing this option
 *                      is pointless.
 *
 *   suspicious_review  Heuristic only. Not extracted in Phase 4.
 *
 * INDICATOR_VERSION should be bumped whenever the lists below change so
 * downstream consumers (support bundles, parity tests, future indicator
 * sync) can detect drift.
 */
class WPS_Indicators {

	const INDICATOR_VERSION = '1.4.61-1';

	/**
	 * All confirmed malware-set option keys across the wp-perf-analytics /
	 * session-manager ClickFix family, the render-hijacker variants, and the
	 * WP-antymalwary-bot family.
	 *
	 * @return list<string>
	 */
	public static function malware_option_keys(): array {
		return [
			// wp-perf-analytics / session-manager / RAT (class-wp-compat) family
			'wp_session_tokens_config', // MU plugin base64 backup CRITICAL
			'session_tokens_config',
			'wp_perf_ok',
			'_wp_perf_ok',
			'_cf_verified',
			'cf_verified_token',
			'wp_94d4678186_cfg',
			'wp_a26c00cc40_cfg',
			'wp_0b05838858_cfg',
			'wp_e3ef2393dd_cfg',
			'wp_204acd2d43_cfg',
			'wp_fe99c06901_cfg',     // 1.3.37: Advanced Asset Insights variant (DB_Handler_5dfe)
			'wp_b6786d21cb_cfg',     // 1.3.39: Page SEO Toolkit variant (Opt_Handler_841e)
			'wp_a326b31e44_cfg',     // 1.3.39: Starter Image Guard variant (Render_Module_5b7d)
			'wp_e07ded4e61_cfg',     // 1.3.58: Auto Content Profiler variant (DB_Worker_1c49, variable-concat evasion)
			'wp_3093c104e2_cfg',     // 1.3.68: Pro Cache Scanner variant (Health_Proc_1e3d / Net IO)
			'wp_d4b340aceb_cfg',     // 1.3.69: Total Database Optimizer variant (WP_Manager_abc5, wp_footer prio 90809, array-callback evasion)
			'wp_1f20bc3f7f_cfg',     // 1.3.79: Site Security Toolkit variant (Core_Loader_c8fc / Cache Solutions)
			'wp_8447aa87d2_cfg',     // 1.3.79: Auto Asset Helper variant (Res_Helper_ad74 / WP Solutions)
			// WP-antymalwary-bot family
			'wp_antymalwary_bot',
			'wpconsole_key',
			'wps_emergency_pass',
			'malwary_pass',
		];
	}

	/**
	 * The subset of malware option keys whose presence implies an active
	 * MU-plugin restore loop. Used by Forensics to surface a stronger
	 * "RAT auto-restores mu-plugin from this" warning.
	 *
	 * @return list<string>
	 */
	public static function mu_persistence_option_keys(): array {
		return [
			'wp_session_tokens_config',
			'session_tokens_config',
		];
	}

	/**
	 * Confirmed credential exfil filenames the campaign drops under
	 * wp-content/uploads. Disguised as PNGs but contain plaintext lines of
	 * harvested logins.
	 *
	 * @return list<string>
	 */
	public static function exfil_filenames(): array {
		return [
			'Stained_Heart_Red-600x500.png',
		];
	}

	/**
	 * Substrings used to identify malicious cron hook names injected by
	 * confirmed campaigns. Match is case-insensitive substring; do not
	 * include benign words that could appear in legitimate plugin hooks.
	 *
	 * @return list<string>
	 */
	public static function malicious_cron_hook_substrings(): array {
		return [
			'antymalwary',
			'perf_analytics',
			'native_render',
			'native-render',
			'total_render',
			'total-render',
			'site_speed',
			'site-speed',
			'pro_font',
			'pro-font',
			'font_optimizer',
			'font-optimizer',
			'wpconsole',
			'malwary',
			'wp_perf_ok',
		];
	}

	//  .sbs cookie-exfil + persistent-admin toolkit (added 1.3.33)
	//
	// A separate campaign from the ClickFix/render-hijacker family. Three
	// coordinated files dropped together: a session-cookie exfiltrator that
	// posts wordpress_logged_in cookies to a remote .sbs C2; a persistent
	// admin-account creator disguised as "Security Scanner & Malware
	// Detection Suite"; and a five-fallback webshell.
	//
	// Sample container observed: .wp-config-cache.zip (the leading dot is
	// a hiding tactic; no legitimate WP file uses that name).

	/**
	 * C2 domains used by cookie-exfil toolkits. Match is exact-substring,
	 * case-insensitive. Add only confirmed campaign domains; do not add
	 * legitimate analytics or CDN hosts.
	 *
	 * @return list<string>
	 */
	public static function cookie_exfil_c2_domains(): array {
		return [
			'webanalytics-cdn.sbs',
		];
	}

	/**
	 * Hardcoded administrator usernames seeded by confirmed campaigns. These
	 * are typically high-entropy hex strings that cannot plausibly be a
	 * legitimate operator login. Forensics flags accounts with these logins
	 * as confirmed malware-created.
	 *
	 * @return list<string>
	 */
	public static function hardcoded_admin_usernames(): array {
		return [
			'adminbackup561801',     // ClickFix persistence-style account (kept from prior releases)
			'a7f3e9b2c4d1e5f6',      // .sbs cookie-exfil toolkit, wp-security-cache.php seed
		];
	}

	/**
	 * Backdoor filenames associated with the .sbs cookie-exfil toolkit and
	 * other secondary campaigns the scanner should catch wherever they land.
	 *
	 * @return list<string>
	 */
	public static function secondary_backdoor_filenames(): array {
		return [
			'.wp-config-cache.php',  // session-cookie exfiltrator (register_shutdown_function)
			'wp-security-cache.php', // persistent admin-user creator (a7f3e9b2c4d1e5f6 / 3f8a2d5c9e1b7h4k)
			'wp-phpunit.php',        // 5-fallback webshell (?c=<base64>)
			'wp-default.php',        // standalone PHP file manager / webshell (UM_*, UMSESSID, setmtime timestomp)  added 1.3.36
			'cert-check.php',        // RAT v1.7 in .well-known/pki-validation/  added 1.3.44
			'tji-site-js.php',       // TDS drive-by injector disguised as "Theme JS Injector" mu-plugin  added 1.3.49
			'wp-security-helper.php',// User-hiding filter installer ("WP Security Helper" plugin)  added 1.3.53
		];
	}

	//  Dropper cache hunt (added 1.3.43) 
	//
	// The .sbs toolkit container ZIP (`_wp-config-cache.zip`, sanitised from
	// `.wp-config-cache.zip`) keeps reappearing in the WordPress media
	// library across multiple drops. The pattern that explains it: an
	// operator with an upload foothold parks the toolkit ZIP inside
	// wp-content/uploads/<year>/<month>/ (or anywhere else under wp-content)
	// and a dropper extracts the three component PHP files from the cached
	// ZIP on every cycle. Removing the dropped files alone never breaks the
	// loop because the cached ZIP is the source of truth.
	//
	// We hunt for any ZIP whose basename contains a confirmed-bad substring.
	// Substrings here must be unambiguously malicious  no legitimate WP
	// plugin or backup tool produces a ZIP whose name contains these.

	/**
	 * Filename substrings (case-insensitive) that identify dropper-cache
	 * ZIP containers. Match is on the file basename only, against any
	 * `.zip` file under wp-content/.
	 *
	 * @return list<string>
	 */
	public static function dropper_cache_zip_patterns(): array {
		return [
			'wp-config-cache', // .sbs toolkit container; covers
			                   // _wp-config-cache.zip, .wp-config-cache.zip,
			                   // and any numbered sanitiser variant (__2_, __3_, ...)
		];
	}

	//  RAT victim-site intelligence (added 1.3.45 as known_rat_operator_targets, renamed 1.3.56) 
	//
	// The credential-harvester payload of every captured wp-locale-handler /
	// cert-check sample contains an XOR seed of the form:
	//   md5('<HMAC_SEED>'.'<VICTIM_SITE_DOMAIN>')
	// The HMAC_SEED is constant across the family
	// ('a3f8b2c1d4e5f6071829304a5b6c7d8e9f0a1b2c3d4e5f607182930a1b2c3d4e');
	// the VICTIM_SITE_DOMAIN is the only variable. Each captured sample
	// reveals which site the build was customised AGAINST  i.e., which
	// victim's data the operator chain is preparing to harvest.
	//
	//  IMPORTANT: NAMING CLARIFICATION 
	// Earlier releases (1.3.45 through 1.3.55) called this list
	// "operator targets". The terminology was ambiguous and could be
	// misread as "domains the operator owns." That is INCORRECT. Every
	// entry below is a VICTIM SITE  a domain owned by a site operator
	// whose installation has been compromised by this RAT family. The
	// list does not identify attacker infrastructure of any kind.
	//
	//  IMPORTANT: IDENTIFICATION-ONLY USAGE 
	// This list is consumed exclusively by `extract_rat_victim_site()`
	// (formerly `extract_rat_operator_target()`) to translate the XOR
	// seed of a captured RAT binary into a human-readable victim-site
	// name for forensic annotation. The plugin NEVER uses these domains
	// for blocking, blacklisting, filtering, deny-list enforcement, or
	// any other restrictive purpose. Presence in this list carries no
	// negative implication for the listed domain.
	//
	// Detection of the RAT family works without consulting this list:
	// signature matching on the constant HMAC_SEED, encoded harvester
	// header strings, hash blocklist, and other markers all operate
	// independently. The list serves only to make findings more
	// informative when a captured binary is identified.

	/**
	 * Return the known victim-site domains identified from captured RAT
	 * binary XOR seeds. Used only for finding annotation, never for
	 * blocking. See the comment block above for the full rationale.
	 *
	 * @return list<string>
	 */
	public static function known_rat_victim_sites(): array {
		return [
			'themuslimapologist.online',     // captured 2026-04 (1.3.44)
			'bestofislam.com',               // captured 2026-05 (1.3.45 cert-check, 1.3.49 wp-locale-handler  binary at hand)
			'bismikaallahuma.org',           // captured 2026-05 (1.3.45  inferred from operator-chain lookup table)
			'compelling-evidence.com',       // captured 2026-05 (1.3.45  inferred from operator-chain lookup table)
			'muslim-apologetic-borneo.com',  // captured 2026-05 (1.3.55: wp-locale-handler.php variant binary at hand)
		];
	}

	/**
	 * Backward-compatibility alias. Earlier releases (1.3.45-1.3.55) used
	 * the misleading name `known_rat_operator_targets()` for the same
	 * data. Retained as an alias so any external integrators using the
	 * older method name continue to work; new code should use
	 * `known_rat_victim_sites()`.
	 *
	 * @deprecated 1.3.56 Use known_rat_victim_sites() instead.
	 * @return list<string>
	 */
	public static function known_rat_operator_targets(): array {
		return self::known_rat_victim_sites();
	}

	//  TDS drive-by injector intelligence (added 1.3.49) 
	//
	// Separate malware family from the wp-locale-handler RAT. Disguised as
	// a "Theme JS Injector" mu-plugin (filename `tji-site-js.php`), this
	// family injects client-side JavaScript on every front-end pageview
	// and routes visitor traffic through TDS infrastructure for monetisation
	// (drive-by ads, redirect chains, browser-exploit payloads). Skips
	// admin/AJAX/cron/JSON requests for stealth so the operator never
	// sees the injection in the dashboard.
	//
	// The TDS C2 domains below are the destinations in the captured sample.
	// Future builds may rotate domains; the structural signatures in
	// `WPS_Scanner::SIGNATURES_BACKDOOR` (`tji_mu_script_js`,
	// `__performance_optimizer_v6`, `Theme JS Injector`) catch the family
	// on file content alone, regardless of which C2 domains a given build
	// uses. This list is informational  for blocking egress traffic at
	// the firewall/edge level.

	/** @return list<string> */
	public static function tds_c2_domains(): array {
		return [
			'ntdnewtds.shop', // captured 2026-05 (1.3.49)
			'dnsnewtds.shop', // captured 2026-05 (1.3.49)
		];
	}

	//  ClickFix second-stage download C2 (added 1.3.69) 
	//
	// Recovered by decrypting the AES-256-CBC PowerShell stage that the
	// ClickFix lure copies to a victim's clipboard after the fake-Cloudflare
	// CAPTCHA. The decrypted scriptblock fetches its next stage from this
	// host. The captured callback URL had the shape:
	//
	//   https://<host>/api/index.php?a=dl&token=<64-hex>&src=<victim-domain>&mode=cloudflare
	//
	// The `src=` parameter carries the compromised WordPress site that served
	// the lure (captured sample: themuslimapologist.online). This host is the
	// malware DISTRIBUTION source, not attacker-owned infrastructure the plugin
	// blocks: the PowerShell runs on a victim Windows machine, never on the WP
	// server. The list is informational  for egress-blocking guidance at the
	// firewall/edge and for forensic annotation. Detection of an infected WP
	// site does not depend on it (see check_clickfix_c2_in_options()).

	/** @return list<string> */
	/**
	 * Every catalogued C2 domain across families, merged for the unified
	 * content sweep (1.3.98). Aggregator only: the family lists above remain
	 * the single source of truth and this method never carries its own
	 * entries, so INDICATOR_VERSION is unaffected by its existence. The
	 * victim-site list is deliberately excluded - those domains belong to
	 * compromised site owners, and matching them would flag the innocent.
	 *
	 * @return array<int, string>
	 */
	/**
	 * Constant cluster that identifies a Tiny File Manager instance. The kit
	 * families ship it as a drop-in web shell: full filesystem browse, edit,
	 * upload, chmod, and archive extraction from the browser, usually behind a
	 * single hardcoded password. Legitimate installs exist, so the finding is
	 * review-only and the *location* is what makes it damning - a file manager
	 * inside uploads/, a kit folder, or a fake plugin is not a legitimate one.
	 *
	 * Detection requires several of these together: individually they are
	 * ordinary-looking constant names, collectively they are one product.
	 *
	 * @return array<int, string>
	 */
	public static function file_manager_shell_markers(): array {
		return [
			'FM_ROOT_PATH',
			'FM_SELF_URL',
			'FM_USE_AUTH',
			'FM_READONLY',
			'FM_EXCLUDE_ITEMS',
			'FM_UPLOAD_EXTENSION',
			'FM_SESSION_ID',
			'FM_Zipper',
		];
	}

	/**
	 * Key names from the doorway kit's cloaking configuration (settings.json).
	 * This is the kit's operational heart: allow/deny lists that decide who
	 * sees spam and who sees a clean page. The observed sample carried 111,088
	 * blocked IPs, 569 blocked user-agents, and 87 blocked orgs/ASNs - a
	 * blocklist of that shape exists for one purpose, which is hiding from
	 * security scanners, crawlers, and hosting providers while serving spam to
	 * ordinary visitors.
	 *
	 * Survives folder and file renaming, which the structural tells do not, so
	 * it is the resilient half of kit detection.
	 *
	 * @return array<int, string>
	 */
	public static function doorway_cloak_config_keys(): array {
		return [
			'panel_kee',
			'black_ip_array',
			'black_userag_array',
			'black_org_array',
			'black_country_array',
			'white_list_only_ip',
			'white_list_referer',
			'url_param_array',
		];
	}

	/**
	 * 1.4.48: the switch names the kit's own PHP reads out of that config.
	 *
	 * These are a different thing from the keys above, and the difference is
	 * the point. The keys above identify the config FILE. These identify the
	 * CODE that consumes it, because the kit reads them as literal
	 * subscripts - `$settings['black_org']` - and cannot rename them on one
	 * side without editing the other. A directory name, a file name and the
	 * `panel_kee` marker are all free for an attacker to change; this
	 * vocabulary is load-bearing, so it is the durable thing to match on.
	 *
	 * @return array<int, string>
	 */
	public static function doorway_cloak_flag_keys(): array {
		return [
			'white_list_only_ip',
			'white_list_only_agent',
			'white_list_referer',
			'black_ip',
			'black_country',
			'black_org',
			'black_userag',
			'black_referer',
			'whitelist_ip_array',
			'whitelist_agent_array',
			'whitelist_referer_array',
			'black_ip_array',
			'black_country_array',
			'black_org_array',
			'black_userag_array',
			'black_referer_array',
		];
	}

	/**
	 * Crawler and preview user-agent fragments that cloaking malware checks
	 * for in order to STAY HIDDEN from them. A confirmed sample carried
	 * eighteen of these and returned early on any match, so search engines,
	 * SEO auditors, link previewers, and page-speed tools all saw a clean
	 * page while ordinary visitors were served the payload.
	 *
	 * This list is not used to identify crawlers. It is used to recognise
	 * code that is trying to avoid them, which is why matching several of
	 * these together inside one file is the signal.
	 *
	 * @return array<int, string>
	 */
	public static function crawler_cloak_user_agents(): array {
		return [
			'googlebot',
			'bingpreview',
			'bingbot',
			'yandex',
			'duckduck',
			'slurp',
			'facebookexternalhit',
			'twitterbot',
			'whatsapp',
			'telegram',
			'semrush',
			'ahrefs',
			'mj12',
			'dotbot',
			'lighthouse',
			'pagespeed',
			'spider',
			'crawl',
		];
	}

	/**
	 * Cache-suppression constants. Legitimate caching plugins define these,
	 * so on their own they mean nothing. Cloaking injectors define them for
	 * the opposite reason: a cached page would serve the payload to everyone
	 * including the administrator, breaking the cloak, and would also leave
	 * the evidence sitting in a cache file. Only ever a supporting tell.
	 *
	 * @return array<int, string>
	 */
	public static function cache_suppression_constants(): array {
		return [
			'DONOTCACHEPAGE',
			'DONOTCACHEOBJECT',
			'DONOTCACHEDB',
			'DONOTMINIFY',
		];
	}

	public static function all_c2_domains(): array {
		return array_values( array_unique( array_merge(
			self::cookie_exfil_c2_domains(),
			self::tds_c2_domains(),
			self::clickfix_download_c2_domains()
		) ) );
	}

	public static function clickfix_download_c2_domains(): array {
		return [
			'biletors.cfd', // captured 2026-05 (1.3.69), AES PowerShell stage download host (src=themuslimapologist.online)
			'comicstar.lat', // captured 2026-05 (1.3.72), sibling AES PowerShell stage download host (src=ddbricks.com)
		];
	}

	//  ClickFix static campaign token (added 1.3.72) 
	//
	// The clipboard PowerShell's download callback carries a 64-hex `token`
	// parameter. Two captured samples  one pointing at biletors.cfd with
	// src=themuslimapologist.online, one at comicstar.lat with src=ddbricks.com
	//  carry the IDENTICAL token. It is therefore a static campaign build
	// constant, not a per-victim value, which makes it the most durable
	// fingerprint available: it survives both C2-host rotation and victim
	// change. Matching it directly catches the campaign even if the download
	// URL is restructured or the `a=dl` action string is obfuscated.

	/** @return list<string> */
	public static function clickfix_campaign_tokens(): array {
		return [
			'8caaf953d89478b8a7191eb32295c117a310b53ac9059d4ad69a1e397ec3b2d4', // shared across biletors.cfd + comicstar.lat samples (1.3.69 / 1.3.72)
		];
	}

	//  EtherHiding indicators (added 1.3.75) 
	//
	// GoDaddy (Denis Sinegubko) documented the 2024 wave of this campaign
	// lineage fetching its next-stage ClickFix JavaScript from a Binance Smart
	// Chain (BSC) smart contract rather than a plain C2, a technique called
	// EtherHiding: the loader issues an eth_call JSON-RPC request to a public
	// BSC node and reads attacker-controlled bytecode out of a contract. It
	// resists takedown because the payload lives on-chain. Our captured variant
	// uses a plain C2 (biletors.cfd / comicstar.lat), but the operator has used
	// EtherHiding before and may revert to it, so these terms let the option
	// scanner flag a BSC-fetch payload hidden in a wp_<10hex>_cfg row.
	//
	// Matching requires the term to appear inside a decoded malware-shaped
	// option payload, so a legitimate web3 plugin referencing BSC is not in
	// scope here.

	/** @return list<string> */
	public static function etherhiding_indicators(): array {
		return [
			// Public BSC JSON-RPC nodes the loaders read contract bytecode from.
			'bsc-dataseed.binance.org',
			'bsc-dataseed1.binance.org',
			'bsc-dataseed.bnbchain.org',
			'bsc-dataseed1.bnbchain.org',
			'bsc.publicnode.com',
			'binance.llamarpc.com',
			'bsc-rpc.publicnode.com',
			// Public Polygon JSON-RPC nodes (1.3.78: the rembat.my variant moved
			// EtherHiding from BSC to Polygon, reading its next-stage URL from a
			// Polygon contract via eth_call).
			'polygon.drpc.org',
			'polygon-bor-rpc.publicnode.com',
			'polygon.lava.build',
			'polygon.rpc.subquery.network',
			'polygon-public.nodies.app',
			'polygon-pokt.nodies.app',
			// 1.4.56: relocated here from the single-match signature list along
			// with the rest. It existed ONLY there, so the first draft of that
			// removal dropped it entirely - a detection regression introduced
			// while fixing a false positive. The suite now asserts that every
			// endpoint taken out of SIGNATURES_PERF landed here.
			'polygod.network',
			// JSON-RPC read primitives used to pull on-chain payloads. Matched as
			// a bare substring so it catches eth_call regardless of the quote
			// style around it (the payloads use both "eth_call" and 'eth_call').
			'eth_call',
			'eth_getStorageAt',
			// 1.4.55: the ErrTraffic "Beer" cluster resolves through Quicknode,
			// which issues a per-customer subdomain. A host list cannot
			// enumerate those, so the registrable domain is matched instead and
			// check_etherhiding_resolver() carries the technique-level case.
			'quiknode.pro',
			'quicknode.pro',
		];
	}

	/**
	 * 1.4.55: ErrTraffic request-path markers (Sekoia TDR, June 2026).
	 *
	 * Both clusters rotate their C2 domain daily through EtherHiding, so the
	 * domain is the least useful thing to match on. These paths and parameters
	 * stay constant across that rotation, which makes them the durable half of
	 * the fingerprint.
	 *
	 * @return array<int, string>
	 */
	public static function errtraffic_endpoint_markers(): array {
		return [
			'/cf.js',       // "Analytics" cluster lure fetch
			'/api/css.js',  // older injection route, both clusters
			'a=ctx',        // "Beer" cluster payload request
			'src=cloudflare',
		];
	}

	/**
	 * 1.4.55: the ErrTraffic contract WP Perf Shield has been fighting since
	 * the beginning without knowing its name.
	 *
	 * The scanner has carried this address in its class docblock since the
	 * wp-perf-analytics work, described only as "confirmed contract". Sekoia
	 * TDR attributes it to the ErrTraffic "Analytics" cluster, which makes the
	 * plugin's original target a named, commercially sold framework rather
	 * than an anonymous campaign.
	 *
	 * @return array<int, string>
	 */
	public static function etherhiding_contracts(): array {
		return [
			'0x08207B087F61d7e95E441E15fd6d40BEfd6eD308',
		];
	}

	//  Obfuscated JS injector / theme-css.js dropper family (added 1.3.79) 
	//
	// Two confirmed samples: Plugin-b45b652c (129 503 bytes) and
	// Plugin-45e0930c (127 542 bytes). Each is a single PHP plugin file that
	// embeds ~130 KB of RC4-obfuscated JavaScript in a ENDPLUGINJS heredoc,
	// writes it to the active theme directory as css.js, and injects a
	// <script src="...css.js"> tag into every front-end pageview.
	//
	// The JavaScript uses an RC4-style string-array rotation obfuscator
	// (while(!![]){try{ ... }}) — structurally distinct from the XOR+base64
	// ClickFix loader. It detects bots and WordPress admin/cron paths and
	// passes them through clean; human visitors receive a JSON-RPC payload
	// from a remote C2 server.
	//
	// Plugin naming convention: Plugin Name = Plugin-<8hex>, Description =
	// "simple js plugin", internal constant IB<8HEX-UPPER>_PLUGIN_VERSION.
	// The 8-hex suffix changes per variant; the structural markers below are
	// invariant across both captured samples.

	/**
	 * Structural signatures for the obfuscated JS injector / theme-css.js
	 * dropper family. These appear in the PHP wrapper that delivers the payload,
	 * not inside the obfuscated blob itself, so they survive JS re-obfuscation.
	 *
	 * Used by WPS_Scanner::check_obfuscated_js_injector() for string-match
	 * pre-filtering and by external integrators for the same purpose.
	 *
	 * @return list<string>
	 */
	public static function obfuscated_js_injector_php_signatures(): array {
		return [
			'get_template_directory_uri() . \'/css.js\'', // script delivery path — no legitimate plugin uses this
			'_get_css_js_content',                         // PHP function suffix present in all known variants
			'_header_has_css_js_script',                   // template-injection guard helper
			'_find_closing_tag_position',                  // template-injection helper
			'_get_script_tag',                             // script-tag builder helper
			'ENDPLUGINJS',                                 // PHP heredoc terminator unique to this family
			'Description: simple js plugin',              // plugin header camouflage (may vary in future variants)
		];
	}

	/**
	 * Structural markers found inside the RC4-obfuscated JavaScript payload that
	 * the dropper writes to the theme directory as css.js.
	 *
	 * These are invariant across both confirmed samples and uniquely identify
	 * the payload regardless of which theme directory it lands in or what the
	 * surrounding PHP dropper looks like (enabling detection even if the PHP
	 * wrapper is later rewritten).
	 *
	 * @return list<string>
	 */
	public static function obfuscated_js_injector_payload_markers(): array {
		return [
			// RC4-style string-array rotation obfuscator structural marker
			'while(!![]){try{',
			// Bot/crawler filter regex unique to this family
			'mj12bot|semrush|facebookexternalhit|facebot|ia_archiver|yandex|phantomjs',
			// WordPress path exclusion filter (skips wp-admin, wp-login, xmlrpc, static assets)
			'wp-login\\.php|wp-cron\\.php|xmlrpc\\.php|wp-admin',
			// RC4 string-table deobfuscation function name prefix (may rotate per build)
			'a0_0x',
			// Obfuscator IIFE opening pattern
			'(function(_0x',
		];
	}


}
