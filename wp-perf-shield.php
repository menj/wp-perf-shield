<?php
/**
 * Plugin Name: WP Perf Shield
 * Description: Blocks wp-perf-analytics traffic-hijacking malware and all renamed variants. Includes real-time activation blocking, scheduled scanning, and one-click remediation.
 * Version: 1.4.73
 * Author: MENJ
 * Author URI: https://github.com/menj
 * License: GPL-2.0+
 * Requires at least: 5.8
 * Requires PHP: 7.4
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WPS_VERSION', '1.4.73' );
define( 'WPS_DIR', plugin_dir_path( __FILE__ ) );
define( 'WPS_URL', plugin_dir_url( __FILE__ ) );
define( 'WPS_LOG_DIR', WPS_DIR . 'logs' );
define( 'WPS_LOG_FILE', WPS_LOG_DIR . '/events.php' );
define( 'WPS_LEGACY_LOG_FILE', WP_CONTENT_DIR . '/wps-security/events.php' );

define( 'WPS_OPTION', 'wps_settings' );

/**
 * Fail-safe bootstrap (1.4.12).
 *
 * A security plugin that takes a site down has done more damage than most of
 * what it defends against. Everything below exists so that a fatal error
 * anywhere in this plugin degrades it instead of the site.
 *
 * Three parts:
 *
 *   A shutdown handler records fatals that originate in this plugin's own
 *   files - and only those, checked by path, because catching another
 *   plugin's crash and blaming it on this one would be worse than useless.
 *
 *   A safe-mode gate reads that record on the next request. If the previous
 *   run died inside this plugin, only the passive core loads: no scanning, no
 *   admin screens, no remediation. The site comes back, the plugin says why,
 *   and nothing silently pretends to be protecting anything.
 *
 *   Every registration below is wrapped, so a throw during hook registration
 *   cannot escape into WordPress.
 *
 * Safe mode clears itself when the plugin version changes, since an upgrade is
 * the usual fix, and can be cleared by hand from the admin notice.
 */
define( 'WPS_FATAL_OPTION', 'wps_last_fatal' );

/**
 * Was the last request killed by a fatal inside this plugin? Read once and
 * cached, because it is consulted several times during bootstrap.
 */
function wps_safe_mode(): bool {
	static $safe = null;
	if ( $safe !== null ) {
		return $safe;
	}
	$rec = function_exists( 'get_option' ) ? get_option( WPS_FATAL_OPTION, null ) : null;
	if ( ! is_array( $rec ) || empty( $rec['file'] ) ) {
		return $safe = false;
	}
	// An upgrade is the normal remedy, so a version change lifts safe mode.
	if ( (string) ( $rec['version'] ?? '' ) !== WPS_VERSION ) {
		if ( function_exists( 'delete_option' ) ) {
			delete_option( WPS_FATAL_OPTION );
		}
		return $safe = false;
	}
	return $safe = true;
}

/**
 * Record a fatal that happened inside this plugin. Registered first so it is
 * still in place if anything below throws.
 */
register_shutdown_function(
	static function (): void {
		$e = error_get_last();
		if ( ! is_array( $e ) ) {
			return;
		}
		if ( ! in_array( (int) $e['type'], [ E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR ], true ) ) {
			return;
		}
		$file = str_replace( '\\', '/', (string) ( $e['file'] ?? '' ) );
		$dir  = str_replace( '\\', '/', WPS_DIR );
		if ( $file === '' || strpos( $file, $dir ) !== 0 ) {
			return; // not ours - never claim another plugin's crash
		}
		if ( ! function_exists( 'update_option' ) ) {
			return;
		}
		update_option(
			WPS_FATAL_OPTION,
			[
				'version' => WPS_VERSION,
				'file'    => substr( $file, strlen( $dir ) ),
				'line'    => (int) ( $e['line'] ?? 0 ),
				'message' => substr( (string) ( $e['message'] ?? '' ), 0, 1000 ),
				'when'    => gmdate( 'Y-m-d H:i:s' ) . ' UTC',
				'context' => ( function_exists( 'is_admin' ) && is_admin() ) ? 'admin' : 'front-end',
			],
			false
		);
	}
);

/**
 * Run a bootstrap step without letting it escape. A throw here is recorded the
 * same way a fatal is, so the next request enters safe mode rather than
 * repeating the crash.
 */
function wps_boot( string $label, callable $step ): void {
	try {
		$step();
	} catch ( \Throwable $t ) {
		if ( function_exists( 'update_option' ) ) {
			update_option(
				WPS_FATAL_OPTION,
				[
					'version' => WPS_VERSION,
					'file'    => str_replace( str_replace( '\\', '/', WPS_DIR ), '', str_replace( '\\', '/', $t->getFile() ) ),
					'line'    => (int) $t->getLine(),
					'message' => $label . ': ' . substr( $t->getMessage(), 0, 900 ),
					'when'    => gmdate( 'Y-m-d H:i:s' ) . ' UTC',
					'context' => ( function_exists( 'is_admin' ) && is_admin() ) ? 'admin' : 'front-end',
				],
				false
			);
		}
	}
}


/**
 * Class autoloader (1.4.8).
 *
 * Until now every class was required on every request - roughly 865 KB of PHP
 * parsed to serve an anonymous visitor a page, of which about four fifths was
 * admin screens, remediation, forensics and the 320 KB scanner that only runs
 * on cron. OPcache softens the parse cost but not the per-process memory, and
 * this plugin is built for exactly the shared hosting where OPcache is most
 * often absent or starved.
 *
 * An explicit map rather than a derived path. Most class names do map cleanly
 * onto their filenames, but three do not - WPS_Utils, WPS_Indicators and the
 * vendored WPS_Parsedown - and a security plugin silently failing to load a
 * class because of a clever naming rule is not a trade worth making. The map
 * doubles as the class inventory.
 *
 * Conditional requires were the obvious alternative and are the wrong answer:
 * WPS_Dropin_Guard runs on init on every request and falls back to different
 * behaviour when WPS_Scanner is absent, so guessing context by hand would have
 * quietly changed what the plugin does. Autoloading cannot, because a class is
 * loaded exactly when something references it.
 */
spl_autoload_register(
	static function ( string $class ): void {
		static $map = [
			// core runtime
			'WPS_Utils'                  => 'includes/class-wps-utils.php',
			'WPS_Indicators'             => 'includes/class-wps-indicators.php',
			'WPS_Logger'                 => 'includes/class-logger.php',
			'WPS_Event_Log'              => 'includes/class-event-log.php',
			'WPS_Chain_Selftest'         => 'includes/class-chain-selftest.php',
			'WPS_Guard'                  => 'includes/class-guard.php',
			'WPS_EDR'                    => 'includes/class-edr.php',
			'WPS_Blocker'                => 'includes/class-blocker.php',
			'WPS_Dropin_Guard'           => 'includes/class-dropin-guard.php',
			'WPS_Csp'                    => 'includes/class-csp.php',
			'WPS_Public_Marker'          => 'includes/class-public-marker.php',
			'WPS_Scan_Lock'              => 'includes/class-scan-lock.php',
			'WPS_Login_Guard'            => 'includes/class-login-guard.php',
			'WPS_Post_Guard'             => 'includes/class-post-guard.php',
			'WPS_Spam_Signatures'        => 'includes/class-spam-signatures.php',
			// scan and remediation
			'WPS_Scanner'                => 'includes/class-scanner.php',
			'WPS_Quarantine'             => 'includes/class-quarantine.php',
			'WPS_Forensics'              => 'includes/class-forensics.php',
			'WPS_Hardening'              => 'includes/class-hardening.php',
			'WPS_Log_Reader'             => 'includes/class-log-reader.php',
			'WPS_Remediation_Controller' => 'includes/class-remediation-controller.php',
			// admin screens
			'WPS_Admin'                  => 'includes/class-admin.php',
			'WPS_Admin_Overview'         => 'includes/class-admin-overview.php',
			'WPS_Admin_Diagnostics'      => 'includes/class-admin-diagnostics.php',
			'WPS_Admin_Forensics'        => 'includes/class-admin-forensics.php',
			'WPS_Admin_Remediation'      => 'includes/class-admin-remediation.php',
			'WPS_Admin_Hardening'        => 'includes/class-admin-hardening.php',
			'WPS_Admin_Events'           => 'includes/class-admin-events.php',
			'WPS_Admin_Docs'             => 'includes/class-admin-docs.php',
			'WPS_Admin_Logs'             => 'includes/class-admin-logs.php',
			'WPS_Admin_Settings'         => 'includes/class-admin-settings.php',
			// vendored
			'WPS_Parsedown'              => 'includes/vendor/class-wps-parsedown.php',
		];
		if ( ! isset( $map[ $class ] ) ) {
			return;
		}
		$path = WPS_DIR . $map[ $class ];
		// 1.4.12: a missing or unreadable class file must not be a fatal. An
		// incomplete upload or a half-finished update is a normal way for this
		// to happen, and the caller's class_exists() check can handle a false
		// far better than the site can handle a white screen.
		if ( is_readable( $path ) ) {
			require_once $path;
		}
	}
);


//  Activation

register_activation_hook( __FILE__, function (): void {
	// Scrub any currently-active blocked plugins from the DB
	WPS_Blocker::scrub_active_list();

	// Schedule hourly scan (first run deferred never run heavy I/O on activation)
	if ( ! wp_next_scheduled( 'wps_hourly_scan' ) ) {
		wp_schedule_event( time() + 300, 'hourly', 'wps_hourly_scan' );
	}

	// 1.4.6: record that this plugin is SUPPOSED to be active, then install
	// the must-use guard. Order matters - the guard reads that expectation on
	// its first run, and without it would have nothing to assert.
	// 1.4.15: the must-use tamper guard is withdrawn. Activation removes any
	// leftovers rather than installing anything.
	WPS_Guard::purge();
} );

//  Deactivation

register_deactivation_hook( __FILE__, function (): void {
	// Intentionally keep MU file it must survive plugin deactivation.
	// Remove it only via the admin UI "danger zone" or full uninstall.
	// 1.4.6: record that this deactivation was deliberate BEFORE clearing the
	// schedule. This hook only fires for a real deactivation - an attacker
	// writing to active_plugins directly never reaches it - so the signed
	// expectation is what separates "the owner turned it off" from "something
	// removed it", and it is why the guard does not fight the owner.
	if ( class_exists( 'WPS_Guard' ) ) {
	}
	wp_clear_scheduled_hook( 'wps_hourly_scan' );
} );

//  Uninstall

register_uninstall_hook( __FILE__, 'wps_uninstall' );
/**
 * Remove transients by key prefix during uninstall. Range counters expire on
 * their own within fifteen minutes, so this is tidiness rather than a bound.
 */
function wps_delete_transients_like( string $prefix ): void {
	global $wpdb;
	if ( ! isset( $wpdb ) || ! is_object( $wpdb ) ) {
		return;
	}
	$like = $wpdb->esc_like( '_transient_' . $prefix ) . '%';
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $like ) );
	$like = $wpdb->esc_like( '_transient_timeout_' . $prefix ) . '%';
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $like ) );
}

function wps_uninstall(): void {
	delete_option( WPS_OPTION );
	delete_option( 'wps_last_scan' );
	delete_option( 'wps_version' );
	delete_option( 'wps_blocked_ips' );
	delete_option( 'wps_wpconfig_hash' );    // wp-config.php baseline hash
	delete_option( 'wps_forensics_report' ); // cached forensics report
	delete_option( 'wps_redrop_history' );   // 1.3.42: hashes of previously-deleted malware
	delete_transient( 'wps_core_checksums' ); // 1.3.47: cached api.wordpress.org core file SHA-1 manifest
	delete_transient( 'wps_scan_results' );  // cached scan findings
	delete_option( 'wps_dropin_baseline' );  // 1.3.71: drop-in integrity baseline
	delete_option( 'wps_csp_reports' );      // 1.3.76: CSP violation report buffer
	delete_transient( 'wps_csp_report_throttle' );
	delete_option( 'wps_dropin_watch_fp' );  // 1.3.71: drop-in watch fingerprint
	delete_transient( 'wps_dropin_watch_throttle' );
	// 1.4.15: options belonging to the withdrawn must-use guard.
	delete_option( 'wps_guard_state' );
	delete_option( 'wps_guard_rec_at' );
	delete_option( 'wps_guard_unsigned_at' );
	delete_option( 'wps_guard_notload_at' );
	delete_option( 'wps_guard_consent' );
	delete_option( 'wps_guard_removed' );
	delete_option( 'wps_admin_login_ips' );
	delete_option( 'wps_login_stats' );
	delete_option( 'wps_login_offenders' );
	delete_option( 'wps_mtime_batches_seen' );
	delete_option( 'wps_permanent_blocks' );   // 1.4.31: permanent sign-in denylist // 1.4.29: reported-batch memory    // 1.4.26: escalation memory
	delete_transient( 'wps_ak_usage' );
	// 1.4.23: range counters are transients and expire on their own, but a
	// removal should not leave them behind either.
	wps_delete_transients_like( 'wps_lfn_' );       // 1.4.20: cached Akismet usage figure        // 1.4.18: login guard activity record    // 1.4.17: protected administrator addresses  // 1.4.13: unsigned-state throttle
	delete_option( 'wps_last_fatal' );          // 1.4.12: safe-mode record
	delete_option( 'wps_first_party_baseline' ); // 1.4.11: first-party plugin fingerprints
	delete_option( 'wps_registration_baseline' ); // 1.4.10: registration/default-role baseline
	delete_option( 'wps_guard_notload_at' ); // 1.4.6: guard deadman timestamp
	if ( class_exists( 'WPS_Guard' ) ) {
		WPS_Guard::purge();                     // 1.4.15: clear any withdrawn-guard leftovers
	}
	wp_clear_scheduled_hook( 'wps_hourly_scan' );
}

//  Cron scan

add_action( 'init', function (): void {
	if ( ! wp_next_scheduled( 'wps_hourly_scan' ) ) {
		wp_schedule_event( time(), 'hourly', 'wps_hourly_scan' );
	}
} );

// 1.3.71: throttled drop-in watch. Internally rate-limited to once per
// WATCH_INTERVAL via a transient, so the cost on a normal request is a single
// transient read; only when the throttle window has elapsed does it stat the
// canonical drop-in paths and log any appearance/change/removal with a UTC
// timestamp for log correlation.
// 1.4.12: everything from here is skipped while safe mode is on. The passive
// core - the autoloader, the fatal recorder, and the admin notice - stays, so
// the site runs and the operator is told why the plugin is standing down.
if ( ! wps_safe_mode() ) {

add_action( 'init', [ 'WPS_Dropin_Guard', 'watch' ] );

// 1.3.76: opt-in Content-Security-Policy (off by default; report-only front door).
add_action( 'send_headers', [ 'WPS_Csp', 'maybe_send_header' ] );

// 1.4.52: opt-in public identification marker (off by default). A named
// callback rather than a closure, so `remove_action` works for anyone who
// enables it and then wants it gone from one template.
add_action( 'wp_head', [ 'WPS_Public_Marker', 'render' ] );
add_action( 'rest_api_init', [ 'WPS_Csp', 'register_rest' ] );

add_action( 'wps_hourly_scan', function (): void {
	// notify_admin for critical findings is handled inside WPS_Scanner::run().
	WPS_Scanner::run();
} );

//  Hook registration

// 1.4.6: self-protection wiring.
//   - import anything the must-use guard recorded while the plugin was not
//     running, so those events reach the tamper-evident chained log;
//   - re-assert expected state and reinstall the guard if it went missing,
//     which makes deleting the guard a temporary win rather than a permanent
//     one for as long as the plugin itself still runs;
//   - watch active_plugins for removals no administrator requested.
// Throttled to once every fifteen minutes: this touches the filesystem and
// must not add that cost to every page load.
add_action( 'init', function (): void {
	if ( get_transient( 'wps_guard_tick' ) ) {
		return;
	}
	set_transient( 'wps_guard_tick', 1, 900 );

	// 1.4.15: the must-use tamper guard is withdrawn. All that remains is a
	// one-time cleanup, which is cheap after the first run - a single option
	// read - and version-keyed so a downgrade-then-upgrade still tidies up.
	WPS_Guard::maybe_purge();
}, 5 );


// 1.4.7: EDR Phase 1 - behavioural hooks. Registered before the admin hooks
// so a login or account change is recorded even on requests that never reach
// an admin screen.
wps_boot( 'edr', static function (): void { WPS_EDR::register_hooks(); } );
wps_boot( 'login-guard', static function (): void { WPS_Login_Guard::register_hooks(); } );
// 1.4.70: block external REST/XML-RPC post writes (auto-blogging / doorway-spam
// injection). Opt-in - it can break legitimate headless or integration
// publishing - so the module registers nothing unless enabled.
wps_boot( 'post-guard', static function (): void { WPS_Post_Guard::register_hooks(); } );
// 1.4.43: refuse outbound requests carrying session cookies. Registered at
// priority 1 so it runs before anything that might short-circuit the filter.
wps_boot( 'outbound-guard', static function (): void {
	add_filter( 'pre_http_request', [ 'WPS_Blocker', 'guard_outbound_request' ], 1, 3 );
} );

} // end: not in safe mode

// Admin screens and the AJAX remediation controller register nothing that can
// fire outside an admin context - admin_menu, admin_enqueue_scripts,
// admin_post_*, wp_ajax_* - and both admin-ajax.php and admin-post.php report
// is_admin() as true. Loading them on front-end requests bought nothing and
// cost 93 KB.
if ( is_admin() ) {
	if ( wps_safe_mode() ) {
		// Admin screens are the most likely place for a crash, so in safe mode
		// they are not registered at all. The notice below is the entire admin
		// surface until the operator clears it.
		add_action(
			'admin_notices',
			static function (): void {
				if ( ! current_user_can( 'activate_plugins' ) ) {
					return;
				}
				$rec = get_option( WPS_FATAL_OPTION, [] );
				if ( ! is_array( $rec ) ) {
					$rec = [];
				}
				$url = wp_nonce_url(
					admin_url( 'admin-post.php?action=wps_clear_safe_mode' ),
					'wps_clear_safe_mode'
				);
				echo '<div class="notice notice-error"><p><strong>WP Perf Shield is in safe mode.</strong> ';
				echo 'A fatal error inside the plugin ended the previous request, so scanning, remediation and the admin screens have been switched off to keep this site running. Nothing is being scanned while this notice is showing.</p>';
				echo '<p><code>' . esc_html( (string) ( $rec['file'] ?? 'unknown file' ) ) . ':' . (int) ( $rec['line'] ?? 0 ) . '</code><br>';
				echo esc_html( (string) ( $rec['message'] ?? '' ) ) . '<br>';
				echo '<em>' . esc_html( (string) ( $rec['when'] ?? '' ) ) . ', ' . esc_html( (string) ( $rec['context'] ?? '' ) ) . ' request</em></p>';
				echo '<p><a class="button button-primary" href="' . esc_url( $url ) . '">Clear safe mode and try again</a> ';
				echo '<span class="description">Upgrading the plugin also clears it automatically.</span></p></div>';
			}
		);
		add_action(
			'admin_post_wps_clear_safe_mode',
			static function (): void {
				if ( ! current_user_can( 'activate_plugins' ) ) {
					wp_die( 'Insufficient permissions.' );
				}
				check_admin_referer( 'wps_clear_safe_mode' );
				delete_option( WPS_FATAL_OPTION );
				wp_safe_redirect( admin_url() );
				exit;
			}
		);
	} else {
		wps_boot( 'admin', static function (): void { WPS_Admin::register_hooks(); } );
		wps_boot( 'remediation', static function (): void { WPS_Remediation_Controller::register_hooks(); } );
	}
}
