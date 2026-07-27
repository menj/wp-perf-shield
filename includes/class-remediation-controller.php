<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * WPS_Remediation_Controller  registration and entry points for every
 * `wp_ajax_wps_*` action exposed by the admin UI. Extracted from
 * wp-perf-shield.php in Phase 2 so the bootstrap file no longer carries
 * thousand-line inline closures.
 *
 * Action names, nonce, and DOM IDs are unchanged. The wired admin JavaScript
 * in `assets/js/admin.js` continues to call `action: 'wps_X'` exactly as
 * before; only the PHP-side dispatch has moved.
 */
class WPS_Remediation_Controller {

	/**
	 * Register every AJAX action exposed by this controller. Called once from
	 * the bootstrap file at plugin load time.
	 */
	public static function register_hooks(): void {
		$actions = [
			'wps_run_scan'              => 'run_scan',
			'wps_clear_log'             => 'clear_log',
			'wps_clear_ip_blocks'       => 'clear_ip_blocks',
			'wps_rebaseline_wpconfig'   => 'rebaseline_wpconfig',
			'wps_clean_wpconfig'        => 'clean_wpconfig',
			'wps_run_forensics'         => 'run_forensics',
			'wps_delete_exfil'          => 'delete_exfil',
			'wps_clean_login'           => 'clean_login',
			'wps_clean_functions'       => 'clean_functions',
			'wps_clean_cron'            => 'clean_cron',
			'wps_delete_db_options'     => 'delete_db_options',
			'wps_hardening_status'      => 'hardening_status',
			'wps_wpconfig_constant'     => 'wpconfig_constant',
			'wps_htaccess_rule'         => 'htaccess_rule',
			'wps_clear_transients'      => 'clear_transients',
			'wps_invalidate_sessions'   => 'invalidate_sessions',
			'wps_regenerate_salts'      => 'regenerate_salts',
			'wps_delete_user'           => 'delete_user',
			'wps_delete_attachment'     => 'delete_attachment',
			'wps_delete_plugin_folder'  => 'delete_plugin_folder',
			'wps_delete_single_option'  => 'delete_single_option',
			'wps_delete_unknown_b64'    => 'delete_unknown_b64_option', // 1.3.40
			'wps_delete_all_unknown_b64' => 'delete_all_unknown_b64_options', // 1.3.85
			'wps_delete_file'           => 'delete_file',
			'wps_delete_theme_file'     => 'delete_theme_file',
			'wps_quarantine_restore'    => 'quarantine_restore',   // 1.3.94
			'wps_quarantine_purge'      => 'quarantine_purge',     // 1.3.94
			'wps_quarantine_empty'      => 'quarantine_empty',     // 1.3.94
			'wps_export_diagnostics'    => 'export_diagnostics',
			// 1.3.67: surgical-edit handlers for the auto_prepend_file hijack
			// chain. Each handler operates on a single hard-coded file
			// (wordfence-waf.php at ABSPATH or .user.ini at ABSPATH) and
			// removes a specific line identified by the offending value
			// passed in the POST body. Backup-on-edit + atomic-write
			// + post-write verification.
			'wps_clean_wfwaf_include'   => 'clean_wfwaf_include',
			'wps_clean_user_ini_prepend' => 'clean_user_ini_prepend',
			'wps_rebaseline_dropins'    => 'rebaseline_dropins', // 1.3.71
			'wps_rebaseline_php_inventory' => 'rebaseline_php_inventory', // 1.3.87
			'wps_log_inspect'           => 'log_inspect',        // 1.3.73
			'wps_csp'                   => 'csp',                // 1.3.76
		];

		foreach ( $actions as $action => $method ) {
			add_action( 'wp_ajax_' . $action, [ self::class, $method ] );
		}
	}

	//  Read-only and log handlers

	public static function run_scan(): void {
		WPS_Utils::guard_request( 'manage_options' );
		wp_send_json_success( WPS_Scanner::run( true ) );
	}

	public static function clear_log(): void {
		WPS_Utils::guard_request( 'manage_options' );
		WPS_Utils::enforce_cooldown( 'clear_log' );
		WPS_Logger::clear();
		wp_send_json_success();
	}

	public static function clear_ip_blocks(): void {
		WPS_Utils::guard_request( 'manage_options' );
		WPS_Utils::enforce_cooldown( 'clear_ip_blocks' );
		WPS_Blocker::clear_blocked_ips();
		WPS_Logger::log_event( 'ip_blocks_cleared', 'Hostile IP auto-block list cleared manually' );
		wp_send_json_success();
	}

	public static function run_forensics(): void {
		WPS_Utils::guard_request( 'manage_options' );
		$report = WPS_Forensics::run();
		update_option( 'wps_forensics_report', $report );
		wp_send_json_success( $report );
	}

	public static function hardening_status(): void {
		WPS_Utils::guard_request( 'manage_options' );
		wp_send_json_success( WPS_Hardening::get_status() );
	}

	//  wp-config.php baseline / cleanup

	public static function rebaseline_wpconfig(): void {
		WPS_Utils::guard_request( 'update_core' );
		$config = rtrim( ABSPATH, '/\\' ) . '/wp-config.php';
		if ( ! file_exists( $config ) ) {
			wp_send_json_error( [ 'error' => 'wp-config.php not found' ] );
			return;
		}
		$hash = hash_file( 'sha256', $config );
		if ( $hash === false ) {
			wp_send_json_error( [ 'error' => 'Could not hash wp-config.php' ] );
			return;
		}
		update_option( 'wps_wpconfig_hash', $hash );
		delete_transient( 'wps_scan_results' );
		WPS_Logger::log_event( 'wp_config_hash_stored', 'Baseline manually reset. SHA-256: ' . substr( $hash, 0, 16 ) . '' );
		wp_send_json_success( [ 'hash' => substr( $hash, 0, 16 ) . '' ] );
	}

	/**
	 * 1.3.71: accept the current drop-in state as the new clean baseline.
	 * Mirrors rebaseline_wpconfig(). Does not modify any drop-in file; it only
	 * re-stores the integrity reference so legitimate changes stop being flagged.
	 */
	public static function rebaseline_dropins(): void {
		WPS_Utils::guard_request( 'update_core' );
		if ( ! class_exists( 'WPS_Dropin_Guard' ) ) {
			wp_send_json_error( [ 'error' => 'Drop-in guard unavailable.' ] );
			return;
		}
		$state = WPS_Dropin_Guard::rebaseline();
		wp_send_json_success( [ 'count' => count( $state ) ] );
	}

	/**
	 * 1.3.87: Re-establish the PHP-inventory drift baseline (uploads / mu-plugins).
	 * Use after a confirmed cleanup so the current, clean set of PHP files becomes
	 * the new reference. Does not modify any file; it only re-captures hashes.
	 */
	public static function rebaseline_php_inventory(): void {
		WPS_Utils::guard_request( 'update_core' );
		if ( ! class_exists( 'WPS_Scanner' ) || ! method_exists( 'WPS_Scanner', 'establish_php_inventory_baseline' ) ) {
			wp_send_json_error( [ 'error' => 'PHP-inventory baseline unavailable.' ] );
			return;
		}
		$count = WPS_Scanner::establish_php_inventory_baseline();
		delete_transient( 'wps_scan_results' );
		wp_send_json_success( [ 'message' => 'PHP-inventory baseline re-established (' . $count . ' files).', 'count' => $count ] );
	}

	/**
	 * 1.3.73: read-only server-log inspector. Modes: "scanall" greps every
	 * discovered log for campaign IOCs; "tail" returns the tail of one log;
	 * "iocscan" returns only the IOC-matching lines of one log. Any path is
	 * re-validated through WPS_Log_Reader::is_safe_log() before it is opened,
	 * so a request cannot point the reader at an arbitrary file. Lines are
	 * returned raw; the admin JS renders them with textContent, never as HTML.
	 */
	public static function log_inspect(): void {
		WPS_Utils::guard_request( 'manage_options' );
		if ( ! class_exists( 'WPS_Log_Reader' ) ) {
			wp_send_json_error( [ 'error' => 'Log reader unavailable.' ] );
			return;
		}
		$mode = isset( $_POST['mode'] ) ? sanitize_key( wp_unslash( $_POST['mode'] ) ) : 'scanall';

		if ( $mode === 'scanall' ) {
			wp_send_json_success( [ 'results' => WPS_Log_Reader::scan_all() ] );
			return;
		}

		if ( $mode === 'loginscanall' ) {
			wp_send_json_success( [ 'results' => WPS_Log_Reader::scan_login_posts_all() ] );
			return;
		}

		$path = isset( $_POST['path'] ) ? wp_unslash( $_POST['path'] ) : '';
		if ( ! WPS_Log_Reader::is_safe_log( $path ) ) {
			wp_send_json_error( [ 'error' => 'Path is not a readable log under an allowed location.' ] );
			return;
		}

		if ( $mode === 'iocscan' ) {
			wp_send_json_success( [ 'hits' => WPS_Log_Reader::scan( $path ) ] );
			return;
		}

		// Default: tail.
		wp_send_json_success( [ 'lines' => WPS_Log_Reader::tail( $path ) ] );
	}

	/**
	 * 1.3.76: save CSP settings or clear the violation-report buffer.
	 * Modes: "save" (mode + policy), "clear" (empty the report ring buffer).
	 */
	public static function csp(): void {
		WPS_Utils::guard_request( 'manage_options' );
		if ( ! class_exists( 'WPS_Csp' ) ) {
			wp_send_json_error( [ 'error' => 'CSP module unavailable.' ] );
			return;
		}
		$op = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : 'save';

		if ( $op === 'clear' ) {
			WPS_Csp::clear_reports();
			wp_send_json_success( [ 'cleared' => true ] );
			return;
		}

		$mode   = isset( $_POST['mode'] ) ? sanitize_key( wp_unslash( $_POST['mode'] ) ) : 'off';
		$policy = isset( $_POST['policy'] ) ? wp_unslash( $_POST['policy'] ) : '';
		$saved  = WPS_Csp::save( $mode, (string) $policy );
		wp_send_json_success( $saved );
	}

	public static function clean_wpconfig(): void {
		WPS_Utils::guard_request( 'update_core' );
		WPS_Utils::enforce_cooldown( 'clean_wpconfig' );

		$result = WPS_Hardening::clean_wpconfig_malware();
		if ( ! is_array( $result ) ) {
			wp_send_json_error( [ 'error' => $result ] );
			return;
		}

		if ( empty( $result['changed'] ) ) {
			WPS_Logger::log_event( 'wp_config_clean_skipped', 'No known removable wp-config.php malware patterns found' );
			wp_send_json_success( [
				'message' => $result['message'] ?? 'No known removable wp-config.php malware patterns were found.',
				'removed' => [],
			] );
			return;
		}

		$removed = is_array( $result['removed'] ?? null ) ? $result['removed'] : [];
		$labels = [];
		foreach ( $removed as $item ) {
			if ( is_array( $item ) && ! empty( $item['label'] ) ) {
				$labels[] = (string) $item['label'];
			}
		}
		$labels = array_values( array_unique( $labels ) );
		WPS_Logger::log_event(
			'wp_config_cleaned',
			'Removed ' . count( $removed ) . ' pattern(s); backup=' . (string) ( $result['backup'] ?? '' ) . '; labels=' . implode( ', ', $labels )
		);

		wp_send_json_success( [
			'message' => ( $result['message'] ?? 'wp-config.php cleaned.' ) . ' Backup: ' . (string) ( $result['backup'] ?? '' ),
			'removed' => $removed,
			'backup'  => (string) ( $result['backup'] ?? '' ),
			'hash'    => ! empty( $result['hash'] ) ? substr( (string) $result['hash'], 0, 16 ) : '',
		] );
	}

	//  Exfil credential file

	public static function delete_exfil(): void {
		WPS_Utils::guard_request( 'delete_posts' );
		WPS_Utils::enforce_cooldown( 'delete_exfil' );

		$upload_dir  = wp_upload_dir();
		$base        = $upload_dir['basedir'] ?? '';
		$exfil_names = WPS_Indicators::exfil_filenames();
		$deleted     = [];
		$failed      = [];
		$files_info  = [];

		if ( $base && is_dir( $base ) ) {
			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $base, FilesystemIterator::SKIP_DOTS )
				);
				foreach ( $iter as $file ) {
					if ( ! ( $file instanceof SplFileInfo ) ) continue;
					if ( ! in_array( $file->getFilename(), $exfil_names, true ) ) continue;

					// Path containment: confirm the resolved path is inside the
					// uploads base before any read or unlink. RecursiveDirectoryIterator
					// doesn't follow symlinks by default, but make this explicit.
					$real = WPS_Utils::guard_path( $file->getPathname(), $base );
					if ( ! $real ) {
						WPS_Logger::log_event( 'exfil_skipped_outside_uploads', basename( $file->getPathname() ) );
						continue;
					}
					if ( is_link( $real ) ) {
						// Refuse to follow symlinks under uploads.
						WPS_Logger::log_event( 'exfil_skipped_symlink', basename( $real ) );
						continue;
					}

					// Count credential lines for the log entry only.
					// Do NOT return file contents to the browser  even an admin
					// viewing the AJAX network tab should not see harvested logins.
					$lines_count = 0;
					$handle = @fopen( $real, 'r' );
					if ( $handle ) {
						while ( ! feof( $handle ) ) {
							if ( fgets( $handle ) !== false ) {
								$lines_count++;
							}
						}
						fclose( $handle );
					}

					if ( $lines_count > 0 ) {
						WPS_Logger::log_event(
							'exfil_file_read',
							basename( $real ) . ' (' . $lines_count . ' credential line(s) before deletion)'
						);
					}

					$rel_path = str_replace( ABSPATH, '', $real );
					if ( @unlink( $real ) ) {
						$deleted[]    = $rel_path;
						$files_info[] = [
							'file'  => $rel_path,
							'lines' => $lines_count,
						];
						WPS_Logger::log_event( 'exfil_file_deleted', $rel_path );
					} else {
						$failed[] = basename( $real );
						WPS_Logger::log_event( 'exfil_delete_failed', basename( $real ) );
					}
				}
			} catch ( \Exception $e ) {
				wp_send_json_error( [ 'error' => 'Iterator failure during exfil sweep.' ] );
				return;
			}
		}

		wp_send_json_success( [
			'deleted' => $deleted,
			'failed'  => $failed,
			'files'   => $files_info,
			'message' => empty( $deleted )
				? ( empty( $failed ) ? 'No exfil files found on disk.' : count( $failed ) . ' exfil file(s) found but could not be deleted check file permissions.' )
				: count( $deleted ) . ' exfil file(s) deleted. Line counts logged to events; contents are not returned to the browser.',
		] );
	}

	//  wp-login.php / functions.php / wp-cron.php cleaners

	public static function clean_login(): void {
		WPS_Utils::guard_request( 'update_core' );
		WPS_Utils::enforce_cooldown( 'clean_login' );

		$login_file = ABSPATH . 'wp-login.php';
		if ( ! file_exists( $login_file ) ) {
			wp_send_json_error( [ 'error' => 'wp-login.php not found' ] );
			return;
		}

		$contents = @file_get_contents( $login_file );
		if ( ! $contents ) {
			wp_send_json_error( [ 'error' => 'Could not read wp-login.php' ] );
			return;
		}

		// Injection marker if not present, already clean
		if ( strpos( $contents, 'd3AtY29udGVudC91cGxvYWRz' ) === false ) {
			wp_send_json_success( [ 'message' => 'wp-login.php is already clean no injection found.' ] );
			return;
		}

		// The injected block starts with "// WordPress Session Cache Handler"
		// and ends before the next line that was originally there.
		// Pattern: remove the injected PHP block using its known delimiters.
		$patterns = [
			// Site-specific credential-harvester marker block
			"/\n\\/\\/ WordPress Session Cache Handler\nif\\(!is_wp_error[^\n]+\n(?:[^\n]+\n)*?[^\n]*FILE_APPEND\\);\n\\}\n/",
			// Generic fallback any block containing the marker
			"/\n\\/\\/ WordPress Session Cache Handler.*?FILE_APPEND\\);\n\\}\n/s",
		];

		$cleaned = $contents;
		foreach ( $patterns as $pattern ) {
			$result = preg_replace( $pattern, "\n", $cleaned );
			if ( $result && $result !== $cleaned ) {
				$cleaned = $result;
				break;
			}
		}

		if ( $cleaned === $contents ) {
			// Pattern didn't match download a clean copy from wordpress.org
			global $wp_version;
			if ( ! isset( $wp_version ) ) {
				@include ABSPATH . 'wp-includes/version.php';
			}
			// WPSEC-005 (1.3.57): validate $wp_version is version-shaped
			// before interpolating into a remote URL. Defends against
			// path-traversal in the URL if version.php is ever compromised
			// (which would already imply filesystem write, but the validation
			// is cheap defense-in-depth).
			if ( isset( $wp_version ) && preg_match( '/^\d+\.\d+(\.\d+)?$/', (string) $wp_version ) ) {
				$clean_url = "https://raw.githubusercontent.com/WordPress/WordPress/{$wp_version}/wp-login.php";
				$remote = WPS_Utils::fetch_remote_file( $clean_url );
				if ( is_wp_error( $remote ) ) {
					WPS_Logger::log_event( 'remote_fetch_failed', $remote->get_error_message() );
					$remote = '';
				}
				if ( $remote && strlen( $remote ) > 4000 && strpos( $remote, 'd3AtY29udGVudC91cGxvYWRz' ) === false ) {
					$cleaned = $remote;
				}
			}
			if ( $cleaned === $contents ) {
				wp_send_json_error( [ 'error' => 'Could not automatically remove injection. Replace wp-login.php manually from a fresh WordPress download.' ] );
				return;
			}
		}

		$backup = WPS_Utils::create_timestamped_backup( $login_file );
		if ( is_wp_error( $backup ) ) {
			wp_send_json_error( [ 'error' => $backup->get_error_message() ] );
			return;
		}

		// Write atomically
		$tmp = $login_file . '.wps_tmp';
		if ( @file_put_contents( $tmp, $cleaned ) && @rename( $tmp, $login_file ) ) {
			WPS_Logger::log_event( 'login_cleaned', 'wp-login.php credential harvester injection removed backup=' . $backup );
			wp_send_json_success( [ 'message' => 'wp-login.php cleaned successfully injection removed. Backup saved as ' . WPS_Utils::backup_location_label( $backup ) . '.' ] );
		} else {
			@unlink( $tmp );
			wp_send_json_error( [ 'error' => 'Could not write cleaned wp-login.php check file permissions.' ] );
		}
	}

	public static function clean_functions(): void {
		WPS_Utils::guard_request( 'edit_themes' );
		WPS_Utils::enforce_cooldown( 'clean_functions' );

		// 1.3.62 (DOC-20260508-001): scan BOTH parent theme and child theme
		// functions.php. Previously this method only inspected
		// get_template_directory() . '/functions.php', which on a site running
		// a child theme resolves to the PARENT theme's file. The credential-
		// harvester injection delivered by the wp-locale-handler RAT v1.7
		// family lands in whichever theme functions.php WordPress treats as
		// active when the malicious payload runs, so on child-theme sites the
		// injection persists in the child's functions.php and the cleanup was
		// missing it. The fix: take the union of get_template_directory() and
		// get_stylesheet_directory(), de-duplicate (when no child theme is
		// active both return the same path), and walk each one independently.
		// All paths must exist; if neither has functions.php the operator
		// is told that explicitly. A theme with the injection on EITHER file
		// gets it cleaned; a clean run reports which files were already
		// clean and which were cleaned.
		$theme_files = array_values( array_unique( array_filter( [
			get_template_directory()   . '/functions.php',
			get_stylesheet_directory() . '/functions.php',
		], 'file_exists' ) ) );

		if ( empty( $theme_files ) ) {
			wp_send_json_error( [ 'error' => 'functions.php not found for active theme or child theme.' ] );
			return;
		}

		$results        = [];
		$cleaned_any    = false;
		$failed_any     = false;
		$injection_marker = 'd3AtY29udGVudC91cGxvYWRz';

		foreach ( $theme_files as $funcs ) {
			$contents = @file_get_contents( $funcs );
			if ( $contents === false || $contents === '' ) {
				$results[]  = basename( dirname( $funcs ) ) . ': could not read functions.php';
				$failed_any = true;
				continue;
			}

			if ( strpos( $contents, $injection_marker ) === false ) {
				$results[] = basename( dirname( $funcs ) ) . ': already clean';
				continue;
			}

			$cleaned = preg_replace(
				"/\n\\/\\/ WordPress session analytics\nadd_filter\\('authenticate'.*?FILE_APPEND\\);\n\\s*\\}\n\\s*return \\\$u;\n\\},\\s*999,\\s*3\\);\n/s",
				"\n",
				$contents
			);

			if ( ! $cleaned || $cleaned === $contents ) {
				$results[]  = basename( dirname( $funcs ) ) . ': injection present but pattern did not match  remove the "WordPress session analytics" block manually';
				$failed_any = true;
				continue;
			}

			$backup = WPS_Utils::create_timestamped_backup( $funcs );
			if ( is_wp_error( $backup ) ) {
				$results[]  = basename( dirname( $funcs ) ) . ': could not create backup - ' . $backup->get_error_message();
				$failed_any = true;
				continue;
			}

			$tmp = $funcs . '.wps_tmp';
			if ( @file_put_contents( $tmp, $cleaned ) && @rename( $tmp, $funcs ) ) {
				$results[]   = basename( dirname( $funcs ) ) . ': cleaned (backup ' . WPS_Utils::backup_location_label( $backup ) . ')';
				$cleaned_any = true;
				WPS_Logger::log_event( 'functions_cleaned', 'functions.php credential harvester removed from ' . basename( dirname( $funcs ) ) . ' backup=' . $backup );
			} else {
				@unlink( $tmp );
				$results[]  = basename( dirname( $funcs ) ) . ': could not write cleaned file  check file permissions';
				$failed_any = true;
			}
		}

		if ( $failed_any ) {
			wp_send_json_error( [ 'error' => 'Cleanup completed with failures: ' . implode( '; ', $results ) ] );
			return;
		}

		if ( ! $cleaned_any ) {
			wp_send_json_success( [ 'message' => 'functions.php is already clean no injection found across ' . count( $theme_files ) . ' theme file(s).' ] );
			return;
		}

		wp_send_json_success( [ 'message' => 'functions.php cleaned: ' . implode( '; ', $results ) ] );
	}

	public static function clean_cron(): void {
		WPS_Utils::guard_request( 'update_core' );
		WPS_Utils::enforce_cooldown( 'clean_cron' );

		$cron_file = ABSPATH . 'wp-cron.php';

		// Detect WP version
		global $wp_version;
		if ( ! isset( $wp_version ) ) {
			@include ABSPATH . 'wp-includes/version.php';
		}
		if ( empty( $wp_version ) ) {
			wp_send_json_error( [ 'error' => 'Could not detect WordPress version. Replace wp-cron.php manually.' ] );
			return;
		}
		// WPSEC-005 (1.3.57): validate $wp_version before interpolating
		// into remote URLs. Same rationale as clean_login above.
		if ( ! preg_match( '/^\d+\.\d+(\.\d+)?$/', (string) $wp_version ) ) {
			wp_send_json_error( [ 'error' => 'WordPress version string is malformed; refusing to construct remote URL. Replace wp-cron.php manually.' ] );
			return;
		}

		// Try official WordPress SVN first, then GitHub mirrors.
		$urls = [
			"https://core.svn.wordpress.org/tags/{$wp_version}/wp-cron.php",
			"https://raw.githubusercontent.com/WordPress/WordPress/{$wp_version}/wp-cron.php",
			"https://raw.githubusercontent.com/WordPress/wordpress-develop/{$wp_version}/src/wp-cron.php",
		];

		$clean = null;
		$failures = [];
		foreach ( $urls as $url ) {
			$response = WPS_Utils::fetch_remote_file( $url );
			if ( is_wp_error( $response ) ) {
				WPS_Logger::log_event( 'remote_fetch_failed', $response->get_error_message() );
				$failures[] = $url . ' => ' . $response->get_error_message();
				continue;
			}
			if ( WPS_Utils::is_clean_wp_cron( $response ) ) {
				$clean = $response;
				break;
			}
			$failures[] = $url . ' => downloaded file failed wp-cron.php sanity checks';
		}

		if ( ! $clean ) {
			wp_send_json_error( [ 'error' => "Could not download a valid clean wp-cron.php for WP {$wp_version}. Tried: " . implode( ' | ', $failures ) ] );
			return;
		}

		// Atomic write with a local backup of the current file.
		$tmp    = $cron_file . '.wps_tmp';
		$backup = file_exists( $cron_file ) ? WPS_Utils::create_timestamped_backup( $cron_file ) : '';
		if ( is_wp_error( $backup ) ) {
			wp_send_json_error( [ 'error' => $backup->get_error_message() ] );
			return;
		}

		if ( @file_put_contents( $tmp, $clean ) && @rename( $tmp, $cron_file ) ) {
			WPS_Logger::log_event( 'cron_replaced', "wp-cron.php replaced with clean copy for WP {$wp_version} backup={$backup}" );
			delete_transient( 'wps_scan_results' ); // Force rescan
			delete_option( 'wps_forensics_report' ); // Force forensics refresh after wp-cron.php changes
			$backup_msg = is_string( $backup ) && $backup !== '' ? ' Backup saved as ' . WPS_Utils::backup_location_label( $backup ) . '.' : '';
			wp_send_json_success( [ 'message' => "wp-cron.php replaced successfully with clean WP {$wp_version} version." . $backup_msg ] );
		} else {
			@unlink( $tmp );
			wp_send_json_error( [ 'error' => 'Could not write wp-cron.php check file permissions.' ] );
		}
	}

	//  DB option cleanup

	public static function delete_db_options(): void {
		WPS_Utils::guard_request( 'manage_options' );
		WPS_Utils::enforce_cooldown( 'delete_db_options' );

		// Full list of known malware-set options from reverse-engineering this campaign.
		// wp_session_tokens_config is the most critical: the RAT reads it and uses it
		// to restore mu-plugins/session-manager.php on every request (mode 'r').
		// Deleting the file without this option is pointless the RAT self-heals.
		$bad_options = WPS_Indicators::malware_option_keys();

		$deleted   = [];
		$not_found = [];

		foreach ( $bad_options as $opt ) {
			if ( get_option( $opt, null ) !== null ) {
				$snapshot_id = null;
				if ( WPS_Scanner::quarantine_enabled() && class_exists( 'WPS_Quarantine' ) ) {
					$snapshot_id = WPS_Quarantine::quarantine_option( $opt, [ 'type' => 'db_option (known-bad key)', 'reason' => 'manual bulk delete of known-bad options' ] );
				}
				delete_option( $opt );
				WPS_Event_Log::audit( 'db_option_deleted', [
					'object_type' => 'wp_option',
					'object_name' => $opt,
					'original'    => $snapshot_id ? 'quarantine snapshot ' . $snapshot_id : 'not snapshotted (quarantine off)',
					'new'         => 'deleted',
					'reason'      => 'manual bulk delete of known-bad options',
					'risk'        => 40,
				] );
				// Verify deletion
				if ( get_option( $opt, null ) === null ) {
					$deleted[] = $opt;
					WPS_Logger::log_event( 'db_option_deleted', $opt );
				}
			} else {
				$not_found[] = $opt;
			}
		}

		// Also purge any suspicious cron events injected by the malware
		$crons        = _get_cron_array();
		$purged_crons = [];
		if ( is_array( $crons ) ) {
			foreach ( $crons as $timestamp => $hooks ) {
				foreach ( $hooks as $hook => $args ) {
					$lower = strtolower( $hook );
					foreach ( WPS_Indicators::malicious_cron_hook_substrings() as $bad ) {
						if ( strpos( $lower, $bad ) !== false ) {
							wp_unschedule_hook( $hook );
							$purged_crons[] = $hook;
							WPS_Logger::log_event( 'cron_purged', $hook );
						}
					}
				}
			}
		}

		delete_transient( 'wps_scan_results' ); // Force rescan
		delete_option( 'wps_forensics_report' ); // Clear stale option-anomaly rows after cleanup

		$msg_parts = [];
		if ( $deleted ) {
			$msg_parts[] = count( $deleted ) . ' malicious DB option(s) deleted';
		}
		if ( $purged_crons ) {
			$msg_parts[] = count( $purged_crons ) . ' malicious cron hook(s) removed';
		}
		if ( ! $deleted && ! $purged_crons ) {
			$msg_parts[] = 'No malicious options or cron hooks found database is clean';
		}

		wp_send_json_success( [
			'message'      => implode( '; ', $msg_parts ) . '.',
			'deleted'      => $deleted,
			'not_found'    => $not_found,
			'purged_crons' => $purged_crons,
		] );
	}

	/**
	 * 1.3.94: restore a quarantined entry to its original path.
	 */
	public static function quarantine_restore(): void {
		WPS_Utils::guard_request( 'manage_options' );
		WPS_Utils::enforce_cooldown( 'quarantine_restore' );
		$id = sanitize_text_field( wp_unslash( $_POST['quarantine_id'] ?? '' ) );
		if ( $id === '' || ! class_exists( 'WPS_Quarantine' ) ) {
			wp_send_json_error( [ 'error' => 'No quarantine id provided.' ] );
			return;
		}
		if ( WPS_Quarantine::restore( $id ) ) {
			wp_send_json_success( [ 'message' => 'Restored to its original location.' ] );
			return;
		}
		wp_send_json_error( [ 'error' => 'Restore failed: the original path may be occupied again, or the entry no longer exists.' ] );
	}

	/**
	 * 1.3.94: permanently delete one quarantined entry.
	 */
	public static function quarantine_purge(): void {
		WPS_Utils::guard_request( 'manage_options' );
		WPS_Utils::enforce_cooldown( 'quarantine_purge' );
		$id = sanitize_text_field( wp_unslash( $_POST['quarantine_id'] ?? '' ) );
		if ( $id === '' || ! class_exists( 'WPS_Quarantine' ) ) {
			wp_send_json_error( [ 'error' => 'No quarantine id provided.' ] );
			return;
		}
		if ( WPS_Quarantine::purge( $id ) ) {
			wp_send_json_success( [ 'message' => 'Permanently deleted.' ] );
			return;
		}
		wp_send_json_error( [ 'error' => 'Purge failed.' ] );
	}

	/**
	 * 1.3.94: empty the quarantine store.
	 */
	public static function quarantine_empty(): void {
		WPS_Utils::guard_request( 'manage_options' );
		WPS_Utils::enforce_cooldown( 'quarantine_empty', 30 );
		if ( ! class_exists( 'WPS_Quarantine' ) ) {
			wp_send_json_error( [ 'error' => 'Quarantine unavailable.' ] );
			return;
		}
		$n = WPS_Quarantine::purge_all();
		wp_send_json_success( [ 'message' => $n . ' ' . ( $n === 1 ? 'entry' : 'entries' ) . ' permanently deleted.' ] );
	}

	public static function delete_single_option(): void {
		WPS_Utils::guard_request( 'manage_options' );
		WPS_Utils::enforce_cooldown( 'delete_single_option' );

		$option_name = sanitize_key( wp_unslash( $_POST['option_name'] ?? '' ) );
		if ( ! $option_name ) {
			wp_send_json_error( [ 'error' => 'No option name provided.' ] );
			return;
		}

		// Safety: only allow deletion of known malicious keys never core WP options
		if ( ! in_array( $option_name, WPS_Indicators::malware_option_keys(), true ) ) {
			wp_send_json_error( [ 'error' => 'Option "' . $option_name . '" is not on the allowed-delete list.' ] );
			return;
		}

		if ( get_option( $option_name, null ) === null ) {
			wp_send_json_success( [ 'message' => '"' . $option_name . '" not found already deleted.' ] );
			return;
		}

		$snapshot_id = null;
		if ( WPS_Scanner::quarantine_enabled() && class_exists( 'WPS_Quarantine' ) ) {
			$snapshot_id = WPS_Quarantine::quarantine_option( $option_name, [ 'type' => 'db_option (known-bad key)', 'reason' => 'manual delete of known-bad option' ] );
		}
		delete_option( $option_name );
		WPS_Event_Log::audit( 'db_option_deleted', [
			'object_type' => 'wp_option',
			'object_name' => $option_name,
			'original'    => $snapshot_id ? 'quarantine snapshot ' . $snapshot_id : 'not snapshotted (quarantine off)',
			'new'         => 'deleted',
			'reason'      => 'manual delete of known-bad option',
			'risk'        => 40,
		] );

		// Verify it's gone
		if ( get_option( $option_name, null ) !== null ) {
			wp_send_json_error( [ 'error' => 'delete_option() call did not remove "' . $option_name . '" check DB permissions.' ] );
			return;
		}

		WPS_Logger::log_event( 'db_option_deleted', $option_name );
		delete_transient( 'wps_scan_results' );
		delete_option( 'wps_forensics_report' );
		wp_send_json_success( [ 'message' => 'Deleted: ' . $option_name ] );
	}

	/**
	 * Delete a wp_options row that was flagged by the 1.3.40
	 * unknown-base64-option Forensics check.
	 *
	 * Differs from delete_single_option() in its safety gate: instead of
	 * requiring the option name to be on the static known-malware list, it
	 * requires the option name to appear in the most recent cached forensics
	 * report's `unknown_base64_options` finding set. That guarantees the
	 * caller has actually seen Forensics flag this option AND that the
	 * structural fingerprint (decoded PHP payload or ClickFix JS shape)
	 * still matches  no synthetic POST can talk this handler into deleting
	 * `siteurl` or any other core option.
	 */
	public static function delete_unknown_b64_option(): void {
		WPS_Utils::guard_request( 'manage_options' );
		WPS_Utils::enforce_cooldown( 'delete_unknown_b64_option' );

		$option_name = sanitize_key( wp_unslash( $_POST['option_name'] ?? '' ) );
		if ( ! $option_name ) {
			wp_send_json_error( [ 'error' => 'No option name provided.' ] );
			return;
		}

		// Hard refuse: never touch any name that contains a WordPress core
		// substring even if a synthetic forensics cache claimed otherwise.
		$core_protected = [ 'siteurl', 'home', 'blogname', 'admin_email', 'template', 'stylesheet', 'active_plugins', 'wp_user_roles', 'cron', 'rewrite_rules', 'db_version' ];
		foreach ( $core_protected as $protected ) {
			if ( $option_name === $protected ) {
				wp_send_json_error( [ 'error' => 'Refused: "' . $option_name . '" is a core WordPress option.' ] );
				return;
			}
		}

		// Require the option to currently appear in the cached forensics report.
		$report = get_option( 'wps_forensics_report', null );
		$flagged = is_array( $report ) ? ( $report['unknown_base64_options'] ?? [] ) : [];
		$is_flagged = false;
		if ( is_array( $flagged ) ) {
			foreach ( $flagged as $f ) {
				if ( is_array( $f ) && ( $f['option_name'] ?? '' ) === $option_name ) {
					$is_flagged = true;
					break;
				}
			}
		}
		if ( ! $is_flagged ) {
			wp_send_json_error( [ 'error' => 'Option "' . $option_name . '" is not in the current forensics report. Run forensics again, then retry.' ] );
			return;
		}

		if ( get_option( $option_name, null ) === null ) {
			wp_send_json_success( [ 'message' => '"' . $option_name . '" not found  already deleted.' ] );
			return;
		}

		$snapshot_id = null;
		if ( WPS_Scanner::quarantine_enabled() && class_exists( 'WPS_Quarantine' ) ) {
			$snapshot_id = WPS_Quarantine::quarantine_option( $option_name, [ 'type' => 'db_option (base64 payload)', 'reason' => 'manual delete of base64 payload option' ] );
		}
		delete_option( $option_name );
		WPS_Event_Log::audit( 'db_option_deleted', [
			'object_type' => 'wp_option',
			'object_name' => $option_name,
			'original'    => $snapshot_id ? 'quarantine snapshot ' . $snapshot_id : 'not snapshotted (quarantine off)',
			'new'         => 'deleted',
			'reason'      => 'manual delete of base64 payload option',
			'risk'        => 40,
		] );

		if ( get_option( $option_name, null ) !== null ) {
			wp_send_json_error( [ 'error' => 'delete_option() call did not remove "' . $option_name . '"  check DB permissions.' ] );
			return;
		}

		WPS_Logger::log_event( 'db_option_deleted_unknown_b64', $option_name );
		delete_transient( 'wps_scan_results' );

		// 1.3.84: keep the cached forensics report in sync instead of discarding
		// it. Remove only the just-deleted option from unknown_base64_options and
		// write the report back. Deleting the whole report here (as before) wiped
		// the validation basis for every sibling finding still shown on the page,
		// so the next "Delete now" in a batch failed with "not in the current
		// forensics report" until Forensics was re-run. The auto_prepend and cron
		// findings in the same report are left intact.
		if ( is_array( $report ) ) {
			if ( isset( $report['unknown_base64_options'] ) && is_array( $report['unknown_base64_options'] ) ) {
				$report['unknown_base64_options'] = array_values( array_filter(
					$report['unknown_base64_options'],
					static function ( $entry ) use ( $option_name ) {
						return ! ( is_array( $entry ) && ( $entry['option_name'] ?? '' ) === $option_name );
					}
				) );
			}
			update_option( 'wps_forensics_report', $report );
		}

		wp_send_json_success( [ 'message' => 'Deleted (unknown-base64-flagged): ' . $option_name ] );
	}

	/**
	 * 1.3.85: Bulk counterpart of delete_unknown_b64_option. Deletes every
	 * option in the cached forensics report's unknown_base64_options set in one
	 * request, so a site with dozens of confirmed ClickFix persistence options
	 * does not require dozens of individual clicks. Uses the same two safety
	 * gates as the single-option handler: the option must already be in the
	 * cached report (so a synthetic POST cannot enumerate arbitrary deletions),
	 * and core WordPress option names are always skipped. The report is spliced
	 * to retain only the entries that were not deleted, keeping it consistent for
	 * any subsequent action (same contract as the 1.3.84 single-delete fix).
	 */
	public static function delete_all_unknown_b64_options(): void {
		WPS_Utils::guard_request( 'manage_options' );
		WPS_Utils::enforce_cooldown( 'delete_all_unknown_b64_options', 30 );

		$report  = get_option( 'wps_forensics_report', null );
		$flagged = is_array( $report ) ? ( $report['unknown_base64_options'] ?? [] ) : [];
		if ( ! is_array( $flagged ) || ! $flagged ) {
			wp_send_json_error( [ 'error' => 'No flagged base64 options in the current forensics report. Run forensics again, then retry.' ] );
			return;
		}

		$core_protected = [ 'siteurl', 'home', 'blogname', 'admin_email', 'template', 'stylesheet', 'active_plugins', 'wp_user_roles', 'cron', 'rewrite_rules', 'db_version' ];

		$deleted   = 0;
		$skipped   = 0;
		$remaining = [];
		foreach ( $flagged as $entry ) {
			$name = is_array( $entry ) ? sanitize_key( (string) ( $entry['option_name'] ?? '' ) ) : '';
			if ( $name === '' || in_array( $name, $core_protected, true ) ) {
				$skipped++;
				if ( is_array( $entry ) ) {
					$remaining[] = $entry;
				}
				continue;
			}

			if ( get_option( $name, null ) === null ) {
				$deleted++; // already gone  treat as success, drop from report
				continue;
			}

			$snapshot_id = null;
			if ( WPS_Scanner::quarantine_enabled() && class_exists( 'WPS_Quarantine' ) ) {
				$snapshot_id = WPS_Quarantine::quarantine_option( $name, [ 'type' => 'db_option (base64 payload)', 'reason' => 'manual bulk delete of base64 payload options' ] );
			}
			delete_option( $name );
			WPS_Event_Log::audit( 'db_option_deleted', [
				'object_type' => 'wp_option',
				'object_name' => $name,
				'original'    => $snapshot_id ? 'quarantine snapshot ' . $snapshot_id : 'not snapshotted (quarantine off)',
				'new'         => 'deleted',
				'reason'      => 'manual bulk delete of base64 payload options',
				'risk'        => 40,
			] );
			if ( get_option( $name, null ) === null ) {
				$deleted++;
				WPS_Logger::log_event( 'db_option_deleted_unknown_b64', $name . ' (bulk)' );
			} else {
				$remaining[] = $entry; // delete failed  keep it flagged
			}
		}

		if ( is_array( $report ) ) {
			$report['unknown_base64_options'] = array_values( $remaining );
			update_option( 'wps_forensics_report', $report );
		}
		delete_transient( 'wps_scan_results' );

		wp_send_json_success( [
			'message' => 'Deleted ' . $deleted . ' confirmed base64 option' . ( 1 === $deleted ? '' : 's' )
				. ( $skipped ? ', skipped ' . $skipped . ' protected/invalid' : '' ) . '.',
		] );
	}

	//  Hardening AJAX

	public static function wpconfig_constant(): void {
		WPS_Utils::guard_request( 'update_core' );
		$constant = strtoupper( sanitize_key( wp_unslash( $_POST['constant'] ?? '' ) ) );
		$enable   = ( ( $_POST['enable'] ?? '1' ) === '1' );
		$result   = WPS_Hardening::set_wpconfig_constant( $constant, $enable );
		if ( $result === true ) {
			wp_send_json_success( [ 'message' => ( $enable ? 'Enabled' : 'Disabled' ) . ': ' . $constant ] );
		} else {
			wp_send_json_error( [ 'error' => $result ] );
		}
	}

	public static function htaccess_rule(): void {
		WPS_Utils::guard_request( 'manage_options' );
		$rule   = sanitize_key( wp_unslash( $_POST['rule'] ?? '' ) );
		$enable = ( ( $_POST['enable'] ?? '1' ) === '1' );
		// Extra param for IP restriction rule
		$ip     = sanitize_text_field( wp_unslash( $_POST['ip'] ?? '' ) );
		$result = WPS_Hardening::set_htaccess_rule( $rule, $enable, $ip );
		if ( $result === true ) {
			wp_send_json_success( [ 'message' => ( $enable ? 'Applied' : 'Removed' ) . ': ' . $rule ] );
		} else {
			wp_send_json_error( [ 'error' => $result ] );
		}
	}

	public static function clear_transients(): void {
		WPS_Utils::guard_request( 'manage_options' );
		WPS_Utils::enforce_cooldown( 'clear_transients' );
		global $wpdb;
		$deleted = (int) $wpdb->query(
			"DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_%' OR option_name LIKE '_site_transient_%'"
		);
		if ( function_exists( 'wp_cache_flush' ) ) {
			wp_cache_flush();
		}
		WPS_Logger::log_event( 'transients_cleared', $deleted . ' transient(s) deleted' );
		wp_send_json_success( [ 'message' => $deleted . ' transient(s) deleted and object cache flushed.' ] );
	}

	public static function invalidate_sessions(): void {
		WPS_Utils::guard_request( 'manage_options' );
		WPS_Utils::enforce_cooldown( 'invalidate_sessions' );
		global $wpdb;
		// Delete all session_tokens usermeta forces every user to log in again
		$deleted = (int) $wpdb->query(
			"DELETE FROM {$wpdb->usermeta} WHERE meta_key = 'session_tokens'"
		);
		WPS_Logger::log_event( 'sessions_invalidated', 'All user sessions invalidated (' . $deleted . ' rows)' );
		wp_send_json_success( [
			'message' => 'All user sessions invalidated every user must log in again. ' . $deleted . ' session record(s) removed.',
		] );
	}

	public static function regenerate_salts(): void {
		WPS_Utils::guard_request( 'update_core' );
		WPS_Utils::enforce_cooldown( 'regenerate_salts', 30 );
		$result = WPS_Hardening::regenerate_salts();
		if ( $result === true ) {
			WPS_Event_Log::audit( 'salts_regenerated', [
				'object_type' => 'wp-config',
				'object_name' => 'auth salts',
				'original'    => 'previous salts (unrecoverable by design)',
				'new'         => 'freshly generated salts',
				'reason'      => 'operator-initiated rotation; all sessions invalidated',
				'risk'        => 60,
			] );
			wp_send_json_success( [ 'message' => 'Auth salts regenerated in wp-config.php. All existing sessions have been invalidated.' ] );
		} else {
			wp_send_json_error( [ 'error' => $result ] );
		}
	}

	//  User / attachment / plugin folder / file deletion

	public static function delete_user(): void {
		WPS_Utils::guard_request( 'delete_users' );
		WPS_Utils::enforce_cooldown( 'delete_user', 30 );

		$user_id = (int) ( $_POST['user_id'] ?? 0 );
		if ( ! $user_id ) {
			wp_send_json_error( [ 'error' => 'Invalid user ID.' ] );
			return;
		}

		// Never allow deleting yourself
		if ( $user_id === get_current_user_id() ) {
			wp_send_json_error( [ 'error' => 'Cannot delete your own account.' ] );
			return;
		}

		$user = get_user_by( 'id', $user_id );
		if ( ! $user ) {
			wp_send_json_error( [ 'error' => 'User not found (may already be deleted).' ] );
			return;
		}

		$login = $user->user_login;

		// Reassign any content to the current admin before deletion
		require_once ABSPATH . 'wp-admin/includes/user.php';
		$result = wp_delete_user( $user_id, get_current_user_id() );

		if ( $result ) {
			WPS_Event_Log::audit( 'user_deleted', [
				'object_type' => 'user',
				'object_name' => $login . ' (ID ' . $user_id . ')',
				'original'    => 'account existed with role(s) at deletion time',
				'new'         => 'deleted; content reassigned per WordPress deletion flow',
				'reason'      => 'operator-confirmed suspect account removal',
				'risk'        => 120,
			] );
			delete_transient( 'wps_scan_results' );
			wp_send_json_success( [ 'message' => 'Account deleted: ' . $login ] );
		} else {
			wp_send_json_error( [ 'error' => 'wp_delete_user() failed check error log.' ] );
		}
	}

	public static function delete_attachment(): void {
		WPS_Utils::guard_request( 'delete_posts' );
		WPS_Utils::enforce_cooldown( 'delete_attachment' );

		$id = (int) ( $_POST['id'] ?? 0 );
		if ( ! $id ) {
			wp_send_json_error( [ 'error' => 'Invalid attachment ID.' ] );
			return;
		}

		$post = get_post( $id );
		if ( ! $post || $post->post_type !== 'attachment' ) {
			wp_send_json_error( [ 'error' => 'Attachment not found.' ] );
			return;
		}

		$title = $post->post_title;
		$file  = get_attached_file( $id );

		$result = wp_delete_attachment( $id, true ); // true = force delete, bypass trash

		if ( $result ) {
			WPS_Logger::log_event( 'attachment_deleted', 'Deleted malicious attachment: ' . $title . ' (' . $file . ')' );
			wp_send_json_success( [ 'message' => 'Attachment deleted: ' . $title ] );
		} else {
			wp_send_json_error( [ 'error' => 'wp_delete_attachment() failed.' ] );
		}
	}

	public static function delete_plugin_folder(): void {
		WPS_Utils::guard_request( 'delete_plugins' );
		WPS_Utils::enforce_cooldown( 'delete_plugin_folder', 30 );

		$path = wp_unslash( $_POST['path'] ?? '' );
		if ( ! $path ) {
			wp_send_json_error( [ 'error' => 'No path provided.' ] );
			return;
		}

		// WPSEC-001 (1.3.57): containment base is WP_PLUGIN_DIR, not
		// WP_CONTENT_DIR. The handler is named delete_plugin_folder and
		// gated on the delete_plugins capability; allowing wp-content/
		// breadth (themes, uploads, mu-plugins, languages, cache) made
		// the capability check meaningless under custom role
		// configurations, since a delete_plugins-only user could pass
		// a wp-content/themes/* path and trigger recursive deletion.
		// WP_PLUGIN_DIR aligns the containment with the capability and
		// the handler name. Theme deletion still has its own dedicated
		// handler (delete_theme_file) gated on edit_themes.
		$real        = realpath( $path );
		$real_plugin = realpath( WP_PLUGIN_DIR );
		$real_self   = realpath( WPS_DIR );

		if ( ! $real || ! $real_plugin ) {
			wp_send_json_error( [ 'error' => 'Path does not exist on disk.' ] );
			return;
		}
		if ( $real === $real_plugin ) {
			wp_send_json_error( [ 'error' => 'Refusing to delete the plugins directory itself.' ] );
			return;
		}
		if ( ! WPS_Utils::path_is_inside( $real, WP_PLUGIN_DIR ) ) {
			wp_send_json_error( [ 'error' => 'Safety check failed: path is outside wp-content/plugins/.' ] );
			return;
		}
		if ( $real_self && ( $real === $real_self || WPS_Utils::path_is_inside( $real, WPS_DIR ) ) ) {
			wp_send_json_error( [ 'error' => 'Cannot delete WP Perf Shield itself.' ] );
			return;
		}

		// Deactivate if it's an active plugin before deleting
		$active = get_option( 'active_plugins', [] );
		$dirty  = false;
		foreach ( $active as $k => $p ) {
			if ( strpos( $p, basename( $real ) . '/' ) === 0 ) {
				unset( $active[ $k ] );
				$dirty = true;
			}
		}
		if ( $dirty ) {
			update_option( 'active_plugins', array_values( $active ) );
		}

		// Delete recursively
		$deleted = 0;
		$errors  = 0;
		if ( is_dir( $real ) ) {
			$iter = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $real, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::CHILD_FIRST
			);
			foreach ( $iter as $item ) {
				$ok = $item->isDir() ? @rmdir( $item->getPathname() ) : @unlink( $item->getPathname() );
				$ok ? $deleted++ : $errors++;
			}
			$ok = @rmdir( $real );
			$ok ? $deleted++ : $errors++;
		} elseif ( is_file( $real ) ) {
			@unlink( $real ) ? $deleted++ : $errors++;
		}

		delete_transient( 'wps_scan_results' );
		WPS_Event_Log::audit( 'plugin_folder_deleted', [
			'object_type' => 'plugin',
			'object_name' => basename( $real ),
			'original'    => $deleted . ' items on disk',
			'new'         => 'folder removed',
			'reason'      => 'operator-confirmed malicious plugin removal',
			'risk'        => 80,
		] );

		if ( $errors === 0 ) {
			wp_send_json_success( [ 'message' => 'Deleted: ' . basename( $real ) . ' (' . $deleted . ' items)' ] );
		} else {
			wp_send_json_error( [ 'error' => $deleted . ' items deleted, ' . $errors . ' failed check file permissions.' ] );
		}
	}

	private static function is_active_theme_critical_file( string $real ): bool {
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

	public static function delete_file(): void {
		WPS_Utils::guard_request( 'manage_options' );
		WPS_Utils::enforce_cooldown( 'delete_file' );

		$path = wp_unslash( $_POST['path'] ?? '' );
		if ( ! $path ) {
			wp_send_json_error( [ 'error' => 'No path provided.' ] );
			return;
		}

		$real    = realpath( $path );
		$real_wc = realpath( WP_CONTENT_DIR );
		$real_ab = realpath( ABSPATH );

		if ( ! $real ) {
			wp_send_json_success( [ 'message' => 'File not found may already be deleted.' ] );
			return;
		}

		// Must be inside ABSPATH, and must not be a core WP file outside wp-content
		if ( ! $real_ab || ! WPS_Utils::path_is_inside( $real, ABSPATH ) ) {
			wp_send_json_error( [ 'error' => 'Safety check failed path is outside ABSPATH.' ] );
			return;
		}

		// WPSEC-003 (1.3.57): protected basename list extended.
		// Original list (1.3.x) only protected the most obvious WordPress
		// core PHP files. Server-config files at the WP root were
		// missed. Adding .htaccess, .user.ini, wp-cron.php,
		// wp-trackback.php, wp-comments-post.php so that an admin
		// session (or any session-stealing XSS that bypasses nonce)
		// cannot delete server-rewrite or PHP per-directory config
		// files via this handler. Files inside wp-content/ remain
		// deletable by basename even if the basename is on this list,
		// because legitimate malware sometimes hides under a core-file
		// basename inside wp-content/uploads/ or similar.
		$basename  = basename( $real );
		$protected = [
			'wp-config.php',
			'wp-load.php',
			'wp-settings.php',
			'wp-blog-header.php',
			'index.php',
			'.htaccess',           // Apache rewrite rules
			'.user.ini',           // PHP per-directory config
			'wp-cron.php',         // WordPress cron entry point
			'wp-trackback.php',    // WordPress trackback endpoint
			'wp-comments-post.php',// WordPress comment submission endpoint
		];
		if ( in_array( $basename, $protected, true ) && ( ! $real_wc || ! WPS_Utils::path_is_inside( $real, WP_CONTENT_DIR ) ) ) {
			wp_send_json_error( [ 'error' => 'Refusing to delete protected WP file: ' . $basename ] );
			return;
		}

		if ( is_file( $real ) && self::is_active_theme_critical_file( $real ) ) {
			wp_send_json_error( [ 'error' => 'Refusing to delete active theme critical file: ' . $basename . '. Use a surgical cleaner or restore from backup instead.' ] );
			return;
		}

		// Directory deletion (added 1.3.70). The scanner only sets
		// `delete_path` (and therefore renders the "Delete this path" button)
		// for directories contained inside WP_PLUGIN_DIR, so the common case
		// is a hidden dev/vendor directory under wp-content/plugins/ (.vscode,
		// .helpers, .git, etc.). The handler still applies a defence-in-depth
		// boundary because it is reachable directly and is gated only on
		// manage_options: a directory must be inside wp-content/, must not be a
		// structural root (wp-content/ itself or the plugins/themes/mu-plugins/
		// uploads/languages roots), and must never be WP Perf Shield's own
		// directory or any ancestor of it.
		if ( is_dir( $real ) ) {
			if ( ! $real_wc || ! WPS_Utils::path_is_inside( $real, WP_CONTENT_DIR ) ) {
				wp_send_json_error( [ 'error' => 'Refusing to recursively delete a directory outside wp-content/.' ] );
				return;
			}

			$forbidden_roots = array_filter( array_map( 'realpath', [
				WP_CONTENT_DIR,
				WP_CONTENT_DIR . '/plugins',
				WP_CONTENT_DIR . '/themes',
				WP_CONTENT_DIR . '/mu-plugins',
				WP_CONTENT_DIR . '/uploads',
				WP_CONTENT_DIR . '/languages',
			] ) );
			if ( in_array( $real, $forbidden_roots, true ) ) {
				wp_send_json_error( [ 'error' => 'Refusing to delete a structural wp-content directory: ' . basename( $real ) ] );
				return;
			}

			$real_self = realpath( WPS_DIR );
			if ( $real_self && ( $real === $real_self || WPS_Utils::path_is_inside( $real_self, $real ) ) ) {
				wp_send_json_error( [ 'error' => 'Refusing to delete WP Perf Shield\'s own directory.' ] );
				return;
			}

			$deleted = 0;
			$errors  = 0;
			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $real, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::CHILD_FIRST
				);
				foreach ( $iter as $item ) {
					$ok = $item->isDir() ? @rmdir( $item->getPathname() ) : @unlink( $item->getPathname() );
					$ok ? $deleted++ : $errors++;
				}
			} catch ( \Exception $e ) {
				wp_send_json_error( [ 'error' => 'Directory walk failed: ' . $e->getMessage() ] );
				return;
			}
			if ( @rmdir( $real ) ) {
				$deleted++;
			} else {
				$errors++;
			}

			delete_transient( 'wps_scan_results' );
			WPS_Logger::log_event( 'directory_deleted', $real . ' (' . $deleted . ' items)' );

			if ( $errors === 0 ) {
				wp_send_json_success( [ 'message' => 'Deleted directory: ' . basename( $real ) . ' (' . $deleted . ' items)' ] );
			} else {
				wp_send_json_error( [ 'error' => $deleted . ' items deleted, ' . $errors . ' failed  check file permissions for: ' . $real ] );
			}
			return;
		}

		if ( ! is_file( $real ) ) {
			wp_send_json_error( [ 'error' => 'Path is neither a regular file nor a directory.' ] );
			return;
		}

		if ( @unlink( $real ) ) {
			WPS_Logger::log_event( 'file_deleted', $real );
			delete_transient( 'wps_scan_results' );
			wp_send_json_success( [ 'message' => 'Deleted: ' . basename( $real ) ] );
		} else {
			wp_send_json_error( [ 'error' => 'unlink() failed check file permissions for: ' . $real ] );
		}
	}

	/**
	 * 1.3.67: surgical-edit handler for `wordfence-waf.php` auto_prepend hijack.
	 *
	 * The genuine wordfence-waf.php file at ABSPATH is a thin wrapper that
	 * contains exactly one include/require pointing at the canonical Wordfence
	 * WAF bootstrap (`wp-content/plugins/wordfence/waf/bootstrap.php` or the
	 * wordfence-protect equivalent). Malware adds an additional include line
	 * pointing at attacker-controlled storage above the genuine include.
	 * This handler removes the specific malicious include line identified by
	 * the `match` parameter (the offending include target path captured by
	 * the scanner), preserving everything else in the file including the
	 * canonical Wordfence include.
	 *
	 * Safety mechanisms:
	 *  - Path is hard-coded to `ABSPATH . 'wordfence-waf.php'`. The handler
	 *    accepts no path parameter from the client. This is narrower than
	 *    `delete_file()`'s ABSPATH-wide trust (see WPSEC-001 in the 1.3.57
	 *    audit) because the handler can ONLY ever touch one specific file.
	 *  - Backup-on-edit: the original file content is copied to
	 *    `<file>.wps-backup-<unix-timestamp>` before any modification. The
	 *    backup persists until the operator deletes it manually. Restoring
	 *    is a one-line operator action.
	 *  - Atomic write: contents are written to a temp file and renamed into
	 *    place. If the write fails, the original is untouched. Matches the
	 *    pattern used by `clean_login()` and `clean_functions()` since 1.3.x.
	 *  - Pre-check: the offending include must actually be present in the
	 *    file. If the scanner finding is stale (operator already cleaned
	 *    manually), the handler reports success with "already clean" rather
	 *    than rewriting the file.
	 *  - Mid-line guard: if the offending include is on a line that contains
	 *    other PHP statements, the handler refuses to clean and asks the
	 *    operator to edit manually. This is the conservative choice line-
	 *    based removal of mixed-content lines could corrupt legitimate code.
	 *  - Post-check: after the rename, the file is re-read and the offending
	 *    include is searched for again. If still present, the handler reports
	 *    a critical error and points at the backup file.
	 */
	public static function clean_wfwaf_include(): void {
		WPS_Utils::guard_request( 'manage_options' );

		$offending = trim( (string) wp_unslash( $_POST['match'] ?? '' ) );
		if ( $offending === '' ) {
			wp_send_json_error( [ 'error' => 'No offending include path provided.' ] );
			return;
		}

		$wf_waf = ABSPATH . 'wordfence-waf.php';
		if ( ! file_exists( $wf_waf ) || ! is_readable( $wf_waf ) ) {
			wp_send_json_error( [ 'error' => 'wordfence-waf.php not found or not readable. Manual review required.' ] );
			return;
		}

		$contents = @file_get_contents( $wf_waf );
		if ( ! is_string( $contents ) || $contents === '' ) {
			wp_send_json_error( [ 'error' => 'Could not read wordfence-waf.php. Manual review required.' ] );
			return;
		}

		$result = self::clean_wfwaf_compute( $contents, $offending );
		if ( $result['status'] === 'already_clean' ) {
			wp_send_json_success( [ 'message' => 'wordfence-waf.php is already clean offending include is not present.' ] );
			return;
		}
		if ( $result['status'] === 'mixed_line' ) {
			wp_send_json_error( [ 'error' => 'The offending include is on a line that contains other PHP code. Refusing to auto-clean. Edit wordfence-waf.php manually.' ] );
			return;
		}
		if ( $result['status'] !== 'cleanable' ) {
			wp_send_json_error( [ 'error' => 'Unrecognised cleaning status: ' . $result['status'] ] );
			return;
		}

		// Backup-on-edit into the protected quarantine store (1.3.97). Refuse to
		// edit without a recoverable backup.
		$backup = WPS_Utils::create_timestamped_backup( $wf_waf );
		if ( is_wp_error( $backup ) ) {
			wp_send_json_error( [ 'error' => 'Could not create a recoverable backup (' . $backup->get_error_message() . '). Refusing to edit wordfence-waf.php without one.' ] );
			return;
		}

		// Atomic write of cleaned contents.
		$tmp = $wf_waf . '.wps_tmp';
		if ( @file_put_contents( $tmp, $result['cleaned'] ) === false || ! @rename( $tmp, $wf_waf ) ) {
			@unlink( $tmp );
			wp_send_json_error( [ 'error' => 'Could not write cleaned wordfence-waf.php. Backup preserved at: ' . WPS_Utils::backup_location_label( $backup ) ] );
			return;
		}

		// Post-check: re-read and verify the offending include is gone.
		clearstatcache( true, $wf_waf );
		$reread = @file_get_contents( $wf_waf );
		if ( is_string( $reread ) && self::contains_include_target( $reread, $offending ) ) {
			WPS_Logger::log_event( 'wfwaf_clean_failed_post_verify', 'offending include still present after write: ' . $offending );
			wp_send_json_error( [ 'error' => 'Wrote the file but the offending include is still present on re-read. The backup file is at: ' . WPS_Utils::backup_location_label( $backup ) . '. Manual review required.' ] );
			return;
		}

		WPS_Logger::log_event( 'wfwaf_cleaned', 'removed include line referencing ' . $offending . '; backup: ' . WPS_Utils::backup_location_label( $backup ) );
		wp_send_json_success( [
			'message' => 'wordfence-waf.php cleaned successfully removed include line referencing ' . $offending . '. Backup saved as ' . WPS_Utils::backup_location_label( $backup ) . '.',
		] );
	}

	/**
	 * Compute the cleaned content of a wordfence-waf.php file given the offending
	 * include target path. Pure function  no side effects, no I/O. Returns
	 * an array with keys `status` and (when status is `cleanable`) `cleaned`
	 * containing the new file content.
	 *
	 * Status values:
	 *  - `already_clean`: no line contains the offending include
	 *  - `mixed_line`:    the offending include is on a line that contains
	 *                     other code besides whitespace and the include
	 *                     directive itself  refuse to auto-clean
	 *  - `cleanable`:     the offending include is on its own line (with
	 *                     optional leading `@`, trailing `;`, and surrounding
	 *                     whitespace)  the line is removed in `cleaned`
	 *
	 * Extracted as a separate method so the logic is testable in isolation
	 * without filesystem I/O.
	 *
	 * @param string $contents  The current wordfence-waf.php content.
	 * @param string $offending The include target path to remove.
	 * @return array{status: string, cleaned?: string}
	 */
	public static function clean_wfwaf_compute( string $contents, string $offending ): array {
		// Pattern matches an include/require directive whose target path
		// matches the offending value. Allows optional `@`, optional
		// parentheses, optional surrounding whitespace, optional trailing
		// semicolon, and accepts both single and double quotes around the
		// path.
		$quoted = preg_quote( $offending, '/' );

		// Form 1: bare include/require on its own line.
		//   include('<offending>'); or @include_once('<offending>'); etc.
		$bare_pattern = '/^\s*@?\s*(?:include|include_once|require|require_once)\s*\(?\s*[\'"]' . $quoted . '[\'"]\s*\)?\s*;?\s*$/i';

		// Form 2: the file_exists wrapper form which is the dominant real-world
		// hijack pattern observed in the field. The line takes the shape:
		//   if (file_exists('<offending>')) include('<offending>');
		// Both halves of the line reference the SAME offending path, both
		// are malicious, and removing the whole line is safe. We only match
		// when the SAME offending path appears in BOTH the file_exists check
		// AND the include directive  this is what distinguishes the malware
		// pattern from legitimate code that might happen to include() the
		// same path.
		$wrapped_pattern = '/^\s*if\s*\(\s*file_exists\s*\(\s*[\'"]' . $quoted . '[\'"]\s*\)\s*\)\s*\{?\s*@?\s*(?:include|include_once|require|require_once)\s*\(?\s*[\'"]' . $quoted . '[\'"]\s*\)?\s*;?\s*\}?\s*$/i';

		// Per-line "does this line contain the offending include anywhere"
		// test (used to detect mid-line / mixed-content lines that we refuse
		// to auto-clean).
		$contains_pattern = '/(?:include|include_once|require|require_once)\s*\(?\s*[\'"]' . $quoted . '[\'"]/i';

		// Use \R to split on any line ending (LF, CRLF, CR), preserving the
		// detection of every line. Re-join with \n on output (acceptable
		// normalisation for a PHP file).
		$lines = preg_split( '/\R/', $contents );
		if ( $lines === false ) {
			return [ 'status' => 'mixed_line' ]; // bail conservatively
		}

		$found_clean    = false;
		$cleaned_lines  = [];
		foreach ( $lines as $line ) {
			if ( preg_match( $contains_pattern, $line ) ) {
				if ( preg_match( $bare_pattern, $line ) || preg_match( $wrapped_pattern, $line ) ) {
					// Recognised cleanable form  drop the line.
					$found_clean = true;
					continue;
				}
				// The offending include is on a line that contains other
				// code and does not match a recognised wrapper form 
				// refuse to auto-clean.
				return [ 'status' => 'mixed_line' ];
			}
			$cleaned_lines[] = $line;
		}

		if ( ! $found_clean ) {
			return [ 'status' => 'already_clean' ];
		}

		return [
			'status'  => 'cleanable',
			'cleaned' => implode( "\n", $cleaned_lines ),
		];
	}

	/**
	 * Test helper: does this content contain an include/require directive
	 * referencing the given target path? Used by the post-write verification
	 * step to confirm the offending include is no longer present.
	 */
	private static function contains_include_target( string $contents, string $target ): bool {
		$quoted  = preg_quote( $target, '/' );
		$pattern = '/(?:include|include_once|require|require_once)\s*\(?\s*[\'"]' . $quoted . '[\'"]/i';
		return (bool) preg_match( $pattern, $contents );
	}

	/**
	 * 1.3.67: surgical-edit handler for `.user.ini` auto_prepend_file directive.
	 *
	 * Removes lines that contain `auto_prepend_file = <offending value>`. The
	 * .user.ini file is plain-text PHP-config (key=value pairs), so removing
	 * a single matching line is safe and well-defined. Each safety mechanism
	 * from `clean_wfwaf_include()` applies here too: hard-coded path,
	 * backup-on-edit, atomic write, pre-check, post-check.
	 */
	public static function clean_user_ini_prepend(): void {
		WPS_Utils::guard_request( 'manage_options' );

		$offending = trim( (string) wp_unslash( $_POST['match'] ?? '' ) );
		if ( $offending === '' ) {
			wp_send_json_error( [ 'error' => 'No offending auto_prepend_file value provided.' ] );
			return;
		}

		$user_ini = ABSPATH . '.user.ini';
		if ( ! file_exists( $user_ini ) || ! is_readable( $user_ini ) ) {
			wp_send_json_error( [ 'error' => '.user.ini not found or not readable. Manual review required.' ] );
			return;
		}

		$contents = @file_get_contents( $user_ini );
		if ( ! is_string( $contents ) || $contents === '' ) {
			wp_send_json_error( [ 'error' => 'Could not read .user.ini. Manual review required.' ] );
			return;
		}

		$result = self::clean_user_ini_compute( $contents, $offending );
		if ( $result['status'] === 'already_clean' ) {
			wp_send_json_success( [ 'message' => '.user.ini is already clean offending auto_prepend_file directive is not present.' ] );
			return;
		}
		if ( $result['status'] !== 'cleanable' ) {
			wp_send_json_error( [ 'error' => 'Unrecognised cleaning status: ' . $result['status'] ] );
			return;
		}

		// Backup-on-edit into the protected quarantine store (1.3.97).
		$backup = WPS_Utils::create_timestamped_backup( $user_ini );
		if ( is_wp_error( $backup ) ) {
			wp_send_json_error( [ 'error' => 'Could not create a recoverable backup (' . $backup->get_error_message() . '). Refusing to edit .user.ini without one.' ] );
			return;
		}

		$tmp = $user_ini . '.wps_tmp';
		if ( @file_put_contents( $tmp, $result['cleaned'] ) === false || ! @rename( $tmp, $user_ini ) ) {
			@unlink( $tmp );
			wp_send_json_error( [ 'error' => 'Could not write cleaned .user.ini. Backup preserved at: ' . WPS_Utils::backup_location_label( $backup ) ] );
			return;
		}

		clearstatcache( true, $user_ini );
		$reread = @file_get_contents( $user_ini );
		if ( is_string( $reread ) && self::user_ini_contains_prepend( $reread, $offending ) ) {
			WPS_Logger::log_event( 'user_ini_clean_failed_post_verify', 'offending auto_prepend_file still present after write: ' . $offending );
			wp_send_json_error( [ 'error' => 'Wrote the file but the offending directive is still present on re-read. The backup file is at: ' . WPS_Utils::backup_location_label( $backup ) . '. Manual review required.' ] );
			return;
		}

		WPS_Logger::log_event( 'user_ini_cleaned', 'removed auto_prepend_file = ' . $offending . '; backup: ' . WPS_Utils::backup_location_label( $backup ) );
		wp_send_json_success( [
			'message' => '.user.ini cleaned successfully removed auto_prepend_file directive referencing ' . $offending . '. Backup saved as ' . WPS_Utils::backup_location_label( $backup ) . '.',
		] );
	}

	/**
	 * Compute the cleaned content of a .user.ini file given the offending
	 * auto_prepend_file value. Pure function  no side effects, no I/O.
	 *
	 * Status values:
	 *  - `already_clean`: no line contains the offending directive
	 *  - `cleanable`:     at least one line is removed in `cleaned`
	 *
	 * @param string $contents  The current .user.ini content.
	 * @param string $offending The auto_prepend_file value to remove.
	 * @return array{status: string, cleaned?: string}
	 */
	public static function clean_user_ini_compute( string $contents, string $offending ): array {
		// Match: auto_prepend_file = "/path" or auto_prepend_file = /path
		// Optional whitespace around =, optional double or single quotes.
		// We do whole-line removal because .user.ini is one-directive-per-line
		// by design no risk of clobbering adjacent code.
		$quoted  = preg_quote( $offending, '/' );
		$pattern = '/^\s*auto_prepend_file\s*=\s*["\']?' . $quoted . '["\']?\s*$/i';

		$lines         = preg_split( '/\R/', $contents );
		if ( $lines === false ) {
			return [ 'status' => 'already_clean' ];
		}

		$found_clean   = false;
		$cleaned_lines = [];
		foreach ( $lines as $line ) {
			if ( preg_match( $pattern, $line ) ) {
				$found_clean = true;
				continue;
			}
			$cleaned_lines[] = $line;
		}

		if ( ! $found_clean ) {
			return [ 'status' => 'already_clean' ];
		}

		return [
			'status'  => 'cleanable',
			'cleaned' => implode( "\n", $cleaned_lines ),
		];
	}

	private static function user_ini_contains_prepend( string $contents, string $offending ): bool {
		$quoted  = preg_quote( $offending, '/' );
		$pattern = '/^\s*auto_prepend_file\s*=\s*["\']?' . $quoted . '["\']?\s*$/im';
		return (bool) preg_match( $pattern, $contents );
	}

	public static function delete_theme_file(): void {
		WPS_Utils::guard_request( 'edit_themes' );
		WPS_Utils::enforce_cooldown( 'delete_theme_file' );

		$path = wp_unslash( $_POST['path'] ?? '' );
		if ( ! $path ) {
			wp_send_json_error( [ 'error' => 'No path provided.' ] );
			return;
		}

		$real       = realpath( $path );
		$real_theme = realpath( get_template_directory() );
		$real_child = realpath( get_stylesheet_directory() );

		if ( ! $real ) {
			wp_send_json_success( [ 'message' => 'File not found may already be deleted.' ] );
			return;
		}

		// Must be inside the active theme or child theme directory
		$in_parent = $real_theme && ( $real === $real_theme || WPS_Utils::path_is_inside( $real, $real_theme ) );
		$in_child  = $real_child && ( $real === $real_child || WPS_Utils::path_is_inside( $real, $real_child ) );
		if ( ! $in_parent && ! $in_child ) {
			wp_send_json_error( [ 'error' => 'Safety check failed path is outside the active theme directories.' ] );
			return;
		}

		// Never delete functions.php via this handler use wps_clean_functions instead
		if ( basename( $real ) === 'functions.php' ) {
			wp_send_json_error( [ 'error' => 'Use "Clean functions.php" in the Remediation tab to clean this file safely rather than deleting it.' ] );
			return;
		}

		if ( @unlink( $real ) ) {
			WPS_Logger::log_event( 'theme_file_deleted', $real );
			delete_transient( 'wps_scan_results' );
			wp_send_json_success( [ 'message' => 'Deleted: ' . basename( $real ) ] );
		} else {
			wp_send_json_error( [ 'error' => 'unlink() failed check file permissions.' ] );
		}
	}

	//  Diagnostics export (Phase 5)

	/**
	 * Build a redacted support bundle as JSON. Includes plugin version,
	 * settings, active protections, recent events with subjects truncated
	 * for privacy, blocked IP summaries, scan findings, environment checks,
	 * and the indicator data version. Never includes raw credentials, auth
	 * salts, DB passwords, or full exfil contents.
	 */
	public static function export_diagnostics(): void {
		WPS_Utils::guard_request( 'manage_options' );

		$settings  = get_option( WPS_OPTION, [] );
		$events    = WPS_Logger::read_events();
		$findings  = get_transient( 'wps_scan_results' );
		$blocked   = WPS_Blocker::get_blocked_ips();
		$last_scan = get_option( 'wps_last_scan', null );
		$forensics = get_option( 'wps_forensics_report', null );

		$bundle = [
			'generated_at'         => gmdate( 'Y-m-d H:i:s' ) . ' UTC',
			'plugin_version'       => WPS_VERSION,
			'indicator_version'    => WPS_Indicators::INDICATOR_VERSION,
			'wp_version'           => get_bloginfo( 'version' ),
			'php_version'          => PHP_VERSION,
			'multisite'            => is_multisite() ? 'yes' : 'no',
			'is_main_site'         => is_main_site() ? 'yes' : 'no',
			'siteurl'              => get_option( 'siteurl' ),
			'settings' => [
				'extra_slugs_count'          => self::count_lines( (string) ( $settings['extra_slugs'] ?? '' ) ),
				'extra_hashes_count'         => self::count_lines( (string) ( $settings['extra_hashes'] ?? '' ) ),
				'auto_delete_enabled'        => ( $settings['auto_delete_enabled'] ?? '1' ) !== '0',
				'auto_ip_block_enabled'      => ( $settings['auto_ip_block_enabled'] ?? '1' ) !== '0',
				'strict_upload_gate_enabled' => ( $settings['strict_upload_gate_enabled'] ?? '1' ) !== '0',
			],
			'active_protections'   => self::active_protection_summary(),
			'environment_checks'   => self::environment_check_summary(),
			'last_scan'            => is_array( $last_scan ) ? [
				'time'           => (string) ( $last_scan['time'] ?? '' ),
				'findings_count' => is_array( $last_scan['findings'] ?? null ) ? count( $last_scan['findings'] ) : 0,
			] : null,
			'cached_findings'      => self::redact_findings( is_array( $findings ) ? $findings : [] ),
			'blocked_ips'          => self::redact_blocked_ips( $blocked ),
			'recent_events'        => self::redact_events( array_slice( array_reverse( $events ), 0, 50 ) ),
			'forensics_summary'    => is_array( $forensics ) ? self::summarise_forensics( $forensics ) : null,
		];

		// 1.4.0: sign the bundle so a tampered export is provable. The signature
		// covers the exact JSON of the bundle WITHOUT the signature block; verify
		// by re-encoding the bundle minus 'signature' and recomputing.
		if ( class_exists( 'WPS_Event_Log' ) ) {
			$bundle['signature'] = WPS_Event_Log::sign( (string) wp_json_encode( $bundle ) );
		}

		WPS_Event_Log::audit( 'diagnostics_exported', [
			'object_type' => 'export',
			'object_name' => 'support bundle',
			'reason'      => 'operator export from Diagnostics',
			'new'         => 'signed bundle sha256 ' . substr( (string) ( $bundle['signature']['sha256'] ?? '' ), 0, 16 ) . '...',
			'risk'        => 10,
		] );

		wp_send_json_success( $bundle );
	}

	private static function count_lines( string $raw ): int {
		if ( $raw === '' ) {
			return 0;
		}
		$lines = preg_split( '/\R+/', $raw ) ?: [];
		return count( array_filter( $lines, static fn( string $l ): bool => trim( $l ) !== '' ) );
	}

	private static function active_protection_summary(): array {
		$status = WPS_Hardening::get_status();
		return [
			'wps_blocker'         => ! empty( $status['wps_blocker'] ),
			'wps_scanner'         => ! empty( $status['wps_scanner'] ),
			'DISALLOW_FILE_MODS'  => ! empty( $status['DISALLOW_FILE_MODS'] ),
			'DISALLOW_FILE_EDIT'  => ! empty( $status['DISALLOW_FILE_EDIT'] ),
			'FORCE_SSL_ADMIN'     => ! empty( $status['FORCE_SSL_ADMIN'] ),
			'htaccess_php_uploads'=> ! empty( $status['php_uploads'] ),
			'htaccess_xmlrpc'     => ! empty( $status['xmlrpc'] ),
			'htaccess_perf_block' => ! empty( $status['perf_analytics'] ),
		];
	}

	private static function environment_check_summary(): array {
		return [
			'log_dir_writable'      => WPS_Logger::can_write(),
			'admin_css_present'     => is_readable( WPS_DIR . 'assets/css/admin.css' ),
			'admin_js_present'      => is_readable( WPS_DIR . 'assets/js/admin.js' ),
			'ziparchive_available'  => class_exists( 'ZipArchive' ),
			'wp_cron_writable'      => is_writable( ABSPATH . 'wp-cron.php' ),
			'wp_config_baseline'    => (string) get_option( 'wps_wpconfig_hash', '' ) !== '' ? 'stored' : 'unset',
		];
	}

	private static function redact_findings( array $findings ): array {
		$out = [];
		foreach ( $findings as $f ) {
			if ( ! is_array( $f ) ) continue;
			$out[] = [
				'severity'             => (string) ( $f['severity'] ?? '' ),
				'type'                 => (string) ( $f['type'] ?? '' ),
				'subject'              => self::truncate( (string) ( $f['subject'] ?? '' ), 200 ),
				'match'                => self::truncate( (string) ( $f['match'] ?? '' ), 200 ),
				'auto_delete'          => ! empty( $f['auto_delete'] ),
				'remediated'           => ! empty( $f['remediated'] ),
				'auto_delete_skipped'  => ! empty( $f['auto_delete_skipped'] ),
			];
		}
		return $out;
	}

	private static function redact_blocked_ips( array $blocked ): array {
		$out = [];
		foreach ( $blocked as $ip => $detail ) {
			if ( ! is_array( $detail ) ) continue;
			$out[] = [
				'ip'            => (string) $ip,
				'attempts'      => (int) ( $detail['attempts'] ?? 1 ),
				'first_seen'    => (string) ( $detail['first_seen'] ?? '' ),
				'last_seen'     => (string) ( $detail['last_seen'] ?? '' ),
				'last_filename' => self::truncate( (string) ( $detail['last_filename'] ?? '' ), 120 ),
				'last_pathway'  => self::truncate( (string) ( $detail['last_pathway'] ?? '' ), 200 ),
				'last_user'     => (string) ( $detail['last_user'] ?? 'guest' ),
				'reason'        => self::truncate( (string) ( $detail['reason'] ?? '' ), 200 ),
				'expires'       => isset( $detail['expires'] ) ? (int) $detail['expires'] : 0,
			];
		}
		return $out;
	}

	private static function redact_events( array $events ): array {
		// Drop event types whose subject can carry sensitive bytes that
		// the support bundle should never expose. exfil_file_read entries
		// only carry line counts since 1.3.28, but redact defensively.
		$drop_types = [
			'exfil_file_read',
		];

		$out = [];
		foreach ( $events as $ev ) {
			if ( ! is_array( $ev ) ) continue;
			$type = (string) ( $ev['type'] ?? '' );
			if ( in_array( $type, $drop_types, true ) ) {
				continue;
			}
			$out[] = [
				'time'    => (string) ( $ev['time'] ?? '' ),
				'type'    => $type,
				'subject' => self::truncate( (string) ( $ev['subject'] ?? '' ), 240 ),
				'ip'      => (string) ( $ev['ip'] ?? '' ),
			];
		}
		return $out;
	}

	private static function summarise_forensics( array $report ): array {
		$generated   = (string) ( $report['generated'] ?? '' );
		$plugin_files = is_array( $report['plugin_files'] ?? null ) ? $report['plugin_files'] : [];
		$option_anom  = is_array( $report['option_anomalies'] ?? null ) ? $report['option_anomalies'] : [];
		$core         = is_array( $report['core_integrity'] ?? null ) ? $report['core_integrity'] : [];
		$cron         = is_array( $report['cron_integrity'] ?? null ) ? $report['cron_integrity'] : [];

		return [
			'generated'                => $generated,
			'plugin_file_count'        => count( $plugin_files ),
			'option_anomaly_count'     => count( $option_anom ),
			'core_integrity_status'    => (string) ( $core['status'] ?? 'unknown' ),
			'core_modified_count'      => is_array( $core['modified'] ?? null ) ? count( $core['modified'] ) : 0,
			'cron_integrity_status'    => (string) ( $cron['status'] ?? 'unknown' ),
		];
	}

	private static function truncate( string $text, int $limit ): string {
		$text = wp_strip_all_tags( $text );
		if ( strlen( $text ) <= $limit ) {
			return $text;
		}
		return substr( $text, 0, max( 0, $limit - 3 ) ) . '...';
	}
}
