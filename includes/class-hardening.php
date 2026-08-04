<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * WPS_Hardening  server-side security hardening engine (added v1.3.0).
 *
 * Provides status checks and one-click apply/revert for the hardening
 * steps documented in the WordPress Security Hardening Guide bundled
 * with WP Perf Shield. All file modifications use atomic writes
 * (write  temp  rename) and are restricted to a vetted allowlist.
 *
 * Supported hardening items:
 *
 *   wp-config.php constants (read + write):
 *     DISALLOW_FILE_MODS  locks plugin/theme installs and auto-updates
 *     DISALLOW_FILE_EDIT  disables the admin code editor
 *     FORCE_SSL_ADMIN     forces HTTPS on all admin pages
 *
 *   .htaccess rules (via WordPress insert_with_markers):
 *     php_uploads       blocks PHP execution in wp-content/uploads/
 *     xmlrpc            blocks direct HTTP access to xmlrpc.php
 *     perf_analytics    blocks known ClickFix malware plugin folder patterns
 *
 *   wp-config.php key rotation:
 *     regenerate_salts  fetches new salts from api.wordpress.org and
 *                        replaces all eight define() statements atomically
 */
class WPS_Hardening {

	/**
	 * Constants this class is permitted to add/remove in wp-config.php.
	 * Any other constant name is rejected.
	 */
	private const ALLOWED_CONSTANTS = [
		'DISALLOW_FILE_MODS',
		'DISALLOW_FILE_EDIT',
		'FORCE_SSL_ADMIN',
	];

	/**
	 * .htaccess rule block definitions.
	 * Each entry maps to a named WordPress marker block. Applying the rule
	 * inserts the lines between BEGIN/END markers; removing it passes an
	 * empty array to erase the block.
	 */
	private const HTACCESS_RULES = [
		'php_uploads' => [
			'marker' => 'WPS PHP Upload Block',
			'lines'  => [
				'<IfModule mod_rewrite.c>',
				'RewriteEngine On',
				'RewriteRule ^wp-content/uploads/.*\.php$ - [F,L]',
				'</IfModule>',
			],
		],
		'xmlrpc' => [
			'marker' => 'WPS XMLRPC Block',
			'lines'  => [
				'<Files xmlrpc.php>',
				'  Order allow,deny',
				'  Deny from all',
				'</Files>',
			],
		],
		'perf_analytics' => [
			'marker' => 'WPS Perf Analytics Block',
			'lines'  => [
				'<IfModule mod_rewrite.c>',
				'RewriteEngine On',
				'RewriteRule ^wp-content/plugins/wp-perf-analytics[-_][a-zA-Z0-9]+/.*$ - [F,L]',
				'RewriteRule ^wp-content/plugins/native-render-toolkit[-_][a-zA-Z0-9]+/.*$ - [F,L]',
				'RewriteRule ^wp-content/plugins/total-render-profiler[-_][a-zA-Z0-9]+/.*$ - [F,L]',
				'RewriteRule ^wp-content/plugins/total-render-toolkit[-_][a-zA-Z0-9]+/.*$ - [F,L]',
				'RewriteRule ^wp-content/plugins/pro-font-optimizer[-_][a-zA-Z0-9]+/.*$ - [F,L]',
				'RewriteRule ^wp-content/plugins/site-speed-insights[-_][a-zA-Z0-9]+/.*$ - [F,L]',
				'RewriteRule ^wp-content/plugins/advanced-asset-insights[-_][a-zA-Z0-9]+/.*$ - [F,L]',
				'RewriteRule ^wp-content/plugins/page-seo-toolkit[-_][a-zA-Z0-9]+/.*$ - [F,L]',
				'RewriteRule ^wp-content/plugins/starter-image-guard[-_][a-zA-Z0-9]+/.*$ - [F,L]',
				'</IfModule>',
			],
		],
	];

	/**
	 * Removable wp-config.php malware indicators.
	 *
	 * These patterns are intentionally narrow. wp-config.php can contain
	 * legitimate custom constants, so the cleaner only removes executable
	 * payload lines or marker-bearing blocks that should not exist there.
	 *
	 * @return array<int, array<string, string>>
	 */
	private static function wpconfig_malware_patterns(): array {
		return [
			[
				'id'    => 'eval_encoded_payload',
				'label' => 'Encoded eval/assert payload',
				'regex' => '~^[ \t]*@?(?:eval|assert)\s*\(.*(?:base64_decode|gzinflate|str_rot13|hex2bin|urldecode).*\)\s*;[ \t]*(?:\?>)?[ \t]*\r?$~mi',
			],
			[
				'id'    => 'suspicious_remote_or_upload_include',
				'label' => 'Suspicious include/require from uploads, cache, tmp, or known malware paths',
				'regex' => '~^[ \t]*@?(?:include|include_once|require|require_once)\s*(?:\(?\s*)?[\'"][^\'"]*(?:wp-content/uploads|wp-content/cache|wp-content/languages|/tmp/|/cache/|session-manager|class-wp-compat|wp-locale-handler|wp-perf-analytics|native-render-toolkit|total-render-profiler|total-render-toolkit|pro-font-optimizer|site-speed-insights|advanced-asset-insights|page-seo-toolkit|starter-image-guard|wpconsole|antymalwary|malwary)[^\'"]*[\'"]\s*\)?\s*;[ \t]*\r?$~mi',
			],
			[
				'id'    => 'remote_include_loader',
				'label' => 'Remote include/require loader',
				'regex' => '~^[ \t]*@?(?:include|include_once|require|require_once)\s*(?:\(?\s*)?[\'"]https?://[^\'"]+[\'"]\s*\)?\s*;[ \t]*\r?$~mi',
			],
			[
				'id'    => 'session_manager_option_loader',
				'label' => 'Session-manager option loader or MU-plugin restorer',
				'regex' => '~^[ \t]*.*(?:wp_session_tokens_config|session_tokens_config).*(?:base64_decode|file_put_contents|session-manager\.php|mu-plugins).*;[ \t]*(?:\?>)?[ \t]*\r?$~mi',
			],
			[
				'id'    => 'clickfix_marker_line',
				'label' => 'Known ClickFix marker line',
				'regex' => '~^[ \t]*.*(?:d3AtY29udGVudC91cGxvYWRz|polygon-rpc|polygon\.drpc\.org|polygon-bor-rpc\.publicnode|polygon-public\.nodies|wp_perf_ok|_cf_verified|cf_verified_token|wp_94d4678186_cfg|wp_a26c00cc40_cfg|wp_0b05838858_cfg|wp_e3ef2393dd_cfg|wp_204acd2d43_cfg|wp_fe99c06901_cfg|wp_b6786d21cb_cfg|wp_a326b31e44_cfg|native-render-toolkit|total-render-profiler|total-render-toolkit|pro-font-optimizer|site-speed-insights|advanced-asset-insights|page-seo-toolkit|starter-image-guard|Health_Manager_5fec|DB_Handler_5dfe|Opt_Handler_841e|Render_Module_5b7d|wp-locale-handler|class-wp-compat|wp-antymalwary|malwary_pass|webanalytics-cdn\.sbs|a7f3e9b2c4d1e5f6).*(?:;|\?>)?[ \t]*\r?$~mi',
			],
			[
				'id'    => 'known_malware_comment_block',
				'label' => 'Known malware marker comment block',
				'regex' => '~\R?[ \t]*(?://|#)[^\r\n]*(?:WordPress Session Cache Handler|WordPress session analytics|wp-perf-analytics|native-render-toolkit|total-render-profiler|total-render-toolkit|pro-font-optimizer|site-speed-insights|advanced-asset-insights|page-seo-toolkit|starter-image-guard|session-manager|wp-locale-handler)[^\r\n]*\R.*?(?=\R[ \t]*(?:/\*\s*That\'s all, stop editing!|require_once\s+ABSPATH\s*\.\s*[\'"]wp-settings\.php[\'"]|define\s*\(|\$table_prefix|if\s*\(\s*!\s*defined\s*\(|$))~is',
			],
		];
	}

	//  Status 

	/**
	 * Return the current hardening status for every tracked item.
	 *
	 * All checks are read-only and safe to run on every page load.
	 *
	 * @return array<string, bool>
	 */
	public static function get_status(): array {
		$htaccess         = ABSPATH . '.htaccess';
		$htaccess_content = file_exists( $htaccess ) ? ( @file_get_contents( $htaccess ) ?: '' ) : '';

		return [
			// wp-config.php constants
			'DISALLOW_FILE_MODS' => defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS === true,
			'DISALLOW_FILE_EDIT' => defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT === true,
			'FORCE_SSL_ADMIN'    => defined( 'FORCE_SSL_ADMIN' )    && FORCE_SSL_ADMIN    === true,

			// .htaccess WPS marker blocks present and matching the expected rule lines
			'php_uploads'    => self::htaccess_rule_is_current( 'php_uploads', $htaccess_content ),
			'xmlrpc'         => self::htaccess_rule_is_current( 'xmlrpc', $htaccess_content ),
			'perf_analytics' => self::htaccess_rule_is_current( 'perf_analytics', $htaccess_content ),

			// Plugin-level protections (always active when the plugin is loaded)
			'wps_blocker' => class_exists( 'WPS_Blocker' ),
			'wps_scanner' => class_exists( 'WPS_Scanner' ),
		];
	}

	//  wp-config.php 

	/**
	 * Add or remove a define() constant in wp-config.php.
	 *
	 * Enable  (true):  If the constant is already defined with any value,
	 *                  the existing line is replaced with define( 'KEY', true );
	 *                  If absent, the line is inserted before the WP stop-editing
	 *                  comment. A backup is placed in the WP Perf Shield quarantine store.
	 *
	 * Disable (false): If the constant is defined, the line is removed entirely.
	 *                  If absent, nothing changes and true is returned.
	 *
	 * @param  string $constant Constant name  must be in ALLOWED_CONSTANTS.
	 * @param  bool   $enable   True to add/set, false to remove.
	 * @return true|string      True on success; error message string on failure.
	 */
	public static function set_wpconfig_constant( string $constant, bool $enable ) {
		if ( ! in_array( $constant, self::ALLOWED_CONSTANTS, true ) ) {
			return 'Constant not in the allowed list.';
		}

		$config = rtrim( ABSPATH, '/\\' ) . '/wp-config.php';
		if ( ! file_exists( $config ) ) {
			return 'wp-config.php not found.';
		}
		if ( ! is_readable( $config ) || ! is_writable( $config ) ) {
			return 'wp-config.php is not readable or not writable. Check file permissions.';
		}

		$contents = @file_get_contents( $config );
		if ( $contents === false ) {
			return 'Could not read wp-config.php.';
		}

		if ( ! self::looks_like_wpconfig( $contents ) ) {
			return 'wp-config.php failed sanity checks before edit. Refusing to modify it automatically.';
		}

		// Regex: match any define() for this constant regardless of value/quoting.
		$pattern = '/^define\s*\(\s*[\'"]' . preg_quote( $constant, '/' )
			. '[\'"]\s*,\s*[^)]+\)\s*;[^\n]*/m';

		if ( $enable ) {
			$new_line = "define( '" . $constant . "', true );";
			if ( preg_match( $pattern, $contents ) ) {
				// Replace existing definition (possibly false or some other value).
				$new_contents = preg_replace( $pattern, $new_line, $contents );
			} else {
				// Insert before the WP stop-editing marker.
				$stop = "/* That's all, stop editing!";
				$pos  = strpos( $contents, $stop );
				if ( $pos === false ) {
					return "Could not find the stop-editing marker in wp-config.php. Add manually:\n" . $new_line;
				}
				$new_contents = substr( $contents, 0, $pos )
					. $new_line . "\n\n"
					. substr( $contents, $pos );
			}
		} else {
			// Remove the constant definition line entirely.
			if ( ! preg_match( $pattern, $contents ) ) {
				return true; // Not defined  nothing to do.
			}
			$new_contents = preg_replace( $pattern, '', $contents );
		}

		if ( $new_contents === null || $new_contents === $contents ) {
			return 'No change was made to wp-config.php  regex may not have matched. Edit manually.';
		}

		// Post-edit sanity: refuse to write a file that no longer looks like wp-config.
		if ( ! self::looks_like_wpconfig( $new_contents ) ) {
			return 'Edited wp-config.php failed sanity checks. No changes were written.';
		}

		// Versioned backup, then atomic write. Each invocation gets its own
		// backup so a second hardening action cannot erase the first one's
		// recovery point.
		$backup = self::backup_wpconfig( $config );
		if ( is_wp_error( $backup ) ) {
			return $backup->get_error_message();
		}

		$tmp = $config . '.wps.tmp';
		if ( @file_put_contents( $tmp, $new_contents ) === false ) {
			@unlink( $tmp );
			return 'Could not write temporary file. Check filesystem permissions.';
		}
		if ( ! @rename( $tmp, $config ) ) {
			@unlink( $tmp );
			return 'Could not replace wp-config.php (rename failed). Try via SSH.';
		}

		return true;
	}

	/**
	 * Scan wp-config.php for known removable malware patterns.
	 *
	 * @return array<int, array<string, string>>
	 */
	public static function scan_wpconfig_malware(): array {
		$config = rtrim( ABSPATH, '/\\' ) . '/wp-config.php';
		if ( ! file_exists( $config ) || ! is_readable( $config ) ) {
			return [];
		}

		$contents = @file_get_contents( $config );
		if ( $contents === false || $contents === '' ) {
			return [];
		}

		$matches = [];
		foreach ( self::wpconfig_malware_patterns() as $pattern ) {
			if ( ! preg_match_all( $pattern['regex'], $contents, $found ) ) {
				continue;
			}

			foreach ( $found[0] as $hit ) {
				$preview = preg_replace( '/\s+/', ' ', trim( (string) $hit ) );
				$matches[] = [
					'id'      => $pattern['id'],
					'label'   => $pattern['label'],
					'preview' => substr( (string) $preview, 0, 180 ),
				];
			}
		}

		return $matches;
	}

	/**
	 * Remove known malware patterns from wp-config.php.
	 *
	 * @return array<string, mixed>|string
	 */
	public static function clean_wpconfig_malware() {
		$config = rtrim( ABSPATH, '/\\' ) . '/wp-config.php';
		if ( ! file_exists( $config ) ) {
			return 'wp-config.php not found.';
		}
		if ( ! is_readable( $config ) || ! is_writable( $config ) ) {
			return 'wp-config.php is not readable or not writable. Check file permissions.';
		}

		$contents = @file_get_contents( $config );
		if ( $contents === false || $contents === '' ) {
			return 'Could not read wp-config.php.';
		}
		if ( ! self::looks_like_wpconfig( $contents ) ) {
			return 'wp-config.php failed sanity checks before cleaning. Refusing to modify it automatically.';
		}

		$cleaned = $contents;
		$removed = [];
		foreach ( self::wpconfig_malware_patterns() as $pattern ) {
			$next = preg_replace_callback(
				$pattern['regex'],
				static function ( array $match ) use ( $pattern, &$removed ): string {
					$preview = preg_replace( '/\s+/', ' ', trim( (string) ( $match[0] ?? '' ) ) );
					$removed[] = [
						'id'      => $pattern['id'],
						'label'   => $pattern['label'],
						'preview' => substr( (string) $preview, 0, 180 ),
					];
					return "\n";
				},
				$cleaned
			);

			if ( $next !== null ) {
				$cleaned = $next;
			}
		}

		$cleaned = preg_replace( "/\n{3,}/", "\n\n", $cleaned );
		if ( $cleaned === null ) {
			return 'Could not normalize cleaned wp-config.php.';
		}

		if ( empty( $removed ) || $cleaned === $contents ) {
			return [
				'changed' => false,
				'removed' => [],
				'message' => 'No known removable wp-config.php malware patterns were found.',
			];
		}

		if ( ! self::looks_like_wpconfig( $cleaned ) ) {
			return 'Cleaned wp-config.php failed sanity checks. No changes were written.';
		}

		$backup = self::backup_wpconfig( $config );
		if ( is_wp_error( $backup ) ) {
			return $backup->get_error_message();
		}

		$tmp = $config . '.wps-clean.tmp';
		if ( @file_put_contents( $tmp, $cleaned ) === false ) {
			@unlink( $tmp );
			return 'Could not write temporary wp-config.php file.';
		}

		$perms = @fileperms( $config );
		if ( $perms !== false ) {
			@chmod( $tmp, $perms & 0777 );
		}

		if ( ! @rename( $tmp, $config ) ) {
			@unlink( $tmp );
			return 'Could not replace wp-config.php (rename failed). Restore from backup or clean manually via SSH.';
		}

		$hash = hash_file( 'sha256', $config );
		if ( $hash !== false ) {
			update_option( 'wps_wpconfig_hash', $hash );
		}
		delete_transient( 'wps_scan_results' );

		return [
			'changed' => true,
			'removed' => $removed,
			'backup'  => $backup,
			'hash'    => $hash !== false ? $hash : '',
			'message' => count( $removed ) . ' wp-config.php malware pattern(s) removed.',
		];
	}

	private static function looks_like_wpconfig( string $contents ): bool {
		return strpos( $contents, 'DB_NAME' ) !== false
			&& strpos( $contents, 'DB_USER' ) !== false
			&& strpos( $contents, 'ABSPATH' ) !== false
			&& strpos( $contents, 'wp-settings.php' ) !== false;
	}

	/**
	 * 1.4.55: safe backup for wp-config.php.
	 *
	 * The three edit paths below each wrote `wp-config.php.wps.bak` beside the
	 * original. That file is not PHP, so the web server hands its contents to
	 * anyone who requests the name - database credentials, table prefix and
	 * every authentication salt. The hardening routine was creating a total
	 * compromise while reporting success.
	 *
	 * 1.3.97 moved remediation backups into the quarantine store for exactly
	 * this reason, with a comment explaining it. Hardening was never migrated.
	 *
	 * Quarantine availability is checked BEFORE the copy rather than after,
	 * because `create_timestamped_backup()` falls back to a filesystem copy
	 * beside the original when the store is unavailable - which for this file
	 * is the very thing being fixed. If a fallback copy is produced anyway it
	 * is removed and the edit refused: a wp-config edit without a safe
	 * recovery point is not worth the exposure it would cost.
	 *
	 * @return string|\WP_Error Quarantine reference, or an error to return to the caller.
	 */
	private static function backup_wpconfig( string $config ) {
		if ( ! class_exists( 'WPS_Utils' ) || ! class_exists( 'WPS_Quarantine' )
			|| ! class_exists( 'WPS_Scanner' ) || ! WPS_Scanner::quarantine_enabled() ) {
			return new \WP_Error(
				'wps_no_safe_backup',
				'Quarantine is switched off, so wp-config.php cannot be backed up safely. '
				. 'Enable Quarantine under Settings before editing wp-config.php - a plain backup '
				. 'beside the original would expose your database credentials to the web.'
			);
		}

		$backup = WPS_Utils::create_timestamped_backup( $config );

		if ( is_wp_error( $backup ) ) {
			return $backup;
		}
		if ( ! is_string( $backup ) || strpos( $backup, 'quarantine:' ) !== 0 ) {
			// Fell back to a filesystem copy. Remove it; it is the exposure.
			if ( is_string( $backup ) && $backup !== '' && is_file( $backup ) ) {
				@unlink( $backup );
			}
			return new \WP_Error(
				'wps_no_safe_backup',
				'Could not place a wp-config.php backup in quarantine. No changes were written.'
			);
		}

		return $backup;
	}

	//  .htaccess 

	private static function htaccess_rule_is_current( string $rule, string $htaccess_content ): bool {
		if ( ! isset( self::HTACCESS_RULES[ $rule ] ) ) {
			return false;
		}

		$marker = self::HTACCESS_RULES[ $rule ]['marker'];
		if ( strpos( $htaccess_content, '# BEGIN ' . $marker ) === false ) {
			return false;
		}

		foreach ( self::HTACCESS_RULES[ $rule ]['lines'] as $line ) {
			if ( strpos( $htaccess_content, $line ) === false ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Apply or remove a named .htaccess rule block using WordPress markers.
	 *
	 * Uses WordPress's built-in insert_with_markers() which writes a
	 * # BEGIN marker / # END marker block  the same mechanism used for
	 * WordPress's own rewrite rules. Multiple calls are idempotent: applying
	 * a rule that is already present simply rewrites the same lines.
	 *
	 * @param  string $rule   Rule key  must be a key in HTACCESS_RULES.
	 * @param  bool   $enable True to apply, false to remove (empty block).
	 * @param  string $ip     IP/CIDR for 'login_ip' rule (unused otherwise).
	 * @return true|string    True on success; error message on failure.
	 */
	public static function set_htaccess_rule( string $rule, bool $enable, string $ip = '' ) {
		if ( ! isset( self::HTACCESS_RULES[ $rule ] ) ) {
			return 'Unknown rule: ' . $rule;
		}

		if ( ! function_exists( 'insert_with_markers' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}

		$def    = self::HTACCESS_RULES[ $rule ];
		$marker = $def['marker'];

		$htaccess = ABSPATH . '.htaccess';
		if ( ! file_exists( $htaccess ) ) {
			// Create a blank .htaccess so insert_with_markers has a target.
			@touch( $htaccess );
		}
		if ( ! is_writable( $htaccess ) ) {
			return '.htaccess is not writable. Apply this rule manually via SSH or your hosting panel.';
		}

		if ( ! $enable ) {
			$removed = self::remove_htaccess_marker_block( $htaccess, $marker );
			if ( $removed !== true ) {
				return $removed;
			}

			$updated = @file_get_contents( $htaccess );
			if ( is_string( $updated ) && self::htaccess_rule_is_current( $rule, $updated ) ) {
				return 'The .htaccess marker block was not removed. Check .htaccess permissions or remove it manually.';
			}

			return true;
		}

		$result = insert_with_markers( $htaccess, $marker, $def['lines'] );
		if ( ! $result ) {
			return 'insert_with_markers() returned false. Check .htaccess permissions.';
		}

		$updated = @file_get_contents( $htaccess );
		if ( ! is_string( $updated ) || ! self::htaccess_rule_is_current( $rule, $updated ) ) {
			return 'The .htaccess rule was written but could not be verified. Check the file manually.';
		}

		return true;
	}

	private static function remove_htaccess_marker_block( string $htaccess, string $marker ) {
		$contents = @file_get_contents( $htaccess );
		if ( ! is_string( $contents ) ) {
			return 'Could not read .htaccess for marker removal.';
		}

		$pattern = '~(?:^|\R)# BEGIN ' . preg_quote( $marker, '~' ) . '\R.*?# END ' . preg_quote( $marker, '~' ) . '(?:\R|$)~s';
		$cleaned = preg_replace( $pattern, "\n", $contents, 1, $count );
		if ( ! is_string( $cleaned ) ) {
			return 'Could not remove the .htaccess marker block.';
		}

		if ( $count === 0 ) {
			return true;
		}

		$cleaned = preg_replace( "/\n{3,}/", "\n\n", trim( $cleaned ) . "\n" );
		if ( ! is_string( $cleaned ) ) {
			return 'Could not normalize .htaccess after marker removal.';
		}

		if ( @file_put_contents( $htaccess, $cleaned, LOCK_EX ) === false ) {
			return 'Could not write .htaccess after marker removal.';
		}

		return true;
	}

	//  Salt rotation 

	/**
	 * Regenerate all eight WordPress auth salts in wp-config.php.
	 *
	 * Fetches a fresh salt block from api.wordpress.org/secret-key/1.1/salt/,
	 * replaces each existing define() for the eight salt constants, and writes
	 * the result atomically. A backup is placed in the quarantine store.
	 *
	 * Side effect: every existing login session is immediately invalidated
	 * because the session token verification uses these salts.
	 *
	 * @return true|string True on success; error message on failure.
	 */
	public static function regenerate_salts() {
		$config = rtrim( ABSPATH, '/\\' ) . '/wp-config.php';
		if ( ! file_exists( $config ) || ! is_readable( $config ) || ! is_writable( $config ) ) {
			return 'wp-config.php not found, not readable, or not writable.';
		}

		$response = wp_safe_remote_get( 'https://api.wordpress.org/secret-key/1.1/salt/', [ 'timeout' => 10 ] );
		if ( is_wp_error( $response ) ) {
			return 'Could not fetch new salts: ' . $response->get_error_message();
		}

		$new_block = wp_remote_retrieve_body( $response );
		if ( empty( $new_block ) || strpos( $new_block, 'AUTH_KEY' ) === false ) {
			return 'Unexpected response from WordPress.org salt API.';
		}

		$salt_keys = [
			'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY',
			'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT',
		];

		$contents = @file_get_contents( $config );
		if ( $contents === false ) {
			return 'Could not read wp-config.php.';
		}

		if ( ! self::looks_like_wpconfig( $contents ) ) {
			return 'wp-config.php failed sanity checks before salt rotation. Refusing to modify it automatically.';
		}

		$original = $contents;
		$replaced_keys = [];

		// The API returns lines in the format:
		// define('AUTH_KEY',         'some long random string');
		// Parse each and replace in wp-config.php.
		foreach ( $salt_keys as $key ) {
			$api_pattern = '/define\s*\(\s*[\'"]' . $key . '[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]\s*\)\s*;/';
			if ( ! preg_match( $api_pattern, $new_block, $api_m ) ) {
				continue; // Couldn't parse this salt from API response  skip.
			}
			$new_line = "define( '" . $key . "', '" . $api_m[1] . "' );";

			$config_pattern = '/define\s*\(\s*[\'"]' . $key . '[\'"]\s*,\s*[^\)]+\)\s*;[^\n]*/';
			if ( preg_match( $config_pattern, $contents ) ) {
				$next = preg_replace( $config_pattern, $new_line, $contents );
				if ( is_string( $next ) && $next !== $contents ) {
					$contents = $next;
					$replaced_keys[] = $key;
				}
			}
		}

		// Refuse to write if nothing actually changed: avoids resetting the
		// baseline backup over an effectively unchanged wp-config.php.
		if ( empty( $replaced_keys ) || $contents === $original ) {
			return 'No salt define() lines matched in wp-config.php. Edit manually.';
		}

		// Post-edit sanity: confirm the file still looks like a real wp-config.
		if ( ! self::looks_like_wpconfig( $contents ) ) {
			return 'Edited wp-config.php failed sanity checks. No changes were written.';
		}

		$backup = self::backup_wpconfig( $config );
		if ( is_wp_error( $backup ) ) {
			return $backup->get_error_message();
		}

		$tmp = $config . '.wps.tmp';
		if ( @file_put_contents( $tmp, $contents ) === false ) {
			@unlink( $tmp );
			return 'Could not write temporary file.';
		}
		if ( ! @rename( $tmp, $config ) ) {
			@unlink( $tmp );
			return 'Could not replace wp-config.php (rename failed).';
		}

		return true;
	}
}
