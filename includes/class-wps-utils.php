<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * WPS_Utils  shared service helpers for path containment, AJAX request
 * gating, remote file fetching, and core file validation. Extracted from
 * wp-perf-shield.php in Phase 2 of the controlled development roadmap so the
 * bootstrap file can stay focused on plugin lifecycle and hook registration.
 */
class WPS_Utils {

	/**
	 * Return true when a resolved child path is inside a resolved parent path.
	 */
	/**
	 * 1.4.16: severity band for an event type, for display weighting.
	 *
	 * The events table previously rendered every row identically, so a
	 * wp-config.php hash change sat in the same visual weight as an admin
	 * screen being viewed. A table where nothing stands out is a table nobody
	 * reads, which defeats the point of keeping the log.
	 *
	 * Prefix matching after the exact list, so new event types inherit a
	 * sensible band instead of silently defaulting to the quietest one.
	 */
	/**
	 * 1.4.21: render a stored UTC timestamp in the site's own timezone.
	 *
	 * Events are stored in UTC and always will be - a log that records local
	 * time is a log that lies twice a year, and one that cannot be compared
	 * against a server log or a host's records. Storage and display are
	 * different problems, and only display was wrong: every screen printed
	 * the stored value directly, so an operator in Kuala Lumpur read every
	 * timestamp eight hours out and did the arithmetic themselves.
	 *
	 * Falls back to the original string rather than throwing, because a
	 * timestamp that cannot be parsed is still better shown than swallowed.
	 */
	public static function local_time( string $stored ): string {
		$clean = trim( str_ireplace( 'UTC', '', $stored ) );
		if ( '' === $clean ) {
			return '';
		}
		try {
			$dt = new DateTimeImmutable( $clean, new DateTimeZone( 'UTC' ) );
		} catch ( \Throwable $t ) {
			return $stored;
		}
		return $dt->setTimezone( self::site_timezone() )->format( 'Y-m-d H:i:s' );
	}

	/** The site's configured timezone, however it happens to be recorded. */
	public static function site_timezone(): DateTimeZone {
		if ( function_exists( 'wp_timezone' ) ) {
			try {
				return wp_timezone();
			} catch ( \Throwable $t ) {
				// fall through
			}
		}
		if ( function_exists( 'get_option' ) ) {
			$name = (string) get_option( 'timezone_string', '' );
			if ( '' !== $name ) {
				try {
					return new DateTimeZone( $name );
				} catch ( \Throwable $t ) {
					// fall through to the offset
				}
			}
			$offset = (float) get_option( 'gmt_offset', 0 );
			if ( 0.0 !== $offset ) {
				$sign    = $offset < 0 ? '-' : '+';
				$abs     = abs( $offset );
				$hours   = (int) $abs;
				$minutes = (int) round( ( $abs - $hours ) * 60 );
				try {
					return new DateTimeZone( sprintf( '%s%02d:%02d', $sign, $hours, $minutes ) );
				} catch ( \Throwable $t ) {
					// fall through
				}
			}
		}
		return new DateTimeZone( 'UTC' );
	}

	/**
	 * Short label for a column heading, so the reader knows what they are
	 * looking at without hovering anything: "MYT", "GMT+8", or "UTC".
	 */
	public static function timezone_label(): string {
		$tz = self::site_timezone();
		try {
			$now  = new DateTimeImmutable( 'now', $tz );
			$abbr = $now->format( 'T' );
		} catch ( \Throwable $t ) {
			return 'UTC';
		}

		// A named zone gives a real abbreviation (MYT, EDT, JST). A pure
		// offset zone gives something like "+08" or "+0530", which reads
		// better as GMT+8 and GMT+5:30.
		if ( 1 === preg_match( '/^[A-Za-z]{2,5}$/', $abbr ) ) {
			return $abbr;
		}

		// Worded as WordPress words it. The Settings screen offers "UTC+8",
		// so a heading reading "GMT+8" would be the same fact in a second
		// vocabulary, leaving the reader to work out they match.
		$mins = (int) round( $now->getOffset() / 60 );
		if ( 0 === $mins ) {
			return 'UTC';
		}
		$sign = $mins < 0 ? '-' : '+';
		$mins = abs( $mins );
		$h    = intdiv( $mins, 60 );
		$m    = $mins % 60;
		return 'UTC' . $sign . $h . ( $m ? ':' . str_pad( (string) $m, 2, '0', STR_PAD_LEFT ) : '' );
	}

	/**
	 * 1.4.21: collapse a run of identical steps.
	 *
	 * An incident of seventy-eight failed sign-ins rendered as the words
	 * "login failed" repeated across the width of the screen, which pushed
	 * out everything worth reading. The count is the information; the
	 * repetition is not.
	 *
	 * @param array<int, string> $steps
	 */
	public static function collapse_steps( array $steps, int $max = 6 ): string {
		$runs = [];
		foreach ( $steps as $step ) {
			$step = trim( (string) $step );
			if ( '' === $step ) {
				continue;
			}
			$last = count( $runs ) - 1;
			if ( $last >= 0 && $runs[ $last ]['label'] === $step ) {
				++$runs[ $last ]['n'];
				continue;
			}
			$runs[] = [ 'label' => $step, 'n' => 1 ];
		}

		$out = [];
		foreach ( array_slice( $runs, 0, $max ) as $run ) {
			$out[] = $run['n'] > 1 ? $run['label'] . ' x' . $run['n'] : $run['label'];
		}
		$hidden = count( $runs ) - $max;
		if ( $hidden > 0 ) {
			$out[] = '+' . $hidden . ' more';
		}
		return implode( ' -> ', $out );
	}

	/**
	 * 1.4.25: resolve PHP string escapes so content signatures cannot be
	 * evaded by writing them in hex.
	 *
	 * A live sample recovered from an infected site wrote its cloaking test as
	 * "\\x48\\x54\\x54\\x50_USER_AGENT" rather than as the plain constant. Every
	 * signature in this scanner matched raw bytes, so the whole content-based
	 * detection layer walked past it. This is not a missing signature; it is a
	 * bypass that defeats all of them at once, which is why the fix belongs
	 * here rather than in any single check.
	 *
	 * Both PHP escape forms are handled - hexadecimal (\\x41) and octal (\\101) -
	 * along with the split-literal trick ('bas'.'e64_decode'), which is the
	 * other cheap way to break a grep.
	 *
	 * Bounded: content beyond the cap is returned untouched rather than
	 * expanded, because this runs across every PHP file on a site.
	 */
	public static function deobfuscate_literals( string $content, int $max_bytes = 1048576 ): string {
		if ( '' === $content || strlen( $content ) > $max_bytes ) {
			return $content;
		}

		// Hex and octal escapes.
		$out = preg_replace_callback(
			'/\\\\x([0-9A-Fa-f]{2})|\\\\([0-7]{1,3})/',
			static function ( array $m ): string {
				if ( isset( $m[2] ) && '' !== $m[2] ) {
					$v = octdec( $m[2] );
				} else {
					$v = hexdec( $m[1] );
				}
				// Only fold back printable bytes. Turning escapes into control
				// characters would corrupt the text for later matching.
				return ( $v >= 32 && $v <= 126 ) ? chr( $v ) : $m[0];
			},
			$content
		);
		if ( ! is_string( $out ) ) {
			return $content;
		}

		// Concatenated string literals: 'bas' . 'e64_decode' -> 'base64_decode'.
		$prev = '';
		$i    = 0;
		while ( $prev !== $out && $i < 4 ) {
			$prev = $out;
			$out  = preg_replace( '/([\'"])\s*\.\s*\1/', '', $out ) ?? $out;
			++$i;
		}

		return $out;
	}

	/**
	 * 1.4.25: density of goto statements, as a control-flow-flattening tell.
	 *
	 * Obfuscators scatter labels and jumps through a file so that reading it
	 * top to bottom tells you nothing. PHP supports goto but real code
	 * essentially never uses it, and unlike a string it cannot be escaped or
	 * renamed away without the file ceasing to work. That makes it a far more
	 * durable signal than any keyword.
	 *
	 * @return array{count: int, per_kb: float}
	 */
	/**
	 * 1.4.37: remove PHP comments before matching a function call.
	 *
	 * PHP permits a comment between a function name and its bracket, so
	 * `/*     *\/@eval/*     *\/($x)` calls eval while defeating every pattern
	 * that looks for `eval` followed by whitespace and a bracket. A sample
	 * recovered from a live site used exactly that, and it walked past the
	 * decoder-chain check added in 1.4.34 for that reason alone.
	 *
	 * Kept separate from deobfuscate_literals() deliberately. That method is
	 * used to compare a file against itself with its split literals rejoined,
	 * and removing comments as well would make almost every file differ from
	 * its own normalised form, destroying that comparison.
	 *
	 * String contents are preserved: only comments outside strings go, so a
	 * URL containing // inside quotes survives.
	 */
	/**
	 * 1.4.47: normalise a file once per scan, not once per check.
	 *
	 * Six content checks call strip_php_comments() and deobfuscate_literals()
	 * on every file they examine. Both are character-level PHP loops, and on a
	 * four-hundred-kilobyte file one pass costs about fifty milliseconds. Six
	 * passes over three hundred such files is eighty-five seconds, which is
	 * how a scan came to exceed a thirty-second execution limit and trip safe
	 * mode on a live site.
	 *
	 * The work was never the problem; doing it six times was. Each file is now
	 * normalised once and the result shared.
	 *
	 * Bounded by total bytes held rather than by entry count, because one
	 * enormous file can cost more memory than a thousand small ones - the
	 * distinction that made an unbounded store take a site down in 1.4.13.
	 *
	 * Keyed on a hash of the CONTENT, not on path, size and mtime. The first
	 * draft used mtime and a test caught it serving stale results: PHP caches
	 * stat() calls, so filemtime() returned the old value for a file edited
	 * moments earlier. That is the same clearstatcache defect this project hit
	 * in 1.4.2 and again in 1.4.13. Hashing the input removes the class of
	 * problem rather than working around it - the content is what is being
	 * transformed, so the content is the correct key.
	 *
	 * @var array<string, string>
	 */
	private static $normal_cache = [];
	private static $normal_bytes = 0;

	private const NORMAL_CACHE_MAX_BYTES = 8388608; // 8 MB held at most

	/**
	 * The comment-stripped, literal-rejoined form of a file, computed once.
	 */
	public static function normalised( string $path, string $raw ): string {
		$key = 'n:' . md5( $raw );
		if ( isset( self::$normal_cache[ $key ] ) ) {
			return self::$normal_cache[ $key ];
		}

		$out = self::deobfuscate_literals( self::strip_php_comments( $raw ) );

		// Never cache more than the ceiling. Past it, keep computing and
		// return correctly - slower, but never a memory problem.
		$len = strlen( $out );
		if ( ( self::$normal_bytes + $len ) <= self::NORMAL_CACHE_MAX_BYTES ) {
			self::$normal_cache[ $key ] = $out;
			self::$normal_bytes        += $len;
		}
		return $out;
	}

	/**
	 * The comment-stripped form alone, for checks that do not need literals
	 * rejoined. Shares the same ceiling, since it is the expensive half.
	 */
	public static function stripped( string $path, string $raw ): string {
		$key = 's:' . md5( $raw );
		if ( isset( self::$normal_cache[ $key ] ) ) {
			return self::$normal_cache[ $key ];
		}
		$out = self::strip_php_comments( $raw );
		$len = strlen( $out );
		if ( ( self::$normal_bytes + $len ) <= self::NORMAL_CACHE_MAX_BYTES ) {
			self::$normal_cache[ $key ] = $out;
			self::$normal_bytes        += $len;
		}
		return $out;
	}

	/** Release the cache. Called when a scan finishes. */
	public static function clear_normalised_cache(): void {
		self::$normal_cache = [];
		self::$normal_bytes = 0;
	}

	public static function strip_php_comments( string $content, int $max_bytes = 2097152 ): string {
		if ( '' === $content || strlen( $content ) > $max_bytes ) {
			return $content;
		}
		$out    = '';
		$len    = strlen( $content );
		$i      = 0;
		$quote  = '';
		while ( $i < $len ) {
			$ch = $content[ $i ];

			if ( '' !== $quote ) {
				$out .= $ch;
				if ( '\\' === $ch && $i + 1 < $len ) {
					$out .= $content[ $i + 1 ];
					$i   += 2;
					continue;
				}
				if ( $ch === $quote ) {
					$quote = '';
				}
				++$i;
				continue;
			}

			if ( "'" === $ch || '"' === $ch ) {
				$quote = $ch;
				$out  .= $ch;
				++$i;
				continue;
			}

			if ( '/' === $ch && $i + 1 < $len && '*' === $content[ $i + 1 ] ) {
				$end = strpos( $content, '*/', $i + 2 );
				$i   = ( false === $end ) ? $len : $end + 2;
				// A comment can separate tokens, so leave a space behind it.
				$out .= ' ';
				continue;
			}
			if ( '/' === $ch && $i + 1 < $len && '/' === $content[ $i + 1 ] ) {
				$end  = strpos( $content, "\n", $i );
				$i    = ( false === $end ) ? $len : $end;
				$out .= ' ';
				continue;
			}
			if ( '#' === $ch && ( $i + 1 >= $len || '[' !== $content[ $i + 1 ] ) ) {
				$end  = strpos( $content, "\n", $i );
				$i    = ( false === $end ) ? $len : $end;
				$out .= ' ';
				continue;
			}

			$out .= $ch;
			++$i;
		}
		return $out;
	}

	public static function goto_density( string $content ): array {
		$n = preg_match_all( '/\bgoto\s+[A-Za-z_][A-Za-z0-9_]*\s*;/', $content );
		$n = is_int( $n ) ? $n : 0;
		$kb = max( 1.0, strlen( $content ) / 1024 );
		return [ 'count' => $n, 'per_kb' => round( $n / $kb, 2 ) ];
	}

	public static function event_severity( string $type ): string {
		$type = strtolower( trim( $type ) );

		// Keys are the event types this plugin actually emits, verified
		// against the log_event()/audit() call sites rather than written from
		// memory. The first draft of this map keyed the wp-config change on
		// 'wp_config_hash_changed', which is emitted nowhere - so the single
		// most serious event a site can raise would have rendered as routine.
		$exact = [
			// Something is wrong on this site, now.
			'wp_config_modified'            => 'critical',
			'core_integrity_fail'           => 'critical',
			'attacker_account_found'        => 'critical',
			'hidden_admin_user'             => 'critical',
			'malware_username_in_db'        => 'critical',
			'malware_email_pattern_in_db'   => 'critical',
			'admin_cookie_stealer_confirmed' => 'critical',
			'obfuscated_loader_confirmed'   => 'critical',
			'clickfix_shape_match'          => 'critical',
			'redrop_detected'               => 'critical',
			'self_integrity_failed'         => 'critical',
			'default_role_escalated'        => 'critical',
			'theme_loader_plugin_match'     => 'critical',

			// Worth opening today.
			'scan_issues'                   => 'high',
			'activation_blocked'            => 'high',
			'upload_blocked'                => 'high',
			'upload_path_blocked'           => 'high',
			'removed_from_db'               => 'high',
			'removed_from_network_db'       => 'high',
			'force_deactivated'             => 'high',
			'network_force_deactivated'     => 'high',
			'auto_deactivated'              => 'high',
			'unknown_drop_in'               => 'high',
			'dropin_appeared'               => 'high',
			'dropin_modified'               => 'high',
			'maintenance_stale'             => 'high',
			'registration_opened'           => 'high',
			'plugin_metadata_camouflage'    => 'high',
			'obfuscated_loader_structure'   => 'high',
			'obfuscated_js_injector_dropper' => 'high',
			'obfuscated_js_injector_payload' => 'high',
			'admin_cookie_stealer_unresolved' => 'high',
			'auto_deleted'                  => 'high',

			// Notable, routine, or partially completed work.
			'ip_auto_blocked'               => 'warning',
			'ip_request_blocked'            => 'warning',
			'ip_block_refreshed'            => 'warning',
			'login_failed'                  => 'warning',
			'plugin_activated'              => 'warning',
			'plugin_deactivated'            => 'warning',
			'user_deleted'                  => 'warning',
			'rate_limited'                  => 'warning',
			'scan_budget_exhausted'         => 'warning',
			'remote_fetch_failed'           => 'warning',
			'exfil_delete_failed'           => 'warning',
			'user_ini_clean_failed_post_verify'  => 'warning',
			'wfwaf_clean_failed_post_verify'     => 'warning',
			'wp_config_clean_skipped'       => 'warning',
			// 1.4.73: injected spam content, found at scan time and at save time.
			'injected_spam_content'         => 'high',
			'disguised_plugin_index_found'  => 'critical',
			'spam_post_injection_detected'  => 'high',

			// 1.4.62: site-policy plugin bans. Not malware - an operator
			// refusing an ordinary plugin - so these sit at warning, not the
			// 'blocked' -> 'high' band the prefix fallback would otherwise
			// assign. Every key here is emitted by WPS_Blocker's policy path.
			'policy_activation_blocked'          => 'warning',
			'policy_upload_blocked'              => 'warning',
			'policy_force_deactivated'           => 'warning',
			'policy_network_force_deactivated'   => 'warning',
			'policy_removed_from_db'             => 'warning',
			'policy_removed_from_network_db'     => 'warning',

			// 1.4.64: the event-chain self-test run marks a routine verification.
			'chain_selftest'                     => 'ok',

			// Work completed successfully - green, not grey, because a
			// remediation that worked is worth seeing.
			'scan_clean'                    => 'ok',
			'login_cleaned'                 => 'ok',
			'functions_cleaned'             => 'ok',
			'cron_replaced'                 => 'ok',
			'cron_purged'                   => 'ok',
			'wp_config_cleaned'             => 'ok',
			'user_ini_cleaned'              => 'ok',
			'wfwaf_cleaned'                 => 'ok',
			'sessions_invalidated'          => 'ok',
			'salts_regenerated'             => 'ok',
			'transients_cleared'            => 'ok',
			'ip_blocks_cleared'             => 'ok',
		];

		if ( isset( $exact[ $type ] ) ) {
			return $exact[ $type ];
		}

		foreach ( [
			'malware_'   => 'critical',
			'_confirmed' => 'critical',
			'_escalat'   => 'critical',
			'obfuscated' => 'high',
			'dropin_'    => 'high',
			'redrop_'    => 'high',
			'blocked'    => 'high',
			'_deleted'   => 'warning',
			'failed'     => 'warning',
			'ip_'        => 'warning',
			'_cleaned'   => 'ok',
			'baseline'   => 'info',
			'guard_'     => 'info',
			'debug'      => 'info',
		] as $needle => $band ) {
			if ( strpos( $type, $needle ) !== false ) {
				return $band;
			}
		}
		return 'info';
	}

	/**
	 * 1.4.16: a readable label for an event type.
	 *
	 * The curated map wins. Anything not in it used to be printed raw, which
	 * is why a log read "admin_screen_visited" on one line and "Scan found
	 * issues" on the next. Unmapped types are now humanised rather than shown
	 * as identifiers, so the column reads as English whether or not anyone
	 * remembered to add the label.
	 *
	 * @param array<string, string> $labels
	 */
	public static function event_label( string $type, array $labels = [] ): string {
		if ( isset( $labels[ $type ] ) && $labels[ $type ] !== '' ) {
			return $labels[ $type ];
		}
		if ( trim( $type ) === '' ) {
			return 'Event';
		}
		$pretty = str_replace( [ '_', '-' ], ' ', strtolower( trim( $type ) ) );
		$pretty = preg_replace( '/\s+/', ' ', $pretty );
		return ucfirst( (string) $pretty );
	}

	public static function path_is_inside( string $child, string $parent ): bool {
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
	 * Shared destructive-action guard for AJAX handlers (Phase 1).
	 *
	 * Verifies the wps_nonce and that the current user has the required
	 * capability, with an optional manage_options fallback for older installs
	 * where the more specific capability may not be granted to the site
	 * administrator. Sends a JSON error and dies on failure.
	 *
	 * @param string $cap         Required capability (e.g. 'delete_plugins').
	 * @param bool   $allow_admin When true, current_user_can('manage_options')
	 *                            is accepted as an alternative. Default true.
	 */
	public static function guard_request( string $cap = 'manage_options', bool $allow_admin = true ): void {
		check_ajax_referer( 'wps_nonce', 'nonce' );
		$ok = current_user_can( $cap );
		if ( ! $ok && $allow_admin && $cap !== 'manage_options' ) {
			$ok = current_user_can( 'manage_options' );
		}
		if ( ! $ok ) {
			wp_die( 'Forbidden', '', [ 'response' => 403 ] );
		}
	}

	/**
	 * Resolve a candidate path and assert it is contained within an allowed base
	 * directory. Returns the canonical realpath on success or false on any
	 * containment failure.
	 *
	 * @param string $candidate Untrusted path from a request.
	 * @param string $base      Trusted base directory the path must live inside.
	 * @return string|false     Realpath of the candidate, or false.
	 */
	/**
	 * 1.4.0: per-user cooldown on destructive actions (Hardening II). One
	 * bucket per action name; a repeat inside the window is refused with the
	 * wait time, and the refusal itself is recorded as a rate_limited event.
	 * Scripted rapid-fire against destructive endpoints - the audit's abuse
	 * case - hits the wall on the second call. Fails closed only for the
	 * repeat; the first call always proceeds.
	 */
	public static function enforce_cooldown( string $bucket, int $seconds = 10 ): void {
		if ( ! function_exists( 'get_transient' ) ) {
			return; // no transient API (harness/CLI edge) - cooldown cannot apply
		}
		$uid = function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0;
		$key = 'wps_cd_' . $uid . '_' . sanitize_key( $bucket );
		$hit = get_transient( $key );
		if ( $hit !== false ) {
			$remaining = max( 1, (int) $hit - time() );
			if ( class_exists( 'WPS_Event_Log' ) ) {
				WPS_Event_Log::audit( 'rate_limited', [
					'object_type' => 'action',
					'object_name' => $bucket,
					'reason'      => 'repeat destructive action inside the ' . $seconds . 's cooldown window',
					'severity'    => 'warning',
					'risk'        => 20,
				] );
			}
			wp_send_json_error( [ 'error' => 'Cooling down: "' . $bucket . '" ran moments ago. Wait ' . $remaining . 's and try again. (Destructive actions are rate-limited to blunt scripted abuse.)' ] );
			return; // unreachable in WP (wp_send_json_error dies); explicit for harnesses
		}
		set_transient( $key, time() + $seconds, $seconds );
	}

	/**
	 * 1.4.5: collapse adjacent string-literal concatenations.
	 *
	 * Malware increasingly splits every meaningful identifier across
	 * concatenated fragments - 'wp' . '_foo' . 'ter', 'goog' . 'lebot',
	 * 's' . 'c' . 'r' . 'i' . 'p' . 't' - so that grep, and every
	 * content-matching scanner built on it, finds nothing. A confirmed sample
	 * had ZERO plaintext occurrences of wp_footer, googlebot, administrator,
	 * or eth_call while using all four.
	 *
	 * Running the source through this first restores the literals, which means
	 * every existing indicator list keeps working against split-literal
	 * evasion instead of being silently defeated by it. Purely a read-side
	 * normalisation: nothing is written back to disk.
	 *
	 * Bounded deliberately - large inputs are skipped and the rewrite passes
	 * are capped, because this runs across a whole site tree.
	 */
	public static function normalise_split_literals( string $src ): string {
		if ( $src === '' || strlen( $src ) > 1048576 ) {
			return $src; // too large to be worth normalising in a full-tree walk
		}
		if ( strpos( $src, "'" ) === false && strpos( $src, '"' ) === false ) {
			return $src;
		}

		$single = "/'([^'\\\\]*)'\\s*\\.\\s*'([^'\\\\]*)'/";
		$double = '/"([^"\\\\]*)"\\s*\\.\\s*"([^"\\\\]*)"/';

		// Each pass halves the number of fragments, so a handful of passes
		// collapses even long chains; the cap stops pathological input.
		for ( $i = 0; $i < 12; $i++ ) {
			$before = $src;
			$src    = (string) preg_replace( $single, "'$1$2'", $src );
			$src    = (string) preg_replace( $double, '"$1$2"', $src );
			if ( $src === $before ) {
				break;
			}
		}
		return $src;
	}

	/**
	 * Count adjacent short-literal concatenations. High density is itself the
	 * evasion signature: across this plugin's own 24 files - 315 KB of code -
	 * the highest count in any single file is 3, while the confirmed sample
	 * carried 70 in under 5 KB.
	 */
	public static function split_literal_count( string $src ): int {
		if ( $src === '' || strlen( $src ) > 1048576 ) {
			return 0;
		}
		$n  = preg_match_all( "/'[^'\\\\]{0,12}'\\s*\\.\\s*'[^'\\\\]{0,12}'/", $src );
		$n += preg_match_all( '/"[^"\\\\]{0,12}"\\s*\\.\\s*"[^"\\\\]{0,12}"/', $src );
		return (int) $n;
	}

	public static function guard_path( string $candidate, string $base ) {
		$real = realpath( $candidate );
		if ( ! $real ) {
			return false;
		}
		if ( ! self::path_is_inside( $real, $base ) ) {
			return false;
		}
		return $real;
	}

	/**
	 * Return true if a resolved path is the WP Perf Shield plugin folder itself
	 * (or contained within it). Used to prevent self-deletion in remediation
	 * handlers that act on plugin folders or arbitrary files.
	 */
	public static function path_is_self( string $real_path ): bool {
		$self = realpath( WPS_DIR );
		if ( ! $self ) {
			return false;
		}
		return $real_path === $self || self::path_is_inside( $real_path, WPS_DIR );
	}

	/**
	 * Boundary-safe string comparison for paths that may no longer exist.
	 */
	public static function path_string_is_same_or_child( string $child, string $parent ): bool {
		$child_norm  = rtrim( str_replace( '\\', '/', $child ), '/' );
		$parent_norm = rtrim( str_replace( '\\', '/', $parent ), '/' );

		if ( $child_norm === '' || $parent_norm === '' ) {
			return false;
		}

		return $child_norm === $parent_norm || strpos( $child_norm, $parent_norm . '/' ) === 0;
	}

	/**
	 * Create a non-overwriting timestamped backup next to a file.
	 *
	 * @return string|WP_Error Absolute backup path on success.
	 */
	public static function create_timestamped_backup( string $path ) {
		if ( ! is_file( $path ) || ! is_readable( $path ) ) {
			return new WP_Error( 'wps_backup_unreadable', 'Original file is not readable: ' . basename( $path ) );
		}

		// 1.3.97: capture the pre-clean copy into the protected quarantine store
		// (neutralised, non-executable, auto-purged) rather than dropping a
		// .wps-backup copy of a possibly-infected file beside the original in the
		// webroot, where it stays executable under a guessable name and can be
		// re-triggered through a second extension. Copy mode leaves the live file
		// in place to receive its cleaned bytes; the return value is prefixed
		// 'quarantine:' so callers can label it (see backup_location_label()).
		if ( class_exists( 'WPS_Quarantine' ) && class_exists( 'WPS_Scanner' ) && WPS_Scanner::quarantine_enabled() ) {
			$id = WPS_Quarantine::quarantine(
				$path,
				[
					'type'   => 'pre_clean_backup',
					'reason' => 'pre-clean snapshot of ' . basename( $path ),
				],
				false
			);
			if ( $id !== null ) {
				return 'quarantine:' . $id;
			}
			// fall through to a filesystem backup if the store refused or failed
		}

		$stamp  = gmdate( 'Ymd-His' );
		$backup = $path . '.wps-backup-' . $stamp;
		$suffix = 1;
		while ( file_exists( $backup ) ) {
			$backup = $path . '.wps-backup-' . $stamp . '-' . $suffix;
			$suffix++;
		}

		if ( ! @copy( $path, $backup ) ) {
			return new WP_Error( 'wps_backup_failed', 'Could not create backup for ' . basename( $path ) . '. Check file permissions.' );
		}

		return $backup;
	}

	/**
	 * Human-readable location for a create_timestamped_backup() return value:
	 * a store id becomes a pointer to the Quarantine card, a filesystem path
	 * becomes its basename (legacy fallback behaviour).
	 *
	 * @param string|\WP_Error $backup
	 */
	public static function backup_location_label( $backup ): string {
		if ( is_string( $backup ) && strpos( $backup, 'quarantine:' ) === 0 ) {
			return 'WP Perf Shield quarantine (restore it from the Quarantine card under Forensics)';
		}
		return basename( (string) $backup );
	}

	/**
	 * Fetch a trusted remote replacement file through the WordPress HTTP API.
	 *
	 * @return string|WP_Error
	 */
	public static function fetch_remote_file( string $url, int $timeout = 10 ) {
		$response = wp_safe_remote_get( $url, [
			'timeout'     => $timeout,
			'redirection' => 3,
		] );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( $code < 200 || $code >= 300 ) {
			return new WP_Error( 'wps_http_error', 'Unexpected HTTP status ' . $code . ' from ' . $url );
		}

		$body = wp_remote_retrieve_body( $response );
		if ( ! is_string( $body ) || $body === '' ) {
			return new WP_Error( 'wps_empty_response', 'Empty response from ' . $url );
		}

		return $body;
	}

	/**
	 * Validate a downloaded wp-cron.php replacement without relying on fragile
	 * text that is not present in every WordPress release.
	 */
	public static function is_clean_wp_cron( string $contents ): bool {
		if ( strlen( $contents ) < 3000 ) {
			return false;
		}

		$required = [
			'wp-load.php',
			'DOING_CRON',
			'wp_get_ready_cron_jobs',
			'wp_reschedule_event',
			'wp_unschedule_event',
		];

		foreach ( $required as $needle ) {
			if ( strpos( $contents, $needle ) === false ) {
				return false;
			}
		}

		$bad = [
			'wp-antymalwary',
			'a3f8b2c1d4e5f607',
			'd3AtY29udGVudC91cGxvYWRz',
			'wp_session_tokens_config',
			'session-manager.php',
			'class-wp-compat',
			'polygon-rpc',
			'base64_decode',
			'eval(',
			'file_put_contents',
		];

		foreach ( $bad as $needle ) {
			if ( stripos( $contents, $needle ) !== false ) {
				return false;
			}
		}

		return true;
	}
}
