<?php
/**
 * WP Perf Shield  drop-in integrity guard (1.3.71).
 *
 * The point-in-time check (WPS_Scanner::check_drop_ins, 1.3.54) recognises
 * drop-ins by publisher signature. This guard adds the temporal dimension: it
 * baselines the canonical wp-content/ drop-ins and reports when one is CREATED,
 * MODIFIED, or REMOVED relative to that baseline, logging each event with a UTC
 * timestamp so the operator can correlate it against web-server access logs and
 * SFTP login logs.
 *
 * Two detection paths:
 *
 *   - check() runs in the hourly scan and produces findings for the Overview
 *     tab. It catches drop-ins that persist between scans plus changes and
 *     disappearances since the stored baseline.
 *   - watch() runs on init, throttled to once per WATCH_INTERVAL seconds via a
 *     transient, and logs the precise moment a drop-in appears, changes, or
 *     vanishes. It is cheap: a stat() of each canonical name compared against a
 *     stored mtime|size fingerprint, hashing nothing and writing only when the
 *     fingerprint actually changes.
 *
 * Honest limitation: a db.php loads during wp-settings.php BEFORE any plugin,
 * so a drop-in that writes and self-deletes within a single request cannot be
 * observed by an in-PHP hook. The guard catches drop-ins that persist into a
 * later request and any change or removal detected between checks. For
 * sub-request transients the recovered mtime in the log line is the
 * correlation key.
 *
 * @package WP_Perf_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPS_Dropin_Guard {

	const BASELINE_OPTION = 'wps_dropin_baseline';
	const WATCH_FP_OPTION = 'wps_dropin_watch_fp';
	const WATCH_THROTTLE  = 'wps_dropin_watch_throttle';
	const WATCH_INTERVAL  = 60; // seconds

	private static function content_dir(): string {
		if ( ! defined( 'WP_CONTENT_DIR' ) ) {
			return '';
		}
		$dir = rtrim( WP_CONTENT_DIR, '/\\' );
		return is_dir( $dir ) ? $dir : '';
	}

	/** @return list<string> */
	private static function names(): array {
		if ( method_exists( 'WPS_Scanner', 'drop_in_canonical_names' ) ) {
			return WPS_Scanner::drop_in_canonical_names();
		}
		return [ 'object-cache.php', 'advanced-cache.php', 'db.php', 'db-error.php', 'maintenance.php', 'fatal-error-handler.php', 'install.php', 'php-error.php', 'sunrise.php' ];
	}

	private static function publisher_of( string $contents ): string {
		if ( method_exists( 'WPS_Scanner', 'match_drop_in_publisher' ) ) {
			return WPS_Scanner::match_drop_in_publisher( $contents );
		}
		return '';
	}

	/**
	 * Full state of present drop-ins: name => [hash, mtime, size, publisher].
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function current_state(): array {
		$dir   = self::content_dir();
		$state = [];
		if ( $dir === '' ) {
			return $state;
		}
		foreach ( self::names() as $name ) {
			$path = $dir . DIRECTORY_SEPARATOR . $name;
			if ( ! is_file( $path ) ) {
				continue;
			}
			$contents = @file_get_contents( $path );
			$contents = is_string( $contents ) ? $contents : '';
			$state[ $name ] = [
				'hash'      => hash( 'sha256', $contents ),
				'mtime'     => (int) @filemtime( $path ),
				'size'      => (int) @filesize( $path ),
				'publisher' => self::publisher_of( $contents ),
			];
		}
		return $state;
	}

	public static function has_baseline(): bool {
		return get_option( self::BASELINE_OPTION, null ) !== null;
	}

	/** @return array<string, array<string, mixed>> */
	public static function get_baseline(): array {
		$b = get_option( self::BASELINE_OPTION, [] );
		return is_array( $b ) ? $b : [];
	}

	/**
	 * Store the current state as the clean baseline.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function set_baseline(): array {
		$state = self::current_state();
		update_option( self::BASELINE_OPTION, $state, false );
		return $state;
	}

	/** Build the lightweight mtime|size fingerprint used by watch(). @return array<string, string> */
	private static function fingerprint(): array {
		$dir = self::content_dir();
		$fp  = [];
		if ( $dir === '' ) {
			return $fp;
		}
		foreach ( self::names() as $name ) {
			$path = $dir . DIRECTORY_SEPARATOR . $name;
			if ( is_file( $path ) ) {
				$fp[ $name ] = (int) @filemtime( $path ) . '|' . (int) @filesize( $path );
			}
		}
		return $fp;
	}

	/**
	 * Compare current drop-in state to the stored baseline and emit findings.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function check(): array {
		$found = [];
		$dir   = self::content_dir();
		if ( $dir === '' ) {
			return $found;
		}

		// First run: establish the baseline and defer comparison. The
		// point-in-time check_drop_ins() still flags any unknown-publisher
		// drop-in present right now, so an already-planted drop-in is not
		// hidden by being baselined.
		if ( ! self::has_baseline() ) {
			$state = self::set_baseline();
			WPS_Logger::log_event( 'dropin_baseline_set', 'Initial drop-in baseline established (' . count( $state ) . ' present)' );
			return $found;
		}

		$baseline  = self::get_baseline();
		$current   = self::current_state();
		$dir_label = 'wp-content/';

		foreach ( self::names() as $name ) {
			$in_base = isset( $baseline[ $name ] );
			$in_curr = isset( $current[ $name ] );
			$full    = $dir . DIRECTORY_SEPARATOR . $name;

			if ( ! $in_base && $in_curr ) {
				$pub     = (string) ( $current[ $name ]['publisher'] ?? '' );
				$when    = gmdate( 'Y-m-d H:i:s', (int) ( $current[ $name ]['mtime'] ?? 0 ) );
				$unknown = ( $pub === '' );
				$found[] = [
					'severity'    => $unknown ? 'high' : 'medium',
					'type'        => 'New WordPress drop-in appeared since baseline',
					'subject'     => $dir_label . $name,
					'path'        => $full,
					'action'      => $unknown
						? 'A new drop-in at ' . $dir_label . $name . ' appeared after the clean baseline and matches no known publisher. Drop-ins load before any plugin, so this is a prime backdoor location. File mtime: ' . $when . ' UTC. Correlate that timestamp with web-server access logs and SFTP login logs to find how it was written. Inspect and delete if it is not yours.'
						: 'A new drop-in at ' . $dir_label . $name . ' appeared after the clean baseline. It matches publisher: ' . $pub . '. If you installed or enabled that plugin, re-baseline to accept it (Hardening tab).',
					'delete_path' => $unknown ? $full : '',
				];
				WPS_Logger::log_event( 'dropin_appeared', 'name=' . $name . ' publisher=' . ( $pub !== '' ? $pub : 'UNKNOWN' ) . ' mtime=' . $when . 'Z' );
				continue;
			}

			if ( $in_base && ! $in_curr ) {
				$found[] = [
					'severity' => 'medium',
					'type'     => 'WordPress drop-in removed since baseline',
					'subject'  => $dir_label . $name,
					'path'     => '',
					'action'   => 'The drop-in ' . $dir_label . $name . ' was present at the clean baseline and is now gone. If you removed it, re-baseline to clear this. If you did not, a self-healing backdoor that writes a drop-in, runs it, then deletes it to cover its tracks produces exactly this signature. Check access and SFTP logs around now, and keep the guard running to catch the next write.',
				];
				WPS_Logger::log_event( 'dropin_removed', 'name=' . $name );
				continue;
			}

			if ( $in_base && $in_curr ) {
				$old = (string) ( $baseline[ $name ]['hash'] ?? '' );
				$new = (string) ( $current[ $name ]['hash'] ?? '' );
				if ( $old !== '' && $new !== '' && $old !== $new ) {
					$pub     = (string) ( $current[ $name ]['publisher'] ?? '' );
					$when    = gmdate( 'Y-m-d H:i:s', (int) ( $current[ $name ]['mtime'] ?? 0 ) );
					$unknown = ( $pub === '' );
					$found[] = [
						'severity'    => $unknown ? 'high' : 'medium',
						'type'        => 'WordPress drop-in modified since baseline',
						'subject'     => $dir_label . $name,
						'path'        => $full,
						'action'      => $unknown
							? 'The drop-in ' . $dir_label . $name . ' changed content since the clean baseline and matches no known publisher. Modified: ' . $when . ' UTC. Inspect immediately and correlate the timestamp with access and SFTP logs.'
							: 'The drop-in ' . $dir_label . $name . ' (publisher: ' . $pub . ') changed since baseline. Cache plugins rewrite their drop-in on reconfiguration, so this is usually benign. Re-baseline to accept it (Hardening tab).',
						'delete_path' => '',
					];
					WPS_Logger::log_event( 'dropin_modified', 'name=' . $name . ' publisher=' . ( $pub !== '' ? $pub : 'UNKNOWN' ) . ' mtime=' . $when . 'Z' );
				}
			}
		}

		return $found;
	}

	/**
	 * Lightweight per-request watch. Throttled to once per WATCH_INTERVAL.
	 * Detects appearance, mtime/size change, or disappearance of any canonical
	 * drop-in and logs the precise moment, without hashing.
	 */
	public static function watch(): void {
		if ( self::content_dir() === '' ) {
			return;
		}
		if ( get_transient( self::WATCH_THROTTLE ) ) {
			return;
		}
		set_transient( self::WATCH_THROTTLE, 1, self::WATCH_INTERVAL );

		$fp   = self::fingerprint();
		$prev = get_option( self::WATCH_FP_OPTION, null );

		if ( ! is_array( $prev ) ) {
			update_option( self::WATCH_FP_OPTION, $fp, false );
			return;
		}

		$now     = gmdate( 'Y-m-d H:i:s' );
		$changed = false;

		foreach ( $fp as $name => $sig ) {
			if ( ! isset( $prev[ $name ] ) ) {
				WPS_Logger::log_event( 'dropin_watch_appeared', 'name=' . $name . ' at=' . $now . 'Z' );
				$changed = true;
			} elseif ( $prev[ $name ] !== $sig ) {
				WPS_Logger::log_event( 'dropin_watch_changed', 'name=' . $name . ' at=' . $now . 'Z' );
				$changed = true;
			}
		}
		foreach ( $prev as $name => $sig ) {
			if ( ! isset( $fp[ $name ] ) ) {
				WPS_Logger::log_event( 'dropin_watch_removed', 'name=' . $name . ' at=' . $now . 'Z' );
				$changed = true;
			}
		}

		if ( $changed ) {
			delete_transient( 'wps_scan_results' );
		}
		update_option( self::WATCH_FP_OPTION, $fp, false );
	}

	/**
	 * Operator-initiated re-baseline: accept the current drop-in state as the
	 * new clean reference and resync the watch fingerprint.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function rebaseline(): array {
		$state = self::set_baseline();
		update_option( self::WATCH_FP_OPTION, self::fingerprint(), false );
		delete_transient( 'wps_scan_results' );
		WPS_Logger::log_event( 'dropin_baseline_reset', 'Drop-in baseline manually reset (' . count( $state ) . ' present)' );
		return $state;
	}
}
