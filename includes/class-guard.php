<?php
/**
 * Must-use tamper guard - WITHDRAWN in 1.4.15.
 *
 * This file used to install a must-use plugin that watched for the plugin
 * being removed from the active list and put it back. The idea was sound and
 * the implementation was not: it caused two outages on a production site
 * inside a week, one of them a white screen that could not be cleared from
 * the dashboard, because a must-use plugin is the one thing an operator
 * cannot switch off from wp-admin.
 *
 * What remains here is the removal path. It is not enough to stop installing
 * the guard: a must-use plugin already on disk keeps loading on every request
 * for ever, whether or not this plugin puts it there. So every install that
 * upgrades to 1.4.15 has the files actively deleted and the options cleared.
 *
 * Kept as a class rather than deleted outright so that anything still holding
 * a reference - the diagnostics card, a cached opcode, a stale include - gets
 * a defined answer instead of a fatal.
 *
 * See doc/upgrading.md for what would have to be true before this returns.
 *
 * @package WP_Perf_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class WPS_Guard {

	/** Files the withdrawn feature wrote into mu-plugins. */
	private const MU_FILE     = '0-wps-guard.php';
	private const KEY_FILE    = '.wps-guard-key.php';
	private const EVENTS_FILE = '.wps-guard-events.php';

	/** Options the withdrawn feature used. */
	private const OPTIONS = array(
		'wps_guard_state',
		'wps_guard_rec_at',
		'wps_guard_unsigned_at',
		'wps_guard_notload_at',
		'wps_guard_consent',
	);

	/** Records that removal completed, keyed by the version that did it. */
	private const DONE_OPTION = 'wps_guard_removed';

	/**
	 * Where the must-use directory is. WPMU_PLUGIN_DIR is usually defined but
	 * is not guaranteed on every install, so fall back rather than assume.
	 */
	private static function mu_dir(): string {
		if ( defined( 'WPMU_PLUGIN_DIR' ) ) {
			return rtrim( (string) WPMU_PLUGIN_DIR, '/\\' );
		}
		return rtrim( (string) WP_CONTENT_DIR, '/\\' ) . '/mu-plugins';
	}

	/**
	 * Delete the withdrawn feature's files and options.
	 *
	 * Deliberately narrow: three exact filenames in one directory, and a fixed
	 * list of options. Nothing is globbed, nothing is walked, and nothing this
	 * plugin did not write is touched.
	 *
	 * Safe to call repeatedly. Returns what it actually did, so a caller can
	 * tell the operator whether anything was left behind.
	 *
	 * @return array{removed: array<int, string>, failed: array<int, string>, dir_writable: bool}
	 */
	public static function purge(): array {
		$dir    = self::mu_dir();
		$result = array(
			'removed'      => array(),
			'failed'       => array(),
			'dir_writable' => is_dir( $dir ) && is_writable( $dir ),
		);

		foreach ( array( self::MU_FILE, self::KEY_FILE, self::EVENTS_FILE ) as $name ) {
			$path = $dir . '/' . $name;
			if ( ! @is_file( $path ) ) {
				continue;
			}
			if ( @unlink( $path ) ) {
				$result['removed'][] = $name;
				continue;
			}
			// Could not delete it. Neutering the contents is the next best
			// thing: an inert stub still loads but does nothing, which stops
			// the withdrawn code running even where the file cannot be removed.
			if ( self::MU_FILE === $name
				&& false !== @file_put_contents( $path, "<?php\n// WP Perf Shield: tamper guard withdrawn in 1.4.15. This file is inert and can be deleted.\n" ) ) {
				$result['removed'][] = $name . ' (neutralised - delete it manually)';
				continue;
			}
			$result['failed'][] = $name;
		}

		foreach ( self::OPTIONS as $opt ) {
			delete_option( $opt );
		}
		if ( function_exists( 'delete_transient' ) ) {
			delete_transient( 'wps_guard_tick' );
		}

		return $result;
	}

	/**
	 * Run the removal once per version, cheaply, on ordinary page loads.
	 *
	 * Version-keyed rather than a plain boolean, so that installing an older
	 * build and then upgrading again still cleans up.
	 */
	public static function maybe_purge(): void {
		if ( get_option( self::DONE_OPTION, '' ) === WPS_VERSION ) {
			return;
		}
		$result = self::purge();
		update_option( self::DONE_OPTION, WPS_VERSION, false );

		if ( ( $result['removed'] || $result['failed'] ) && class_exists( 'WPS_Event_Log' ) ) {
			WPS_Event_Log::audit(
				'guard_feature_withdrawn',
				array(
					'object_type' => 'mu-plugin',
					'object_name' => self::MU_FILE,
					'original'    => 'must-use tamper guard installed',
					'new'         => $result['failed']
						? 'removal incomplete; could not delete: ' . implode( ', ', $result['failed'] )
						: 'removed: ' . implode( ', ', $result['removed'] ),
					'reason'      => 'the must-use tamper guard was withdrawn in 1.4.15 after repeated outages; its files are deleted on upgrade because a must-use plugin keeps loading whether or not this plugin installs it',
					'severity'    => $result['failed'] ? 'warning' : 'info',
					'risk'        => $result['failed'] ? 20 : 0,
				)
			);
		}
	}

	/**
	 * Status for the diagnostics card. The shape is unchanged so the caller
	 * needs no special case; the feature simply reports as withdrawn.
	 *
	 * @return array{installed: bool, current: bool, mu_writable: bool, version: string, withdrawn: bool, leftover: bool}
	 */
	public static function status(): array {
		$dir = self::mu_dir();
		return array(
			'installed'   => false,
			'current'     => false,
			'mu_writable' => is_dir( $dir ) && is_writable( $dir ),
			'version'     => '',
			'withdrawn'   => true,
			'leftover'    => @is_file( $dir . '/' . self::MU_FILE ),
		);
	}

	// -------------------------------------------------------------------
	//  No-ops. Kept so a stale reference cannot fatal - a plugin that dies
	//  on an unused code path has learnt nothing from the last fortnight.
	// -------------------------------------------------------------------

	/** @return array{ok: bool, reason: string} */
	public static function install(): array {
		return array( 'ok' => false, 'reason' => 'the must-use tamper guard was withdrawn in 1.4.15' );
	}

	public static function remove(): bool {
		$r = self::purge();
		return empty( $r['failed'] );
	}

	public static function ensure_key(): bool {
		return false;
	}

	public static function import_events(): int {
		return 0;
	}

	public static function write_state( bool $expected_active = true ): bool {
		return false;
	}

	/** @return array<string, mixed>|null */
	public static function read_state(): ?array {
		return null;
	}

	/** @param array<string, mixed> $state */
	public static function state_is_signed( array $state ): bool {
		return false;
	}

	public static function installed_version(): string {
		return '';
	}

	/**
	 * @param mixed $new
	 * @param mixed $old
	 * @return mixed
	 */
	public static function watch_active_plugins( $new, $old = null ) {
		return $new;
	}
}
