<?php
/**
 * WP Perf Shield - single-flight scan lock (1.4.60, CRIT-004).
 *
 * Before this existed, nothing stopped two scans running at once. The hourly
 * cron, a manual scan from the dashboard, and a post-upgrade scan could all be
 * in flight simultaneously, each traversing the whole filesystem and each
 * entitled to quarantine or delete. Two workers remediating the same finding
 * is how one of them ends up acting on a path the other has already moved.
 *
 * The acquisition is atomic and it has to be. A read-then-set transient looks
 * like a lock and is not one: two workers can both read "free" before either
 * writes, and both proceed. This uses the row-level uniqueness of the options
 * table instead - an INSERT that either creates the row or fails, with no
 * window between the check and the claim.
 *
 * The lock carries an owner token so a worker can only release its own lock,
 * and an expiry so a crashed worker cannot block scanning forever.
 *
 * @package WP_Perf_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPS_Scan_Lock {

	/** Option name holding the lock. Autoload off: this is written, not read hot. */
	const OPTION = 'wps_scan_lock';

	/**
	 * How long a lock stays valid without a heartbeat.
	 *
	 * Longer than the scan time budget, so a scan that uses its full allowance
	 * does not have its own lock expire underneath it, and short enough that a
	 * worker killed mid-scan does not lock the site out for an operator-visible
	 * length of time.
	 */
	const TTL_SECONDS = 900;

	/** @var string|null Token for the lock this process holds, if any. */
	private static $owner_token = null;

	/**
	 * Try to claim the lock.
	 *
	 * @param string $context Why the scan is running, for the admin display.
	 * @return string|null Owner token on success, null when another scan holds it.
	 */
	public static function acquire( string $context = 'scan' ): ?string {
		global $wpdb;

		self::release_if_stale();

		$token = self::mint_token();
		$value = wp_json_encode( [
			'token'      => $token,
			'context'    => $context,
			'acquired'   => time(),
			'expires'    => time() + self::TTL_SECONDS,
			'pid'        => function_exists( 'getmypid' ) ? (int) getmypid() : 0,
		] );

		if ( ! isset( $wpdb ) || ! is_object( $wpdb ) ) {
			return null; // no database, no safe lock, so no scan
		}

		// The atomic step. INSERT succeeds only if no row exists, because
		// option_name is unique. There is no read-then-write window.
		$inserted = $wpdb->query(
			$wpdb->prepare(
				"INSERT INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')",
				self::OPTION,
				$value
			)
		);

		if ( $inserted ) {
			self::$owner_token = $token;
			return $token;
		}

		return null; // somebody else owns it
	}

	/**
	 * Release the lock, but only if this process owns it.
	 *
	 * The token comparison is the point: without it, a worker finishing late
	 * could delete a lock a different worker had legitimately acquired after
	 * the first one's expiry.
	 */
	public static function release( ?string $token = null ): bool {
		global $wpdb;
		$token = $token ?? self::$owner_token;
		if ( $token === null || ! isset( $wpdb ) || ! is_object( $wpdb ) ) {
			return false;
		}

		$held = self::current();
		if ( ! $held || ( $held['token'] ?? '' ) !== $token ) {
			return false; // not ours to release
		}

		$wpdb->query(
			$wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name = %s", self::OPTION )
		);
		if ( self::$owner_token === $token ) {
			self::$owner_token = null;
		}
		return true;
	}

	/**
	 * Extend the expiry of a lock this process holds.
	 *
	 * A long scan calls this so its own lock does not expire mid-run and let a
	 * second worker in behind it.
	 */
	public static function heartbeat( ?string $token = null ): bool {
		global $wpdb;
		$token = $token ?? self::$owner_token;
		if ( $token === null ) {
			return false;
		}
		$held = self::current();
		if ( ! $held || ( $held['token'] ?? '' ) !== $token ) {
			return false;
		}
		$held['expires'] = time() + self::TTL_SECONDS;
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s",
				wp_json_encode( $held ),
				self::OPTION
			)
		);
		return true;
	}

	/** The lock currently held, or null. */
	public static function current(): ?array {
		global $wpdb;
		if ( ! isset( $wpdb ) || ! is_object( $wpdb ) ) {
			return null;
		}
		$raw = $wpdb->get_var(
			$wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", self::OPTION )
		);
		if ( ! is_string( $raw ) || $raw === '' ) {
			return null;
		}
		$data = json_decode( $raw, true );
		return is_array( $data ) ? $data : null;
	}

	/** Whether a scan is running right now, for the admin screen. */
	public static function is_locked(): bool {
		self::release_if_stale();
		return self::current() !== null;
	}

	/**
	 * Describe the current holder without exposing the token.
	 *
	 * The token is what authorises release, so it is a credential and does not
	 * belong on a screen.
	 */
	public static function describe(): array {
		$held = self::current();
		if ( ! $held ) {
			return [ 'locked' => false ];
		}
		return [
			'locked'   => true,
			'context'  => (string) ( $held['context'] ?? 'scan' ),
			'acquired' => (int) ( $held['acquired'] ?? 0 ),
			'expires'  => (int) ( $held['expires'] ?? 0 ),
			'age'      => max( 0, time() - (int) ( $held['acquired'] ?? time() ) ),
		];
	}

	/** Drop a lock whose owner has evidently died. */
	private static function release_if_stale(): void {
		global $wpdb;
		$held = self::current();
		if ( ! $held ) {
			return;
		}
		$expires = (int) ( $held['expires'] ?? 0 );
		if ( $expires > time() ) {
			return;
		}
		if ( isset( $wpdb ) && is_object( $wpdb ) ) {
			$wpdb->query(
				$wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name = %s", self::OPTION )
			);
			WPS_Logger::write( 'scan lock: released a stale lock (expired ' . ( time() - $expires ) . 's ago)' );
		}
	}

	/** Unguessable owner token. */
	private static function mint_token(): string {
		try {
			return bin2hex( random_bytes( 16 ) );
		} catch ( \Throwable $e ) {
			return hash( 'sha256', uniqid( 'wps', true ) . microtime( true ) );
		}
	}
}
