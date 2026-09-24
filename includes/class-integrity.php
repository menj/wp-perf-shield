<?php
/**
 * Official-source verification (1.4.96).
 *
 * WordPress publishes cryptographic checksums for core and for every plugin in
 * its directory. This plugin has been fetching both since 1.3.89 and using them
 * only to report modified files. The more valuable use runs in the opposite
 * direction: a file whose hash matches the published release is, by proof,
 * the software its author shipped, and no behavioural rule should be permitted
 * to contradict that.
 *
 * WHY THIS REPLACES A HAND-MAINTAINED LIST.
 *
 * The remediation policy has carried a hardcoded set of "known good" plugin
 * prefixes since 1.4.88: Performance Lab, WP-Optimize, Abstract Box,
 * Auto-justify Content. Every entry was added after a false positive, several
 * of them after this plugin quarantined working software and took a production
 * site down. A list of that kind is only ever as complete as the last incident,
 * and each new entry is a record of damage already done.
 *
 * A checksum answers the same question without waiting for the damage. The
 * WP-Optimize cache classes that broke the site match wordpress.org byte for
 * byte, so under this layer they could not have been removed no matter what the
 * self-concealment heuristic concluded about them. The hardcoded list stays as
 * a fallback for the case where the network is unavailable, and is no longer
 * the primary mechanism.
 *
 * THE INVERSE IS THE STRONGER SIGNAL.
 *
 * A PHP file sitting inside a directory plugin that the official manifest does
 * not list at all did not come from the author. That is the shape of every
 * planted-file case in this project: the backdoored Automattic block plugin
 * carrying two extra files in its assets folder, the loader buried in the
 * Filester upload directory, the shell dropped into WP File Manager. Each was
 * found by a separate bespoke heuristic. The manifest identifies all of them by
 * the same question, asked once.
 *
 * FAILURE BEHAVIOUR.
 *
 * Verification can only ever grant trust here, never withdraw it. A network
 * failure, a premium plugin absent from the directory, or a version that
 * publishes no hashes all resolve to "unknown", which leaves existing behaviour
 * exactly as it was. Nothing becomes more aggressive because a lookup failed.
 */

defined( 'ABSPATH' ) || exit;

final class WPS_Integrity {

	/** Verification verdicts. */
	const VERIFIED = 'verified';   // hash matches the published release
	const FOREIGN  = 'foreign';    // inside a verifiable plugin, absent from its manifest
	const MODIFIED = 'modified';   // listed in the manifest, hash differs
	const UNKNOWN  = 'unknown';    // no manifest available: premium, custom, or offline

	/** Per-request memo so one scan does not re-hash the same file repeatedly. */
	private static $memo = [];

	/**
	 * Verify a file against the official release of whatever ships it.
	 *
	 * @return string One of the verdict constants.
	 */
	public static function verify( string $abs_path ): string {
		$real = realpath( $abs_path );
		if ( ! $real || ! is_file( $real ) ) {
			return self::UNKNOWN;
		}
		if ( isset( self::$memo[ $real ] ) ) {
			return self::$memo[ $real ];
		}
		$verdict = self::determine( $real );
		self::$memo[ $real ] = $verdict;
		return $verdict;
	}

	/** Convenience: is this file provably the software its author published? */
	public static function is_official( string $abs_path ): bool {
		return self::VERIFIED === self::verify( $abs_path );
	}

	private static function determine( string $real ): string {
		$rel = self::relative( $real );
		if ( '' === $rel ) {
			return self::UNKNOWN;
		}
		// Only directory plugins can be verified this way. Core has its own
		// check, and core is never auto-removed regardless.
		if ( ! preg_match( '#^wp-content/plugins/([^/]+)/(.+)$#', $rel, $m ) ) {
			return self::UNKNOWN;
		}
		$slug     = $m[1];
		$in_plugin = $m[2];

		$manifest = self::manifest( $slug );
		if ( ! is_array( $manifest ) || ! $manifest ) {
			return self::UNKNOWN;
		}

		if ( ! isset( $manifest[ $in_plugin ] ) ) {
			// The author's manifest does not mention this file at all.
			return self::FOREIGN;
		}

		$entry = $manifest[ $in_plugin ];
		$type  = (string) ( $entry['type'] ?? '' );
		$want  = (array) ( $entry['hashes'] ?? [] );
		if ( '' === $type || ! $want ) {
			return self::UNKNOWN;
		}
		$have = @hash_file( $type, $real );
		if ( ! is_string( $have ) || '' === $have ) {
			return self::UNKNOWN;
		}
		foreach ( $want as $candidate ) {
			if ( hash_equals( (string) $candidate, $have ) ) {
				return self::VERIFIED;
			}
		}
		return self::MODIFIED;
	}

	/**
	 * Manifest for a plugin slug, or null when none can be obtained.
	 *
	 * Delegates to the scanner's existing fetcher, which already caches for
	 * seven days, negative-caches a definitive 404 and deliberately does not
	 * cache a transport failure.
	 */
	private static function manifest( string $slug ): ?array {
		if ( ! class_exists( 'WPS_Scanner' ) ) {
			return null;
		}
		$dir = ( defined( 'WP_PLUGIN_DIR' ) ? rtrim( WP_PLUGIN_DIR, '/\\' ) : '' ) . '/' . $slug;
		if ( ! is_dir( $dir ) ) {
			return null;
		}
		try {
			$ver = self::call_scanner( 'read_plugin_version', [ $dir, $slug ] );
			if ( ! is_string( $ver ) || '' === $ver ) {
				return null;
			}
			$manifest = self::call_scanner( 'get_plugin_checksums', [ $slug, $ver ] );
			return is_array( $manifest ) ? $manifest : null;
		} catch ( \Throwable $t ) {
			return null;
		}
	}

	/**
	 * The fetcher and version reader are private to the scanner and are reused
	 * here rather than duplicated, because two implementations of the same
	 * lookup would drift and one of them would be wrong.
	 *
	 * @param mixed[] $args
	 * @return mixed
	 */
	private static function call_scanner( string $method, array $args ) {
		if ( ! method_exists( 'WPS_Scanner', $method ) ) {
			return null;
		}
		$m = new ReflectionMethod( 'WPS_Scanner', $method );
		$m->setAccessible( true );
		return $m->invokeArgs( null, $args );
	}

	/** Site-relative, forward-slashed path, or '' when outside the install. */
	private static function relative( string $real ): string {
		$root = defined( 'ABSPATH' ) ? str_replace( '\\', '/', rtrim( ABSPATH, '/\\' ) ) : '';
		if ( '' === $root ) {
			return '';
		}
		$rroot = realpath( $root );
		if ( is_string( $rroot ) && '' !== $rroot ) {
			$root = str_replace( '\\', '/', rtrim( $rroot, '/' ) );
		}
		$p = str_replace( '\\', '/', $real );
		return 0 === strpos( $p, $root . '/' ) ? substr( $p, strlen( $root ) + 1 ) : '';
	}
}
