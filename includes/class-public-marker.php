<?php
/**
 * WP Perf Shield - opt-in public identification marker (1.4.52).
 *
 * Emits a single `<meta name="generator">` tag on front-end pages so that
 * technology profilers - Wappalyzer, BuiltWith, WhatRuns and the various
 * open-source forks - can recognise the plugin. Nothing else about WP Perf
 * Shield is visible to an anonymous visitor: the admin CSS and JavaScript
 * enqueue only on its own settings screen, and the only other front-end
 * output is the opt-in CSP header, which carries no identity.
 *
 * Three decisions are deliberate and are asserted in the test suite.
 *
 * OFF BY DEFAULT. Announcing which security software a site runs is
 * reconnaissance handed to whoever is looking. That may be a trade an operator
 * wants to make for the visibility, but it is theirs to make, and silence is
 * the safer default for a plugin in this category.
 *
 * NEVER THE VERSION. This is the load-bearing one. Site Kit publishes
 * `Site Kit by Google 1.139.0` and for an analytics plugin that costs nothing.
 * Here it would be a lookup table: releases 1.4.48 through 1.4.51 each closed a
 * specific evasion, so a version string tells an attacker exactly which
 * bypasses still work against this install. The tag carries the name and
 * stops.
 *
 * REMOVABLE. The callback is a named method rather than a closure, so
 * `remove_action( 'wp_head', [ 'WPS_Public_Marker', 'render' ] )` works, and
 * the `wps_public_marker` filter can rewrite or empty the markup. Site Kit
 * used a closure and collected years of support requests about it.
 *
 * @package WP_Perf_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPS_Public_Marker {

	/** The published name. No version, by design - see the class comment. */
	const MARKER_NAME = 'WP Perf Shield';

	/**
	 * Whether the operator has opted in. Off unless explicitly enabled, so a
	 * missing or malformed settings array yields silence rather than exposure.
	 */
	public static function enabled(): bool {
		$settings = get_option( WPS_OPTION, [] );
		if ( ! is_array( $settings ) ) {
			return false;
		}
		return ( $settings['public_marker'] ?? '0' ) === '1';
	}

	/**
	 * The markup, or an empty string when disabled or filtered away.
	 *
	 * Separated from render() so the suite can assert what would be emitted
	 * without capturing output, and so the "no version" property can be
	 * checked directly.
	 */
	public static function markup(): string {
		if ( ! self::enabled() ) {
			return '';
		}

		$tag = '<meta name="generator" content="' . esc_attr( self::MARKER_NAME ) . '" />';

		/**
		 * Filter the public identification tag.
		 *
		 * Return an empty string to suppress it while leaving the setting on.
		 *
		 * @param string $tag  The complete meta tag.
		 * @param string $name The published name.
		 */
		$filtered = apply_filters( 'wps_public_marker', $tag, self::MARKER_NAME );

		return is_string( $filtered ) ? $filtered : '';
	}

	/** Print the marker. Hooks `wp_head`, so it never runs in wp-admin. */
	public static function render(): void {
		$tag = self::markup();
		if ( $tag === '' ) {
			return;
		}
		echo $tag . "\n"; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built and escaped in markup()
	}
}
