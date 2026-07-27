<?php
/**
 * WP Perf Shield  opt-in Content-Security-Policy (1.3.76).
 *
 * Why this exists: the visitor-facing half of the ClickFix campaign is injected
 * inline JavaScript that paints the fake CAPTCHA and reaches out to a C2 or a
 * Binance Smart Chain node. A CSP `connect-src` can stop that script from
 * phoning home even on an already-injected page, and `object-src` / `base-uri`
 * / `frame-ancestors` add low-risk hardening. CSP is also the single easiest
 * way to break a legitimate WordPress site, so this feature is built to be safe
 * before it is strict:
 *
 *   - OFF by default. Nothing is emitted unless the operator opts in.
 *   - REPORT-ONLY is the front door. In that mode the browser never blocks
 *     anything; it only posts violation reports, so the operator can see what
 *     WOULD break (and spot the malware's outbound calls) before enforcing.
 *   - The default policy is permissive exactly where WordPress breaks, it keeps
 *     'unsafe-inline'/'unsafe-eval' for script and style, and strict only where
 *     that is both low-risk and relevant to this malware (connect-src 'self',
 *     object-src 'none', base-uri 'self', frame-ancestors 'self'). connect-src
 *     'self' is the one that surfaces, and later blocks, the C2/BSC callback;
 *     the operator widens it to their legitimate third parties from the reports
 *     before switching to enforce.
 *   - Front-end only. Never emitted in wp-admin, AJAX, REST, cron, or feeds,
 *     where inline scripts are unavoidable and would only generate noise.
 *
 * The report endpoint is public (browsers post reports unauthenticated), so it
 * is hardened: it stores nothing when CSP is off, ignores bodies over 8 KB,
 * throttles writes, truncates every field, and keeps only the most recent
 * reports in a ring buffer.
 *
 * @package WP_Perf_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPS_Csp {

	const REPORTS_OPTION  = 'wps_csp_reports';
	const THROTTLE_TRANS  = 'wps_csp_report_throttle';
	const MAX_REPORTS     = 50;
	const MAX_FIELD_LEN   = 300;
	const MAX_BODY_BYTES  = 8192;
	const REST_NS         = 'wp-perf-shield/v1';
	const REST_ROUTE      = '/csp-report';

	/** Read CSP settings from the shared plugin option. */
	private static function settings(): array {
		$o        = get_option( WPS_OPTION, [] );
		$o        = is_array( $o ) ? $o : [];
		$mode_raw = $o['csp_mode'] ?? 'off';
		return [
			'mode'   => in_array( $mode_raw, [ 'off', 'report', 'enforce' ], true ) ? $mode_raw : 'off',
			'policy' => is_string( $o['csp_policy'] ?? null ) && trim( $o['csp_policy'] ) !== '' ? $o['csp_policy'] : self::default_policy(),
		];
	}

	public static function get_mode(): string {
		return self::settings()['mode'];
	}

	public static function get_policy(): string {
		return self::settings()['policy'];
	}

	/**
	 * Baseline policy: permissive where WordPress breaks, strict where it is
	 * both safe and anti-ClickFix. report-uri is appended at emit time.
	 */
	public static function default_policy(): string {
		return "default-src 'self'; "
			. "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
			. "style-src 'self' 'unsafe-inline'; "
			. "img-src 'self' data: blob: https:; "
			. "font-src 'self' data: https:; "
			. "connect-src 'self'; "
			. "object-src 'none'; "
			. "base-uri 'self'; "
			. "frame-ancestors 'self'";
	}

	private static function report_url(): string {
		return rest_url( self::REST_NS . self::REST_ROUTE );
	}

	/** True only for a normal front-end page render. */
	private static function is_frontend_pageview(): bool {
		if ( is_admin() ) {
			return false;
		}
		if ( function_exists( 'wp_doing_ajax' ) && wp_doing_ajax() ) {
			return false;
		}
		if ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() ) {
			return false;
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return false;
		}
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return false;
		}
		if ( function_exists( 'is_feed' ) && is_feed() ) {
			return false;
		}
		return true;
	}

	/** Emit the CSP header on front-end responses when enabled. Hooks send_headers. */
	public static function maybe_send_header(): void {
		$s = self::settings();
		if ( $s['mode'] === 'off' || headers_sent() || ! self::is_frontend_pageview() ) {
			return;
		}
		$policy = trim( $s['policy'] );
		if ( $policy === '' ) {
			return;
		}
		// Append our report endpoint (report-uri has the broadest browser support).
		$policy .= '; report-uri ' . esc_url_raw( self::report_url() );

		$header = ( $s['mode'] === 'enforce' )
			? 'Content-Security-Policy'
			: 'Content-Security-Policy-Report-Only';
		header( $header . ': ' . $policy );
	}

	/** Register the public report-collection endpoint. Hooks rest_api_init. */
	public static function register_rest(): void {
		register_rest_route(
			self::REST_NS,
			self::REST_ROUTE,
			[
				'methods'             => 'POST',
				'permission_callback' => '__return_true', // browsers post reports unauthenticated
				'callback'            => [ __CLASS__, 'receive_report' ],
			]
		);
	}

	/**
	 * Receive a CSP violation report. Hardened: stores nothing when CSP is off,
	 * ignores oversized bodies, throttles writes, truncates fields, ring-buffers.
	 *
	 * @param WP_REST_Request $request
	 * @return WP_REST_Response
	 */
	public static function receive_report( $request ) {
		$noop = new WP_REST_Response( null, 204 );

		if ( self::get_mode() === 'off' ) {
			return $noop; // not collecting
		}
		if ( get_transient( self::THROTTLE_TRANS ) ) {
			return $noop; // bound write frequency under flood
		}

		$body = (string) $request->get_body();
		if ( $body === '' || strlen( $body ) > self::MAX_BODY_BYTES ) {
			return $noop;
		}
		$data = json_decode( $body, true );
		if ( ! is_array( $data ) || ! isset( $data['csp-report'] ) || ! is_array( $data['csp-report'] ) ) {
			return $noop; // not a CSP report payload
		}
		$r = $data['csp-report'];

		$clip = static function ( $v ): string {
			$v = is_scalar( $v ) ? (string) $v : '';
			$v = sanitize_text_field( $v );
			return substr( $v, 0, self::MAX_FIELD_LEN );
		};

		$entry = [
			'time'      => gmdate( 'Y-m-d H:i:s' ),
			'directive' => $clip( $r['effective-directive'] ?? ( $r['violated-directive'] ?? '' ) ),
			'blocked'   => $clip( $r['blocked-uri'] ?? '' ),
			'document'  => $clip( $r['document-uri'] ?? '' ),
			'source'    => $clip( $r['source-file'] ?? '' ),
			'line'      => (int) ( $r['line-number'] ?? 0 ),
		];

		$reports = get_option( self::REPORTS_OPTION, [] );
		$reports = is_array( $reports ) ? $reports : [];
		$reports[] = $entry;
		if ( count( $reports ) > self::MAX_REPORTS ) {
			$reports = array_slice( $reports, -self::MAX_REPORTS );
		}
		update_option( self::REPORTS_OPTION, $reports, false );
		set_transient( self::THROTTLE_TRANS, 1, 2 );

		return $noop;
	}

	/** @return array<int, array<string, mixed>> Most-recent-first. */
	public static function get_reports(): array {
		$r = get_option( self::REPORTS_OPTION, [] );
		$r = is_array( $r ) ? $r : [];
		return array_reverse( $r );
	}

	public static function clear_reports(): void {
		delete_option( self::REPORTS_OPTION );
	}

	/**
	 * Persist mode + policy. Returns the normalised values actually stored.
	 *
	 * @return array{mode:string, policy:string}
	 */
	public static function save( string $mode, string $policy ): array {
		$mode = in_array( $mode, [ 'off', 'report', 'enforce' ], true ) ? $mode : 'off';
		// Keep the policy to a single header line; strip CR/LF and cap length.
		$policy = trim( preg_replace( '/[\r\n]+/', ' ', $policy ) );
		if ( strlen( $policy ) > 2000 ) {
			$policy = substr( $policy, 0, 2000 );
		}
		if ( $policy === '' ) {
			$policy = self::default_policy();
		}

		$o = get_option( WPS_OPTION, [] );
		$o = is_array( $o ) ? $o : [];
		$o['csp_mode']   = $mode;
		$o['csp_policy'] = $policy;
		update_option( WPS_OPTION, $o );

		WPS_Logger::log_event( 'csp_settings_saved', 'mode=' . $mode );
		return [ 'mode' => $mode, 'policy' => $policy ];
	}
}
