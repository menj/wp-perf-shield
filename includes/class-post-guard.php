<?php
/**
 * Post guard (1.4.70).
 *
 * Merged from the standalone Block External Posting plugin. Blocks external
 * creation, modification and deletion of posts through the REST API and
 * XML-RPC, while leaving genuine dashboard publishing (Gutenberg, Classic
 * Editor) and internally scheduled posts alone. This is the injection vector
 * behind auto-blogging and doorway/SEO-spam posts: an attacker with an
 * Application Password, Basic Auth, JWT, OAuth, a Zapier-style integration, or
 * no auth at all writes posts straight through /wp/v2/posts or the
 * post-writing XML-RPC methods, never touching wp-login.php.
 *
 * What the standalone did silently, this does visibly: a blocked write is
 * recorded as a security event (throttled per address so a hammering bot
 * cannot bury the log), so the operator sees the attempt instead of only its
 * absence.
 *
 * Off by default. Unlike the login-guard hardening, this one CAN break a
 * legitimate setup - headless WordPress, mobile-app posting, Zapier/IFTTT,
 * anything that publishes through an Application Password - so it is opt-in,
 * the same reasoning that keeps "disable XML-RPC sign-in" off by default.
 */

defined( 'ABSPATH' ) || exit;

final class WPS_Post_Guard {

	/** Seconds between logged blocks from one address, so a flood is one line, not thousands. */
	private const LOG_THROTTLE = 600;

	/**
	 * A sustained injection campaign - this many blocked writes from one address
	 * within the window - earns a persistent hostile-IP block, not just a
	 * per-request refusal (1.4.72). Set high on purpose: a stray or misconfigured
	 * request must never trip a full-request block, only a clear campaign does.
	 */
	private const ESCALATE_THRESHOLD = 10;
	private const ESCALATE_WINDOW    = 3600;

	public static function register_hooks(): void {
		if ( ! self::enabled() ) {
			return;
		}
		add_filter( 'rest_pre_dispatch', [ __CLASS__, 'block_external_rest_post_writes' ], 20, 3 );
		add_filter( 'xmlrpc_methods', [ __CLASS__, 'remove_xmlrpc_post_writing_methods' ], PHP_INT_MAX );
	}

	/** Opt-in: it can break legitimate external publishing, so it stays off until the operator turns it on. */
	public static function enabled(): bool {
		$s = get_option( WPS_OPTION, [] );
		return is_array( $s ) && ( $s['post_guard_enabled'] ?? '0' ) === '1';
	}

	/**
	 * Block write requests to the standard posts REST routes unless they come
	 * from an administrator's authenticated dashboard session. Gutenberg uses
	 * the REST API, so it is permitted only when the request carries a valid
	 * logged-in cookie, a valid wp_rest nonce, and an administrator who can
	 * publish - a test Application Passwords, Basic Auth, JWT and OAuth cannot
	 * pass.
	 *
	 * @param mixed $result Response from an earlier filter, preserved if set.
	 * @return mixed|WP_Error
	 */
	public static function block_external_rest_post_writes( $result, $server, $request ) {
		unset( $server );

		// Preserve a response or error an earlier filter already produced.
		if ( null !== $result ) {
			return $result;
		}
		if ( ! is_object( $request ) || ! method_exists( $request, 'get_route' ) ) {
			return $result;
		}

		$route = (string) $request->get_route();

		// /wp/v2/posts, /wp/v2/posts/{id}, and child routes beneath it.
		if ( ! preg_match( '#^/wp/v2/posts(?:/|$)#', $route ) ) {
			return $result;
		}

		$method = strtoupper( (string) $request->get_method() );
		if ( ! in_array( $method, [ 'POST', 'PUT', 'PATCH', 'DELETE' ], true ) ) {
			return $result;
		}

		// Genuine administrator dashboard session (Gutenberg) is allowed through.
		if ( self::is_manual_dashboard_rest_request( $request ) ) {
			return $result;
		}

		$ip = class_exists( 'WPS_Blocker' ) ? WPS_Blocker::client_ip() : (string) ( $_SERVER['REMOTE_ADDR'] ?? '' );
		self::on_block( $ip, 'rest', $method . ' ' . $route );

		return new WP_Error(
			'external_posting_blocked',
			__( 'External post creation and modification are disabled on this site.', 'wp-perf-shield' ),
			[ 'status' => 403 ]
		);
	}

	/**
	 * True only for a real administrator dashboard session: logged in, can
	 * manage options and publish posts, carrying a valid logged-in browser
	 * cookie and a valid wp_rest nonce.
	 */
	private static function is_manual_dashboard_rest_request( $request ): bool {
		if (
			! is_user_logged_in()
			|| ! current_user_can( 'manage_options' )
			|| ! current_user_can( 'publish_posts' )
		) {
			return false;
		}
		if ( ! self::has_valid_logged_in_cookie() ) {
			return false;
		}

		$nonce = $request->get_header( 'X-WP-Nonce' );
		if ( empty( $nonce ) ) {
			$nonce = $request->get_param( '_wpnonce' );
		}
		if ( ! is_string( $nonce ) || '' === $nonce ) {
			return false;
		}
		return (bool) wp_verify_nonce( $nonce, 'wp_rest' );
	}

	/** Validate the actual logged-in browser cookie and confirm it belongs to the current user. */
	private static function has_valid_logged_in_cookie(): bool {
		if ( ! defined( 'LOGGED_IN_COOKIE' ) || empty( $_COOKIE[ LOGGED_IN_COOKIE ] ) ) {
			return false;
		}
		$cookie         = wp_unslash( $_COOKIE[ LOGGED_IN_COOKIE ] );
		$cookie_user_id = wp_validate_auth_cookie( $cookie, 'logged_in' );
		if ( ! $cookie_user_id ) {
			return false;
		}
		return (int) $cookie_user_id === get_current_user_id();
	}

	/**
	 * Unregister the XML-RPC methods that create, edit, publish or delete
	 * posts. Read-only methods and pingbacks are left intact.
	 *
	 * @param mixed $methods Registered XML-RPC methods.
	 * @return mixed
	 */
	public static function remove_xmlrpc_post_writing_methods( $methods ) {
		if ( ! is_array( $methods ) ) {
			return $methods;
		}
		foreach (
			[
				'wp.newPost',
				'wp.editPost',
				'wp.deletePost',
				'blogger.newPost',
				'blogger.editPost',
				'blogger.deletePost',
				'metaWeblog.newPost',
				'metaWeblog.editPost',
				'metaWeblog.deletePost',
				'mt.publishPost',
			] as $method
		) {
			unset( $methods[ $method ] );
		}
		return $methods;
	}

	/**
	 * Handle one blocked external write: record it (throttled) and report the
	 * address to Akismet (once), then count it toward escalation. The block
	 * itself is never throttled - only its logging and reporting.
	 */
	private static function on_block( string $ip, string $vector, string $detail ): void {
		if ( '' === $ip ) {
			$ip = (string) ( $_SERVER['REMOTE_ADDR'] ?? '' );
		}
		$logkey = 'wps_epw_' . md5( $vector . '|' . $ip );
		if ( ! get_transient( $logkey ) ) {
			set_transient( $logkey, 1, self::LOG_THROTTLE );

			if ( class_exists( 'WPS_EDR' ) && method_exists( 'WPS_EDR', 'record' ) ) {
				WPS_EDR::record(
					'external_post_write_blocked',
					[
						'object_type' => 'request',
						'object_name' => $detail,
						'severity'    => 'high',
						'notes'       => 'external ' . $vector . ' post write blocked from ' . ( '' !== $ip ? $ip : 'unknown address' )
							. ' (no administrator dashboard session); further attempts from this address within '
							. (int) ( self::LOG_THROTTLE / 60 ) . ' minutes are not logged separately',
					]
				);
			}
			// Conclusive abuse: contribute the address to Akismet (safeguarded,
			// once per address).
			if ( '' !== $ip && class_exists( 'WPS_Login_Guard' ) && method_exists( 'WPS_Login_Guard', 'report_attacker_ip' ) ) {
				WPS_Login_Guard::report_attacker_ip( $ip, 'external post-write injection (' . $vector . ')' );
			}
		}

		self::maybe_escalate( $ip );
	}

	/**
	 * A sustained injection campaign from one address escalates from a
	 * per-request refusal to a persistent hostile-IP block, its length weighted
	 * by Akismet reputation. Counting is unthrottled (unlike logging) so the
	 * threshold reflects real volume. Shared-infrastructure addresses are never
	 * escalated - a full-request block on a CDN edge would take out real
	 * visitors - and the whole path is gated by the hostile-IP auto-block master
	 * switch inside record_ip_block().
	 */
	private static function maybe_escalate( string $ip ): void {
		if ( '' === $ip || ! class_exists( 'WPS_Blocker' ) || ! method_exists( 'WPS_Blocker', 'record_ip_block' ) ) {
			return;
		}
		if ( class_exists( 'WPS_Login_Guard' ) && method_exists( 'WPS_Login_Guard', 'ip_looks_like_infrastructure' )
			&& WPS_Login_Guard::ip_looks_like_infrastructure( $ip ) ) {
			return;
		}

		$ckey  = 'wps_epwc_' . md5( $ip );
		$count = (int) get_transient( $ckey ) + 1;
		set_transient( $ckey, $count, self::ESCALATE_WINDOW );
		if ( $count < self::ESCALATE_THRESHOLD ) {
			return;
		}

		$days = 1;
		if ( class_exists( 'WPS_Login_Guard' ) && method_exists( 'WPS_Login_Guard', 'akismet_reputation' )
			&& 'spam' === WPS_Login_Guard::akismet_reputation( $ip, 'wps-post-injection' ) ) {
			$days = 7;
		}

		$seconds = defined( 'DAY_IN_SECONDS' ) ? $days * DAY_IN_SECONDS : $days * 86400;
		WPS_Blocker::record_ip_block(
			$ip,
			'sustained external post-write injection (' . self::ESCALATE_THRESHOLD . '+ attempts in an hour)'
				. ( $days > 1 ? '; known-bad reputation, extended hold' : '' ),
			$seconds,
			[ 'source' => 'post-guard', 'scope' => 'address' ]
		);
		// Re-arm rather than firing on every subsequent request past threshold.
		delete_transient( $ckey );
	}
}
