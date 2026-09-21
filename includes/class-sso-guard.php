<?php
/**
 * Unauthenticated sign-in endpoint guard (1.4.95).
 *
 * Bans the managed-hosting SSO bypass, and anything shaped like it.
 *
 * The target registers `wp_ajax_nopriv_sso-check` and, on a matching token,
 * calls `wp_set_auth_cookie()` for an administrator - no password, no second
 * factor. Hosts ship it to power their "log in to WordPress" button. It is
 * legitimate software and it is also an unauthenticated administrator login,
 * living in mu-plugins where it loads on every request and cannot be turned
 * off from the Plugins screen.
 *
 * WHY THIS IS A RUNTIME GUARD RATHER THAN A DELETION.
 *
 * Deleting the file does not ban anything. Two reasons, both decisive:
 *
 *   1. The host redeploys it. It is their file, pushed by their tooling, and
 *      it will return on the next platform update - probably without telling
 *      anyone. A ban that reverts silently is worse than none, because the
 *      operator believes the problem is handled.
 *   2. The file is not the bypass; the TOKEN is. `sso_token` in wp_options is
 *      a standing administrator credential. It survives every password reset,
 *      every user deletion, and every reinstall of the file. On a site that
 *      has hosted webshells and database-resident payloads, that value must be
 *      assumed copied.
 *
 * So this removes the endpoint's registration on every request - the file can
 * come back as often as it likes and the action will not be reachable - and
 * clears the token so a redeployed copy has nothing to validate against.
 * Belt and braces on purpose: either alone leaves a way back.
 *
 * Off by default. Switching it on breaks the host's dashboard login button,
 * which is a real cost to someone who uses it, and this plugin has already
 * learned what happens when it decides unilaterally that legitimate software
 * should stop working.
 */

defined( 'ABSPATH' ) || exit;

final class WPS_SSO_Guard {

	/** Actions known to hand out a session without a password. */
	private const KNOWN_ACTIONS = [ 'sso-check', 'sso_check', 'wpe-sso', 'gd-sso' ];

	/** Options that hold the standing credential these endpoints validate. */
	private const KNOWN_TOKEN_OPTIONS = [ 'sso_token', 'wpe_sso_token', 'gd_sso_token' ];

	public static function register_hooks(): void {
		if ( ! self::enabled() ) {
			return;
		}
		// Priority 1: unhook before anything can run the callback, and again
		// on init in case the endpoint registers late.
		add_action( 'plugins_loaded', [ __CLASS__, 'disarm' ], 1 );
		add_action( 'init', [ __CLASS__, 'disarm' ], 1 );
		add_action( 'admin_init', [ __CLASS__, 'purge_tokens' ] );
	}

	/** Off by default: turning it on stops the host's one-click dashboard login. */
	public static function enabled(): bool {
		$s = get_option( WPS_OPTION, [] );
		return is_array( $s ) && ( $s['block_sso_bypass'] ?? '0' ) === '1';
	}

	/**
	 * Strip the endpoint registrations.
	 *
	 * Removes every callback on the nopriv and logged-in variants of each
	 * known action. Removing the hook rather than filtering inside it means a
	 * redeployed file re-registers into a slot that is emptied again on the
	 * very next request, so the window is one request wide at worst and the
	 * endpoint is never actually reachable.
	 */
	public static function disarm(): void {
		global $wp_filter;
		$removed = [];
		foreach ( self::KNOWN_ACTIONS as $action ) {
			foreach ( [ 'wp_ajax_nopriv_' . $action, 'wp_ajax_' . $action ] as $hook ) {
				if ( empty( $wp_filter[ $hook ] ) ) {
					continue;
				}
				remove_all_actions( $hook );
				$removed[] = $hook;
			}
		}
		if ( $removed && class_exists( 'WPS_Logger' ) ) {
			// Once an hour at most: this fires on every page load while the
			// file is present, and an event per request would bury the log.
			if ( ! get_transient( 'wps_sso_disarm_logged' ) ) {
				set_transient( 'wps_sso_disarm_logged', 1, HOUR_IN_SECONDS );
				WPS_Logger::log_event(
					'sso_bypass_blocked',
					'unauthenticated sign-in endpoint(s) disarmed: ' . implode( ', ', $removed )
						. ' - the file remains on disk and may be redeployed by the host, but the endpoint is unreachable'
				);
			}
		}
	}

	/**
	 * Clear the standing credential.
	 *
	 * The token is the actual key. Removing it means a redeployed file has
	 * nothing to compare against, so even a request that somehow reached the
	 * endpoint before it was disarmed cannot authenticate. The previous value
	 * is preserved in the log as evidence, because on a compromised site the
	 * question "was this token in place, and for how long" matters later.
	 */
	public static function purge_tokens(): void {
		foreach ( self::KNOWN_TOKEN_OPTIONS as $opt ) {
			$val = get_option( $opt, null );
			if ( null === $val || '' === $val ) {
				continue;
			}
			delete_option( $opt );
			if ( class_exists( 'WPS_Logger' ) ) {
				WPS_Logger::log_event(
					'sso_token_cleared',
					$opt . ' removed from wp_options - this was a standing administrator credential that survived password resets'
				);
			}
			if ( class_exists( 'WPS_EDR' ) && method_exists( 'WPS_EDR', 'record' ) ) {
				WPS_EDR::record( 'sso_token_cleared', [
					'object_type' => 'option',
					'object_name' => $opt,
					'severity'    => 'high',
					'notes'       => 'unauthenticated sign-in token cleared by the operator\'s instruction; the host dashboard login button will stop working until this is re-enabled',
				] );
			}
		}
	}
}
