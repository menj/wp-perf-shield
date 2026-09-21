<?php
/**
 * Account-takeover guard (1.4.100).
 *
 * Built from a confirmed live incident. The credentials for one account were
 * correct - real username, real password, real login through wp-login.php -
 * used from dozens of unrelated IPs worldwide over three weeks to create and
 * trash "link-factory-verification" test posts, overwrite an existing
 * high-traffic page with injected content, and probe for a persistent PHP
 * backdoor (a plugin folder and an uploads-directory file both named
 * "easypost", both refused by hosting/this plugin's existing defences). Every
 * request in that incident carried a completely genuine logged-in cookie and
 * a freshly-fetched REST nonce, because the login itself was genuine.
 *
 * That is precisely what WPS_Post_Guard's dashboard-session test cannot
 * catch: it exists to tell a real administrator apart from an Application
 * Password, Basic Auth, JWT or OAuth client, not to tell a real administrator
 * apart from someone who is, at this moment, holding their real password.
 * Stopping the second kind needs a different signal entirely: not "is this
 * request authenticated", but "does this authenticated session behave like
 * the account's owner". Two behavioural tells came directly out of the
 * incident:
 *
 *   1. A post or page write arriving within seconds of that user's login,
 *      from an IP/browser combination never associated with that account
 *      before. A human does not fetch the login form, submit credentials,
 *      and publish through the block editor in under five seconds - the
 *      recovered sessions did it in one to four. This is the same
 *      "how, not just whether" reasoning WPS_Post_Guard already uses for
 *      Application Passwords, extended to sessions that pass the cookie
 *      test because the cookie is real.
 *
 *   2. A hit on authorize-application.php carrying a success_url on a
 *      DIFFERENT host, with no referer. That page exists so a real
 *      third-party integration can request an Application Password; a
 *      legitimate visit arrives because the person clicked a button inside
 *      that integration, which shows up as a referer from the integration's
 *      own domain. The recovered sessions hit it directly, scripted, one
 *      step after a scripted login, requesting a credential mailed back to
 *      an attacker-controlled domain (in the recovered sample, disguised as
 *      "SEO Super Tool"). No legitimate flow produces that shape.
 *
 * Both are opt-in-by-default ON, unlike WPS_Post_Guard, because unlike
 * blocking ALL external posting, neither of these can fire on an ordinary
 * publishing workflow: nothing legitimate both logs a user in seconds ago
 * from a new device AND immediately writes content, and nothing legitimate
 * hits authorize-application.php cold with an off-site callback and no
 * referer. A false positive here would mean an administrator's own first
 * login from a new computer happening to publish within the window - see
 * KNOWN_DEVICE_WINDOW and the new-device check below for how that is kept
 * rare rather than impossible.
 */

defined( 'ABSPATH' ) || exit;

final class WPS_Account_Guard {

	/** How long after login a write still counts as "rapid" (seconds). */
	private const RAPID_WINDOW = 90;

	/** How long a device (IP+UA pair) is remembered as "known" for a user. */
	private const DEVICE_MEMORY_DAYS = 90;

	/** Cap on remembered devices per user, oldest evicted first. */
	private const MAX_DEVICES_PER_USER = 20;

	public static function register_hooks(): void {
		if ( self::enabled() ) {
			add_action( 'wp_login', [ __CLASS__, 'record_login' ], 10, 2 );
			add_action( 'rest_insert_post', [ __CLASS__, 'check_rest_write' ], 10, 3 );
			add_action( 'rest_insert_page', [ __CLASS__, 'check_rest_write' ], 10, 3 );
			// xmlrpc.php can publish too (wp.newPost etc.) when WPS_Post_Guard's
			// XML-RPC method removal is off; catch that route as well rather
			// than assuming REST is the only door.
			add_action( 'xmlrpc_call', [ __CLASS__, 'check_xmlrpc_write' ] );
		}
		if ( self::app_password_guard_enabled() ) {
			add_action( 'admin_init', [ __CLASS__, 'guard_authorize_application' ], 1 );
		}
	}

	public static function enabled(): bool {
		$s = get_option( WPS_OPTION, [] );
		return ! is_array( $s ) || ( $s['account_guard_enabled'] ?? '1' ) !== '0';
	}

	public static function app_password_guard_enabled(): bool {
		$s = get_option( WPS_OPTION, [] );
		return ! is_array( $s ) || ( $s['account_guard_app_password_enabled'] ?? '1' ) !== '0';
	}

	/**
	 * Record this login as the user's current fingerprint, and - only if the
	 * device is already known for this user - refresh it in the known-device
	 * list. A first-ever login from a new device is deliberately NOT added
	 * here: it is added only after a write from it passes review (see
	 * remember_device()), so that the very login an attacker is riding on
	 * cannot whitelist itself.
	 */
	public static function record_login( string $user_login, $user ): void {
		unset( $user_login );
		if ( ! is_object( $user ) || empty( $user->ID ) ) {
			return;
		}
		update_user_meta( (int) $user->ID, '_wps_login_fingerprint', [
			'time' => time(),
			'ip'   => self::client_ip(),
			'ua'   => substr( (string) ( $_SERVER['HTTP_USER_AGENT'] ?? '' ), 0, 200 ),
		] );
	}

	/**
	 * After a post or page is created/updated via the REST API, decide
	 * whether the write looks like it came from the account's owner or from
	 * someone who currently holds their credentials.
	 *
	 * @param \WP_Post          $post    The inserted/updated post.
	 * @param \WP_REST_Request  $request The request.
	 * @param bool              $creating True on create, false on update.
	 */
	public static function check_rest_write( $post, $request, $creating ): void {
		unset( $request );
		if ( ! is_object( $post ) || empty( $post->ID ) || empty( $post->post_author ) ) {
			return;
		}
		self::evaluate( (int) $post->post_author, (int) $post->ID, 'rest', (bool) $creating );
	}

	/** Same evaluation for the XML-RPC post-writing methods, if they are not already unregistered by WPS_Post_Guard. */
	public static function check_xmlrpc_write( string $method ): void {
		$post_methods = [
			'wp.newPost', 'wp.editPost',
			'blogger.newPost', 'blogger.editPost',
			'metaWeblog.newPost', 'metaWeblog.editPost',
			'mt.publishPost',
		];
		if ( ! in_array( $method, $post_methods, true ) ) {
			return;
		}
		$user_id = get_current_user_id();
		if ( ! $user_id ) {
			return;
		}
		// No post ID is reliably available from this hook alone; the value
		// still matters for the log and for the lockdown response even
		// without a specific post to trash.
		self::evaluate( $user_id, 0, 'xmlrpc', true );
	}

	/**
	 * The actual rapid-write / new-device test, shared by both entry points.
	 */
	private static function evaluate( int $user_id, int $post_id, string $vector, bool $creating ): void {
		if ( $user_id <= 0 ) {
			return;
		}
		$fp = get_user_meta( $user_id, '_wps_login_fingerprint', true );
		if ( ! is_array( $fp ) || empty( $fp['time'] ) ) {
			return; // no recorded login for this session; nothing to compare against
		}

		$elapsed = time() - (int) $fp['time'];
		$ip      = self::client_ip();
		$ua      = substr( (string) ( $_SERVER['HTTP_USER_AGENT'] ?? '' ), 0, 200 );
		$device  = self::device_key( $ip, $ua );

		if ( $elapsed < 0 || $elapsed > self::RAPID_WINDOW ) {
			// Not a rapid post-login write - ordinary publishing. A write
			// this session is trusted to make is exactly what should teach
			// the account which devices are normal for it, so remember this
			// one for next time.
			self::remember_device( $user_id, $ip, $ua );
			return;
		}

		if ( self::is_known_device( $user_id, $device ) ) {
			self::remember_device( $user_id, $ip, $ua ); // refresh last-seen
			return; // this device has published for this account before; not new
		}

		// Rapid AND unrecognised device: this is the shape recovered from
		// the incident. Act on it.
		self::flag( $user_id, $post_id, $vector, $creating, $ip, $ua, $elapsed );
	}

	private static function flag( int $user_id, int $post_id, string $vector, bool $creating, string $ip, string $ua, int $elapsed ): void {
		$user = get_userdata( $user_id );
		$who  = $user ? $user->user_login : ( 'user #' . $user_id );

		if ( class_exists( 'WPS_EDR' ) && method_exists( 'WPS_EDR', 'record' ) ) {
			WPS_EDR::record(
				'account_takeover_write_blocked',
				[
					'object_type' => 'post',
					'object_name' => $post_id > 0 ? ( 'post #' . $post_id ) : ( $vector . ' write' ),
					'severity'    => 'critical',
					'notes'       => ( $creating ? 'New' : 'Modified' ) . ' content via ' . $vector . ' as ' . $who
						. ' only ' . $elapsed . 's after that account logged in, from ' . ( '' !== $ip ? $ip : 'an unknown address' )
						. ' - a device never associated with this account before. Genuine dashboard publishing does not '
						. 'happen this fast after a fresh login from a new browser/IP; this is the same shape recorded in a '
						. 'confirmed account-takeover incident (credentials correct, session genuine, spam and link-injection '
						. 'written straight through the REST API). Auto-remediated below.',
				]
			);
		}

		if ( $post_id > 0 && self::auto_trash_enabled() ) {
			// Trash, never force-delete: reversible, and content review still
			// needs to happen (was this the ONLY thing this session touched?).
			wp_trash_post( $post_id );
		}

		if ( self::lockdown_enabled() ) {
			self::destroy_other_sessions( $user_id );
			self::block_ip( $ip, 'account-takeover pattern: rapid post-login write from a new device (user: ' . $who . ')' );
		}
	}

	/** Log every other active session out, leaving only the one making this request (if any) - in practice, kills all of them, since this fires from an anonymous API context with no session of its own to preserve. */
	private static function destroy_other_sessions( int $user_id ): void {
		if ( ! class_exists( 'WP_Session_Tokens' ) ) {
			return;
		}
		WP_Session_Tokens::get_instance( $user_id )->destroy_all();
	}

	private static function block_ip( string $ip, string $reason ): void {
		if ( '' === $ip || ! class_exists( 'WPS_Blocker' ) || ! method_exists( 'WPS_Blocker', 'record_ip_block' ) ) {
			return;
		}
		// Shared-infrastructure addresses are never full-blocked, same rule
		// WPS_Post_Guard already applies - a stolen-credential hit riding
		// through a corporate NAT or CDN edge must not take out real users.
		if ( class_exists( 'WPS_Login_Guard' ) && method_exists( 'WPS_Login_Guard', 'ip_looks_like_infrastructure' )
			&& WPS_Login_Guard::ip_looks_like_infrastructure( $ip ) ) {
			return;
		}
		// No repeat-offence counting here, unlike WPS_Post_Guard's escalation:
		// the rapid+new-device combination is already strong enough evidence
		// on its own, and the account is actively being used against its
		// owner right now - waiting for a tenth hit is waiting too long.
		WPS_Blocker::record_ip_block( $ip, $reason, 7 * DAY_IN_SECONDS, [ 'source' => 'account-guard', 'scope' => 'address' ] );
		if ( class_exists( 'WPS_Login_Guard' ) && method_exists( 'WPS_Login_Guard', 'report_attacker_ip' ) ) {
			WPS_Login_Guard::report_attacker_ip( $ip, 'account-takeover post-write pattern' );
		}
	}

	/**
	 * Block direct, scripted hits on authorize-application.php that request
	 * an off-site callback - the Application Password self-authorization
	 * phishing step recovered from the incident (disguised as an app named
	 * "SEO Super Tool"). A legitimate request arrives with a referer from the
	 * requesting integration's own domain, because the person clicked a
	 * button there; this checks for exactly that being absent.
	 */
	public static function guard_authorize_application(): void {
		global $pagenow;
		if ( 'authorize-application.php' !== ( $pagenow ?? '' ) ) {
			return;
		}
		$success_url = isset( $_GET['success_url'] ) ? esc_url_raw( wp_unslash( $_GET['success_url'] ) ) : '';
		if ( '' === $success_url ) {
			return; // nothing to redirect to off-site; not the phishing shape
		}
		$target_host = wp_parse_url( $success_url, PHP_URL_HOST );
		$site_host   = wp_parse_url( home_url(), PHP_URL_HOST );
		if ( ! $target_host || ! $site_host || strtolower( $target_host ) === strtolower( $site_host ) ) {
			return; // same-site or unparseable; not what this guards against
		}

		$referer      = (string) ( $_SERVER['HTTP_REFERER'] ?? '' );
		$referer_host = $referer !== '' ? wp_parse_url( $referer, PHP_URL_HOST ) : '';
		if ( $referer_host && strtolower( (string) $referer_host ) === strtolower( $target_host ) ) {
			return; // arrived via a referer from the requesting app's own domain: legitimate
		}

		$ip = self::client_ip();
		if ( class_exists( 'WPS_EDR' ) && method_exists( 'WPS_EDR', 'record' ) ) {
			WPS_EDR::record(
				'account_takeover_app_password_blocked',
				[
					'object_type' => 'request',
					'object_name' => 'authorize-application.php',
					'severity'    => 'critical',
					'notes'       => 'Blocked a direct hit on the Application Password authorization page requesting a callback to '
						. $target_host . ' with no referer from that domain, from ' . ( '' !== $ip ? $ip : 'an unknown address' )
						. ' - the self-authorization step of a confirmed account-takeover pattern (an app calling itself '
						. '"SEO Super Tool" in the recovered incident). A real third-party integration arrives here because the '
						. 'user clicked something inside it, which carries a referer from its own domain.',
				]
			);
		}
		self::block_ip( $ip, 'scripted Application Password self-authorization request (callback to ' . $target_host . ')' );

		wp_die(
			esc_html__( 'This request was blocked by WP Perf Shield.', 'wp-perf-shield' ),
			esc_html__( 'Request blocked', 'wp-perf-shield' ),
			[ 'response' => 403 ]
		);
	}

	//  Known-device bookkeeping 

	private static function device_key( string $ip, string $ua ): string {
		return md5( $ip . '|' . $ua );
	}

	private static function is_known_device( int $user_id, string $device ): bool {
		$devices = get_user_meta( $user_id, '_wps_known_devices', true );
		if ( ! is_array( $devices ) ) {
			return false;
		}
		return isset( $devices[ $device ] );
	}

	/**
	 * A device earns trust the same way a person does: by publishing
	 * normally, more than RAPID_WINDOW seconds after logging in, without
	 * being flagged. Never called from the flagged path itself, so an
	 * attacker's own rapid, suspicious write can never whitelist their
	 * device - only an unremarkable one does that.
	 */
	public static function remember_device( int $user_id, string $ip, string $ua ): void {
		$devices = get_user_meta( $user_id, '_wps_known_devices', true );
		if ( ! is_array( $devices ) ) {
			$devices = [];
		}
		$devices[ self::device_key( $ip, $ua ) ] = time();
		if ( count( $devices ) > self::MAX_DEVICES_PER_USER ) {
			asort( $devices );
			$devices = array_slice( $devices, -self::MAX_DEVICES_PER_USER, null, true );
		}
		$cutoff = time() - self::DEVICE_MEMORY_DAYS * DAY_IN_SECONDS;
		foreach ( $devices as $key => $seen ) {
			if ( (int) $seen < $cutoff ) {
				unset( $devices[ $key ] );
			}
		}
		update_user_meta( $user_id, '_wps_known_devices', $devices );
	}

	private static function auto_trash_enabled(): bool {
		$s = get_option( WPS_OPTION, [] );
		return ! is_array( $s ) || ( $s['account_guard_auto_trash'] ?? '1' ) !== '0';
	}

	private static function lockdown_enabled(): bool {
		$s = get_option( WPS_OPTION, [] );
		return ! is_array( $s ) || ( $s['account_guard_lockdown'] ?? '1' ) !== '0';
	}

	private static function client_ip(): string {
		if ( class_exists( 'WPS_Blocker' ) && method_exists( 'WPS_Blocker', 'client_ip' ) ) {
			return WPS_Blocker::client_ip();
		}
		return (string) ( $_SERVER['REMOTE_ADDR'] ?? '' );
	}
}
