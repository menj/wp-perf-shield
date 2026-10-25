<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * EDR Phase 1 - sessions, incidents, risk (1.4.7).
 *
 * Everything before this release answered one question: is this file
 * known-bad? That is scanning, and it only sees what an attacker leaves on
 * disk. This is the first release that answers a different question - what
 * happened here? - by recording behaviour as it occurs and grouping related
 * events into incidents.
 *
 * The distinction matters because the samples analysed over 1.4.1 to 1.4.5
 * kept arriving as finished artefacts. Something put them there, and the
 * sequence that did so - a login from an unfamiliar address, a visit to the
 * plugin installer, an upload, an activation - was invisible, because nothing
 * was watching. A file scan finds the web shell; a timeline shows the account
 * that uploaded it, and everything else that account did afterwards.
 *
 * Three pieces:
 *
 *   SESSIONS. WordPress already issues a session token per login, and the
 *   event schema has carried session_id since 1.3.99. Recording it against
 *   behavioural events turns scattered rows into a per-login narrative.
 *
 *   INCIDENTS. Events sharing an actor - the same user, or the same address -
 *   inside a time window belong to one story. Grouping is deliberately simple
 *   and explainable; a clever correlator that nobody can reason about is worse
 *   than an obvious one, because incident grouping is what an operator reads
 *   when deciding whether they have been breached.
 *
 *   RISK. Each event type carries a weight; an incident's risk is the sum of
 *   its events. One login is unremarkable. A login, then the user editor, then
 *   a new administrator account, inside ten minutes, is not - and the sum says
 *   so without anyone having to write a rule for that specific sequence.
 *
 * Deliberately NOT here, per the roadmap's gating decisions: no GeoIP, so
 * country, city, asn and impossible-travel scoring stay null and dormant
 * (Decision 1); no client-side fingerprinting (Decision 2); no deception
 * (Decision 3). Nothing here makes a third-party network call.
 *
 * Behavioural findings are observations, never grounds for automatic
 * remediation - the standing rule that only content-confirmed malware is
 * auto-removed applies here too. A high-risk incident raises an alarm; it
 * never deletes anything.
 */
class WPS_EDR {

	/** Events sharing an actor within this many seconds join one incident. */
	private const INCIDENT_WINDOW = 1800; // 30 minutes

	/** Repeat visits to the same screen in one session are collapsed. */
	private const SCREEN_THROTTLE = 600; // 10 minutes

	/**
	 * Risk weights, adopted from the roadmap (Decision 5, shipping the
	 * roadmap's values as defaults). Two anchors were fixed by the roadmap -
	 * a successful login is 10, a new administrator account is 120 - and the
	 * rest are placed relative to those and to the audit weights already in
	 * use since 1.4.0, so a single table governs both.
	 *
	 * One source of truth, filterable, exactly as the standing rule requires.
	 * Recalibration after real timeline data exists is expected and is why
	 * this is a filter rather than a hard-coded literal.
	 */
	private const SCORES = [
		// authentication
		'login_success'          => 10,
		'login_failed'           => 5,
		'logout'                 => 0,
		// accounts - the sharp end
		'user_registered'        => 40,
		'admin_account_created'  => 120,
		'user_role_elevated'     => 90,
		'password_changed'       => 30,
		'email_changed'          => 35,
		// code execution surfaces
		'plugin_activated'       => 30,
		'plugin_deactivated'     => 25,
		'plugin_installed'       => 45,
		'theme_switched'         => 35,
		'file_editor_opened'     => 60,
		'file_uploaded'          => 15,
		// 1.4.148: an application password is a second way in that survives a password change.
		'application_password_created' => 60,
		'password_reset_requested'     => 30,
		// reconnaissance - individually trivial, meaningful in aggregate
		'admin_screen_visited'   => 8,
		'settings_changed'       => 20,
		// 1.4.10: option changes that turn the site into an account factory.
		// Scored at the admin-account level because that is the outcome.
		'registration_opened'    => 70,
		'default_role_escalated' => 120,
	];

	/** Severity bands over cumulative incident risk (roadmap values). */
	private const BANDS = [
		'low'      => 0,
		'medium'   => 51,
		'high'     => 121,
		'critical' => 221,
	];

	/**
	 * Admin screens worth recording. Every admin page view would drown the
	 * store - the event table caps at 10,000 rows - and most of them tell you
	 * nothing. These are the screens an attacker actually needs.
	 */
	private const WATCHED_SCREENS = [
		'users'        => 'User list',
		'user-edit'    => 'Editing a user',
		'user'         => 'Adding a user',
		'plugin-editor'=> 'Plugin file editor',
		'theme-editor' => 'Theme file editor',
		'plugin-install'=> 'Plugin installer',
		'plugins'      => 'Plugin list',
		'options-general' => 'General settings',
		'tools_page_export' => 'Export tool',
	];

	//  Score access 

	/** @return array<string, int> */
	public static function scores(): array {
		$scores = self::SCORES;
		if ( function_exists( 'apply_filters' ) ) {
			$filtered = apply_filters( 'wps_edr_risk_scores', $scores );
			if ( is_array( $filtered ) && $filtered ) {
				$scores = array_map( 'intval', $filtered );
			}
		}
		return $scores;
	}

	public static function score_for( string $event_type ): int {
		$scores = self::scores();
		return isset( $scores[ $event_type ] ) ? (int) $scores[ $event_type ] : 0;
	}

	/** @return array<string, int> */
	public static function bands(): array {
		$bands = self::BANDS;
		if ( function_exists( 'apply_filters' ) ) {
			$filtered = apply_filters( 'wps_edr_risk_bands', $bands );
			if ( is_array( $filtered ) && $filtered ) {
				$bands = array_map( 'intval', $filtered );
			}
		}
		return $bands;
	}

	public static function band_for( int $risk ): string {
		$bands = self::bands();
		arsort( $bands );
		foreach ( $bands as $name => $floor ) {
			if ( $risk >= (int) $floor ) {
				return (string) $name;
			}
		}
		return 'low';
	}

	//  Recording 

	/** Current WordPress session token, when there is one. */
	public static function session_id(): ?string {
		if ( function_exists( 'wp_get_session_token' ) ) {
			$t = (string) wp_get_session_token();
			if ( $t !== '' ) {
				return substr( $t, 0, 64 );
			}
		}
		return null;
	}

	private static function client_ip(): ?string {
		if ( ! isset( $_SERVER['REMOTE_ADDR'] ) ) {
			return null;
		}
		$ip = filter_var( (string) $_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP );
		return $ip ?: null;
	}

	/**
	 * Find the incident this event belongs to, or mint a new one.
	 *
	 * An event joins the most recent open incident that shares its actor -
	 * the same user id, or failing that the same address - within the window.
	 * Matching on address as well as user matters: a failed-login run has no
	 * user id, and the successful login that follows it belongs to the same
	 * story.
	 */
	public static function incident_for( ?int $user_id, ?string $ip ): string {
		$db = ( isset( $GLOBALS['wpdb'] ) && is_object( $GLOBALS['wpdb'] ) ) ? $GLOBALS['wpdb'] : null;
		if ( $db && class_exists( 'WPS_Event_Log' ) && WPS_Event_Log::available() ) {
			$table  = WPS_Event_Log::table();
			$cutoff = gmdate( 'Y-m-d H:i:s', time() - self::INCIDENT_WINDOW );

			$sql = null;
			if ( $user_id ) {
				$sql = $db->prepare(
					"SELECT incident_id FROM {$table} WHERE incident_id IS NOT NULL AND ts >= %s AND user_id = %d ORDER BY id DESC LIMIT 1",
					$cutoff,
					$user_id
				);
			} elseif ( $ip ) {
				$sql = $db->prepare(
					"SELECT incident_id FROM {$table} WHERE incident_id IS NOT NULL AND ts >= %s AND ip = %s ORDER BY id DESC LIMIT 1",
					$cutoff,
					$ip
				);
			}
			if ( $sql ) {
				$existing = $db->get_var( $sql );
				if ( is_string( $existing ) && $existing !== '' ) {
					return $existing;
				}
			}
		}
		return 'inc-' . gmdate( 'Ymd-His' ) . '-' . substr( md5( (string) $user_id . '|' . (string) $ip . '|' . microtime( true ) ), 0, 8 );
	}

	/**
	 * Record a behavioural event: scored, session-stamped, and attached to an
	 * incident. Thin on purpose - storage, hashing, and user context are all
	 * WPS_Event_Log's job, and this must not duplicate them.
	 */
	public static function record( string $event_type, array $ctx = [] ): bool {
		if ( ! class_exists( 'WPS_Event_Log' ) ) {
			return false;
		}
		$user_id = isset( $ctx['user_id'] ) ? (int) $ctx['user_id'] : null;
		if ( ! $user_id && function_exists( 'get_current_user_id' ) ) {
			$uid     = (int) get_current_user_id();
			$user_id = $uid > 0 ? $uid : null;
		}
		$ip   = self::client_ip();
		$risk = isset( $ctx['risk'] ) ? (int) $ctx['risk'] : self::score_for( $event_type );

		// 1.4.148: say how the actor authenticated. On a compromised site the log showed uploads and
		// posts from the admin account and no way to tell a dashboard session from XML-RPC, an
		// application password or a stolen cookie.
		$via = self::auth_method();
		if ( '' !== $via && $user_id ) {
			$ctx['notes'] = trim( (string) ( $ctx['notes'] ?? '' ) . ' [via ' . $via . ']' );
		}
		$fields = [
			'event_type'  => $event_type,
			'action'      => $event_type,
			'session_id'  => $ctx['session_id'] ?? self::session_id(),
			'incident_id' => self::incident_for( $user_id, $ip ),
			'object_type' => $ctx['object_type'] ?? null,
			'object_name' => $ctx['object_name'] ?? null,
			'severity'    => $ctx['severity'] ?? ( $risk >= 90 ? 'warning' : 'info' ),
			'risk_score'  => $risk,
			'notes'       => $ctx['notes'] ?? null,
		];
		if ( $user_id ) {
			$fields['user_id'] = $user_id;
		}
		if ( isset( $ctx['username'] ) ) {
			$fields['username'] = $ctx['username'];
		}
		if ( isset( $ctx['user_role'] ) ) {
			$fields['user_role'] = $ctx['user_role'];
		}
		return null !== WPS_Event_Log::record( $fields );
	}

	/** The application password that authenticated this request, when one did. */
	private static $app_password = '';

	/**
	 * How the current request authenticated: cli, xmlrpc, application password, rest api, cookie
	 * session, wp-cron, or '' when unknown.
	 */
	public static function auth_method(): string {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return 'wp-cli';
		}
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return 'xmlrpc';
		}
		if ( '' !== self::$app_password ) {
			return 'application password "' . self::$app_password . '"';
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return 'rest api';
		}
		if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
			return 'wp-cron';
		}
		return function_exists( 'is_user_logged_in' ) && is_user_logged_in() ? 'cookie session' : '';
	}

	/** @param mixed $user @param mixed $item */
	public static function on_app_password_auth( $user = null, $item = null ): void {
		self::$app_password = is_array( $item ) ? substr( preg_replace( '/[^\P{C}]+/u', '', (string) ( $item['name'] ?? '' ) ) ?? '', 0, 60 ) : 'unnamed';
		if ( '' === self::$app_password ) {
			self::$app_password = 'unnamed';
		}
	}

	/**
	 * A new application password. Alerts when it was made from an address no administrator has
	 * signed in from, which is what a stolen session does.
	 *
	 * @param mixed $user_id @param mixed $item
	 */
	public static function on_app_password_created( $user_id = 0, $item = null ): void {
		$ip      = (string) self::client_ip();
		$name    = is_array( $item ) ? substr( preg_replace( '/[^\P{C}]+/u', '', (string) ( $item['name'] ?? '' ) ) ?? '', 0, 60 ) : '';
		$known   = class_exists( 'WPS_Login_Guard' ) && WPS_Login_Guard::admin_ip_known( $ip );
		$risk    = $known ? self::score_for( 'application_password_created' ) : self::score_for( 'application_password_created' ) + 60;
		self::record( 'application_password_created', [
			'user_id'     => (int) $user_id,
			'object_type' => 'application_password',
			'object_name' => $name,
			'severity'    => $known ? 'info' : 'warning',
			'risk'        => $risk,
			'notes'       => 'application password "' . $name . '" created'
				. ( $known ? '' : ' from an address no administrator has signed in from recently: if you did not make it, revoke it and every session for this account' ),
		] );
	}

	/** A password-reset request, for an account that can administer the site. @param mixed $login */
	public static function on_password_reset_requested( $login = '' ): void {
		$login = is_string( $login ) ? $login : '';
		if ( '' === $login || ! function_exists( 'get_user_by' ) ) {
			return;
		}
		$user = get_user_by( strpos( $login, '@' ) ? 'email' : 'login', $login );
		if ( ! $user || ! function_exists( 'user_can' ) || ! user_can( $user, 'manage_options' ) ) {
			return;
		}
		self::record( 'password_reset_requested', [
			'user_id'     => (int) $user->ID,
			'object_type' => 'user',
			'object_name' => (string) $user->user_login,
			'severity'    => 'warning',
			'notes'       => 'a password reset was requested for an administrator account; if you did not ask for it, someone is trying to take the account',
		] );
	}

	//  Hooks 

	public static function register_hooks(): void {
		add_action( 'wp_login', [ __CLASS__, 'on_login' ], 10, 2 );
		add_action( 'wp_login_failed', [ __CLASS__, 'on_login_failed' ], 10, 1 );
		add_action( 'clear_auth_cookie', [ __CLASS__, 'on_logout' ], 10, 0 );
		add_action( 'user_register', [ __CLASS__, 'on_user_register' ], 10, 1 );
		// 1.4.73: real-time injected-spam detection. Fires on every publish, but
		// the matcher only flags actual gambling/SEO-spam, so a legitimate post
		// returns immediately. Catches injection whatever the vector - REST,
		// XML-RPC, a webshell calling wp_insert_post(), or a malicious cron.
		add_action( 'save_post', [ __CLASS__, 'on_save_post' ], 10, 3 );		add_action( 'set_user_role', [ __CLASS__, 'on_role_change' ], 10, 3 );
		add_action( 'after_password_reset', [ __CLASS__, 'on_password_changed' ], 10, 1 );
		add_action( 'activated_plugin', [ __CLASS__, 'on_plugin_activated' ], 10, 1 );
		add_action( 'deactivated_plugin', [ __CLASS__, 'on_plugin_deactivated' ], 10, 1 );
		add_action( 'switch_theme', [ __CLASS__, 'on_theme_switched' ], 10, 1 );
		add_action( 'upgrader_process_complete', [ __CLASS__, 'on_upgrader_complete' ], 10, 2 );
		add_action( 'add_attachment', [ __CLASS__, 'on_attachment_added' ], 10, 1 );
		add_action( 'application_password_did_authenticate', [ __CLASS__, 'on_app_password_auth' ], 10, 2 );
		add_action( 'wp_create_application_password', [ __CLASS__, 'on_app_password_created' ], 10, 2 );
		add_action( 'retrieve_password', [ __CLASS__, 'on_password_reset_requested' ], 10, 1 );
		add_action( 'current_screen', [ __CLASS__, 'on_admin_screen' ], 10, 1 );
		// 1.4.10: scan-time detection finds the bad state; these find the moment
		// it was set, and who was signed in when it happened.
		add_action( 'update_option_users_can_register', [ __CLASS__, 'on_registration_toggled' ], 10, 2 );
		add_action( 'update_option_default_role', [ __CLASS__, 'on_default_role_changed' ], 10, 2 );
	}

	/** @param mixed $user */
	public static function on_login( $user_login, $user = null ): void {
		$role = '';
		$uid  = null;
		if ( is_object( $user ) ) {
			$uid  = isset( $user->ID ) ? (int) $user->ID : null;
			$role = ( ! empty( $user->roles ) && is_array( $user->roles ) ) ? (string) reset( $user->roles ) : '';
		}
		self::record( 'login_success', [
			'user_id'     => $uid,
			'username'    => (string) $user_login,
			'user_role'   => $role,
			'object_type' => 'session',
			'object_name' => (string) $user_login,
			'notes'       => 'successful sign-in' . ( $role !== '' ? ' as ' . $role : '' ),
		] );
	}

	public static function on_login_failed( $user_login ): void {
		self::record( 'login_failed', [
			'username'    => is_string( $user_login ) ? substr( $user_login, 0, 60 ) : '',
			'object_type' => 'session',
			'object_name' => is_string( $user_login ) ? substr( $user_login, 0, 190 ) : '',
			'notes'       => 'failed sign-in attempt',
		] );
	}

	public static function on_logout(): void {
		if ( ! function_exists( 'get_current_user_id' ) || (int) get_current_user_id() === 0 ) {
			return;
		}
		self::record( 'logout', [
			'object_type' => 'session',
			'notes'       => 'signed out',
		] );
	}

	public static function on_user_register( $user_id ): void {
		$uid   = (int) $user_id;
		$login = '';
		$role  = '';
		if ( function_exists( 'get_userdata' ) ) {
			$u = get_userdata( $uid );
			if ( $u ) {
				$login = (string) $u->user_login;
				$role  = ( ! empty( $u->roles ) && is_array( $u->roles ) ) ? (string) reset( $u->roles ) : '';
			}
		}
		$is_admin_role = in_array( $role, [ 'administrator', 'super-admin' ], true );
		self::record( $is_admin_role ? 'admin_account_created' : 'user_registered', [
			'object_type' => 'user',
			'object_name' => $login !== '' ? $login : ( 'user #' . $uid ),
			'severity'    => $is_admin_role ? 'critical' : 'info',
			'notes'       => $is_admin_role
				? 'a new ADMINISTRATOR account was created - if you did not create it, treat the site as compromised'
				: 'new account registered with role ' . ( $role !== '' ? $role : 'unknown' ),
		] );
	}

	/**
	 * 1.4.73: flag a post saved with injected gambling/SEO-spam signatures, in
	 * real time, whatever wrote it. The shared matcher requires an SEO-spam
	 * token or a stuffing-plus-cloaking combination, so a legitimate post - even
	 * one that discusses gambling - returns without an event. Flagged once per
	 * post (a meta marker) so ordinary edits do not re-fire.
	 */
	public static function on_save_post( $post_id, $post = null, $update = false ): void {
		$post_id = (int) $post_id;
		if ( $post_id <= 0 || ! class_exists( 'WPS_Spam_Signatures' ) ) {
			return;
		}
		if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
			return;
		}
		if ( function_exists( 'wp_is_post_revision' ) && wp_is_post_revision( $post_id ) ) {
			return;
		}
		if ( function_exists( 'wp_is_post_autosave' ) && wp_is_post_autosave( $post_id ) ) {
			return;
		}
		if ( ! is_object( $post ) && function_exists( 'get_post' ) ) {
			$post = get_post( $post_id );
		}
		if ( ! is_object( $post ) ) {
			return;
		}
		if ( ! in_array( (string) $post->post_type, [ 'post', 'page' ], true ) ) {
			return;
		}
		if ( in_array( (string) $post->post_status, [ 'auto-draft', 'inherit', 'trash' ], true ) ) {
			return;
		}

		$eval = WPS_Spam_Signatures::evaluate( (string) $post->post_title . "\n" . (string) $post->post_content );
		if ( empty( $eval['spam'] ) ) {
			return;
		}

		// Once per post: do not re-fire on every subsequent edit.
		if ( function_exists( 'get_post_meta' ) && get_post_meta( $post_id, '_wps_spam_flagged', true ) ) {
			return;
		}

		// 1.4.153: the once-per-post marker is written only after the event is stored. Set first, a
		// failed store left the marker behind and every later save of the post skipped the alert.
		$recorded = self::record(
			'spam_post_injection_detected',
			[
				'object_type' => 'post',
				'object_name' => ucfirst( (string) $post->post_type ) . ' #' . $post_id . ' (' . (string) $post->post_status . ')',
				'severity'    => 'high',
				'notes'       => 'a ' . (string) $post->post_type . ' was saved carrying injected gambling/SEO-spam signatures (' . $eval['reason'] . '). '
					. 'If you did not write this, treat it as an injection: find the entry point (rogue admin, mu-plugins, PHP in uploads, modified functions.php) BEFORE deleting the post, or it will be republished.',
			]
		);
		if ( $recorded && function_exists( 'update_post_meta' ) ) {
			update_post_meta( $post_id, '_wps_spam_flagged', time() );
		}
	}

	public static function on_role_change( $user_id, $role, $old_roles = [] ): void {
		if ( ! in_array( (string) $role, [ 'administrator', 'super-admin' ], true ) ) {
			return; // only elevation to admin is interesting at this phase
		}
		$old = is_array( $old_roles ) && $old_roles ? (string) reset( $old_roles ) : 'none';
		if ( in_array( $old, [ 'administrator', 'super-admin' ], true ) ) {
			return; // already an admin, no elevation happened
		}
		self::record( 'user_role_elevated', [
			'object_type' => 'user',
			'object_name' => 'user #' . (int) $user_id,
			'severity'    => 'critical',
			'notes'       => 'role raised from ' . $old . ' to ' . (string) $role,
		] );
	}

	/** @param mixed $user */
	public static function on_password_changed( $user = null ): void {
		self::record( 'password_changed', [
			'object_type' => 'user',
			'object_name' => is_object( $user ) && isset( $user->user_login ) ? (string) $user->user_login : null,
			'notes'       => 'password reset completed',
		] );
	}

	public static function on_plugin_activated( $plugin ): void {
		self::record( 'plugin_activated', [
			'object_type' => 'plugin',
			'object_name' => is_string( $plugin ) ? substr( $plugin, 0, 190 ) : '',
			'notes'       => 'plugin activated',
		] );
	}

	public static function on_plugin_deactivated( $plugin ): void {
		self::record( 'plugin_deactivated', [
			'object_type' => 'plugin',
			'object_name' => is_string( $plugin ) ? substr( $plugin, 0, 190 ) : '',
			'notes'       => 'plugin deactivated',
		] );
	}

	public static function on_theme_switched( $new_name ): void {
		self::record( 'theme_switched', [
			'object_type' => 'theme',
			'object_name' => is_string( $new_name ) ? substr( $new_name, 0, 190 ) : '',
			'notes'       => 'active theme changed',
		] );
	}

	/** @param mixed $upgrader @param mixed $extra */
	public static function on_upgrader_complete( $upgrader = null, $extra = null ): void {
		if ( ! is_array( $extra ) || ( $extra['type'] ?? '' ) !== 'plugin' ) {
			return;
		}
		$names = [];
		if ( ! empty( $extra['plugins'] ) && is_array( $extra['plugins'] ) ) {
			$names = array_slice( array_map( 'strval', $extra['plugins'] ), 0, 5 );
		} elseif ( ! empty( $extra['plugin'] ) ) {
			$names = [ (string) $extra['plugin'] ];
		}
		self::record( 'plugin_installed', [
			'object_type' => 'plugin',
			'object_name' => $names ? substr( implode( ', ', $names ), 0, 190 ) : null,
			'notes'       => 'plugin ' . ( ( $extra['action'] ?? '' ) === 'install' ? 'installed' : 'updated' ) . ' through the upgrader',
		] );

		// 1.4.83: attribute these slugs in the plugin roster. A plugin that
		// arrives through the upgrader was installed by someone using the
		// dashboard or WP-CLI - that is an authorised route, whoever they
		// were. A plugin folder that simply appears on disk with no such
		// record did not come that way, and that difference is the whole
		// point of the roster.
		//
		// 1.4.152: installs only. The hook also fires for updates, and attributing those let a folder that
		// had been planted on disk become "installed" the moment WordPress auto-updated it.
		if ( ( $extra['action'] ?? '' ) === 'install' && class_exists( 'WPS_Scanner' ) && method_exists( 'WPS_Scanner', 'attribute_plugin_install' ) ) {
			foreach ( $names as $n ) {
				WPS_Scanner::attribute_plugin_install( $n );
			}
		}
	}

	public static function on_attachment_added( $post_id ): void {
		$file = function_exists( 'get_attached_file' ) ? (string) get_attached_file( (int) $post_id ) : '';
		self::record( 'file_uploaded', [
			'object_type' => 'attachment',
			'object_name' => $file !== '' ? substr( basename( $file ), 0, 190 ) : ( 'attachment #' . (int) $post_id ),
			'notes'       => 'file uploaded to the media library',
		] );
	}

	/**
	 * Admin screen views. Only the screens that matter, and throttled per
	 * session so that reloading the user list twenty times does not fill the
	 * store with twenty rows. The file editors are recorded as their own
	 * event type because opening one is a materially different act from
	 * viewing a list.
	 *
	 * @param mixed $screen
	 */
	public static function on_admin_screen( $screen = null ): void {
		if ( ! is_object( $screen ) || empty( $screen->id ) ) {
			return;
		}
		$id = (string) $screen->id;
		if ( ! isset( self::WATCHED_SCREENS[ $id ] ) ) {
			return;
		}
		if ( function_exists( 'get_current_user_id' ) && (int) get_current_user_id() === 0 ) {
			return;
		}

		$session = self::session_id() ?: 'nosession';
		$key     = 'wps_edr_scr_' . substr( md5( $session . '|' . $id ), 0, 24 );
		if ( function_exists( 'get_transient' ) && get_transient( $key ) ) {
			return;
		}
		if ( function_exists( 'set_transient' ) ) {
			set_transient( $key, 1, self::SCREEN_THROTTLE );
		}

		$is_editor = in_array( $id, [ 'plugin-editor', 'theme-editor' ], true );
		self::record( $is_editor ? 'file_editor_opened' : 'admin_screen_visited', [
			'object_type' => 'screen',
			'object_name' => $id,
			'severity'    => $is_editor ? 'warning' : 'info',
			'notes'       => self::WATCHED_SCREENS[ $id ]
				. ( $is_editor ? ' - the file editors can write executable PHP straight into the site' : '' ),
		] );
	}

	/**
	 * 1.4.10: registration switched on. Recorded either way - a legitimate
	 * change is worth having in the timeline too, because it explains a later
	 * run of new accounts instead of leaving it mysterious.
	 *
	 * @param mixed $old @param mixed $new
	 */
	public static function on_registration_toggled( $old = null, $new = null ): void {
		if ( (int) $old === (int) $new ) {
			return;
		}
		$opened = ( (int) $new === 1 );
		self::record( 'registration_opened', [
			'object_type' => 'option',
			'object_name' => 'users_can_register',
			'severity'    => $opened ? 'warning' : 'info',
			'risk'        => $opened ? self::score_for( 'registration_opened' ) : 0,
			'notes'       => $opened
				? 'open registration was switched ON - anyone reaching wp-login.php can now create an account'
				: 'open registration was switched off',
		] );
	}

	/**
	 * 1.4.10: default role changed. Escalation to a privileged role is the
	 * single most valuable thing this class can catch, because it needs no
	 * file and no further access - the registration form becomes the backdoor.
	 *
	 * @param mixed $old @param mixed $new
	 */
	public static function on_default_role_changed( $old = null, $new = null ): void {
		$old_r = strtolower( trim( (string) $old ) );
		$new_r = strtolower( trim( (string) $new ) );
		if ( $old_r === $new_r ) {
			return;
		}
		$privileged = [ 'administrator', 'super-admin', 'editor', 'author' ];
		$escalated  = in_array( $new_r, $privileged, true ) && ! in_array( $old_r, $privileged, true );
		self::record( 'default_role_escalated', [
			'object_type' => 'option',
			'object_name' => 'default_role',
			'severity'    => $escalated ? 'critical' : 'info',
			'risk'        => $escalated ? self::score_for( 'default_role_escalated' ) : 10,
			'notes'       => $escalated
				? 'the role given to every new account was raised from ' . ( $old_r !== '' ? $old_r : 'subscriber' ) . ' to ' . $new_r . ' - if you did not do this, every registration since is an attacker account'
				: 'default role for new accounts changed from ' . ( $old_r !== '' ? $old_r : 'unset' ) . ' to ' . $new_r,
		] );
	}

	//  Reading: incidents & timelines 

	/**
	 * Recent incidents with their cumulative risk, newest first.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function recent_incidents( int $limit = 10 ): array {
		$db = ( isset( $GLOBALS['wpdb'] ) && is_object( $GLOBALS['wpdb'] ) ) ? $GLOBALS['wpdb'] : null;
		if ( ! $db || ! class_exists( 'WPS_Event_Log' ) || ! WPS_Event_Log::available() ) {
			return [];
		}
		$table = WPS_Event_Log::table();
		$rows  = $db->get_results(
			$db->prepare(
				"SELECT incident_id,
				        MIN(ts) AS started,
				        MAX(ts) AS ended,
				        COUNT(*) AS events,
				        SUM(COALESCE(risk_score,0)) AS risk,
				        MAX(username) AS username,
				        MAX(ip) AS ip
				 FROM {$table}
				 WHERE incident_id IS NOT NULL
				 GROUP BY incident_id
				 ORDER BY MAX(id) DESC
				 LIMIT %d",
				max( 1, $limit )
			),
			ARRAY_A
		);
		if ( ! is_array( $rows ) ) {
			return [];
		}
		foreach ( $rows as &$r ) {
			$r['risk']   = (int) ( $r['risk'] ?? 0 );
			$r['events'] = (int) ( $r['events'] ?? 0 );
			$r['band']   = self::band_for( $r['risk'] );
		}
		unset( $r );
		return $rows;
	}

	/**
	 * The events of one incident, oldest first - the narrative order an
	 * operator reads.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function incident_timeline( string $incident_id, int $limit = 100 ): array {
		$db = ( isset( $GLOBALS['wpdb'] ) && is_object( $GLOBALS['wpdb'] ) ) ? $GLOBALS['wpdb'] : null;
		if ( ! $db || ! class_exists( 'WPS_Event_Log' ) || ! WPS_Event_Log::available() ) {
			return [];
		}
		$table = WPS_Event_Log::table();
		$rows  = $db->get_results(
			$db->prepare(
				"SELECT ts, event_type, username, ip, object_type, object_name, severity, risk_score, notes
				 FROM {$table}
				 WHERE incident_id = %s
				 ORDER BY id ASC
				 LIMIT %d",
				$incident_id,
				max( 1, $limit )
			),
			ARRAY_A
		);
		return is_array( $rows ) ? $rows : [];
	}
}
