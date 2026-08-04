<?php
/**
 * Login guard (1.4.17): stops automated credential guessing.
 *
 * The shape of this feature is decided by one number: Akismet's HTTP client
 * uses a fifteen-second timeout. If a block decision waited on that call, an
 * attacker who can make Akismet slow could pin every PHP worker on the site
 * simply by hammering wp-login.php, and an Akismet outage would mean no login
 * protection at all. So the local counter decides WHETHER to block, always,
 * with no network in the path. Akismet decides only HOW LONG, after the fact.
 *
 * That ordering is not a detail. It is the feature.
 *
 * Locking an operator out of their own site is the obvious way for this to go
 * wrong, and it is the same failure class as the must-use guard withdrawn in
 * 1.4.15, so the protections are in the original design:
 *
 *   - a logged-in administrator's address is never blockable;
 *   - addresses that have recently completed an administrator login are
 *     remembered and protected, which covers the operator who is logged out;
 *   - an allowlist for shared office and VPN egress addresses;
 *   - every block expires, and there is no permanent state;
 *   - WPS_DISABLE_LOGIN_GUARD in wp-config.php switches the whole thing off
 *     with FTP access alone, needing no database and no admin screen.
 *
 * Counters are transients rather than an option row. A transient carries its
 * own expiry, so the store cannot outlive its window - and once an address is
 * blocked the gate rejects it before wp_login_failed can fire, so a blocked
 * bot stops generating writes entirely. Both bounds are structural rather
 * than a threshold hoped to hold.
 *
 * @package WP_Perf_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class WPS_Login_Guard {

	/** Rolling window for counting failures, in seconds. */
	private const WINDOW = 900;

	/** Failures within the window before an address is blocked. */
	private const THRESHOLD = 5;

	/** Block durations. Akismet selects between clean and spam; default is the fallback. */
	private const BLOCK_DEFAULT = 3600;
	private const BLOCK_CLEAN   = 900;
	private const BLOCK_SPAM    = 86400;

	/**
	 * 1.4.26: escalation ladder for a returning offender.
	 *
	 * A block that expires and lets the same address straight back in is an
	 * inconvenience, not a deterrent - the live log showed 41.216.188.106
	 * blocked, waiting out fifteen minutes, and resuming. Each fresh block of
	 * an address that has been blocked before steps up this ladder, and the
	 * step count is remembered past the block's own lifetime so the escalation
	 * survives the wait.
	 */
	private const LADDER = [ 900, 3600, 21600, 86400, 604800 ]; // 15m, 1h, 6h, 24h, 7d
	/**
	 * 1.4.31: permanent sign-in denylist.
	 *
	 * A bot trying "root" or "admin" on a site where no such account exists
	 * is not ambiguous, and it does not deserve a fifteen-minute cool-off. The
	 * operator asked for these to be held permanently.
	 *
	 * This is deliberately NOT a flag on the ordinary block list. That list is
	 * a fixed-size cache which evicts by soonest expiry: a permanent entry put
	 * in there would either be evicted anyway - so not permanent - or would
	 * crowd out the ability to block a live attack. A permanent record needs
	 * its own store.
	 *
	 * Two properties bound the harm, and both are worth stating because they
	 * are what make "permanent" defensible at all:
	 *
	 *   - the gate runs on `authenticate`, so a permanent block prevents
	 *     signing in and nothing else. Whoever holds that address can still
	 *     read the site.
	 *   - it can only be triggered by a username that does NOT exist here, so
	 *     no real account - including the operator's - can ever put its own
	 *     address on this list.
	 *
	 * Still bounded, because an unbounded store is how this plugin took a site
	 * down in 1.4.13. Oldest entries are dropped first, and every entry can be
	 * removed by hand from Diagnostics.
	 */
	private const PERMANENT_OPTION = 'wps_permanent_blocks';
	private const PERMANENT_MAX    = 1000;

	private const OFFENDERS_OPTION = 'wps_login_offenders';
	private const OFFENDER_TTL     = 1209600; // remember an address for 14 days
	private const OFFENDERS_MAX    = 500;

	/**
	 * Distinct non-existent usernames from one address before the local
	 * evidence alone is conclusive. A human mistyping their password does not
	 * cycle through root, admin, site_admin and a dozen others.
	 */
	private const MULTIUSER_FLOOR = 5;

	/**
	 * 1.4.23: network-level counting, for rotation across a range.
	 *
	 * A per-address threshold is the right rule for one attacker at one
	 * address, and useless against one attacker holding a range. Observed on
	 * a live site: five failures against a single username from four
	 * addresses in one /24, each address stopping before the per-address
	 * count could reach five.
	 *
	 * Blocking a whole network is a much larger hammer than blocking an
	 * address. A /24 can be a mobile carrier's NAT egress with thousands of
	 * ordinary people behind it, so every constant here is deliberately more
	 * cautious than its per-address equivalent, and three separate conditions
	 * must hold before a range is touched at all.
	 */
	private const NET_WINDOW    = 900;
	private const NET_THRESHOLD = 12;  // failures across the range, vs 5 for one address
	private const NET_MIN_IPS   = 3;   // distinct addresses, or it is just the per-address case
	private const NET_MAX_IPS   = 24;  // cap on addresses remembered per range
	private const NET_BLOCK     = 1800; // half the per-address default: bigger blast radius, shorter hold

	/**
	 * 1.4.65: low-and-slow subnet rotation.
	 *
	 * The count-based rule above (NET_THRESHOLD in NET_WINDOW) is a rate rule,
	 * and rate is exactly what an attacker drops to evade it: one failed sign-in
	 * every nine or ten minutes, each from a different address in the same /24,
	 * so no address reaches five, no fifteen-minute window reaches twelve, and a
	 * gap just over the window resets the tally. What that pattern cannot hide is
	 * the rotation itself. Legitimate people do not fail sign-ins from five
	 * different addresses in one /24 inside an hour; an attacker cycling a subnet
	 * does. So distinct addresses within a longer rolling window become a trigger
	 * in their own right, independent of the raw count.
	 *
	 * This is still gated by network_is_protected(): a range holding the
	 * allowlist or any remembered administrator address is never blocked, so the
	 * larger blast radius cannot lock the operator out. A confirmed rotation is a
	 * high-confidence signal, so it is held longer than a raw-count block.
	 */
	private const NET_ROTATION_WINDOW  = 3600;  // 1h rolling window, timestamp-pruned (not TTL-reset)
	private const NET_DISTINCT_TRIGGER = 5;     // distinct addresses in that window that alone mark rotation
	private const NET_BLOCK_ROTATION   = 21600; // 6h: rotation is high-confidence, so hold longer than NET_BLOCK
	private const NET_EVENTS_MAX       = 300;   // cap on stored failure events per range, to bound the transient

	/**
	 * 1.4.67: repeat-offender ladder for ranges.
	 *
	 * A flat block lets a persistent rotator return the moment it lifts, which
	 * is most of why a busy site keeps seeing the same /24. A range that
	 * re-offends inside the 14-day memory now climbs this ladder, so its usable
	 * window shrinks every time it comes back. It stops at seven days rather
	 * than going permanent: a /24 can hold people who are not the attacker, so
	 * an automatic forever-ban of a whole range is a bigger hammer than this
	 * should swing on its own. Permanent range bans stay a manual decision.
	 */
	private const NET_LADDER          = [ 21600, 86400, 259200, 604800 ]; // 6h, 24h, 3d, 7d
	private const NET_OFFENDERS_OPTION = 'wps_login_net_offenders';

	/** How long an Akismet verdict is trusted for an address. */
	private const VERDICT_TTL = 86400;

	/** Addresses that have completed an administrator login recently. */
	/**
	 * 1.4.18: a small activity record.
	 *
	 * The guard was silent until something got blocked, which made a working
	 * installation indistinguishable from a broken one. Counting is cheap and
	 * already bounded - a failed attempt can only be recorded until the
	 * address is blocked, after which the gate rejects it before this code
	 * runs - so the same bound that protects the counter protects this.
	 */
	private const STATS_OPTION = 'wps_login_stats';

	/**
	 * Every counter the guard keeps. Named in one place because they are
	 * written in several and, until 1.4.32, four of them were recorded daily
	 * and never surfaced anywhere - the screen simply did not ask for them.
	 */
	private const COUNTERS = [
		'attempts',
		'blocks',
		'permanent_blocks',
		'network_blocks',
		'multiuser_blocks',
		'spam_reports',
		'akismet_spam',
		'akismet_clean',
		'akismet_unavailable',
	];

	private const ADMIN_IPS_OPTION = 'wps_admin_login_ips';
	private const ADMIN_IPS_MAX    = 12;
	private const ADMIN_IP_TTL     = 2592000; // 30 days

	/**
	 * Usernames automated tooling tries first. Blocked on sight, but only
	 * when no such account exists here - if the site really does have a user
	 * called admin, attempts against it are ordinary failures and go through
	 * the counter like any other.
	 *
	 * @return array<int, string>
	 */
	public static function bot_usernames(): array {
		return (array) apply_filters(
			'wps_login_bot_usernames',
			[
				'admin', 'administrator', 'root', 'test', 'tester', 'webmaster',
				'support', 'demo', 'guest', 'user', 'wpadmin', 'wp-admin',
				'sysadmin', 'operator', 'manager', 'info', 'backup',
			]
		);
	}

	public static function register_hooks(): void {
		if ( ! self::enabled() ) {
			return;
		}
		// Priority 1: reject a blocked address before WordPress looks up the
		// user or hashes a password.
		add_filter( 'authenticate', [ __CLASS__, 'gate' ], 1, 3 );
		add_action( 'wp_login_failed', [ __CLASS__, 'on_failed' ], 10, 1 );
		add_action( 'wp_login', [ __CLASS__, 'on_success' ], 10, 2 );

		if ( self::xmlrpc_auth_disabled() ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'xmlrpc_methods', [ __CLASS__, 'strip_multicall' ] );
		} elseif ( self::multicall_strip_enabled() ) {
			// 1.4.66: neuter the credential-amplification vector without
			// disabling XML-RPC sign-in. Jetpack and the mobile apps
			// authenticate through direct methods (wp.getUsersBlogs), not
			// system.multicall, so removing multicall alone does not break
			// them - only the full disable above does. This is the middle
			// ground the all-or-nothing toggle never offered.
			add_filter( 'xmlrpc_methods', [ __CLASS__, 'strip_multicall_only' ] );
		}
	}

	/**
	 * Master switch. The constant wins over the setting, deliberately: it is
	 * the recovery route for an operator who cannot reach wp-admin.
	 */
	public static function enabled(): bool {
		if ( defined( 'WPS_DISABLE_LOGIN_GUARD' ) && WPS_DISABLE_LOGIN_GUARD ) {
			return false;
		}
		$s = get_option( WPS_OPTION, [] );
		return ! is_array( $s ) || ( $s['login_guard_enabled'] ?? '1' ) !== '0';
	}

	/**
	 * Network-level blocking. On by default, but separable, because it is the
	 * one part of this feature that can affect people who are not the
	 * attacker.
	 */
	public static function network_guard_enabled(): bool {
		$s = get_option( WPS_OPTION, [] );
		return ! is_array( $s ) || ( $s['login_network_guard'] ?? '1' ) !== '0';
	}

	private static function xmlrpc_auth_disabled(): bool {
		$s = get_option( WPS_OPTION, [] );
		// Off by default: switching it on silently would break Jetpack and
		// the mobile apps for anyone relying on them.
		return is_array( $s ) && ( $s['xmlrpc_auth_disabled'] ?? '0' ) === '1';
	}

	/**
	 * Strip system.multicall by default (1.4.66). Unlike disabling XML-RPC
	 * sign-in wholesale, this does not affect Jetpack or the mobile apps, which
	 * use direct methods - so it is safe to default on, and it closes the one
	 * request-batching path an attacker uses to carry many credential guesses
	 * at once. Has an off switch for the rare tool that batches through
	 * system.multicall on purpose.
	 */
	public static function multicall_strip_enabled(): bool {
		$s = get_option( WPS_OPTION, [] );
		return ! is_array( $s ) || ( $s['xmlrpc_strip_multicall'] ?? '1' ) !== '0';
	}

	/**
	 * Remove system.multicall, which lets one request carry hundreds of
	 * credential guesses. The rest of the XML-RPC surface is left alone.
	 *
	 * @param array<string, mixed> $methods
	 * @return array<string, mixed>
	 */
	public static function strip_multicall( $methods ) {
		if ( ! is_array( $methods ) ) {
			return $methods;
		}
		unset( $methods['system.multicall'], $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
		return $methods;
	}

	/**
	 * Remove only system.multicall - the credential-amplification vector -
	 * leaving the rest of the XML-RPC surface, including pingback and the
	 * direct sign-in methods Jetpack and the mobile apps use, untouched.
	 *
	 * @param array<string, mixed> $methods
	 * @return array<string, mixed>
	 */
	public static function strip_multicall_only( $methods ) {
		if ( ! is_array( $methods ) ) {
			return $methods;
		}
		unset( $methods['system.multicall'] );
		return $methods;
	}

	// ---------------------------------------------------------------
	//  The gate
	// ---------------------------------------------------------------

	/**
	 * Reject a blocked address before authentication work happens.
	 *
	 * @param mixed  $user
	 * @param string $username
	 * @param string $password
	 * @return mixed
	 */
	public static function gate( $user, $username = '', $password = '' ) {
		if ( '' === (string) $username && '' === (string) $password ) {
			return $user; // not a submitted login
		}
		$ip = self::ip();
		if ( '' === $ip || self::is_protected_ip( $ip ) ) {
			return $user;
		}
		// 1.4.31: permanent denylist first. No expiry to compute and no
		// duration to report - this address does not sign in here again.
		if ( self::is_permanently_blocked( $ip ) ) {
			return new WP_Error(
				'wps_login_blocked_permanent',
				'<strong>Sign-in from this address is blocked.</strong> This address was used in an automated attack on an account that does not exist on this site.'
			);
		}

		$until = self::blocked_until( $ip );
		$scope = 'address';
		if ( $until <= 0 && self::network_guard_enabled() ) {
			$until = self::network_blocked_until( $ip );
			$scope = 'network';
		}
		if ( $until <= 0 ) {
			return $user;
		}
		$mins = max( 1, (int) ceil( ( $until - time() ) / 60 ) );
		return new WP_Error(
			'network' === $scope ? 'wps_login_blocked_network' : 'wps_login_blocked',
			sprintf(
				/* translators: %d: minutes remaining */
				'<strong>Too many failed sign-in attempts.</strong> Further attempts from this address are blocked for another %d minute(s).',
				$mins
			)
		);
	}

	/**
	 * Count a failure, and block once the threshold is reached.
	 *
	 * @param string $username
	 */
	public static function on_failed( $username = '' ): void {
		$ip = self::ip();
		if ( '' === $ip || self::is_protected_ip( $ip ) ) {
			return;
		}
		$username = (string) $username;
		self::record_username( $ip, $username );

		// A bot favourite that is not a real account here. Unambiguous on the
		// first attempt: no human tries "root" on a WordPress site, and the
		// username_exists() gate above means no real account can land here.
		if ( self::is_bot_username( $username ) ) {
			self::note( 'attempts' );
			$reason = 'automated sign-in attempt on non-existent account "' . self::safe( $username ) . '"';

			// 1.4.31: permanent rather than a cool-off. Recorded in its own
			// store so it cannot be evicted by the rotating block cache.
			if ( self::block_permanently( $ip, $reason, $username ) ) {
				self::note( 'blocks' );
				// Still reported to Akismet - a bot username is conclusive
				// evidence and always was.
				self::maybe_report_spam( $ip, $username, self::distinct_bad_usernames( $ip ), 1 );
				return;
			}

			// Protected or unparseable address: fall back to the ordinary
			// path rather than silently doing nothing.
			self::block( $ip, $reason, $username );
			return;
		}

		self::note( 'attempts' );

		$key   = self::counter_key( $ip );
		$count = (int) get_transient( $key );
		++$count;
		// The transient's own expiry bounds the store; nothing accumulates
		// beyond the window.
		set_transient( $key, $count, self::WINDOW );

		if ( $count >= self::THRESHOLD ) {
			delete_transient( $key );
			self::block( $ip, sprintf( '%d failed sign-in attempts within %d minutes', $count, (int) ( self::WINDOW / 60 ) ), $username );
			return;
		}

		// 1.4.23: the same failure also counts against the address's range.
		// Only reached when the per-address rule has NOT fired, so an
		// ordinary noisy address is handled as before and never escalates
		// into a network block on its own. 1.4.65: the range rule now also
		// catches slow distinct-address rotation, not just bursts.
		if ( self::network_guard_enabled() ) {
			$scope = self::note_network_failure( $ip );
			if ( '' !== $scope ) {
				self::block_network( $ip, $username, $scope );
			}
		}
	}

	/**
	 * A success clears the counter, and records the address as one an
	 * administrator signs in from.
	 *
	 * @param string $user_login
	 * @param mixed  $user
	 */
	public static function on_success( $user_login = '', $user = null ): void {
		$ip = self::ip();
		if ( '' === $ip ) {
			return;
		}
		delete_transient( self::counter_key( $ip ) );

		if ( ! is_object( $user ) || ! isset( $user->ID ) ) {
			return;
		}
		if ( ! user_can( $user->ID, 'manage_options' ) ) {
			return;
		}
		self::remember_admin_ip( $ip );
	}

	// ---------------------------------------------------------------
	//  Blocking
	// ---------------------------------------------------------------

	/**
	 * Record the block first, then ask Akismet how long it should have been.
	 *
	 * The order matters: the address is blocked whether or not Akismet
	 * answers, is reachable, or is installed at all.
	 */
	private static function block( string $ip, string $reason, string $username ): void {
		// 1.4.26: local evidence leads. The old logic asked Akismet first and
		// let a "clean" verdict impose the lenient 15-minute cool-off even on
		// an address the site had already watched try twenty usernames. That
		// was backwards: Akismet not yet knowing an address is not evidence
		// the address is innocent. So the local signal decides the floor, and
		// Akismet may only lengthen from there, never shorten below it.
		$offence   = self::register_offence( $ip );          // how many times this address has been blocked
		$multiuser = self::distinct_bad_usernames( $ip );    // conclusive local signal

		$verdict = self::akismet_verdict( $ip, $username );

		// Base duration from the escalation ladder, indexed by prior offences.
		$rung    = min( $offence - 1, count( self::LADDER ) - 1 );
		$rung    = max( 0, $rung );
		$seconds = self::LADDER[ $rung ];
		$why     = [];
		if ( $offence > 1 ) {
			$why[] = 'repeat offender (block #' . $offence . ')';
		}

		// Conclusive local evidence sets a hard floor, regardless of Akismet.
		if ( $multiuser >= self::MULTIUSER_FLOOR ) {
			$seconds = max( $seconds, self::BLOCK_SPAM );
			$why[]   = $multiuser . ' different usernames tried from this address';
			self::note( 'multiuser_blocks' );
		}

		// Akismet may only escalate. A spam verdict raises to at least a day;
		// a clean verdict is allowed to shorten ONLY a first, single-username
		// offence - the genuine mistyped-password case - and never touches an
		// address the local signal has already damned.
		if ( 'spam' === $verdict ) {
			$seconds = max( $seconds, self::BLOCK_SPAM );
			$why[]   = 'Akismet: address known for spam';
			self::note( 'akismet_spam' );
		} elseif ( 'ham' === $verdict ) {
			if ( $offence === 1 && $multiuser < 2 ) {
				$seconds = self::BLOCK_CLEAN;
				$why[]   = 'Akismet: not known for spam and only one username tried, shorter cool-off';
			} else {
				$why[] = 'Akismet: not known for spam (ignored - local evidence is stronger)';
			}
			self::note( 'akismet_clean' );
		} else {
			self::note( 'akismet_unavailable' );
		}

		self::note( 'blocks' );

		$dur_source = 'escalation';
		if ( $multiuser >= self::MULTIUSER_FLOOR ) {
			$dur_source = 'multi-username';
		} elseif ( 'spam' === $verdict ) {
			$dur_source = 'akismet-spam';
		} elseif ( 'ham' === $verdict && $offence === 1 && $multiuser < 2 ) {
			$dur_source = 'akismet-clean';
		}

		$full = $reason . '; blocked ' . self::human_duration( $seconds )
			. ( $why ? ' - ' . implode( '; ', $why ) : '' );

		if ( class_exists( 'WPS_Blocker' ) ) {
			WPS_Blocker::record_ip_block(
				$ip,
				$full,
				$seconds,
				[
					'last_user'       => self::safe( $username ),
					'source'          => 'login-guard',
					'duration_source' => $dur_source,
					'offence'         => $offence,
				]
			);
		}
		if ( class_exists( 'WPS_EDR' ) && method_exists( 'WPS_EDR', 'record' ) ) {
			// Recorded as behaviour too, so it lands in the incident timeline.
			WPS_EDR::record(
				'login_blocked',
				[
					'object_type' => 'ip',
					'object_name' => $ip,
					'severity'    => ( $seconds >= self::BLOCK_SPAM ) ? 'high' : 'warning',
					'notes'       => $full,
				]
			);
		}

		// Last, after the block is recorded: contribute this address to
		// Akismet when the evidence is conclusive.
		//
		// 1.4.60: this comment previously said "if the operator opted in",
		// which contradicted the implementation - `akismet_enrichment` defaults
		// to '1', so reporting is ON unless the operator turns it off. The
		// default-enabled behaviour is intentional: every install contributes
		// to the shared spam corpus out of the box, which is what makes the
		// corpus worth consulting. The comment was wrong, not the code, and
		// `readme.txt` has described it correctly throughout.
		//
		// Opt-OUT lives in Settings. Reporting failures are contained inside
		// maybe_report_spam() so an unreachable Akismet cannot break the block
		// that has already been recorded above.
		self::maybe_report_spam( $ip, $username, $multiuser, $offence );
	}

	/**
	 * How long to block for. Akismet is consulted only here - after the
	 * decision to block has already been taken - and never on the path of a
	 * login attempt.
	 */
	private static function seconds_for( string $verdict ): int {
		if ( 'spam' === $verdict ) {
			return self::BLOCK_SPAM;
		}
		if ( 'ham' === $verdict ) {
			// A clean-looking address is more likely a person who mistyped
			// their password than a botnet, so let them back sooner.
			return self::BLOCK_CLEAN;
		}
		return self::BLOCK_DEFAULT;
	}

	/**
	 * Ask Akismet whether an address is known-bad. Returns 'spam', 'ham', or
	 * '' when no usable answer was available for any reason.
	 *
	 * Everything about this method is written to fail into ''. No key, plugin
	 * absent, method missing, network down, malformed reply, or an outright
	 * throw all produce the same result, and the caller falls back to the
	 * default duration.
	 */
	private static function akismet_verdict( string $ip, string $author = '', string $type = 'wps-login-attempt', string $permalink = '' ): string {
		if ( ! self::akismet_available() ) {
			return '';
		}
		$cache = 'wps_akv_' . md5( $ip );
		$hit   = get_transient( $cache );
		if ( is_string( $hit ) && '' !== $hit ) {
			return 'spam' === $hit ? 'spam' : 'ham';
		}

		if ( '' === $permalink ) {
			$permalink = wp_login_url();
		}

		try {
			$result = Akismet::comment_check(
				[
					// Passed explicitly rather than left to Akismet's own
					// request-scoped lookup: that default is correct only
					// while this runs inline, and would silently score the
					// wrong address if it ever ran deferred.
					'user_ip'              => $ip,
					'user_agent'           => (string) ( $_SERVER['HTTP_USER_AGENT'] ?? '' ),
					'comment_type'         => $type,
					'comment_author'       => self::safe( $author ),
					'comment_content'      => '',
					'permalink'            => $permalink,
					'is_test'              => defined( 'WP_DEBUG' ) && WP_DEBUG ? 'true' : 'false',
				]
			);
		} catch ( \Throwable $t ) {
			return '';
		}

		if ( ! is_object( $result ) || ! isset( $result->is_spam ) ) {
			return '';
		}
		$verdict = $result->is_spam ? 'spam' : 'ham';
		set_transient( $cache, $verdict, self::VERDICT_TTL );
		return $verdict;
	}

	/**
	 * Public reputation lookup for the OTHER guards (malware-upload,
	 * post-injection), so a known-bad address can lengthen the block those
	 * guards place - the same reputation input the login guard already uses for
	 * its own block duration. Returns 'spam', 'ham', or '' (no usable answer,
	 * for any reason). Fails into '' so a caller can always fall back to its
	 * default duration. The per-address verdict is cached and shared, so an
	 * address already scored by one guard is not re-queried by another.
	 */
	public static function akismet_reputation( string $ip, string $type = 'wps-attacker' ): string {
		if ( '' === $ip ) {
			return '';
		}
		$permalink = function_exists( 'home_url' ) ? home_url( '/' ) : '';
		return self::akismet_verdict( $ip, '', $type, $permalink );
	}

	/**
	 * Whether Akismet may be CONSULTED to weigh a block duration.
	 *
	 * Distinct from `login_report_spam`, which governs whether confirmed
	 * attackers are REPORTED to Akismet. The two are different data flows and
	 * an operator may reasonably want one without the other: reporting sends
	 * attacker data outward, enrichment only asks a question about an address.
	 * Both default to enabled.
	 *
	 * 1.4.60: this docblock previously read "there is nothing to switch on",
	 * directly above a line reading a switch - and that switch, `akismet_enrichment`,
	 * had no settings control and no save handler, so it could never be set to
	 * '0'. The code implied an operator control that did not exist. The control
	 * is now real; the comment now matches it.
	 */
	public static function akismet_available(): bool {
		$s = get_option( WPS_OPTION, [] );
		if ( is_array( $s ) && ( $s['akismet_enrichment'] ?? '1' ) === '0' ) {
			return false;
		}
		if ( ! class_exists( 'Akismet' ) || ! method_exists( 'Akismet', 'comment_check' ) ) {
			return false;
		}
		if ( ! method_exists( 'Akismet', 'get_api_key' ) ) {
			return false;
		}
		$key = '';
		try {
			$key = (string) Akismet::get_api_key();
		} catch ( \Throwable $t ) {
			return false;
		}
		return '' !== $key;
	}

	/** For the settings screen: what the operator should be told is happening. */
	public static function akismet_status(): string {
		if ( ! class_exists( 'Akismet' ) ) {
			return 'not detected - blocks use the default duration';
		}
		if ( ! self::akismet_available() ) {
			return 'detected but no API key - blocks use the default duration';
		}
		return 'detected - block duration adjusted by reputation';
	}

	/**
	 * 1.4.20: monthly API usage for the configured key.
	 *
	 * Requested directly rather than through the Akismet plugin, because
	 * `Akismet::http_post()` posts to a hardcoded /1.1/ path and this is a GET
	 * against /1.2/. The contract is taken from Akismet's published
	 * specification: the key goes in the query string, a success returns JSON
	 * with limit, usage, percentage and throttled, and an error returns the
	 * plain string "invalid".
	 *
	 * `limit` is documented as possibly being the string "none" for an
	 * unlimited key, which is why it is not cast to an integer.
	 *
	 * Cached for an hour. Checking a status page should not itself consume
	 * the allowance it is reporting on.
	 *
	 * @return array{state: string, limit: string, usage: int, percentage: string, throttled: bool, checked: string}
	 */
	public static function akismet_usage( bool $force = false ): array {
		$empty = [
			'state'      => 'unavailable',
			'limit'      => '',
			'usage'      => 0,
			'percentage' => '',
			'throttled'  => false,
			'checked'    => '',
		];

		if ( ! class_exists( 'Akismet' ) || ! method_exists( 'Akismet', 'get_api_key' ) ) {
			return $empty;
		}
		try {
			$key = (string) Akismet::get_api_key();
		} catch ( \Throwable $t ) {
			return $empty;
		}
		if ( '' === $key ) {
			return $empty;
		}

		$cache = 'wps_ak_usage';
		if ( ! $force ) {
			$hit = get_transient( $cache );
			if ( is_array( $hit ) && isset( $hit['state'] ) ) {
				return $hit;
			}
		}

		$response = wp_remote_get(
			add_query_arg( 'api_key', rawurlencode( $key ), 'https://rest.akismet.com/1.2/usage-limit' ),
			[
				// Deliberately short. This runs on an admin screen, not the
				// login path, but a status panel should not hang a page.
				'timeout'    => 8,
				'user-agent' => 'WP Perf Shield/' . WPS_VERSION,
			]
		);

		if ( is_wp_error( $response ) ) {
			$out = array_merge( $empty, [ 'state' => 'error', 'checked' => gmdate( 'Y-m-d H:i:s' ) . ' UTC' ] );
			set_transient( $cache, $out, 300 ); // retry sooner after a failure
			return $out;
		}

		$body = trim( (string) wp_remote_retrieve_body( $response ) );
		$data = json_decode( $body, true );

		if ( ! is_array( $data ) || ! isset( $data['usage'] ) ) {
			// The documented error response is the plain string "invalid".
			$out = array_merge(
				$empty,
				[
					'state'   => ( 'invalid' === strtolower( $body ) ) ? 'invalid' : 'error',
					'checked' => gmdate( 'Y-m-d H:i:s' ) . ' UTC',
				]
			);
			set_transient( $cache, $out, 300 );
			return $out;
		}

		$out = [
			'state'      => 'ok',
			'limit'      => (string) ( $data['limit'] ?? '' ),
			'usage'      => (int) $data['usage'],
			'percentage' => (string) ( $data['percentage'] ?? '' ),
			'throttled'  => ! empty( $data['throttled'] ),
			'checked'    => gmdate( 'Y-m-d H:i:s' ) . ' UTC',
		];
		set_transient( $cache, $out, HOUR_IN_SECONDS );
		return $out;
	}

	/** Human summary of the usage record, for the admin screens. */
	public static function akismet_usage_label(): string {
		$u = self::akismet_usage();
		if ( 'unavailable' === $u['state'] ) {
			return 'no key configured';
		}
		if ( 'invalid' === $u['state'] ) {
			return 'key rejected by Akismet';
		}
		if ( 'ok' !== $u['state'] ) {
			return 'could not be read';
		}
		$limit = ( '' === $u['limit'] || 'none' === strtolower( $u['limit'] ) ) ? 'unlimited' : $u['limit'];
		$pct   = '' !== $u['percentage'] ? ' (' . rtrim( $u['percentage'], '%' ) . '%)' : '';
		return number_format_i18n( $u['usage'] ) . ' of ' . $limit . $pct;
	}

	// ---------------------------------------------------------------
	//  Escalation, offender memory, and evidence
	// ---------------------------------------------------------------

	/**
	 * Record that this address has been blocked, and return how many times it
	 * has been blocked in the memory window (this block included).
	 *
	 * Kept in a bounded option rather than a transient, deliberately: the
	 * whole point is that the count must OUTLIVE the block, or a returning
	 * attacker would reset to the bottom rung every time.
	 */
	private static function register_offence( string $ip ): int {
		return self::register_offence_in( self::OFFENDERS_OPTION, $ip );
	}

	/**
	 * How many times this range has been blocked inside the 14-day memory.
	 * Kept in its own bounded option, separate from the per-address store, so a
	 * flood of single addresses cannot evict the range history and vice versa.
	 */
	private static function register_network_offence( string $net ): int {
		return self::register_offence_in( self::NET_OFFENDERS_OPTION, $net );
	}

	/**
	 * Shared offence counter. Kept in a bounded option rather than a transient,
	 * deliberately: the count must OUTLIVE the block, or a returning attacker
	 * would reset to the bottom rung every time.
	 */
	private static function register_offence_in( string $option, string $key ): int {
		$rec = get_option( $option, [] );
		if ( ! is_array( $rec ) ) {
			$rec = [];
		}
		$now    = time();
		$cutoff = $now - self::OFFENDER_TTL;

		// Prune expired entries before counting.
		foreach ( $rec as $k => $v ) {
			if ( ( (int) ( $v['last'] ?? 0 ) ) < $cutoff ) {
				unset( $rec[ $k ] );
			}
		}

		$entry          = $rec[ $key ] ?? [ 'n' => 0, 'first' => $now ];
		$entry['n']     = (int) ( $entry['n'] ?? 0 ) + 1;
		$entry['last']  = $now;
		$entry['first'] = (int) ( $entry['first'] ?? $now );
		$rec[ $key ]    = $entry;

		// Bound the store: keep the most recently active offenders.
		if ( count( $rec ) > self::OFFENDERS_MAX ) {
			uasort( $rec, static function ( array $a, array $b ): int {
				return (int) ( $b['last'] ?? 0 ) <=> (int) ( $a['last'] ?? 0 );
			} );
			$rec = array_slice( $rec, 0, self::OFFENDERS_MAX, true );
		}

		update_option( $option, $rec, false );
		return (int) $entry['n'];
	}

	/**
	 * How many distinct usernames this address has failed against in the
	 * current window. Tracked as a bounded set on a transient, so it expires
	 * with the window and cannot grow without bound.
	 */
	private static function record_username( string $ip, string $username ): int {
		$username = strtolower( trim( $username ) );
		if ( '' === $username ) {
			return 0;
		}
		$key  = 'wps_lu_' . md5( $ip );
		$set  = get_transient( $key );
		if ( ! is_array( $set ) ) {
			$set = [];
		}
		if ( ! isset( $set[ $username ] ) && count( $set ) < 40 ) {
			$set[ $username ] = 1;
			set_transient( $key, $set, self::WINDOW );
		}
		return count( $set );
	}

	private static function distinct_bad_usernames( string $ip ): int {
		$set = get_transient( 'wps_lu_' . md5( $ip ) );
		return is_array( $set ) ? count( $set ) : 0;
	}

	/** A duration in words, for the block reason and the event log. */
	private static function human_duration( int $seconds ): string {
		if ( $seconds >= 86400 ) {
			$d = (int) round( $seconds / 86400 );
			return $d . ' day' . ( $d === 1 ? '' : 's' );
		}
		if ( $seconds >= 3600 ) {
			$h = (int) round( $seconds / 3600 );
			return $h . ' hour' . ( $h === 1 ? '' : 's' );
		}
		return max( 1, (int) round( $seconds / 60 ) ) . ' min';
	}

	// ---------------------------------------------------------------
	//  Reporting confirmed attackers back to Akismet
	// ---------------------------------------------------------------

	/**
	 * 1.4.26: report a confirmed-bad address to Akismet's submit-spam.
	 *
	 * Everything Akismet learns is shared across every site that queries it,
	 * so this contributes to a global corpus - which is the good version, and
	 * also why it is dangerous. A wrongly-reported address has its reputation
	 * degraded everywhere, and submit-ham only walks that back slowly. So this
	 * fires ONLY on conclusive local evidence, never on an Akismet verdict,
	 * and never on a plain N-failures-on-one-real-username block, which is the
	 * mistyped-password case.
	 *
	 * Opt-in, off by default, reported once per address, and always after the
	 * block is already recorded - never on the login path.
	 */
	private static function maybe_report_spam( string $ip, string $username, int $distinct, int $offence ): void {
		if ( ! self::spam_reporting_enabled() ) {
			return;
		}
		$conclusive = $distinct >= self::MULTIUSER_FLOOR
			|| ( $offence >= 2 )
			|| self::is_bot_username( $username );
		// 1.4.68: with "report every blocked address" on (the operator's
		// instruction), a first-offence single-username block is reported too -
		// the case this used to hold back as a possible mistyped password. The
		// infrastructure guard and the once-per-address limit inside
		// report_single_attacker() still apply, so this can neither feed a CDN
		// edge into the shared corpus nor submit the same address twice.
		if ( ! $conclusive && ! self::report_all_blocks_enabled() ) {
			return;
		}
		$note = $conclusive
			? $distinct . ' distinct usernames, block #' . $offence
			: 'blocked after failed sign-ins, block #' . $offence;
		self::report_single_attacker( $ip, $username, $note );
	}

	/**
	 * Report one attacking address to Akismet's submit-spam, with the two
	 * safeguards that protect people who are not the attacker: never report an
	 * address that looks like shared infrastructure (a CDN edge, a proxy, a
	 * private range), and never report the same address twice. Shared by the
	 * automatic per-address path, the range-member path, and internal callers;
	 * the manual operator button uses report_ip_manually(), which is trusted
	 * and skips the infrastructure guard.
	 */
	private static function report_single_attacker( string $ip, string $username, string $note ): void {
		if ( ! self::akismet_available() ) {
			return;
		}
		if ( self::ip_looks_like_infrastructure( $ip ) ) {
			if ( class_exists( 'WPS_Logger' ) ) {
				WPS_Logger::log_event(
					'akismet_spam_report_skipped',
					$ip . ' not auto-reported: address is in a known proxy or private range (report it manually if you are sure)',
					$ip
				);
			}
			return;
		}
		$seen = 'wps_reported_' . md5( $ip );
		if ( get_transient( $seen ) ) {
			return;
		}
		set_transient( $seen, 1, self::OFFENDER_TTL );

		$ok = self::submit_spam( $ip, $username, $note );
		self::note( 'spam_reports' );
		if ( class_exists( 'WPS_Logger' ) ) {
			WPS_Logger::log_event(
				'akismet_spam_reported',
				$ip . ' reported to Akismet as spam (' . $note . ')' . ( $ok ? '' : ' [submission failed]' ),
				$ip
			);
		}
	}

	/**
	 * 1.4.68: whether to report every blocked address, not only the
	 * conclusive ones. On by default at the operator's instruction; the
	 * infrastructure and once-per-address safeguards are not affected by it.
	 */
	public static function report_all_blocks_enabled(): bool {
		$s = get_option( WPS_OPTION, [] );
		return ! is_array( $s ) || ( $s['akismet_report_all_blocks'] ?? '1' ) !== '0';
	}

	/**
	 * Shared entry for the OTHER guards to contribute a caught address to
	 * Akismet: malware-upload blocking (WPS_Blocker) and external-post-write
	 * blocking (WPS_Post_Guard). These are conclusive abuse — a malware upload
	 * or a REST post-injection attempt is nothing like a mistyped password — so
	 * they report whenever reporting is enabled, without needing the aggressive
	 * "report every blocked address" toggle. Every third-party safeguard still
	 * applies through report_single_attacker(): never a CDN/proxy/private
	 * address, never a range (this takes one address), and once per address.
	 */
	public static function report_attacker_ip( string $ip, string $note ): void {
		if ( '' === $ip || ! self::spam_reporting_enabled() ) {
			return;
		}
		self::report_single_attacker( $ip, '', $note );
	}

	/**
	 * The submit-spam call itself, shared by the automatic and manual paths.
	 *
	 * Uses Akismet::http_post() to the submit-spam endpoint, the same route
	 * Akismet's own spam reporting takes. Fails into false rather than
	 * throwing, so neither caller has to guard it.
	 */
	private static function submit_spam( string $ip, string $username, string $note ): bool {
		try {
			if ( ! class_exists( 'Akismet' )
				|| ! method_exists( 'Akismet', 'http_post' )
				|| ! method_exists( 'Akismet', 'build_query' )
				|| ! method_exists( 'Akismet', 'get_api_key' ) ) {
				return false;
			}
			$key = (string) Akismet::get_api_key();
			if ( '' === $key ) {
				return false;
			}
			$body = [
				'blog'            => get_option( 'home' ),
				'user_ip'         => $ip,
				'user_agent'      => (string) ( $_SERVER['HTTP_USER_AGENT'] ?? '' ),
				'comment_type'    => 'wps-login-attempt',
				'comment_author'  => self::safe( $username ),
				'comment_content' => 'Automated WordPress login attack blocked by WP Perf Shield: ' . $note . '.',
			];
			Akismet::http_post( Akismet::build_query( $body ), 'submit-spam' );
			return true;
		} catch ( \Throwable $t ) {
			return false;
		}
	}

	public static function spam_reporting_enabled(): bool {
		$s = get_option( WPS_OPTION, [] );
		// 1.4.27: on by default, at the operator's instruction and against the
		// recommendation recorded in doc/upgrading.md. The proxy guard below
		// is what makes that defensible for sites this plugin also ships to,
		// where REMOTE_ADDR may be a CDN's address rather than the visitor's.
		return ! is_array( $s ) || ( $s['login_report_spam'] ?? '1' ) !== '0';
	}

	/**
	 * 1.4.27: refuse to auto-report when the client address looks like shared
	 * infrastructure rather than an attacker.
	 *
	 * Auto-reporting on by default is only safe if it cannot feed a CDN or
	 * proxy address into Akismet's shared corpus. On a site behind Cloudflare
	 * without the real IP restored, REMOTE_ADDR is Cloudflare's edge, and
	 * reporting it would flag Cloudflare as a spam source for every site that
	 * queries Akismet. So automatic reporting stands down when the address
	 * falls in a known proxy or private range; a human using the manual button
	 * is trusted to have looked, and is not subject to this guard.
	 *
	 * The ranges are the published Cloudflare networks plus RFC1918 and
	 * loopback/link-local, which should never appear as a real remote client.
	 */
	public static function ip_looks_like_infrastructure( string $ip ): bool {
		if ( '' === $ip ) {
			return true;
		}
		$cidrs = [
			// Private / loopback / link-local - never a legitimate public client.
			'10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8',
			'169.254.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10',
			// Cloudflare IPv4 (published ranges).
			'173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
			'141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
			'197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
			'104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
			// Cloudflare IPv6.
			'2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
			'2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
		];
		foreach ( $cidrs as $cidr ) {
			if ( self::ip_in_cidr( $ip, $cidr ) ) {
				return true;
			}
		}
		return false;
	}

	/** CIDR membership for both address families, via packed bytes. */
	private static function ip_in_cidr( string $ip, string $cidr ): bool {
		if ( false === strpos( $cidr, '/' ) ) {
			return false;
		}
		[ $subnet, $bits ] = explode( '/', $cidr, 2 );
		$bits = (int) $bits;

		$ip_bin  = @inet_pton( $ip );
		$net_bin = @inet_pton( $subnet );
		if ( false === $ip_bin || false === $net_bin || strlen( $ip_bin ) !== strlen( $net_bin ) ) {
			return false; // different families, or unparseable
		}

		$bytes = intdiv( $bits, 8 );
		$rem   = $bits % 8;
		if ( $bytes > 0 && 0 !== substr_compare( $ip_bin, $net_bin, 0, $bytes ) ) {
			return false;
		}
		if ( 0 === $rem ) {
			return true;
		}
		$mask = ~( ( 1 << ( 8 - $rem ) ) - 1 ) & 0xFF;
		return ( ord( $ip_bin[ $bytes ] ) & $mask ) === ( ord( $net_bin[ $bytes ] ) & $mask );
	}

	/**
	 * 1.4.27: manual, operator-initiated report of an already-blocked address.
	 *
	 * This is the trusted path. A human has looked at the block list and
	 * chosen this address, so the conclusive-evidence gate and the
	 * infrastructure guard - both of which exist to make AUTOMATIC reporting
	 * safe - do not apply. What does apply: an active key, and reporting each
	 * address at most once.
	 *
	 * @return string One of 'reported', 'already', 'no-key', 'failed'.
	 */
	public static function report_ip_manually( string $ip, string $username = '' ): string {
		$ip = trim( $ip );
		if ( '' === $ip || false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return 'failed';
		}
		if ( ! self::akismet_available() ) {
			return 'no-key';
		}
		$seen = 'wps_reported_' . md5( $ip );
		if ( get_transient( $seen ) ) {
			return 'already';
		}
		$ok = self::submit_spam( $ip, $username, 'reported manually by the operator from the block list' );
		if ( $ok ) {
			set_transient( $seen, 1, self::OFFENDER_TTL );
			self::note( 'spam_reports' );
			if ( class_exists( 'WPS_Logger' ) ) {
				WPS_Logger::log_event( 'akismet_spam_reported', $ip . ' reported to Akismet as spam (manual)', $ip );
			}
			return 'reported';
		}
		return 'failed';
	}

	// ---------------------------------------------------------------
	//  Permanent sign-in denylist
	// ---------------------------------------------------------------

	/** @return array<string, array{at:int, reason:string, user:string}> */
	public static function permanent_blocks(): array {
		$list = get_option( self::PERMANENT_OPTION, [] );
		return is_array( $list ) ? $list : [];
	}

	public static function is_permanently_blocked( string $ip ): bool {
		if ( '' === $ip ) {
			return false;
		}
		$list = self::permanent_blocks();
		if ( isset( $list[ $ip ] ) ) {
			return true;
		}
		// 1.4.68: permanent entries may be CIDR ranges (manual operator bans).
		// Exact addresses match above in O(1); only range entries are walked,
		// and the list is capped, so the per-login cost stays bounded.
		if ( false !== filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			foreach ( $list as $key => $meta ) {
				if ( is_string( $key ) && false !== strpos( $key, '/' ) && self::ip_in_cidr( $ip, $key ) ) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * True if a manual CIDR ban would catch the operator: any allowlisted or
	 * recently-seen administrator address falling inside the range. Unlike
	 * network_is_protected(), which only compares whole /24 strings, this tests
	 * real containment, so an over-broad range (a /16 holding an admin address)
	 * is refused.
	 */
	private static function range_holds_protected( string $cidr ): bool {
		foreach ( self::allowlist() as $safe ) {
			if ( self::ip_in_cidr( $safe, $cidr ) ) {
				return true;
			}
		}
		$known = get_option( self::ADMIN_IPS_OPTION, [] );
		if ( is_array( $known ) ) {
			$cutoff = time() - self::ADMIN_IP_TTL;
			foreach ( $known as $safe => $seen ) {
				if ( (int) $seen > $cutoff && self::ip_in_cidr( (string) $safe, $cidr ) ) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Add an address to the permanent denylist.
	 *
	 * Refuses to add a protected address, so the operator's own network can
	 * never end up here even if something unexpected calls this.
	 */
	public static function block_permanently( string $ip, string $reason, string $username = '' ): bool {
		if ( '' === $ip || false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}
		if ( self::is_protected_ip( $ip ) ) {
			return false;
		}

		$list = self::permanent_blocks();
		if ( isset( $list[ $ip ] ) ) {
			return true; // already there; nothing to record twice
		}

		$list[ $ip ] = [
			'at'     => time(),
			'reason' => substr( $reason, 0, 240 ),
			'user'   => self::safe( $username ),
		];

		// Bounded. Oldest first, because a recent attacker is likelier to
		// still be active than one from a year ago.
		if ( count( $list ) > self::PERMANENT_MAX ) {
			uasort( $list, static function ( array $a, array $b ): int {
				return (int) ( $a['at'] ?? 0 ) <=> (int) ( $b['at'] ?? 0 );
			} );
			$list = array_slice( $list, -self::PERMANENT_MAX, null, true );
		}

		update_option( self::PERMANENT_OPTION, $list, false );
		self::note( 'permanent_blocks' );

		if ( class_exists( 'WPS_Logger' ) ) {
			WPS_Logger::log_event(
				'ip_blocked_permanently',
				$ip . ' permanently blocked from signing in: ' . $reason
					. ' (site access is unaffected; remove it from Diagnostics if this was wrong)',
				$ip
			);
		}
		if ( class_exists( 'WPS_EDR' ) && method_exists( 'WPS_EDR', 'record' ) ) {
			WPS_EDR::record(
				'login_blocked_permanently',
				[
					'object_type' => 'ip',
					'object_name' => $ip,
					'severity'    => 'high',
					'notes'       => $reason,
				]
			);
		}
		return true;
	}

	/**
	 * 1.4.68: permanently ban a whole range, the operator's manual decision.
	 *
	 * The automatic range guard tops out at seven days on purpose; this is the
	 * deliberate, human forever-ban for a range that has proven itself hostile.
	 * It refuses a range that holds the operator (allowlist or a remembered
	 * administrator address), and refuses a dangerously broad prefix - a manual
	 * ban should be a subnet, not a swathe of the internet.
	 *
	 * @return string One of 'blocked', 'exists', 'protected', 'too-broad', 'invalid'.
	 */
	public static function block_permanently_cidr( string $cidr, string $reason, string $username = '' ): string {
		$cidr = trim( $cidr );
		if ( '' === $cidr || false === strpos( $cidr, '/' ) ) {
			return 'invalid';
		}
		[ $subnet, $bits ] = array_pad( explode( '/', $cidr, 2 ), 2, '' );
		if ( false === filter_var( $subnet, FILTER_VALIDATE_IP ) || '' === $bits || ! ctype_digit( (string) $bits ) ) {
			return 'invalid';
		}
		$bits  = (int) $bits;
		$is_v6 = false !== strpos( $subnet, ':' );
		$max   = $is_v6 ? 128 : 32;
		$min   = $is_v6 ? 32 : 16; // refuse anything broader than a /16 (v4) or /32 (v6)
		if ( $bits < $min || $bits > $max ) {
			return 'too-broad';
		}
		if ( self::range_holds_protected( $cidr ) ) {
			return 'protected';
		}

		$list = self::permanent_blocks();
		if ( isset( $list[ $cidr ] ) ) {
			return 'exists';
		}
		$list[ $cidr ] = [
			'at'     => time(),
			'reason' => substr( $reason, 0, 240 ),
			'user'   => self::safe( $username ),
			'cidr'   => true,
		];
		if ( count( $list ) > self::PERMANENT_MAX ) {
			uasort( $list, static function ( array $a, array $b ): int {
				return (int) ( $a['at'] ?? 0 ) <=> (int) ( $b['at'] ?? 0 );
			} );
			$list = array_slice( $list, -self::PERMANENT_MAX, null, true );
		}
		update_option( self::PERMANENT_OPTION, $list, false );
		self::note( 'permanent_blocks' );

		if ( class_exists( 'WPS_Logger' ) ) {
			WPS_Logger::log_event(
				'range_blocked_permanently',
				$cidr . ' permanently blocked from signing in by the operator: ' . $reason
					. ' (site access is unaffected; remove it from Diagnostics if this was wrong)',
				$subnet
			);
		}
		if ( class_exists( 'WPS_EDR' ) && method_exists( 'WPS_EDR', 'record' ) ) {
			WPS_EDR::record(
				'login_blocked_permanently',
				[
					'object_type' => 'network',
					'object_name' => $cidr,
					'severity'    => 'high',
					'notes'       => 'permanent range ban: ' . $reason,
				]
			);
		}
		return 'blocked';
	}

	/** Remove an address or range from the permanent denylist. */
	public static function unblock_permanently( string $ip ): bool {
		$list = self::permanent_blocks();
		if ( ! isset( $list[ $ip ] ) ) {
			return false;
		}
		unset( $list[ $ip ] );
		update_option( self::PERMANENT_OPTION, $list, false );
		if ( class_exists( 'WPS_Logger' ) ) {
			WPS_Logger::log_event( 'ip_permanent_block_removed', $ip . ' removed from the permanent sign-in denylist by the operator', $ip );
		}
		return true;
	}

	// ---------------------------------------------------------------
	//  Operator protection
	// ---------------------------------------------------------------

	/**
	 * Addresses that must never be blocked: the current administrator, any
	 * address an administrator has signed in from recently, and the operator's
	 * own allowlist.
	 */
	public static function is_protected_ip( string $ip ): bool {
		if ( '' === $ip ) {
			return true;
		}
		if ( function_exists( 'is_user_logged_in' ) && is_user_logged_in()
			&& function_exists( 'current_user_can' ) && current_user_can( 'manage_options' ) ) {
			return true;
		}
		if ( in_array( $ip, self::allowlist(), true ) ) {
			return true;
		}
		$known = get_option( self::ADMIN_IPS_OPTION, [] );
		if ( is_array( $known ) && isset( $known[ $ip ] ) ) {
			if ( (int) $known[ $ip ] > ( time() - self::ADMIN_IP_TTL ) ) {
				return true;
			}
		}
		return false;
	}

	/** @return array<int, string> */
	private static function allowlist(): array {
		$s   = get_option( WPS_OPTION, [] );
		$raw = is_array( $s ) ? (string) ( $s['login_ip_allowlist'] ?? '' ) : '';
		if ( '' === trim( $raw ) ) {
			return [];
		}
		$out = [];
		foreach ( preg_split( '/[\r\n,\s]+/', $raw ) ?: [] as $line ) {
			$ip = filter_var( trim( (string) $line ), FILTER_VALIDATE_IP );
			if ( false !== $ip ) {
				$out[] = $ip;
			}
		}
		return $out;
	}

	private static function remember_admin_ip( string $ip ): void {
		$known = get_option( self::ADMIN_IPS_OPTION, [] );
		if ( ! is_array( $known ) ) {
			$known = [];
		}
		$known[ $ip ] = time();

		$cutoff = time() - self::ADMIN_IP_TTL;
		foreach ( $known as $k => $seen ) {
			if ( (int) $seen < $cutoff ) {
				unset( $known[ $k ] );
			}
		}
		if ( count( $known ) > self::ADMIN_IPS_MAX ) {
			arsort( $known );
			$known = array_slice( $known, 0, self::ADMIN_IPS_MAX, true );
		}
		update_option( self::ADMIN_IPS_OPTION, $known, false );
	}

	// ---------------------------------------------------------------
	//  Network-level counting
	// ---------------------------------------------------------------

	/**
	 * The range an address belongs to: /24 for IPv4, /64 for IPv6.
	 *
	 * Those are the units an attacker actually rents. Anything narrower does
	 * not catch rotation; anything wider is indiscriminate.
	 *
	 * Returns '' for anything unparseable, which disables network counting
	 * for that request rather than guessing.
	 */
	public static function network_of( string $ip ): string {
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			$parts = explode( '.', $ip );
			if ( 4 !== count( $parts ) ) {
				return '';
			}
			return $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.0/24';
		}
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			$packed = @inet_pton( $ip );
			if ( false === $packed || strlen( $packed ) < 8 ) {
				return '';
			}
			// First 64 bits, remainder zeroed.
			$prefix = substr( $packed, 0, 8 ) . str_repeat( "\0", 8 );
			$text   = @inet_ntop( $prefix );
			return false === $text ? '' : $text . '/64';
		}
		return '';
	}

	/**
	 * Count a failure against the address's range, and report which rule (if
	 * any) the range has now tripped: '' for none, 'count' for a burst within
	 * the short window, 'rotation' for distinct-address rotation across the long
	 * window.
	 *
	 * Failures are stored as timestamped events and pruned by age on every call,
	 * so the window is a true rolling window rather than a TTL that a slow
	 * attacker can keep alive or step just outside. Distinct addresses are what
	 * separate rotation from one noisy address, and one noisy address is already
	 * handled by the per-address counter.
	 */
	private static function note_network_failure( string $ip ): string {
		$net = self::network_of( $ip );
		if ( '' === $net ) {
			return '';
		}
		$key = 'wps_lfn_' . md5( $net );
		$rec = get_transient( $key );
		if ( ! is_array( $rec ) || ! isset( $rec['events'] ) || ! is_array( $rec['events'] ) ) {
			$rec = [ 'events' => [] ];
		}
		$now = time();

		$rec['events'][] = [ 't' => $now, 'ip' => $ip ];
		if ( count( $rec['events'] ) > self::NET_EVENTS_MAX ) {
			$rec['events'] = array_slice( $rec['events'], -self::NET_EVENTS_MAX );
		}

		// Prune anything older than the long window; everything is judged from
		// what survives.
		$cutoff_long  = $now - self::NET_ROTATION_WINDOW;
		$cutoff_short = $now - self::NET_WINDOW;
		$events       = [];
		foreach ( $rec['events'] as $e ) {
			if ( is_array( $e ) && (int) ( $e['t'] ?? 0 ) >= $cutoff_long ) {
				$events[] = $e;
			}
		}
		$rec['events'] = $events;
		set_transient( $key, $rec, self::NET_ROTATION_WINDOW );

		$distinct_long  = [];
		$short_n        = 0;
		$distinct_short = [];
		foreach ( $events as $e ) {
			$eip = (string) ( $e['ip'] ?? '' );
			$et  = (int) ( $e['t'] ?? 0 );
			if ( '' === $eip ) {
				continue;
			}
			$distinct_long[ $eip ] = true;
			if ( $et >= $cutoff_short ) {
				++$short_n;
				$distinct_short[ $eip ] = true;
			}
		}

		// Rotation: enough distinct addresses in one range over the long window
		// is, on its own, the signature the per-address counter cannot see. This
		// is what low-and-slow /24 rotation trips.
		if ( count( $distinct_long ) >= self::NET_DISTINCT_TRIGGER ) {
			return 'rotation';
		}
		// Burst: the original rate rule, now measured over a true rolling window.
		if ( $short_n >= self::NET_THRESHOLD && count( $distinct_short ) >= self::NET_MIN_IPS ) {
			return 'count';
		}
		return '';
	}

	/**
	 * Block a range, but only once it is clear no one we know is inside it.
	 *
	 * The protected-address check is the whole safety argument. An operator
	 * whose own network starts failing sign-ins must not be able to lock
	 * themselves out of their own site from the other side of the office.
	 */
	private static function block_network( string $ip, string $username, string $scope = 'count' ): void {
		$net = self::network_of( $ip );
		if ( '' === $net || self::network_is_protected( $net ) ) {
			return;
		}
		$key = 'wps_lfn_' . md5( $net );
		$rec = get_transient( $key );
		$events = ( is_array( $rec ) && is_array( $rec['events'] ?? null ) ) ? $rec['events'] : [];
		$n = count( $events );
		$distinct = [];
		foreach ( $events as $e ) {
			$eip = (string) ( $e['ip'] ?? '' );
			if ( '' !== $eip ) {
				$distinct[ $eip ] = true;
			}
		}
		$c = count( $distinct );
		delete_transient( $key );

		self::note( 'blocks' );
		self::note( 'network_blocks' );

		// 1.4.67: repeat ranges climb the ladder. The rotation/burst base is the
		// floor for a first offence; each return inside the 14-day memory raises
		// it, up to seven days.
		$offence  = self::register_network_offence( $net );
		$rotation = ( 'rotation' === $scope );
		$base     = $rotation ? self::NET_BLOCK_ROTATION : self::NET_BLOCK;
		$rung     = max( 0, min( $offence - 1, count( self::NET_LADDER ) - 1 ) );
		$duration = max( $base, self::NET_LADDER[ $rung ] );

		$window_min = (int) ( ( $rotation ? self::NET_ROTATION_WINDOW : self::NET_WINDOW ) / 60 );
		$reason     = $rotation
			? sprintf(
				'sign-in failures from %d distinct addresses in %s within %d minutes - subnet rotation paced to slip the per-address and burst rules',
				$c,
				$net,
				$window_min
			)
			: sprintf(
				'%d failed sign-ins from %d addresses in %s within %d minutes - rotation across a range, not a single address',
				$n,
				$c,
				$net,
				$window_min
			);
		if ( $offence > 1 ) {
			$reason .= sprintf( '; repeat range offender (block #%d), held %s', $offence, self::human_duration( $duration ) );
		}

		if ( class_exists( 'WPS_Blocker' ) ) {
			WPS_Blocker::record_ip_block(
				$net,
				$reason,
				$duration,
				[
					'last_user'       => self::safe( $username ),
					'source'          => 'login-guard-network',
					'duration_source' => $offence > 1 ? 'network-escalation' : ( $rotation ? 'network-rotation-distinct' : 'network-rotation' ),
					'offence'         => $offence,
					'scope'           => 'network',
				]
			);
		}
		if ( class_exists( 'WPS_EDR' ) && method_exists( 'WPS_EDR', 'record' ) ) {
			WPS_EDR::record(
				'login_network_blocked',
				[
					'object_type' => 'network',
					'object_name' => $net,
					'severity'    => 'high',
					'notes'       => $reason . '; sign-in blocked for this range for ' . (int) ( $duration / 60 ) . ' minutes',
				]
			);
		}

		// 1.4.68: contribute the individual addresses that actually attacked
		// from this range - never the CIDR itself, which would flag innocent
		// neighbours in a shared range. Each member still passes the
		// infrastructure guard and the once-per-address limit, and the count is
		// capped so one wide sweep cannot become a flood of submissions.
		if ( self::spam_reporting_enabled() && self::report_all_blocks_enabled() ) {
			$reported = 0;
			foreach ( array_keys( $distinct ) as $member ) {
				if ( $reported >= 20 ) {
					break;
				}
				self::report_single_attacker( (string) $member, $username, 'address in blocked rotating range ' . $net );
				++$reported;
			}
		}
	}

	/**
	 * A range containing any address we trust is never blocked.
	 *
	 * Checked against the allowlist and every remembered administrator
	 * address, not just the current one, so an operator on a dynamic address
	 * within their own ISP range stays safe.
	 */
	private static function network_is_protected( string $net ): bool {
		foreach ( self::allowlist() as $safe ) {
			if ( self::network_of( $safe ) === $net ) {
				return true;
			}
		}
		$known = get_option( self::ADMIN_IPS_OPTION, [] );
		if ( is_array( $known ) ) {
			$cutoff = time() - self::ADMIN_IP_TTL;
			foreach ( $known as $safe => $seen ) {
				if ( (int) $seen > $cutoff && self::network_of( (string) $safe ) === $net ) {
					return true;
				}
			}
		}
		return false;
	}

	/** Seconds-since-epoch this address's range is blocked until, or 0. */
	private static function network_blocked_until( string $ip ): int {
		$net = self::network_of( $ip );
		if ( '' === $net || ! class_exists( 'WPS_Blocker' ) ) {
			return 0;
		}
		$blocked = WPS_Blocker::get_blocked_ips();
		if ( empty( $blocked[ $net ] ) || ! is_array( $blocked[ $net ] ) ) {
			return 0;
		}
		$expires = (int) ( $blocked[ $net ]['expires'] ?? 0 );
		return $expires > time() ? $expires : 0;
	}

	// ---------------------------------------------------------------
	//  Activity record
	// ---------------------------------------------------------------

	/** Increment one counter, rolling the record over at midnight UTC. */
	private static function note( string $field ): void {
		$s = get_option( self::STATS_OPTION, [] );
		if ( ! is_array( $s ) ) {
			$s = [];
		}
		$today = gmdate( 'Y-m-d' );
		if ( ( $s['day'] ?? '' ) !== $today ) {
			// 1.4.32: carry EVERY counter into history, not just attempts and
			// blocks. The others were being recorded all day and silently
			// discarded at midnight, so a seven-day figure for them was
			// impossible however the screen asked for it.
			$carried = [];
			foreach ( self::COUNTERS as $c ) {
				$carried[ $c ] = (int) ( $s[ $c ] ?? 0 );
			}
			$s = [
				'day'     => $today,
				'history' => array_slice(
					array_merge(
						is_array( $s['history'] ?? null ) ? $s['history'] : [],
						isset( $s['day'] ) ? [ $s['day'] => $carried ] : []
					),
					-6,
					null,
					true
				),
			];
		}
		$s[ $field ] = (int) ( $s[ $field ] ?? 0 ) + 1;
		$s['last']   = gmdate( 'Y-m-d H:i:s' ) . ' UTC';
		update_option( self::STATS_OPTION, $s, false );
	}

	/**
	 * Activity summary for the admin screens.
	 *
	 * @return array<string, mixed>
	 */
	public static function stats(): array {
		$s = get_option( self::STATS_OPTION, [] );
		if ( ! is_array( $s ) ) {
			$s = [];
		}

		$out = [];
		foreach ( self::COUNTERS as $c ) {
			$today = (int) ( $s[ $c ] ?? 0 );
			$week  = $today;
			foreach ( (array) ( $s['history'] ?? [] ) as $row ) {
				$week += (int) ( $row[ $c ] ?? 0 );
			}
			$out[ 'today_' . $c ] = $today;
			$out[ 'week_' . $c ]  = $week;
			// Bare key kept for the Akismet verdict breakdown, which reads
			// lifetime-ish totals rather than a window.
			$out[ $c ] = $today;
		}

		// Names the rest of the plugin already uses.
		$out['today_attempts'] = $out['today_attempts'] ?? 0;
		$out['today_blocks']   = $out['today_blocks'] ?? 0;
		$out['week_attempts']  = $out['week_attempts'] ?? 0;
		$out['week_blocks']    = $out['week_blocks'] ?? 0;

		// Current state, not a running total: the permanent list is a fact
		// about the site right now, and the count of it is more useful than
		// how many were ever added.
		$out['permanent_total'] = count( self::permanent_blocks() );
		$out['last']            = (string) ( $s['last'] ?? '' );

		return $out;
	}

	/**
	 * 1.4.18: ask Akismet to confirm the key, on demand.
	 *
	 * The point of this is that an operator should not have to wait for an
	 * attack to discover whether the integration works. Returns one of
	 * 'valid', 'invalid', 'failed', or 'unavailable'.
	 */
	public static function verify_akismet(): string {
		if ( ! class_exists( 'Akismet' ) || ! method_exists( 'Akismet', 'verify_key' ) || ! method_exists( 'Akismet', 'get_api_key' ) ) {
			return 'unavailable';
		}
		try {
			$key = (string) Akismet::get_api_key();
			if ( '' === $key ) {
				return 'unavailable';
			}
			$r = Akismet::verify_key( $key );
		} catch ( \Throwable $t ) {
			return 'failed';
		}
		return in_array( $r, [ 'valid', 'invalid', 'failed' ], true ) ? (string) $r : 'failed';
	}

	// ---------------------------------------------------------------
	//  Helpers
	// ---------------------------------------------------------------

	private static function is_bot_username( string $username ): bool {
		$u = strtolower( trim( $username ) );
		if ( '' === $u || ! in_array( $u, self::bot_usernames(), true ) ) {
			return false;
		}
		// Only when there is no such account here. A site that genuinely has
		// a user called admin gets ordinary counting instead.
		if ( function_exists( 'username_exists' ) && username_exists( $username ) ) {
			return false;
		}
		if ( function_exists( 'email_exists' ) && is_email( $username ) && email_exists( $username ) ) {
			return false;
		}
		return true;
	}

	/** Seconds-since-epoch this address is blocked until, or 0. */
	private static function blocked_until( string $ip ): int {
		if ( ! class_exists( 'WPS_Blocker' ) ) {
			return 0;
		}
		$blocked = WPS_Blocker::get_blocked_ips();
		if ( empty( $blocked[ $ip ] ) || ! is_array( $blocked[ $ip ] ) ) {
			return 0;
		}
		$expires = (int) ( $blocked[ $ip ]['expires'] ?? 0 );
		return $expires > time() ? $expires : 0;
	}

	private static function counter_key( string $ip ): string {
		return 'wps_lf_' . md5( $ip );
	}

	private static function ip(): string {
		if ( class_exists( 'WPS_Blocker' ) && method_exists( 'WPS_Blocker', 'client_ip' ) ) {
			return WPS_Blocker::client_ip();
		}
		$ip = filter_var( (string) ( $_SERVER['REMOTE_ADDR'] ?? '' ), FILTER_VALIDATE_IP );
		return false === $ip ? '' : (string) $ip;
	}

	private static function safe( string $v ): string {
		return substr( preg_replace( '/[^\P{C}]+/u', '', wp_strip_all_tags( $v ) ) ?? '', 0, 120 );
	}
}
