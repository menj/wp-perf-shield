<?php
/**
 * Remediation policy (1.4.88).
 *
 * Written after this plugin took a production site down twice by quarantining
 * legitimate software - WP-Optimize's cache classes among them - leaving the
 * install unable to boot. The operator marked the findings safe. The next scan
 * quarantined them again.
 *
 * The cause was not a single bad detector. It was that DETECTION AUTHORISED
 * REMOVAL DIRECTLY: any check could set `auto_delete` on a finding and the
 * remediator acted on it, with nothing in between able to say no. There was no
 * operator veto in the codebase at all, so there was nothing the operator could
 * do that a later scan would respect. Broadening heuristics (which recent
 * releases did, repeatedly) therefore widened the blast radius with no
 * corresponding brake.
 *
 * This class is that brake. Every destructive action must ask it first, and it
 * answers on the basis of persistent operator trust state rather than on
 * whatever the current scan happens to believe.
 *
 * Three rules that are not negotiable, because each maps to a way the site was
 * actually broken:
 *
 *   1. SAFE IS A VETO, NOT A DISPLAY FILTER. If a target is Safe, automatic
 *      remediation is denied. Not deprioritised, not skipped-unless-critical:
 *      denied. A detector that is certain must ask the operator.
 *   2. FAIL CLOSED. If the trust store cannot be read, remediation is denied.
 *      An unknown trust state is not permission; it is a reason to stop.
 *   3. HEURISTICS MAY NOT REMOVE PACKAGES OR CORE. A signature match on a file
 *      is evidence about that file. A behavioural guess about a plugin is not
 *      grounds to delete the plugin, and nothing heuristic touches WordPress
 *      core.
 *
 * Safe state lives in its own option and is never touched by scan cleanup,
 * finding expiry, or quarantine purging - the previous design would have lost
 * it on the next cleanup even if it had existed.
 */

defined( 'ABSPATH' ) || exit;

final class WPS_Remediation_Policy {

	/** Persistent trust store. Deliberately separate from any scan record. */
	const SAFE_OPTION = 'wps_safe_targets';

	/** Circuit breaker state. */
	const BREAKER_OPTION = 'wps_remediation_breaker';

	/** Scopes an operator decision can carry. */
	const SCOPE_FILE   = 'file';
	const SCOPE_DIR    = 'directory';
	const SCOPE_PLUGIN = 'plugin';
	const SCOPE_THEME  = 'theme';

	/**
	 * Packages that ship legitimate code the behavioural checks have already
	 * misread once. These are not "ignore forever" entries: they downgrade
	 * automatic removal to a report for HEURISTIC findings only. A confirmed
	 * signature match inside one of them is still reported, and still
	 * removable by hand.
	 *
	 * Every entry here is a real false positive that caused or nearly caused an
	 * outage, not a guess about what might be safe.
	 */
	private const KNOWN_GOOD_PREFIXES = [
		'wp-content/plugins/performance-lab',
		'wp-content/plugins/wp-optimize',
		'wp-content/plugins/abstract-box',
		'wp-content/plugins/auto-justify-content',
	];

	/**
	 * Detectors whose findings rest on a match against known-malicious content
	 * - a signature, a hash, a catalogued sample - rather than on inference
	 * about behaviour.
	 *
	 * 1.4.89: this list is deliberately the CONFIRMED one, not the heuristic
	 * one. The previous release listed heuristic detectors instead and treated
	 * everything absent from that list as confirmed, which meant every detector
	 * added afterwards, and every one simply forgotten, was granted permission
	 * to delete WordPress core. That is how a genuine `wp-admin/setup-config.php`
	 * stayed removable: the credential-exfiltration check was not on the
	 * heuristic list, so the core protection never applied to it.
	 *
	 * An allowlist of things trusted to be certain fails safe when it is
	 * incomplete; a denylist of things known to be uncertain fails dangerous.
	 * Anything not named here is treated as inference, which is the correct
	 * default for a check whose confidence nobody has assessed.
	 */
	private const CONFIRMED_TYPES = [
		'Malicious plugin folder on disk',
		'Known malware upload',
		'Malware signature in theme file',
		'Malware signature in mu-plugin file',
		'Malware signature in cache directory PHP file',
	];

	/** True unless the finding comes from a confirmed-content match. */
	private static function is_heuristic( string $type ): bool {
		foreach ( self::CONFIRMED_TYPES as $confirmed ) {
			if ( $type === $confirmed || 0 === strpos( $type, $confirmed ) ) {
				return false;
			}
		}
		return true;
	}

	//  Identity 

	/**
	 * Canonical, site-relative identity for a target.
	 *
	 * A Safe decision is worthless if the next scan describes the same file
	 * differently, so every representation of one path must collapse to one
	 * string: absolute or relative, realpath or not, trailing or duplicated
	 * slashes, backslashes on Windows. Returns '' when no sane identity can be
	 * derived, which callers must treat as "cannot verify" rather than "fine".
	 */
	public static function identity( string $path ): string {
		$path = trim( $path );
		if ( '' === $path ) {
			return '';
		}
		$path = str_replace( '\\', '/', $path );

		// Resolve where the target still exists; fall back to lexical cleanup
		// so a Safe decision survives the file being temporarily absent.
		$real = @realpath( $path );
		if ( is_string( $real ) && '' !== $real ) {
			$path = str_replace( '\\', '/', $real );
		}

		$path = preg_replace( '#/+#', '/', $path );
		$path = (string) $path;

		// Reject traversal remnants outright rather than trying to fix them.
		if ( false !== strpos( $path, '/../' ) || substr( $path, -3 ) === '/..' ) {
			return '';
		}

		$root = defined( 'ABSPATH' ) ? str_replace( '\\', '/', rtrim( ABSPATH, '/\\' ) ) : '';
		if ( '' !== $root ) {
			$rroot = @realpath( $root );
			if ( is_string( $rroot ) && '' !== $rroot ) {
				$root = str_replace( '\\', '/', rtrim( $rroot, '/' ) );
			}
			if ( 0 === strpos( $path, $root . '/' ) ) {
				$path = substr( $path, strlen( $root ) + 1 );
			} elseif ( $path === $root ) {
				$path = '';
			}
		}

		return rtrim( $path, '/' );
	}

	//  Trust store 

	/** @return array<string, array<string, mixed>> */
	private static function safe_store(): array {
		$raw = get_option( self::SAFE_OPTION, [] );
		return is_array( $raw ) ? $raw : [];
	}

	/**
	 * Record an operator decision that a target is safe.
	 *
	 * @param string $path   Target path.
	 * @param string $scope  One of the SCOPE_* constants.
	 * @param string $reason Operator's stated reason (kept for the audit trail).
	 */
	public static function mark_safe( string $path, string $scope = self::SCOPE_FILE, string $reason = '' ): bool {
		$id = self::identity( $path );
		if ( '' === $id ) {
			return false;
		}
		$scope = in_array( $scope, [ self::SCOPE_FILE, self::SCOPE_DIR, self::SCOPE_PLUGIN, self::SCOPE_THEME ], true )
			? $scope
			: self::SCOPE_FILE;

		$store        = self::safe_store();
		$store[ $id ] = [
			'scope'  => $scope,
			'reason' => substr( $reason, 0, 240 ),
			'at'     => time(),
			'user'   => function_exists( 'wp_get_current_user' ) ? (string) ( wp_get_current_user()->user_login ?? '' ) : '',
		];
		update_option( self::SAFE_OPTION, $store, false );

		if ( class_exists( 'WPS_Logger' ) ) {
			WPS_Logger::log_event( 'safe_marked', $id . ' marked safe (' . $scope . ')' . ( '' !== $reason ? ': ' . $reason : '' ) );
		}
		return true;
	}

	/** Revoke a Safe decision. Only an explicit act removes trust. */
	public static function revoke_safe( string $path ): bool {
		$id    = self::identity( $path );
		$store = self::safe_store();
		if ( '' === $id || ! isset( $store[ $id ] ) ) {
			return false;
		}
		unset( $store[ $id ] );
		update_option( self::SAFE_OPTION, $store, false );
		if ( class_exists( 'WPS_Logger' ) ) {
			WPS_Logger::log_event( 'safe_revoked', $id . ' safe decision revoked by operator' );
		}
		return true;
	}

	/** @return array<string, array<string, mixed>> */
	public static function list_safe(): array {
		return self::safe_store();
	}

	/**
	 * Is this target covered by an operator Safe decision?
	 *
	 * Checks the target itself and every ancestor, so a directory- or
	 * package-scoped decision covers what is inside it. A file-scoped decision
	 * never broadens: it protects that path only.
	 *
	 * @return array{safe:bool, id:string, scope:string, reason:string}
	 */
	public static function safe_state( string $path ): array {
		$none = [ 'safe' => false, 'id' => '', 'scope' => '', 'reason' => '' ];
		$id   = self::identity( $path );
		if ( '' === $id ) {
			return $none;
		}
		$store = self::safe_store();

		if ( isset( $store[ $id ] ) ) {
			$e = $store[ $id ];
			return [ 'safe' => true, 'id' => $id, 'scope' => (string) ( $e['scope'] ?? self::SCOPE_FILE ), 'reason' => (string) ( $e['reason'] ?? '' ) ];
		}

		// Ancestors: a directory/plugin/theme decision covers descendants.
		$parts = explode( '/', $id );
		while ( count( $parts ) > 1 ) {
			array_pop( $parts );
			$anc = implode( '/', $parts );
			if ( '' === $anc || ! isset( $store[ $anc ] ) ) {
				continue;
			}
			$scope = (string) ( $store[ $anc ]['scope'] ?? self::SCOPE_FILE );
			if ( self::SCOPE_FILE === $scope ) {
				continue; // a file decision protects only that file
			}
			return [ 'safe' => true, 'id' => $anc, 'scope' => $scope, 'reason' => (string) ( $store[ $anc ]['reason'] ?? '' ) ];
		}

		return $none;
	}

	//  Circuit breaker 

	/** Is automatic remediation currently halted? */
	public static function breaker_tripped(): bool {
		$b = get_option( self::BREAKER_OPTION, [] );
		return is_array( $b ) && ! empty( $b['tripped'] );
	}

	/**
	 * Halt all automatic remediation. Called when the scanner tries to remove
	 * something the operator has approved - which can only happen through a
	 * defect, and a defect in this area destroys sites, so the correct response
	 * is to stop rather than to continue carefully.
	 */
	public static function trip_breaker( string $why ): void {
		update_option(
			self::BREAKER_OPTION,
			[ 'tripped' => 1, 'at' => time(), 'why' => substr( $why, 0, 300 ) ],
			false
		);
		if ( class_exists( 'WPS_Logger' ) ) {
			WPS_Logger::log_event( 'remediation_halted', 'automatic remediation halted: ' . $why );
			WPS_Logger::notify_admin(
				'WP Perf Shield halted automatic removal',
				"Automatic remediation has been stopped because: $why\n\n"
				. "Nothing further will be removed automatically until you clear this from Diagnostics. "
				. "Findings are still reported. This is a safety stop, not a failure of the scan."
			);
		}
	}

	/** Operator clears the halt after reviewing. */
	public static function reset_breaker(): void {
		delete_option( self::BREAKER_OPTION );
		if ( class_exists( 'WPS_Logger' ) ) {
			WPS_Logger::log_event( 'remediation_resumed', 'operator cleared the automatic-remediation halt' );
		}
	}

	//  The decision 

	/**
	 * May this finding be remediated automatically?
	 *
	 * @param array<string, mixed> $finding
	 * @return array{allowed:bool, reason:string, rule:string, trust:string}
	 */
	public static function decide( array $finding ): array {
		$target = (string) ( $finding['delete_path'] ?? '' );
		$type   = (string) ( $finding['type'] ?? '' );

		$deny = static function ( string $rule, string $reason, string $trust = 'unreviewed' ): array {
			return [ 'allowed' => false, 'reason' => $reason, 'rule' => $rule, 'trust' => $trust ];
		};

		if ( self::breaker_tripped() ) {
			return $deny( 'circuit_breaker', 'automatic removal is halted pending operator review', 'halted' );
		}

		if ( '' === $target ) {
			return $deny( 'no_target', 'no removal target was given' );
		}

		// Fail closed: an identity we cannot derive is one we cannot check
		// against the trust store, so we must not act on it.
		$id = self::identity( $target );
		if ( '' === $id ) {
			return $deny( 'identity_unresolvable', 'the target path could not be resolved to a canonical identity' );
		}

		// Fail closed: if the store itself is unreadable, deny.
		$store_raw = get_option( self::SAFE_OPTION, null );
		if ( null !== $store_raw && ! is_array( $store_raw ) ) {
			return $deny( 'trust_state_unreadable', 'the Safe list could not be read, so removal is denied' );
		}

		// THE VETO.
		$safe = self::safe_state( $target );
		if ( $safe['safe'] ) {
			if ( class_exists( 'WPS_Logger' ) ) {
				WPS_Logger::log_event(
					'remediation_denied_safe',
					'REMEDIATION DENIED: ' . $id . ' is operator-approved Safe'
						. ( $safe['id'] !== $id ? ' via ' . $safe['scope'] . ' ' . $safe['id'] : '' )
				);
			}
			return $deny( 'operator_safe', 'the operator marked this target Safe' . ( $safe['id'] !== $id ? ' via the ' . $safe['scope'] . ' ' . $safe['id'] : '' ), 'safe' );
		}

		$heuristic = self::is_heuristic( $type );

		// WordPress core is never removed automatically. Not on a heuristic,
		// not on a signature match, not ever.
		//
		// 1.4.89: this was conditional on the finding being heuristic, and a
		// genuine core installer file was therefore removable. The condition
		// was wrong in principle as well as in practice: deleting a core file
		// does not disinfect a site, it breaks it, and the remedy for genuinely
		// infected core is to restore the file from an official WordPress
		// release. There is no case where silently deleting part of core is
		// the right automatic action, so confidence is irrelevant here.
		if ( self::is_core_path( $id ) ) {
			return $deny(
				'core_protected',
				'this is a WordPress core file, which is never removed automatically - if it is genuinely infected, replace it from an official WordPress release instead',
				'core'
			);
		}

		// Known-good packages: heuristics report, they do not remove.
		foreach ( self::KNOWN_GOOD_PREFIXES as $prefix ) {
			if ( $id === $prefix || 0 === strpos( $id, $prefix . '/' ) ) {
				if ( $heuristic ) {
					return $deny( 'known_good_package', 'this is part of ' . $prefix . ', which is known-legitimate software; the finding is reported but not acted on automatically', 'trusted' );
				}
			}
		}

		// A heuristic finding may not remove a whole package directory.
		if ( $heuristic && self::is_package_root( $id ) ) {
			return $deny( 'package_scope_denied', 'a behavioural finding may not remove an entire plugin or theme; remove it by hand after review' );
		}

		/*
		 * 1.4.90: calibration between too aggressive and too lax.
		 *
		 * The outages all had the same shape: a behavioural guess about a file
		 * INSIDE a legitimate plugin, acted on automatically. The guess was
		 * wrong, the file mattered, and the site stopped booting. But refusing
		 * every behavioural removal would be its own failure - a web shell
		 * dropped in the uploads folder would then sit there being reported,
		 * scan after scan, while nothing happened to it.
		 *
		 * What separates those two cases is not how clever the detector is. It
		 * is WHERE the file is. Executable PHP inside wp-content/uploads, or in
		 * a cache directory, has no legitimate reason to exist: WordPress does
		 * not put it there and no plugin needs to. A wrong guess in those
		 * locations costs an image directory a file that should not have been
		 * in it. The same guess inside wp-content/plugins/<something> is a
		 * guess about software someone installed on purpose, where being wrong
		 * costs them a working site.
		 *
		 * So location decides, not confidence:
		 *   - confirmed content match: removable anywhere but core.
		 *   - behavioural finding in a no-executables location: removable.
		 *   - behavioural finding inside an installed package: REPORTED, never
		 *     removed automatically. This is the change that would have
		 *     prevented both outages.
		 */
		if ( $heuristic && ! self::is_no_executables_location( $id ) ) {
			return $deny(
				'heuristic_in_managed_location',
				'this is a behavioural finding about a file inside installed software, so it is reported rather than removed automatically - review it and remove it by hand, or mark it Safe if it is legitimate',
				'unreviewed'
			);
		}

		return [ 'allowed' => true, 'reason' => 'no policy rule denies this removal', 'rule' => 'permitted', 'trust' => 'unreviewed' ];
	}

	/**
	 * Everything WordPress itself ships and replaces on update.
	 *
	 * 1.4.89: widened. The first version matched `wp-admin/`, `wp-includes/`
	 * and root files beginning `wp-`, which silently excluded `index.php`,
	 * `xmlrpc.php` and `license.txt` - core files that do not follow the `wp-`
	 * naming and were therefore removable. A root-level PHP file that is not
	 * inside wp-content is core by definition on a standard install, so that is
	 * what this now tests, rather than trying to enumerate names.
	 */
	/** Public wrapper: is this absolute path part of WordPress core? */
	public static function is_core_file( string $path ): bool {
		return self::is_core_path( self::identity( $path ) );
	}

	private static function is_core_path( string $id ): bool {
		if ( '' === $id ) {
			return false;
		}
		if ( 0 === strpos( $id, 'wp-admin/' ) || 0 === strpos( $id, 'wp-includes/' ) ) {
			return true;
		}
		// Anything at the site root that is not user content.
		if ( false === strpos( $id, '/' ) ) {
			return (bool) preg_match( '#\.(php|txt|html)$#i', $id );
		}
		return false;
	}

	/**
	 * Locations where an executable PHP file has no legitimate reason to exist.
	 *
	 * These are directories WordPress and its plugins write DATA into - media,
	 * caches, backups, logs. None of them is a place code is supposed to live,
	 * so a behavioural finding there is far safer to act on than the same
	 * finding inside installed software: the worst case is losing a file that
	 * should not have been in an uploads folder, rather than breaking a plugin
	 * the site depends on.
	 *
	 * mu-plugins is deliberately NOT here. Code belongs there, legitimately -
	 * ManageWP and Burst both ship loaders into it - and this session has
	 * already seen both wrongly suspected.
	 */
	private static function is_no_executables_location( string $id ): bool {
		$prefixes = [
			'wp-content/uploads/',
			'wp-content/cache/',
			'wp-content/backup',
			'wp-content/upgrade/',
			'wp-content/wflogs/',
		];
		foreach ( $prefixes as $p ) {
			if ( 0 === strpos( $id, $p ) ) {
				return true;
			}
		}
		// A cache directory belonging to any plugin: data, not code.
		if ( preg_match( '#^wp-content/(?:plugins|themes)/[^/]+/(?:cache|logs?|tmp|temp)/#', $id ) ) {
			return true;
		}
		return false;
	}

	/** Is this the root folder of a plugin or theme, rather than a file inside it? */
	private static function is_package_root( string $id ): bool {
		return (bool) preg_match( '#^wp-content/(?:plugins|themes)/[^/]+$#', $id );
	}

	/**
	 * Final gate immediately before a destructive act.
	 *
	 * Separate from decide() on purpose: the trust state is re-read here, so a
	 * Safe decision made while a long scan was running is still honoured, and a
	 * caller that somehow skipped decide() cannot get past this.
	 */
	public static function assert_may_remove( string $target, string $type = '' ): bool {
		$decision = self::decide( [ 'delete_path' => $target, 'type' => $type ] );
		if ( $decision['allowed'] ) {
			return true;
		}
		// A Safe target reaching this point means an earlier gate was skipped:
		// a defect of exactly the kind that broke the site. Stop everything.
		if ( 'operator_safe' === $decision['rule'] ) {
			self::trip_breaker( 'the scanner attempted to remove ' . self::identity( $target ) . ', which the operator had marked Safe' );
			if ( class_exists( 'WPS_EDR' ) && method_exists( 'WPS_EDR', 'record' ) ) {
				WPS_EDR::record( 'security_policy_violation', [
					'object_type' => 'file',
					'object_name' => self::identity( $target ),
					'severity'    => 'critical',
					'notes'       => 'Scanner attempted remediation of an operator-approved Safe target. Automatic removal has been halted.',
				] );
			}
		}
		return false;
	}
}
