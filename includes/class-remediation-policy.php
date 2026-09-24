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
		// 1.4.94: the plain signature type was missing from this list while
		// three of its narrower siblings were present. A confirmed hash or
		// signature match on a plugin file - the strongest evidence this
		// scanner produces - was therefore classed as inference and reported
		// rather than removed, which is the opposite of the intended
		// calibration and would have left known malware in place.
		//
		// Found by running a real sample through the policy rather than by
		// reading the list, which is the only way a gap of this shape shows
		// up: every entry present looks correct, and the missing one is
		// invisible until something needs it.
		'Malware signature in PHP file',
		'Malware signature in theme file',
		'Malware signature in mu-plugin file',
		'Malware signature in cache directory PHP file',
		'Malware signature in plugin file',
		'Known malware hash',
		'Known malware-created admin user',
		'Malicious wp-content drop-in persistence loader',
		'Malicious wp-content drop-in re-dropper',
		'Malicious cron hook scheduled by malware',
		'Malicious wp-content drop-in re-dropper (writes obfuscated payload to mu-plugins)',
		'malware signature in WordPress root PHP file',
	];

	/** True unless the finding comes from a confirmed-content match. */
	/**
	 * 1.4.110: behavioural findings that are nonetheless conclusive.
	 *
	 * The package-scope rule stops a behavioural finding removing an entire
	 * plugin, and it exists because this plugin quarantined WP-Optimize on a
	 * single behavioural signal and stopped a site from booting. That reason
	 * holds, and it has now been applied three times to findings where it made
	 * no sense: an operator's own ban, a folder containing no plugin, and a
	 * plugin whose purpose is a hidden administrator account. Each was patched
	 * individually. A third instance is a pattern rather than a coincidence.
	 *
	 * The distinction the rule was missing is not between behavioural and
	 * confirmed evidence. It is between one suspicious behaviour and several
	 * malicious behaviours co-occurring. WP-Optimize was flagged by a single
	 * signal, self-concealment, which legitimate software can exhibit for
	 * legitimate reasons. The findings listed here each require independent
	 * behaviours that no legitimate software combines: creating an
	 * administrator AND hiding it from the user list; identifying search
	 * crawlers AND serving them different content; declaring no plugin header
	 * AND carrying an encrypted payload.
	 *
	 * Each detector below establishes its own conjunction before reporting, so
	 * the conclusion rests on the detector's own evidence rather than on
	 * confidence in this list. Anything not named here keeps the protection
	 * exactly as it was.
	 */
	private const CONCLUSIVE_TYPES = [
		'Hidden administrator account backdoor',
		'Plugin folder with no plugin in it',
		// 1.4.111: a nest of constants resolving to a dangerous call whose
		// plain name is absent from the file. Three conditions that only
		// coincide when someone is hiding what the code calls.
		'Function names assembled from constants to defeat searching',
	];

	/*
	 * Deliberately absent: 'Unauthenticated administrator sign-in endpoint'.
	 *
	 * It meets the test on its face, since granting an administrator session
	 * without a password to an unauthenticated caller is several behaviours at
	 * once. It is also what managed hosts install to power their dashboard
	 * login button, so the conjunction is present in legitimate software and
	 * the reasoning that justifies this tier does not hold for it. Its detector
	 * reports and never sets a removal target, so the policy is not consulted
	 * today; listing it here would quietly authorise removal the moment anyone
	 * wired one up. The runtime guard in 1.4.95 is how that endpoint is
	 * stopped, and it is switched on deliberately by the operator.
	 */

	/** Does this finding rest on several malicious behaviours at once? */
	private static function is_conclusive( string $type ): bool {
		foreach ( self::CONCLUSIVE_TYPES as $t ) {
			if ( $type === $t || 0 === strpos( $type, $t ) ) {
				return true;
			}
		}
		return false;
	}

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

		/*
		 * 1.4.111: the host SSO loader is removed only if the operator has
		 * asked for it.
		 *
		 * `sso-loader.php` is listed as a known-bad mu-plugin filename, which
		 * queues it for automatic removal. The copy recovered from this site is
		 * byte for byte the loader managed hosts install to power their
		 * dashboard login button, so removing it automatically would break that
		 * button with no warning, and the host would redeploy the file anyway.
		 * That is the shape of the failure this plugin has already caused twice.
		 *
		 * The operator does have a way to say they want it gone: the
		 * "Block unauthenticated sign-in endpoints" setting added in 1.4.95,
		 * which disarms the endpoint on every request and clears the token.
		 * Where that is switched on, removing the file as well is consistent
		 * with what was asked for. Where it is off, the file is reported and
		 * left alone, because nobody has asked for host software to be deleted.
		 */
		if ( false !== stripos( $id, 'sso-loader.php' ) ) {
			$s = get_option( WPS_OPTION, [] );
			$sso_guard_on = is_array( $s ) && ( $s['block_sso_bypass'] ?? '0' ) === '1';
			if ( ! $sso_guard_on ) {
				return $deny(
					'host_sso_loader',
					'this is the sign-in loader managed hosts install, so it is reported rather than removed; switch on "Block unauthenticated sign-in endpoints" in Settings to disable the endpoint and clear its token, and this file will be removed too',
					'unreviewed'
				);
			}
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

		/*
		 * 1.4.103: proof outranks inference.
		 *
		 * A file whose hash matches the release its author published is that
		 * software. No behavioural rule may remove it, because every such
		 * removal is a false positive by definition: the question the
		 * heuristic is guessing at has already been answered
		 * cryptographically.
		 *
		 * This is what the hardcoded known-good list below was standing in
		 * for. That list only ever grew after an incident, and its WP-Optimize
		 * entry was added after this plugin quarantined those cache classes
		 * and stopped a production site from booting. They match wordpress.org
		 * byte for byte, so under this rule that outage could not have
		 * occurred, and the protection extends to every plugin in the
		 * directory rather than the four that happened to break first. The
		 * list remains below as the fallback for when no manifest can be
		 * fetched.
		 *
		 * Confirmed signature matches are deliberately still permitted
		 * through. A published release can itself be compromised at source, so
		 * a hash match establishes provenance rather than innocence.
		 */
		if ( $heuristic && class_exists( 'WPS_Integrity' ) && WPS_Integrity::is_official( $target ) ) {
			return $deny(
				'verified_official_release',
				'this file matches the official published release of its plugin, so a behavioural finding about it is a false positive by definition; it is reported and never removed automatically',
				'verified'
			);
		}


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

		/*
		 * 1.4.104: an operator ban is a decision, not a guess.
		 *
		 * The site-policy denylist exists because the operator named a plugin
		 * and said it must not run here. That is the most explicit instruction
		 * this plugin ever receives, and from 1.4.90 until now it was being
		 * overruled: the finding type was absent from the confirmed list, so it
		 * counted as inference, and because the target is a plugin folder the
		 * package-scope rule then refused the removal. WP File Manager was
		 * therefore reported on every scan and removed on none, while the
		 * operator reasonably believed it had been banned.
		 *
		 * The calibration that produced this was right about heuristics and
		 * wrong to treat an operator instruction as one. A behavioural guess
		 * about a plugin is not grounds to delete it; the operator's own
		 * decision about that same plugin plainly is, since nobody is better
		 * placed to say what may run on their site.
		 *
		 * Everything above this point still applies: a Safe decision, core
		 * protection and the circuit breaker all outrank it, so this authorises
		 * the removal the operator asked for and nothing else.
		 */
		if ( false !== stripos( $type, 'banned by site policy' ) ) {
			return [
				'allowed' => true,
				'reason'  => 'the operator placed this plugin on the site-policy denylist',
				'rule'    => 'operator_policy_ban',
				'trust'   => 'banned',
			];
		}

		// Known-good packages: heuristics report, they do not remove.
		foreach ( self::KNOWN_GOOD_PREFIXES as $prefix ) {
			if ( $id === $prefix || 0 === strpos( $id, $prefix . '/' ) ) {
				if ( $heuristic ) {
					return $deny( 'known_good_package', 'this is part of ' . $prefix . ', which is known-legitimate software; the finding is reported but not acted on automatically', 'trusted' );
				}
			}
		}

		/*
		 * 1.4.105: a folder with no plugin header is not a plugin.
		 *
		 * The package-scope rule below exists to stop a behavioural guess
		 * deleting software somebody installed on purpose. A folder in which no
		 * file declares a Plugin Name is not that: WordPress cannot load it, it
		 * has no entry point, and nothing on the site depends on it running.
		 * The protection is for installed software, and this is packaging
		 * around a payload.
		 *
		 * Written narrowly on purpose. This does not relax the package-scope
		 * rule, which stays exactly as it was for every real plugin; it
		 * declines to apply it to a directory that only resembles one. The
		 * detector establishes the absence of a header directly, so the
		 * judgement rests on a fact about the folder rather than on confidence
		 * in a heuristic.
		 */
		if ( false !== stripos( $type, 'no plugin in it' ) ) {
			return [
				'allowed' => true,
				'reason'  => 'this folder declares no Plugin Name, so it is not installed software and the protection for installed software does not apply',
				'rule'    => 'not_a_plugin',
				'trust'   => 'unreviewed',
			];
		}

		// A heuristic finding may not remove a whole package directory.
		if ( $heuristic && ! self::is_conclusive( $type ) && self::is_package_root( $id ) ) {
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
		if ( $heuristic && ! self::is_conclusive( $type ) && ! self::is_no_executables_location( $id ) ) {
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
		if ( false !== strpos( $id, '/' ) ) {
			return false;
		}

		/*
		 * 1.4.107: the root test is a list of the files WordPress actually
		 * ships, rather than "any PHP file at the site root".
		 *
		 * The earlier rule was written to stop core being deleted and had an
		 * effect nobody intended: it also shielded anything an attacker dropped
		 * beside core. A recovered sample named `wp-slgnup.php`, one letter away
		 * from `wp-signup.php`, sat in the root and was therefore protected from
		 * removal even by a confirmed signature match. Naming a payload after a
		 * core file is among the oldest techniques there is, and the protection
		 * was rewarding it.
		 *
		 * WordPress ships a fixed, well-known set of root files. A file in the
		 * root that is not among them is not core, whatever it is called, and is
		 * judged on its merits like any other file. `wp-config.php` is included
		 * because deleting it destroys a site even though WordPress does not
		 * ship it.
		 */
		$core_root = [
			'index.php', 'license.txt', 'readme.html', 'wp-activate.php',
			'wp-blog-header.php', 'wp-comments-post.php', 'wp-config.php',
			'wp-config-sample.php', 'wp-cron.php', 'wp-links-opml.php',
			'wp-load.php', 'wp-login.php', 'wp-mail.php', 'wp-settings.php',
			'wp-signup.php', 'wp-trackback.php', 'xmlrpc.php',
		];
		return in_array( strtolower( $id ), $core_root, true );
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
		/*
		 * 1.4.107: the WordPress root, excluding the files WordPress ships.
		 *
		 * The root is not a directory where arbitrary PHP belongs. WordPress
		 * ships a fixed set of files there and nothing else, so a PHP file in
		 * the root that is not one of them was placed by somebody, and a
		 * behavioural finding about it should be acted on rather than held for
		 * review. A recovered doorway script exploited exactly this gap: it sat
		 * in the root under a near-copy of a core filename, where the rule
		 * protecting installed software applied to it and the rule protecting
		 * core did so as well.
		 *
		 * is_core_path() already enumerates the genuine root files, so this
		 * asks it rather than keeping a second list that could drift.
		 */
		if ( false === strpos( $id, '/' ) && preg_match( '#\.php$#i', $id ) && ! self::is_core_path( $id ) ) {
			return true;
		}

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
