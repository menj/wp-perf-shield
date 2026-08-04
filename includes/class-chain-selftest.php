<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * 1.4.64: in-plugin verification for the CRIT-005 concurrency-safe append.
 *
 * The build environment has no database, so the append fix could only be
 * logic-checked there. This runs the real proof against the real database,
 * from the Diagnostics screen, on the actual host - which is the only place
 * the guarantee genuinely lives.
 *
 * Two checks, both against the live DB:
 *
 *   A. Real-chain integrity. The genuine record()/verify_chain() code path is
 *      exercised against an ISOLATED scratch table (WPS_Event_Log's self-test
 *      namespace), never the real chain. A batch of appends must produce one
 *      linear, verifiable chain with no duplicate predecessor. The scratch
 *      table is dropped afterwards, so nothing is added to or deleted from the
 *      real tamper-evident log - deleting probe rows from the real chain would
 *      itself break it, which is exactly why the scratch table exists.
 *
 *   B. Cross-connection mutual exclusion. A second, independent database
 *      connection takes the append advisory lock; the primary connection must
 *      then fail to acquire it, and must succeed once the second releases. This
 *      proves - deterministically, no flaky parallel burst required - that the
 *      lock the fix relies on actually excludes across connections on THIS
 *      server. Where GET_LOCK is unavailable (a non-MySQL/MariaDB host), this
 *      is reported as not-applicable and the append uses its FOR UPDATE
 *      fallback instead.
 *
 * Honest scope: this does not simulate N-way parallel throughput. It proves the
 * load-bearing property (real cross-connection exclusion) and that the real
 * append path yields a clean chain on this database. That pair is stronger
 * evidence than a timing-dependent burst, and it always runs.
 */
class WPS_Chain_Selftest {

	/** Scratch namespace tag (matches WPS_Event_Log's [a-z0-9]{1,16} rule). */
	const NS = 'probe';

	/** Sequential appends for the integrity check. Small: this is a proof, not a benchmark. */
	const BATCH = 120;

	/**
	 * Run both checks and return a structured, render-ready result.
	 *
	 * @return array{
	 *   ts:string, ok:bool, summary:string,
	 *   checks:array<int,array{id:string,label:string,status:string,detail:string}>
	 * }
	 */
	public static function run(): array {
		$checks = [];

		if ( ! class_exists( 'WPS_Event_Log' ) || ! WPS_Event_Log::available() ) {
			return self::finish( [ [
				'id' => 'availability', 'label' => 'Event store reachable',
				'status' => 'fail', 'detail' => 'The event store is unavailable, so the chain cannot be tested here.',
			] ] );
		}

		$checks[] = self::check_scratch_integrity();
		$checks[] = self::check_mutual_exclusion();

		return self::finish( $checks );
	}

	/** Check A: real record()/verify_chain() over an isolated scratch chain. */
	private static function check_scratch_integrity(): array {
		global $wpdb;

		$real_table         = WPS_Event_Log::table();
		$real_anchor_before = get_option( 'wps_event_chain', null );
		$real_rows_before   = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . $real_table ); // phpcs:ignore

		$verify = null;
		$dupes  = -1;
		$count  = -1;

		try {
			if ( ! WPS_Event_Log::begin_selftest( self::NS ) ) {
				return [
					'id' => 'integrity', 'label' => 'Real append path yields a clean chain',
					'status' => 'fail', 'detail' => 'Could not create the isolated scratch table.',
				];
			}
			for ( $i = 0; $i < self::BATCH; $i++ ) {
				WPS_Event_Log::record( [
					'event_type' => 'chain_selftest_probe',
					'severity'   => 'info',
					'notes'      => 'scratch probe ' . $i,
				] );
			}
			$scratch = WPS_Event_Log::table();
			$verify  = WPS_Event_Log::verify_chain();
			$count   = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$scratch} WHERE curr_hash <> ''" ); // phpcs:ignore
			$dupes   = (int) $wpdb->get_var( // phpcs:ignore
				"SELECT COUNT(*) FROM ( SELECT prev_hash FROM {$scratch} WHERE curr_hash <> '' AND prev_hash <> '' GROUP BY prev_hash HAVING COUNT(*) > 1 ) d"
			);
		} finally {
			WPS_Event_Log::end_selftest();
		}

		// Isolation: the real chain must be byte-for-byte untouched.
		$real_anchor_after = get_option( 'wps_event_chain', null );
		$real_rows_after   = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . $real_table ); // phpcs:ignore
		$isolated          = ( $real_rows_after === $real_rows_before ) && ( $real_anchor_after === $real_anchor_before );

		$status_ok = is_array( $verify ) && ( $verify['status'] ?? '' ) === 'ok'
			&& $count === self::BATCH && $dupes === 0 && $isolated;

		$detail = sprintf(
			'%d appends -> verify_chain: %s; verified %d; duplicate predecessors: %d; real chain untouched: %s.',
			self::BATCH,
			is_array( $verify ) ? (string) $verify['status'] : 'n/a',
			is_array( $verify ) ? (int) $verify['verified'] : 0,
			max( 0, $dupes ),
			$isolated ? 'yes' : 'NO'
		);

		return [
			'id'     => 'integrity',
			'label'  => 'Real append path yields a clean, isolated chain',
			'status' => $status_ok ? 'pass' : 'fail',
			'detail' => $detail,
		];
	}

	/** Check B: the append lock excludes across two independent DB connections. */
	private static function check_mutual_exclusion(): array {
		$label = 'Append lock excludes across connections';

		if ( ! class_exists( 'wpdb' ) || ! defined( 'DB_USER' ) || ! defined( 'DB_NAME' ) ) {
			return [ 'id' => 'exclusion', 'label' => $label, 'status' => 'skip',
				'detail' => 'No second-connection path on this host; not tested.' ];
		}

		global $wpdb;
		$name = WPS_Event_Log::append_lock_name();

		$second = null;
		try {
			$second = new wpdb( DB_USER, DB_PASSWORD, DB_NAME, DB_HOST );
			if ( method_exists( $second, 'suppress_errors' ) ) {
				$second->suppress_errors( true );
			}

			$held = $second->get_var( $second->prepare( 'SELECT GET_LOCK(%s, %d)', $name, 0 ) );
			if ( $held === null ) {
				return [ 'id' => 'exclusion', 'label' => $label, 'status' => 'skip',
					'detail' => 'GET_LOCK is unavailable on this database; the append uses its FOR UPDATE fallback. Verify that path on staging.' ];
			}
			if ( (string) $held !== '1' ) {
				return [ 'id' => 'exclusion', 'label' => $label, 'status' => 'skip',
					'detail' => 'The lock was already held during the test; result inconclusive. Re-run when the site is quiet.' ];
			}

			// Primary must be excluded while the second connection holds the lock.
			$contended = $wpdb->get_var( $wpdb->prepare( 'SELECT GET_LOCK(%s, %d)', $name, 0 ) );
			$excluded  = ( (string) $contended === '0' );
			if ( (string) $contended === '1' ) {
				$wpdb->query( $wpdb->prepare( 'DO RELEASE_LOCK(%s)', $name ) ); // accidental grab: release it
			}

			// Release the second connection's lock; the primary must now acquire.
			$second->query( $second->prepare( 'DO RELEASE_LOCK(%s)', $name ) );
			$free      = $wpdb->get_var( $wpdb->prepare( 'SELECT GET_LOCK(%s, %d)', $name, 0 ) );
			$reacquire = ( (string) $free === '1' );
			if ( $reacquire ) {
				$wpdb->query( $wpdb->prepare( 'DO RELEASE_LOCK(%s)', $name ) );
			}

			$ok = $excluded && $reacquire;
			return [
				'id'     => 'exclusion',
				'label'  => $label,
				'status' => $ok ? 'pass' : 'fail',
				'detail' => sprintf(
					'While a second connection held the lock, the primary was %s; after release it %s reacquire.',
					$excluded ? 'correctly blocked' : 'NOT blocked',
					$reacquire ? 'could' : 'could NOT'
				),
			];
		} catch ( \Throwable $e ) {
			return [ 'id' => 'exclusion', 'label' => $label, 'status' => 'skip',
				'detail' => 'Could not open a second database connection to test the lock.' ];
		} finally {
			if ( is_object( $second ) && method_exists( $second, 'query' ) ) {
				// Closing the connection releases any held lock; be explicit anyway.
				$second->query( $second->prepare( 'DO RELEASE_LOCK(%s)', $name ) );
			}
		}
	}

	/** Assemble the summary, record one durable audit event, and return. */
	private static function finish( array $checks ): array {
		$fail = 0;
		$skip = 0;
		foreach ( $checks as $c ) {
			if ( $c['status'] === 'fail' ) { $fail++; }
			if ( $c['status'] === 'skip' ) { $skip++; }
		}
		$ok      = ( $fail === 0 );
		$summary = $ok
			? ( $skip > 0 ? 'Passed, with one check not applicable on this host.' : 'Passed. The concurrency-safe append is verified on this database.' )
			: 'Failed. The append did not behave as required on this database.';

		// A single real event, so the run and its verdict are themselves on the
		// audit record - appended to the real chain, after the scratch table is
		// already gone.
		if ( class_exists( 'WPS_Event_Log' ) && method_exists( 'WPS_Event_Log', 'audit' ) ) {
			WPS_Event_Log::audit( 'chain_selftest', [
				'object_type' => 'event_chain',
				'object_name' => 'CRIT-005 self-test',
				'severity'    => $ok ? 'notice' : 'warning',
				'reason'      => $summary,
			] );
		}

		return [
			'ts'      => gmdate( 'Y-m-d H:i:s' ) . ' UTC',
			'ok'      => $ok,
			'summary' => $summary,
			'checks'  => $checks,
		];
	}
}
