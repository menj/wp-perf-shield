<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * 1.3.99: tamper-evident event store - the platform foundation for the EDR
 * programme (SSOT: "Product Roadmap", the one-schema rule).
 *
 * Design in brief:
 *
 * - STORAGE is a custom table ({$wpdb->prefix}wps_events) carrying the full
 *   unified 24-field schema. Fields the plugin cannot populate yet (country,
 *   city, asn before the GeoIP decision; incident/correlation ids before
 *   phase 1) are stored NULL so the record shape never changes underneath
 *   consumers (roadmap Decision 4, resolved 1.3.99: table over file - the
 *   phase-1 incident work is query-shaped, and a table survives filesystem
 *   resets).
 *
 * - INTEGRITY is an HMAC chain: every record carries prev_hash (the previous
 *   record's curr_hash), curr_hash (sha256 over the canonical serialisation
 *   of the record's content fields plus prev_hash), and hmac_signature
 *   (HMAC-SHA256 of curr_hash under a per-install key). Editing a row breaks
 *   its own hash; deleting one breaks its successor's prev link.
 *
 * - The chain HEAD (hash + row count + genesis) is anchored in two places:
 *   the wps_event_chain option and a PHP-guarded mirror file under
 *   WPS_LOG_DIR with a randomised name. Truncating or dropping the table
 *   leaves the anchors describing rows that no longer exist.
 *
 * - HONEST LIMITS, stated plainly: this is tamper-EVIDENT, not tamper-proof.
 *   An attacker holding both DB write access and the HMAC key can rebuild
 *   the chain; the key is therefore mirrored outside the DB, and the two
 *   anchors force such an attacker to win in three places at once. The
 *   common real-world case - a cleanup DELETE or UPDATE against the table -
 *   is detected.
 *
 * - Rows rotate at MAX_ROWS. Pruning re-anchors the genesis hash to the new
 *   oldest row's prev_hash, so verification of the surviving window still
 *   closes. Rotation is the only deletion path; there is no clear() here by
 *   design.
 */
class WPS_Event_Log {

	const SCHEMA_VERSION = 1;
	const MAX_ROWS       = 10000;

	/**
	 * Seconds to wait on the advisory append lock before falling back to the
	 * transaction path (CRIT-005, 1.4.63). Short: a chain append is a handful
	 * of small statements, so anything approaching this ceiling means real
	 * contention, and the caller is better served by the FOR UPDATE fallback
	 * than by blocking a page load.
	 */
	const LOCK_TIMEOUT = 5;

	/**
	 * When non-empty, record()/verify_chain()/etc. operate on an isolated
	 * scratch table and a scratch anchor option instead of the real chain
	 * (1.4.64, the in-plugin CRIT-005 self-test). The real table, its anchor
	 * option and its mirror files are never touched while this is set.
	 */
	private static $selftest_ns = '';

	/** Content fields, in canonical hash order. Never reorder: hashes depend on it. */
	private const CONTENT_FIELDS = [
		'ts', 'event_type', 'username', 'user_role', 'user_id', 'session_id',
		'incident_id', 'correlation_id', 'ip', 'country', 'city', 'asn',
		'user_agent', 'referer', 'request_uri', 'object_type', 'object_name',
		'action', 'severity', 'risk_score', 'notes',
	];

	//  Availability & schema 

	private static function db() {
		return ( isset( $GLOBALS['wpdb'] ) && is_object( $GLOBALS['wpdb'] ) ) ? $GLOBALS['wpdb'] : null;
	}

	public static function table(): string {
		$db     = self::db();
		$prefix = $db ? $db->prefix : 'wp_';
		if ( self::$selftest_ns !== '' ) {
			return $prefix . 'wps_events_st_' . self::$selftest_ns;
		}
		return $prefix . 'wps_events';
	}

	/** True when the DB is reachable and the table exists (creating it on first call). */
	public static function available(): bool {
		$db = self::db();
		if ( ! $db || ! function_exists( 'get_option' ) ) {
			return false;
		}
		if ( self::$selftest_ns !== '' ) {
			return self::ensure_table(); // scratch table: create on demand, no real schema shortcut
		}
		if ( (int) get_option( 'wps_events_schema', 0 ) === self::SCHEMA_VERSION ) {
			return true;
		}
		return self::ensure_table();
	}

	private static function ensure_table(): bool {
		$db = self::db();
		if ( ! $db ) {
			return false;
		}
		$table   = self::table();
		$charset = method_exists( $db, 'get_charset_collate' ) ? (string) $db->get_charset_collate() : '';
		$sql = "CREATE TABLE IF NOT EXISTS {$table} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			ts DATETIME NOT NULL,
			event_type VARCHAR(64) NOT NULL DEFAULT '',
			username VARCHAR(60) NULL,
			user_role VARCHAR(32) NULL,
			user_id BIGINT UNSIGNED NULL,
			session_id CHAR(64) NULL,
			incident_id CHAR(36) NULL,
			correlation_id CHAR(36) NULL,
			ip VARCHAR(45) NULL,
			country CHAR(2) NULL,
			city VARCHAR(64) NULL,
			asn VARCHAR(16) NULL,
			user_agent VARCHAR(255) NULL,
			referer VARCHAR(255) NULL,
			request_uri VARCHAR(255) NULL,
			object_type VARCHAR(32) NULL,
			object_name VARCHAR(190) NULL,
			action VARCHAR(64) NULL,
			severity VARCHAR(16) NULL,
			risk_score INT NULL,
			notes TEXT NULL,
			prev_hash CHAR(64) NOT NULL DEFAULT '',
			curr_hash CHAR(64) NOT NULL DEFAULT '',
			hmac_signature CHAR(64) NOT NULL DEFAULT '',
			PRIMARY KEY (id),
			KEY ts (ts),
			KEY event_type (event_type),
			KEY incident_id (incident_id)
		) {$charset}";
		$ok = $db->query( $sql );
		if ( $ok === false ) {
			return false;
		}
		if ( self::$selftest_ns === '' ) {
			update_option( 'wps_events_schema', self::SCHEMA_VERSION, false );
			self::migrate_legacy();
		}
		return true;
	}

	//  Key & anchors 

	/**
	 * Per-install HMAC key, 64 hex chars. Lives in the wps_event_hmac_key
	 * option AND a PHP-guarded mirror file under WPS_LOG_DIR; whichever copy
	 * survives restores the other, so a DB restore or a filesystem reset
	 * alone does not orphan the chain.
	 */
	private static function hmac_key(): string {
		$opt = function_exists( 'get_option' ) ? (string) get_option( 'wps_event_hmac_key', '' ) : '';
		$file = self::key_file();
		$disk = ( $file && is_file( $file ) ) ? self::read_guarded( $file ) : '';

		if ( preg_match( '/^[0-9a-f]{64}$/', $opt ) ) {
			if ( $disk !== $opt && $file ) {
				self::write_guarded( $file, $opt );
			}
			return $opt;
		}
		if ( preg_match( '/^[0-9a-f]{64}$/', $disk ) ) {
			if ( function_exists( 'update_option' ) ) {
				update_option( 'wps_event_hmac_key', $disk, false );
			}
			return $disk;
		}
		try {
			$key = bin2hex( random_bytes( 32 ) );
		} catch ( \Exception $e ) {
			$key = hash( 'sha256', uniqid( (string) mt_rand(), true ) . microtime( true ) );
		}
		if ( function_exists( 'update_option' ) ) {
			update_option( 'wps_event_hmac_key', $key, false );
		}
		if ( $file ) {
			self::write_guarded( $file, $key );
		}
		return $key;
	}

	/** Randomised-name key mirror inside the hardened log dir; null when unavailable. */
	private static function key_file(): ?string {
		if ( ! defined( 'WPS_LOG_DIR' ) ) {
			return null;
		}
		if ( ! is_dir( WPS_LOG_DIR ) && ! @mkdir( WPS_LOG_DIR, 0755, true ) ) {
			return null;
		}
		$suffix = function_exists( 'get_option' ) ? (string) get_option( 'wps_event_key_suffix', '' ) : '';
		if ( ! preg_match( '/^[0-9a-f]{12}$/', $suffix ) ) {
			try {
				$suffix = bin2hex( random_bytes( 6 ) );
			} catch ( \Exception $e ) {
				$suffix = substr( hash( 'sha256', uniqid( '', true ) ), 0, 12 );
			}
			if ( function_exists( 'update_option' ) ) {
				update_option( 'wps_event_key_suffix', $suffix, false );
			}
		}
		return WPS_LOG_DIR . '/chain-key-' . $suffix . '.php';
	}

	private static function anchor_file(): ?string {
		$key_file = self::key_file();
		return $key_file ? str_replace( 'chain-key-', 'chain-head-', $key_file ) : null;
	}

	private static function write_guarded( string $path, string $payload ): void {
		@file_put_contents( $path, "<?php exit; ?>\n" . $payload, LOCK_EX );
	}

	private static function read_guarded( string $path ): string {
		$raw = @file_get_contents( $path );
		if ( ! is_string( $raw ) ) {
			return '';
		}
		return trim( str_replace( "<?php exit; ?>", '', $raw ) );
	}

	/** Option key holding the chain anchor - namespaced during a self-test so the real anchor is never read or written. */
	private static function chain_option(): string {
		return self::$selftest_ns !== '' ? 'wps_event_chain_st_' . self::$selftest_ns : 'wps_event_chain';
	}

	/** @return array{head: string, count: int, genesis: string} */
	private static function read_anchor(): array {
		$default = [ 'head' => '', 'count' => 0, 'genesis' => '' ];
		$opt = function_exists( 'get_option' ) ? get_option( self::chain_option(), null ) : null;
		if ( is_array( $opt ) && isset( $opt['head'], $opt['count'], $opt['genesis'] ) ) {
			return [ 'head' => (string) $opt['head'], 'count' => (int) $opt['count'], 'genesis' => (string) $opt['genesis'] ];
		}
		if ( self::$selftest_ns === '' ) {
			$file = self::anchor_file();
			if ( $file && is_file( $file ) ) {
				$disk = json_decode( self::read_guarded( $file ), true );
				if ( is_array( $disk ) && isset( $disk['head'], $disk['count'], $disk['genesis'] ) ) {
					return [ 'head' => (string) $disk['head'], 'count' => (int) $disk['count'], 'genesis' => (string) $disk['genesis'] ];
				}
			}
		}
		return $default;
	}

	private static function write_anchor( array $anchor ): void {
		if ( function_exists( 'update_option' ) ) {
			update_option( self::chain_option(), $anchor, false );
		}
		if ( self::$selftest_ns === '' ) {
			$file = self::anchor_file();
			if ( $file ) {
				self::write_guarded( $file, (string) wp_json_encode( $anchor ) );
			}
		}
	}

	/**
	 * Enter an isolated scratch namespace for the diagnostic self-test. Every
	 * record()/verify_chain() call afterwards targets a throwaway table and a
	 * throwaway anchor option; the real chain, its anchor option and its mirror
	 * files are neither read nor written. Always pair with end_selftest() in a
	 * finally.
	 */
	public static function begin_selftest( string $ns ): bool {
		if ( ! preg_match( '/^[a-z0-9]{1,16}$/', $ns ) ) {
			return false;
		}
		self::$selftest_ns = $ns;
		if ( function_exists( 'delete_option' ) ) {
			delete_option( self::chain_option() ); // start from a clean genesis
		}
		return self::ensure_table();
	}

	/** Leave the scratch namespace, dropping the scratch table and its anchor option. */
	public static function end_selftest(): void {
		if ( self::$selftest_ns === '' ) {
			return;
		}
		$db    = self::db();
		$table = self::table();
		// Guard: only ever drop a table that is unmistakably a scratch table.
		if ( $db && method_exists( $db, 'query' ) && strpos( $table, 'wps_events_st_' ) !== false ) {
			$db->query( 'DROP TABLE IF EXISTS ' . $table );
		}
		if ( function_exists( 'delete_option' ) ) {
			delete_option( self::chain_option() );
		}
		self::$selftest_ns = '';
	}

	//  Recording 

	/**
	 * Append one event. $fields may carry any unified-schema field; request
	 * context (user, ip, user agent, referer, uri, session) is auto-filled
	 * when absent. Returns the new row id, or null when the store is
	 * unavailable (callers must not treat logging as fallible - the file-log
	 * shim keeps a belt-and-braces copy either way).
	 */
	public static function record( array $fields ): ?int {
		if ( ! self::available() ) {
			return null;
		}
		$db  = self::db();
		$row = self::build_row( $fields );

		/*
		 * CRIT-005 (1.4.63): serialise the append so two concurrent writers
		 * cannot both attach to the same head and fork the chain.
		 *
		 * The head is read from the TABLE inside the lock - the newest chained
		 * row's curr_hash - not from the cached wps_event_chain option. That is
		 * deliberate and does two things at once: it closes the race, and it
		 * makes an append self-healing, because the authoritative head is
		 * always the last row actually committed to disk. A stale or
		 * previously-forked anchor can no longer misdirect a new link.
		 *
		 * The previous sequence (read anchor -> compute -> insert -> advance
		 * anchor) ran with no lock and no transaction. Under concurrent load it
		 * forked the chain, and verify_chain() then reported that fork as
		 * tampering - a false alarm indistinguishable from a real one, and the
		 * likely source of an unexplained tamper report on a busy site.
		 */
		$lock      = self::acquire_append_lock();
		$id        = null;
		$committed = false;

		try {
			$head                  = self::current_head();
			$row['prev_hash']      = $head;
			$row['curr_hash']      = self::compute_hash( $row, $head );
			$row['hmac_signature'] = hash_hmac( 'sha256', $row['curr_hash'], self::hmac_key() );

			$ok = $db->insert( self::table(), $row );
			if ( $ok === false ) {
				return null; // finally still releases the lock / rolls back
			}
			$id = (int) $db->insert_id;

			// Advance the cached anchor. Safe under the lock; count is taken
			// from the table so a formerly-lost increment cannot leave it
			// permanently adrift.
			$anchor          = self::read_anchor();
			$anchor['head']  = $row['curr_hash'];
			$anchor['count'] = self::chained_row_count();
			self::write_anchor( $anchor );

			// Prune inside the lock too: it re-anchors genesis and deletes the
			// oldest rows, and must not race an append writing the same anchor.
			self::maybe_prune();

			$committed = true;
		} finally {
			self::release_append_lock( $lock, $committed );
		}

		return $id;
	}

	/**
	 * The authoritative chain head: the newest chained row's curr_hash, or the
	 * empty string when no chained rows exist yet (genesis). Pre-chain import
	 * rows carry an empty curr_hash and are skipped, so they never masquerade
	 * as the head.
	 */
	private static function current_head(): string {
		$db = self::db();
		if ( ! $db ) {
			return '';
		}
		$head = $db->get_var(
			"SELECT curr_hash FROM " . self::table() . " WHERE curr_hash <> '' ORDER BY id DESC LIMIT 1"
		);
		return is_string( $head ) ? $head : '';
	}

	/** Count of chained (non-import) rows, for the anchor's count field. */
	private static function chained_row_count(): int {
		$db = self::db();
		if ( ! $db ) {
			return 0;
		}
		return (int) $db->get_var( "SELECT COUNT(*) FROM " . self::table() . " WHERE curr_hash <> ''" );
	}

	/**
	 * Serialise chain appends (CRIT-005).
	 *
	 * Preferred: a MySQL/MariaDB advisory lock (GET_LOCK). The lock name is
	 * derived from the table, so two sites sharing a database server but not a
	 * prefix do not serialise each other, and a multisite install serialises
	 * per network table as intended.
	 *
	 * Fallback, when GET_LOCK is unavailable or does not return success: a
	 * transaction that locks the current tail row FOR UPDATE, which serialises
	 * appenders on InnoDB. HONEST LIMIT, stated where it lives: on an empty
	 * table there is no tail row to lock, so the fallback alone cannot serialise
	 * the very first two concurrent genesis appends. WordPress runs on
	 * MySQL/MariaDB, where GET_LOCK is present, so the fallback is the rare
	 * path; it degrades safely rather than dropping the guard silently.
	 *
	 * @return array{type:string, name?:string}
	 */
	/**
	 * The advisory-lock name that serialises appends, derived from the table so
	 * unrelated sites on one server do not block each other. Public so the
	 * diagnostic self-test locks the exact same name record() does, rather than
	 * a copy that could drift.
	 */
	public static function append_lock_name(): string {
		return 'wpsapp_' . substr( md5( self::table() ), 0, 32 ); // <= 64 chars, GET_LOCK ceiling
	}

	private static function acquire_append_lock(): array {
		$db = self::db();
		if ( ! $db || ! method_exists( $db, 'get_var' ) ) {
			return [ 'type' => 'none' ];
		}

		$name = self::append_lock_name();
		$got  = null;
		if ( method_exists( $db, 'prepare' ) ) {
			$got = $db->get_var( $db->prepare( 'SELECT GET_LOCK(%s, %d)', $name, self::LOCK_TIMEOUT ) );
		}
		if ( (string) $got === '1' ) {
			return [ 'type' => 'get_lock', 'name' => $name ];
		}

		if ( method_exists( $db, 'query' ) ) {
			$db->query( 'START TRANSACTION' );
			// Lock the current tail row so a second appender blocks here until
			// the first commits.
			$db->get_var( 'SELECT id FROM ' . self::table() . " WHERE curr_hash <> '' ORDER BY id DESC LIMIT 1 FOR UPDATE" );
			return [ 'type' => 'for_update' ];
		}

		return [ 'type' => 'none' ];
	}

	/**
	 * Release whatever acquire_append_lock() took. For the transaction path,
	 * commit on success and roll back an incomplete append, so the anchor is
	 * never advanced without its event row.
	 */
	private static function release_append_lock( array $lock, bool $committed ): void {
		$db = self::db();
		if ( ! $db ) {
			return;
		}
		$type = $lock['type'] ?? 'none';
		if ( $type === 'get_lock' && ! empty( $lock['name'] ) && method_exists( $db, 'query' ) && method_exists( $db, 'prepare' ) ) {
			$db->query( $db->prepare( 'DO RELEASE_LOCK(%s)', $lock['name'] ) );
		} elseif ( $type === 'for_update' && method_exists( $db, 'query' ) ) {
			$db->query( $committed ? 'COMMIT' : 'ROLLBACK' );
		}
	}

	/** Normalise/truncate incoming fields onto the schema; nulls preserved. */
	private static function build_row( array $fields ): array {
		$user_login = '';
		$user_role  = '';
		$user_id    = null;
		if ( function_exists( 'wp_get_current_user' ) ) {
			$u = wp_get_current_user();
			if ( $u && ! empty( $u->user_login ) ) {
				$user_login = (string) $u->user_login;
				$user_id    = isset( $u->ID ) ? (int) $u->ID : null;
				$user_role  = ( ! empty( $u->roles ) && is_array( $u->roles ) ) ? (string) reset( $u->roles ) : '';
			}
		}
		$session = '';
		if ( function_exists( 'wp_get_session_token' ) ) {
			$tok = (string) wp_get_session_token();
			if ( $tok !== '' ) {
				$session = hash( 'sha256', $tok );
			}
		}
		$server = static function ( string $k, int $len ): ?string {
			if ( ! isset( $_SERVER[ $k ] ) ) {
				return null;
			}
			$v = (string) ( function_exists( 'wp_unslash' ) ? wp_unslash( $_SERVER[ $k ] ) : $_SERVER[ $k ] );
			return $v === '' ? null : substr( $v, 0, $len );
		};
		$ip = null;
		if ( isset( $_SERVER['REMOTE_ADDR'] ) ) {
			$valid = filter_var( (string) $_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP );
			$ip    = $valid ?: 'invalid';
		}

		$s   = static fn( $v, int $len ) => $v === null ? null : substr( (string) $v, 0, $len );
		$row = [
			'ts'             => $s( $fields['ts'] ?? gmdate( 'Y-m-d H:i:s' ), 19 ),
			'event_type'     => $s( function_exists( 'sanitize_key' ) ? sanitize_key( (string) ( $fields['event_type'] ?? '' ) ) : (string) ( $fields['event_type'] ?? '' ), 64 ),
			'username'       => $s( $fields['username'] ?? ( $user_login !== '' ? $user_login : null ), 60 ),
			'user_role'      => $s( $fields['user_role'] ?? ( $user_role !== '' ? $user_role : null ), 32 ),
			'user_id'        => isset( $fields['user_id'] ) ? (int) $fields['user_id'] : $user_id,
			'session_id'     => $s( $fields['session_id'] ?? ( $session !== '' ? $session : null ), 64 ),
			'incident_id'    => $s( $fields['incident_id'] ?? null, 36 ),
			'correlation_id' => $s( $fields['correlation_id'] ?? null, 36 ),
			'ip'             => $s( $fields['ip'] ?? $ip, 45 ),
			'country'        => $s( $fields['country'] ?? null, 2 ),
			'city'           => $s( $fields['city'] ?? null, 64 ),
			'asn'            => $s( $fields['asn'] ?? null, 16 ),
			'user_agent'     => $s( $fields['user_agent'] ?? $server( 'HTTP_USER_AGENT', 255 ), 255 ),
			'referer'        => $s( $fields['referer'] ?? $server( 'HTTP_REFERER', 255 ), 255 ),
			'request_uri'    => $s( $fields['request_uri'] ?? $server( 'REQUEST_URI', 255 ), 255 ),
			'object_type'    => $s( $fields['object_type'] ?? null, 32 ),
			'object_name'    => $s( $fields['object_name'] ?? null, 190 ),
			'action'         => $s( $fields['action'] ?? null, 64 ),
			'severity'       => $s( $fields['severity'] ?? 'info', 16 ),
			'risk_score'     => isset( $fields['risk_score'] ) ? (int) $fields['risk_score'] : null,
			'notes'          => $s( $fields['notes'] ?? null, 2000 ),
		];
		if ( $row['notes'] !== null && function_exists( 'wp_strip_all_tags' ) ) {
			$row['notes'] = wp_strip_all_tags( $row['notes'] );
		}
		return $row;
	}

	/** Canonical hash: fixed field order + prev link. Never change the order. */
	private static function compute_hash( array $row, string $prev ): string {
		$canonical = [];
		foreach ( self::CONTENT_FIELDS as $f ) {
			$canonical[] = $row[ $f ] ?? null;
		}
		return hash( 'sha256', wp_json_encode( $canonical ) . '|' . $prev );
	}

	//  Enriched auditing & signing (1.4.0) 

	/**
	 * Per-action audit enrichment (Hardening II). Generalises the quarantine
	 * manifest's stored_by/reason pattern: a destructive action records WHO,
	 * WHAT it acted on, the ORIGINAL and NEW values (or pointers to preserved
	 * evidence such as a quarantine id), WHY, and a risk weight - into the
	 * chained store, with a file-log copy for the no-database fallback.
	 *
	 * $ctx keys (all optional): object_type, object_name, original, new,
	 * reason, files (array), risk (int), severity, ip.
	 */
	public static function audit( string $action, array $ctx = [] ): void {
		$parts = [];
		if ( isset( $ctx['reason'] ) && $ctx['reason'] !== '' )     { $parts[] = 'reason: ' . $ctx['reason']; }
		if ( isset( $ctx['original'] ) && $ctx['original'] !== '' ) { $parts[] = 'original: ' . $ctx['original']; }
		if ( isset( $ctx['new'] ) && $ctx['new'] !== '' )           { $parts[] = 'new: ' . $ctx['new']; }
		if ( ! empty( $ctx['files'] ) && is_array( $ctx['files'] ) ) {
			$parts[] = 'files: ' . implode( ', ', array_map( 'strval', array_slice( $ctx['files'], 0, 20 ) ) );
		}
		$notes = implode( '; ', $parts );

		$fields = [
			'event_type'  => $action,
			'action'      => $action,
			'object_type' => $ctx['object_type'] ?? null,
			'object_name' => $ctx['object_name'] ?? null,
			'severity'    => $ctx['severity'] ?? 'notice',
			'risk_score'  => isset( $ctx['risk'] ) ? (int) $ctx['risk'] : null,
			'notes'       => $notes !== '' ? $notes : null,
		];
		if ( isset( $ctx['ip'] ) && $ctx['ip'] !== '' ) {
			$fields['ip'] = $ctx['ip'];
		}
		self::record( $fields );

		if ( class_exists( 'WPS_Logger' ) && method_exists( 'WPS_Logger', 'file_event' ) ) {
			$obj = (string) ( $ctx['object_name'] ?? '' );
			WPS_Logger::file_event( $action, trim( $obj . ( $notes !== '' ? ' - ' . $notes : '' ) ), (string) ( $ctx['ip'] ?? '' ) );
		}
	}

	/**
	 * Sign an export payload under the per-install chain key. Returns the
	 * signature block to embed beside the payload: verify by recomputing the
	 * sha256 of the exact payload string and the HMAC of that hash.
	 */
	public static function sign( string $payload ): array {
		$sha = hash( 'sha256', $payload );
		return [
			'signed_at'      => gmdate( 'Y-m-d H:i:s' ) . ' UTC',
			'plugin_version' => defined( 'WPS_VERSION' ) ? WPS_VERSION : '',
			'algorithm'      => 'sha256 + hmac-sha256 (per-install chain key)',
			'sha256'         => $sha,
			'hmac'           => hash_hmac( 'sha256', $sha, self::hmac_key() ),
		];
	}

	//  Reading & verification 

	/** Newest-first rows for the Events tab. @return array<int, array> */
	public static function latest( int $n = 200 ): array {
		if ( ! self::available() ) {
			return [];
		}
		$db   = self::db();
		$rows = $db->get_results(
			$db->prepare( 'SELECT * FROM ' . self::table() . ' ORDER BY id DESC LIMIT %d', max( 1, $n ) ),
			'ARRAY_A'
		);
		return is_array( $rows ) ? $rows : [];
	}

	/**
	 * Walk the chain oldest-first and recompute every link.
	 *
	 * @return array{status:string, verified:int, pre_chain:int, total:int,
	 *               first_bad_id:?int, head_matches_anchor:bool,
	 *               truncation_suspected:bool}
	 */
	public static function verify_chain(): array {
		$out = [
			'status' => 'empty', 'verified' => 0, 'pre_chain' => 0, 'total' => 0,
			'first_bad_id' => null, 'head_matches_anchor' => true, 'truncation_suspected' => false,
		];
		if ( ! self::available() ) {
			$out['status'] = 'unavailable';
			return $out;
		}
		$db   = self::db();
		$rows = $db->get_results( 'SELECT * FROM ' . self::table() . ' ORDER BY id ASC', 'ARRAY_A' );
		if ( ! is_array( $rows ) || ! $rows ) {
			return $out;
		}
		$out['total'] = count( $rows );

		$anchor = self::read_anchor();
		$key    = self::hmac_key();
		$prev   = $anchor['genesis'];
		$last   = '';

		foreach ( $rows as $r ) {
			if ( ( $r['hmac_signature'] ?? '' ) === '' ) {
				$out['pre_chain']++;
				continue; // imported pre-chain rows carry no signatures by design
			}
			if ( (string) $r['prev_hash'] !== $prev ) {
				$out['status']       = 'tampered';
				$out['first_bad_id'] = (int) $r['id'];
				return $out;
			}
			$expect = self::compute_hash( $r, $prev );
			if ( ! hash_equals( $expect, (string) $r['curr_hash'] )
				|| ! hash_equals( hash_hmac( 'sha256', $expect, $key ), (string) $r['hmac_signature'] ) ) {
				$out['status']       = 'tampered';
				$out['first_bad_id'] = (int) $r['id'];
				return $out;
			}
			$out['verified']++;
			$prev = (string) $r['curr_hash'];
			$last = $prev;
		}

		$out['head_matches_anchor']  = ( $anchor['head'] === $last );
		$out['truncation_suspected'] = ( ! $out['head_matches_anchor'] ) || ( $anchor['count'] > 0 && $out['verified'] > 0 && $anchor['count'] < $out['verified'] );
		if ( $anchor['count'] > $out['verified'] && $anchor['head'] !== $last ) {
			$out['truncation_suspected'] = true;
		}
		$out['status'] = ( $out['head_matches_anchor'] && ! $out['truncation_suspected'] ) ? 'ok' : 'tampered';
		if ( $out['status'] === 'tampered' && $out['first_bad_id'] === null ) {
			// links all close internally but the head disagrees with the anchors:
			// rows were removed from the tail (or the whole table was rebuilt).
			$out['first_bad_id'] = 0;
		}
		return $out;
	}

	//  Rotation & migration 

	/** Rotate oldest rows out past MAX_ROWS, re-anchoring genesis so the surviving window still verifies. */
	private static function maybe_prune(): void {
		$db    = self::db();
		$count = (int) $db->get_var( 'SELECT COUNT(*) FROM ' . self::table() );
		if ( $count <= self::MAX_ROWS ) {
			return;
		}
		self::prune( self::MAX_ROWS );
	}

	/** Keep the newest $keep rows. Public for the fixture harness. */
	public static function prune( int $keep ): void {
		$db   = self::db();
		$keep = max( 1, $keep );
		$edge = $db->get_var( $db->prepare( 'SELECT id FROM ' . self::table() . ' ORDER BY id DESC LIMIT 1 OFFSET %d', $keep - 1 ) );
		if ( $edge === null ) {
			return;
		}
		$oldest = $db->get_row( $db->prepare( 'SELECT prev_hash FROM ' . self::table() . ' WHERE id = %d', (int) $edge ), 'ARRAY_A' );
		$db->query( $db->prepare( 'DELETE FROM ' . self::table() . ' WHERE id < %d', (int) $edge ) );
		$anchor            = self::read_anchor();
		$anchor['genesis'] = is_array( $oldest ) ? (string) $oldest['prev_hash'] : '';
		self::write_anchor( $anchor );
	}

	/**
	 * One-time import of the legacy 200-entry file log. Imported rows carry
	 * empty prev/curr/hmac and a pre-chain note: they are preserved evidence,
	 * counted separately by verify_chain(), never claimed as verified.
	 */
	public static function migrate_legacy(): void {
		if ( ! function_exists( 'get_option' ) || get_option( 'wps_events_migrated', '' ) === '1' ) {
			return;
		}
		update_option( 'wps_events_migrated', '1', false );
		if ( ! class_exists( 'WPS_Logger' ) || ! method_exists( 'WPS_Logger', 'read_events' ) ) {
			return;
		}
		$db     = self::db();
		$legacy = WPS_Logger::read_events();
		foreach ( $legacy as $ev ) {
			if ( ! is_array( $ev ) ) {
				continue;
			}
			$ts = isset( $ev['time'] ) ? substr( str_replace( ' UTC', '', (string) $ev['time'] ), 0, 19 ) : gmdate( 'Y-m-d H:i:s' );
			$db->insert( self::table(), [
				'ts'             => $ts,
				'event_type'     => substr( (string) ( $ev['type'] ?? '' ), 0, 64 ),
				'ip'             => substr( (string) ( $ev['ip'] ?? '' ), 0, 45 ),
				'severity'       => 'info',
				'notes'          => substr( (string) ( $ev['subject'] ?? '' ), 0, 2000 ),
				'object_name'    => 'pre-chain import from file log',
				'prev_hash'      => '',
				'curr_hash'      => '',
				'hmac_signature' => '',
			] );
		}
	}
}
