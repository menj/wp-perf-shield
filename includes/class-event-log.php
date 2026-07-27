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
		$db = self::db();
		return $db ? $db->prefix . 'wps_events' : 'wp_wps_events';
	}

	/** True when the DB is reachable and the table exists (creating it on first call). */
	public static function available(): bool {
		$db = self::db();
		if ( ! $db || ! function_exists( 'get_option' ) ) {
			return false;
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
		update_option( 'wps_events_schema', self::SCHEMA_VERSION, false );
		self::migrate_legacy();
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

	/** @return array{head: string, count: int, genesis: string} */
	private static function read_anchor(): array {
		$default = [ 'head' => '', 'count' => 0, 'genesis' => '' ];
		$opt = function_exists( 'get_option' ) ? get_option( 'wps_event_chain', null ) : null;
		if ( is_array( $opt ) && isset( $opt['head'], $opt['count'], $opt['genesis'] ) ) {
			return [ 'head' => (string) $opt['head'], 'count' => (int) $opt['count'], 'genesis' => (string) $opt['genesis'] ];
		}
		$file = self::anchor_file();
		if ( $file && is_file( $file ) ) {
			$disk = json_decode( self::read_guarded( $file ), true );
			if ( is_array( $disk ) && isset( $disk['head'], $disk['count'], $disk['genesis'] ) ) {
				return [ 'head' => (string) $disk['head'], 'count' => (int) $disk['count'], 'genesis' => (string) $disk['genesis'] ];
			}
		}
		return $default;
	}

	private static function write_anchor( array $anchor ): void {
		if ( function_exists( 'update_option' ) ) {
			update_option( 'wps_event_chain', $anchor, false );
		}
		$file = self::anchor_file();
		if ( $file ) {
			self::write_guarded( $file, (string) wp_json_encode( $anchor ) );
		}
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

		$anchor            = self::read_anchor();
		$row['prev_hash']  = $anchor['head'];
		$row['curr_hash']  = self::compute_hash( $row, $row['prev_hash'] );
		$row['hmac_signature'] = hash_hmac( 'sha256', $row['curr_hash'], self::hmac_key() );

		$ok = $db->insert( self::table(), $row );
		if ( $ok === false ) {
			return null;
		}
		$id = (int) $db->insert_id;

		$anchor['head']  = $row['curr_hash'];
		$anchor['count'] = $anchor['count'] + 1;
		self::write_anchor( $anchor );

		self::maybe_prune();
		return $id;
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
