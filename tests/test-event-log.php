<?php
/**
 * Regression test for the event store's append lock and self-test scratch space (1.4.153).
 *
 * Run from the command line only:  php tests/test-event-log.php
 *
 * A GET_LOCK timeout means another appender holds the lock; the append must be refused rather
 * than fall through to a row lock the holder does not take, which forked the chain. A database
 * with no advisory locks still uses the row lock. A self-test drops a leftover scratch table before
 * it starts, and every run gets a namespace of its own.
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}
define( 'ABSPATH', '/x/' );
define( 'WP_CONTENT_DIR', sys_get_temp_dir() . '/wps-el-' . bin2hex( random_bytes( 4 ) ) );
mkdir( WP_CONTENT_DIR, 0777, true );
$GLOBALS['opts'] = [ 'wps_events_schema' => 1, 'wps_event_hmac_key' => str_repeat( 'a', 64 ) ];
function get_option( $k, $d = false ) { return $GLOBALS['opts'][ $k ] ?? $d; }
function update_option( $k, $v, $a = null ) { $GLOBALS['opts'][ $k ] = $v; return true; }
function delete_option( $k ) { unset( $GLOBALS['opts'][ $k ] ); return true; }
function wp_json_encode( $v ) { return json_encode( $v ); }
function wp_get_current_user() { return (object) [ 'ID' => 1, 'user_login' => 'op', 'roles' => [ 'administrator' ] ]; }
function wp_unslash( $v ) { return $v; }
class WPS_Logger {
	public static $lines   = [];
	public static $forward = 0; // calls that would re-enter WPS_Event_Log::record() in WordPress
	public static function write( $m ) { ++self::$forward; self::log_event( 'debug', $m ); }
	public static function log_event( $t, $s, $ip = '' ) { ++self::$forward; if ( self::$forward < 5 ) { WPS_Event_Log::record( [ 'event_type' => $t, 'notes' => $s ] ); } }
	public static function file_event( $t, $s, $ip = '' ) { self::$lines[] = $t . ': ' . $s; }
}
class FakeDB {
	public $prefix     = 'wp_';
	public $insert_id  = 0;
	public $queries    = [];
	public $lock       = '1'; // what GET_LOCK answers: '1' granted, '0' timed out, null unsupported
	public $last_error = '';
	public $rows       = 0;   // rows in the table
	public $tbl        = [];  // the table itself, oldest first; every row carries its id
	public $auto       = 0;
	public $fail_on    = 0;   // 1.4.159: make the Nth insert from now fail (1 = the next one)
	public function prepare( $sql, ...$a ) { foreach ( $a as $x ) { $sql = preg_replace( '/%[sd]/', is_int( $x ) ? (string) $x : "'" . addslashes( (string) $x ) . "'", $sql, 1 ); } return $sql; }
	public function sync() { $this->rows = count( $this->tbl ); }
	private function chained() { return array_values( array_filter( $this->tbl, static fn( $r ) => '' !== (string) ( $r['curr_hash'] ?? '' ) ) ); }
	public function get_var( $sql ) {
		$this->queries[] = $sql;
		if ( false !== strpos( $sql, 'GET_LOCK' ) ) { return $this->lock; }
		if ( preg_match( "/WHERE curr_hash = '([0-9a-f]+)'/", $sql, $m ) ) { return (string) count( array_filter( $this->tbl, static fn( $r ) => ( $r['curr_hash'] ?? '' ) === $m[1] ) ); }
		if ( false !== strpos( $sql, 'SELECT curr_hash' ) ) { $c = $this->chained(); return [] === $c ? null : end( $c )['curr_hash']; }
		if ( false !== strpos( $sql, 'COUNT(*)' ) ) { return (string) ( false !== strpos( $sql, "curr_hash <> ''" ) ? count( $this->chained() ) : count( $this->tbl ) ); }
		if ( preg_match( '/SELECT id FROM .* OFFSET (\d+)/', $sql, $m ) ) { $ids = array_reverse( array_column( $this->tbl, 'id' ) ); return isset( $ids[ (int) $m[1] ] ) ? (string) $ids[ (int) $m[1] ] : null; }
		return null;
	}
	public function get_row( $sql, $o = null ) {
		$this->queries[] = $sql;
		if ( preg_match( '/WHERE id = (\d+)/', $sql, $m ) ) { foreach ( $this->tbl as $r ) { if ( (int) $r['id'] === (int) $m[1] ) { return $r; } } }
		return null;
	}
	public function get_results( $sql, $o = null ) { $this->queries[] = $sql; return $this->tbl; }
	public function query( $sql ) {
		$this->queries[] = $sql;
		if ( preg_match( '/^DELETE FROM \S+ WHERE id < (\d+)/', $sql, $m ) ) { $this->tbl = array_values( array_filter( $this->tbl, static fn( $r ) => (int) $r['id'] >= (int) $m[1] ) ); $this->sync(); }
		return 1;
	}
	public function insert( $table, $row ) {
		$this->queries[] = 'INSERT INTO ' . $table;
		if ( $this->fail_on > 0 && 0 === --$this->fail_on ) { return false; }
		$row['id'] = ++$this->auto;
		$this->tbl[] = $row;
		$this->insert_id = $row['id'];
		$this->sync();
		return 1;
	}
	public function get_charset_collate() { return ''; }
}
$wpdb = new FakeDB();
require dirname( __DIR__ ) . '/includes/class-event-log.php';
require dirname( __DIR__ ) . '/includes/class-chain-selftest.php';

$fail = 0;
function check( string $name, bool $ok, string $detail = '' ): void {
	global $fail;
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $name . ( $ok ? '' : ' :: ' . $detail ) . "\n";
	if ( ! $ok ) {
		++$fail;
	}
}
function q( string $needle ): int { global $wpdb; return count( array_filter( $wpdb->queries, static fn( $s ) => false !== strpos( $s, $needle ) ) ); }

// ---- 1. the lock is granted: one GET_LOCK, an INSERT, a RELEASE_LOCK.
$wpdb->lock = '1';
$id = WPS_Event_Log::record( [ 'event_type' => 'probe', 'severity' => 'info' ] );
check( 'with the advisory lock granted the event is appended', 1 === $id && 1 === q( 'INSERT INTO wp_wps_events' ) && 0 === q( 'FOR UPDATE' ), json_encode( $wpdb->queries ) );

// ---- 2. the lock times out: another appender holds it. Wait once more, then refuse; never the row lock.
$wpdb->queries = [];
$wpdb->lock    = '0';
$id = WPS_Event_Log::record( [ 'event_type' => 'probe', 'severity' => 'info' ] );
check( 'a held advisory lock is waited for a second time', 2 === q( 'GET_LOCK' ), json_encode( $wpdb->queries ) );
check( 'and then the append is refused rather than forking the chain', null === $id && 0 === q( 'INSERT INTO' ) && 0 === q( 'FOR UPDATE' ) && 0 === q( 'START TRANSACTION' ), json_encode( $wpdb->queries ) );
check( 'the refusal is written to the file log', 1 === count( array_filter( WPS_Logger::$lines, static fn( $l ) => false !== strpos( $l, 'refused' ) ) ), json_encode( WPS_Logger::$lines ) );
check( 'and never through the logger path that re-enters record() (it recursed while the lock was held)', 0 === WPS_Logger::$forward && 2 === q( 'GET_LOCK' ), WPS_Logger::$forward . ' forwards, ' . q( 'GET_LOCK' ) . ' lock queries' );

// ---- 3. no advisory locks at all: the row lock is the only serialisation there is, and it is used.
$wpdb->queries = [];
$wpdb->lock    = null;
$id = WPS_Event_Log::record( [ 'event_type' => 'probe', 'severity' => 'info' ] );
check( 'a database without GET_LOCK uses the row-lock transaction and appends', null !== $id && 1 === q( 'FOR UPDATE' ) && 1 === q( 'INSERT INTO' ) && 1 === q( 'COMMIT' ), json_encode( $wpdb->queries ) );

// ---- 3b. NULL that came with a query error is not "unsupported": refuse, do not fork.
$wpdb->queries    = [];
$wpdb->lock       = null;
$wpdb->last_error = 'Lock wait timeout exceeded';
$id = WPS_Event_Log::record( [ 'event_type' => 'probe', 'severity' => 'info' ] );
check( 'a failed GET_LOCK query refuses the append rather than taking the row lock', null === $id && 0 === q( 'FOR UPDATE' ) && 0 === q( 'INSERT INTO' ), json_encode( $wpdb->queries ) );
$wpdb->last_error = '';

// ---- 3c. rows removed from the log are recorded, not forgotten, by the next append (1.4.159).
function fresh_db(): FakeDB {
	global $wpdb;
	$wpdb = new FakeDB();
	$GLOBALS['opts'] = [ 'wps_events_schema' => 1, 'wps_event_hmac_key' => str_repeat( 'a', 64 ) ];
	WPS_Logger::$lines = [];
	return $wpdb;
}
function anchor(): array { return $GLOBALS['opts']['wps_event_chain'] ?? []; }
function types(): array { global $wpdb; return array_column( $wpdb->tbl, 'event_type' ); }
function break_lines(): int { return count( array_filter( WPS_Logger::$lines, static fn( $l ) => 0 === strpos( $l, 'chain_break_detected:' ) ) ); }

$wpdb = fresh_db();
foreach ( [ 1, 2, 3 ] as $i ) { WPS_Event_Log::record( [ 'event_type' => 'probe' . $i, 'severity' => 'info' ] ); }
$v = WPS_Event_Log::verify_chain();
check( 'three appends anchor the chain at the third, and the chain really verifies', 3 === $wpdb->rows && anchor()['head'] === $wpdb->tbl[2]['curr_hash'] && 3 === anchor()['count'] && 2 === anchor()['v'] && 'ok' === $v['status'] && 3 === $v['verified'] && 0 === $v['breaks'], json_encode( [ anchor(), $v ] ) );

// the two newest rows are deleted
array_splice( $wpdb->tbl, 1 ); $wpdb->rows = 1;
$wpdb->queries = [];
WPS_Event_Log::record( [ 'event_type' => 'probe4', 'severity' => 'info' ] );
check( 'the next append writes the break as a signed event of its own, then the new event', [ 'probe1', 'chain_break_detected', 'probe4' ] === types() && 2 === q( 'INSERT INTO wp_wps_events' ), json_encode( types() ) );
$v = WPS_Event_Log::verify_chain();
check( 'the anchor counts the break and keeps its details; the chain closes and verify_chain() still reports the break', 1 === anchor()['breaks'] && false !== strpos( (string) ( anchor()['last_break']['detail'] ?? '' ), 'removed from the end of the log' ) && 'ok' === $v['status'] && 3 === $v['verified'] && 1 === $v['breaks'], json_encode( [ anchor(), $v ] ) );
check( 'the break is mirrored to the file log', 1 === break_lines(), json_encode( WPS_Logger::$lines ) );

// an append whose anchor write was lost: a newer chained row exists that the anchor does not know
$wpdb->tbl[] = [ 'id' => ++$wpdb->auto, 'event_type' => 'orphan', 'curr_hash' => str_repeat( 'f', 64 ), 'prev_hash' => $wpdb->tbl[2]['curr_hash'] ]; $wpdb->rows = count( $wpdb->tbl );
$wpdb->queries = [];
WPS_Event_Log::record( [ 'event_type' => 'probe5', 'severity' => 'info' ] );
check( 'a lost anchor write is healed quietly, not reported as a break', 1 === q( 'INSERT INTO wp_wps_events' ) && 1 === anchor()['breaks'] && 1 === break_lines(), json_encode( [ types(), anchor()['breaks'] ] ) );

// 1.4.159 review: an OLDER row removed while the newest is still there
$wpdb = fresh_db();
foreach ( [ 1, 2, 3 ] as $i ) { WPS_Event_Log::record( [ 'event_type' => 'probe' . $i ] ); }
array_splice( $wpdb->tbl, 0, 1 ); $wpdb->rows = 2; // the oldest row is deleted, the head is untouched
WPS_Event_Log::record( [ 'event_type' => 'probe4' ] );
check( 'removing an older row is recorded as a break although the head still matches', in_array( 'chain_break_detected', types(), true ) && 1 === anchor()['breaks'] && false !== strpos( (string) anchor()['last_break']['detail'], 'older records were removed' ), json_encode( [ types(), anchor() ] ) );
$wpdb = fresh_db();
foreach ( [ 1, 2, 3 ] as $i ) { WPS_Event_Log::record( [ 'event_type' => 'probe' . $i ] ); }
$GLOBALS['opts']['wps_event_chain']['v'] = 0; // an anchor an earlier version wrote: its count may be stale after a prune
array_splice( $wpdb->tbl, 0, 1 ); $wpdb->rows = 2;
WPS_Event_Log::record( [ 'event_type' => 'probe4' ] );
check( 'an anchor from an earlier version is upgraded quietly rather than trusted for its count', ! in_array( 'chain_break_detected', types(), true ) && 2 === anchor()['v'], json_encode( [ types(), anchor() ] ) );

// 1.4.159 review: the break row is written but the event row after it fails
$wpdb = fresh_db();
foreach ( [ 1, 2, 3 ] as $i ) { WPS_Event_Log::record( [ 'event_type' => 'probe' . $i ] ); }
array_splice( $wpdb->tbl, 1 ); $wpdb->rows = 1;
$wpdb->fail_on = 2; // the break insert (1) succeeds, the event insert (2) fails
$id = WPS_Event_Log::record( [ 'event_type' => 'probe4' ] );
check( 'a failed event insert after a written break still moves the anchor onto the break', null === $id && [ 'probe1', 'chain_break_detected' ] === types() && anchor()['head'] === $wpdb->tbl[1]['curr_hash'] && 1 === anchor()['breaks'], json_encode( [ types(), anchor() ] ) );
WPS_Event_Log::record( [ 'event_type' => 'probe5' ] );
check( 'so the next append does not record the same truncation again', 1 === count( array_keys( types(), 'chain_break_detected', true ) ) && 1 === anchor()['breaks'], json_encode( types() ) );

// 1.4.159 review: the break insert fails but the event insert succeeds
$wpdb = fresh_db();
foreach ( [ 1, 2, 3 ] as $i ) { WPS_Event_Log::record( [ 'event_type' => 'probe' . $i ] ); }
array_splice( $wpdb->tbl, 1 ); $wpdb->rows = 1;
$wpdb->fail_on = 1; // the break insert fails
WPS_Event_Log::record( [ 'event_type' => 'probe4' ] );
check( 'a break that could not be written is not claimed in the anchor, and the file log still holds it', [ 'probe1', 'probe4' ] === types() && 0 === anchor()['breaks'] && null === ( anchor()['last_break'] ?? null ) && 1 === break_lines(), json_encode( [ types(), anchor(), WPS_Logger::$lines ] ) );

// 1.4.159 review: a prune that really removes rows
$wpdb = fresh_db();
foreach ( [ 1, 2, 3, 4, 5, 6 ] as $i ) { WPS_Event_Log::record( [ 'event_type' => 'probe' . $i ] ); }
WPS_Event_Log::prune( 2 );
$v = WPS_Event_Log::verify_chain();
check( 'a prune keeps the newest rows, lowers the anchored count with the table, and the surviving window verifies', 2 === count( $wpdb->tbl ) && [ 'probe5', 'probe6' ] === types() && 2 === anchor()['count'] && 'ok' === $v['status'] && 2 === $v['verified'], json_encode( [ types(), anchor(), $v ] ) );
WPS_Event_Log::record( [ 'event_type' => 'probe7' ] );
check( 'and the next append after a prune sees no break', ! in_array( 'chain_break_detected', types(), true ) && 0 === anchor()['breaks'], json_encode( [ types(), anchor() ] ) );

// ---- 4. the self-test drops a leftover scratch table before creating its own, and ends cleanly.
$wpdb->queries = [];
$wpdb->lock    = '1';
check( 'the scratch namespace is accepted', WPS_Event_Log::begin_selftest( 'p0123456789abcde' ) );
$drop_i   = array_search( 'DROP TABLE IF EXISTS wp_wps_events_st_p0123456789abcde', $wpdb->queries, true );
$create_i = null;
foreach ( $wpdb->queries as $i => $s ) { if ( 0 === strpos( $s, 'CREATE TABLE IF NOT EXISTS wp_wps_events_st_p0123456789abcde' ) ) { $create_i = $i; break; } }
check( 'a leftover scratch table is dropped before the scratch table is created', false !== $drop_i && null !== $create_i && $drop_i < $create_i, json_encode( $wpdb->queries ) );
check( 'the scratch table is the one in use', 'wp_wps_events_st_p0123456789abcde' === WPS_Event_Log::table() );
WPS_Event_Log::end_selftest();
check( 'ending the self-test drops the scratch table and returns to the real one', 2 === q( 'DROP TABLE IF EXISTS wp_wps_events_st_p0123456789abcde' ) && 'wp_wps_events' === WPS_Event_Log::table() );

// ---- 5. every self-test run gets a namespace of its own.
$m = new ReflectionMethod( 'WPS_Chain_Selftest', 'namespace_for_run' );
$m->setAccessible( true );
$a = $m->invoke( null );
$b = $m->invoke( null );
check( 'two runs use two namespaces, both within the store\'s naming rule', $a !== $b && 1 === preg_match( '/^[a-z0-9]{1,16}$/', $a ) && 1 === preg_match( '/^[a-z0-9]{1,16}$/', $b ), $a . ' ' . $b );

exec( 'rm -rf ' . escapeshellarg( WP_CONTENT_DIR ) );
echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
