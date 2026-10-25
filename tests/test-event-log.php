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
class WPS_Logger { public static $lines = []; public static function write( $m ) { self::$lines[] = $m; } public static function log_event( $t, $s, $ip = '' ) {} }
class FakeDB {
	public $prefix    = 'wp_';
	public $insert_id = 0;
	public $queries   = [];
	public $lock      = '1'; // what GET_LOCK answers: '1' granted, '0' timed out, null unsupported
	public $last_error = '';
	public $rows      = 0;
	public function prepare( $sql, ...$a ) { foreach ( $a as $x ) { $sql = preg_replace( '/%[sd]/', is_int( $x ) ? (string) $x : "'" . addslashes( (string) $x ) . "'", $sql, 1 ); } return $sql; }
	public function get_var( $sql ) {
		$this->queries[] = $sql;
		if ( false !== strpos( $sql, 'GET_LOCK' ) ) { return $this->lock; }
		if ( false !== strpos( $sql, 'COUNT(*)' ) ) { return (string) $this->rows; }
		return null;
	}
	public function query( $sql ) { $this->queries[] = $sql; return 1; }
	public function insert( $table, $row ) { $this->queries[] = 'INSERT INTO ' . $table; ++$this->rows; $this->insert_id = $this->rows; return 1; }
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
