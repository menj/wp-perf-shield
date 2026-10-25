<?php
/**
 * Regression test for WPS_Scan_Lock (1.4.152): a stale lock is released only if it is still the
 * stale value, so a lock another request has just re-acquired is never deleted from under it.
 *
 * Run from the command line only:  php tests/test-scan-lock.php
 *
 * The options table is a small in-memory stand-in whose DELETE honours a WHERE on option_value.
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}
define( 'ABSPATH', '/x/' );
function wp_json_encode( $v ) { return json_encode( $v ); }
class WPS_Logger { public static function write( $m ) { $GLOBALS['log'][] = $m; } }
$GLOBALS['log'] = [];

class FakeDB {
	public $options = 'wp_options';
	public $rows    = [];
	public $queries = [];
	public $between = null; // callable run between a SELECT and the next statement, to simulate another worker
	public function prepare( $sql, ...$args ) {
		foreach ( $args as $a ) {
			$sql = preg_replace( '/%[sd]/', is_int( $a ) ? (string) $a : "'" . addslashes( (string) $a ) . "'", $sql, 1 );
		}
		return $sql;
	}
	public function get_var( $sql ) {
		$this->queries[] = $sql;
		preg_match( "/option_name = '([^']+)'/", $sql, $m );
		$v = $this->rows[ $m[1] ] ?? null;
		if ( $this->between ) { ( $this->between )( $this ); $this->between = null; }
		return $v;
	}
	public function query( $sql ) {
		$this->queries[] = $sql;
		if ( preg_match( "/^INSERT INTO \S+ \(option_name, option_value, autoload\) VALUES \('([^']+)', '((?:[^'\\\\]|\\\\.)*)'/", $sql, $m ) ) {
			if ( isset( $this->rows[ $m[1] ] ) ) { return 0; }
			$this->rows[ $m[1] ] = stripslashes( $m[2] );
			return 1;
		}
		if ( preg_match( "/^DELETE FROM \S+ WHERE option_name = '([^']+)'(?: AND option_value = '((?:[^'\\\\]|\\\\.)*)')?/", $sql, $m ) ) {
			if ( ! isset( $this->rows[ $m[1] ] ) ) { return 0; }
			if ( isset( $m[2] ) && $this->rows[ $m[1] ] !== stripslashes( $m[2] ) ) { return 0; }
			unset( $this->rows[ $m[1] ] );
			return 1;
		}
		return 0;
	}
}
$wpdb = new FakeDB();
require dirname( __DIR__ ) . '/includes/class-scan-lock.php';

$fail = 0;
function check( string $name, bool $ok, string $detail = '' ): void {
	global $fail;
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $name . ( $ok ? '' : ' :: ' . $detail ) . "\n";
	if ( ! $ok ) {
		++$fail;
	}
}

// ---- the plain path
$t1 = WPS_Scan_Lock::acquire( 'scan' );
check( 'the lock is acquired', is_string( $t1 ) && isset( $wpdb->rows['wps_scan_lock'] ) );
check( 'a second acquire while held fails', null === WPS_Scan_Lock::acquire( 'scan' ) );
check( 'release by the owner frees it', WPS_Scan_Lock::release( $t1 ) && ! isset( $wpdb->rows['wps_scan_lock'] ) );
check( 'release of a token nobody holds is refused', ! WPS_Scan_Lock::release( 'nope' ) );

// ---- the race: request A reads an expired lock; before it deletes, request B releases the stale
// lock itself and acquires a fresh one. A's delete must not remove B's lock.
$wpdb->rows['wps_scan_lock'] = json_encode( [ 'token' => 'old', 'context' => 'scan', 'acquired' => time() - 2000, 'expires' => time() - 1000, 'pid' => 1 ] );
$fresh = null;
$wpdb->between = static function ( FakeDB $db ) use ( &$fresh ) {
	unset( $db->rows['wps_scan_lock'] ); // B released the stale lock
	$fresh = json_encode( [ 'token' => 'fresh', 'context' => 'scan', 'acquired' => time(), 'expires' => time() + 900, 'pid' => 2 ] );
	$db->rows['wps_scan_lock'] = $fresh; // and acquired its own
};
$t2 = WPS_Scan_Lock::acquire( 'scan' );
check( 'request A does not win the lock when B got there first', null === $t2 );
check( 'and B\'s fresh lock survives A\'s stale-release attempt', ( $wpdb->rows['wps_scan_lock'] ?? null ) === $fresh, json_encode( $wpdb->rows ) );
$deletes = array_values( array_filter( $wpdb->queries, static fn( $q ) => 0 === strpos( $q, 'DELETE' ) ) );
check( 'the stale release is conditional on the value it read', [] !== $deletes && false !== strpos( end( $deletes ), 'AND option_value =' ), json_encode( $deletes ) );
check( 'nothing was logged as released, because nothing was', [] === array_filter( $GLOBALS['log'], static fn( $m ) => false !== strpos( $m, 'stale' ) ), json_encode( $GLOBALS['log'] ) );

// ---- the same race on release(): owner A reads its own lock, B expires and replaces it, A's delete must miss.
$wpdb->rows = [];
$t3 = WPS_Scan_Lock::acquire( 'scan' );
$wpdb->between = static function ( FakeDB $db ) use ( &$fresh ) {
	$db->rows['wps_scan_lock'] = $fresh;
};
WPS_Scan_Lock::release( $t3 );
check( 'an owner releasing after its lock was replaced leaves the new lock alone', ( $wpdb->rows['wps_scan_lock'] ?? null ) === $fresh );

// ---- an actually stale lock is still released and the release logged.
$wpdb->rows['wps_scan_lock'] = json_encode( [ 'token' => 'old', 'context' => 'scan', 'acquired' => time() - 2000, 'expires' => time() - 1000, 'pid' => 1 ] );
$t4 = WPS_Scan_Lock::acquire( 'scan' );
check( 'a genuinely stale lock is released and re-acquired', is_string( $t4 ) && [] !== array_filter( $GLOBALS['log'], static fn( $m ) => false !== strpos( $m, 'stale' ) ) );

echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
