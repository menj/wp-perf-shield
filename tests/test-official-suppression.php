<?php
/**
 * A self-concealing finding is not reported for a file identical to its plugin's official release (1.4.148).
 *
 * Run from the command line only:  php tests/test-official-suppression.php
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}
$tmp = sys_get_temp_dir() . '/wps-off-' . bin2hex( random_bytes( 4 ) );
mkdir( $tmp . '/wp-content/plugins/wps-self', 0777, true );
mkdir( $tmp . '/wp-content/mu-plugins', 0777, true );
define( 'ABSPATH', $tmp . '/' );
define( 'WPS_DIR', $tmp . '/wp-content/plugins/wps-self/' );
define( 'WPS_OPTION', 'wps_opts' );
define( 'WP_PLUGIN_DIR', $tmp . '/wp-content/plugins' );
define( 'WPMU_PLUGIN_DIR', $tmp . '/wp-content/mu-plugins' );
define( 'WP_CONTENT_DIR', $tmp . '/wp-content' );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'DAY_IN_SECONDS', 86400 );
$GLOBALS['transients'] = [];
function get_option( $k, $d = false ) { return 'wps_opts' === $k ? [ 'quarantine_enabled' => '0' ] : $d; }
function update_option() { return true; }
function apply_filters( $t, $v ) { return $v; }
function wp_json_encode( $v ) { return json_encode( $v ); }
function get_transient( $k ) { return $GLOBALS['transients'][ $k ] ?? false; }
function set_transient( $k, $v ) { $GLOBALS['transients'][ $k ] = $v; return true; }
function wp_remote_get() { return null; }
function is_wp_error() { return true; }
function add_action() {}
function add_filter() {}
class WPS_Logger {
	public static function log_event() {}
	public static function write( $m ) {}
}
foreach ( glob( dirname( __DIR__ ) . '/includes/class-*.php' ) as $f ) {
	if ( false === strpos( $f, 'blocker' ) && false === strpos( $f, 'class-admin' ) && false === strpos( $f, 'class-logger' ) && false === strpos( $f, 'class-event-log' ) ) {
		require_once $f;
	}
}
$fail = 0;
function check( string $name, bool $ok, string $detail = '' ): void {
	global $fail;
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $name . ( $ok ? '' : ' :: ' . $detail ) . "\n";
	if ( ! $ok ) {
		++$fail;
	}
}
function run(): array {
	// The integrity verdict is memoised per file for the length of a scan; each run here is a new scan.
	$p = new ReflectionProperty( 'WPS_Integrity', 'memo' );
	$p->setAccessible( true );
	$p->setValue( null, [] );
	if ( class_exists( 'WPS_Integrity' ) && method_exists( 'WPS_Integrity', 'reset' ) ) {
		WPS_Integrity::reset(); // each run() is a new scan: the manifest memo is scan-scoped (1.4.153)
	}
	$m = new ReflectionMethod( 'WPS_Scanner', 'check_self_hiding_plugins' );
	$m->setAccessible( true );
	return $m->invoke( null );
}
$code = "<?php\n/* Plugin Name: Hider\n * Version: 1.0\n */\nadd_filter('all_plugins', function (\$p) { unset(\$p[plugin_basename(__FILE__)]); return \$p; });\n";
mkdir( $tmp . '/wp-content/plugins/hider' );
file_put_contents( $tmp . '/wp-content/plugins/hider/hider.php', $code );
$f = run();
check( 'a self-removing plugin with no published release is reported', 1 === count( $f ), (string) count( $f ) );
$key = 'wps_pcs_' . md5( 'hider|1.0' );
$GLOBALS['transients'][ $key ] = [ 'hider.php' => [ 'type' => 'sha256', 'hashes' => [ hash( 'sha256', $code ) ] ] ];
check( 'the same file is not reported when it matches the official release', 0 === count( run() ), json_encode( array_map( static fn( $x ) => $x['subject'], run() ) ) );
$GLOBALS['transients'][ $key ] = [ 'hider.php' => [ 'type' => 'sha256', 'hashes' => [ hash( 'sha256', 'something else' ) ] ] ];
check( 'it is reported when it differs from the official release', 1 === count( run() ) );
exec( 'rm -rf ' . escapeshellarg( $tmp ) );
echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
