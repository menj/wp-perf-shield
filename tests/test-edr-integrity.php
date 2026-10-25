<?php
/**
 * Regression test for two attribution gaps from the 1.4.152 review.
 *
 * Run from the command line only:  php tests/test-edr-integrity.php
 *
 * 1. WPS_EDR::on_upgrader_complete() attributed a plugin to the roster on an UPDATE as well as an
 *    install, so a folder planted on disk became "installed through the upgrader" the moment
 *    WordPress auto-updated it.
 * 2. WPS_Integrity::determine() matched the path against a literal wp-content/plugins/ under
 *    ABSPATH, so a renamed or relocated content directory made every verdict UNKNOWN and the
 *    foreign-file detector inert. Here the plugins directory sits outside ABSPATH entirely.
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}
$tmp = sys_get_temp_dir() . '/wps-ei-' . bin2hex( random_bytes( 4 ) );
mkdir( $tmp . '/site', 0777, true );
mkdir( $tmp . '/app/plugins/wps-self', 0777, true ); // Bedrock-style: plugins outside ABSPATH
define( 'ABSPATH', $tmp . '/site/' );
define( 'WPS_DIR', $tmp . '/app/plugins/wps-self/' );
define( 'WPS_OPTION', 'wps_opts' );
define( 'WP_CONTENT_DIR', $tmp . '/app' );
define( 'WP_PLUGIN_DIR', $tmp . '/app/plugins' );
define( 'WPMU_PLUGIN_DIR', $tmp . '/app/mu-plugins' );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'DAY_IN_SECONDS', 86400 );

$GLOBALS['opts']  = [];
$GLOBALS['trans'] = [];
function get_option( $k, $d = false ) { return $GLOBALS['opts'][ $k ] ?? $d; }
function update_option( $k, $v, $a = null ) { $GLOBALS['opts'][ $k ] = $v; return true; }
function get_transient( $k ) { return $GLOBALS['trans'][ $k ] ?? false; }
function set_transient( $k, $v, $t = 0 ) { $GLOBALS['trans'][ $k ] = $v; return true; }
function delete_transient( $k ) { unset( $GLOBALS['trans'][ $k ] ); return true; }
function apply_filters( $t, $v ) { return $v; }
function add_action() {}
function add_filter() {}
function wp_json_encode( $v ) { return json_encode( $v ); }
function wp_remote_get() { return new WP_Error( 'offline', 'no network in tests' ); }
function is_wp_error( $t ) { return $t instanceof WP_Error; }
function wp_normalize_path( $p ) { return str_replace( '\\', '/', $p ); }
function get_theme_root() { return ABSPATH . 'themes'; }
function get_current_user_id() { return 0; }
class WP_Error { public $code; public $message; public function __construct( $c = '', $m = '' ) { $this->code = $c; $this->message = $m; } }
class WPS_Logger {
	public static function log_event( $t, $s, $ip = '' ) {}
	public static function write( $m ) {}
	public static function notify_admin( $a, $b ) {}
}
class WPS_Event_Log {
	public static $rows = [];
	public static function available(): bool { return false; }
	public static function table(): string { return 'wp_wps_events'; }
	public static function record( array $f ): ?int { self::$rows[] = $f; return count( self::$rows ); }
}

require dirname( __DIR__ ) . '/includes/class-wps-utils.php';
require dirname( __DIR__ ) . '/includes/class-scanner.php';
require dirname( __DIR__ ) . '/includes/class-edr.php';
require dirname( __DIR__ ) . '/includes/class-integrity.php';

$fail = 0;
function check( string $name, bool $ok, string $detail = '' ): void {
	global $fail;
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $name . ( $ok ? '' : ' :: ' . $detail ) . "\n";
	if ( ! $ok ) {
		++$fail;
	}
}
function put( string $p, string $c ): void {
	@mkdir( dirname( $p ), 0777, true );
	file_put_contents( $p, $c );
}
$P = WP_PLUGIN_DIR;

// ---- 1. upgrader attribution: installs only.
put( $P . '/planted/planted.php', "<?php\n/* Plugin Name: Planted\nVersion: 1.0 */\n" );
WPS_EDR::on_upgrader_complete( null, [ 'type' => 'plugin', 'action' => 'update', 'plugins' => [ 'planted/planted.php' ] ] );
$roster = get_option( WPS_Scanner::ROSTER_OPTION, [] );
check( 'an update through the upgrader does not attribute the folder as installed', ! isset( $roster['planted'] ), json_encode( $roster ) );
check( 'the update is still recorded as an event', 1 === count( WPS_Event_Log::$rows ) && false !== strpos( (string) WPS_Event_Log::$rows[0]['notes'], 'updated' ), json_encode( WPS_Event_Log::$rows ) );
WPS_EDR::on_upgrader_complete( null, [ 'type' => 'plugin', 'action' => 'install', 'plugin' => 'planted/planted.php' ] );
$roster = get_option( WPS_Scanner::ROSTER_OPTION, [] );
check( 'an install through the upgrader attributes it', isset( $roster['planted'] ), json_encode( $roster ) );

// ---- 2. integrity verdicts with the plugins directory outside ABSPATH.
put( $P . '/akismet/akismet.php', "<?php\n/* Plugin Name: Akismet\nVersion: 5.3 */\n" );
put( $P . '/akismet/class.akismet.php', "<?php\n// genuine\n" );
put( $P . '/akismet/wp-vcd.php', "<?php\n// dropped in\n" );
$GLOBALS['trans'][ 'wps_pcs_' . md5( 'akismet|5.3' ) ] = [
	'akismet.php'       => [ 'type' => 'sha256', 'hashes' => [ hash_file( 'sha256', $P . '/akismet/akismet.php' ) ] ],
	'class.akismet.php' => [ 'type' => 'sha256', 'hashes' => [ hash( 'sha256', 'different bytes' ) ] ],
];
check( 'a file matching the author manifest is VERIFIED', WPS_Integrity::VERIFIED === WPS_Integrity::verify( $P . '/akismet/akismet.php' ), WPS_Integrity::verify( $P . '/akismet/akismet.php' ) );
check( 'a listed file whose bytes differ is MODIFIED', WPS_Integrity::MODIFIED === WPS_Integrity::verify( $P . '/akismet/class.akismet.php' ), WPS_Integrity::verify( $P . '/akismet/class.akismet.php' ) );
check( 'a file the manifest never mentions is FOREIGN', WPS_Integrity::FOREIGN === WPS_Integrity::verify( $P . '/akismet/wp-vcd.php' ), WPS_Integrity::verify( $P . '/akismet/wp-vcd.php' ) );
check( 'a path outside the plugins directory is UNKNOWN', WPS_Integrity::UNKNOWN === WPS_Integrity::verify( ABSPATH . 'wp-load.php' ) );
check( 'is_official() agrees', WPS_Integrity::is_official( $P . '/akismet/akismet.php' ) && ! WPS_Integrity::is_official( $P . '/akismet/wp-vcd.php' ) );

$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $tmp, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::CHILD_FIRST );
foreach ( $it as $f ) { $f->isDir() ? @rmdir( $f->getPathname() ) : @unlink( $f->getPathname() ); }
@rmdir( $tmp );

echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
