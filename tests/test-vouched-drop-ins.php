<?php
/**
 * Regression test for hash-vouched error-page drop-ins (1.4.165).
 *
 * Run from the command line only:  php tests/test-vouched-drop-ins.php
 *
 * The drop-in below is the one the BMK theme writes as php-error.php: it sends
 * a status, reads a saved page from wp-content and fills in a reference. It is
 * not inert, so before 1.4.165 every scan listed it as an unknown publisher.
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}
$tmp = sys_get_temp_dir() . '/wps-vouch-' . bin2hex( random_bytes( 4 ) );
mkdir( $tmp . '/wp-content/bismika-notices', 0777, true );
define( 'ABSPATH', $tmp . '/' );
define( 'WP_CONTENT_DIR', $tmp . '/wp-content' );
define( 'WPS_DIR', $tmp . '/wp-content/plugins/wp-perf-shield/' );
define( 'WPS_OPTION', 'wps_opts' );
define( 'WP_PLUGIN_DIR', $tmp . '/wp-content/plugins' );
define( 'WPMU_PLUGIN_DIR', $tmp . '/wp-content/mu-plugins' );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'DAY_IN_SECONDS', 86400 );
$GLOBALS['vouch'] = [];
function apply_filters( $t, $v ) { return 'wps_vouched_drop_ins' === $t ? $GLOBALS['vouch'] : $v; }
function get_option( $k, $d = false ) { return $d; }
class WPS_Logger {
	public static function log_event( $t, $s, $ip = '' ) {}
	public static function write( $m ) {}
}
require dirname( __DIR__ ) . '/includes/class-wps-utils.php';
require dirname( __DIR__ ) . '/includes/class-scanner.php';

$fail = 0;
function check( string $name, bool $ok ): void {
	global $fail;
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $name . "\n";
	if ( ! $ok ) {
		++$fail;
	}
}

$dropin = <<<'PHP'
<?php
/* Bismika notice page: written by the Bismika Allahuma theme (BMK). Switching to another theme removes this file. */
defined( 'ABSPATH' ) || exit;
$bismika_file = __DIR__ . '/bismika-notices/500.tpl.html';
$bismika_ref = strtoupper( bin2hex( random_bytes( 4 ) ) );
if ( isset( $error ) && is_array( $error ) ) {
	error_log( sprintf( '[Bismika notice] ref %s: %s in %s on line %d', $bismika_ref, isset( $error['message'] ) ? $error['message'] : '', isset( $error['file'] ) ? $error['file'] : '', isset( $error['line'] ) ? (int) $error['line'] : 0 ) );
}
if ( ! headers_sent() ) {
	header( ( isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.1' ) . ' 500 Internal Server Error', true, 500 );
	header( 'Content-Type: text/html; charset=utf-8' );
	header( 'Cache-Control: no-store, max-age=0' );
}
if ( is_readable( $bismika_file ) ) {
	echo str_replace( '{{BISMIKA_REF}}', $bismika_ref, file_get_contents( $bismika_file ) );
} else {
	echo '<!doctype html><meta charset="utf-8"><title>Bismika Allahuma</title><p>The site is unavailable for a moment.</p>';
}
PHP;
$page = WP_CONTENT_DIR . '/bismika-notices/500.tpl.html';
file_put_contents( $page, '<!doctype html><title>500</title><script src="/wp-content/themes/BMK/assets/js/notice.js"></script><p>{{BISMIKA_REF}}</p>' );
$good = [ 'php-error.php' => [ 'sha256' => hash( 'sha256', $dropin ), 'source' => 'BMK theme', 'reads' => [ $page => hash_file( 'sha256', $page ) ] ] ];
$v = function ( $name, $c ) { return WPS_Scanner::effective_drop_in_publisher( $name, $c ); };

check( 'without a vouch the BMK drop-in is unknown', '' === $v( 'php-error.php', $dropin ) );
$GLOBALS['vouch'] = $good;
check( 'a matching vouch names the source', 'Vouched by BMK theme (sha256 verified)' === $v( 'php-error.php', $dropin ) );
check( 'the vouch is for one name only', '' === WPS_Scanner::vouched_drop_in_publisher( 'maintenance.php', $dropin ) );
check( 'one changed byte voids it', '' === $v( 'php-error.php', $dropin . ' ' ) );

$evil = $dropin . "\nif ( isset( \$_COOKIE['k'] ) ) { eval( \$_COOKIE['k'] ); }\n";
$GLOBALS['vouch'] = [ 'php-error.php' => [ 'sha256' => hash( 'sha256', $evil ), 'source' => 'BMK theme', 'reads' => [] ] ];
check( 'a vouch cannot clear executable code, even with the right hash', '' === $v( 'php-error.php', $evil ) );

$GLOBALS['vouch'] = $good;
file_put_contents( $page, file_get_contents( $page ) . '<script>alert(1)</script>' );
check( 'an edit to the page it serves voids it', '' === $v( 'php-error.php', $dropin ) );

$GLOBALS['vouch'] = [ 'php-error.php' => [ 'sha256' => hash( 'sha256', $dropin ), 'reads' => [ '/etc/hostname' => str_repeat( 'a', 64 ) ] ] ];
check( 'a read outside wp-content voids it', '' === $v( 'php-error.php', $dropin ) );
$php = WP_CONTENT_DIR . '/bismika-notices/x.php';
file_put_contents( $php, '<?php' );
$GLOBALS['vouch'] = [ 'php-error.php' => [ 'sha256' => hash( 'sha256', $dropin ), 'reads' => [ $php => hash_file( 'sha256', $php ) ] ] ];
check( 'a read of a PHP file voids it', '' === $v( 'php-error.php', $dropin ) );
$GLOBALS['vouch'] = [ 'php-error.php' => [ 'sha256' => hash( 'sha256', $dropin ), 'source' => '<b>x</b>"', 'reads' => [] ] ];
check( 'source text is stripped', 'Vouched by x (sha256 verified)' === $v( 'php-error.php', $dropin ) );
$GLOBALS['vouch'] = [ 'php-error.php' => 'nonsense' ];
check( 'a malformed vouch is ignored', '' === $v( 'php-error.php', $dropin ) );

$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $tmp, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::CHILD_FIRST );
foreach ( $it as $f ) {
	$f->isDir() ? @rmdir( $f->getPathname() ) : @unlink( $f->getPathname() );
}
@rmdir( $tmp );
echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
