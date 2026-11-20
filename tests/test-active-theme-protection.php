<?php
/**
 * Regression test: automatic removal never takes the active theme folder (1.4.164).
 *
 * Run from the command line only:  php tests/test-active-theme-protection.php
 *
 * The all-themes signature walk proposes a whole theme folder for removal. Before 1.4.164
 * is_protected_auto_delete_path() looked at files only, so a folder target passed and one
 * signature string inside the active theme quarantined the site's theme.
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}
$tmp = sys_get_temp_dir() . '/wps-theme-' . bin2hex( random_bytes( 4 ) );
foreach ( [ '/wp-content/themes/BMK/inc', '/wp-content/themes/twentytwentyfive', '/wp-content/themes/config_1791852300' ] as $d ) {
	mkdir( $tmp . $d, 0777, true );
}
define( 'ABSPATH', $tmp . '/' );
define( 'WP_CONTENT_DIR', $tmp . '/wp-content' );
define( 'WPS_DIR', $tmp . '/wp-content/plugins/wp-perf-shield/' );
define( 'WPS_OPTION', 'wps_opts' );
define( 'WP_PLUGIN_DIR', $tmp . '/wp-content/plugins' );
define( 'WPMU_PLUGIN_DIR', $tmp . '/wp-content/mu-plugins' );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'DAY_IN_SECONDS', 86400 );
function get_option( $k, $d = false ) { return $d; }
function apply_filters( $t, $v ) { return $v; }
function get_stylesheet_directory() { return WP_CONTENT_DIR . '/themes/BMK'; }
function get_template_directory() { return WP_CONTENT_DIR . '/themes/twentytwentyfive'; }
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
file_put_contents( WP_CONTENT_DIR . '/themes/BMK/inc/security.php', "<?php\n" );
file_put_contents( WP_CONTENT_DIR . '/themes/BMK/functions.php', "<?php\n" );
file_put_contents( WP_CONTENT_DIR . '/themes/config_1791852300/functlons.php', "<?php\n" );

$m = new ReflectionMethod( 'WPS_Scanner', 'is_protected_auto_delete_path' );
$m->setAccessible( true );
$p = function ( $path ) use ( $m ) { return $m->invoke( null, $path ); };

check( 'active child theme folder is protected', $p( WP_CONTENT_DIR . '/themes/BMK' ) );
check( 'active parent theme folder is protected', $p( WP_CONTENT_DIR . '/themes/twentytwentyfive' ) );
check( 'the themes folder itself is protected (it holds the active theme)', $p( WP_CONTENT_DIR . '/themes' ) );
check( 'a decoy theme folder is not protected', ! $p( WP_CONTENT_DIR . '/themes/config_1791852300' ) );
check( 'a critical file in the active theme is still protected', $p( WP_CONTENT_DIR . '/themes/BMK/functions.php' ) );
check( 'an ordinary file in the active theme is not (surgical removal stays possible)', ! $p( WP_CONTENT_DIR . '/themes/BMK/inc/security.php' ) );
check( 'a shell file in a decoy theme is not protected', ! $p( WP_CONTENT_DIR . '/themes/config_1791852300/functlons.php' ) );

$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $tmp, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::CHILD_FIRST );
foreach ( $it as $f ) {
	$f->isDir() ? @rmdir( $f->getPathname() ) : @unlink( $f->getPathname() );
}
@rmdir( $tmp );
echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
