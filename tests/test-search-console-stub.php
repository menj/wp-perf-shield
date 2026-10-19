<?php
/**
 * Regression test for check_search_console_stub (1.4.137).
 *
 * Run from the command line only:  php tests/test-search-console-stub.php
 *
 * Builds a throwaway web root with stubs in different places and runs the real
 * check with the Site Kit setting off and on.
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}
$tmp = sys_get_temp_dir() . '/wps-gsc-' . bin2hex( random_bytes( 4 ) );
mkdir( $tmp . '/wp-content/plugins/wps-self', 0777, true );
mkdir( $tmp . '/wp-content/uploads', 0777, true );
define( 'ABSPATH', $tmp . '/' );
define( 'WPS_DIR', $tmp . '/wp-content/plugins/wps-self/' );
define( 'WPS_OPTION', 'wps_opts' );
define( 'WP_PLUGIN_DIR', $tmp . '/wp-content/plugins' );
define( 'WPMU_PLUGIN_DIR', $tmp . '/wp-content/mu-plugins' );
define( 'WP_CONTENT_DIR', $tmp . '/wp-content' );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'DAY_IN_SECONDS', 86400 );
$GLOBALS['opts'] = [];
function get_option( $k, $d = false ) { return $k === WPS_OPTION ? $GLOBALS['opts'] : $d; }
function update_option() { return true; }
function apply_filters( $t, $v ) { return $v; }
function wp_json_encode( $v ) { return json_encode( $v ); }
function wp_upload_dir() { return [ 'basedir' => WP_CONTENT_DIR . '/uploads', 'baseurl' => '/', 'error' => false ]; }
require dirname( __DIR__ ) . '/includes/class-wps-utils.php';
require dirname( __DIR__ ) . '/includes/class-scanner.php';

$fail = 0;
function check( string $name, bool $ok ): void {
	global $fail;
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $name . "\n";
	if ( ! $ok ) { ++$fail; }
}
function put( string $p, string $c ): void { @mkdir( dirname( $p ), 0777, true ); file_put_contents( $p, $c ); }
function run(): array {
	$m = new ReflectionMethod( 'WPS_Scanner', 'check_search_console_stub' );
	$m->setAccessible( true );
	return $m->invoke( null );
}
function has( array $f, string $needle ): ?array {
	foreach ( $f as $x ) { if ( false !== strpos( $x['path'], $needle ) ) { return $x; } }
	return null;
}

$stub = 'google471b9cce54b5a1ab.html';
put( $tmp . '/' . $stub, 'google-site-verification: ' . $stub );
put( $tmp . '/sitemap.xml', '<?xml version="1.0"?><urlset></urlset>' );
put( $tmp . '/blog/' . $stub, 'google-site-verification: ' . $stub );
put( $tmp . '/wp-content/uploads/x/googleaaaaaaaaaaaaaaaa.html', 'google-site-verification: googleaaaaaaaaaaaaaaaa.html' );
put( $tmp . '/wp-content/uploads/y/google1111111111111111.html', 'not a verification file' );

$f = run();
check( 'Site Kit off: a root stub is left alone', ! has( $f, $tmp . '/' . $stub ) );
check( 'Site Kit off: a root sitemap.xml is left alone', ! has( $f, '/sitemap.xml' ) );
$b = has( $f, '/blog/' );
check( 'a stub in a web-root subfolder is reported but not removed (it can be that folder\'s own property)', $b && empty( $b['auto_delete'] ) );
$u = has( $f, '/uploads/x/' );
check( 'a stub inside uploads is reported and removable', $u && ! empty( $u['auto_delete'] ) );
put( $tmp . '/other-site/wp-config.php', '<?php' );
put( $tmp . '/other-site/' . $stub, 'google-site-verification: ' . $stub );
$f = run();
check( 'a folder that is another WordPress install is not searched', ! has( $f, '/other-site/' ) );
check( 'a google-named file whose content is not the stub text is ignored', ! has( $f, '/uploads/y/' ) );

$GLOBALS['opts'] = [ 'site_kit_search_console' => '1' ];
$f = run();
$r = has( $f, $tmp . '/' . $stub );
check( 'Site Kit on: the root stub is reported and removable', $r && ! empty( $r['auto_delete'] ) );
$s = has( $f, '/sitemap.xml' );
check( 'Site Kit on: the root sitemap.xml is reported but never auto-deleted', $s && empty( $s['auto_delete'] ) );

$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $tmp, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::CHILD_FIRST );
foreach ( $it as $x ) { $x->isDir() ? @rmdir( $x->getPathname() ) : @unlink( $x->getPathname() ); }
@rmdir( $tmp );
echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
