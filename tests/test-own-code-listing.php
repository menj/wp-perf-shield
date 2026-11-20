<?php
/**
 * Regression test for the 1.4.164 changes found by scanning the operator's themes folder.
 *
 * Run from the command line only:  php tests/test-own-code-listing.php
 *
 *  - a signature hit in a theme removes the file, not the whole theme folder;
 *  - a file that only LISTS indicators (a detection list, a comment) is not malware: reported for
 *    review, or not reported at all when the folder is the operator's own;
 *  - code that uses an indicator is still malware, however it is written;
 *  - theme folders named with a Unix timestamp are reported, never removed.
 *
 * Synthetic fixtures only; the real WPS_Scanner checks run through reflection.
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}

$tmp = sys_get_temp_dir() . '/wps-listing-' . bin2hex( random_bytes( 4 ) );
foreach ( [ '/plugins/wps-self', '/mu-plugins', '/uploads', '/themes', '/site' ] as $d ) {
	mkdir( $tmp . $d, 0777, true );
}
define( 'ABSPATH', $tmp . '/site/' );
define( 'WPS_DIR', $tmp . '/plugins/wps-self/' );
define( 'WPS_OPTION', 'wps_opts' );
define( 'WP_PLUGIN_DIR', $tmp . '/plugins' );
define( 'WPMU_PLUGIN_DIR', $tmp . '/mu-plugins' );
define( 'WP_CONTENT_DIR', $tmp );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'DAY_IN_SECONDS', 86400 );

$GLOBALS['home'] = 'https://example.test';
$GLOBALS['opts'] = [];
function get_option( $k, $d = false ) {
	if ( 'home' === $k ) {
		return $GLOBALS['home'];
	}
	if ( 'wps_opts' === $k ) {
		return $GLOBALS['opts'];
	}
	return $d;
}
function update_option() { return true; }
function apply_filters( $t, $v ) { return $v; }
function wp_json_encode( $v ) { return json_encode( $v ); }
function wp_upload_dir() { return [ 'basedir' => $GLOBALS['tmp'] . '/uploads', 'baseurl' => '/', 'error' => false ]; }
function get_stylesheet() { return 'liveform'; }
function get_template() { return 'liveform'; }
foreach ( [ 'add_action', 'add_filter' ] as $fn ) {
	eval( "function $fn() {}" );
}
class WPS_Logger {
	public static $events = [];
	public static function log_event( $t, $d = '', $ip = '' ) { self::$events[] = $t; }
	public static function write() {}
}
$GLOBALS['tmp'] = $tmp;

require dirname( __DIR__ ) . '/includes/class-wps-utils.php';
require dirname( __DIR__ ) . '/includes/class-wps-indicators.php';
require dirname( __DIR__ ) . '/includes/class-scanner.php';

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
function run( string $method ): array {
	$m = new ReflectionMethod( 'WPS_Scanner', $method );
	$m->setAccessible( true );
	return $m->invoke( null );
}
function for_path( array $f, string $needle ): array {
	return array_values( array_filter( $f, static fn( $x ) => false !== strpos( (string) ( $x['path'] ?? '' ), $needle ) ) );
}

$sig = '_wp_perf_ok'; // a real signature of the wp-perf-analytics family

$listing = "<?php\n/**\n * Malware suppression. The dropper sets the $sig cookie.\n */\nfunction block_it( \$out ) {\n\t\$fingerprints = [\n\t\t// cookie names set by the dropper\n\t\t'$sig',\n\t\t'eth_call',\n\t];\n\t\$re = implode( '|', array_map( 'preg_quote', \$fingerprints ) );\n\treturn preg_replace_callback( '/' . \$re . '/', static function ( \$m ) { return ''; }, \$out );\n}\nadd_filter( 'the_content', 'block_it' );\n";

// The operator's own theme: Author URI is the site's own domain.
put( $tmp . '/themes/ownthm/style.css', "/*\nTheme Name: Own\nAuthor URI: https://www.example.test\n*/\n" );
put( $tmp . '/themes/ownthm/inc/security.php', $listing );
// A theme by someone else carrying the same detection file.
put( $tmp . '/themes/otherthm/style.css', "/*\nTheme Name: Other\nAuthor URI: https://elsewhere.invalid\n*/\n" );
put( $tmp . '/themes/otherthm/inc/security.php', $listing );
put( $tmp . '/themes/otherthm/index.php', "<?php\n// Silence is golden.\n" );

// Code that USES the indicator, written five ways. Each is in a theme of its own.
$uses = [
	'drop-arg'    => "<?php\nsetcookie( '$sig', '1' );\n",
	'drop-assign' => "<?php\n\$name = '$sig';\n",
	'drop-index'  => "<?php\nif ( isset( \$_COOKIE['$sig'] ) ) { echo 'x'; }\n",
	'drop-eval'   => "<?php\n\$list = [ '$sig' ];\neval( \$_POST['c'] );\n",
	'drop-varcall' => "<?php\n\$list = [ '$sig' ];\n\$f = 'sys' . 'tem';\n\$f( \$_GET['c'] );\n",
	'drop-assertmap' => "<?php\n\$list = [ '$sig' ];\narray_map( 'assert', [ \$_POST['c'] ] );\n",
	'drop-decode' => "<?php\n\$list = [ '$sig' ];\n\$x = base64_decode( \$_POST['c'] );\n",
];
foreach ( $uses as $name => $code ) {
	put( $tmp . "/themes/$name/style.css", "/*\nTheme Name: $name\n*/\n" );
	put( $tmp . "/themes/$name/inc/x.php", $code );
	put( $tmp . "/themes/$name/index.php", "<?php\n// Silence is golden.\n" );
}

$f = run( 'check_php_signatures' );

check( 'the operator\'s own theme that only lists indicators is not reported at all', ! for_path( $f, '/ownthm/' ), json_encode( for_path( $f, '/ownthm/' ) ) );
check( 'the quiet is logged', in_array( 'own_indicator_listing', WPS_Logger::$events, true ) );
$o = for_path( $f, '/otherthm/' );
check( 'the same file in someone else\'s theme is reported for review', 1 === count( $o ) && 'medium' === $o[0]['severity'] && 'Indicator strings listed in a defensive file' === $o[0]['type'], json_encode( $o ) );
check( 'and is never removed', empty( $o[0]['auto_delete'] ) && empty( $o[0]['delete_path'] ) );

foreach ( array_keys( $uses ) as $name ) {
	$r = for_path( $f, "/$name/" );
	check( "code that uses the indicator ($name) is still critical and removable", 1 === count( $r ) && 'critical' === $r[0]['severity'] && ! empty( $r[0]['auto_delete'] ), json_encode( $r ) );
}
$r = for_path( $f, '/drop-arg/' );
check( 'a theme signature hit removes the file, not the theme folder', 1 === count( $r ) && $r[0]['delete_path'] === $r[0]['path'] && '/x.php' === substr( $r[0]['delete_path'], -6 ), json_encode( $r ) );
check( 'the theme\'s other files are untouched by that finding', ! for_path( $f, '/drop-arg/index.php' ) );

// An operator-declared plugin that lists indicators is quiet too.
put( $tmp . '/plugins/mine/mine.php', "<?php\n/* Plugin Name: Mine */\n" );
put( $tmp . '/plugins/mine/detect.php', $listing );
put( $tmp . '/plugins/theirs/theirs.php', "<?php\n/* Plugin Name: Theirs */\n" );
put( $tmp . '/plugins/theirs/detect.php', $listing );
$GLOBALS['opts'] = [ 'first_party_plugins' => 'mine' ];
$f = run( 'check_php_signatures' );
check( 'a declared plugin that lists indicators is quiet', ! for_path( $f, '/plugins/mine/' ), json_encode( for_path( $f, '/plugins/mine/' ) ) );
$t = for_path( $f, '/plugins/theirs/' );
check( 'an undeclared plugin with the same file is reported for review, not removed', 1 === count( $t ) && 'medium' === $t[0]['severity'] && empty( $t[0]['auto_delete'] ), json_encode( $t ) );
$GLOBALS['opts'] = [];

// A file whose only mention is in a comment is a listing too.
put( $tmp . '/themes/otherthm/inc/note.php', "<?php\n// The dropper sets the $sig cookie; see the writeup.\nfunction noop() { return 1; }\n" );
$f = run( 'check_php_signatures' );
$n = for_path( $f, '/otherthm/inc/note.php' );
check( 'a comment that names an indicator is reported for review, not removed', 1 === count( $n ) && empty( $n[0]['auto_delete'] ), json_encode( $n ) );

// EtherHiding resolver: the operator's own listing is quiet; the same file elsewhere is still judged.
$eth = "<?php\n\$fp = [\n\t'0x08207B087F61d7e95E441E15fd6d40BEfd6eD308',\n\t'eth_call',\n\t'atob(',\n\t'charCodeAt',\n];\n";
put( $tmp . '/themes/ownthm/inc/eth.php', $eth );
put( $tmp . '/themes/otherthm/inc/eth.php', $eth );
$e = run( 'check_etherhiding_resolver' );
check( 'the operator\'s own listing is not an EtherHiding finding', ! for_path( $e, '/ownthm/' ), json_encode( for_path( $e, '/ownthm/' ) ) );
check( 'the same listing in someone else\'s theme is still judged', (bool) for_path( $e, '/otherthm/inc/eth.php' ) );

// Decoy theme folders named with a timestamp.
foreach ( [ 'config_1791852300', 'post-1791852298', 'liveform_1791852311' ] as $d ) {
	put( $tmp . "/themes/$d/style.css", "/*\nTheme Name: $d\n*/\n" );
}
put( $tmp . '/themes/liveform/style.css', "/*\nTheme Name: Live\n*/\n" );
foreach ( [ 'twentytwentyfive', 'theme-2024', 'shop-12345' ] as $d ) {
	put( $tmp . "/themes/$d/style.css", "/*\nTheme Name: $d\n*/\n" );
}
$ts = run( 'check_timestamp_named_themes' );
$names = array_map( static fn( $x ) => basename( $x['path'] ), $ts );
sort( $names );
check( 'folders ending in a Unix timestamp are reported', in_array( 'config_1791852300', $names, true ) && in_array( 'post-1791852298', $names, true ), json_encode( $names ) );
check( 'an ordinary theme name is not reported', ! in_array( 'ownthm', $names, true ) && ! in_array( 'liveform', $names, true ), json_encode( $names ) );
check( 'a name ending in a year or a short number is not a timestamp', ! in_array( 'twentytwentyfive', $names, true ) && ! in_array( 'theme-2024', $names, true ) && ! in_array( 'shop-12345', $names, true ), json_encode( $names ) );
check( 'the finding is report only', ! array_filter( $ts, static fn( $x ) => ! empty( $x['auto_delete'] ) || ! empty( $x['delete_path'] ) ) );
check( 'the date is read from the number', false !== strpos( $ts[0]['subject'], '2026-10-1' ), $ts[0]['subject'] );

// cleanup
$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $tmp, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::CHILD_FIRST );
foreach ( $it as $x ) {
	$x->isDir() ? @rmdir( $x->getPathname() ) : @unlink( $x->getPathname() );
}
@rmdir( $tmp );

echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
