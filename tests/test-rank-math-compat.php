<?php
/**
 * Regression test: a hidden folder inside a Composer package is not a finding (1.4.154).
 *
 * Run from the command line only:  php tests/test-rank-math-compat.php
 *
 * Rank Math SEO ships donatj/phpuseragentparser in its Composer vendor tree, and that library
 * carries a `.helpers/constants.php`. Two checks reported it on every site that ran Rank Math,
 * and the October 2026 incident review took it for malware. The fixture rebuilds that layout from
 * synthetic files: no Rank Math code is stored here. A hidden folder that only pretends to be a
 * package (a composer.json with no entry in installed.json), or one outside vendor/, is still
 * reported, so the detection is narrowed, not removed.
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}
$tmp = sys_get_temp_dir() . '/wps-rm-' . bin2hex( random_bytes( 4 ) );
mkdir( $tmp . '/wp-content/plugins/wps-self', 0777, true );
define( 'ABSPATH', $tmp . '/' );
define( 'WPS_DIR', $tmp . '/wp-content/plugins/wps-self/' );
define( 'WPS_OPTION', 'wps_opts' );
define( 'WP_CONTENT_DIR', $tmp . '/wp-content' );
define( 'WP_PLUGIN_DIR', $tmp . '/wp-content/plugins' );
define( 'WPMU_PLUGIN_DIR', $tmp . '/wp-content/mu-plugins' );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'DAY_IN_SECONDS', 86400 );
function get_option( $k, $d = false ) { return $d; }
function update_option() { return true; }
function get_transient() { return false; }
function set_transient() { return true; }
function delete_transient() { return true; }
function apply_filters( $t, $v ) { return $v; }
function add_action() {}
function add_filter() {}
function wp_json_encode( $v ) { return json_encode( $v ); }
function wp_upload_dir() { return [ 'basedir' => WP_CONTENT_DIR . '/uploads', 'baseurl' => '/', 'error' => false ]; }
function get_theme_root() { return WP_CONTENT_DIR . '/themes'; }
class WPS_Logger { public static function log_event() {} public static function write() {} public static function notify_admin() {} }
class WPS_Indicators {
	public static function dropper_cache_zip_patterns() { return [ 'dropper-cache' ]; }
	public static function secondary_backdoor_filenames() { return [ 'wp-vcd.php' ]; }
}

require dirname( __DIR__ ) . '/includes/class-wps-utils.php';
require dirname( __DIR__ ) . '/includes/class-scanner.php';

$fail = 0;
function check( string $name, bool $ok, string $detail = '' ): void {
	global $fail;
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $name . ( $ok ? '' : ' :: ' . $detail ) . "\n";
	if ( ! $ok ) {
		++$fail;
	}
}
function put( string $p, string $c = "<?php\n" ): void {
	@mkdir( dirname( $p ), 0777, true );
	file_put_contents( $p, $c );
}
function run( string $check ): array {
	$m = new ReflectionMethod( 'WPS_Scanner', $check );
	$m->setAccessible( true );
	return array_values( array_filter( (array) $m->invoke( null ), static fn( $f ) => false !== strpos( (string) ( $f['type'] ?? '' ), 'Hidden' ) ) );
}
$P = WP_PLUGIN_DIR;

// ---- the Rank Math layout, rebuilt from synthetic files
put( $P . '/seo-by-rank-math/rank-math.php', "<?php\n/* Plugin Name: Rank Math SEO\nVersion: 1.0.279 */\n" );
put( $P . '/seo-by-rank-math/vendor/donatj/phpuseragentparser/composer.json', '{"name":"donatj/phpuseragentparser"}' );
put( $P . '/seo-by-rank-math/vendor/donatj/phpuseragentparser/.helpers/constants.php', "<?php\nrequire __DIR__ . '/../vendor/autoload.php';\n\$class = new ReflectionClass(\$argv[1]);\n" );
put( $P . '/seo-by-rank-math/vendor/composer/installed.json', json_encode( [ 'packages' => [ [ 'name' => 'donatj/phpuseragentparser', 'version' => '1.8.0' ], [ 'name' => 'cmb2/cmb2', 'version' => '2.10' ] ] ] ) );
check( 'the helper folder is recognised as part of its Composer package', 'donatj/phpuseragentparser' === WPS_Utils::composer_package_of( $P . '/seo-by-rank-math/vendor/donatj/phpuseragentparser/.helpers' ) );
check( 'check_plugin_dot_directories does not report it', [] === run( 'check_plugin_dot_directories' ), json_encode( run( 'check_plugin_dot_directories' ) ) );
check( 'check_dropper_cache does not report it', [] === run( 'check_dropper_cache' ), json_encode( run( 'check_dropper_cache' ) ) );

// ---- the same folder name planted where no Composer package explains it is still reported
put( $P . '/some-plugin/some-plugin.php', "<?php\n/* Plugin Name: Some */\n" );
put( $P . '/some-plugin/inc/.helpers/shell.php', "<?php\n// nothing yet\n" );
$f = run( 'check_plugin_dot_directories' );
check( 'a hidden code folder outside any package is still reported', 1 === count( $f ) && false !== strpos( (string) $f[0]['subject'], 'some-plugin/inc/.helpers' ), json_encode( $f ) );
check( 'the dropper walk reports it too', 1 === count( run( 'check_dropper_cache' ) ) );

// ---- a folder under vendor/ that brings its own composer.json but is not in installed.json is not a package
put( $P . '/some-plugin/vendor/evil/pkg/composer.json', '{"name":"evil/pkg"}' );
put( $P . '/some-plugin/vendor/evil/pkg/.x/door.php', "<?php\n" );
put( $P . '/some-plugin/vendor/composer/installed.json', json_encode( [ 'packages' => [ [ 'name' => 'real/dep' ] ] ] ) );
check( 'a composer.json alone does not make a package', '' === WPS_Utils::composer_package_of( $P . '/some-plugin/vendor/evil/pkg/.x' ) );
$f = run( 'check_plugin_dot_directories' );
check( 'so the hidden folder inside it is still reported', 2 === count( $f ) && 1 === count( array_filter( $f, static fn( $x ) => false !== strpos( (string) $x['subject'], 'vendor/evil/pkg/.x' ) ) ), json_encode( $f ) );

// ---- the older installed.json shape (a bare array) is read too
put( $P . '/old-style/old-style.php', "<?php\n/* Plugin Name: Old */\n" );
put( $P . '/old-style/vendor/acme/lib/composer.json', '{"name":"acme/lib"}' );
put( $P . '/old-style/vendor/acme/lib/.bin/tool.php', "<?php\n" );
put( $P . '/old-style/vendor/composer/installed.json', json_encode( [ [ 'name' => 'acme/lib' ] ] ) );
check( 'a bare-array installed.json is honoured', 'acme/lib' === WPS_Utils::composer_package_of( $P . '/old-style/vendor/acme/lib/.bin' ) );
check( 'vendor/composer itself is never a package', '' === WPS_Utils::composer_package_of( $P . '/old-style/vendor/composer/.x' ) );

exec( 'rm -rf ' . escapeshellarg( $tmp ) );
echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
