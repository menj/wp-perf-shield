<?php
/**
 * Regression test for findings contributed by other code (1.4.163).
 *
 * Run from the command line only:  php tests/test-external-findings.php
 *
 * WPS_Scanner::external_findings() reads the `wps_external_findings` filter and keeps only
 * well-formed entries: text stripped and capped, severity from the four known levels, a path
 * inside the WordPress root, a delete_path inside wp-content, and no second report of a path
 * a WP Perf Shield finding already covers.
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}

$tmp = sys_get_temp_dir() . '/wps-ext-' . bin2hex( random_bytes( 4 ) );
mkdir( $tmp . '/site/wp-content/themes/config_1791852300', 0777, true );
mkdir( $tmp . '/outside', 0777, true );

define( 'ABSPATH', $tmp . '/site/' );
define( 'WP_CONTENT_DIR', $tmp . '/site/wp-content' );
define( 'WPS_DIR', $tmp . '/site/wp-content/plugins/wp-perf-shield/' );
define( 'WPS_OPTION', 'wps_opts' );
define( 'WP_PLUGIN_DIR', $tmp . '/site/wp-content/plugins' );
define( 'WPMU_PLUGIN_DIR', $tmp . '/site/wp-content/mu-plugins' );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'DAY_IN_SECONDS', 86400 );

$GLOBALS['filters'] = [];
function add_filter( $t, $cb ) { $GLOBALS['filters'][ $t ][] = $cb; }
function apply_filters( $t, $v ) {
	foreach ( $GLOBALS['filters'][ $t ] ?? [] as $cb ) {
		$v = $cb( $v );
	}
	return $v;
}
function get_option( $k, $d = false ) { return $d; }
class WPS_Logger {
	public static function log_event( $t, $s, $ip = '' ) {}
	public static function write( $m ) {}
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

$shell = WP_CONTENT_DIR . '/themes/config_1791852300/functlons.php';
file_put_contents( $shell, "<?php // shell\n" );
$known = WP_CONTENT_DIR . '/themes/config_1791852300/known.php';
file_put_contents( $known, "<?php // known\n" );
file_put_contents( $tmp . '/outside/x.php', "<?php\n" );

// No filter attached: nothing.
check( 'no contributors, no findings', [] === WPS_Scanner::external_findings() );

add_filter( 'wps_external_findings', function ( $list ) use ( $shell, $known, $tmp ) {
	$list[] = [ 'type' => 'Web shell', 'subject' => 'wp-content/themes/config_1791852300/functlons.php', 'path' => $shell, 'delete_path' => dirname( $shell ), 'severity' => 'critical', 'source' => 'BMK theme' ];
	$list[] = [ 'type' => '<b>Bold</b> type', 'subject' => 'option _track_a764e5', 'severity' => 'urgent' ];
	$list[] = [ 'type' => 'Outside', 'subject' => 'x', 'path' => $tmp . '/outside/x.php' ];
	$list[] = [ 'type' => 'Bad delete', 'subject' => 'y', 'delete_path' => ABSPATH . 'wp-config.php' ];
	$list[] = [ 'type' => 'Already reported', 'subject' => 'z', 'path' => $known ];
	$list[] = [ 'subject' => 'no type' ];
	$list[] = 'not an array';
	return $list;
} );

$out = WPS_Scanner::external_findings( [ [ 'path' => $known, 'type' => 'own finding' ] ] );
$by  = [];
foreach ( $out as $f ) {
	$by[ $f['subject'] ] = $f;
}

check( 'three of seven entries survive', 3 === count( $out ), (string) count( $out ) . ': ' . implode( ' | ', array_keys( $by ) ) );
check( 'web shell kept with its path', isset( $by['wp-content/themes/config_1791852300/functlons.php'] ) && realpath( $shell ) === $by['wp-content/themes/config_1791852300/functlons.php']['path'] );
check( 'delete_path inside wp-content kept', realpath( dirname( $shell ) ) === ( $by['wp-content/themes/config_1791852300/functlons.php']['delete_path'] ?? '' ) );
check( 'source named in the type', false !== strpos( $by['wp-content/themes/config_1791852300/functlons.php']['type'], 'reported by BMK theme' ) );
check( 'tags stripped, unknown severity becomes high', isset( $by['option _track_a764e5'] ) && 'Bold type (reported by external)' === $by['option _track_a764e5']['type'] && 'high' === $by['option _track_a764e5']['severity'] );
check( 'path outside the WordPress root dropped', ! isset( $by['x'] ) );
check( 'delete_path outside wp-content is not offered', isset( $by['y'] ) && ! isset( $by['y']['delete_path'] ) );
check( 'path already reported by WP Perf Shield left out', ! isset( $by['z'] ) );

$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $tmp, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::CHILD_FIRST );
foreach ( $it as $f ) {
	$f->isDir() ? @rmdir( $f->getPathname() ) : @unlink( $f->getPathname() );
}
@rmdir( $tmp );
echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
