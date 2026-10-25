<?php
/**
 * Regression test for the bootstrap's completeness check (1.4.156).
 *
 * Run from the command line only:  php tests/test-bootstrap-integrity.php
 *
 * Incident: a plugin uploaded over FTP had its main file in place while includes/ was still
 * arriving. Every request that reached `init` for the next seven minutes died with
 * `Class "WPS_Guard" not found`, and the fatal put the plugin into safe mode until cleared by hand.
 * The main file is run here, in a child process against a copy with one class file removed, with
 * WordPress replaced by stand-ins.
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}
$fail = 0;
function check( string $name, bool $ok, string $detail = '' ): void {
	global $fail;
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $name . ( $ok ? '' : ' :: ' . $detail ) . "\n";
	if ( ! $ok ) {
		++$fail;
	}
}
function copy_tree( string $from, string $to ): void {
	mkdir( $to, 0777, true );
	foreach ( scandir( $from ) ?: [] as $item ) {
		if ( '.' === $item || '..' === $item ) {
			continue;
		}
		if ( is_dir( $from . '/' . $item ) ) {
			copy_tree( $from . '/' . $item, $to . '/' . $item );
		} else {
			copy( $from . '/' . $item, $to . '/' . $item );
		}
	}
}
$repo = dirname( __DIR__ );
$base = sys_get_temp_dir() . '/wps-boot-' . bin2hex( random_bytes( 4 ) );
mkdir( $base );
copy_tree( $repo . '/includes', $base . '/complete/includes' );
copy( $repo . '/wp-perf-shield.php', $base . '/complete/wp-perf-shield.php' );
copy_tree( $base . '/complete', $base . '/partial' );
unlink( $base . '/partial/includes/class-guard.php' );
preg_match( "/define\\(\\s*'WPS_VERSION',\\s*'([0-9.]+)'/", (string) file_get_contents( $repo . '/wp-perf-shield.php' ), $vm );
$version = $vm[1] ?? '';

// The child: WordPress stand-ins, then the real main file, then the main file's own init closures.
$runner = $base . '/runner.php';
file_put_contents( $runner, <<<'PHP'
<?php
define( 'ABSPATH', '/x/' );
define( 'WP_CONTENT_DIR', '/x/wp-content' );
define( 'WP_PLUGIN_DIR', '/x/wp-content/plugins' );
function plugin_dir_path( $f ) { return dirname( $f ) . '/'; }
function plugin_dir_url( $f ) { return 'http://x/'; }
$GLOBALS['opts'] = json_decode( (string) ( $argv[2] ?? '{}' ), true ) ?: [];
function get_option( $k, $d = false ) { return array_key_exists( $k, $GLOBALS['opts'] ) ? $GLOBALS['opts'][ $k ] : $d; }
function update_option( $k, $v, $a = null ) { $GLOBALS['opts'][ $k ] = $v; return true; }
function delete_option( $k ) { unset( $GLOBALS['opts'][ $k ] ); return true; }
$GLOBALS['actions'] = [];
function add_action( $t, $cb, $p = 10, $a = 1 ) { $GLOBALS['actions'][ $t ][] = $cb; }
function add_filter( $t, $cb, $p = 10, $a = 1 ) { $GLOBALS['actions'][ $t ][] = $cb; }
function register_activation_hook() {}
function register_deactivation_hook() {}
function register_uninstall_hook() {}
function is_admin() { return false; }
function get_transient( $k ) { return false; }
function set_transient( $k, $v, $t = 0 ) { return true; }
function wp_next_scheduled( $h ) { return 1; }
function wp_schedule_event() {}
function esc_html( $s ) { return $s; }
require $argv[1];
$err = null;
try {
	foreach ( $GLOBALS['actions']['init'] ?? [] as $cb ) {
		if ( $cb instanceof Closure ) { // the main file's own closures; module hooks are arrays
			$cb();
		}
	}
} catch ( Throwable $t ) {
	$err = get_class( $t ) . ': ' . $t->getMessage();
}
echo json_encode( [
	'missing'    => function_exists( 'wps_missing_files' ) ? wps_missing_files() : null,
	'safe'       => wps_safe_mode(),
	'init_error' => $err,
	'fatal'      => $GLOBALS['opts']['wps_last_fatal'] ?? null,
] );
PHP
);
function run( string $main, array $opts = [] ): array {
	global $runner;
	$out = (string) shell_exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $runner ) . ' ' . escapeshellarg( $main ) . ' ' . escapeshellarg( json_encode( $opts ) ) . ' 2>&1' );
	$lines = explode( "\n", trim( $out ) );
	$j     = json_decode( (string) end( $lines ), true ); // the report is the last line; the record it echoes has braces of its own
	return is_array( $j ) ? $j + [ 'raw' => $out ] : [ 'raw' => $out ];
}

// ---- a complete copy
$r = run( $base . '/complete/wp-perf-shield.php' );
check( 'a complete copy reports no missing file', isset( $r['missing'] ) && [] === $r['missing'], (string) ( $r['raw'] ?? '' ) );
check( 'its init closures run without error', array_key_exists( 'init_error', $r ) && null === $r['init_error'], (string) ( $r['init_error'] ?? $r['raw'] ?? '' ) );

// ---- a copy still being uploaded
$r = run( $base . '/partial/wp-perf-shield.php' );
check( 'the missing class file is named', [ 'includes/class-guard.php' ] === ( $r['missing'] ?? null ), (string) ( $r['raw'] ?? '' ) );
check( 'init runs without the fatal the incident recorded', array_key_exists( 'init_error', $r ) && null === $r['init_error'], (string) ( $r['init_error'] ?? $r['raw'] ?? '' ) );
check( 'no fatal is recorded, so nothing is left for the operator to clear', empty( $r['fatal'] ), json_encode( $r['fatal'] ?? null ) );

// ---- safe mode lifts itself once the upload is complete
$fatal = [ 'version' => $version, 'file' => 'wp-perf-shield.php', 'line' => 370, 'message' => 'Uncaught Error: Class "WPS_Guard" not found in /x/wp-perf-shield.php:370', 'when' => '2026-10-20 05:52:11 UTC', 'context' => 'front-end' ];
$r = run( $base . '/complete/wp-perf-shield.php', [ 'wps_last_fatal' => $fatal ] );
check( 'a "class not found" fatal is cleared once every file is present', isset( $r['safe'] ) && false === $r['safe'] && empty( $r['fatal'] ), json_encode( [ $r['safe'] ?? null, $r['fatal'] ?? null ] ) );
$r = run( $base . '/partial/wp-perf-shield.php', [ 'wps_last_fatal' => $fatal ] );
check( 'the same record keeps safe mode while a file is still missing', isset( $r['safe'] ) && true === $r['safe'] && ! empty( $r['fatal'] ), json_encode( [ $r['safe'] ?? null, $r['fatal'] ?? null ] ) );
$other = [ 'message' => 'Uncaught TypeError: something else' ] + $fatal;
$r = run( $base . '/complete/wp-perf-shield.php', [ 'wps_last_fatal' => $other ] );
check( 'any other fatal keeps safe mode on a complete copy, as before', isset( $r['safe'] ) && true === $r['safe'] && ! empty( $r['fatal'] ), json_encode( [ $r['safe'] ?? null, $r['fatal'] ?? null ] ) );

exec( 'rm -rf ' . escapeshellarg( $base ) );
echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
