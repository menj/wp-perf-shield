<?php
/**
 * Regression test for WPS_Utils::remove_dev_files() (1.4.154): the development test suite is
 * removed from an installed copy of the plugin, and left alone in a git checkout.
 *
 * Run from the command line only:  php tests/test-dev-files.php
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}
define( 'ABSPATH', '/x/' );
require dirname( __DIR__ ) . '/includes/class-wps-utils.php';

$fail = 0;
function check( string $name, bool $ok, string $detail = '' ): void {
	global $fail;
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $name . ( $ok ? '' : ' :: ' . $detail ) . "\n";
	if ( ! $ok ) {
		++$fail;
	}
}
function plugin_copy( bool $git ): string {
	$dir = sys_get_temp_dir() . '/wps-dev-' . bin2hex( random_bytes( 4 ) );
	mkdir( $dir . '/tests/sub', 0777, true );
	mkdir( $dir . '/includes', 0777, true );
	mkdir( $dir . '/doc', 0777, true );
	file_put_contents( $dir . '/tests/test-x.php', "<?php\n" );
	file_put_contents( $dir . '/tests/sub/fixture.txt', "x" );
	file_put_contents( $dir . '/includes/class-x.php', "<?php\n" );
	file_put_contents( $dir . '/doc/readme.md', "# x\n" );
	file_put_contents( $dir . '/wp-perf-shield.php', "<?php\n" );
	if ( $git ) {
		mkdir( $dir . '/.git' );
	}
	return $dir;
}

// ---- an uploaded install: tests/ goes, everything else stays
$dir = plugin_copy( false );
$removed = WPS_Utils::remove_dev_files( $dir );
check( 'tests/ is removed from an installed copy', [ 'tests' ] === $removed && ! is_dir( $dir . '/tests' ), json_encode( $removed ) );
check( 'includes, doc and the main file are untouched', is_file( $dir . '/includes/class-x.php' ) && is_file( $dir . '/doc/readme.md' ) && is_file( $dir . '/wp-perf-shield.php' ) );
check( 'a second call finds nothing to do', [] === WPS_Utils::remove_dev_files( $dir ) );

// ---- a developer checkout keeps its tests
$git = plugin_copy( true );
check( 'a git checkout keeps tests/', [] === WPS_Utils::remove_dev_files( $git ) && is_file( $git . '/tests/test-x.php' ) );

// ---- a symbolic link under tests/ is unlinked, never followed
$dir2 = plugin_copy( false );
$outside = sys_get_temp_dir() . '/wps-dev-outside-' . bin2hex( random_bytes( 4 ) );
mkdir( $outside );
file_put_contents( $outside . '/keep.txt', 'keep' );
symlink( $outside, $dir2 . '/tests/link' );
WPS_Utils::remove_dev_files( $dir2 );
check( 'a link inside tests/ is removed without touching what it points to', ! is_dir( $dir2 . '/tests' ) && is_file( $outside . '/keep.txt' ) );
check( 'a missing or bogus directory is a no-op', [] === WPS_Utils::remove_dev_files( $dir . '/nope' ) && [] === WPS_Utils::remove_dev_files( '' ) );

foreach ( [ $dir, $git, $dir2, $outside ] as $d ) {
	exec( 'rm -rf ' . escapeshellarg( $d ) );
}
echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
