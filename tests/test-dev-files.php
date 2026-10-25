<?php
/**
 * Regression test for WPS_Utils::remove_dev_files() (1.4.154) and protect_repo_dir() (1.4.156):
 * the development test suite is removed from an installed copy of the plugin, git checkout or
 * not, and a git repository uploaded with the plugin is refused to the web.
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

// ---- 1.4.156: a git checkout loses them too; the one site this was for had .git uploaded as well
$git = plugin_copy( true );
check( 'a git checkout loses tests/ as well', [ 'tests' ] === WPS_Utils::remove_dev_files( $git ) && ! is_dir( $git . '/tests' ) );
check( 'the repository itself is not deleted', is_dir( $git . '/.git' ) );

// ---- a repository inside the plugin folder is refused to the web
check( 'no repository, nothing to protect', '' === WPS_Utils::protect_repo_dir( $dir ) && ! file_exists( $dir . '/.git' ) );
check( 'a repository is reported', '.git' === WPS_Utils::protect_repo_dir( $git ) );
$ht = (string) @file_get_contents( $git . '/.git/.htaccess' );
check( '.git/.htaccess denies for both Apache generations', false !== strpos( $ht, 'Require all denied' ) && false !== strpos( $ht, 'Deny from all' ), $ht );
check( '.git/index.php is silent', "<?php\n// Silence is golden.\n" === (string) @file_get_contents( $git . '/.git/index.php' ) );
$mtime = filemtime( $git . '/.git/.htaccess' );
touch( $git . '/.git/.htaccess', $mtime - 100 );
clearstatcache();
WPS_Utils::protect_repo_dir( $git );
clearstatcache();
check( 'a second call leaves files that are already right alone', $mtime - 100 === filemtime( $git . '/.git/.htaccess' ) );
file_put_contents( $git . '/.git/.htaccess', 'tampered' );
WPS_Utils::protect_repo_dir( $git );
check( 'a changed .htaccess is rewritten', false !== strpos( (string) file_get_contents( $git . '/.git/.htaccess' ), 'Require all denied' ) );
$linked = plugin_copy( true );
$target = sys_get_temp_dir() . '/wps-dev-target-' . bin2hex( random_bytes( 4 ) );
file_put_contents( $target, 'precious' );
symlink( $target, $linked . '/.git/.htaccess' );
WPS_Utils::protect_repo_dir( $linked );
check( 'a link where the .htaccess should be is not written through', 'precious' === file_get_contents( $target ) && is_link( $linked . '/.git/.htaccess' ) );
check( 'the other protection file is still written beside it', is_file( $linked . '/.git/index.php' ) );
$gitfile = plugin_copy( false );
file_put_contents( $gitfile . '/.git', "gitdir: ../elsewhere/.git\n" );
check( 'a .git file (a worktree pointer) is not a repository folder and is left alone', '' === WPS_Utils::protect_repo_dir( $gitfile ) && "gitdir: ../elsewhere/.git\n" === file_get_contents( $gitfile . '/.git' ) );

// ---- a symbolic link under tests/ is unlinked, never followed
$dir2 = plugin_copy( false );
$outside = sys_get_temp_dir() . '/wps-dev-outside-' . bin2hex( random_bytes( 4 ) );
mkdir( $outside );
file_put_contents( $outside . '/keep.txt', 'keep' );
symlink( $outside, $dir2 . '/tests/link' );
WPS_Utils::remove_dev_files( $dir2 );
check( 'a link inside tests/ is removed without touching what it points to', ! is_dir( $dir2 . '/tests' ) && is_file( $outside . '/keep.txt' ) );
check( 'a missing or bogus directory is a no-op', [] === WPS_Utils::remove_dev_files( $dir . '/nope' ) && [] === WPS_Utils::remove_dev_files( '' ) );

foreach ( [ $dir, $git, $dir2, $outside, $gitfile, $linked, $target ] as $d ) {
	exec( 'rm -rf ' . escapeshellarg( $d ) );
}
echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
