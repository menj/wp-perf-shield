<?php
/**
 * Regression test for the on-disk policy ban, WPS_Blocker::enforce_policy_ban().
 *
 * Run from the command line only:  php tests/test-policy-ban.php
 *
 * The options table, logger and quarantine store are small in-memory stand-ins;
 * the blocker and scanner code under test are the real files.
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}

$tmp = sys_get_temp_dir() . '/wps-pb-' . bin2hex( random_bytes( 4 ) );
mkdir( $tmp . '/plugins/wp-perf-shield-self', 0777, true );
mkdir( $tmp . '/q', 0777, true );
define( 'ABSPATH', $tmp . '/' );
define( 'WPS_DIR', $tmp . '/plugins/wp-perf-shield-self/' );
define( 'WPS_OPTION', 'wps_opts' );
define( 'WP_PLUGIN_DIR', $tmp . '/plugins' );
define( 'WPMU_PLUGIN_DIR', $tmp . '/mu' );
define( 'WP_CONTENT_DIR', $tmp );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'DAY_IN_SECONDS', 86400 );

$GLOBALS['opts']   = [];
$GLOBALS['events'] = [];
$GLOBALS['mails']  = 0;
function get_option( $k, $d = false ) { return array_key_exists( $k, $GLOBALS['opts'] ) ? $GLOBALS['opts'][ $k ] : $d; }
function update_option( $k, $v, $a = null ) { $GLOBALS['opts'][ $k ] = $v; return true; }
function delete_transient() { return true; }
function apply_filters( $t, $v ) { return $v; }
function add_action() {}
function add_filter() {}
function sanitize_title( $s ) { return strtolower( trim( preg_replace( '/[^a-z0-9_-]+/i', '-', $s ), '-' ) ); }

class WPS_Logger {
	public static function log_event( $t, $s, $ip = '' ) { $GLOBALS['events'][] = [ $t, $s ]; }
	public static function write( $m ) {}
	public static function notify_admin( $a, $b ) { ++$GLOBALS['mails']; }
}
class WPS_Quarantine {
	public static function store_dir(): string { return ABSPATH . 'q'; }
	public static function is_quarantine_path( string $p ): bool { return false; }
	public static function quarantine( string $path, array $meta = [], bool $move = true ): ?string {
		$id = 'q' . count( glob( ABSPATH . 'q/*' ) );
		rename( $path, ABSPATH . 'q/' . $id );
		return $id;
	}
	public static function quarantine_option( string $name, array $meta = [] ): ?string { return 'o'; }
}

require dirname( __DIR__ ) . '/includes/class-wps-utils.php';
require dirname( __DIR__ ) . '/includes/class-scanner.php';
require dirname( __DIR__ ) . '/includes/class-blocker.php';

function put( string $p, string $c ): void {
	@mkdir( dirname( $p ), 0777, true );
	file_put_contents( $p, $c );
}
function events( string $type ): int {
	return count( array_filter( $GLOBALS['events'], static fn( $e ) => $type === $e[0] ) );
}
$fail = 0;
function check( string $name, bool $ok, string $detail = '' ): void {
	global $fail;
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $name . ( $ok ? '' : ' :: ' . $detail ) . "\n";
	if ( ! $ok ) {
		++$fail;
	}
}
$P = WP_PLUGIN_DIR;
function drop(): void {
	put( WP_PLUGIN_DIR . '/wp-file-manager/file_folder_manager.php', "<?php\n/* Plugin Name: WP File Manager */\n" );
	put( WP_PLUGIN_DIR . '/wp-file-manager/lib/php/connector.minimal.php', "<?php\n" );
}

put( $P . '/fine/fine.php', "<?php\n/* Plugin Name: Fine */\n" );
drop();
$removed = WPS_Blocker::enforce_policy_ban();
check( 'banned folder is removed', [ 'wp-file-manager' ] === $removed, json_encode( $removed ) );
check( 'it is quarantined, so restorable', 1 === count( glob( $tmp . '/q/*' ) ) );
check( 'a tombstone FILE now sits where the folder was', is_file( $P . '/wp-file-manager' ) && ! is_dir( $P . '/wp-file-manager' ) );
check( 'a plain re-extract cannot create the directory over it', false === @mkdir( $P . '/wp-file-manager' ) );
check( 'an unrelated plugin is untouched', is_file( $P . '/fine/fine.php' ) );
check( 'the removal is logged with its provenance', 1 === events( 'policy_ban_enforced' ) && false !== strpos( end( $GLOBALS['events'] )[1], 'seen 1x' ), json_encode( $GLOBALS['events'] ) );

// Something removes the tombstone and drops the plugin again (second return).
unlink( $P . '/wp-file-manager' );
drop();
WPS_Blocker::enforce_policy_ban();
check( 'second return is counted and raised as a re-drop', 2 === $GLOBALS['opts']['wps_ban_redrops']['wp-file-manager']['count'] && 1 === events( 'policy_ban_redrop' ) && 1 === $GLOBALS['mails'], json_encode( $GLOBALS['opts']['wps_ban_redrops'] ?? null ) . ' mails=' . $GLOBALS['mails'] );

// Third and fourth returns: the first three are quarantined; after that nothing more is stored.
unlink( $P . '/wp-file-manager' ); drop(); WPS_Blocker::enforce_policy_ban();
$after3 = count( glob( $tmp . '/q/*' ) );
unlink( $P . '/wp-file-manager' ); drop(); WPS_Blocker::enforce_policy_ban();
check( 'after repeated returns the quarantine store stops growing', 3 === $after3 && 3 === count( glob( $tmp . '/q/*' ) ), $after3 . ' / ' . count( glob( $tmp . '/q/*' ) ) );
check( 'the folder is still removed once quarantining stops', ! is_dir( $P . '/wp-file-manager' ) && is_file( $P . '/wp-file-manager' ) );

// Substring rule, the same one the installer ban uses.
put( $P . '/wp-file-manager-pro/x.php', "<?php\n" );
$removed = WPS_Blocker::enforce_policy_ban();
check( 'a renamed or pro variant is removed too', in_array( 'wp-file-manager-pro', $removed, true ), json_encode( $removed ) );

// A file that is merely named like a banned plugin but is not our tombstone is left alone.
put( $P . '/fileorganizer-notes', "some notes the operator wrote\n" );
WPS_Blocker::enforce_policy_ban();
check( 'a non-tombstone file is never deleted', is_file( $P . '/fileorganizer-notes' ) );

// Protect Uploads (operator ban, 1.4.128): its slug, two folder names it was found under, and
// the same plugin under a folder name nobody has listed.
$pu = "<?php\n/**\n * Plugin Name:       Protect Uploads\n * Version:           0.3\n */\n";
put( $P . '/rcromlb/protect-uploads.php', $pu );
put( $P . '/hvmosjt/protect-uploads.php', $pu );
put( $P . '/zzqq-random-77/protect-uploads.php', $pu );
put( $P . '/zzqq-random-77/includes/class-protect-uploads.php', "<?php\n" );
$removed = WPS_Blocker::enforce_policy_ban();
check( 'the two listed folder names are removed', in_array( 'rcromlb', $removed, true ) && in_array( 'hvmosjt', $removed, true ), json_encode( $removed ) );
check( 'the same plugin under an unlisted folder name is removed by its main file', in_array( 'zzqq-random-77', $removed, true ), json_encode( $removed ) );
check( 'tombstones sit where all three were', is_file( $P . '/rcromlb' ) && is_file( $P . '/hvmosjt' ) && is_file( $P . '/zzqq-random-77' ) );
check( 'the activation guard refuses its main file under any folder', WPS_Blocker::is_policy_banned( 'rcromlb/protect-uploads.php' ) && WPS_Blocker::is_policy_banned( 'anything-at-all/protect-uploads.php' ) );

// Near misses stay.
put( $P . '/compat-bridge/protect-uploads-compat.php', "<?php\n/* Plugin Name: Compat Bridge */\n" );
put( $P . '/notaplugin/protect-uploads.php', "<?php\n// a file with the name but no plugin header\n" );
put( $P . '/wp-protect-me/wp-protect-me.php', "<?php\n/* Plugin Name: Protect Me */\n" );
$removed = WPS_Blocker::enforce_policy_ban();
check( 'a plugin that only has a file with the word in its name is left alone', is_file( $P . '/compat-bridge/protect-uploads-compat.php' ) && ! in_array( 'compat-bridge', $removed, true ), json_encode( $removed ) );
check( 'a file with the exact name but no plugin header is left alone', is_file( $P . '/notaplugin/protect-uploads.php' ) && ! in_array( 'notaplugin', $removed, true ), json_encode( $removed ) );
check( 'a similar but different plugin name is left alone', is_file( $P . '/wp-protect-me/wp-protect-me.php' ) );

// Our own directory is never touched even if the policy list names it.
$GLOBALS['opts'][ WPS_OPTION ] = [ 'policy_banned_slugs' => "wp-perf-shield-self\n" ];
WPS_Blocker::enforce_policy_ban();
check( 'the plugin never removes itself', is_dir( WPS_DIR ) );
unset( $GLOBALS['opts'][ WPS_OPTION ] );

// Ban switched off: nothing removed, tombstones cleaned up.
$GLOBALS['opts'][ WPS_OPTION ] = [ 'policy_ban_enabled' => '0' ];
unlink( $P . '/wp-file-manager' );
drop();
$removed = WPS_Blocker::enforce_policy_ban();
check( 'ban off: a banned folder is left alone', [] === $removed && is_dir( $P . '/wp-file-manager' ), json_encode( $removed ) );
check( 'ban off: leftover tombstones are deleted', ! file_exists( $P . '/wp-file-manager-pro' ), 'tombstone still present' );
unset( $GLOBALS['opts'][ WPS_OPTION ] );

$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $tmp, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::CHILD_FIRST );
foreach ( $it as $f ) {
	$f->isDir() ? @rmdir( $f->getPathname() ) : @unlink( $f->getPathname() );
}
@rmdir( $tmp );
echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
