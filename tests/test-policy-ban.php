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

class WP_Error { public $code; public $message; public function __construct( $c = '', $m = '' ) { $this->code = $c; $this->message = $m; } }
function esc_html( $s ) { return $s; }

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
	public static function quarantine_and_remove_option( string $name, array $meta = [] ): ?string { unset( $GLOBALS['opts'][ $name ] ); return 'o'; }
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
function drop( string $slug = 'filebird' ): void {
	put( WP_PLUGIN_DIR . '/' . $slug . '/' . $slug . '.php', "<?php\n/* Plugin Name: " . $slug . " */\n" );
	put( WP_PLUGIN_DIR . '/' . $slug . '/lib/x.php', "<?php\n" );
}

put( $P . '/fine/fine.php', "<?php\n/* Plugin Name: Fine */\n" );
drop();
$removed = WPS_Blocker::enforce_policy_ban();
check( 'banned folder is removed', [ 'filebird' ] === $removed, json_encode( $removed ) );
check( 'it is quarantined, so restorable', 1 === count( glob( $tmp . '/q/*' ) ) );
check( 'a tombstone FILE now sits where the folder was', is_file( $P . '/filebird' ) && ! is_dir( $P . '/filebird' ) );
check( 'a plain re-extract cannot create the directory over it', false === @mkdir( $P . '/filebird' ) );
check( 'an unrelated plugin is untouched', is_file( $P . '/fine/fine.php' ) );
check( 'the removal is logged with its provenance', 1 === events( 'policy_ban_enforced' ) && false !== strpos( end( $GLOBALS['events'] )[1], 'seen 1x' ), json_encode( $GLOBALS['events'] ) );

// Something removes the tombstone and drops the plugin again (second return).
unlink( $P . '/filebird' );
drop();
WPS_Blocker::enforce_policy_ban();
check( 'second return is counted and raised as a re-drop', 2 === $GLOBALS['opts']['wps_ban_redrops']['filebird']['count'] && 1 === events( 'policy_ban_redrop' ) && 1 === $GLOBALS['mails'], json_encode( $GLOBALS['opts']['wps_ban_redrops'] ?? null ) . ' mails=' . $GLOBALS['mails'] );

// Third and fourth returns: the first three are quarantined; after that nothing more is stored.
unlink( $P . '/filebird' ); drop(); WPS_Blocker::enforce_policy_ban();
$after3 = count( glob( $tmp . '/q/*' ) );
unlink( $P . '/filebird' ); drop(); WPS_Blocker::enforce_policy_ban();
check( 'after repeated returns the quarantine store stops growing', 3 === $after3 && 3 === count( glob( $tmp . '/q/*' ) ), $after3 . ' / ' . count( glob( $tmp . '/q/*' ) ) );
check( 'the folder is still removed once quarantining stops', ! is_dir( $P . '/filebird' ) && is_file( $P . '/filebird' ) );

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

// A tombstone written for a folder banned by its main file (an arbitrary name) must SURVIVE the
// next sweep; it used to be deleted because that folder name is not itself banned.
WPS_Blocker::enforce_policy_ban();
check( 'a main-file tombstone survives the next sweep', is_file( $P . '/zzqq-random-77' ) && false !== strpos( (string) file_get_contents( $P . '/zzqq-random-77' ), 'slug: protect-uploads' ), (string) @file_get_contents( $P . '/zzqq-random-77' ) );

// A folder padded with hundreds of harmless files must not hide its main file.
put( $P . '/padded-zzz/protect-uploads.php', $pu );
for ( $i = 0; $i < 600; $i++ ) {
	put( $P . '/padded-zzz/assets/f' . $i . '.txt', 'x' );
}
$removed = WPS_Blocker::enforce_policy_ban();
check( 'a folder padded with 600 files is still found by its main file', in_array( 'padded-zzz', $removed, true ), json_encode( $removed ) );

// Near misses stay.
put( $P . '/compat-bridge/protect-uploads-compat.php', "<?php\n/* Plugin Name: Compat Bridge */\n" );
put( $P . '/notaplugin/protect-uploads.php', "<?php\n// a file with the name but no plugin header\n" );
put( $P . '/wp-protect-me/wp-protect-me.php', "<?php\n/* Plugin Name: Protect Me */\n" );
$removed = WPS_Blocker::enforce_policy_ban();
check( 'a plugin that only has a file with the word in its name is left alone', is_file( $P . '/compat-bridge/protect-uploads-compat.php' ) && ! in_array( 'compat-bridge', $removed, true ), json_encode( $removed ) );
check( 'a file with the exact name but no plugin header is left alone', is_file( $P . '/notaplugin/protect-uploads.php' ) && ! in_array( 'notaplugin', $removed, true ), json_encode( $removed ) );
check( 'a similar but different plugin name is left alone', is_file( $P . '/wp-protect-me/wp-protect-me.php' ) );

// Hard ban (1.4.129): wp-file-manager and fileorganizer are deleted outright, never quarantined.
$qbefore = count( glob( $tmp . '/q/*' ) );
$mails0  = $GLOBALS['mails'];
drop( 'wp-file-manager' );
$removed = WPS_Blocker::enforce_policy_ban();
check( 'wp-file-manager is removed on first sight', in_array( 'wp-file-manager', $removed, true ), json_encode( $removed ) );
check( 'hard ban: nothing is quarantined, so nothing can be restored', count( glob( $tmp . '/q/*' ) ) === $qbefore, $qbefore . ' -> ' . count( glob( $tmp . '/q/*' ) ) );
check( 'hard ban: a tombstone still sits where it was', is_file( $P . '/wp-file-manager' ) && ! is_dir( $P . '/wp-file-manager' ) );
check( 'hard ban: the administrator is emailed on the FIRST appearance', $GLOBALS['mails'] === $mails0 + 1, 'mails ' . $mails0 . ' -> ' . $GLOBALS['mails'] );
$last = array_values( array_filter( $GLOBALS['events'], static fn( $e ) => 'policy_ban_enforced' === $e[0] && false !== strpos( $e[1], 'wp-file-manager' ) ) );
check( 'hard ban: the log says so', $last && false !== strpos( end( $last )[1], 'hard ban' ), json_encode( $last ) );
drop( 'fileorganizer' );
$removed = WPS_Blocker::enforce_policy_ban();
check( 'fileorganizer is hard-banned too', in_array( 'fileorganizer', $removed, true ) && count( glob( $tmp . '/q/*' ) ) === $qbefore );

// WP File Manager's real main file, under a folder name nobody listed.
put( $P . '/zz-fm-123/file_folder_manager.php', "<?php\n/**\n  Plugin Name: WP File Manager\n  Version: 8.0.4\n **/\n" );
$removed = WPS_Blocker::enforce_policy_ban();
check( 'WP File Manager is found by its main file under an unlisted folder name, and deleted outright', in_array( 'zz-fm-123', $removed, true ) && count( glob( $tmp . '/q/*' ) ) === $qbefore, json_encode( $removed ) );
put( $P . '/different/file_folder_manager.php', "<?php\n/* Plugin Name: Some Other Plugin */\n" );
$removed = WPS_Blocker::enforce_policy_ban();
check( 'a file_folder_manager.php with a different plugin header is left alone', is_file( $P . '/different/file_folder_manager.php' ) && ! in_array( 'different', $removed, true ), json_encode( $removed ) );

put( $P . '/fm-addon/file_folder_manager.php', "<?php\n/**\n  Plugin Name: WP File Manager Compatible Add-on\n **/\n" );
$removed = WPS_Blocker::enforce_policy_ban();
check( 'a plugin whose header only STARTS with WP File Manager is not deleted', is_file( $P . '/fm-addon/file_folder_manager.php' ) && ! in_array( 'fm-addon', $removed, true ), json_encode( $removed ) );
put( $P . '/zz-fm-inline/file_folder_manager.php', "<?php\n/* Plugin Name: WP File Manager */\n" );
$removed = WPS_Blocker::enforce_policy_ban();
check( 'the exact header is still found when it closes on the same line as a comment', in_array( 'zz-fm-inline', $removed, true ), json_encode( $removed ) );

// The download guard.
$err = WPS_Blocker::block_banned_download( false, [], 'https://downloads.wordpress.org/plugin/wp-file-manager.8.0.5.zip' );
check( 'the download of wp-file-manager.zip is refused', $err instanceof WP_Error && 'wps_policy_banned' === $err->code );
check( 'a renamed copy of the zip is refused too', WPS_Blocker::block_banned_download( false, [], 'https://example.com/dl/wp-file-manager-pro-9.zip?x=1' ) instanceof WP_Error );
check( 'an unrelated zip is not touched', false === WPS_Blocker::block_banned_download( false, [], 'https://downloads.wordpress.org/plugin/akismet.5.3.zip' ) );
check( 'a non-zip URL that mentions the slug is not touched', false === WPS_Blocker::block_banned_download( false, [], 'https://wordpress.org/plugins/wp-file-manager/' ) );
check( 'an earlier filter that already answered is respected', [ 'x' ] === WPS_Blocker::block_banned_download( [ 'x' ], [], 'https://downloads.wordpress.org/plugin/wp-file-manager.zip' ) );

// The upload guard sees the main file inside a zip with a neutral name.
if ( class_exists( 'ZipArchive' ) ) {
	$zp = $tmp . '/neutral.zip';
	$za = new ZipArchive();
	$za->open( $zp, ZipArchive::CREATE );
	$za->addFromString( 'harmless-name/file_folder_manager.php', "<?php\n" );
	$za->close();
	$m = new ReflectionMethod( 'WPS_Blocker', 'policy_upload_match' );
	$m->setAccessible( true );
	check( 'a zip with a neutral name holding file_folder_manager.php is refused on upload', '' !== $m->invoke( null, 'neutral.zip', [ 'tmp_name' => $zp ] ) );
	$zp3 = $tmp . '/renamed.zip';
	$za3 = new ZipArchive();
	$za3->open( $zp3, ZipArchive::CREATE );
	$za3->addFromString( 'random/protect-uploads.php', "<?php\n" );
	$za3->close();
	check( 'a renamed zip holding random/protect-uploads.php is refused on upload', '' !== $m->invoke( null, 'renamed.zip', [ 'tmp_name' => $zp3 ] ) );
	$zp2 = $tmp . '/fine.zip';
	$za2 = new ZipArchive();
	$za2->open( $zp2, ZipArchive::CREATE );
	$za2->addFromString( 'fine/fine.php', "<?php\n" );
	$za2->close();
	check( 'an ordinary zip passes the upload guard', '' === $m->invoke( null, 'fine.zip', [ 'tmp_name' => $zp2 ] ) );
} else {
	echo "SKIP upload-guard cases (ZipArchive not available)\n";
}

// A banned folder whose name merely starts with this plugin's own folder name is NOT exempt.
put( $P . '/wp-perf-shield-self-filebird/x.php', "<?php\n" );
$removed = WPS_Blocker::enforce_policy_ban();
check( 'a banned folder sharing a name prefix with this plugin is still removed', in_array( 'wp-perf-shield-self-filebird', $removed, true ), json_encode( $removed ) );

// Our own directory is never touched even if the policy list names it.
$GLOBALS['opts'][ WPS_OPTION ] = [ 'policy_banned_slugs' => "wp-perf-shield-self\n" ];
WPS_Blocker::enforce_policy_ban();
check( 'the plugin never removes itself', is_dir( WPS_DIR ) );
unset( $GLOBALS['opts'][ WPS_OPTION ] );

// A file whose first line merely STARTS with the marker is not a tombstone and is never deleted.
put( $P . '/filebird-decoy', "WP-PERF-SHIELD-BAN-TOMBSTONE but this line has more text on it\n" );
WPS_Blocker::enforce_policy_ban();
check( 'a file that only begins with the marker is left alone', is_file( $P . '/filebird-decoy' ) );

// Ban switched off: nothing removed, tombstones cleaned up.
$GLOBALS['opts'][ WPS_OPTION ] = [ 'policy_ban_enabled' => '0' ];
unlink( $P . '/filebird' );
drop();
$removed = WPS_Blocker::enforce_policy_ban();
check( 'ban off: a banned folder is left alone', [] === $removed && is_dir( $P . '/filebird' ), json_encode( $removed ) );
check( 'ban off: leftover tombstones are deleted', ! file_exists( $P . '/wp-file-manager-pro' ), 'tombstone still present' );
unset( $GLOBALS['opts'][ WPS_OPTION ] );

$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $tmp, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::CHILD_FIRST );
foreach ( $it as $f ) {
	$f->isDir() ? @rmdir( $f->getPathname() ) : @unlink( $f->getPathname() );
}
@rmdir( $tmp );
echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
