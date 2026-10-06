<?php
/**
 * Regression test for the "Delete this path" button's removal routine,
 * WPS_Scanner::remediate_manually().
 *
 * Run from the command line only:  php tests/test-manual-removal.php
 *
 * The options table, logger and quarantine store are replaced with small
 * in-memory stand-ins; the scanner code under test is the real file.
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}

$tmp = sys_get_temp_dir() . '/wps-mr-' . bin2hex( random_bytes( 4 ) );
mkdir( $tmp . '/plugins', 0777, true );
mkdir( $tmp . '/mu', 0777, true );
mkdir( $tmp . '/self', 0777, true );
mkdir( $tmp . '/q', 0777, true );

define( 'ABSPATH', $tmp . '/' );
define( 'WPS_DIR', $tmp . '/self/' );
define( 'WPS_OPTION', 'wps_opts' );
define( 'WP_PLUGIN_DIR', $tmp . '/plugins' );
define( 'WPMU_PLUGIN_DIR', $tmp . '/mu' );
define( 'WP_CONTENT_DIR', $tmp );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'DAY_IN_SECONDS', 86400 );

$GLOBALS['opts']    = [];
$GLOBALS['qopts']   = [];
$GLOBALS['events']  = [];
$GLOBALS['q_fail']  = false;
function get_option( $k, $d = false ) { return array_key_exists( $k, $GLOBALS['opts'] ) ? $GLOBALS['opts'][ $k ] : $d; }
function update_option( $k, $v ) { $GLOBALS['opts'][ $k ] = $v; return true; }
function delete_transient() { return true; }
function apply_filters( $t, $v ) { return $v; }

class WPS_Logger {
	public static function log_event( $t, $s, $ip = '' ) { $GLOBALS['events'][] = $t; }
	public static function write( $m ) {}
}
class WPS_Quarantine {
	public static function store_dir(): string { return ABSPATH . 'q'; }
	public static function is_quarantine_path( string $p ): bool { return false; }
	public static function quarantine( string $path, array $meta = [], bool $move = true ): ?string {
		if ( $GLOBALS['q_fail'] ) {
			return null;
		}
		$id = 'q' . count( glob( ABSPATH . 'q/*' ) );
		rename( $path, ABSPATH . 'q/' . $id );
		return $id;
	}
	/** Like the real class: writes a snapshot and leaves the option where it is. */
	public static function quarantine_option( string $name, array $meta = [] ): ?string {
		if ( ! empty( $GLOBALS['snapshot_fail'] ) ) {
			return null;
		}
		$GLOBALS['qopts'][] = $name;
		return 'o' . count( $GLOBALS['qopts'] );
	}
	/** Like the real class: snapshot first, remove only if the snapshot was written. */
	public static function quarantine_and_remove_option( string $name, array $meta = [] ): ?string {
		$id = self::quarantine_option( $name, $meta );
		if ( null === $id ) {
			return null;
		}
		unset( $GLOBALS['opts'][ $name ] );
		return $id;
	}
}

require dirname( __DIR__ ) . '/includes/class-wps-utils.php';
require dirname( __DIR__ ) . '/includes/class-scanner.php';

function put( string $p, string $c ): void {
	@mkdir( dirname( $p ), 0777, true );
	file_put_contents( $p, $c );
}
$fail = 0;
function check( string $name, bool $ok, string $detail = '' ): void {
	global $fail;
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $name . ( $ok ? '' : ' :: ' . $detail ) . "\n";
	if ( ! $ok ) {
		++$fail;
	}
}

// Fixture A: a worm-shaped plugin quoting its option family, with options stored.
$worm = "<?php\n/* Plugin Name: WP Link Helper */\n";
foreach ( [ 'wlh_key', 'wlh_cdn', 'wlh_origin', 'wlh_hide_self', 'wlh_bot_hits' ] as $o ) {
	$worm .= "get_option( '$o' );\n";
}
put( WP_PLUGIN_DIR . '/wp-link-helper/wp-link-helper.php', $worm );
foreach ( [ 'wlh_key', 'wlh_cdn', 'wlh_origin', 'wlh_hide_self', 'wlh_bot_hits', 'unrelated_opt' ] as $o ) {
	$GLOBALS['opts'][ $o ] = 'x';
}
put( WP_PLUGIN_DIR . '/keep/keep.php', "<?php\n/* Plugin Name: Keep */\n" );
$GLOBALS['opts']['active_plugins'] = [ 'wp-link-helper/wp-link-helper.php', 'keep/keep.php' ];

$r = WPS_Scanner::remediate_manually( WP_PLUGIN_DIR . '/wp-link-helper' );
check( 'worm folder removal succeeds', $r['ok'], $r['message'] );
check( 'worm folder is quarantined, not just deleted', null !== $r['quarantined'] && ! is_dir( WP_PLUGIN_DIR . '/wp-link-helper' ) && is_dir( ABSPATH . 'q/' . $r['quarantined'] ) );
check( 'worm options are quarantined with it', 5 === count( array_intersect( $GLOBALS['qopts'], [ 'wlh_key', 'wlh_cdn', 'wlh_origin', 'wlh_hide_self', 'wlh_bot_hits' ] ) ), implode( ',', $GLOBALS['qopts'] ) );
check( 'worm options are REMOVED from the options table, not just snapshotted', ! array_intersect( array_keys( $GLOBALS['opts'] ), [ 'wlh_key', 'wlh_cdn', 'wlh_origin', 'wlh_hide_self', 'wlh_bot_hits' ] ), implode( ',', array_keys( $GLOBALS['opts'] ) ) );
check( 'an unrelated option is left alone', 'x' === get_option( 'unrelated_opt' ) );
check( 'removed plugin is deactivated, others kept', [ 'keep/keep.php' ] === get_option( 'active_plugins' ), json_encode( get_option( 'active_plugins' ) ) );
check( 'message says restorable and names the options', false !== strpos( $r['message'], 'restorable' ) && false !== strpos( $r['message'], 'option' ), $r['message'] );

// Fixture B: a header-less payload folder whose uninstall.php declares options.
put( WP_PLUGIN_DIR . '/blobby-3f8f/uninstall.php', "<?php\ndelete_option('blobby_initialized');\ndelete_option('blobby_cfg');\n" );
put( WP_PLUGIN_DIR . '/blobby-3f8f/res/cache.dat', str_repeat( "\x01\x02\xfe", 400 ) );
$GLOBALS['opts']['blobby_initialized'] = 1;
$GLOBALS['opts']['blobby_cfg']         = 1;
$GLOBALS['qopts']                      = [];
$r = WPS_Scanner::remediate_manually( WP_PLUGIN_DIR . '/blobby-3f8f' );
check( 'header-less folder: uninstall.php options quarantined', 2 === count( $GLOBALS['qopts'] ) && ! is_dir( WP_PLUGIN_DIR . '/blobby-3f8f' ), implode( ',', $GLOBALS['qopts'] ) . ' ' . $r['message'] );
check( 'header-less folder: those options are removed too', ! isset( $GLOBALS['opts']['blobby_initialized'] ) && ! isset( $GLOBALS['opts']['blobby_cfg'] ) );

// Fixture C: a real plugin with a header and an uninstall.php must NOT lose its options.
put( WP_PLUGIN_DIR . '/real/real.php', "<?php\n/* Plugin Name: Real */\n" );
put( WP_PLUGIN_DIR . '/real/uninstall.php', "<?php\ndelete_option('real_settings');\n" );
$GLOBALS['opts']['real_settings'] = 'keepme';
$GLOBALS['qopts']                 = [];
$r = WPS_Scanner::remediate_manually( WP_PLUGIN_DIR . '/real' );
check( 'plugin with a header: its options are not touched', 'keepme' === get_option( 'real_settings' ) && [] === $GLOBALS['qopts'], implode( ',', $GLOBALS['qopts'] ) );

// Fixture C2: if the snapshot cannot be written, the option is NOT deleted and is not reported as cleared.
put( WP_PLUGIN_DIR . '/worm2/worm2.php', "<?php\n/* Plugin Name: Worm2 */\nget_option( 'wlh_key' );\nget_option( 'wlh_cdn' );\nget_option( 'wlh_origin' );\n" );
$GLOBALS['opts']['wlh_key'] = $GLOBALS['opts']['wlh_cdn'] = $GLOBALS['opts']['wlh_origin'] = 'v';
$GLOBALS['snapshot_fail']   = true;
$r = WPS_Scanner::remediate_manually( WP_PLUGIN_DIR . '/worm2' );
$GLOBALS['snapshot_fail']   = false;
check( 'a failed snapshot never destroys the only copy of an option', 'v' === ( $GLOBALS['opts']['wlh_key'] ?? null ) && 'v' === ( $GLOBALS['opts']['wlh_cdn'] ?? null ), json_encode( $GLOBALS['opts'] ) );
check( 'and it is not reported as cleared', false === strpos( $r['message'], 'cleared' ), $r['message'] );
unset( $GLOBALS['opts']['wlh_key'], $GLOBALS['opts']['wlh_cdn'], $GLOBALS['opts']['wlh_origin'] );

// Fixture D: a loose mu-plugins file.
put( WPMU_PLUGIN_DIR . '/loader.php', "<?php\nrequire_once __DIR__ . '/x/x.php';\n" );
$r = WPS_Scanner::remediate_manually( WPMU_PLUGIN_DIR . '/loader.php' );
check( 'single file is quarantined too', $r['ok'] && null !== $r['quarantined'] && ! file_exists( WPMU_PLUGIN_DIR . '/loader.php' ), $r['message'] );

// Fixture E: quarantine fails -> nothing deleted, operator told why.
put( WP_PLUGIN_DIR . '/stays/stays.php', "<?php\n" );
$GLOBALS['q_fail'] = true;
$r = WPS_Scanner::remediate_manually( WP_PLUGIN_DIR . '/stays' );
check( 'quarantine failure deletes nothing', ! $r['ok'] && is_file( WP_PLUGIN_DIR . '/stays/stays.php' ) && false !== strpos( $r['message'], 'nothing was deleted' ), $r['message'] );
$GLOBALS['q_fail'] = false;

// Fixture F: quarantine switched off -> permanent delete, as configured.
$GLOBALS['opts'][ WPS_OPTION ] = [ 'quarantine_enabled' => '0' ];
$r = WPS_Scanner::remediate_manually( WP_PLUGIN_DIR . '/stays' );
check( 'quarantine disabled: deleted outright', $r['ok'] && null === $r['quarantined'] && ! is_dir( WP_PLUGIN_DIR . '/stays' ), $r['message'] );
unset( $GLOBALS['opts'][ WPS_OPTION ] );

// Fixture G: already gone.
$r = WPS_Scanner::remediate_manually( WP_PLUGIN_DIR . '/does-not-exist' );
check( 'missing path reports already gone', $r['ok'] );

$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $tmp, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::CHILD_FIRST );
foreach ( $it as $f ) {
	$f->isDir() ? @rmdir( $f->getPathname() ) : @unlink( $f->getPathname() );
}
@rmdir( $tmp );
echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
