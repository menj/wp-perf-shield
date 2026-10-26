<?php
/**
 * Regression test for post provenance, WPS_Post_Origin (1.4.157).
 *
 * Run from the command line only:  php tests/test-post-origin.php
 *
 * Every post saved through WordPress carries a record of the channel, the sign-in method, the
 * address, the cron hook and the file that asked for the save; a post newer than tracking with
 * no record was written straight into the database. The call stack is real: fixture files under
 * a fake installation call the hook, and the class names them.
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}
$tmp = sys_get_temp_dir() . '/wps-po-' . bin2hex( random_bytes( 4 ) );
foreach ( [ '/wp-includes', '/wp-admin', '/wp-content/plugins/wps-self', '/wp-content/plugins/importer', '/wp-content/themes/mine', '/wp-content/uploads/2026/10', '/wp-content/mu-plugins' ] as $d ) {
	mkdir( $tmp . $d, 0777, true );
}
define( 'ABSPATH', $tmp . '/' );
define( 'WPS_DIR', $tmp . '/wp-content/plugins/wps-self/' );
define( 'WP_CONTENT_DIR', $tmp . '/wp-content' );
define( 'WP_PLUGIN_DIR', $tmp . '/wp-content/plugins' );
define( 'WPMU_PLUGIN_DIR', $tmp . '/wp-content/mu-plugins' );

$GLOBALS['opts']  = [];
$GLOBALS['pmeta'] = [];
$GLOBALS['trans'] = [];
$GLOBALS['hooks'] = [];
$GLOBALS['uid']   = 0;
function get_option( $k, $d = false ) { return array_key_exists( $k, $GLOBALS['opts'] ) ? $GLOBALS['opts'][ $k ] : $d; }
function update_option( $k, $v, $a = null ) { $GLOBALS['opts'][ $k ] = $v; return true; }
function get_post_meta( $id, $k, $single = false ) { return $GLOBALS['pmeta'][ $id ][ $k ] ?? ''; }
function update_post_meta( $id, $k, $v ) { $GLOBALS['pmeta'][ $id ][ $k ] = $v; return true; }
function get_transient( $k ) { return $GLOBALS['trans'][ $k ] ?? false; }
function set_transient( $k, $v, $t = 0 ) { $GLOBALS['trans'][ $k ] = $v; return true; }
function add_action( $t, $cb, $p = 10, $a = 1 ) { $GLOBALS['hooks'][] = [ 'action', $t, $p ]; }
function add_filter( $t, $cb, $p = 10, $a = 1 ) { $GLOBALS['hooks'][] = [ 'filter', $t, $p ]; }
function get_current_user_id() { return $GLOBALS['uid']; }
function get_theme_root() { return WP_CONTENT_DIR . '/themes'; }
function is_admin() { return false; }
function esc_attr( $s ) { return htmlspecialchars( (string) $s, ENT_QUOTES ); }
function esc_html( $s ) { return htmlspecialchars( (string) $s, ENT_QUOTES ); }
class WPS_EDR {
	public static $auth   = 'cookie session';
	public static $events = [];
	public static function auth_method() { return self::$auth; }
	public static function record( $type, $ctx = [] ) { self::$events[] = [ $type, $ctx ]; return true; }
}
require dirname( __DIR__ ) . '/includes/class-post-origin.php';

$fail = 0;
function check( string $name, bool $ok, string $detail = '' ): void {
	global $fail;
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $name . ( $ok ? '' : ' :: ' . $detail ) . "\n";
	if ( ! $ok ) {
		++$fail;
	}
}
function post( int $id, string $type = 'post', string $status = 'publish' ): object {
	return (object) [ 'ID' => $id, 'post_type' => $type, 'post_status' => $status ];
}

// ---- 1. the channel
check( 'WP-CLI wins over everything', 'wp-cli' === WPS_Post_Origin::channel_of( true, true, true, true, true, true ) );
check( 'cron before xmlrpc', 'cron' === WPS_Post_Origin::channel_of( false, true, true, false, false, false ) );
check( 'xmlrpc', 'xmlrpc' === WPS_Post_Origin::channel_of( false, false, true, false, false, false ) );
check( 'rest', 'rest' === WPS_Post_Origin::channel_of( false, false, false, true, false, false ) );
check( 'ajax (which is_admin also claims)', 'ajax' === WPS_Post_Origin::channel_of( false, false, false, false, true, true ) );
check( 'dashboard and front end', 'admin' === WPS_Post_Origin::channel_of( false, false, false, false, false, true ) && 'front' === WPS_Post_Origin::channel_of( false, false, false, false, false, false ) );

// ---- 2. the cron hook is the outermost entry of the hook stack
check( 'the outermost hook names the cron event', 'my_importer_run' === WPS_Post_Origin::cron_hook_of( true, [ 'my_importer_run', 'wp_insert_post' ] ) );
check( 'no cron, no hook', '' === WPS_Post_Origin::cron_hook_of( false, [ 'my_importer_run' ] ) );
check( 'a bare save stack names nothing', '' === WPS_Post_Origin::cron_hook_of( true, [ 'wp_insert_post' ] ) && '' === WPS_Post_Origin::cron_hook_of( true, [] ) );

// ---- 3. the caller, from synthetic frames
$frames = static fn( array $files ) => array_map( static fn( $f ) => [ 'file' => $f ], $files );
$core   = [ ABSPATH . 'wp-includes/post.php', ABSPATH . 'wp-includes/class-wp-hook.php', ABSPATH . 'wp-admin/includes/post.php', ABSPATH . 'wp-admin/post.php', ABSPATH . 'index.php' ];
$r = WPS_Post_Origin::caller_of( $frames( array_merge( [ WPS_DIR . 'includes/class-post-origin.php' ], $core ) ) );
check( 'WordPress alone: no caller, nothing odd', '' === $r['file'] && false === $r['odd'], json_encode( $r ) );
$r = WPS_Post_Origin::caller_of( $frames( array_merge( [ WPS_DIR . 'includes/class-post-origin.php', ABSPATH . 'wp-includes/post.php', WP_PLUGIN_DIR . '/importer/importer.php' ], $core ) ) );
check( 'a plugin file is named and is not odd', 'wp-content/plugins/importer/importer.php' === $r['file'] && false === $r['odd'], json_encode( $r ) );
$r = WPS_Post_Origin::caller_of( $frames( [ ABSPATH . 'wp-includes/post.php', WP_CONTENT_DIR . '/themes/mine/functions.php', ABSPATH . 'wp-settings.php' ] ) );
check( 'a theme file is named and is not odd', 'wp-content/themes/mine/functions.php' === $r['file'] && false === $r['odd'], json_encode( $r ) );
$r = WPS_Post_Origin::caller_of( $frames( [ ABSPATH . 'wp-includes/post.php', WP_CONTENT_DIR . '/uploads/2026/10/cache.php', ABSPATH . 'wp-cron.php' ] ) );
check( 'a file in uploads is named and is odd', 'wp-content/uploads/2026/10/cache.php' === $r['file'] && true === $r['odd'], json_encode( $r ) );
$r = WPS_Post_Origin::caller_of( $frames( [ ABSPATH . 'wp-includes/post.php', ABSPATH . 'wp-conf1g.php', ABSPATH . 'index.php' ] ) );
check( 'a non-core file at the web root is odd', 'wp-conf1g.php' === $r['file'] && true === $r['odd'], json_encode( $r ) );
$r = WPS_Post_Origin::caller_of( $frames( [ ABSPATH . 'wp-includes/post.php', WPMU_PLUGIN_DIR . '/loader.php' ] ) );
check( 'an mu-plugin is code, not odd', 'wp-content/mu-plugins/loader.php' === $r['file'] && false === $r['odd'], json_encode( $r ) );
$r = WPS_Post_Origin::caller_of( $frames( [ ABSPATH . 'wp-includes/post.php', '/usr/local/bin/wp' ] ) );
check( 'a file outside the installation is odd and shown as given', '/usr/local/bin/wp' === $r['file'] && true === $r['odd'], json_encode( $r ) );
check( 'frames without a file are skipped', '' === WPS_Post_Origin::caller_of( [ [ 'function' => 'x' ] ] )['file'] );

// ---- 4. the hook, with a real call stack
file_put_contents( WP_CONTENT_DIR . '/plugins/importer/importer.php', "<?php\nfunction importer_write( \$id ) { WPS_Post_Origin::on_insert( \$id, post( \$id ), false ); }\n" );
file_put_contents( WP_CONTENT_DIR . '/uploads/2026/10/cache.php', "<?php\nfunction dropped_write( \$id, \$update = false ) { WPS_Post_Origin::on_insert( \$id, post( \$id ), \$update ); }\n" );
require WP_CONTENT_DIR . '/plugins/importer/importer.php';
require WP_CONTENT_DIR . '/uploads/2026/10/cache.php';
$_SERVER['REMOTE_ADDR']     = '203.0.113.9';
$_SERVER['REQUEST_METHOD']  = 'POST';
$_SERVER['REQUEST_URI']     = '/wp-json/wp/v2/posts';
$_SERVER['HTTP_USER_AGENT'] = 'curl/8';
$GLOBALS['uid'] = 1;
importer_write( 10 );
$o = $GLOBALS['pmeta'][10]['_wps_origin'] ?? null;
check( 'a save records channel, auth, user, address, request and caller', is_array( $o ) && 'front' === $o['channel'] && 'cookie session' === $o['auth'] && 1 === $o['user'] && '203.0.113.9' === $o['ip'] && 'POST /wp-json/wp/v2/posts' === $o['request'] && 'wp-content/plugins/importer/importer.php' === $o['caller'] && false === $o['odd'], json_encode( $o ) );
check( 'the last-write record is the same on a first save', $o === ( $GLOBALS['pmeta'][10]['_wps_last_write'] ?? null ) );
check( 'a plugin writing a post is no event', [] === WPS_EDR::$events, json_encode( WPS_EDR::$events ) );

WPS_EDR::$auth = 'application password "PBN Automation (WPU)"';
$_SERVER['REMOTE_ADDR'] = '198.51.100.7';
dropped_write( 10, true );
check( 'an update keeps the creation record and replaces the last-write record', $o === $GLOBALS['pmeta'][10]['_wps_origin'] && '198.51.100.7' === $GLOBALS['pmeta'][10]['_wps_last_write']['ip'] && true === $GLOBALS['pmeta'][10]['_wps_last_write']['odd'] );
check( 'a file in uploads writing a post is a high event naming the file', 1 === count( WPS_EDR::$events ) && 'post_written_by_unexpected_file' === WPS_EDR::$events[0][0] && false !== strpos( WPS_EDR::$events[0][1]['notes'], 'wp-content/uploads/2026/10/cache.php' ) && 'high' === WPS_EDR::$events[0][1]['severity'], json_encode( WPS_EDR::$events ) );
dropped_write( 11 );
check( 'the same file is reported once an hour, not per post', 1 === count( WPS_EDR::$events ) && isset( $GLOBALS['pmeta'][11]['_wps_origin'] ) );
check( 'an update of a post with no record gains one', ( function () { dropped_write( 12, true ); return isset( $GLOBALS['pmeta'][12]['_wps_origin'] ) && 'wp-content/uploads/2026/10/cache.php' === $GLOBALS['pmeta'][12]['_wps_origin']['caller']; } )() );
WPS_Post_Origin::on_insert( 13, post( 13, 'revision' ), false );
WPS_Post_Origin::on_insert( 14, post( 14, 'post', 'auto-draft' ), false );
WPS_Post_Origin::on_insert( 0, post( 0 ), false );
check( 'revisions, auto-drafts and a missing id are skipped', ! isset( $GLOBALS['pmeta'][13] ) && ! isset( $GLOBALS['pmeta'][14] ) && ! isset( $GLOBALS['pmeta'][0] ) );

// ---- 5. the label on the Posts screen
check( 'a dashboard save', 'Dashboard · cookie session · 203.0.113.9' === WPS_Post_Origin::origin_label( [ 'channel' => 'admin', 'auth' => 'cookie session', 'ip' => '203.0.113.9' ], true ) );
check( 'a REST save with an application password', 'REST API · application password "PBN Automation (WPU)" · 193.24.211.106' === WPS_Post_Origin::origin_label( [ 'channel' => 'rest', 'auth' => 'application password "PBN Automation (WPU)"', 'ip' => '193.24.211.106' ], true ) );
check( 'a cron save names the hook and not the auth', 'WP-Cron · hook autoposter_tick' === WPS_Post_Origin::origin_label( [ 'channel' => 'cron', 'cron' => 'autoposter_tick', 'auth' => 'wp-cron', 'ip' => '' ], true ) );
check( 'an odd caller is named', 'front end · 198.51.100.7 · by wp-content/uploads/2026/10/cache.php' === WPS_Post_Origin::origin_label( [ 'channel' => 'front', 'auth' => '', 'ip' => '198.51.100.7', 'caller' => 'wp-content/uploads/2026/10/cache.php', 'odd' => true ], true ) );
check( 'no record: inside tracking it was not WordPress; before tracking it is unknown', 'Not through WordPress' === WPS_Post_Origin::origin_label( '', true ) && 'Before tracking' === WPS_Post_Origin::origin_label( '', false ) );
check( 'the column is added', isset( WPS_Post_Origin::add_column( [ 'title' => 'Title' ] )['wps_origin'] ) && 'x' === WPS_Post_Origin::add_column( 'x' ) );

// ---- 6. posts that never passed through WordPress
class Stub_Wpdb {
	public $posts = 'wp_posts';
	public $postmeta = 'wp_postmeta';
	public $sql = '';
	public $rows = [];
	public function prepare( $sql, ...$args ) { return $sql . ' |' . implode( ',', $args ); }
	public function get_results( $sql ) { $this->sql = $sql; return $this->rows; }
}
$db = new Stub_Wpdb();
$since = 1_760_000_000;
check( 'nothing to look for before tracking began', [] === WPS_Post_Origin::find_untracked( $db, 0 ) && '' === $db->sql );
$db->rows = [ (object) [ 'ID' => 501, 'post_title' => 'Buy now', 'post_type' => 'post', 'post_status' => 'publish', 'post_author' => 1, 'post_date_gmt' => '2026-10-20 05:55:00', 'post_modified_gmt' => '2026-10-20 05:55:00' ] ];
$rows = WPS_Post_Origin::find_untracked( $db, $since, 25 );
check( 'the query joins the origin record, limits to posts and pages, and cuts at the tracking date', 1 === count( $rows ) && false !== strpos( $db->sql, "meta_key = %s" ) && false !== strpos( $db->sql, "IN ('post','page')" ) && false !== strpos( $db->sql, '_wps_origin,' . gmdate( 'Y-m-d H:i:s', $since ) . ',25' ), $db->sql );
$f = WPS_Post_Origin::untracked_finding( $rows, $since );
check( 'one high finding naming the post, its author and its time', 1 === count( $f ) && 'high' === $f[0]['severity'] && false !== strpos( $f[0]['subject'], '#501 "Buy now" (post, publish, author #1, 2026-10-20 05:55:00 UTC)' ), json_encode( $f ) );
check( 'no rows, no finding', [] === WPS_Post_Origin::untracked_finding( [], $since ) );
$many = array_fill( 0, 14, $rows[0] );
check( 'more than ten are counted, not listed', false !== strpos( WPS_Post_Origin::untracked_finding( $many, $since )[0]['subject'], '14 posts' ) && false !== strpos( WPS_Post_Origin::untracked_finding( $many, $since )[0]['subject'], 'and 4 more' ) );

// ---- 7. registration
$GLOBALS['hooks'] = [];
WPS_Post_Origin::register_hooks();
check( 'tracking start is recorded once and the save hook registered at priority 1', is_int( $GLOBALS['opts']['wps_origin_since'] ?? null ) && in_array( [ 'action', 'wp_insert_post', 1 ], $GLOBALS['hooks'], true ) );
$was = $GLOBALS['opts']['wps_origin_since'];
WPS_Post_Origin::register_hooks();
check( 'a second registration keeps the original start date', $was === $GLOBALS['opts']['wps_origin_since'] );

exec( 'rm -rf ' . escapeshellarg( $tmp ) );
echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
