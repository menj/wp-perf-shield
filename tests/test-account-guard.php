<?php
/**
 * Regression test for WPS_Account_Guard (1.4.152).
 *
 * Run from the command line only:  php tests/test-account-guard.php
 *
 * Covers the four findings of the whole-code-base review: the login fingerprint is kept per
 * device, a REST write is judged by the session making it, the role-change block reads the
 * parameter wherever core would, a remembered device expires, and an XML-RPC write that matches the
 * takeover shape is refused instead of merely logged for next time.
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}
define( 'ABSPATH', '/x/' );
define( 'WPS_OPTION', 'wps_opts' );
define( 'DAY_IN_SECONDS', 86400 );
define( 'WPS_TESTING_NO_EXIT', true );

$GLOBALS['meta']    = [];
$GLOBALS['opts']    = [];
$GLOBALS['trashed'] = [];
$GLOBALS['uid']     = 0;
$GLOBALS['hooks']   = [];
function get_user_meta( $u, $k, $single = false ) { return $GLOBALS['meta'][ $u ][ $k ] ?? ''; }
function update_user_meta( $u, $k, $v ) { $GLOBALS['meta'][ $u ][ $k ] = $v; return true; }
function get_option( $k, $d = false ) { return $GLOBALS['opts'][ $k ] ?? $d; }
function get_userdata( $u ) { return (object) [ 'ID' => $u, 'user_login' => 'user' . $u ]; }
function wp_trash_post( $id ) { $GLOBALS['trashed'][] = $id; return true; }
function get_current_user_id() { return $GLOBALS['uid']; }
function is_user_logged_in() { return $GLOBALS['uid'] > 0; }
function add_action( $h, $cb, $p = 10, $a = 1 ) { $GLOBALS['hooks'][ $h ] = [ $cb, $a ]; }
function add_filter( $h, $cb, $p = 10, $a = 1 ) { $GLOBALS['hooks'][ $h ] = [ $cb, $a ]; }
function status_header( $c ) { echo "STATUS:$c;"; }
function get_bloginfo( $k ) { return 'UTF-8'; }
function __( $s, $d = '' ) { return $s; }
function wp_json_encode( $v ) { return json_encode( $v ); }
class WP_Error { public $code; public $message; public $data; public function __construct( $c = '', $m = '', $d = [] ) { $this->code = $c; $this->message = $m; $this->data = $d; } }
class Req {
	public function __construct( public string $route, public string $method, public array $json = [], public array $body = [], public array $query = [] ) {}
	public function get_route() { return $this->route; }
	public function get_method() { return $this->method; }
	public function get_json_params() { return $this->json; }
	public function get_body_params() { return $this->body; }
	public function get_query_params() { return $this->query; }
	public function get_param( $k ) { return $this->json[ $k ] ?? $this->body[ $k ] ?? $this->query[ $k ] ?? null; }
}

require dirname( __DIR__ ) . '/includes/class-account-guard.php';

$fail = 0;
function check( string $name, bool $ok, string $detail = '' ): void {
	global $fail;
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $name . ( $ok ? '' : ' :: ' . $detail ) . "\n";
	if ( ! $ok ) {
		++$fail;
	}
}
function as_device( string $ip, string $ua ): void {
	$_SERVER['REMOTE_ADDR']     = $ip;
	$_SERVER['HTTP_USER_AGENT'] = $ua;
}
$u    = (object) [ 'ID' => 7, 'user_login' => 'user7' ];
$post = (object) [ 'ID' => 101, 'post_author' => 7 ];
$GLOBALS['opts']['wps_opts'] = [ 'account_guard_lockdown' => '0' ]; // no WPS_Blocker here; keep the trash path only

// ---- 1. one login record per device.
as_device( '203.0.113.5', 'Laptop' );
WPS_Account_Guard::record_login( 'user7', $u );
$GLOBALS['meta'][7]['_wps_login_fingerprint'][ md5( '203.0.113.5|Laptop' ) ]['time'] = time() - 3600; // the laptop logged in an hour ago
as_device( '198.51.100.9', 'Phone' );
WPS_Account_Guard::record_login( 'user7', $u ); // a fresh login from the phone just now
check( 'the login fingerprint holds one record per device', 2 === count( $GLOBALS['meta'][7]['_wps_login_fingerprint'] ), json_encode( $GLOBALS['meta'][7] ) );

as_device( '203.0.113.5', 'Laptop' );
$GLOBALS['uid'] = 7;
WPS_Account_Guard::check_rest_write( $post, null, true );
check( 'a write from the laptop an hour after its own login is ordinary publishing, not "rapid" because the phone just logged in', [] === $GLOBALS['trashed'], json_encode( $GLOBALS['trashed'] ) );
check( 'and it taught the account the laptop', isset( $GLOBALS['meta'][7]['_wps_known_devices'][ md5( '203.0.113.5|Laptop' ) ] ) );

as_device( '198.51.100.9', 'Phone' );
WPS_Account_Guard::check_rest_write( $post, null, true );
check( 'a write from the phone seconds after its first login from a device never seen is flagged and trashed', [ 101 ] === $GLOBALS['trashed'], json_encode( $GLOBALS['trashed'] ) );
check( 'a flagged device is not remembered as known', ! isset( $GLOBALS['meta'][7]['_wps_known_devices'][ md5( '198.51.100.9|Phone' ) ] ) );

// ---- 2. the acting session is judged, not the post's author.
$GLOBALS['trashed'] = [];
$GLOBALS['uid']     = 9; // user 9 writes a post whose author field says 7
as_device( '192.0.2.44', 'Scripted' );
WPS_Account_Guard::record_login( 'user9', (object) [ 'ID' => 9, 'user_login' => 'user9' ] );
WPS_Account_Guard::check_rest_write( (object) [ 'ID' => 202, 'post_author' => 7 ], null, true );
check( 'a rapid write by user 9 is flagged even when the post names user 7 as author', [ 202 ] === $GLOBALS['trashed'], json_encode( $GLOBALS['trashed'] ) );
$GLOBALS['trashed'] = [];
$GLOBALS['uid']     = 7;
as_device( '203.0.113.5', 'Laptop' );
WPS_Account_Guard::check_rest_write( (object) [ 'ID' => 203, 'post_author' => 9 ], null, true );
check( 'and the laptop session is not punished for user 9\'s fresh login', [] === $GLOBALS['trashed'] );

// ---- 3. a remembered device expires.
$GLOBALS['meta'][7]['_wps_known_devices'][ md5( '198.51.100.9|Phone' ) ] = time() - 91 * DAY_IN_SECONDS;
$GLOBALS['meta'][7]['_wps_login_fingerprint'][ md5( '198.51.100.9|Phone' ) ]['time'] = time();
as_device( '198.51.100.9', 'Phone' );
WPS_Account_Guard::check_rest_write( $post, null, true );
check( 'a device last seen 91 days ago is no longer trusted', [ 101 ] === $GLOBALS['trashed'], json_encode( $GLOBALS['trashed'] ) );

// ---- 4. the role-change block reads the parameter wherever core would.
$GLOBALS['uid'] = 5;
$r = WPS_Account_Guard::guard_critical_rest_writes( null, null, new Req( '/wp/v2/users/5', 'POST', [], [], [ 'roles' => [ 'administrator' ] ] ) );
check( 'a role sent on the query string is blocked', $r instanceof WP_Error && 'wps_role_change_disabled' === $r->code, json_encode( $r ) );
$r = WPS_Account_Guard::guard_critical_rest_writes( null, null, new Req( '/wp/v2/users/5', 'POST', [ 'roles' => [ 'editor' ] ] ) );
check( 'a role in the JSON body is still blocked', $r instanceof WP_Error );
$r = WPS_Account_Guard::guard_critical_rest_writes( null, null, new Req( '/wp/v2/users/5', 'POST', [ 'description' => 'hi' ] ) );
check( 'a profile edit with no role passes', null === $r );

// ---- 5. XML-RPC: the flagged write is refused, and a write over XML-RPC never teaches a device.
define( 'XMLRPC_REQUEST', true );
$GLOBALS['trashed'] = [];
$GLOBALS['uid']     = 7;
as_device( '198.51.100.77', 'Python-xmlrpc' );
$GLOBALS['meta'][7]['_wps_login_fingerprint'][ md5( '198.51.100.77|Python-xmlrpc' ) ] = [ 'time' => time(), 'ip' => '198.51.100.77', 'ua' => 'Python-xmlrpc' ];
ob_start();
WPS_Account_Guard::check_xmlrpc_write( 'wp.newPost' );
$out = ob_get_clean();
check( 'a rapid first write over XML-RPC from a new device is answered with a fault', false !== strpos( $out, 'STATUS:403;' ) && false !== strpos( $out, '<fault>' ), $out );
$GLOBALS['meta'][7]['_wps_login_fingerprint'][ md5( '198.51.100.77|Python-xmlrpc' ) ]['time'] = time() - 3600;
ob_start();
WPS_Account_Guard::check_xmlrpc_write( 'wp.newPost' );
$out = ob_get_clean();
check( 'a later XML-RPC write passes', '' === $out, $out );
check( 'but never adds the device to the known list, since XML-RPC never logged in through wp_login', ! isset( $GLOBALS['meta'][7]['_wps_known_devices'][ md5( '198.51.100.77|Python-xmlrpc' ) ] ) );

// ---- 6. the hook accepts the three arguments core passes.
WPS_Account_Guard::register_hooks();
check( 'the xmlrpc_call handler tolerates the (method, args, server) signature', is_callable( $GLOBALS['hooks']['xmlrpc_call'][0] ?? null ) && ( new ReflectionMethod( 'WPS_Account_Guard', 'check_xmlrpc_write' ) )->getNumberOfParameters() >= 3 );

echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
