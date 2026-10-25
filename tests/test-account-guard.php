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
function get_user_meta( $u, $k = '', $single = false ) {
	if ( '' === $k ) { // every key, each as a list of serialized values, as WordPress returns it
		return array_map( static fn( $v ) => [ serialize( $v ) ], $GLOBALS['meta'][ $u ] ?? [] );
	}
	return $GLOBALS['meta'][ $u ][ $k ] ?? '';
}
function update_user_meta( $u, $k, $v ) { $GLOBALS['meta'][ $u ][ $k ] = $v; return true; }
function delete_user_meta( $u, $k ) { unset( $GLOBALS['meta'][ $u ][ $k ] ); return true; }
function maybe_unserialize( $v ) { return is_string( $v ) ? @unserialize( $v ) : $v; }
function fp_key( string $ip, string $ua ): string { return '_wps_login_fp_' . md5( $ip . '|' . $ua ); }
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
class Req { // no constructor promotion: the plugin supports PHP 7.4
	public $route; public $method; public $json; public $body; public $query;
	public function __construct( string $route, string $method, array $json = [], array $body = [], array $query = [] ) {
		$this->route = $route; $this->method = $method; $this->json = $json; $this->body = $body; $this->query = $query;
	}
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
$GLOBALS['meta'][7][ fp_key( '203.0.113.5', 'Laptop' ) ]['time'] = time() - 3600; // the laptop logged in an hour ago
as_device( '198.51.100.9', 'Phone' );
WPS_Account_Guard::record_login( 'user7', $u ); // a fresh login from the phone just now
check( 'each device has its own login record row', isset( $GLOBALS['meta'][7][ fp_key( '203.0.113.5', 'Laptop' ) ], $GLOBALS['meta'][7][ fp_key( '198.51.100.9', 'Phone' ) ] ) && ! isset( $GLOBALS['meta'][7]['_wps_login_fingerprint'] ), json_encode( $GLOBALS['meta'][7] ) );

as_device( '203.0.113.5', 'Laptop' );
$GLOBALS['uid'] = 7;
WPS_Account_Guard::check_rest_write( $post, null, true );
check( 'a write from the laptop an hour after its own login is ordinary publishing, not "rapid" because the phone just logged in', [] === $GLOBALS['trashed'], json_encode( $GLOBALS['trashed'] ) );
check( 'and it taught the account the laptop', isset( $GLOBALS['meta'][7]['_wps_known_devices'][ md5( '203.0.113.5|Laptop' ) ] ) );

as_device( '198.51.100.9', 'Phone' );
WPS_Account_Guard::check_rest_write( $post, null, true );
check( 'a write from the phone seconds after its first login from a device never seen is flagged and trashed', [ 101 ] === $GLOBALS['trashed'], json_encode( $GLOBALS['trashed'] ) );
check( 'a flagged device is not remembered as known', ! isset( $GLOBALS['meta'][7]['_wps_known_devices'][ md5( '198.51.100.9|Phone' ) ] ) );

// ---- 1b. two sign-ins at the same instant keep both records (one row per device, no shared list).
$GLOBALS['meta'][8] = [];
$u8 = (object) [ 'ID' => 8, 'user_login' => 'user8' ];
as_device( '203.0.113.1', 'A' );
WPS_Account_Guard::record_login( 'user8', $u8 );
as_device( '203.0.113.2', 'B' );
WPS_Account_Guard::record_login( 'user8', $u8 );
check( 'a sign-in writes only its own device row and never rewrites the list', isset( $GLOBALS['meta'][8][ fp_key( '203.0.113.1', 'A' ) ], $GLOBALS['meta'][8][ fp_key( '203.0.113.2', 'B' ) ] ) && 2 === count( $GLOBALS['meta'][8] ), json_encode( array_keys( $GLOBALS['meta'][8] ) ) );
$GLOBALS['meta'][8][ fp_key( '203.0.113.1', 'A' ) ]['time'] = time() - 5000;
$GLOBALS['meta'][8][ fp_key( '203.0.113.2', 'B' ) ]['time'] = time() - 4000;
for ( $n = 0; $n < 25; $n++ ) { as_device( '203.0.113.' . ( 10 + $n ), 'D' ); WPS_Account_Guard::record_login( 'user8', $u8 ); }
check( 'the oldest rows are pruned past the per-account cap', 20 === count( $GLOBALS['meta'][8] ) && ! isset( $GLOBALS['meta'][8][ fp_key( '203.0.113.1', 'A' ) ] ), count( $GLOBALS['meta'][8] ) . ' rows' );
// a record written before 1.4.152 is still honoured
$GLOBALS['meta'][9] = [ '_wps_login_fingerprint' => [ 'time' => time(), 'ip' => '192.0.2.44', 'ua' => 'Scripted' ] ];

// ---- 2. the acting session is judged, not the post's author.
$GLOBALS['trashed'] = [];
$GLOBALS['uid']     = 9; // user 9 writes a post whose author field says 7
as_device( '192.0.2.44', 'Scripted' );
WPS_Account_Guard::check_rest_write( (object) [ 'ID' => 202, 'post_author' => 7 ], null, true );
check( 'a rapid write by user 9 is flagged even when the post names user 7 as author (and a pre-1.4.152 login record still counts)', [ 202 ] === $GLOBALS['trashed'], json_encode( $GLOBALS['trashed'] ) );
$GLOBALS['trashed'] = [];
$GLOBALS['uid']     = 7;
as_device( '203.0.113.5', 'Laptop' );
WPS_Account_Guard::check_rest_write( (object) [ 'ID' => 203, 'post_author' => 9 ], null, true );
check( 'and the laptop session is not punished for user 9\'s fresh login', [] === $GLOBALS['trashed'] );

// ---- 3. a remembered device expires.
$GLOBALS['meta'][7]['_wps_known_devices'][ md5( '198.51.100.9|Phone' ) ] = time() - 91 * DAY_IN_SECONDS;
$GLOBALS['meta'][7][ fp_key( '198.51.100.9', 'Phone' ) ]['time'] = time();
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

// ---- 5. XML-RPC and application passwords never fire wp_login: the first write from a device is its sign-in.
class WPS_EDR {
	public static $auth = '';
	public static $rows = [];
	public static function auth_method() { return self::$auth; }
	public static function record( $t, $c = [] ) { self::$rows[] = $t; }
}
define( 'XMLRPC_REQUEST', true );
$GLOBALS['trashed'] = [];
$GLOBALS['uid']     = 7;
as_device( '198.51.100.77', 'Python-xmlrpc' );
check( 'no login record exists for a device that has only ever used XML-RPC', ! isset( $GLOBALS['meta'][7][ fp_key( '198.51.100.77', 'Python-xmlrpc' ) ] ) );
ob_start();
WPS_Account_Guard::check_xmlrpc_write( 'wp.newPost' );
$out = ob_get_clean();
check( 'the first write over XML-RPC from a device never seen is answered with a fault', false !== strpos( $out, 'STATUS:403;' ) && false !== strpos( $out, '<fault>' ), $out );
check( 'and that first contact is recorded as the device\'s sign-in', isset( $GLOBALS['meta'][7][ fp_key( '198.51.100.77', 'Python-xmlrpc' ) ] ) );
check( 'the device is not remembered as known', ! isset( $GLOBALS['meta'][7]['_wps_known_devices'][ md5( '198.51.100.77|Python-xmlrpc' ) ] ) );
ob_start();
WPS_Account_Guard::check_xmlrpc_write( 'wp.newPost' );
$out = ob_get_clean();
check( 'a second write seconds later is refused too', false !== strpos( $out, 'STATUS:403;' ), $out );
$GLOBALS['meta'][7][ fp_key( '198.51.100.77', 'Python-xmlrpc' ) ]['time'] = time() - 3600;
ob_start();
WPS_Account_Guard::check_xmlrpc_write( 'wp.newPost' );
$out = ob_get_clean();
check( 'a write an hour after the device first authenticated passes', '' === $out, $out );
check( 'and the device is now known, as a dashboard device would be', isset( $GLOBALS['meta'][7]['_wps_known_devices'][ md5( '198.51.100.77|Python-xmlrpc' ) ] ) );

// a REST write authenticated by an application password behaves the same
WPS_EDR::$auth = 'application password "SEO Super Tool"';
as_device( '192.0.2.200', 'curl/8' );
WPS_Account_Guard::check_rest_write( (object) [ 'ID' => 303, 'post_author' => 7 ], null, true );
check( 'the first REST write with an application password from a device never seen is flagged and trashed', [ 303 ] === $GLOBALS['trashed'], json_encode( $GLOBALS['trashed'] ) );
WPS_EDR::$auth = '';

// ---- 5b. 1.4.155: the REST write is refused before it is saved, so the editor shows an error.
$GLOBALS['trashed'] = [];
$GLOBALS['uid']     = 12;
as_device( '192.0.2.120', 'NewBrowser' );
WPS_Account_Guard::record_login( 'user12', (object) [ 'ID' => 12, 'user_login' => 'user12' ] );
$r = WPS_Account_Guard::check_rest_pre_insert( (object) [ 'ID' => 404, 'post_title' => 'x' ], null );
check( 'a rapid write from a new device is refused with a REST error before it is saved', $r instanceof WP_Error && 'wps_rapid_write_refused' === $r->code && 403 === ( $r->data['status'] ?? 0 ), json_encode( $r ) );
check( 'and nothing is trashed, since nothing was written', [] === $GLOBALS['trashed'] );
$GLOBALS['meta'][12][ fp_key( '192.0.2.120', 'NewBrowser' ) ]['time'] = time() - 3600;
$p = (object) [ 'ID' => 404, 'post_title' => 'x' ];
check( 'the same save an hour later goes through untouched', $p === WPS_Account_Guard::check_rest_pre_insert( $p, null ) );
$err = new WP_Error( 'earlier', 'x' );
check( 'an error from an earlier filter is passed on', $err === WPS_Account_Guard::check_rest_pre_insert( $err, null ) );

// ---- 6. the hook accepts the three arguments core passes.
WPS_Account_Guard::register_hooks();
check( 'the REST guard is registered before the write, not after', isset( $GLOBALS['hooks']['rest_pre_insert_post'] ) && ! isset( $GLOBALS['hooks']['rest_insert_post'] ) );

// ---- 7. the refusal really ends an XML-RPC request (child process, no WPS_TESTING_NO_EXIT)
$child = sys_get_temp_dir() . '/wps-ag-exit-' . getmypid() . '.php';
file_put_contents( $child, '<?php define("ABSPATH","/x/"); define("WPS_OPTION","wps_opts"); define("DAY_IN_SECONDS",86400); define("XMLRPC_REQUEST",true);'
	. '$GLOBALS["meta"]=[]; function get_user_meta($u,$k="",$s=false){ if(""===$k){ return array_map(static fn($v)=>[serialize($v)],$GLOBALS["meta"][$u]??[]); } return $GLOBALS["meta"][$u][$k]??""; }'
	. 'function update_user_meta($u,$k,$v){ $GLOBALS["meta"][$u][$k]=$v; return true; } function delete_user_meta($u,$k){ return true; } function maybe_unserialize($v){ return @unserialize($v); }'
	. 'function get_option($k,$d=false){ return "wps_opts"===$k ? ["account_guard_lockdown"=>"0"] : $d; } function get_userdata($u){ return (object)["user_login"=>"u"]; } function get_current_user_id(){ return 3; }'
	. 'function status_header($c){ echo "STATUS:$c;"; } function wp_trash_post(){ return true; }'
	. 'require ' . var_export( dirname( __DIR__ ) . '/includes/class-account-guard.php', true ) . ';'
	. '$_SERVER["REMOTE_ADDR"]="198.51.100.200"; $_SERVER["HTTP_USER_AGENT"]="bot"; WPS_Account_Guard::check_xmlrpc_write("wp.newPost"); echo "WRITE CONTINUED";' );
$out = (string) shell_exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $child ) . ' 2>&1' );
@unlink( $child );
check( 'a refused XML-RPC write ends the request, so the method never runs', false !== strpos( $out, 'STATUS:403;' ) && false === strpos( $out, 'WRITE CONTINUED' ), $out );

check( 'the xmlrpc_call handler tolerates the (method, args, server) signature', is_callable( $GLOBALS['hooks']['xmlrpc_call'][0] ?? null ) && ( new ReflectionMethod( 'WPS_Account_Guard', 'check_xmlrpc_write' ) )->getNumberOfParameters() >= 3 );

echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
