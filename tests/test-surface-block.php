<?php
/**
 * Regression test: a permanent block reaches beyond sign-in (1.4.148).
 *
 * Run from the command line only:  php tests/test-surface-block.php
 *
 * Incident: an address permanently blocked at 14:34 uploaded 24 files through
 * xmlrpc.php at 14:38, because the block only ran on `authenticate`. The block
 * now also refuses XML-RPC, REST requests that write, and uploads.
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}
define( 'ABSPATH', '/x/' );
define( 'WPS_OPTION', 'wps_opts' );
class WP_Error {
	public $code;
	public $data;
	public function __construct( $code = '', $msg = '', $data = [] ) {
		$this->code = $code;
		$this->data = $data;
	}
}
$GLOBALS['opts']     = [];
$GLOBALS['perm']     = [];
$GLOBALS['hooks']    = [];
$GLOBALS['admin_ips'] = [];
function get_option( $k, $d = false ) {
	if ( 'wps_opts' === $k ) {
		return $GLOBALS['opts'];
	}
	if ( 'wps_permanent_blocks' === $k ) {
		return $GLOBALS['perm'];
	}
	if ( false !== strpos( $k, 'admin_ips' ) ) {
		return $GLOBALS['admin_ips'];
	}
	return $d;
}
function apply_filters( $t, $v ) { return $v; }
function add_filter( $h, $cb ) { $GLOBALS['hooks'][] = $h; }
function add_action( $h, $cb ) { $GLOBALS['hooks'][] = $h; }
function get_transient() { return false; }
function set_transient() { return true; }
function is_user_logged_in() { return false; }
require dirname( __DIR__ ) . '/includes/class-login-guard.php';

$fail = 0;
function check( string $name, bool $ok, string $detail = '' ): void {
	global $fail;
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $name . ( $ok ? '' : ' :: ' . $detail ) . "\n";
	if ( ! $ok ) {
		++$fail;
	}
}
function as_ip( string $ip, string $method = 'GET', string $script = '/index.php' ): void {
	$_SERVER['REMOTE_ADDR']    = $ip;
	$_SERVER['REQUEST_METHOD'] = $method;
	$_SERVER['SCRIPT_NAME']    = $script;
	$_FILES                    = [];
}

$bad  = '198.51.100.7';
$good = '203.0.113.9';
$GLOBALS['perm'] = [ $bad => [ 'at' => time(), 'reason' => 'x' ], '192.0.2.0/24' => [ 'at' => time(), 'reason' => 'range' ] ];

// ---- surfaces
as_ip( $bad, 'POST', '/wp-admin/async-upload.php' );
check( 'async-upload.php is a blocked surface', 'upload' === WPS_Login_Guard::blocked_surface() );
as_ip( $bad, 'POST', '/wp-admin/admin-ajax.php' );
$_FILES = [ 'async-upload' => [ 'name' => 'a.php' ] ];
check( 'a POST that carries files is a blocked surface', 'upload' === WPS_Login_Guard::blocked_surface() );
as_ip( $bad, 'POST', '/wp-admin/admin-ajax.php' );
check( 'an ordinary POST with no files is not', '' === WPS_Login_Guard::blocked_surface() );
as_ip( $bad, 'GET', '/index.php' );
check( 'a page view is not', '' === WPS_Login_Guard::blocked_surface() );

// ---- REST
as_ip( $bad, 'POST', '/index.php' );
$r = WPS_Login_Guard::refuse_blocked_rest( null );
check( 'a REST write from a blocked address is refused with 403', $r instanceof WP_Error && 403 === ( $r->data['status'] ?? 0 ), json_encode( $r ) );
as_ip( $bad, 'DELETE', '/index.php' );
check( 'so is a DELETE', WPS_Login_Guard::refuse_blocked_rest( null ) instanceof WP_Error );
as_ip( $bad, 'GET', '/index.php' );
check( 'a REST read from a blocked address passes through', null === WPS_Login_Guard::refuse_blocked_rest( null ) );
as_ip( $good, 'POST', '/index.php' );
check( 'a REST write from any other address passes through', null === WPS_Login_Guard::refuse_blocked_rest( null ) );
as_ip( '192.0.2.55', 'POST', '/index.php' );
check( 'a REST write from inside a blocked range is refused', WPS_Login_Guard::refuse_blocked_rest( null ) instanceof WP_Error );
$prev = new WP_Error( 'earlier', 'x' );
as_ip( $good, 'POST' );
$kept = WPS_Login_Guard::refuse_blocked_rest( $prev );
as_ip( $bad, 'POST' );
$replaced = WPS_Login_Guard::refuse_blocked_rest( $prev );
check( 'an earlier error result is kept for an unblocked address and replaced for a blocked one', $prev === $kept && $replaced instanceof WP_Error && 'wps_address_blocked' === $replaced->code );

// ---- upload prefilter
as_ip( $bad, 'POST', '/wp-admin/async-upload.php' );
$f = WPS_Login_Guard::refuse_blocked_upload( [ 'name' => 'a.jpg', 'error' => 0 ] );
check( 'an upload from a blocked address gets an error', ! empty( $f['error'] ) );
as_ip( $good, 'POST', '/wp-admin/async-upload.php' );
$f = WPS_Login_Guard::refuse_blocked_upload( [ 'name' => 'a.jpg', 'error' => 0 ] );
check( 'an upload from any other address is untouched', 0 === $f['error'] );

// ---- the operator is never refused
$GLOBALS['opts'] = [ 'login_ip_allowlist' => $bad ];
as_ip( $bad, 'POST', '/index.php' );
check( 'an allowlisted address is never refused, even if it is on the block list', null === WPS_Login_Guard::refuse_blocked_rest( null ) && 0 === WPS_Login_Guard::refuse_blocked_upload( [ 'error' => 0 ] )['error'] );
$GLOBALS['opts'] = [];

// ---- switch and registration
check( 'the setting is on by default and can be switched off', WPS_Login_Guard::surface_block_enabled() && ! ( function () { $GLOBALS['opts'] = [ 'login_block_surfaces' => '0' ]; $r = WPS_Login_Guard::surface_block_enabled(); $GLOBALS['opts'] = []; return $r; } )() );
$GLOBALS['hooks'] = [];
WPS_Login_Guard::register_hooks();
check( 'the three gates are hooked', in_array( 'init', $GLOBALS['hooks'], true ) && in_array( 'rest_authentication_errors', $GLOBALS['hooks'], true ) && in_array( 'wp_handle_upload_prefilter', $GLOBALS['hooks'], true ), json_encode( $GLOBALS['hooks'] ) );
$GLOBALS['opts']  = [ 'login_block_surfaces' => '0' ];
$GLOBALS['hooks'] = [];
WPS_Login_Guard::register_hooks();
check( 'and not hooked when switched off', ! in_array( 'rest_authentication_errors', $GLOBALS['hooks'], true ) );

// ---- the refusal itself ends the request (run in a child process, since it exits)
$code = '<?php define("ABSPATH","/x/"); define("WPS_OPTION","wps_opts"); define("XMLRPC_REQUEST", true);'
	. 'function get_option($k,$d=false){ return "wps_permanent_blocks"===$k ? ["198.51.100.7"=>["at"=>1]] : ( "wps_opts"===$k ? [] : $d ); }'
	. 'function apply_filters($t,$v){return $v;} function get_transient(){return false;} function set_transient(){return true;} function is_user_logged_in(){return false;} function status_header($c){ echo "STATUS:$c;"; }'
	. 'class WP_Error{} require ' . var_export( dirname( __DIR__ ) . '/includes/class-login-guard.php', true ) . ';'
	. '$_SERVER["REMOTE_ADDR"]="198.51.100.7"; WPS_Login_Guard::refuse_blocked_surfaces(); echo "NOT REFUSED";';
$tmpf = sys_get_temp_dir() . '/wps-sb-' . getmypid() . '.php';
file_put_contents( $tmpf, $code );
$out = (string) shell_exec( 'php ' . escapeshellarg( $tmpf ) . ' 2>&1' );
@unlink( $tmpf );
check( 'an XML-RPC request from a blocked address gets a 403 and the request ends', false !== strpos( $out, 'STATUS:403;' ) && false === strpos( $out, 'NOT REFUSED' ), $out );
$code = str_replace( '$_SERVER["REMOTE_ADDR"]="198.51.100.7";', '$_SERVER["REMOTE_ADDR"]="203.0.113.9";', $code );
file_put_contents( $tmpf, $code );
$out = (string) shell_exec( 'php ' . escapeshellarg( $tmpf ) . ' 2>&1' );
@unlink( $tmpf );
check( 'an XML-RPC request from any other address is not refused', false !== strpos( $out, 'NOT REFUSED' ) && false === strpos( $out, 'STATUS:403' ), $out );

// ---- 1.4.152: a signed-in administrator session on a blocked address is still refused.
// is_protected_ip() exempts whoever is signed in; the surface refusals must judge the address alone,
// or a stolen administrator cookie on a blocked address walks through the very checks built for it.
$code = '<?php define("ABSPATH","/x/"); define("WPS_OPTION","wps_opts");'
	. 'function get_option($k,$d=false){ return "wps_permanent_blocks"===$k ? ["198.51.100.7"=>["at"=>1]] : ( "wps_opts"===$k ? [] : $d ); }'
	. 'function apply_filters($t,$v){return $v;} function get_transient(){return false;} function set_transient(){return true;}'
	. 'function is_user_logged_in(){return true;} function current_user_can($c){return true;}'
	. 'class WP_Error{ public $code; public $data; public function __construct($c="",$m="",$d=[]){ $this->code=$c; $this->data=$d; } }'
	. 'require ' . var_export( dirname( __DIR__ ) . '/includes/class-login-guard.php', true ) . ';'
	. '$_SERVER["REMOTE_ADDR"]="198.51.100.7"; $_SERVER["REQUEST_METHOD"]="POST"; $_SERVER["SCRIPT_NAME"]="/index.php";'
	. '$r = WPS_Login_Guard::refuse_blocked_rest( null ); echo $r instanceof WP_Error ? "REFUSED" : "PASSED";'
	. '$f = WPS_Login_Guard::refuse_blocked_upload( [ "name" => "a.jpg", "error" => 0 ] ); echo empty( $f["error"] ) ? ";UPLOAD-OK" : ";UPLOAD-REFUSED";';
file_put_contents( $tmpf, $code );
$out = (string) shell_exec( 'php ' . escapeshellarg( $tmpf ) . ' 2>&1' );
@unlink( $tmpf );
check( 'a signed-in administrator session on a blocked address is still refused REST writes and uploads', 'REFUSED;UPLOAD-REFUSED' === trim( $out ), $out );
$code = str_replace( '"wps_opts"===$k ? []', '"wps_opts"===$k ? ["login_ip_allowlist"=>"198.51.100.7"]', $code );
file_put_contents( $tmpf, $code );
$out = (string) shell_exec( 'php ' . escapeshellarg( $tmpf ) . ' 2>&1' );
@unlink( $tmpf );
check( 'the operator allowlist still exempts the address', 'PASSED;UPLOAD-OK' === trim( $out ), $out );

echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
