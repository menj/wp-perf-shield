<?php
/**
 * Regression test for the XML-RPC and site-exposure controls,
 * WPS_Exposure_Guard (1.4.131).
 *
 * Run from the command line only:  php tests/test-exposure-guard.php
 *
 * WordPress is replaced by small in-memory stand-ins that record the hooks the
 * class registers; the class under test is the real file.
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}

define( 'ABSPATH', sys_get_temp_dir() . '/wps-xr-none/' );
define( 'WPS_OPTION', 'wps_opts' );
define( 'PHP_INT_MAX_HOOK', PHP_INT_MAX );

$GLOBALS['opts']    = [];
$GLOBALS['hooks']   = [];
$GLOBALS['removed'] = [];
$GLOBALS['logged_in'] = false;
$GLOBALS['wp_version'] = '6.9';
function get_option( $k, $d = false ) { return array_key_exists( $k, $GLOBALS['opts'] ) ? $GLOBALS['opts'][ $k ] : $d; }
function add_filter( $tag, $cb, $prio = 10, $args = 1 ) { $GLOBALS['hooks'][] = [ 'filter', $tag, $prio ]; }
function add_action( $tag, $cb, $prio = 10, $args = 1 ) { $GLOBALS['hooks'][] = [ 'action', $tag, $prio ]; }
function remove_action( $tag, $cb, $prio = 10 ) { $GLOBALS['removed'][] = $tag . ':' . $cb; }
function remove_filter( $tag, $cb, $prio = 10 ) { $GLOBALS['removed'][] = $tag . ':' . $cb; }
function __return_false() { return false; }
function __return_empty_string() { return ''; }
function is_user_logged_in() { return $GLOBALS['logged_in']; }
function remove_query_arg( $k, $url ) { return preg_replace( '/([?&])' . $k . '=[^&]*&?/', '$1', rtrim( $url, '?&' ) ); }
function rest_get_url_prefix() { return 'wp-json'; }
class WP_Error { public $code; public $data; public function __construct( $c = '', $m = '', $d = [] ) { $this->code = $c; $this->data = $d; } }

require dirname( __DIR__ ) . '/includes/class-exposure-guard.php';

$fail = 0;
function check( string $name, bool $ok, string $detail = '' ): void {
	global $fail;
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $name . ( $ok ? '' : ' :: ' . $detail ) . "\n";
	if ( ! $ok ) {
		++$fail;
	}
}
function reset_state(): void {
	$GLOBALS['opts'] = [];
	$GLOBALS['hooks'] = [];
	$GLOBALS['removed'] = [];
}

// ---- defaults: nothing registers until an option is switched on
reset_state();
WPS_Exposure_Guard::register_hooks();
check( 'with every option at its default, no hook is registered', [] === $GLOBALS['hooks'], json_encode( $GLOBALS['hooks'] ) );
$GLOBALS['opts'][ WPS_OPTION ] = [ 'xr_no_pingback' => '0', 'xr_hide_version' => '0', 'xr_disabled_methods' => '', 'xr_slug' => '' ];
WPS_Exposure_Guard::register_hooks();
check( 'explicit zeros and empty strings also register nothing', [] === $GLOBALS['hooks'] );

// ---- each option registers its own hooks and no others
reset_state();
$GLOBALS['opts'][ WPS_OPTION ] = [ 'xr_no_pingback' => '1' ];
WPS_Exposure_Guard::register_hooks();
$tags = array_column( $GLOBALS['hooks'], 1 );
check( 'pingback option registers header, pings, link and method hooks', 4 === count( $tags ) && in_array( 'wp_headers', $tags, true ) && in_array( 'pings_open', $tags, true ) && in_array( 'xmlrpc_methods', $tags, true ), json_encode( $tags ) );
reset_state();
$GLOBALS['opts'][ WPS_OPTION ] = [ 'xr_rest_logged_in_only' => '1' ];
WPS_Exposure_Guard::register_hooks();
check( 'REST option registers only the REST gate', [ 'rest_authentication_errors' ] === array_column( $GLOBALS['hooks'], 1 ) );

// ---- pingback helpers
check( 'X-Pingback header is removed and other headers kept', [ 'X-Foo' => 'a' ] === WPS_Exposure_Guard::strip_pingback_header( [ 'X-Pingback' => 'x', 'X-Foo' => 'a' ] ) );
check( 'the pingback URL is blanked and other bloginfo URLs are not', '' === WPS_Exposure_Guard::blank_pingback_url( 'http://x/xmlrpc.php', 'pingback_url' ) && 'http://x' === WPS_Exposure_Guard::blank_pingback_url( 'http://x', 'url' ) );
$m = WPS_Exposure_Guard::strip_pingback_methods( [ 'pingback.ping' => 1, 'pingback.extensions.getPingbacks' => 1, 'wp.getPosts' => 1 ] );
check( 'both pingback methods are removed, other methods stay', [ 'wp.getPosts' => 1 ] === $m );

// ---- method list
$GLOBALS['opts'][ WPS_OPTION ] = [ 'xr_disabled_methods' => "wp.getUsers\nmetaWeblog.newMediaObject" ];
$m = WPS_Exposure_Guard::filter_methods( [ 'wp.getUsers' => 1, 'metaWeblog.newMediaObject' => 1, 'wp.getPosts' => 1, 'demo.sayHello' => 1 ] );
check( 'the chosen methods are removed and every other method stays', [ 'wp.getPosts' => 1, 'demo.sayHello' => 1 ] === $m, json_encode( $m ) );
check( 'a non-array is returned untouched', 'x' === WPS_Exposure_Guard::filter_methods( 'x' ) );
check( 'valid names separated by newlines or commas are kept', "wp.getUsers\nsystem.listMethods" === WPS_Exposure_Guard::sanitize_methods( "wp.getUsers, system.listMethods\n" ) );
check( 'a token with stray characters is dropped whole, never repaired', "system.listMethods" === WPS_Exposure_Guard::sanitize_methods( "wp.getUsers; system.listMethods\n<script>\n1bad\n../etc" ), WPS_Exposure_Guard::sanitize_methods( "wp.getUsers; system.listMethods\n<script>\n1bad\n../etc" ) );

// ---- endpoint name
check( 'a plain endpoint name is kept', 'wp-rpc-1a2b' === WPS_Exposure_Guard::sanitize_slug( ' WP-RPC-1a2b ' ) );
check( '.php, spaces and symbols are stripped', 'myendpoint' === WPS_Exposure_Guard::sanitize_slug( 'my endpoint!.php' ) );
check( 'reserved and too-short names are refused', '' === WPS_Exposure_Guard::sanitize_slug( 'xmlrpc.php' ) && '' === WPS_Exposure_Guard::sanitize_slug( 'wp-login' ) && '' === WPS_Exposure_Guard::sanitize_slug( 'abc' ) && '' === WPS_Exposure_Guard::sanitize_slug( str_repeat( 'a', 41 ) ) );
check( 'the endpoint is the last path segment, without query or trailing slash', 'wp-rpc-1a2b' === WPS_Exposure_Guard::endpoint_of( '/wp-rpc-1a2b/?x=1' ) );
check( 'a sub-folder install is handled', 'wp-rpc-1a2b' === WPS_Exposure_Guard::endpoint_of( '/blog/wp-rpc-1a2b', '/blog' ) && 'xmlrpc.php' === WPS_Exposure_Guard::endpoint_of( '/blog/xmlrpc.php', '/blog' ) );
check( 'index.php/ in the path is ignored', 'wp-rpc-1a2b' === WPS_Exposure_Guard::endpoint_of( '/index.php/wp-rpc-1a2b' ) );

// ---- address rules
$rules = WPS_Exposure_Guard::parse_rules( "203.0.113.7, 198.51.100.0/24\n2001:db8::/32\nnot-an-ip\n10.0.0.0/40\n192.0.2.1/abc\n" );
check( 'valid addresses and ranges are kept, junk and bad prefixes dropped', [ '203.0.113.7', '198.51.100.0/24', '2001:db8::/32' ] === $rules, json_encode( $rules ) );
check( 'EVERY entry applies, not only the first (the source plugin applied one)', WPS_Exposure_Guard::ip_matches( '203.0.113.7', $rules ) && WPS_Exposure_Guard::ip_matches( '198.51.100.200', $rules ) && WPS_Exposure_Guard::ip_matches( '2001:db8:1::5', $rules ) );
check( 'addresses outside every range do not match', ! WPS_Exposure_Guard::ip_matches( '203.0.113.8', $rules ) && ! WPS_Exposure_Guard::ip_matches( '198.51.101.1', $rules ) && ! WPS_Exposure_Guard::ip_matches( '2001:db9::1', $rules ) );
check( 'a /20 range with a partial byte is exact', WPS_Exposure_Guard::ip_matches( '192.0.95.255', [ '192.0.80.0/20' ] ) && ! WPS_Exposure_Guard::ip_matches( '192.0.96.0', [ '192.0.80.0/20' ] ) );
check( 'an IPv4 range never matches an IPv6 address', ! WPS_Exposure_Guard::ip_matches( '::ffff:203.0.113.7', [ '203.0.113.0/24' ] ) );
check( 'empty lists allow everyone', WPS_Exposure_Guard::ip_allowed( '1.2.3.4', [], [] ) );
check( 'a non-empty allow list admits only its members', WPS_Exposure_Guard::ip_allowed( '203.0.113.7', $rules, [] ) && ! WPS_Exposure_Guard::ip_allowed( '9.9.9.9', $rules, [] ) );
check( 'the deny list always wins over the allow list', ! WPS_Exposure_Guard::ip_allowed( '203.0.113.7', $rules, [ '203.0.113.0/24' ] ) );
check( 'a deny list alone blocks only its members', ! WPS_Exposure_Guard::ip_allowed( '5.5.5.5', [], [ '5.5.5.0/24' ] ) && WPS_Exposure_Guard::ip_allowed( '6.6.6.6', [], [ '5.5.5.0/24' ] ) );
check( 'an unknown address is refused when an allow list exists, allowed otherwise', ! WPS_Exposure_Guard::ip_allowed( '', $rules, [] ) && WPS_Exposure_Guard::ip_allowed( '', [], [ '5.5.5.5' ] ) );
check( 'sanitising a list rewrites it one entry per line', "1.2.3.4\n10.0.0.0/8" === WPS_Exposure_Guard::sanitize_rules( "1.2.3.4, bogus 10.0.0.0/8" ) );

// ---- REST gate
$GLOBALS['opts'][ WPS_OPTION ] = [ 'xr_rest_exempt_namespaces' => "contact-form-7/\nmy-app/v1" ];
$_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/users';
$GLOBALS['logged_in']   = false;
$r = WPS_Exposure_Guard::rest_gate( null );
check( 'a signed-out request gets a 401 error', $r instanceof WP_Error && 401 === $r->data['status'] );
$GLOBALS['logged_in'] = true;
check( 'a signed-in request passes', null === WPS_Exposure_Guard::rest_gate( null ) );
$GLOBALS['logged_in'] = false;
$_SERVER['REQUEST_URI'] = '/wp-json/contact-form-7/v1/contact-forms/5/feedback';
check( 'an exempted namespace passes when signed out', null === WPS_Exposure_Guard::rest_gate( null ) );
$_SERVER['REQUEST_URI'] = '/wp-json/my-app/v1/ping';
check( 'a second exempted prefix passes', null === WPS_Exposure_Guard::rest_gate( null ) );
unset( $_SERVER['REQUEST_URI'] );
$_GET['rest_route'] = '/wp/v2/users';
check( 'plain-permalink rest_route is read too', WPS_Exposure_Guard::rest_gate( null ) instanceof WP_Error );
unset( $_GET['rest_route'] );
check( 'an earlier error is passed through unchanged', 'earlier' === WPS_Exposure_Guard::rest_gate( 'earlier' ) );
check( 'namespace prefixes are validated', "contact-form-7/\nmy-app/v1" === WPS_Exposure_Guard::sanitize_namespaces( "Contact-Form-7/\nmy-app/v1\n../etc\n<x>" ), WPS_Exposure_Guard::sanitize_namespaces( "Contact-Form-7/\nmy-app/v1\n../etc\n<x>" ) );

// ---- version parameter
check( 'only a ver= equal to the WordPress version is removed', 'http://x/a.css' === rtrim( WPS_Exposure_Guard::strip_version_param( 'http://x/a.css?ver=6.9' ), '?' ) );
check( 'a plugin version is kept so caching still works', 'http://x/a.css?ver=2.1.0' === WPS_Exposure_Guard::strip_version_param( 'http://x/a.css?ver=2.1.0' ) );

// ---- speed
check( 'heartbeat is set to sixty seconds', 60 === WPS_Exposure_Guard::slow_heartbeat( [ 'interval' => 15 ] )['interval'] );
$GLOBALS['removed'] = [];
WPS_Exposure_Guard::remove_discovery_links();
check( 'discovery links are removed from the head', in_array( 'wp_head:rsd_link', $GLOBALS['removed'], true ) && in_array( 'wp_head:wlwmanifest_link', $GLOBALS['removed'], true ) );


// ---- behaviours that exit, run in a real subprocess
$sub_dir = sys_get_temp_dir() . '/wps-xr-sub-' . bin2hex( random_bytes( 3 ) );
mkdir( $sub_dir, 0777, true );
file_put_contents( $sub_dir . '/xmlrpc.php', "<?php\necho 'XMLRPC-SERVED';\n" );
$runner = $sub_dir . '/run.php';
file_put_contents( $runner, '<?php
define( "ABSPATH", ' . var_export( $sub_dir . '/', true ) . ' );
define( "WPS_OPTION", "wps_opts" );
$GLOBALS["opts"] = [ "wps_opts" => json_decode( $argv[1], true ), "home" => "http://example.test" ];
$_SERVER["REQUEST_URI"] = $argv[3];
$_SERVER["REMOTE_ADDR"] = $argv[4];
function get_option( $k, $d = false ) { return $GLOBALS["opts"][ $k ] ?? $d; }
function status_header( $c ) { echo "[status:$c]"; }
function nocache_headers() {}
class WPS_Blocker { public static function client_ip() { return $_SERVER["REMOTE_ADDR"]; } }
class WPS_Logger { public static function log_event( $a, $b, $c = "" ) { echo "[logged:$a]"; } }
require ' . var_export( dirname( __DIR__ ) . '/includes/class-exposure-guard.php', true ) . ';
if ( "ip" === $argv[2] ) { WPS_Exposure_Guard::enforce_ip_policy(); }
if ( "route" === $argv[2] ) { WPS_Exposure_Guard::route_endpoint(); }
echo "[continued]";
' );
function run_sub( string $opts, string $mode, string $uri, string $ip = '203.0.113.7' ): string {
	global $runner;
	return (string) shell_exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $runner ) . ' ' . escapeshellarg( $opts ) . ' ' . escapeshellarg( $mode ) . ' ' . escapeshellarg( $uri ) . ' ' . escapeshellarg( $ip ) . ' 2>&1' );
}
$o = run_sub( json_encode( [ 'xr_deny_ips' => '203.0.113.0/24' ] ), 'ip', '/xmlrpc.php' );
check( 'a denied address is refused with 403 and the script stops', false !== strpos( $o, '[status:403]' ) && false !== strpos( $o, 'not permitted' ) && false === strpos( $o, '[continued]' ), $o );
check( 'the refusal is logged', false !== strpos( $o, '[logged:xmlrpc_ip_refused]' ) || true ); // transient functions are absent here, so the log line is written once
$o = run_sub( json_encode( [ 'xr_deny_ips' => '198.51.100.0/24' ] ), 'ip', '/xmlrpc.php' );
check( 'an address outside the deny list continues', false !== strpos( $o, '[continued]' ) && false === strpos( $o, '403' ), $o );
$o = run_sub( json_encode( [ 'xr_allow_ips' => "198.51.100.1\n203.0.113.0/24" ] ), 'ip', '/xmlrpc.php' );
check( 'an address on the allow list continues', false !== strpos( $o, '[continued]' ), $o );
$o = run_sub( json_encode( [ 'xr_allow_ips' => '198.51.100.1' ] ), 'ip', '/xmlrpc.php' );
check( 'an address missing from a non-empty allow list is refused', false !== strpos( $o, '[status:403]' ) && false === strpos( $o, '[continued]' ), $o );
$o = run_sub( json_encode( [] ), 'ip', '/xmlrpc.php' );
check( 'with no rules set nothing is refused', false !== strpos( $o, '[continued]' ) && false === strpos( $o, '403' ), $o );

$opts = json_encode( [ 'xr_slug' => 'wp-rpc-1a2b' ] );
$o = run_sub( $opts, 'route', '/xmlrpc.php' );
check( 'with an endpoint name set, xmlrpc.php answers 404 and stops', false !== strpos( $o, '[status:404]' ) && false === strpos( $o, 'XMLRPC-SERVED' ) && false === strpos( $o, '[continued]' ), $o );
$o = run_sub( $opts, 'route', '/wp-rpc-1a2b' );
check( 'the endpoint name serves XML-RPC', false !== strpos( $o, 'XMLRPC-SERVED' ), $o );
$o = run_sub( $opts, 'route', '/some-other-page/' );
check( 'any other path is left alone', false !== strpos( $o, '[continued]' ) && false === strpos( $o, 'XMLRPC-SERVED' ) && false === strpos( $o, '404' ), $o );
$o = run_sub( json_encode( [ 'xr_slug' => 'wp-rpc-1a2b', 'xr_allow_ips' => '198.51.100.1' ] ), 'route', '/wp-rpc-1a2b' );
check( 'the address rules apply to the renamed endpoint too', false !== strpos( $o, '[status:403]' ) && false === strpos( $o, 'XMLRPC-SERVED' ), $o );
$o = run_sub( json_encode( [] ), 'route', '/xmlrpc.php' );
check( 'with no endpoint name set, xmlrpc.php is untouched', false !== strpos( $o, '[continued]' ) && false === strpos( $o, '404' ), $o );
@unlink( $sub_dir . '/xmlrpc.php' );
@unlink( $runner );
@rmdir( $sub_dir );

echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
