<?php
/**
 * Regression test for the XML-RPC hardening from one site's October access log (1.4.156).
 *
 * Run from the command line only:  php tests/test-xmlrpc-forgery.php
 *
 * 13,125 failed XML-RPC sign-ins from 166 addresses carried a Jetpack or WordPress.com user agent,
 * and none came from Automattic's range. A failed sign-in with such an agent from anywhere else is
 * now a permanent block on the first attempt. A temporarily blocked address is refused on
 * xmlrpc.php with a 403 rather than being answered with the full sign-in fault.
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}
define( 'ABSPATH', '/x/' );
define( 'WPS_OPTION', 'wps_opts' );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'DAY_IN_SECONDS', 86400 );

$GLOBALS['opts']    = [ 'wps_opts' => [] ];
$GLOBALS['trans']   = [];
$GLOBALS['blocked'] = [];
function get_option( $k, $d = false ) { return $GLOBALS['opts'][ $k ] ?? $d; }
function update_option( $k, $v, $a = null ) { $GLOBALS['opts'][ $k ] = $v; return true; }
function delete_option( $k ) { unset( $GLOBALS['opts'][ $k ] ); return true; }
function get_transient( $k ) { return $GLOBALS['trans'][ $k ] ?? false; }
function set_transient( $k, $v, $t = 0 ) { $GLOBALS['trans'][ $k ] = $v; return true; }
function delete_transient( $k ) { unset( $GLOBALS['trans'][ $k ] ); return true; }
function apply_filters( $t, $v ) { return $v; }
function add_action() {}
function add_filter() {}
function username_exists( $u ) { return false; }
function email_exists( $e ) { return false; }
function is_email( $e ) { return false !== strpos( (string) $e, '@' ); }
function is_user_logged_in() { return false; }
function wp_json_encode( $v ) { return json_encode( $v ); }
function wp_strip_all_tags( $s ) { return strip_tags( (string) $s ); }
function sanitize_text_field( $s ) { return trim( strip_tags( (string) $s ) ); }
function esc_html( $s ) { return $s; }
function get_bloginfo( $k ) { return 'x'; }
function home_url( $p = '' ) { return 'http://example.test' . $p; }
class WPS_Logger {
	public static $events = [];
	public static function log_event( $t, $s, $ip = '' ) { self::$events[] = [ $t, $s ]; }
	public static function write( $m ) {}
	public static function notify_admin( $a, $b ) {}
}
class WPS_Blocker {
	public static $blocks = [];
	public static function client_ip() { return (string) ( $_SERVER['REMOTE_ADDR'] ?? '' ); }
	public static function record_ip_block( $ip, $reason, $duration = 0, $meta = [] ) { self::$blocks[] = [ 'ip' => $ip, 'duration' => (int) $duration, 'meta' => $meta ]; return true; }
	public static function get_blocked_ips() { return $GLOBALS['blocked']; }
}
class Akismet {
	public static function get_api_key() { return ''; }
}
require dirname( __DIR__ ) . '/includes/class-login-guard.php';

$fail = 0;
function check( string $name, bool $ok, string $detail = '' ): void {
	global $fail;
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $name . ( $ok ? '' : ' :: ' . $detail ) . "\n";
	if ( ! $ok ) {
		++$fail;
	}
}
function request( string $ip, string $ua, string $script = '/xmlrpc.php' ): void {
	$_SERVER['REMOTE_ADDR']     = $ip;
	$_SERVER['HTTP_USER_AGENT'] = $ua;
	$_SERVER['SCRIPT_NAME']     = $script;
	$_SERVER['REQUEST_METHOD']  = 'POST';
}
$agents = [
	'Jetpack by WordPress.com',
	'Jetpack by WordPress.com (Jetpack 14.9; WordPress 6.9)',
	'Jetpack/14.9; WordPress/6.9; http://site34.com',
	'WordPress.com; https://wordpress.com',
];

// ---- 1. the judgement itself
foreach ( $agents as $ua ) {
	check( 'forged from outside Automattic: ' . $ua, '' !== WPS_Login_Guard::forged_vendor_agent( $ua, '198.51.100.7' ), WPS_Login_Guard::forged_vendor_agent( $ua, '198.51.100.7' ) );
}
check( 'the vendor named is the one claimed', 'Jetpack' === WPS_Login_Guard::forged_vendor_agent( $agents[0], '198.51.100.7' ) && 'WordPress.com' === WPS_Login_Guard::forged_vendor_agent( $agents[3], '198.51.100.7' ) );
check( 'the same agents from inside 192.0.64.0/18 are not forgeries', '' === WPS_Login_Guard::forged_vendor_agent( $agents[0], '192.0.64.1' ) && '' === WPS_Login_Guard::forged_vendor_agent( $agents[3], '192.0.127.254' ) && '' === WPS_Login_Guard::forged_vendor_agent( $agents[2], '192.0.100.50' ) );
check( 'the range ends where it ends', 'Jetpack' === WPS_Login_Guard::forged_vendor_agent( $agents[0], '192.0.128.1' ) && 'Jetpack' === WPS_Login_Guard::forged_vendor_agent( $agents[0], '192.0.63.255' ) );
check( 'a browser agent claims nothing', '' === WPS_Login_Guard::forged_vendor_agent( 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36', '198.51.100.7' ) );
check( 'the mobile apps claim nothing', '' === WPS_Login_Guard::forged_vendor_agent( 'wp-android/26.1 (Android 15; en_US; Pixel)', '198.51.100.7' ) && '' === WPS_Login_Guard::forged_vendor_agent( 'wp-iphone/26.1 (iOS 18)', '198.51.100.7' ) );
check( 'an empty agent claims nothing', '' === WPS_Login_Guard::forged_vendor_agent( '', '198.51.100.7' ) );
check( 'an IPv6 address cannot be inside an IPv4 range, so the claim is a forgery', 'Jetpack' === WPS_Login_Guard::forged_vendor_agent( $agents[0], '2001:db8::7' ) );

// ---- 2. one failed XML-RPC sign-in with a forged agent is a permanent block
request( '198.51.100.10', $agents[1] );
WPS_Login_Guard::on_failed( 'bestofislam' );
check( 'a real account name, one failure, forged agent: permanently blocked', WPS_Login_Guard::is_permanently_blocked( '198.51.100.10' ), json_encode( WPS_Login_Guard::permanent_blocks() ) );
$reason = (string) ( WPS_Login_Guard::permanent_blocks()['198.51.100.10']['reason'] ?? json_encode( WPS_Login_Guard::permanent_blocks()['198.51.100.10'] ?? null ) );
check( 'the reason names the vendor claimed', false !== strpos( $reason, 'Jetpack' ), $reason );

request( '192.0.70.9', $agents[1] );
WPS_Login_Guard::on_failed( 'bestofislam' );
check( 'the same from inside Automattic\'s range gets ordinary counting', ! WPS_Login_Guard::is_permanently_blocked( '192.0.70.9' ) && 1 === (int) get_transient( 'wps_lf_' . md5( '192.0.70.9' ) ) );

request( '198.51.100.11', $agents[0], '/wp-login.php' );
WPS_Login_Guard::on_failed( 'bestofislam' );
check( 'a forged agent on the sign-in form, not XML-RPC, gets ordinary counting', ! WPS_Login_Guard::is_permanently_blocked( '198.51.100.11' ) && 1 === (int) get_transient( 'wps_lf_' . md5( '198.51.100.11' ) ) );

request( '10.20.30.40', $agents[0] );
WPS_Login_Guard::on_failed( 'bestofislam' );
check( 'a forged agent from an address that looks like shared infrastructure gets ordinary counting', ! WPS_Login_Guard::is_permanently_blocked( '10.20.30.40' ) );

$GLOBALS['opts']['wps_opts'] = [ 'login_forged_agent_block' => '0' ];
request( '198.51.100.12', $agents[3] );
WPS_Login_Guard::on_failed( 'bestofislam' );
check( 'with the setting off, ordinary counting', ! WPS_Login_Guard::is_permanently_blocked( '198.51.100.12' ) && 1 === (int) get_transient( 'wps_lf_' . md5( '198.51.100.12' ) ) );
$GLOBALS['opts']['wps_opts'] = [];

request( '198.51.100.13', 'Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0' );
WPS_Login_Guard::on_failed( 'bestofislam' );
check( 'a browser agent over XML-RPC gets ordinary counting', ! WPS_Login_Guard::is_permanently_blocked( '198.51.100.13' ) && 1 === (int) get_transient( 'wps_lf_' . md5( '198.51.100.13' ) ) );

// ---- 3. the surface refusal reaches temporary blocks on XML-RPC
request( '198.51.100.20', 'wp-android/26.1' );
check( 'an unblocked address is not refused', '' === WPS_Login_Guard::surface_refusal( 'xmlrpc' ) );
$GLOBALS['blocked']['198.51.100.20'] = [ 'expires' => time() + 600, 'reason' => 'five failures' ];
$r = WPS_Login_Guard::surface_refusal( 'xmlrpc' );
check( 'a temporarily blocked address is refused on xmlrpc.php, with the minutes left', false !== strpos( $r, 'blocked for another 10 minute' ), $r );
check( 'the same temporary block does not refuse an upload', '' === WPS_Login_Guard::surface_refusal( 'upload' ) );
$GLOBALS['blocked']['198.51.100.20']['expires'] = time() - 5;
check( 'an expired block refuses nothing', '' === WPS_Login_Guard::surface_refusal( 'xmlrpc' ) );
request( '198.51.100.10', 'wp-android/26.1' );
check( 'a permanent block refuses every surface', '' !== WPS_Login_Guard::surface_refusal( 'xmlrpc' ) && '' !== WPS_Login_Guard::surface_refusal( 'upload' ) );
$GLOBALS['opts']['wps_opts'] = [ 'login_ip_allowlist' => '198.51.100.10' ];
check( 'an allowlisted address is never refused', '' === WPS_Login_Guard::surface_refusal( 'xmlrpc' ) );
$GLOBALS['opts']['wps_opts'] = [];
request( '198.51.100.21', 'x', '/xmlrpc.php' );
check( 'xmlrpc.php is recognised by script name as well as by constant', 'xmlrpc' === WPS_Login_Guard::blocked_surface() );

echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
