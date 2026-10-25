<?php
/**
 * Regression test for four sign-in guard findings (1.4.153).
 *
 * Run from the command line only:  php tests/test-login-guard.php
 *
 * A bot username from an address that looks like shared infrastructure gets ordinary counting, not
 * a permanent block; Akismet reporting works with enrichment switched off; a failed report is not
 * remembered as sent; and a first range block holds for its base duration, not the ladder's.
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}
define( 'ABSPATH', '/x/' );
define( 'WPS_OPTION', 'wps_opts' );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'DAY_IN_SECONDS', 86400 );

$GLOBALS['opts']  = [ 'wps_opts' => [] ];
$GLOBALS['trans'] = [];
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
}
class Akismet {
	public static $ok    = true;
	public static $posts = 0;
	public static function get_api_key() { return 'abc123'; }
	public static function comment_check() { return 'false'; }
	public static function build_query( $b ) { return http_build_query( $b ); }
	public static function http_post( $q, $path ) { ++self::$posts; if ( ! self::$ok ) { throw new RuntimeException( 'network down' ); } return [ [], 'Thanks for making the web a better place.' ]; }
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
function events( string $type ): int {
	return count( array_filter( WPS_Logger::$events, static fn( $e ) => $type === $e[0] ) );
}

// ---- 1. a bot username from shared infrastructure is counted, not permanently blocked.
$_SERVER['REMOTE_ADDR'] = '10.20.30.40'; // a private range: a NAT or proxy, not a public client
WPS_Login_Guard::on_failed( 'root' );
check( '"root" from a private address does not permanently block it', ! WPS_Login_Guard::is_permanently_blocked( '10.20.30.40' ), json_encode( WPS_Login_Guard::permanent_blocks() ) );
$_SERVER['REMOTE_ADDR'] = '198.51.100.7';
WPS_Login_Guard::on_failed( 'root' );
check( '"root" from a public address still blocks it permanently on the first attempt', WPS_Login_Guard::is_permanently_blocked( '198.51.100.7' ), json_encode( WPS_Login_Guard::permanent_blocks() ) );

// ---- 2. reporting is governed by its own setting, not by enrichment.
$GLOBALS['opts']['wps_opts'] = [ 'akismet_enrichment' => '0', 'login_report_spam' => '1' ];
Akismet::$posts = 0;
WPS_Login_Guard::report_attacker_ip( '203.0.113.50', 'account-takeover post-write pattern' );
check( 'with enrichment off and reporting on, the address is still reported', 1 === Akismet::$posts && 2 === events( 'akismet_spam_reported' ), json_encode( [ Akismet::$posts, WPS_Logger::$events ] ) );
check( 'enrichment itself is off', ! WPS_Login_Guard::akismet_available() && WPS_Login_Guard::akismet_configured() );
check( 'the operator\'s manual report is sent with enrichment off', 'reported' === WPS_Login_Guard::report_ip_manually( '203.0.113.52' ) && 2 === Akismet::$posts, (string) Akismet::$posts );
check( 'the settings line says enrichment is off, not that the key is missing', false !== strpos( WPS_Login_Guard::akismet_status(), 'enrichment switched off' ), WPS_Login_Guard::akismet_status() );
$GLOBALS['opts']['wps_opts'] = [ 'akismet_enrichment' => '0', 'login_report_spam' => '0' ];
WPS_Login_Guard::report_attacker_ip( '203.0.113.51', 'x' );
check( 'with reporting off nothing is sent', 2 === Akismet::$posts );

// ---- 3. a failed submission is not remembered as sent.
$GLOBALS['opts']['wps_opts'] = [ 'login_report_spam' => '1' ];
Akismet::$ok    = false;
Akismet::$posts = 0;
WPS_Login_Guard::report_attacker_ip( '203.0.113.60', 'first try' );
check( 'the failed attempt is logged as failed', 1 === Akismet::$posts && false !== strpos( end( WPS_Logger::$events )[1], 'submission failed' ), json_encode( end( WPS_Logger::$events ) ) );
Akismet::$ok = true;
WPS_Login_Guard::report_attacker_ip( '203.0.113.60', 'second try' );
check( 'the next attempt for the same address is sent, because the failure was not remembered', 2 === Akismet::$posts, (string) Akismet::$posts );
WPS_Login_Guard::report_attacker_ip( '203.0.113.60', 'third try' );
check( 'a successful report is remembered and not sent twice', 2 === Akismet::$posts );

// ---- 4. a first range block holds for its base duration; returns climb the ladder.
$m = new ReflectionMethod( 'WPS_Login_Guard', 'block_network' );
$m->setAccessible( true );
WPS_Blocker::$blocks = [];
$m->invoke( null, '192.0.2.10', 'bot', 'count' );
$m->invoke( null, '192.0.2.11', 'bot', 'count' );
$m->invoke( null, '192.0.2.12', 'bot', 'count' );
$d = array_map( static fn( $b ) => $b['duration'], WPS_Blocker::$blocks );
check( 'a first burst block is 30 minutes, the second 6 hours, the third 24 hours', [ 1800, 21600, 86400 ] === $d, json_encode( $d ) );
WPS_Blocker::$blocks = [];
$m->invoke( null, '198.18.5.1', 'bot', 'rotation' );
$m->invoke( null, '198.18.5.2', 'bot', 'rotation' );
$d = array_map( static fn( $b ) => $b['duration'], WPS_Blocker::$blocks );
check( 'a first rotation block is 6 hours and the second is 24 hours', [ 21600, 86400 ] === $d, json_encode( $d ) );

echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
