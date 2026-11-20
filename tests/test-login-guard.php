<?php
/**
 * Regression test for four sign-in guard findings (1.4.153).
 *
 * Run from the command line only:  php tests/test-login-guard.php
 *
 * A bot username from an address that looks like shared infrastructure gets ordinary counting, not
 * a permanent block; nothing is sent to Akismet's submit-spam (1.4.160); and a first range block holds for
 * its base duration, not the ladder's.
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
function get_bloginfo( $k ) { return [ 'language' => 'en-US', 'charset' => 'UTF-8' ][ $k ] ?? 'x'; }
function home_url( $p = '' ) { return 'http://example.test' . $p; }
function wp_login_url() { return 'http://example.test/wp-login.php'; }
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
	public static $last = [];
	public static $reply = null;
	public static function comment_check( $args = [] ) { self::$last = $args; return self::$reply ?? (object) [ 'is_spam' => false ]; }
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

$before = (int) WPS_Login_Guard::stats()['today_blocks'];
WPS_Login_Guard::block_permanently( '203.0.113.99', 'operator ban' );
WPS_Login_Guard::block_permanently_cidr( '203.0.114.0/24', 'operator range ban' );
$after = WPS_Login_Guard::stats();
check( 'manual permanent blocks count in the total as well as the permanent counter', (int) $after['today_blocks'] === $before + 2 && (int) $after['today_permanent_blocks'] >= 3, json_encode( [ $before, $after['today_blocks'] ?? null, $after['today_permanent_blocks'] ?? null ] ) );
check( 'the automatic permanent block earlier was counted once, not twice', 1 === $before, (string) $before );

// ---- 2. nothing is sent to Akismet's submit-spam (Akismet asked for this, 1.4.160).
Akismet::$posts = 0;
$_SERVER['REMOTE_ADDR'] = '198.51.100.77';
WPS_Login_Guard::on_failed( 'root' );
WPS_Login_Guard::block_permanently( '203.0.113.70', 'operator ban' );
check( 'a permanent block sends nothing to Akismet', 0 === Akismet::$posts, (string) Akismet::$posts );
foreach ( [ 'report_attacker_ip', 'report_ip_manually', 'submit_spam', 'maybe_report_spam', 'report_single_attacker', 'spam_reporting_enabled', 'report_all_blocks_enabled' ] as $gone ) {
	check( "the reporting method $gone no longer exists", ! method_exists( 'WPS_Login_Guard', $gone ) );
}
$GLOBALS['opts']['wps_opts'] = [ 'akismet_enrichment' => '0' ];
check( 'enrichment itself can still be switched off while the key stays configured', ! WPS_Login_Guard::akismet_available() && WPS_Login_Guard::akismet_configured() );
check( 'the settings line says enrichment is off, not that the key is missing', false !== strpos( WPS_Login_Guard::akismet_status(), 'enrichment switched off' ), WPS_Login_Guard::akismet_status() );
$GLOBALS['opts']['wps_opts'] = [];
$src = (string) file_get_contents( dirname( __DIR__ ) . '/includes/class-login-guard.php' );
check( 'the login guard source holds no submit-spam endpoint', false === strpos( $src, 'submit-spam' ) );

// ---- 5. the comment-check request carries every documented parameter the plugin can supply (1.4.161).
$_SERVER['REMOTE_ADDR']       = '203.0.113.9';
$_SERVER['HTTP_USER_AGENT']   = 'curl/8.0';
$_SERVER['HTTP_REFERER']      = 'https://example.test/wp-login.php';
$_SERVER['HTTP_ACCEPT']       = 'text/html';
$_SERVER['HTTP_COOKIE']       = 'wordpress_logged_in_x=secret';
$_SERVER['HTTP_AUTHORIZATION'] = 'Basic c2VjcmV0';
$_SERVER['PHP_AUTH_PW']       = 'secret';
$_SERVER['DOCUMENT_ROOT']     = '/var/www/private';
$_SERVER['SCRIPT_FILENAME']   = '/var/www/private/wp-login.php';
$_SERVER['REQUEST_METHOD']    = 'POST';
$_SERVER['REQUEST_URI']       = '/wp-login.php';
$_SERVER['SERVER_NAME']       = 'example.test';
$GLOBALS['opts']['wps_opts']  = [];
$GLOBALS['trans']             = [];
Akismet::$last = [];
$av = new ReflectionMethod( 'WPS_Login_Guard', 'akismet_verdict' );
$av->setAccessible( true );
$av->invoke( null, '203.0.113.9', 'root' );
$q = Akismet::$last;
foreach ( [ 'user_ip', 'user_agent', 'referrer', 'permalink', 'comment_type', 'comment_author', 'comment_content', 'is_test' ] as $k ) {
	check( "comment-check carries $k", array_key_exists( $k, $q ), json_encode( array_keys( $q ) ) );
}
check( 'the request says what it is', 'wps-login-attempt' === $q['comment_type'] && 'root' === $q['comment_author'] && '' === $q['comment_content'] && '203.0.113.9' === $q['user_ip'] );
check( 'blog, language and charset are left to Akismet, which adds them itself', ! isset( $q['blog'], $q['blog_lang'], $q['blog_charset'] ) );
check( 'the HTTP headers and request line are passed on', 'text/html' === ( $q['HTTP_ACCEPT'] ?? '' ) && 'POST' === ( $q['REQUEST_METHOD'] ?? '' ) && '/wp-login.php' === ( $q['REQUEST_URI'] ?? '' ) && 'example.test' === ( $q['SERVER_NAME'] ?? '' ) && '203.0.113.9' === ( $q['REMOTE_ADDR'] ?? '' ) );
check( 'no cookie, credential or password variable is sent', ! array_intersect_key( $q, array_flip( [ 'HTTP_COOKIE', 'HTTP_AUTHORIZATION', 'PHP_AUTH_PW' ] ) ), json_encode( array_keys( $q ) ) );
check( 'no filesystem path is sent', ! isset( $q['DOCUMENT_ROOT'] ) && ! isset( $q['SCRIPT_FILENAME'] ) );
check( 'user_role is never sent, since "administrator" makes Akismet answer false', ! isset( $q['user_role'] ) );
check( 'the server variables cannot overwrite the named parameters', '203.0.113.9' === $q['user_ip'] && 'wps-login-attempt' === $q['comment_type'] );
unset( $_SERVER['HTTP_REFERER'] );
$GLOBALS['trans'] = [];
$av->invoke( null, '203.0.113.9', 'root' );
check( 'an empty referrer is left out, not sent blank', ! array_key_exists( 'referrer', Akismet::$last ) );


// ---- 6. a failed Akismet call is not a clean verdict (1.4.162).
$GLOBALS['trans'] = [];
Akismet::$reply = (object) [ 'is_spam' => false, 'error' => '12345' ];
check( 'a reply carrying an error header gives no verdict', '' === $av->invoke( null, '203.0.113.20', 'root' ) );
check( 'and the failure is not cached as a clean answer', false === get_transient( 'wps_akv_' . md5( '203.0.113.20' ) ) );
Akismet::$reply = (object) [ 'is_spam' => true ];
check( 'a spam answer without an error still counts', 'spam' === $av->invoke( null, '203.0.113.21', 'root' ) );
Akismet::$reply = null;
$GLOBALS['trans'] = [];
check( 'a clean answer without an error still counts', 'ham' === $av->invoke( null, '203.0.113.22', 'root' ) );


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
