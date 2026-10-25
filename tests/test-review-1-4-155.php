<?php
/**
 * Regression tests for the 1.4.155 whole-codebase review fixes that have no suite of their own.
 *
 * Run from the command line only:  php tests/test-review-1-4-155.php
 *
 * Comment stripping with old Mac line endings and a ?> inside a // comment; the outbound guard
 * reading session cookies from the cookies argument and a Cookie header; the XML-RPC page
 * methods; Akismet's answer to a submission; yesterday's counters; the authentication label for
 * an application password over XML-RPC; the forensics grep commands; split-pattern counts over 64.
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}
define( 'ABSPATH', '/x/' );
define( 'WPS_OPTION', 'wps_opts' );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'DAY_IN_SECONDS', 86400 );
define( 'XMLRPC_REQUEST', true );
$GLOBALS['opts']  = [];
$GLOBALS['trans'] = [];
function get_option( $k, $d = false ) { return $GLOBALS['opts'][ $k ] ?? $d; }
function update_option( $k, $v, $a = null ) { $GLOBALS['opts'][ $k ] = $v; return true; }
function get_transient( $k ) { return $GLOBALS['trans'][ $k ] ?? false; }
function set_transient( $k, $v, $t = 0 ) { $GLOBALS['trans'][ $k ] = $v; return true; }
function delete_transient( $k ) { unset( $GLOBALS['trans'][ $k ] ); return true; }
function apply_filters( $t, $v ) { return $v; }
function add_action() {}
function add_filter() {}
function wp_parse_url( $u, $c = -1 ) { return parse_url( $u, $c ); }
function wp_strip_all_tags( $s ) { return strip_tags( (string) $s ); }
function wp_json_encode( $v ) { return json_encode( $v ); }
class WP_Error { public $code; public function __construct( $c = '', $m = '' ) { $this->code = $c; } }
class WPS_Logger { public static $events = []; public static function log_event( $t, $s, $ip = '' ) { self::$events[] = $t; } public static function write() {} public static function file_event() {} public static function notify_admin() {} }
class Akismet {
	public static $reply = [ [], 'Thanks for making the web a better place.' ];
	public static function get_api_key() { return 'k'; }
	public static function build_query( $b ) { return http_build_query( $b ); }
	public static function http_post( $q, $p ) { return self::$reply; }
}
class Cookie { public $name; public $value; public function __construct( $n, $v ) { $this->name = $n; $this->value = $v; } }

require dirname( __DIR__ ) . '/includes/class-wps-utils.php';
require dirname( __DIR__ ) . '/includes/class-blocker.php';
require dirname( __DIR__ ) . '/includes/class-post-guard.php';
require dirname( __DIR__ ) . '/includes/class-login-guard.php';
require dirname( __DIR__ ) . '/includes/class-edr.php';
require dirname( __DIR__ ) . '/includes/class-signature-engine.php';

$fail = 0;
function check( string $name, bool $ok, string $detail = '' ): void {
	global $fail;
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $name . ( $ok ? '' : ' :: ' . $detail ) . "\n";
	if ( ! $ok ) {
		++$fail;
	}
}

// ---- comment stripping
$cr = "<?php\r// a note\reval(\$_POST['x']);\r";
check( 'a lone CR ends a // comment, so the code after it survives stripping', false !== strpos( WPS_Utils::strip_php_comments( $cr ), "eval(\$_POST['x'])" ), json_encode( WPS_Utils::strip_php_comments( $cr ) ) );
$cr2 = "<?php\r# note\rsystem(\$_GET['c']);";
check( 'and a # comment', false !== strpos( WPS_Utils::strip_php_comments( $cr2 ), "system(\$_GET['c'])" ) );
$close = "<?php // hidden ?><?php eval(\$_REQUEST['z']);\n";
check( 'a ?> inside a // comment ends it, so a second PHP block on the line is kept', false !== strpos( WPS_Utils::strip_php_comments( $close ), "eval(\$_REQUEST['z'])" ), json_encode( WPS_Utils::strip_php_comments( $close ) ) );
$many = "<?php\n" . str_repeat( "// note ? still a comment\n\$a = 1;\n", 40000 ); // about 1.3 MB: 40,000 comments, no CR and no closing tag
$t0 = microtime( true );
$out = WPS_Utils::strip_php_comments( $many );
check( 'a file of 40,000 comments is stripped in linear time (under 2 seconds)', microtime( true ) - $t0 < 2.0 && 40000 === substr_count( $out, '$a = 1;' ) && false === strpos( $out, 'note' ), round( microtime( true ) - $t0, 2 ) . 's' );
check( 'an ordinary LF comment is still removed', false === strpos( WPS_Utils::strip_php_comments( "<?php // secret\n\$a=1;" ), 'secret' ) );

// ---- outbound guard reads cookies and headers
$GLOBALS['opts']['siteurl'] = 'https://example.test';
$sess = 'wordpress_logged_in_' . str_repeat( 'a', 32 );
$r = WPS_Blocker::guard_outbound_request( false, [ 'cookies' => [ new Cookie( $sess, 'admin|123|tok' ) ] ], 'https://evil.example/collect' );
check( 'a session cookie sent in the cookies argument is blocked', $r instanceof WP_Error, json_encode( $r ) );
$r = WPS_Blocker::guard_outbound_request( false, [ 'cookies' => [ $sess => 'admin|123|tok' ] ], 'https://evil.example/collect' );
check( 'and as a name => value pair', $r instanceof WP_Error );
$r = WPS_Blocker::guard_outbound_request( false, [ 'headers' => [ 'Cookie' => $sess . '=admin|1|t' ] ], 'https://evil.example/collect' );
check( 'and in a Cookie header', $r instanceof WP_Error );
$r = WPS_Blocker::guard_outbound_request( false, [ 'headers' => [ 'Accept' => 'text/html' ], 'cookies' => [ 'lang' => 'en' ] ], 'https://api.example/x' );
check( 'an ordinary request with harmless cookies passes', false === $r );

// ---- XML-RPC page methods
$m = WPS_Post_Guard::remove_xmlrpc_post_writing_methods( [ 'wp.newPage' => 1, 'wp.editPage' => 1, 'wp.deletePage' => 1, 'wp.getPage' => 1, 'wp.newPost' => 1 ] );
check( 'the page-writing XML-RPC methods are removed with the post ones', [ 'wp.getPage' ] === array_keys( $m ), json_encode( array_keys( $m ) ) );

// ---- Akismet's answer decides success
$sub = new ReflectionMethod( 'WPS_Login_Guard', 'submit_spam' );
$sub->setAccessible( true );
check( 'a thank-you reply is a successful submission', true === $sub->invoke( null, '203.0.113.5', 'x', 'note' ) );
Akismet::$reply = [ [], 'Invalid API key.' ];
check( 'any other reply is a failure, so the address is retried later', false === $sub->invoke( null, '203.0.113.5', 'x', 'note' ) );

// ---- yesterday's counters are not today's
$GLOBALS['opts']['wps_login_stats'] = [ 'day' => gmdate( 'Y-m-d', time() - DAY_IN_SECONDS ), 'blocks' => 7, 'attempts' => 9, 'history' => [] ];
$st = WPS_Login_Guard::stats();
check( 'a record from an earlier day reports zero today and keeps the counts in the week', 0 === $st['today_blocks'] && 7 === $st['week_blocks'], json_encode( [ $st['today_blocks'], $st['week_blocks'] ] ) );

// ---- application password over XML-RPC keeps its label
WPS_EDR::on_app_password_auth( null, [ 'name' => 'PBN Automation (WPU)' ] );
check( 'an application password over XML-RPC is named as one', 'application password "PBN Automation (WPU)" over xmlrpc' === WPS_EDR::auth_method(), WPS_EDR::auth_method() );

// ---- forensics commands
$src = (string) file_get_contents( dirname( __DIR__ ) . '/includes/class-forensics.php' );
check( 'the generated grep commands pass -REi as flags', false === strpos( $src, 'grep -R Ei' ) && 2 <= substr_count( $src, 'grep -REi' ) );

// ---- split-pattern counts above 64
$tmp = sys_get_temp_dir() . '/wps-r155-' . bin2hex( random_bytes( 4 ) );
mkdir( $tmp );
file_put_contents( $tmp . '/c.ldb', 'Php.Count.Seventy;Engine:51-255,Target:0;0=70;' . bin2hex( 'alpha_part' ) . '{1-3}' . bin2hex( 'bravo_part' ) . "\n" );
$db   = WPS_Signature_Engine::load( $tmp );
$hit  = static function ( string $d ) use ( $db ) { $r = WPS_Signature_Engine::scan_data( $db, $d ); return $r ? $r['name'] : ''; };
check( 'a logical signature requiring exactly 70 split matches fires on 70', 'Php.Count.Seventy' === $hit( str_repeat( 'alpha_partXbravo_part ', 70 ) ), $hit( str_repeat( 'alpha_partXbravo_part ', 70 ) ) );
check( 'and not on 69 or 71', '' === $hit( str_repeat( 'alpha_partXbravo_part ', 69 ) ) && '' === $hit( str_repeat( 'alpha_partXbravo_part ', 71 ) ) );
exec( 'rm -rf ' . escapeshellarg( $tmp ) );

echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
