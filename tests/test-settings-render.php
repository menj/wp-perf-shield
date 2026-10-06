<?php
/**
 * Render test for the Settings screen's "XML-RPC & exposure" panel (1.4.131).
 *
 * Run from the command line only:  php tests/test-settings-render.php
 *
 * Renders the real Settings tab with in-memory stand-ins for the WordPress
 * escaping and URL helpers, then checks the markup, that the saved values show
 * as checked, that no inline style attribute was added, and that every field in
 * the panel is one the save handler actually writes (a field the handler ignores
 * would silently never persist).
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}
define( 'ABSPATH', sys_get_temp_dir() . '/wps-sr-none/' );
define( 'WPS_OPTION', 'wps_opts' );
define( 'WPS_DIR', sys_get_temp_dir() . '/wps-sr-self/' );

function esc_url( $s ) { return htmlspecialchars( (string) $s, ENT_QUOTES ); }
function esc_attr( $s ) { return htmlspecialchars( (string) $s, ENT_QUOTES ); }
function esc_html( $s ) { return htmlspecialchars( (string) $s, ENT_QUOTES ); }
function esc_textarea( $s ) { return htmlspecialchars( (string) $s, ENT_QUOTES ); }
function admin_url( $p = '' ) { return 'http://example.test/wp-admin/' . $p; }
function home_url( $p = '' ) { return 'http://example.test' . $p; }
function wp_nonce_field( $a ) { echo '<input type="hidden" name="_wpnonce" value="n">'; }
function checked( $c, $current = true, $echo = true ) { $r = $c ? " checked='checked'" : ''; if ( $echo ) { echo $r; } return $r; }
function selected( $a, $b = true, $echo = true ) { $r = ( (string) $a === (string) $b ) ? " selected='selected'" : ''; if ( $echo ) { echo $r; } return $r; }
function wp_nonce_url( $u, $a = -1 ) { return $u . '&_wpnonce=n'; }
function get_option( $k, $d = false ) { return $d; }
function current_user_can( $c ) { return true; }
function get_site_url() { return 'http://example.test'; }
function wp_json_encode( $v ) { return json_encode( $v ); }

require dirname( __DIR__ ) . '/includes/class-exposure-guard.php';
require dirname( __DIR__ ) . '/includes/class-admin-settings.php';
// Minimal stand-ins for the collaborators the existing Sign-in panel calls.
class WPS_Login_Guard {
	public static function akismet_status() { return 'not configured'; }
	public static function akismet_usage() { return [ 'state' => 'unavailable' ]; }
	public static function akismet_usage_label() { return ''; }
	public static function __callStatic( $n, $a ) { return null; }
}
class WPS_Quarantine {
	const RETENTION_DAYS = 30;
	public static function __callStatic( $n, $a ) { return null; }
}
foreach ( [ 'WPS_Blocker', 'WPS_Post_Guard', 'WPS_Account_Guard' ] as $c ) {
	if ( ! class_exists( $c ) ) {
		eval( 'class ' . $c . ' { public static function __callStatic( $n, $a ) { return null; } }' );
	}
}

$fail = 0;
function check( string $name, bool $ok, string $detail = '' ): void {
	global $fail;
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $name . ( $ok ? '' : ' :: ' . $detail ) . "\n";
	if ( ! $ok ) {
		++$fail;
	}
}

$settings = [
	'xr_no_pingback'       => '1',
	'xr_disabled_methods'  => "wp.getUsers\nsystem.listMethods\nmy.customMethod",
	'xr_slug'              => 'wp-rpc-1a2b',
	'xr_allow_ips'         => "203.0.113.7\n198.51.100.0/24",
	'xr_hide_version'      => '1',
	'xr_rest_logged_in_only' => '1',
	'xr_rest_exempt_namespaces' => 'contact-form-7/',
];
ob_start();
try {
	WPS_Admin_Settings::render( [
		'settings' => $settings, 'auto_delete_enabled' => true, 'quarantine_enabled' => true,
		'auto_ip_block_enabled' => true, 'strict_upload_gate_enabled' => true, 'appearance' => 'light',
	] );
} catch ( \Throwable $e ) {
	echo 'RENDER EXCEPTION: ' . $e->getMessage() . "\n";
}
$html = (string) ob_get_clean();
check( 'the Settings screen renders', strlen( $html ) > 5000, (string) strlen( $html ) );

check( 'there is a tab button and a panel for XML-RPC & exposure', false !== strpos( $html, 'id="wps-st-xmlrpc"' ) && false !== strpos( $html, 'id="wps-sp-xmlrpc"' ) && false !== strpos( $html, 'data-panel="xmlrpc"' ) && false !== strpos( $html, 'data-wps-panel="xmlrpc"' ) );
preg_match_all( '/class="wps-subtab"/', $html, $tabs );
preg_match_all( '/data-wps-panel="/', $html, $panels );
check( 'every tab button has a panel (' . count( $tabs[0] ) . ' / ' . count( $panels[0] ) . ')', count( $tabs[0] ) === count( $panels[0] ) && count( $tabs[0] ) > 0 );
check( 'the new tab sits right after Sign-in', 1 === preg_match( '/id="wps-st-signin".*?<\/button>\s*<button[^>]*id="wps-st-xmlrpc"/s', $html ) );

$start = strpos( $html, 'id="wps-sp-xmlrpc"' );
$end   = strpos( $html, 'id="wps-sp-posting"', (int) $start );
$panel = false === $start || false === $end ? '' : substr( $html, $start, $end - $start );
check( 'the panel was found and is non-trivial', strlen( $panel ) > 3000, (string) strlen( $panel ) );

check( 'saved toggles render checked', 1 === preg_match( '/name="xr_no_pingback"[^>]*checked/', $panel ) && 1 === preg_match( '/name="xr_hide_version"[^>]*checked/', $panel ) && 1 === preg_match( '/name="xr_rest_logged_in_only"[^>]*checked/', $panel ) );
check( 'unset toggles render unchecked', 0 === preg_match( '/name="xr_disable_feeds"[^>]*checked/', $panel ) && 0 === preg_match( '/name="xr_remove_emoji"[^>]*checked/', $panel ) );
check( 'saved curated methods render checked, the others do not', 1 === preg_match( '/value="wp\.getUsers"[^>]*checked/', $panel ) && 1 === preg_match( '/value="system\.listMethods"[^>]*checked/', $panel ) && 0 === preg_match( '/value="wp\.getPosts"[^>]*checked/', $panel ) );
check( 'a non-curated saved method appears in the free-text box, a curated one does not', false !== strpos( $panel, 'my.customMethod' ) && 1 === preg_match( '/name="xr_methods_extra"[^>]*>my\.customMethod<\/textarea>/', $panel ) );
check( 'the endpoint name and address lists show their saved values', false !== strpos( $panel, 'value="wp-rpc-1a2b"' ) && false !== strpos( $panel, '198.51.100.0/24' ) && false !== strpos( $panel, 'contact-form-7/' ) );
check( 'no inline style attribute was added to the panel', false === strpos( $panel, 'style="' ), 'found style=' );
check( 'no inline script was added to the panel', false === stripos( $panel, '<script' ) );
check( 'every curated method has a checkbox', substr_count( $panel, 'name="xr_methods[]"' ) === count( WPS_Exposure_Guard::CURATED_METHODS ) );

// Every named field in the panel must be one the save handler writes.
preg_match_all( '/name="(xr_[a-z_]+)(\[\])?"/', $panel, $names );
$fields = array_unique( $names[1] );
$handler = (string) file_get_contents( dirname( __DIR__ ) . '/includes/class-admin.php' );
$missing = [];
foreach ( $fields as $f ) {
	$ok = false !== strpos( $handler, "\$_POST['" . $f . "']" ) || ( 'xr_methods' === $f && false !== strpos( $handler, "\$_POST['xr_methods']" ) );
	if ( ! $ok ) {
		$missing[] = $f;
	}
}
check( 'every xr_ field in the panel is read by the save handler (' . count( $fields ) . ' fields)', [] === $missing && count( $fields ) >= 13, implode( ',', $missing ) );
check( 'every stored xr_ key the guard reads is written by the handler', (function () use ( $handler ) {
	$src = (string) file_get_contents( dirname( __DIR__ ) . '/includes/class-exposure-guard.php' );
	preg_match_all( "/(?:self::on|self::get)\( '(xr_[a-z_]+)'/", $src, $m );
	foreach ( array_unique( $m[1] ) as $k ) {
		if ( false === strpos( $handler, "'" . $k . "'" ) ) {
			return false;
		}
	}
	return true;
})() );

echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
