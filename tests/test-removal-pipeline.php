<?php
/**
 * Regression test for the removal pipeline (1.4.152): the quarantine's policy gate, the
 * operator's own removals, the policy-ban tiers and the findings screen's forms.
 *
 * Run from the command line only:  php tests/test-removal-pipeline.php
 *
 * Before 1.4.152 no caller passed `finding_type` to WPS_Quarantine::quarantine(), so its last gate
 * judged every removal as an untyped heuristic and refused everything under plugins and themes,
 * while the screen reported a broken quarantine store. This suite loads the real policy, quarantine,
 * scanner, blocker and overview renderer together, which no earlier suite did.
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}

$tmp = sys_get_temp_dir() . '/wps-rp-' . bin2hex( random_bytes( 4 ) );
mkdir( $tmp . '/wp-content/plugins/wp-perf-shield-self', 0777, true );
mkdir( $tmp . '/wp-content/mu-plugins', 0777, true );
mkdir( $tmp . '/wp-includes', 0777, true );
mkdir( $tmp . '/wp-admin', 0777, true );
define( 'ABSPATH', $tmp . '/' );
define( 'WPS_DIR', $tmp . '/wp-content/plugins/wp-perf-shield-self/' );
define( 'WPS_OPTION', 'wps_opts' );
define( 'WP_CONTENT_DIR', $tmp . '/wp-content' );
define( 'WP_PLUGIN_DIR', $tmp . '/wp-content/plugins' );
define( 'WPMU_PLUGIN_DIR', $tmp . '/wp-content/mu-plugins' );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'DAY_IN_SECONDS', 86400 );

$GLOBALS['opts']   = [];
$GLOBALS['trans']  = [];
$GLOBALS['events'] = [];
function get_option( $k, $d = false ) {
	$v = array_key_exists( $k, $GLOBALS['opts'] ) ? $GLOBALS['opts'][ $k ] : $d;
	// A stand-in for another request rewriting the option between a read and a delete.
	if ( isset( $GLOBALS['mutate'] ) && $GLOBALS['mutate']['name'] === $k && --$GLOBALS['mutate']['after'] === 0 ) {
		$GLOBALS['opts'][ $k ] = $GLOBALS['mutate']['to'];
	}
	return $v;
}
function update_option( $k, $v, $a = null ) { $GLOBALS['opts'][ $k ] = $v; return true; }
function delete_option( $k ) { unset( $GLOBALS['opts'][ $k ] ); return true; }
function get_transient( $k ) { return array_key_exists( $k, $GLOBALS['trans'] ) ? $GLOBALS['trans'][ $k ] : false; }
function set_transient( $k, $v, $t = 0 ) { $GLOBALS['trans'][ $k ] = $v; return true; }
function delete_transient( $k ) { unset( $GLOBALS['trans'][ $k ] ); return true; }
function apply_filters( $t, $v ) { return $v; }
function add_action() {}
function add_filter() {}
function wp_json_encode( $v ) { return json_encode( $v ); }
function wp_get_current_user() { return (object) [ 'ID' => 1, 'user_login' => 'operator' ]; }
function sanitize_title( $s ) { return strtolower( trim( preg_replace( '/[^a-z0-9_-]+/i', '-', $s ), '-' ) ); }
function sanitize_key( $s ) { return preg_replace( '/[^a-z0-9_-]/', '', strtolower( (string) $s ) ); }
function sanitize_html_class( $s ) { return preg_replace( '/[^A-Za-z0-9_-]/', '', (string) $s ); }
function esc_url( $s ) { return htmlspecialchars( (string) $s, ENT_QUOTES ); }
function esc_attr( $s ) { return htmlspecialchars( (string) $s, ENT_QUOTES ); }
function esc_html( $s ) { return htmlspecialchars( (string) $s, ENT_QUOTES ); }
function admin_url( $p = '' ) { return 'http://example.test/wp-admin/' . $p; }
function wp_nonce_field( $a ) { echo '<input type="hidden" name="_wpnonce" value="n">'; }
function wp_unslash( $s ) { return $s; }
function get_bloginfo( $k ) { return '6.9'; }
function get_theme_root() { return ABSPATH . 'wp-content/themes'; }
function wp_normalize_path( $p ) { return str_replace( '\\', '/', $p ); }

class WP_Error { public $code; public $message; public $data; public function __construct( $c = '', $m = '', $d = [] ) { $this->code = $c; $this->message = $m; $this->data = $d; } }
/** The options table as the quarantine's conditional DELETE sees it (values stored the WordPress way). */
class FakeDB {
	public $options = 'wp_options';
	public $deletes = [];
	public function prepare( $sql, ...$a ) { foreach ( $a as $x ) { $sql = preg_replace( '/%[sd]/', is_int( $x ) ? (string) $x : "'" . addslashes( (string) $x ) . "'", $sql, 1 ); } return $sql; }
	public function get_var( $sql ) { return 'yes'; }
	public function query( $sql ) {
		$this->deletes[] = $sql;
		if ( preg_match( "/^DELETE FROM wp_options WHERE option_name = '([^']+)' AND option_value = '((?:[^'\\\\]|\\\\.)*)'/", $sql, $m ) ) {
			$name = $m[1];
			if ( ! array_key_exists( $name, $GLOBALS['opts'] ) ) { return 0; }
			$v      = $GLOBALS['opts'][ $name ];
			$stored = ( is_array( $v ) || is_object( $v ) ) ? serialize( $v ) : (string) $v;
			if ( $stored !== stripslashes( $m[2] ) ) { return 0; }
			unset( $GLOBALS['opts'][ $name ] );
			return 1;
		}
		return 0;
	}
}
$wpdb = new FakeDB();
class WPS_Logger {
	public static function log_event( $t, $s, $ip = '' ) { $GLOBALS['events'][] = [ $t, $s ]; }
	public static function write( $m ) {}
	public static function notify_admin( $a, $b ) {}
}

require dirname( __DIR__ ) . '/includes/class-wps-utils.php';
require dirname( __DIR__ ) . '/includes/class-remediation-policy.php';
require dirname( __DIR__ ) . '/includes/class-quarantine.php';
require dirname( __DIR__ ) . '/includes/class-scanner.php';
require dirname( __DIR__ ) . '/includes/class-blocker.php';
require dirname( __DIR__ ) . '/includes/class-admin-overview.php';

$fail = 0;
function check( string $name, bool $ok, string $detail = '' ): void {
	global $fail;
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $name . ( $ok ? '' : ' :: ' . $detail ) . "\n";
	if ( ! $ok ) {
		++$fail;
	}
}
function put( string $p, string $c = "<?php\n" ): void {
	@mkdir( dirname( $p ), 0777, true );
	file_put_contents( $p, $c );
}
function events( string $type ): int {
	return count( array_filter( $GLOBALS['events'], static fn( $e ) => $type === $e[0] ) );
}
$P = WP_PLUGIN_DIR;

// ---- 1. the automatic path: a confirmed finding inside a plugin folder is quarantined.
put( $P . '/evil-one/shell.php', "<?php eval(base64_decode(\$_POST['x']));\n" );
$id = WPS_Quarantine::quarantine( $P . '/evil-one/shell.php', [
	'type'         => 'Known malware upload',
	'finding_type' => 'Known malware upload',
	'severity'     => 'critical',
	'subject'      => 'evil-one/shell.php',
	'reason'       => 'auto-remediation: Known malware upload',
] );
check( 'a confirmed finding under plugins/ is quarantined by the automatic path', null !== $id && ! file_exists( $P . '/evil-one/shell.php' ), json_encode( [ $id, WPS_Quarantine::last_denial(), $GLOBALS['events'] ] ) );

// ---- 2. the operator's own removal, as the Remediation tab sends it.
put( $P . '/evil-two/door.php' );
$res = WPS_Scanner::remediate_manually( $P . '/evil-two/door.php' );
check( '"Delete this path" removes a file inside a plugin folder', ! empty( $res['ok'] ) && ! file_exists( $P . '/evil-two/door.php' ), json_encode( $res ) );
put( $P . '/evil-three/x.php' );
$res = WPS_Scanner::remediate_manually( $P . '/evil-three' );
check( 'and a whole plugin folder', ! empty( $res['ok'] ) && ! is_dir( $P . '/evil-three' ), json_encode( $res ) );

// ---- 3. the operator's removal still honours a Safe decision and never trips the breaker.
put( $P . '/kept/kept.php', "<?php\n/* Plugin Name: Kept */\n" );
WPS_Remediation_Policy::mark_safe( $P . '/kept/kept.php', WPS_Remediation_Policy::SCOPE_FILE, 'operator says so' );
$res = WPS_Scanner::remediate_manually( $P . '/kept/kept.php' );
check( 'a Safe target is refused', empty( $res['ok'] ) && is_file( $P . '/kept/kept.php' ), json_encode( $res ) );
check( 'the refusal names the policy, not the quarantine store', false !== stripos( (string) $res['message'], 'removal policy' ) && false !== stripos( (string) $res['message'], 'Safe' ), (string) $res['message'] );
check( 'an operator refusal does not trip the circuit breaker', ! WPS_Remediation_Policy::breaker_tripped() );
check( 'the refusal names the rule', false !== strpos( (string) $res['message'], 'operator_safe' ), (string) $res['message'] );
$id = WPS_Quarantine::quarantine( $P . '/kept/kept.php', [ 'type' => 'manual removal', 'reason' => 'x' ] );
check( 'the quarantine\'s own gate refuses it too and records why', null === $id && false !== strpos( WPS_Quarantine::last_denial(), 'operator_safe' ), WPS_Quarantine::last_denial() );

// ---- 4. core is never removed, by anyone.
put( ABSPATH . 'wp-includes/pluggable.php' );
$res = WPS_Scanner::remediate_manually( ABSPATH . 'wp-includes/pluggable.php' );
check( 'a core file is refused even to the operator', empty( $res['ok'] ) && is_file( ABSPATH . 'wp-includes/pluggable.php' ), json_encode( $res ) );

// ---- 5. the gate with no type at all still treats the two operator callers as the operator.
put( $P . '/evil-four/x.php' );
$id = WPS_Quarantine::quarantine( $P . '/evil-four/x.php', [ 'type' => 'operator_bulk_delete', 'reason' => 'removed in bulk by the operator' ] );
check( 'the bulk caller with no finding_type is treated as an operator removal', null !== $id, WPS_Quarantine::last_denial() );
put( $P . '/evil-five/x.php' );
$id = WPS_Quarantine::quarantine( $P . '/evil-five/x.php', [ 'type' => 'Suspicious PHP in uploads', 'reason' => 'x' ] );
check( 'a heuristic type with no finding_type is still refused under plugins/', null === $id && is_file( $P . '/evil-five/x.php' ) );
check( 'a heuristic refusal is not a Safe violation, so the breaker stays armed', ! WPS_Remediation_Policy::breaker_tripped() );
$id = WPS_Quarantine::quarantine( $P . '/kept/kept.php', [ 'type' => 'Known malware upload', 'finding_type' => 'Known malware upload', 'reason' => 'x' ] );
check( 'a scanner finding reaching the gate on a Safe target is refused and trips the breaker', null === $id && is_file( $P . '/kept/kept.php' ) && WPS_Remediation_Policy::breaker_tripped() );
WPS_Remediation_Policy::reset_breaker();

// ---- 5b. the policy holds immediately before a permanent removal and on the bulk channel (CodeAnt, PR 29).
put( $P . '/kept/kept.php', "<?php\n/* Plugin Name: Kept */\n" );
$res = WPS_Scanner::remediate_manually( $P . '/kept/kept.php', true );
check( 'a permanent removal of a Safe target is refused before anything is deleted', empty( $res['ok'] ) && is_file( $P . '/kept/kept.php' ) && false !== strpos( (string) $res['message'], 'operator_safe' ), json_encode( $res ) );
WPS_Remediation_Policy::trip_breaker( 'test' );
put( $P . '/evil-six/x.php' );
$res = WPS_Scanner::remediate_manually( $P . '/evil-six/x.php', true );
check( 'a permanent removal is refused while the circuit breaker is tripped', empty( $res['ok'] ) && is_file( $P . '/evil-six/x.php' ) && false !== strpos( (string) $res['message'], 'circuit_breaker' ), json_encode( $res ) );
WPS_Remediation_Policy::reset_breaker();
$id = WPS_Quarantine::quarantine( $P . '/kept/kept.php', [ 'type' => 'operator_bulk_delete', 'finding_type' => 'Known malware upload', 'reason' => 'x' ] );
check( 'the bulk channel carrying a detector type is refused on a Safe target without tripping the breaker', null === $id && is_file( $P . '/kept/kept.php' ) && ! WPS_Remediation_Policy::breaker_tripped() && false !== strpos( WPS_Quarantine::last_denial(), 'operator_safe' ), WPS_Quarantine::last_denial() );

check( 'a refusal is this call\'s: a later call on a path that is gone reports no stale policy denial', null === WPS_Quarantine::quarantine( $P . '/no-such-file.php', [ 'type' => 'manual removal' ] ) && '' === WPS_Quarantine::last_denial(), WPS_Quarantine::last_denial() );

// ---- 5c. an option snapshot is of the value actually removed (1.4.153).
$GLOBALS['opts']['evil_state'] = [ 'v' => 1 ];
$GLOBALS['mutate'] = [ 'name' => 'evil_state', 'after' => 1, 'to' => [ 'v' => 2 ] ]; // rewritten right after the first read
$qid = WPS_Quarantine::quarantine_and_remove_option( 'evil_state', [ 'type' => 'db_option', 'reason' => 'x' ] );
unset( $GLOBALS['mutate'] );
$man = null !== $qid ? json_decode( (string) @file_get_contents( WPS_Quarantine::store_dir() . '/' . $qid . '/manifest.json' ), true ) : null;
check( 'the option is removed and the restorable snapshot holds the value that was removed, not the one first read', null !== $qid && ! array_key_exists( 'evil_state', $GLOBALS['opts'] ) && is_array( $man ) && serialize( [ 'v' => 2 ] ) === base64_decode( (string) $man['option_value_b64'] ) && ! empty( $man['supersedes'] ), json_encode( [ $qid, $man ] ) );
$GLOBALS['opts']['calm_state'] = 'x';
$qid = WPS_Quarantine::quarantine_and_remove_option( 'calm_state', [ 'type' => 'db_option', 'reason' => 'x' ] );
$man = null !== $qid ? json_decode( (string) @file_get_contents( WPS_Quarantine::store_dir() . '/' . $qid . '/manifest.json' ), true ) : null;
check( 'an option nobody rewrote is snapshotted once', null !== $qid && is_array( $man ) && empty( $man['supersedes'] ) );
check( 'the removal is a conditional DELETE on the snapshotted value, not a blind delete_option()', 3 === count( array_filter( $wpdb->deletes, static fn( $q ) => false !== strpos( $q, 'AND option_value =' ) ) ), json_encode( $wpdb->deletes ) );

// ---- 6. the on-disk policy ban: both tiers go through the policy.
$GLOBALS['opts']['wps_opts'] = [ 'policy_ban_enabled' => '1' ];
put( $P . '/wp-file-manager/file_folder_manager.php', "<?php\n/* Plugin Name: File Manager */\n" );
WPS_Remediation_Policy::mark_safe( $P . '/wp-file-manager', WPS_Remediation_Policy::SCOPE_DIR, 'operator wants it' );
$removed = WPS_Blocker::enforce_policy_ban();
check( 'a hard-banned folder the operator marked Safe is left alone', ! in_array( 'wp-file-manager', $removed, true ) && is_dir( $P . '/wp-file-manager' ), json_encode( [ $removed, $GLOBALS['events'] ] ) );
check( 'and the skip is logged with the rule', 1 === events( 'policy_ban_skipped_policy' ), json_encode( $GLOBALS['events'] ) );
WPS_Remediation_Policy::revoke_safe( $P . '/wp-file-manager' );
$removed = WPS_Blocker::enforce_policy_ban();
check( 'with the Safe decision revoked the hard tier removes it', in_array( 'wp-file-manager', $removed, true ) && ! is_dir( $P . '/wp-file-manager' ), json_encode( [ $removed, $GLOBALS['events'] ] ) );
put( $P . '/filebird/filebird.php', "<?php\n/* Plugin Name: filebird */\n" );
$removed = WPS_Blocker::enforce_policy_ban();
check( 'the soft tier quarantines a banned folder on first sight', in_array( 'filebird', $removed, true ) && ! is_dir( $P . '/filebird' ), json_encode( [ $removed, $GLOBALS['events'] ] ) );
WPS_Remediation_Policy::trip_breaker( 'test' );
put( $P . '/filebird-two/filebird.php', "<?php\n/* Plugin Name: filebird */\n" );
$removed = WPS_Blocker::enforce_policy_ban();
check( 'a tripped circuit breaker halts the ban sweep too', [] === $removed && is_dir( $P . '/filebird-two' ), json_encode( $removed ) );
WPS_Remediation_Policy::reset_breaker();
$GLOBALS['opts']['wps_opts'] = [];

// ---- 7. the findings screen: no form inside the bulk form, and each Mark Safe has its own.
$findings = [
	[ 'type' => 'Known malware upload', 'severity' => 'critical', 'subject' => 'a', 'delete_path' => $P . '/a/a.php', 'action' => 'x' ],
	[ 'type' => 'Backdoor', 'severity' => 'high', 'subject' => 'b', 'delete_path' => $P . '/b/b.php', 'action' => 'y' ],
	[ 'type' => 'Note only', 'severity' => 'low', 'subject' => 'c', 'action' => 'z' ],
];
ob_start();
WPS_Admin_Overview::render( [ 'last_scan' => [ 'time' => 'now' ], 'findings' => $findings, 'events' => [], 'blocked_ips' => [], 'event_labels' => [] ] );
$html = ob_get_clean();
$open = strpos( $html, '<form method="post" action="http://example.test/wp-admin/admin-post.php" id="wps-bulk-findings">' );
check( 'the bulk form is rendered', false !== $open );
$close = false !== $open ? strpos( $html, '</form>', $open ) : false;
$inner = ( false !== $open && false !== $close ) ? substr( $html, $open + 5, $close - $open - 5 ) : '';
check( 'no form is nested inside the bulk form', '' !== $inner && false === strpos( $inner, '<form' ) );
check( 'both bulk buttons are inside the bulk form', false !== strpos( $inner, 'value="delete"' ) && false !== strpos( $inner, 'value="safe"' ) );
check( 'the bulk form holds no Mark Safe action field', false === strpos( $inner, 'wps_mark_safe' ) );
preg_match_all( '/<form [^>]*id="(wps-ms-\d+)"[^>]*>(.*?)<\/form>/s', $html, $ms, PREG_SET_ORDER );
check( 'one Mark Safe form per finding with a file target, after the bulk form', 2 === count( $ms ) && strpos( $html, 'id="wps-ms-1"' ) > $close, count( $ms ) . ' forms' );
$ok = count( $ms ) > 0;
foreach ( $ms as $m ) {
	$ok = $ok && false !== strpos( $m[2], 'value="wps_mark_safe"' )
		&& 1 === preg_match( '/<select name="scope" form="' . $m[1] . '"/', $html )
		&& 1 === preg_match( '/<button type="submit" form="' . $m[1] . '"/', $html );
}
check( 'each Mark Safe select and button point at their own form', $ok );
check( 'the hidden path travels with the right form', false !== strpos( $ms[0][2] ?? '', esc_attr( $P . '/a/a.php' ) ) && false !== strpos( $ms[1][2] ?? '', esc_attr( $P . '/b/b.php' ) ) );
check( 'the tab opens and closes its divs evenly', substr_count( $html, '<div' ) === substr_count( $html, '</div>' ) && substr_count( $html, '<form' ) === substr_count( $html, '</form>' ) );

// ---- 8. the bulk handler is the operator's action, judged like "Delete this path".
require dirname( __DIR__ ) . '/includes/class-admin.php';
check( 'the bulk handler no longer carries a per-finding lookup', ! method_exists( 'WPS_Admin', 'finding_type_for' ) );
check( 'the operator bulk type is refused on a Safe target with the Safe rule', 'operator_safe' === WPS_Remediation_Policy::decide( [ 'delete_path' => $P . '/kept/kept.php', 'type' => 'operator bulk removal' ] )['rule'] );
put( $P . '/bulk/x.php' );
$d = WPS_Remediation_Policy::decide( [ 'delete_path' => $P . '/bulk/x.php', 'type' => 'operator bulk removal' ] );
check( 'an unmarked file in a plugin folder is allowed to the operator with the operator_removal rule', $d['allowed'] && 'operator_removal' === $d['rule'], json_encode( $d ) );
// CodeAnt, PR 29: the official-release protection is for behavioural findings; an operator's removal of a file that
// matches its published release is still the operator's call.
if ( ! class_exists( 'WPS_Integrity' ) ) { // conditional, so the stub is not hoisted above the earlier checks
	class WPS_Integrity { public static function is_official( string $p ): bool { return true; } }
}
$d = WPS_Remediation_Policy::decide( [ 'delete_path' => $P . '/bulk/x.php', 'type' => 'manual removal by operator' ] );
check( 'an operator removal of a verified official file is allowed', $d['allowed'] && 'operator_removal' === $d['rule'], json_encode( $d ) );
$d = WPS_Remediation_Policy::decide( [ 'delete_path' => $P . '/bulk/x.php', 'type' => 'Suspicious PHP in uploads' ] );
check( 'while a behavioural finding about the same file is still refused as verified', 'verified_official_release' === $d['rule'], json_encode( $d ) );
check( 'a banned-by-policy type keeps its own rule', 'operator_policy_ban' === WPS_Remediation_Policy::decide( [ 'delete_path' => $P . '/bulk/x.php', 'type' => 'wp-file-manager banned by site policy' ] )['rule'] );

// cleanup
$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $tmp, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::CHILD_FIRST );
foreach ( $it as $f ) { $f->isDir() ? @rmdir( $f->getPathname() ) : @unlink( $f->getPathname() ); }
@rmdir( $tmp );

echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
