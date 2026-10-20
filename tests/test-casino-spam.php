<?php
/**
 * Regression test for the casino-spam injector checks (1.4.147).
 *
 * Run from the command line only:  php tests/test-casino-spam.php
 *
 * Synthetic fixtures modelled on a public write-up of a casino-spam injector:
 * a crawler-only eval, a hidden-link content filter, rewrite rules to a PHP
 * script in uploads, and an encoded payload kept in an option. Each check is
 * also run against near misses that must stay quiet.
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}

$tmp = sys_get_temp_dir() . '/wps-cas-' . bin2hex( random_bytes( 4 ) );
mkdir( $tmp . '/plugins/wps-self', 0777, true );
mkdir( $tmp . '/mu-plugins', 0777, true );
mkdir( $tmp . '/uploads', 0777, true );
define( 'ABSPATH', $tmp . '/site/' );
mkdir( ABSPATH, 0777, true );
define( 'WPS_DIR', $tmp . '/plugins/wps-self/' );
define( 'WPS_OPTION', 'wps_opts' );
define( 'WP_PLUGIN_DIR', $tmp . '/plugins' );
define( 'WPMU_PLUGIN_DIR', $tmp . '/mu-plugins' );
define( 'WP_CONTENT_DIR', $tmp );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'DAY_IN_SECONDS', 86400 );
$GLOBALS['opts']    = [ 'quarantine_enabled' => '0' ];
$GLOBALS['options'] = [];
$GLOBALS['deleted'] = [];
$GLOBALS['crons']   = [];
function get_option( $k, $d = false ) {
	if ( 'wps_opts' === $k ) {
		return $GLOBALS['opts'];
	}
	return array_key_exists( $k, $GLOBALS['options'] ) ? $GLOBALS['options'][ $k ] : $d;
}
function update_option() { return true; }
function delete_option( $k ) { $GLOBALS['deleted'][] = $k; unset( $GLOBALS['options'][ $k ] ); return true; }
function apply_filters( $t, $v ) { return $v; }
function wp_json_encode( $v ) { return json_encode( $v ); }
function _get_cron_array() { return $GLOBALS['crons']; }
function wp_unschedule_event() { return true; }
function get_transient() { return false; }
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
foreach ( glob( dirname( __DIR__ ) . '/includes/class-*.php' ) as $f ) {
	if ( false === strpos( $f, 'admin' ) && false === strpos( $f, 'blocker' ) ) {
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
function by_name( array $f ): array {
	$o = [];
	foreach ( $f as $x ) {
		$o[ basename( (string) ( $x['path'] ?? '' ) ) ] = $x;
	}
	return $o;
}

$P = $tmp . '/plugins';
$M = $tmp . '/mu-plugins';

// ---- crawler-gated eval
$inject = "add_action('init', function () {\n    \$ua = isset(\$_SERVER['HTTP_USER_AGENT']) ? \$_SERVER['HTTP_USER_AGENT'] : '';\n    if (preg_match('/googlebot|bingbot/i', \$ua)) {\n        \$p = get_option('_gg_link_cache');\n        if (\$p) { eval('?>' . base64_decode(\$p)); exit; }\n    }\n});\n";
put( $M . '/wp-seo-helper.php', "<?php\n/* Plugin Name: WP SEO Helper */\n" . $inject );
put( $P . '/tiny-seo/tiny-seo.php', "<?php\n/* Plugin Name: Tiny SEO */\n" . $inject );
put( $P . '/big-seo/big-seo.php', "<?php\n/* Plugin Name: Big SEO */\n" . $inject . str_repeat( "function pad_fn_x() { return 'padding line to make the file large enough'; }\n", 400 ) );
put( $P . '/crawler-list/crawler-list.php', "<?php\n/* Plugin Name: Crawler List */\nfunction is_bot() { return (bool) preg_match('/googlebot|bingbot|yandexbot/i', \$_SERVER['HTTP_USER_AGENT'] ?? ''); }\n" . str_repeat( "// filler\n", 20 ) );
put( $P . '/evaler/evaler.php', "<?php\n/* Plugin Name: Evaler */\nfunction run_x(\$code) { eval(\$code); }\n" . str_repeat( "// filler\n", 20 ) );
put( $P . '/far/far.php', "<?php\n/* Plugin Name: Far */\nif (preg_match('/googlebot/i', \$_SERVER['HTTP_USER_AGENT'] ?? '')) { echo 'hi'; }\n" . implode( '', array_map( static fn( $i ) => "function ordinary_fn_$i() { return $i; }\n", range( 1, 90 ) ) ) . "function z(\$c) { eval(\$c); }\n" );
$f  = run( 'check_crawler_gated_eval' );
$by = by_name( $f );
check( 'a crawler-only eval dropped into mu-plugins is a removable finding', isset( $by['wp-seo-helper.php'] ) && ! empty( $by['wp-seo-helper.php']['auto_delete'] ) && 'Crawler-only payload runner' === $by['wp-seo-helper.php']['type'] );
check( 'even a small plugin file holding only the payload is reported, not removed: inside a plugin folder a proximity match is not enough to delete', isset( $by['tiny-seo.php'] ) && empty( $by['tiny-seo.php']['auto_delete'] ) && ! isset( $by['tiny-seo.php']['delete_path'] ) );
check( 'the same code spliced into a large plugin file is reported, not removed', isset( $by['big-seo.php'] ) && empty( $by['big-seo.php']['auto_delete'] ) && ! isset( $by['big-seo.php']['delete_path'] ), json_encode( $by['big-seo.php'] ?? null ) );
check( 'a crawler list with no eval, an eval with no crawler, and the two far apart are all quiet', ! isset( $by['crawler-list.php'] ) && ! isset( $by['evaler.php'] ) && ! isset( $by['far.php'] ), implode( ',', array_keys( $by ) ) );

// ---- hidden gambling-link filter
$hid = "add_filter('the_content', function (\$c) {\n    return \$c . '<div style=\"height:0;overflow:hidden\"><a href=\"https://example.invalid/a\">online casino no deposit bonus</a> <a href=\"https://example.invalid/b\">Slot Gacor</a></div>';\n}, 999);\n";
put( $M . '/hidden-links.php', "<?php\n/* Plugin Name: Hidden Links */\n" . $hid );
put( $P . '/big-links/big-links.php', "<?php\n/* Plugin Name: Big Links */\n" . $hid . str_repeat( "function pad_fn_y() { return 'padding line to make the file large enough'; }\n", 400 ) );
put( $P . '/cookie-banner/cookie-banner.php', "<?php\n/* Plugin Name: Cookie Banner */\nadd_filter('the_content', function (\$c) {\n    return \$c . '<div id=\"banner\" style=\"display:none\"><a href=\"/privacy\">Privacy policy</a> <a href=\"/cookies\">Cookie settings</a></div>';\n});\n" . str_repeat( "// filler\n", 20 ) );
put( $P . '/visible-casino/visible-casino.php', "<?php\n/* Plugin Name: Casino Reviews */\nadd_filter('the_content', function (\$c) {\n    return \$c . '<p>Read our <a href=\"/casino-reviews\">online casino no deposit bonus</a> guide.</p>';\n});\n" . str_repeat( "// filler\n", 20 ) );
put( $P . '/option-links/option-links.php', "<?php\n/* Plugin Name: Option Links */\nadd_filter('the_content', function (\$c) {\n    \$l = get_option('_wp_seo_boost');\n    return \$c . '<div style=\"height:0;overflow:hidden\"><a href=\"' . \$l . '\">x</a></div>';\n}, 999);\n" . str_repeat( "// filler\n", 20 ) );
$by = by_name( run( 'check_hidden_link_filter' ) );
check( 'a hidden-link filter with gambling anchors in mu-plugins is removable', isset( $by['hidden-links.php'] ) && ! empty( $by['hidden-links.php']['auto_delete'] ) && 'Hidden gambling-link injector' === $by['hidden-links.php']['type'] );
check( 'the same filter inside a large plugin file is reported, not removed', isset( $by['big-links.php'] ) && empty( $by['big-links.php']['auto_delete'] ) );
check( 'hidden links beside a listed option name are found', isset( $by['option-links.php'] ), implode( ',', array_keys( $by ) ) );
check( 'a hidden privacy-link banner and visible casino links are not reported', ! isset( $by['cookie-banner.php'] ) && ! isset( $by['visible-casino.php'] ), implode( ',', array_keys( $by ) ) );

// ---- htaccess rewrite to a PHP script in uploads
$wp_rules = "# BEGIN WordPress\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteBase /\nRewriteRule ^index\\.php\$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteRule . /index.php [L]\n</IfModule>\n# END WordPress\n";
put( ABSPATH . '.htaccess', $wp_rules );
check( 'the default WordPress rules are not reported', [] === run( 'check_htaccess_php_doorway' ) );
put( ABSPATH . '.htaccess', $wp_rules . "RewriteRule ^security-handler/(.*)\$ /wp-content/plugins/sec/handler.php?x=\$1 [L]\n" );
check( 'a rule to a PHP script in a plugin folder is not reported', [] === run( 'check_htaccess_php_doorway' ) );
put( ABSPATH . '.htaccess', "# BEGIN casino\nRewriteEngine On\nRewriteRule ^casino-bonus-(.*)\\.html\$ /wp-content/uploads/cache/render.php?k=\$1 [L]\nRewriteRule ^slot-review-(.*)\\.html\$ /wp-content/uploads/cache/render.php?k=\$1 [L]\n# END casino\n" . $wp_rules );
$f = run( 'check_htaccess_php_doorway' );
check( 'rules to a PHP script in uploads/cache are reported once, and nothing is removed', 1 === count( $f ) && empty( $f[0]['auto_delete'] ) && ! isset( $f[0]['delete_path'] ) && false !== strpos( $f[0]['subject'], 'render.php' ), json_encode( $f ) );
unlink( ABSPATH . '.htaccess' );
put( $tmp . '/uploads/.htaccess', "RewriteEngine On\nRewriteRule ^pic\\.jpg\$ shell.php [L]\n" );
check( 'any rule to a .php file in the uploads .htaccess is reported', 1 === count( run( 'check_htaccess_php_doorway' ) ) );
unlink( $tmp . '/uploads/.htaccess' );

// ---- options and cron
$blob = base64_encode( str_repeat( '<?php echo 1; ', 40 ) );
$GLOBALS['options'] = [ '_wp_seo_boost' => $blob, 'theme_perf_settings' => 'a:2:{s:5:"color";s:3:"red";s:4:"size";i:12;}', 'wp_ad_render_cache' => "<?php eval(base64_decode('" . str_repeat( 'QQ', 60 ) . "')); ?>", '_cache_optimizer_v2' => '1' ];
$f  = run( 'check_casino_spam_options' );
$by = [];
foreach ( $f as $x ) {
	$by[ strtok( $x['subject'], ' ' ) ] = $x;
}
check( 'a base64 blob and an eval under the listed names are found and cleaned', isset( $by['_wp_seo_boost'] ) && isset( $by['wp_ad_render_cache'] ) && ! empty( $by['_wp_seo_boost']['remediated'] ) && in_array( '_wp_seo_boost', $GLOBALS['deleted'], true ), json_encode( array_keys( $by ) ) );
$GLOBALS['options'] = [ '_wp_seo_boost' => base64_encode( str_repeat( 'ordinary encoded setting value, nothing executable here. ', 12 ) ), 'wp_ad_render_cache' => base64_encode( random_bytes( 240 ) ) ];
$GLOBALS['deleted'] = [];
$f = run( 'check_casino_spam_options' );
check( 'a long base64 value that decodes to plain text or binary is left alone', [] === $f && ! $GLOBALS['deleted'], json_encode( array_map( static fn( $x ) => $x['subject'], $f ) ) );
$GLOBALS['options'] = [ '_wp_seo_boost' => $blob, 'theme_perf_settings' => 'a:2:{s:5:"color";s:3:"red";s:4:"size";i:12;}', 'wp_ad_render_cache' => "<?php eval(base64_decode('" . str_repeat( 'QQ', 60 ) . "')); ?>", '_cache_optimizer_v2' => '1' ];
$GLOBALS['deleted'] = [];
$f  = run( 'check_casino_spam_options' );
$by = [];
foreach ( $f as $x ) {
	$by[ strtok( $x['subject'], ' ' ) ] = $x;
}
check( 'an ordinary settings array and a one-character value under the same names are left alone', ! isset( $by['theme_perf_settings'] ) && ! isset( $by['_cache_optimizer_v2'] ) && ! in_array( 'theme_perf_settings', $GLOBALS['deleted'], true ) );
// Decoded links alone (an encoded footer) are ordinary; links that read as gambling spam are not.
$GLOBALS['opts']    = [ 'quarantine_enabled' => '0' ];
$GLOBALS['options'] = [ 'theme_perf_settings' => base64_encode( '<p>Follow us: <a href="https://example.com/news">our news page</a> and <a href="https://example.com/contact">contact us</a>. ' . str_repeat( 'Thank you for visiting. ', 10 ) . '</p>' ) ];
$GLOBALS['deleted'] = [];
check( 'an encoded footer with ordinary links under a generic name is left alone', [] === run( 'check_casino_spam_options' ) && ! $GLOBALS['deleted'] );
$GLOBALS['options'] = [ 'theme_perf_settings' => base64_encode( '<div><a href="https://x.invalid/a">online casino no deposit bonus</a> <a href="https://x.invalid/b">Slot Gacor</a> ' . str_repeat( 'pad ', 40 ) . '</div>' ) ];
check( 'encoded links that read as gambling spam are found', 1 === count( run( 'check_casino_spam_options' ) ) );
// With quarantine on and the store unwritable, the option is kept.
$GLOBALS['opts']    = [ 'quarantine_enabled' => '1' ];
$GLOBALS['options'] = [ '_wp_seo_boost' => $blob ];
$GLOBALS['deleted'] = [];
file_put_contents( WP_CONTENT_DIR . '/wps-quarantine', 'not a folder' );
$f = run( 'check_casino_spam_options' );
check( 'when the quarantine copy cannot be made the option is not deleted and the finding says so', 1 === count( $f ) && empty( $f[0]['remediated'] ) && ! $GLOBALS['deleted'] && false !== strpos( $f[0]['action'], 'NOT removed' ), json_encode( [ $f[0]['action'] ?? '', $GLOBALS['deleted'] ] ) );
unlink( WP_CONTENT_DIR . '/wps-quarantine' );
$GLOBALS['options'] = [ '_wp_seo_boost' => $blob ];
$f = run( 'check_casino_spam_options' );
check( 'with a working quarantine the option is copied there and then deleted', 1 === count( $f ) && ! empty( $f[0]['remediated'] ) && in_array( '_wp_seo_boost', $GLOBALS['deleted'], true ) && is_dir( WP_CONTENT_DIR . '/wps-quarantine' ), json_encode( [ $f[0]['action'] ?? '', $GLOBALS['deleted'] ] ) );
$GLOBALS['opts'] = [ 'quarantine_enabled' => '0' ];
$GLOBALS['opts']    = [ 'quarantine_enabled' => '0', 'auto_delete_enabled' => '0' ];
$GLOBALS['options'] = [ '_wp_seo_boost' => $blob ];
$GLOBALS['deleted'] = [];
$f = run( 'check_casino_spam_options' );
check( 'with Auto-delete off the option is reported and kept', 1 === count( $f ) && empty( $f[0]['remediated'] ) && ! in_array( '_wp_seo_boost', $GLOBALS['deleted'], true ), json_encode( [ count( $f ), $f[0]['remediated'] ?? null, $GLOBALS['deleted'] ] ) );
$GLOBALS['opts']    = [ 'quarantine_enabled' => '0', 'auto_delete_enabled' => '0' ];
$GLOBALS['options'] = [ '_gg_link_cache' => 'QQ==' ];
$GLOBALS['crons']   = [ 12345 => [ 'gg_casino_reinstall' => [ 'x' => [ 'schedule' => 'hourly' ] ], 'my_plugin_nightly' => [ 'y' => [] ], 'my_gg_casino_stats' => [ 'z' => [] ] ] ];
$f = run( 'check_malicious_db_options' );
$s = implode( ' | ', array_map( static fn( $x ) => $x['subject'] . ':' . $x['type'], $f ) );
check( 'the payload option _gg_link_cache is a known-bad key', false !== strpos( $s, '_gg_link_cache' ), $s );
check( 'the gg_casino_reinstall cron hook is found; an ordinary hook and an unrelated hook with gg_casino in its name are not', false !== strpos( $s, 'gg_casino_reinstall' ) && false === strpos( $s, 'my_plugin_nightly' ) && false === strpos( $s, 'my_gg_casino_stats' ), $s );
$GLOBALS['options'] = [];
$GLOBALS['crons']   = [];
$GLOBALS['opts']    = [ 'quarantine_enabled' => '0' ];

// ---- spam wording and the removal policy
check( 'the Japanese no-deposit-bonus phrase and the English doorway phrases are spam markers', WPS_Spam_Signatures::evaluate( '<a href="https://x.invalid">オンラインカジノ入金不要ボーナス</a>' )['spam'] && WPS_Spam_Signatures::evaluate( 'best online casino no deposit bonus 2026' )['spam'] );
check( 'ordinary prose about casinos is still not spam', ! WPS_Spam_Signatures::evaluate( 'The council debated whether the new casino would change the town. Critics worry about gambling harm.' )['spam'] );
$fm = run( 'check_crawler_gated_eval' );
$fh = run( 'check_hidden_link_filter' );
$pm = array_values( array_filter( array_merge( $fm, $fh ), static fn( $x ) => ! empty( $x['auto_delete'] ) ) );
$ok = $pm ? true : false;
foreach ( $pm as $x ) {
	$ok = $ok && WPS_Remediation_Policy::decide( $x )['allowed'];
}
check( 'the removal policy allows every removable finding of the two file checks', $ok, json_encode( array_map( static fn( $x ) => WPS_Remediation_Policy::decide( $x )['rule'] ?? '', $pm ) ) );
$ro = array_values( array_filter( array_merge( $fm, $fh ), static fn( $x ) => empty( $x['auto_delete'] ) ) );
$ok = true;
foreach ( $ro as $x ) {
	$ok = $ok && ! WPS_Remediation_Policy::decide( $x )['allowed'];
}
check( 'and denies the report-only ones', $ro && $ok );
check( 'the scheduled scan reaches posts that carry only the Japanese marker or the free-spins phrase', in_array( 'オンラインカジノ', WPS_Spam_Signatures::like_prefilter_terms(), true ) && in_array( 'free spins', WPS_Spam_Signatures::like_prefilter_terms(), true ) );
check( 'the four checks are registered', 4 === preg_match_all( "/'check_(?:crawler_gated_eval|hidden_link_filter|htaccess_php_doorway|casino_spam_options)' => \\[ __CLASS__/", (string) file_get_contents( dirname( __DIR__ ) . '/includes/class-scanner.php' ) ) );

exec( 'rm -rf ' . escapeshellarg( $tmp ) );
echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
