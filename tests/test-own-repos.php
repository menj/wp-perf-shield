<?php
/**
 * Regression test for the operator's own repositories as a verification source (1.4.158).
 *
 * Run from the command line only:  php tests/test-own-repos.php
 *
 * A plugin or theme whose folder is a repository under a declared GitHub account is verified
 * file by file against the repository's tree, by git blob id. Identical files are the operator's
 * own work and findings against them are not reported; a changed or added file keeps its findings.
 * GitHub is replaced by a stand-in that serves a tree listing and records what it was asked.
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}
$tmp = sys_get_temp_dir() . '/wps-own-' . bin2hex( random_bytes( 4 ) );
foreach ( [ '/wp-content/plugins/wps-self', '/wp-content/plugins/citepress/includes', '/wp-content/plugins/other', '/wp-content/themes/book-wp/inc', '/wp-content/mu-plugins' ] as $d ) {
	mkdir( $tmp . $d, 0777, true );
}
define( 'ABSPATH', $tmp . '/' );
define( 'WPS_DIR', $tmp . '/wp-content/plugins/wps-self/' );
define( 'WPS_OPTION', 'wps_opts' );
define( 'WP_CONTENT_DIR', $tmp . '/wp-content' );
define( 'WP_PLUGIN_DIR', $tmp . '/wp-content/plugins' );
define( 'WPMU_PLUGIN_DIR', $tmp . '/wp-content/mu-plugins' );

$GLOBALS['opts']  = [ 'own_repo_owners' => 'menj' ];
$GLOBALS['trans'] = [];
$GLOBALS['http']  = [];
$GLOBALS['trees'] = [];
$GLOBALS['events'] = [];
function get_option( $k, $d = false ) { return 'wps_opts' === $k ? $GLOBALS['opts'] : $d; }
function get_transient( $k ) { return $GLOBALS['trans'][ $k ] ?? false; }
function set_transient( $k, $v, $t = 0 ) { $GLOBALS['trans'][ $k ] = $v; return true; }
function get_theme_root() { return WP_CONTENT_DIR . '/themes'; }
function is_wp_error( $x ) { return $x instanceof WP_Error; }
function wp_remote_retrieve_response_code( $r ) { return $r['response']['code']; }
function wp_remote_retrieve_body( $r ) { return $r['body']; }
function wp_remote_get( $url, $args = [] ) {
	$GLOBALS['http'][] = [ $url, $args ];
	foreach ( $GLOBALS['trees'] as $needle => $answer ) {
		if ( false !== strpos( $url, $needle ) ) {
			return $answer instanceof WP_Error ? $answer : [ 'response' => [ 'code' => $answer[0] ], 'body' => $answer[1] ];
		}
	}
	return [ 'response' => [ 'code' => 404 ], 'body' => '{"message":"Not Found"}' ];
}
class WP_Error { public $code; public $message; public function __construct( $c = "", $m = "" ) { $this->code = $c; $this->message = $m; } }
class WPS_Logger { public static function log_event( $t, $s, $ip = '' ) { $GLOBALS['events'][] = [ $t, $s ]; } }
require dirname( __DIR__ ) . '/includes/class-own-repos.php';
require dirname( __DIR__ ) . '/includes/class-integrity.php';

$fail = 0;
function check( string $name, bool $ok, string $detail = '' ): void {
	global $fail;
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $name . ( $ok ? '' : ' :: ' . $detail ) . "\n";
	if ( ! $ok ) {
		++$fail;
	}
}
function blob( string $content ): string { return sha1( 'blob ' . strlen( $content ) . "\0" . $content ); }
function tree( array $files ): string {
	$t = [];
	foreach ( $files as $path => $content ) {
		$t[] = [ 'path' => $path, 'mode' => '100644', 'type' => 'blob', 'sha' => blob( $content ), 'size' => strlen( $content ) ];
	}
	$t[] = [ 'path' => 'includes', 'mode' => '040000', 'type' => 'tree', 'sha' => str_repeat( 'a', 40 ) ];
	return json_encode( [ 'sha' => str_repeat( 'b', 40 ), 'truncated' => false, 'tree' => $t ] );
}
function fresh(): void { WPS_Integrity::reset(); $GLOBALS['http'] = []; }

// ---- 1. settings
check( 'owners are parsed from names, URLs and separators', [ 'menj', 'Other-Org' ] === WPS_Own_Repos::parse_owners( "menj\nhttps://github.com/Other-Org/\nmenj, bad_name!" ) );
check( 'nothing declared, nothing done', [] === WPS_Own_Repos::parse_owners( '' ) );

// ---- 2. the git blob id
$content = "<?php\n/* Plugin Name: CitePress */\necho 'hi';\n";
file_put_contents( $tmp . '/wp-content/plugins/citepress/citepress.php', $content );
check( 'the blob id is what git would compute', blob( $content ) === WPS_Own_Repos::git_blob_sha( $tmp . '/wp-content/plugins/citepress/citepress.php' ) );
file_put_contents( $tmp . '/wp-content/plugins/citepress/crlf.php', str_replace( "\n", "\r\n", $content ) );
check( 'a Windows checkout with CRLF still matches the LF blob', WPS_Own_Repos::blob_matches( $tmp . '/wp-content/plugins/citepress/crlf.php', [ blob( $content ) ] ) );
check( 'other content does not', ! WPS_Own_Repos::blob_matches( $tmp . '/wp-content/plugins/citepress/citepress.php', [ blob( 'x' ) ] ) );

// ---- 3. verification against the repository tree
$inc = "<?php\nclass CP_Citations {}\n";
file_put_contents( $tmp . '/wp-content/plugins/citepress/includes/class-citations.php', $inc );
file_put_contents( $tmp . '/wp-content/plugins/citepress/includes/planted.php', "<?php\neval(\$_POST['x']);\n" );
file_put_contents( $tmp . '/wp-content/plugins/citepress/includes/edited.php', "<?php\n// edited on the server\n" );
$GLOBALS['trees']['api.github.com/repos/menj/citepress/git/trees/HEAD?recursive=1'] = [ 200, tree( [ 'citepress.php' => $content, 'crlf.php' => $content, 'includes/class-citations.php' => $inc, 'includes/edited.php' => "<?php\n// as published\n", 'readme.txt' => "=== CitePress ===\n" ] ) ];
fresh();
check( 'a file identical to the repository is VERIFIED', WPS_Integrity::VERIFIED === WPS_Integrity::verify( $tmp . '/wp-content/plugins/citepress/citepress.php' ) );
check( 'one request for the tree, with the GitHub media type and no token', 1 === count( $GLOBALS['http'] ) && 'application/vnd.github+json' === $GLOBALS['http'][0][1]['headers']['Accept'] && ! isset( $GLOBALS['http'][0][1]['headers']['Authorization'] ), json_encode( $GLOBALS['http'] ) );
check( 'a nested file is VERIFIED by its repository path', WPS_Integrity::VERIFIED === WPS_Integrity::verify( $tmp . '/wp-content/plugins/citepress/includes/class-citations.php' ) );
check( 'a file the repository does not know is FOREIGN', WPS_Integrity::FOREIGN === WPS_Integrity::verify( $tmp . '/wp-content/plugins/citepress/includes/planted.php' ) );
check( 'a file that differs from the repository is MODIFIED', WPS_Integrity::MODIFIED === WPS_Integrity::verify( $tmp . '/wp-content/plugins/citepress/includes/edited.php' ) );
check( 'the tree was fetched once for all of those', 1 === count( $GLOBALS['http'] ), (string) count( $GLOBALS['http'] ) );
check( 'the tree is cached as a transient', isset( $GLOBALS['trans'][ 'wps_gh_' . md5( 'menj/citepress' ) ] ) );
file_put_contents( $tmp . '/wp-content/plugins/other/other.php', "<?php\n" );
fresh();
check( 'a folder with no repository under the account is UNKNOWN, and the miss is remembered', WPS_Integrity::UNKNOWN === WPS_Integrity::verify( $tmp . '/wp-content/plugins/other/other.php' ) && 'none' === ( $GLOBALS['trans'][ 'wps_gh_' . md5( 'menj/other' ) ] ?? null ) );

// ---- 4. themes, which wordpress.org never verifies
$style = "/*\nTheme Name: Book WP\n*/\n";
$fn    = "<?php\nadd_action( 'init', 'book_wp_setup' );\n";
file_put_contents( $tmp . '/wp-content/themes/book-wp/style.css', $style );
file_put_contents( $tmp . '/wp-content/themes/book-wp/functions.php', $fn );
file_put_contents( $tmp . '/wp-content/themes/book-wp/inc/helpers.php', "<?php\nfunction book_wp_setup() {}\n" );
$GLOBALS['trees']['api.github.com/repos/menj/book-wp/git/trees/HEAD?recursive=1'] = [ 200, tree( [ 'style.css' => $style, 'functions.php' => $fn, 'inc/helpers.php' => "<?php\nfunction book_wp_setup() {}\n" ] ) ];
fresh();
check( 'a theme file identical to its repository is VERIFIED', WPS_Integrity::VERIFIED === WPS_Integrity::verify( $tmp . '/wp-content/themes/book-wp/functions.php' ) );
check( 'the theme folder is the operator\'s own code', WPS_Own_Repos::is_own_code( $tmp . '/wp-content/themes/book-wp' ) );
check( 'a plugin folder holding a planted file is not', ! WPS_Own_Repos::is_own_code( $tmp . '/wp-content/plugins/citepress' ) );
check( 'a verified file inside it is', WPS_Own_Repos::is_own_code( $tmp . '/wp-content/plugins/citepress/citepress.php' ) );
check( 'the planted file is not', ! WPS_Own_Repos::is_own_code( $tmp . '/wp-content/plugins/citepress/includes/planted.php' ) );

// ---- 5. findings against own code are dropped; the rest stay
$findings = [
	[ 'severity' => 'high', 'type' => 'Theme hooks into init suspiciously', 'subject' => 'book-wp', 'path' => $tmp . '/wp-content/themes/book-wp/functions.php' ],
	[ 'severity' => 'critical', 'type' => 'Web shell', 'subject' => 'planted', 'path' => $tmp . '/wp-content/plugins/citepress/includes/planted.php' ],
	[ 'severity' => 'high', 'type' => 'Edited in place', 'subject' => 'edited', 'path' => $tmp . '/wp-content/plugins/citepress/includes/edited.php' ],
	[ 'severity' => 'medium', 'type' => 'Hidden folder', 'subject' => 'theme', 'path' => '', 'delete_path' => $tmp . '/wp-content/themes/book-wp' ],
	[ 'severity' => 'low', 'type' => 'No path at all', 'subject' => 'x', 'path' => '' ],
];
fresh();
$kept = WPS_Own_Repos::filter_findings( $findings );
check( 'the two findings against verified own code are dropped', 3 === count( $kept ) && 'Web shell' === $kept[0]['type'] && 'Edited in place' === $kept[1]['type'] && 'No path at all' === $kept[2]['type'], json_encode( array_column( $kept, 'type' ) ) );
check( 'the log says what was not reported and why', 1 === count( $GLOBALS['events'] ) && 'own_code_verified' === $GLOBALS['events'][0][0] && false !== strpos( $GLOBALS['events'][0][1], '2 findings against theme book-wp' ) && false !== strpos( $GLOBALS['events'][0][1], 'github.com/menj/book-wp' ), json_encode( $GLOBALS['events'] ) );
check( 'installed folders with a repository are listed', [ 'citepress', 'book-wp' ] === WPS_Own_Repos::verified_slugs() );

// ---- 6. no account declared: nothing is fetched, nothing is dropped
$GLOBALS['opts'] = [];
fresh();
$GLOBALS['trans'] = [];
check( 'with no account declared the filter is a no-op and GitHub is never asked', $findings === WPS_Own_Repos::filter_findings( $findings ) && [] === $GLOBALS['http'] );
check( 'and a plugin file is UNKNOWN as before', WPS_Integrity::UNKNOWN === WPS_Integrity::verify( $tmp . '/wp-content/plugins/citepress/citepress.php' ) && [] === $GLOBALS['http'] );

// ---- 7. a token, a truncated tree, a transport failure
$GLOBALS['opts'] = [ 'own_repo_owners' => 'menj', 'own_repo_token' => 'github_pat_abc' ];
$GLOBALS['trees']['api.github.com/repos/menj/citepress/git/trees/HEAD?recursive=1'] = [ 200, json_encode( [ 'truncated' => true, 'tree' => [] ] ) ];
fresh();
check( 'a truncated tree is no basis for a verdict', WPS_Integrity::UNKNOWN === WPS_Integrity::verify( $tmp . '/wp-content/plugins/citepress/citepress.php' ) && 'Bearer github_pat_abc' === $GLOBALS['http'][0][1]['headers']['Authorization'], json_encode( $GLOBALS['http'] ) );
check( 'and is remembered as unusable, so it is not fetched again for six hours', 'none' === ( $GLOBALS['trans'][ 'wps_gh_' . md5( 'menj/citepress' ) ] ?? null ) );
$GLOBALS['trees']['api.github.com/repos/menj/citepress/git/trees/HEAD?recursive=1'] = new WP_Error( 'http_request_failed', 'timeout' );
fresh();
unset( $GLOBALS['trans'][ 'wps_gh_' . md5( 'menj/citepress' ) ] );
check( 'a transport failure is UNKNOWN and not remembered between scans', WPS_Integrity::UNKNOWN === WPS_Integrity::verify( $tmp . '/wp-content/plugins/citepress/citepress.php' ) && ! isset( $GLOBALS['trans'][ 'wps_gh_' . md5( 'menj/citepress' ) ] ) );
WPS_Integrity::verify( $tmp . '/wp-content/plugins/citepress/includes/class-citations.php' );
check( 'but within one scan the repository is asked once, not once per file', 1 === count( $GLOBALS['http'] ), (string) count( $GLOBALS['http'] ) );
$GLOBALS['trees']['api.github.com/repos/menj/citepress/git/trees/HEAD?recursive=1'] = [ 403, '{"message":"API rate limit exceeded"}' ];
fresh();
unset( $GLOBALS['trans'][ 'wps_gh_' . md5( 'menj/citepress' ) ] );
WPS_Integrity::verify( $tmp . '/wp-content/plugins/citepress/citepress.php' );
fresh();
WPS_Integrity::verify( $tmp . '/wp-content/themes/book-wp/functions.php' );
check( 'a rate-limit refusal stops every request for an hour', isset( $GLOBALS['trans']['wps_gh_backoff'] ) && [] === $GLOBALS['http'], json_encode( $GLOBALS['http'] ) );
unset( $GLOBALS['trans']['wps_gh_backoff'] );
$GLOBALS['opts'] = [ 'own_repo_owners' => 'menj' ];
unset( $GLOBALS['trees']['api.github.com/repos/menj/citepress/git/trees/HEAD?recursive=1'] );
foreach ( range( 1, 30 ) as $i ) {
	mkdir( $tmp . '/wp-content/plugins/pkg' . $i );
}
fresh();
unset( $GLOBALS['trans'][ 'wps_gh_' . md5( 'menj/citepress' ) ] );
WPS_Own_Repos::verified_slugs();
check( 'one process never makes more than ' . WPS_Own_Repos::MAX_REQUESTS . ' requests', WPS_Own_Repos::MAX_REQUESTS === count( $GLOBALS['http'] ), (string) count( $GLOBALS['http'] ) );
check( 'tree_to_manifest ignores tree entries and bad hashes', [ 'a.php' => [ 'type' => 'gitblob', 'hashes' => [ str_repeat( 'c', 40 ) ] ] ] === WPS_Own_Repos::tree_to_manifest( [ 'tree' => [ [ 'path' => 'a.php', 'type' => 'blob', 'sha' => str_repeat( 'C', 40 ) ], [ 'path' => 'dir', 'type' => 'tree', 'sha' => str_repeat( 'd', 40 ) ], [ 'path' => 'b.php', 'type' => 'blob', 'sha' => 'short' ] ] ] ) && null === WPS_Own_Repos::tree_to_manifest( 'nope' ) );

exec( 'rm -rf ' . escapeshellarg( $tmp ) );
echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
