<?php
/**
 * Regression test for the spam-content guard and spam signatures (1.4.153).
 *
 * Run from the command line only:  php tests/test-spam-content-guard.php
 *
 * Covers the four review findings: content still matching after the save-boundary strip is held
 * as pending instead of logged as cleaned; the daily sweep walks the whole site with a cursor
 * instead of re-reading the newest batch; every diagnostic term is reachable through the SQL
 * prefilter; and a long post is judged by its tail as well as its head.
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}
define( 'ABSPATH', '/x/' );
define( 'WPS_OPTION', 'wps_opts' );
define( 'HOUR_IN_SECONDS', 3600 );

$GLOBALS['opts']    = [ 'wps_opts' => [ 'spam_content_guard_enabled' => '1' ] ];
$GLOBALS['posts']   = [];
$GLOBALS['trashed'] = [];
$GLOBALS['filters'] = [];
function get_option( $k, $d = false ) { return $GLOBALS['opts'][ $k ] ?? $d; }
function update_option( $k, $v, $a = null ) { $GLOBALS['opts'][ $k ] = $v; return true; }
function apply_filters( $t, $v ) { return $v; }
function add_action() {}
function add_filter( $h, $cb, $p = 10, $a = 1 ) { $GLOBALS['filters'][ $h ] = $cb; }
function remove_filter( $h, $cb, $p = 10 ) { unset( $GLOBALS['filters'][ $h ] ); }
function sanitize_key( $s ) { return preg_replace( '/[^a-z0-9_-]/', '', strtolower( (string) $s ) ); }
function __( $s, $d = '' ) { return $s; }
function absint( $n ) { return abs( (int) $n ); }
function get_post( $id ) { return $GLOBALS['posts'][ $id ] ?? null; }
function wp_trash_post( $id ) { $GLOBALS['trashed'][] = $id; $GLOBALS['posts'][ $id ]->post_status = 'trash'; return true; }
/** A stand-in for get_posts() that honours the sweep's cursor argument the way the posts_where filter does in WordPress. */
function get_posts( $args ) {
	$ids = array_keys( $GLOBALS['posts'] );
	rsort( $ids );
	if ( ! empty( $args['wps_id_below'] ) ) {
		$ids = array_values( array_filter( $ids, static fn( $i ) => $i < (int) $args['wps_id_below'] ) );
	}
	$GLOBALS['sweep_calls'][] = [ 'below' => (int) ( $args['wps_id_below'] ?? 0 ), 'filter_hooked' => isset( $GLOBALS['filters']['posts_where'] ) ];
	return array_slice( $ids, 0, (int) $args['posts_per_page'] );
}
class WPS_EDR {
	public static $events = [];
	public static function record( $t, $c = [] ) { self::$events[] = [ $t, (string) ( $c['notes'] ?? '' ) ]; return true; }
}

require dirname( __DIR__ ) . '/includes/class-spam-content-guard.php';
require dirname( __DIR__ ) . '/includes/class-spam-signatures.php';

$fail = 0;
function check( string $name, bool $ok, string $detail = '' ): void {
	global $fail;
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $name . ( $ok ? '' : ' :: ' . $detail ) . "\n";
	if ( ! $ok ) {
		++$fail;
	}
}
function events( string $type ): int {
	return count( array_filter( WPS_EDR::$events, static fn( $e ) => $type === $e[0] ) );
}

// ---- 1. the save boundary: English link spam is stripped and published; prose the strip cannot cut is held.
$data = WPS_Spam_Content_Guard::scan_save_boundary( [
	'post_type'    => 'post',
	'post_status'  => 'publish',
	'post_title'   => 'Holiday notes',
	'post_content' => '<p>Our trip.</p><a href="https://example.test/best-casino-bonus">play now</a><p>More notes.</p>',
	'post_excerpt' => '',
], [ 'ID' => 5 ] );
check( 'an English gambling link is stripped and the post stays published', 'publish' === $data['post_status'] && false === strpos( $data['post_content'], 'casino' ) && 1 === events( 'spam_content_stripped' ) && 0 === events( 'spam_content_held' ), json_encode( $data ) );

WPS_EDR::$events = [];
$data = WPS_Spam_Content_Guard::scan_save_boundary( [
	'post_type'    => 'post',
	'post_status'  => 'publish',
	'post_title'   => 'Come scegliere i migliori siti non AAMS',
	'post_content' => '<p>I siti non AAMS offrono bonus senza registrazione per giocatori italiani.</p>',
	'post_excerpt' => '',
], [ 'ID' => 6 ] );
check( 'a regulatory-evasion post the strip cannot clean is held as pending, not published', 'pending' === $data['post_status'] && 1 === events( 'spam_content_held' ), json_encode( [ $data['post_status'], WPS_EDR::$events ] ) );
check( 'the held event names the rule', false !== strpos( WPS_EDR::$events[1][1] ?? '', 'gambling-regulatory-evasion' ), json_encode( WPS_EDR::$events ) );
$data = WPS_Spam_Content_Guard::scan_save_boundary( [
	'post_type'    => 'post',
	'post_status'  => 'draft',
	'post_title'   => 'Come scegliere i migliori siti non AAMS',
	'post_content' => '<p>I siti non AAMS offrono bonus.</p>',
	'post_excerpt' => '',
], [ 'ID' => 7 ] );
check( 'a draft is left a draft', 'draft' === $data['post_status'] );
$data = WPS_Spam_Content_Guard::scan_save_boundary( [ 'post_type' => 'post', 'post_status' => 'publish', 'post_title' => 'Garden', 'post_content' => '<p>Tomatoes this year.</p>', 'post_excerpt' => '' ], [ 'ID' => 8 ] );
check( 'clean content is untouched', 'publish' === $data['post_status'] && 'Garden' === $data['post_title'] );

// ---- 2. the sweep walks the whole site: 450 posts, batches of 200, spam at ID 10.
for ( $i = 1; $i <= 450; $i++ ) {
	$GLOBALS['posts'][ $i ] = (object) [ 'ID' => $i, 'post_status' => 'publish', 'post_title' => 'Post ' . $i, 'post_content' => '<p>ordinary</p>', 'post_excerpt' => '' ];
}
$GLOBALS['posts'][10]->post_content = '<a href="https://example.test/casino">bonus</a>';
$GLOBALS['sweep_calls'] = [];
$n1 = WPS_Spam_Content_Guard::sweep_existing( 200 );
check( 'the first run reads the newest batch and records where it stopped', 0 === $n1 && 251 === (int) get_option( 'wps_spam_sweep_cursor' ), json_encode( [ $n1, get_option( 'wps_spam_sweep_cursor' ), $GLOBALS['sweep_calls'] ] ) );
$n2 = WPS_Spam_Content_Guard::sweep_existing( 200 );
check( 'the second run continues below the cursor with the WHERE filter hooked', 0 === $n2 && 51 === (int) get_option( 'wps_spam_sweep_cursor' ) && 251 === $GLOBALS['sweep_calls'][1]['below'] && $GLOBALS['sweep_calls'][1]['filter_hooked'], json_encode( $GLOBALS['sweep_calls'] ) );
check( 'the WHERE filter is unhooked after the query', ! isset( $GLOBALS['filters']['posts_where'] ) );
$n3 = WPS_Spam_Content_Guard::sweep_existing( 200 );
check( 'the third run reaches the oldest posts and quarantines the spam at ID 10', 1 === $n3 && [ 10 ] === $GLOBALS['trashed'], json_encode( [ $n3, $GLOBALS['trashed'] ] ) );
check( 'a short last batch resets the cursor so the next run starts from the newest again', 0 === (int) get_option( 'wps_spam_sweep_cursor' ) );

// ---- 3. the SQL prefilter can reach every diagnostic term.
$pre = WPS_Spam_Signatures::like_prefilter_terms();
$unreachable = [];
foreach ( WPS_Spam_Signatures::diagnostic_terms() as $term ) {
	$hit = false;
	foreach ( $pre as $p ) {
		if ( false !== strpos( $term, $p ) ) { $hit = true; break; }
	}
	if ( ! $hit ) { $unreachable[] = $term; }
}
check( 'every diagnostic term is a substring of some prefilter term (pragmatic play was not)', [] === $unreachable, implode( ',', $unreachable ) );
check( 'the prefilter list carries no duplicates', count( $pre ) === count( array_unique( $pre ) ) );

// ---- 4. a long post is judged by its tail too.
$long = str_repeat( "A perfectly ordinary sentence about gardening and weather.\n", 5000 ) . "\n<p>situs slot gacor maxwin hari ini</p>";
check( 'the fixture is longer than the matcher\'s ceiling', strlen( $long ) > 200000 );
$eval = WPS_Spam_Signatures::evaluate( $long );
check( 'a spam marker after the first 200,000 bytes is still found', ! empty( $eval['spam'] ), json_encode( $eval ) );
$eval = WPS_Spam_Signatures::evaluate( "slot gacor\n" . str_repeat( "benign text here.\n", 20000 ) );
check( 'and one at the head still is', ! empty( $eval['spam'] ) );

echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
