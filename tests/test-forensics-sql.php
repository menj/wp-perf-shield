<?php
/**
 * Regression test for the Forensics media-upload trace query,
 * WPS_Forensics::trace_media_uploads().
 *
 * Run from the command line only:  php tests/test-forensics-sql.php
 *
 * The query is built from a pattern list; this checks that the number of
 * placeholders always equals the number of arguments, and that the `.zip`
 * patterns still reach the title and guid clauses. (Until 1.4.130 the
 * placeholders were hard-coded, and slugs added to the list shifted every
 * argument: the guid clause received a slug pattern and the `.zip` patterns
 * were dropped.)
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}
define( 'ABSPATH', '/x/' );
define( 'WPS_DIR', sys_get_temp_dir() . '/wps-fs-none/' );
define( 'ARRAY_A', 'ARRAY_A' );

$GLOBALS['captured'] = null;
class WPS_Stub_Wpdb {
	public $posts = 'wp_posts';
	public function prepare( $sql, ...$args ) {
		if ( null === $GLOBALS["captured"] ) {
			$GLOBALS["captured"] = [ $sql, $args ]; // the first query is the one under test
		}
		return 'PREPARED';
	}
	public function get_results( $q, $out = null ) { return []; }
}
$wpdb = new WPS_Stub_Wpdb();
$GLOBALS['wpdb'] = $wpdb;
function get_post_meta() { return ''; }

require dirname( __DIR__ ) . '/includes/class-forensics.php';

$fail = 0;
function check( string $name, bool $ok, string $detail = '' ): void {
	global $fail;
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $name . ( $ok ? '' : ' :: ' . $detail ) . "\n";
	if ( ! $ok ) {
		++$fail;
	}
}

$m = new ReflectionMethod( 'WPS_Forensics', 'trace_media_uploads' );
$m->setAccessible( true );
$m->invoke( null );
[ $sql, $args ] = $GLOBALS['captured'] ?? [ '', [] ];
$slots = substr_count( $sql, '%s' );
check( 'the query was prepared', '' !== $sql );
check( 'placeholders equal arguments (' . $slots . ' / ' . count( $args ) . ')', $slots === count( $args ) && $slots > 0, $slots . ' vs ' . count( $args ) );
check( 'the last two arguments are the .zip patterns, for title and guid', array_slice( $args, -2 ) === [ '%.zip%', '%.zip%' ] );
check( 'the guid clause is the last clause', false !== strpos( $sql, 'OR guid LIKE %s' ) && strrpos( $sql, 'guid LIKE %s' ) > strrpos( $sql, 'post_title LIKE %s' ) );
check( 'a recently added family name is among the title patterns', in_array( '%ultra-render-helper%', $args, true ) && in_array( '%auto-speed-insights%', $args, true ) );

echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
