<?php
/**
 * Documentation-sync test: the documents must agree with the code they describe.
 *
 * Run from the command line only:  php tests/test-docs-sync.php
 *
 * Checks version markers across the release files, that the current version has
 * a changelog, upgrade-notes and readme.txt entry, that every fingerprint the
 * code carries in includes/class-blocker.php is listed in doc/variants.md
 * Appendix F with matching counts, and that doc/ssot.md lists every document in
 * doc/.
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}

$root = dirname( __DIR__ );
$read = static fn( string $p ): string => (string) file_get_contents( $root . '/' . $p );
$fail = 0;
function check( string $name, bool $ok, string $detail = '' ): void {
	global $fail;
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $name . ( $ok ? '' : ' :: ' . $detail ) . "\n";
	if ( ! $ok ) {
		++$fail;
	}
}

// 1. Version markers.
$main = $read( 'wp-perf-shield.php' );
preg_match( '/^\s*\*\s*Version:\s*([0-9.]+)/m', $main, $m1 );
preg_match( "/define\\(\\s*'WPS_VERSION',\\s*'([0-9.]+)'/", $main, $m2 );
preg_match( '/^Stable tag:\s*([0-9.]+)/m', $read( 'readme.txt' ), $m3 );
preg_match( '/Current plugin version:\s*`([0-9.]+)`/', $read( 'doc/readme.md' ), $m4 );
$v = $m1[1] ?? '';
check( 'plugin header, WPS_VERSION, readme.txt and doc/readme.md agree', '' !== $v && $v === ( $m2[1] ?? '' ) && $v === ( $m3[1] ?? '' ) && $v === ( $m4[1] ?? '' ), json_encode( [ $m1[1] ?? null, $m2[1] ?? null, $m3[1] ?? null, $m4[1] ?? null ] ) );

// 2. The current version is documented.
check( 'doc/changelog.md has an entry for ' . $v, 1 === preg_match( '/^## ' . preg_quote( $v, '/' ) . '\s*$/m', $read( 'doc/changelog.md' ) ) );
check( 'doc/upgrading.md has an entry for ' . $v, 1 === preg_match( '/^## ' . preg_quote( $v, '/' ) . '\s*$/m', $read( 'doc/upgrading.md' ) ) );
$rt  = $read( 'readme.txt' );
$chg = substr( $rt, (int) strpos( $rt, '== Changelog ==' ) );
check( 'readme.txt changelog has an entry for ' . $v, 1 === preg_match( '/^= ' . preg_quote( $v, '/' ) . ' =\s*$/m', $chg ) );

// 3. Appendix F against the code.
$blocker = $read( 'includes/class-blocker.php' );
preg_match_all( "/'([0-9a-f]{32}|[0-9a-f]{64})',\\s*\\/\\//", $blocker, $hm );
$code = array_unique( $hm[1] );
$vars = $read( 'doc/variants.md' );
$app  = (string) substr( $vars, (int) strpos( $vars, '## Appendix F' ) );
$app  = (string) substr( $app, 0, (int) strpos( $app, '## Appendix G' ) ?: strlen( $app ) );
preg_match_all( '/`([0-9a-f]{32}|[0-9a-f]{64})`/', $app, $dm );
$doc     = array_unique( $dm[1] );
$missing = array_values( array_diff( $code, $doc ) );
check( 'every fingerprint in includes/class-blocker.php is listed in Appendix F', [] === $missing, count( $missing ) . ' missing, first: ' . ( $missing[0] ?? '' ) );
$nm = count( array_filter( $code, static fn( $h ) => 32 === strlen( $h ) ) );
$ns = count( array_filter( $code, static fn( $h ) => 64 === strlen( $h ) ) );
check( 'Appendix F states the real counts (' . $nm . ' MD5, ' . $ns . ' SHA-256)', false !== strpos( $app, $nm . ' MD5 and ' . $ns . ' SHA-256 entries' ) );
check( 'Appendix F values are all well-formed', 0 === preg_match( '/`[0-9a-fA-F]{33,63}`/', $app ) );

// 4. The SSOT lists every document in doc/.
$ssot = $read( 'doc/ssot.md' );
$unl  = [];
foreach ( glob( $root . '/doc/*.md' ) as $f ) {
	if ( false === strpos( $ssot, 'doc/' . basename( $f ) ) ) {
		$unl[] = basename( $f );
	}
}
check( 'doc/ssot.md names every document in doc/', [] === $unl, implode( ',', $unl ) );

// 5. 1.4.152: wps_uninstall() deletes every option the code writes. The review found fifteen it
// missed, among them the Safe list and the circuit breaker, which kept automatic removal halted
// across a reinstall.
$written = [];
foreach ( array_merge( glob( $root . '/includes/*.php' ), [ $root . '/wp-perf-shield.php' ] ) as $f ) {
	$src = (string) file_get_contents( $f );
	preg_match_all( "/(?:update_option|add_option)\\(\\s*'(wps_[a-z0-9_]+)'/", $src, $lm );
	preg_match_all( "/const\\s+[A-Z_]*OPTION[A-Z_]*\\s*=\\s*'(wps_[a-z0-9_]+)'/", $src, $cm );
	$written = array_merge( $written, $lm[1], $cm[1] );
}
$written = array_unique( $written );
preg_match( '/function wps_uninstall\\(\\): void \\{(.*?)\\n\\}/s', $main, $um );
$un      = (string) ( $um[1] ?? '' );
$left    = array_values( array_filter( $written, static fn( string $o ): bool => false === strpos( $un, "'" . $o . "'" ) ) );
check( 'wps_uninstall() deletes every option the plugin writes (' . count( $written ) . ' found)', '' !== $un && [] === $left, implode( ',', $left ) );
check( 'wps_uninstall() deletes the settings option named by the WPS_OPTION constant', false !== strpos( $un, 'delete_option( WPS_OPTION )' ) );
check( 'wps_uninstall() drops the event table and the self-test scratch tables, and no wider', false !== strpos( $un, 'DROP TABLE' ) && false !== strpos( $un, "'wps_events_st_'" ) && false === strpos( $un, "'wps_events' ) . '%'" ) );

echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
