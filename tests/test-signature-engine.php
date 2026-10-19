<?php
/**
 * Regression test for the ClamAV-format signature engine.
 *
 * Run from the command line only:  php tests/test-signature-engine.php
 *
 * Builds small databases from text in a temporary folder (no real malware is
 * stored in the repository) and runs the real WPS_Signature_Engine against
 * synthetic strings and files.
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}

define( 'ABSPATH', '/x/' );
require dirname( __DIR__ ) . '/includes/class-signature-engine.php';

$fail = 0;
function check( string $name, bool $ok, string $detail = '' ): void {
	global $fail;
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $name . ( $ok ? '' : ' :: ' . $detail ) . "\n";
	if ( ! $ok ) {
		++$fail;
	}
}

$tmp = sys_get_temp_dir() . '/wps-sig-' . bin2hex( random_bytes( 4 ) );
mkdir( $tmp, 0777, true );
function hx( string $s ): string {
	return bin2hex( $s );
}
/** Build a database from [ext => lines] and return the loaded engine state. */
function db( array $files ): array {
	global $tmp;
	static $n = 0;
	$dir = $tmp . '/db' . ( ++$n );
	mkdir( $dir, 0777, true );
	foreach ( $files as $name => $lines ) {
		file_put_contents( $dir . '/' . $name, implode( "\n", (array) $lines ) . "\n" );
	}
	return WPS_Signature_Engine::load( $dir );
}
/** Name of the signature that matches a string, or '' for none. */
function hit( array $db, string $data ): string {
	$r = WPS_Signature_Engine::scan_data( $db, $data );
	return $r ? $r['name'] : '';
}

// ---- hash signatures
$body  = "<?php eval(\$_POST['x']); // sample body\n";
$md5   = md5( $body );
$sha1  = sha1( $body );
$sha   = hash( 'sha256', $body );
$size  = strlen( $body );
file_put_contents( $tmp . '/sample.php', $body );
$d = db( [ 'a.hdb' => [ "$md5:$size:Php.Test.Md5", "# comment", "", "$md5:" . ( $size + 1 ) . ':Php.Test.WrongSize' ], 'b.hsb' => [ "$sha:$size:Php.Test.Sha256", "$sha1:*:Php.Test.Sha1Any" ] ] );
$r = WPS_Signature_Engine::scan_file( $d, $tmp . '/sample.php' );
check( 'an MD5 hash with the right size matches', $r && 'hash' === $r['kind'] );
check( 'hash counts are right', 4 === $d['counts']['hash'], json_encode( $d['counts'] ) );
$d = db( [ 'a.hdb' => [ "$md5:" . ( $size + 1 ) . ':Php.Test.WrongSize' ] ] );
check( 'a hash with the wrong size does not match', null === WPS_Signature_Engine::scan_file( $d, $tmp . '/sample.php' ) );
$d = db( [ 'b.hsb' => [ "$sha:$size:Php.Test.Sha256" ] ] );
check( 'a SHA-256 hash matches', 'Php.Test.Sha256' === ( WPS_Signature_Engine::scan_file( $d, $tmp . '/sample.php' )['name'] ?? '' ) );
$d = db( [ 'b.hsb' => [ "$sha1:*:Php.Test.Sha1Any" ] ] );
check( 'a SHA-1 hash with size * matches', 'Php.Test.Sha1Any' === ( WPS_Signature_Engine::scan_file( $d, $tmp . '/sample.php' )['name'] ?? '' ) );
$d = db( [ 'a.hdb' => [ "$md5:$size:Php.Test.Md5" ], 'z.fp' => [ "$md5:$size:Known.Good" ] ] );
check( 'a file listed in a .fp exception is never reported', null === WPS_Signature_Engine::scan_file( $d, $tmp . '/sample.php' ) );
$d = db( [ 'a.hdb' => [ "$md5:$size:Php.Test.Md5" ], 'a.ign2' => [ 'Php.Test.Md5' ] ] );
check( 'a signature named in an .ign2 file is dropped', null === WPS_Signature_Engine::scan_file( $d, $tmp . '/sample.php' ) );
$d = db( [ 'a.hdb' => [ "$sha:$size:Php.Test.NotMd5" ] ] );
check( 'a SHA-256 hash in an .hdb file is rejected (MD5 only there)', 1 === $d['counts']['rejected'] );
$d = db( [ 'a.hdb' => [ 'zz:1:Bad', "$md5:abc:Bad2", "$md5:$size:bad name!" ] ] );
check( 'malformed hash lines are rejected, not loaded', 3 === $d['counts']['rejected'] && 0 === $d['counts']['hash'], json_encode( $d['errors'] ) );

// ---- extended body signatures
$sig = static function ( string $hex, string $target = '0', string $off = '*' ) {
	return "Php.T.X:$target:$off:$hex";
};
$d = db( [ 'a.ndb' => [ $sig( hx( 'eval(base64_decode(' ) ) ] ] );
check( 'a plain hex body signature matches', 'Php.T.X' === hit( $d, 'x eval(base64_decode($a)) y' ) );
check( 'and does not match something else', '' === hit( $d, 'eval(base64_encode($a))' ) );
$d = db( [ 'a.ndb' => [ $sig( hx( 'eval(' ) . '??' . hx( 'ase64_decode' ) ) ] ] );
check( '?? matches any byte', 'Php.T.X' === hit( $d, 'eval(Xase64_decode' ) && '' === hit( $d, 'eval(ase64_decode' ) );
$d = db( [ 'a.ndb' => [ $sig( hx( 'abcdef' ) . '6?' . hx( 'xyz' ) ) ] ] );
check( 'a? matches a high nibble', 'Php.T.X' === hit( $d, 'abcdefaxyz' ) && '' === hit( $d, 'abcdef~xyz' ) && '' === hit( $d, 'abcdef' . chr( 0x70 ) . 'xyz' ) );
$d = db( [ 'a.ndb' => [ $sig( hx( 'abcdef' ) . '?1' . hx( 'xyz' ) ) ] ] );
check( '?a matches a low nibble', 'Php.T.X' === hit( $d, 'abcdef' . chr( 0x41 ) . 'xyz' ) && '' === hit( $d, 'abcdef' . chr( 0x42 ) . 'xyz' ) );
$d = db( [ 'a.ndb' => [ $sig( hx( 'first_part' ) . '*' . hx( 'second_part' ) ) ] ] );
check( '* matches any number of bytes, in order', 'Php.T.X' === hit( $d, 'first_part ...... second_part' ) && 'Php.T.X' === hit( $d, 'first_partsecond_part' ) && '' === hit( $d, 'second_part first_part' ) );
$d = db( [ 'a.ndb' => [ $sig( hx( 'first_part' ) . '{3}' . hx( 'second_part' ) ) ] ] );
check( '{n} matches exactly n bytes', 'Php.T.X' === hit( $d, 'first_partABCsecond_part' ) && '' === hit( $d, 'first_partABsecond_part' ) && '' === hit( $d, 'first_partABCDsecond_part' ) );
$d = db( [ 'a.ndb' => [ $sig( hx( 'first_part' ) . '{-3}' . hx( 'second_part' ) ) ] ] );
check( '{-n} matches n or fewer', 'Php.T.X' === hit( $d, 'first_partsecond_part' ) && 'Php.T.X' === hit( $d, 'first_partABCsecond_part' ) && '' === hit( $d, 'first_partABCDsecond_part' ) );
$d = db( [ 'a.ndb' => [ $sig( hx( 'first_part' ) . '{3-}' . hx( 'second_part' ) ) ] ] );
check( '{n-} matches n or more', '' === hit( $d, 'first_partABsecond_part' ) && 'Php.T.X' === hit( $d, 'first_partABCsecond_part' ) && 'Php.T.X' === hit( $d, 'first_part' . str_repeat( 'q', 500 ) . 'second_part' ) );
$d = db( [ 'a.ndb' => [ $sig( hx( 'first_part' ) . '{2-4}' . hx( 'second_part' ) ) ] ] );
check( '{n-m} matches within the range', '' === hit( $d, 'first_partAsecond_part' ) && 'Php.T.X' === hit( $d, 'first_partABsecond_part' ) && 'Php.T.X' === hit( $d, 'first_partABCDsecond_part' ) && '' === hit( $d, 'first_partABCDEsecond_part' ) );
$d = db( [ 'a.ndb' => [ $sig( hx( 'first_part' ) . '[1-2]' . '41' ) ] ] );
check( '[x-y] matches a short range up to a single byte', 'Php.T.X' === hit( $d, 'first_part' . 'zz' . 'A' ) && '' === hit( $d, 'first_part' . 'zzz' . 'A' ) );
$d = db( [ 'a.ndb' => [ $sig( hx( 'run_this_' ) . '(41|42|43)' . hx( '_now' ) ) ] ] );
check( 'a single-byte alternate matches a member only', 'Php.T.X' === hit( $d, 'run_this_B_now' ) && '' === hit( $d, 'run_this_D_now' ) );
$d = db( [ 'a.ndb' => [ $sig( hx( 'run_this_' ) . '!(41|42)' . hx( '_now' ) ) ] ] );
check( 'a negated alternate matches a non-member', 'Php.T.X' === hit( $d, 'run_this_D_now' ) && '' === hit( $d, 'run_this_A_now' ) );
$d = db( [ 'a.ndb' => [ $sig( hx( 'run_this_' ) . '(4141|4242)' . hx( '_now' ) ) ] ] );
check( 'a multi-byte alternate matches a member', 'Php.T.X' === hit( $d, 'run_this_BB_now' ) && '' === hit( $d, 'run_this_AB_now' ) );
$d = db( [ 'a.ndb' => [ $sig( hx( 'run_this_' ) . '(41??|4242)' . hx( '_now' ) ) ] ] );
check( 'a generic alternate takes wildcards', 'Php.T.X' === hit( $d, 'run_this_AZ_now' ) && 'Php.T.X' === hit( $d, 'run_this_BB_now' ) && '' === hit( $d, 'run_this_CC_now' ) );
$d = db( [ 'a.ndb' => [ $sig( '(B)' . hx( 'badwordxyz' ) . '(B)' ) ] ] );
check( '(B) matches a word boundary, file edges included', 'Php.T.X' === hit( $d, 'badwordxyz' ) && 'Php.T.X' === hit( $d, 'a badwordxyz here' ) && '' === hit( $d, 'abadwordxyzz' ) );
$d = db( [ 'a.ndb' => [ $sig( '(L)' . hx( 'badlinexyz' ) . '(L)' ) ] ] );
check( '(L) matches a line boundary', 'Php.T.X' === hit( $d, "x\nbadlinexyz\ny" ) && '' === hit( $d, 'xbadlinexyzy' ) );
$d = db( [ 'a.ndb' => [ $sig( hx( 'badwordxyz' ) . '(W)' ) ] ] );
check( '(W) matches a non-alphanumeric byte', 'Php.T.X' === hit( $d, 'badwordxyz;' ) && '' === hit( $d, 'badwordxyzz' ) );

// ---- offsets
$d = db( [ 'a.ndb' => [ $sig( hx( '<?php evil_start' ), '0', '0' ) ] ] );
check( 'offset 0 anchors at the start of the file', 'Php.T.X' === hit( $d, '<?php evil_start();' ) && '' === hit( $d, ' <?php evil_start();' ) );
$d = db( [ 'a.ndb' => [ $sig( hx( 'evil_end;' ), '0', 'EOF-9' ) ] ] );
check( 'EOF-n anchors at the end', 'Php.T.X' === hit( $d, 'padding padding evil_end;' ) && '' === hit( $d, 'evil_end; and more bytes follow' ) );
$d = db( [ 'a.ndb' => [ $sig( hx( 'floating_sig' ), '0', '10,5' ) ] ] );
check( 'a floating offset matches within its shift', 'Php.T.X' === hit( $d, str_repeat( '.', 12 ) . 'floating_sig' ) && '' === hit( $d, str_repeat( '.', 20 ) . 'floating_sig' ) && '' === hit( $d, str_repeat( '.', 5 ) . 'floating_sig' ) );

// ---- text normalisation
$d = db( [ 'a.ndb' => [ $sig( hx( 'eval( $_post' ), '7' ) ] ] );
check( 'a text target sees lower-cased text with whitespace collapsed', 'Php.T.X' === hit( $d, "<?php EVAL( \$_POST['a'] );" ) && 'Php.T.X' === hit( $d, "<?php EVAL(\n\n\t\$_POST['a'] );" ) && 'Php.T.X' === hit( $d, "<?php\n\tEVAL(   \$_POST['a'] );" ) );
$d = db( [ 'a.ndb' => [ $sig( hx( 'evalbad(x)' ), '3' ) ] ] );
check( 'an HTML comment cannot hide a signature from an HTML target', 'Php.T.X' === hit( $d, 'eval<!-- c -->bad(x)' ) );
$d = db( [ 'a.ndb' => [ $sig( hx( 'eval( $_post' ), '0' ) ] ] );
check( 'a raw target is case-sensitive and not normalised', '' === hit( $d, "<?php EVAL( \$_POST['a'] );" ) );

// ---- logical signatures
$l = static function ( string $expr, array $subs, string $td = 'Engine:51-255,Target:0' ) {
	return 'Php.L.X;' . $td . ';' . $expr . ';' . implode( ';', $subs );
};
$A = hx( 'alpha_marker' );
$B = hx( 'bravo_marker' );
$C = hx( 'charlie_mark' );
$d = db( [ 'a.ldb' => [ $l( '0&1', [ $A, $B ] ) ] ] );
check( 'a logical AND needs both subsignatures', 'Php.L.X' === hit( $d, 'alpha_marker bravo_marker' ) && '' === hit( $d, 'alpha_marker only' ) );
$d = db( [ 'a.ldb' => [ $l( '0|1', [ $A, $B ] ) ] ] );
check( 'a logical OR needs either', 'Php.L.X' === hit( $d, 'bravo_marker' ) && '' === hit( $d, 'nothing here at all' ) );
$d = db( [ 'a.ldb' => [ $l( '(0|1)&2', [ $A, $B, $C ] ) ] ] );
check( 'parentheses group', 'Php.L.X' === hit( $d, 'bravo_marker charlie_mark' ) && '' === hit( $d, 'alpha_marker bravo_marker' ) );
$d = db( [ 'a.ldb' => [ $l( '0&1=0', [ $A, $B ] ) ] ] );
check( '=0 is negation', 'Php.L.X' === hit( $d, 'alpha_marker' ) && '' === hit( $d, 'alpha_marker bravo_marker' ) );
$d = db( [ 'a.ldb' => [ $l( '0>2', [ $A ] ) ] ] );
check( '>N counts matches', '' === hit( $d, 'alpha_marker alpha_marker' ) && 'Php.L.X' === hit( $d, 'alpha_marker alpha_marker alpha_marker' ) );
$d = db( [ 'a.ldb' => [ $l( '0<2', [ $A ] ) ] ] );
check( '<N requires fewer matches', 'Php.L.X' === hit( $d, 'alpha_marker' ) && '' === hit( $d, 'alpha_marker alpha_marker' ) );
$d = db( [ 'a.ldb' => [ $l( '(0|1|2)>2,2', [ $A, $B, $C ] ) ] ] );
check( 'a block with ,Y needs Y different subsignatures', 'Php.L.X' === hit( $d, 'alpha_marker alpha_marker bravo_marker' ) && '' === hit( $d, 'alpha_marker alpha_marker alpha_marker' ) );
$d = db( [ 'a.ldb' => [ $l( '0', [ hx( 'mixedcase' ) . '::i' ], 'Engine:81-255,Target:0' ) ] ] );
check( '::i matches without regard to case', 'Php.L.X' === hit( $d, 'a MiXeDcAsE b' ) );
$d = db( [ 'a.ldb' => [ $l( '0', [ hx( 'fullword' ) . '::f' ], 'Engine:81-255,Target:0' ) ] ] );
check( '::f matches a whole word only', 'Php.L.X' === hit( $d, 'a fullword b' ) && '' === hit( $d, 'afullwordb' ) );
$d = db( [ 'a.ldb' => [ $l( '0', [ hx( 'widetext' ) . '::w' ], 'Engine:81-255,Target:0' ) ] ] );
check( '::w matches two bytes per character', 'Php.L.X' === hit( $d, implode( "\0", str_split( 'widetext' ) ) . "\0" ) && '' === hit( $d, 'widetext' ) );
$d = db( [ 'a.ldb' => [ $l( '0', [ hx( 'widetext' ) . '::wa' ], 'Engine:81-255,Target:0' ) ] ] );
check( '::wa matches both', 'Php.L.X' === hit( $d, 'widetext' ) && 'Php.L.X' === hit( $d, implode( "\0", str_split( 'widetext' ) ) . "\0" ) );
$d = db( [ 'a.ldb' => [ $l( '0', [ $A ], 'Engine:51-255,Target:0,FileSize:30-40' ) ] ] );
check( 'FileSize limits a logical signature', '' === hit( $d, 'alpha_marker' ) && 'Php.L.X' === hit( $d, 'alpha_marker' . str_repeat( 'x', 22 ) ) && '' === hit( $d, 'alpha_marker' . str_repeat( 'x', 60 ) ) );
$d = db( [ 'a.ldb' => [ $l( '0&1', [ '0:' . hx( '<?php' ), 'EOF-11:' . hx( "echo 1;\n?>\n" ) ] ) ] ] );
check( 'a subsignature can carry its own offset', 'Php.L.X' === hit( $d, "<?php echo 1;\n?>\n" ) && '' === hit( $d, "x<?php echo 1;\n?>\n" ) && '' === hit( $d, "<?php echo 1;\n?>\n\n\n" ), json_encode( $d['errors'] ) );

// ---- what is rejected or skipped
$d = db( [ 'a.ndb' => [ 'Php.T.Short:0:*:' . hx( 'abc' ), 'Php.T.Wild:0:*:' . hx( 'ab' ) . '*' . hx( 'cd' ), 'Php.T.Odd:0:*:abc', 'Php.T.Bad:0:*:zz11', 'Php.T.Ok:0:*:' . hx( 'long_enough_text' ) ] ] );
check( 'too-generic, odd and malformed signatures are rejected; a good one loads', 4 === $d['counts']['rejected'] && 1 === $d['counts']['ndb'], json_encode( $d['errors'] ) );
$d = db( [ 'a.ndb' => [ 'Win.T.Pe:1:*:' . hx( 'This program cannot be run' ), 'Php.T.Ep:0:EP+10:' . hx( 'long_enough_text' ), 'Pdf.T.Doc:10:*:' . hx( 'long_enough_text' ) ], 'b.ldb' => [ 'Php.L.Macro;Engine:51-255,Target:0;0&1;' . hx( 'long_enough_text' ) . ';${6-7}12$', 'Php.L.Pcre;Engine:51-255,Target:0;0&1;' . hx( 'long_enough_text' ) . ';/regex+/i', 'Php.L.Cont;Engine:51-255,Target:0,Container:CL_TYPE_ZIP;0;' . hx( 'long_enough_text' ) ], 'c.mdb' => [ '1:abc:Win.Section' ], 'd.cvd' => [ 'x' ] ] );
check( 'executable targets, EP offsets, macros, PCRE subsignatures and containers are skipped, not errors', 6 === $d['counts']['skipped'] && 0 === $d['counts']['rejected'] && 0 === $d['counts']['ndb'] + $d['counts']['ldb'], json_encode( $d['counts'] ) );
check( 'database files for other engines are listed as left alone', in_array( 'c.mdb', $d['skipped_files'], true ) && in_array( 'd.cvd', $d['skipped_files'], true ) );
$d = db( [ 'a.ldb' => [ 'Php.L.Bad;Engine:51-255,Target:0;0&9;' . hx( 'long_enough_text' ) , 'Php.L.Bad2;Engine:51-255,Target:0;(0&;' . hx( 'long_enough_text' ) ] ] );
check( 'a logical expression naming a missing subsignature or left open is rejected', 2 === $d['counts']['rejected'] );
$d = db( [ 'a.ndb' => [ 'Php.T.Ign:0:*:' . hx( 'long_enough_text' ) ], 'x.ign2' => [ 'Php.T.Ign' ] ] );
check( 'an ignored body signature is not loaded', 0 === $d['counts']['ndb'] );

// ---- safety
$d = db( [ 'a.ndb' => [ 'Php.T.Many:0:*:' . hx( 'aaaa' ) . str_repeat( '*' . hx( 'aaaa' ), 6 ) . '*' . hx( 'zzzz' ) ] ] );
$big = str_repeat( 'a', 900000 );
$t0  = microtime( true );
$r   = hit( $d, $big );
check( 'a signature with many * parts cannot be made to backtrack on a large file', '' === $r && ( microtime( true ) - $t0 ) < 3.0, round( microtime( true ) - $t0, 2 ) . 's' );
$d = db( [ 'a.ndb' => [ 'Php.T.Gap:0:*:' . hx( 'aaaa' ) . '{4000}' . hx( 'zzzz' ) ] ] );
$t0 = microtime( true );
$r  = hit( $d, $big );
check( 'a large bounded gap on a large file stays quick', '' === $r && ( microtime( true ) - $t0 ) < 3.0, round( microtime( true ) - $t0, 2 ) . 's' );
$many = [];
for ( $i = 0; $i < 40; $i++ ) {
	$many[] = 'Php.T.Slow' . $i . ':0:*:' . hx( 'aaaa' ) . '{1-4000}' . hx( 'aaaa' ) . '{1-4000}' . hx( 'zzzz' );
}
$d  = db( [ 'a.ndb' => $many ] );
$t0 = microtime( true );
$r  = WPS_Signature_Engine::scan_data( $d, $big, 0.5 );
check( 'a time budget stops a file from being held by many slow signatures', null === $r && ( microtime( true ) - $t0 ) < 4.0, round( microtime( true ) - $t0, 2 ) . 's' );
// ---- fixes from review (PR 23)
$d = db( [ 'a.ndb' => [ 'Php.T.Retired:0:*:' . hx( 'long_enough_text' ) . ':51:100', 'Php.T.Current:0:*:' . hx( 'long_enough_text' ) . ':51:255', 'Php.T.Open:0:*:' . hx( 'long_enough_text' ) . ':51' ] ] );
check( 'an NDB signature retired below this engine level (maxFL) is skipped, the others load', 2 === $d['counts']['ndb'] && 1 === $d['counts']['skipped'], json_encode( $d['counts'] ) );
$d = db( [ 'a.ldb' => [ 'Php.L.Rev;Engine:51-255,Target:0,FileSize:40-30;0;' . $A ] ] );
check( 'a reversed FileSize range is rejected, not loaded as never matching', 1 === $d['counts']['rejected'] && 0 === $d['counts']['ldb'], json_encode( $d['errors'] ) );
$d = db( [ 'a.ndb' => [ 'Php.T.Big:0:*:' . hx( 'first_part' ) . '{5000}' . hx( 'second_part' ) ] ] );
check( 'a fixed gap beyond the supported size is rejected, not clamped', 1 === $d['counts']['rejected'] && 0 === $d['counts']['ndb'], json_encode( $d['errors'] ) );
$d = db( [ 'a.ldb' => [ 'Php.L.Wn;Engine:81-255,Target:0;0;' . hx( 'first' ) . '!(41|42)' . hx( 'second' ) . '::w' ] ] );
$wide = static fn( string $s ) => implode( "\0", str_split( $s ) ) . "\0";
check( 'a negated alternate in a wide signature consumes two bytes per character', 'Php.L.Wn' === hit( $d, $wide( 'first' ) . $wide( 'C' ) . $wide( 'second' ) ) && '' === hit( $d, $wide( 'first' ) . $wide( 'A' ) . $wide( 'second' ) ) );
$many = [];
for ( $i = 0; $i < 3; $i++ ) {
	$many[] = md5( 'x' . $i ) . ':' . ( 10 + $i ) . ':Php.Test.H' . $i;
}
$d = db( [ 'a.hdb' => $many ] );
check( 'a small database is not cut off by the memory budget', 3 === $d['counts']['hash'] && ! $d['full'] );
check( 'the memory budget and the hash cap are set', WPS_Signature_Engine::MAX_DB_MEMORY <= 134217728 && WPS_Signature_Engine::MAX_HASH_SIGS <= 200000 );
check( 'scan_file returns the SHA-256 of the bytes it scanned', hash( 'sha256', $body ) === ( WPS_Signature_Engine::scan_file( db( [ 'a.hdb' => [ "$md5:$size:Php.Test.Md5" ] ] ), $tmp . '/sample.php' )['sha256'] ?? '' ) );
check( 'PUA, Heuristics and Hunting names are report-only', WPS_Signature_Engine::is_report_only( 'PUA.Php.Tool' ) && WPS_Signature_Engine::is_report_only( 'Heuristics.Php.X' ) && ! WPS_Signature_Engine::is_report_only( 'Php.Trojan.Agent-1-0' ) );
$d = db( [ 'a.ndb' => [ 'Php.T.Ok:0:*:' . hx( 'long_enough_text' ) ] ] );
$st = WPS_Signature_Engine::status( $tmp . '/db' . 'zzz' );
check( 'the status of a missing folder is empty and unusable', ! $st['exists'] && ! $st['usable'] );
$st = WPS_Signature_Engine::status( $d['dir'] );
check( 'the status of a loaded folder counts its signatures', $st['usable'] && 1 === $st['ndb'] );
mkdir( $tmp . '/link-target' );
file_put_contents( $tmp . '/link-target/x.ndb', 'Php.T.Ok:0:*:' . hx( 'long_enough_text' ) . "\n" );
mkdir( $tmp . '/linkdb' );
@symlink( $tmp . '/link-target/x.ndb', $tmp . '/linkdb/x.ndb' );
check( 'a symlinked database file is not followed', 0 === WPS_Signature_Engine::load( $tmp . '/linkdb' )['counts']['ndb'] );
$d = db( [ 'a.ndb' => [ 'Php.T.Ok:0:*:' . hx( 'long_enough_text' ) ] ] );
file_put_contents( $tmp . '/scan.php', 'xx long_enough_text yy' );
check( 'scan_file reads a file and reports the body signature', 'Php.T.Ok' === ( WPS_Signature_Engine::scan_file( $d, $tmp . '/scan.php' )['name'] ?? '' ) );

// ---- the scanner check, end to end through the removal policy
$wp = $tmp . '/wp';
mkdir( $wp . '/plugins/wps-self', 0777, true );
mkdir( $wp . '/mu-plugins', 0777, true );
mkdir( $wp . '/wps-signatures', 0777, true );
define( 'WPS_DIR', $wp . '/plugins/wps-self/' );
define( 'WPS_OPTION', 'wps_opts' );
define( 'WP_PLUGIN_DIR', $wp . '/plugins' );
define( 'WPMU_PLUGIN_DIR', $wp . '/mu-plugins' );
define( 'WP_CONTENT_DIR', $wp );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'DAY_IN_SECONDS', 86400 );
$GLOBALS['opts'] = [];
function get_option( $k, $d = false ) { return 'wps_opts' === $k ? $GLOBALS['opts'] : $d; }
function update_option() { return true; }
function apply_filters( $t, $v ) { return $v; }
function wp_json_encode( $v ) { return json_encode( $v ); }
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
$run = static function (): array {
	WPS_Signature_Engine::forget();
	$m = new ReflectionMethod( 'WPS_Scanner', 'check_signature_database' );
	$m->setAccessible( true );
	return $m->invoke( null );
};
$evil  = "<?php\n// planted\n\$k = 'long_enough_text_for_a_signature';\n";
$body  = "<?php\n\$x = 'another_planted_marker_string';\n";
$pua   = "<?php\n// a tool that is not malware: pua_marker_string_here\n";
file_put_contents( $wp . '/plugins/wps-self/self.php', $evil );
@mkdir( $wp . '/plugins/p1' );
file_put_contents( $wp . '/plugins/p1/evil.php', $evil );
file_put_contents( $wp . '/plugins/p1/body.php', $body );
file_put_contents( $wp . '/plugins/p1/pua.php', $pua );
file_put_contents( $wp . '/plugins/p1/clean.php', "<?php\n// nothing to see\n" );
file_put_contents( $wp . '/plugins/p1/readme.txt', $evil );
@mkdir( $wp . '/plugins/p1/real' );
@symlink( $wp . '/plugins/p1/evil.php', $wp . '/plugins/p1/real/link.php' );
check( 'with no signature folder content, the check finds nothing', [] === $run() );
file_put_contents( $wp . '/wps-signatures/a.hdb', md5( $evil ) . ':' . strlen( $evil ) . ":Php.Trojan.Planted-1-0\n" . md5( $pua ) . ':' . strlen( $pua ) . ":PUA.Php.Tool\n" );
file_put_contents( $wp . '/wps-signatures/a.ndb', 'Php.Backdoor.Body-2-0:0:*:' . hx( 'another_planted_marker_string' ) . "\n" );
$f  = $run();
$by = [];
foreach ( $f as $x ) {
	$by[ basename( $x['path'] ) ] = $x;
}
check( 'a whole-file hash match is a critical, removable finding', isset( $by['evil.php'] ) && 'Known malicious file (hash signature)' === $by['evil.php']['type'] && ! empty( $by['evil.php']['auto_delete'] ) && $by['evil.php']['delete_path'] === $by['evil.php']['path'] );
check( 'a body match is report only by default', isset( $by['body.php'] ) && 'Signature database match (report only)' === $by['body.php']['type'] && empty( $by['body.php']['auto_delete'] ) && ! isset( $by['body.php']['delete_path'] ) );
check( 'a PUA name is report only even on a hash match', isset( $by['pua.php'] ) && empty( $by['pua.php']['auto_delete'] ) );
check( 'this plugin, a clean file, a non-code extension and a symlink are not reported', ! isset( $by['self.php'] ) && ! isset( $by['clean.php'] ) && ! isset( $by['readme.txt'] ) && ! isset( $by['link.php'] ) && 3 === count( $f ), subjects_of( $f ) );
function subjects_of( array $f ): string {
	return implode( ' | ', array_map( static fn( $x ) => $x['subject'] ?? '', $f ) );
}
$pol = static fn( array $x ) => WPS_Remediation_Policy::decide( $x );
check( 'a removable finding carries the fingerprint of what matched', ! empty( $by['evil.php']['expect_sha256'] ) && hash( 'sha256', $evil ) === $by['evil.php']['expect_sha256'] );
$ih = new ReflectionMethod( 'WPS_Remediation_Policy', 'is_heuristic' );
$ih->setAccessible( true );
check( 'a hash match has the standing of a confirmed match; a body match does not', ! $ih->invoke( null, 'Known malicious file (hash signature)' ) && $ih->invoke( null, 'Signature database match, removal enabled' ) );
// A file that changed after the scan is not removed for the old match.
$swap = $wp . '/plugins/p1/swapped.php';
file_put_contents( $swap, $evil );
$fd = [ [ 'type' => 'Known malicious file (hash signature)', 'severity' => 'critical', 'subject' => 'swapped.php', 'path' => $swap, 'auto_delete' => true, 'delete_path' => $swap, 'action' => 'x', 'expect_sha256' => hash( 'sha256', $evil ) ] ];
file_put_contents( $swap, "<?php // replaced after the scan\n" );
$ar = new ReflectionMethod( 'WPS_Scanner', 'auto_remediate' );
$ar->setAccessible( true );
$ar->invokeArgs( null, [ &$fd ] );
check( 'a file changed after the scan is not removed for the earlier match', is_file( $swap ) && ! empty( $fd[0]['auto_delete_skipped'] ) && false !== strpos( $fd[0]['action'], 'changed after it was scanned' ), json_encode( $fd[0] ) );
check( 'the removal policy allows the hash match to be deleted', $pol( $by['evil.php'] )['allowed'], json_encode( $pol( $by['evil.php'] ) ) );
check( 'and denies the report-only ones', ! $pol( $by['body.php'] )['allowed'] && ! $pol( $by['pua.php'] )['allowed'] );
$GLOBALS['opts'] = [ 'signature_auto_remove' => '1' ];
$by = [];
foreach ( $run() as $x ) {
	$by[ basename( $x['path'] ) ] = $x;
}
check( 'with removal turned on a body match is removable and the policy allows it', 'Signature database match, removal enabled' === ( $by['body.php']['type'] ?? '' ) && $pol( $by['body.php'] )['allowed'], json_encode( $pol( $by['body.php'] ?? [] ) ) );
check( 'a PUA match stays report only with removal on', empty( $by['pua.php']['auto_delete'] ) && ! $pol( $by['pua.php'] )['allowed'] );
file_put_contents( $wp . '/wps-signatures/z.ign2', "Php.Backdoor.Body-2-0\n" );
check( 'an .ign2 entry silences a body signature', ! isset( array_column( array_map( static fn( $x ) => [ basename( $x['path'] ) => 1 ], $run() ), 'body.php' )[0] ) );
file_put_contents( $wp . '/wps-signatures/z.fp', md5( $evil ) . ':' . strlen( $evil ) . ":Known.Good\n" );
check( 'a .fp entry silences a hash signature', ! in_array( 'evil.php', array_map( static fn( $x ) => basename( $x['path'] ), $run() ), true ) );
$GLOBALS['opts'] = [ 'signature_db_enabled' => '0' ];
check( 'the check does nothing when switched off', [] === $run() );
$GLOBALS['opts'] = [];
check( 'the check is registered', false !== strpos( (string) file_get_contents( dirname( __DIR__ ) . '/includes/class-scanner.php' ), "'check_signature_database' => [ __CLASS__" ) );

exec( 'rm -rf ' . escapeshellarg( $tmp ) );
echo $fail ? "\n$fail FAILED\n" : "\nAll passed\n";
exit( $fail ? 1 : 0 );
