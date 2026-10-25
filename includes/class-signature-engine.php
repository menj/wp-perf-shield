<?php
/**
 * ClamAV-format signature engine (1.4.146).
 *
 * Reads the signature file formats ClamAV uses, so a site operator can drop a
 * database into one folder and have the scanner use it, and so signatures
 * written for ClamAV can be reused. It is not ClamAV: there is no executable,
 * archive or document unpacking, and nothing here calls out to a binary.
 *
 * Supported (see doc/signatures.md for the details and the limits):
 *   .hdb / .hsb   whole-file hash:size:name (MD5, SHA-1, SHA-256, size `*`)
 *   .ndb          extended body signatures, Name:Target:Offset:HexSig
 *   .ldb          logical signatures, Name;Target description;Expression;Subsigs
 *   .fp / .sfp    hash exceptions, a file with a listed hash is never reported
 *   .ign / .ign2  signature names to ignore
 * Hex signatures support ??, a?, ?a, *, {n} {-n} {n-} {n-m}, [x-y], (B) (L) (W),
 * and (aa|bb) / !(aa|bb) alternates. Logical signatures support & | ( ) and
 * =X >X <X with an optional ,Y, and the ::i ::w ::f ::a subsignature modifiers.
 *
 * What is deliberately left out, and counted as "skipped" rather than failing:
 * signatures for executables (PE, ELF, Mach-O), documents, images and mail,
 * entry-point and section offsets, container conditions, macro and PCRE
 * subsignatures, bytecode, YARA, icon and phishing databases.
 *
 * Two things differ from ClamAV on purpose. A body signature must hold at least
 * eight fixed bytes (four per logical subsignature) or it is rejected as too
 * generic: ClamAV can lean on its other conditions, and this engine reports
 * files on a live site. And a text target (7) or HTML target (3) is matched
 * against a lower-cased, whitespace-collapsed copy of the file, the way ClamAV
 * normalises text, so a signature written for ClamAV sees the same bytes.
 *
 * Matching is bounded (and a file gets a time budget, three seconds): each signature is anchored on its longest run of fixed
 * bytes, found through a three-byte index before any pattern runs; `*` and
 * `{n-}` split a signature into parts matched one after another, never as a
 * backtracking `.*`; and a pattern error counts as no match.
 *
 * @package WP_Perf_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class WPS_Signature_Engine {

	const MAX_BODY_SIGS  = 20000;
	const MAX_HASH_SIGS  = 200000;
	const MAX_DB_MEMORY  = 67108864;
	const MAX_DB_BYTES   = 33554432;
	const MAX_LINE       = 65536;
	const MAX_ERRORS     = 25;
	const MAX_SCAN_BYTES = 1048576;
	const MAX_HASH_BYTES = 67108864;
	const MAX_SUBSIGS    = 64;
	const MIN_FIXED_NDB  = 8;
	const MIN_FIXED_SUB  = 4;
	const MIN_ANCHOR     = 3;
	const MAX_GAP        = 4096;
	const MAX_FILE_SECS  = 3.0;

	/** Names that are reported but never removed, whatever the operator's removal setting. */
	const REPORT_ONLY_PREFIXES = [ 'PUA.', 'Heuristics.', 'Hunting.' ];

	/** Extensions this engine reads, and ones it recognises and leaves alone. */
	const READ_EXTS = [ 'hdb', 'hsb', 'ndb', 'ldb', 'fp', 'sfp', 'ign', 'ign2' ];
	const SKIP_EXTS = [ 'mdb', 'msb', 'imp', 'cdb', 'idb', 'ftm', 'ftmcore', 'crb', 'cbc', 'yar', 'yara', 'pdb', 'gdb', 'wdb', 'cfg', 'info', 'cvd', 'cld', 'cud' ];

	/** @var array<string, array<string, mixed>> */
	private static $cache = [];

	/** The folder the operator puts the database in. */
	public static function default_dir(): string {
		$dir = defined( 'WP_CONTENT_DIR' ) ? rtrim( WP_CONTENT_DIR, '/\\' ) . '/wps-signatures' : '';
		$dir = function_exists( 'apply_filters' ) ? apply_filters( 'wps_signature_dir', $dir ) : $dir;
		return is_string( $dir ) ? $dir : '';
	}

	// ------------------------------------------------------------------ loading

	/**
	 * Load every readable database file in a folder.
	 *
	 * @return array<string, mixed>
	 */
	public static function load( string $dir ): array {
		$dir = rtrim( $dir, '/\\' );
		$key = self::dir_key( $dir );
		if ( isset( self::$cache[ $dir ] ) && self::$cache[ $dir ]['key'] === $key ) {
			return self::$cache[ $dir ];
		}
		$db = [
			'dir'       => $dir,
			'key'       => $key,
			'hash'      => [ 'md5' => [], 'sha1' => [], 'sha256' => [] ],
			'fp'        => [ 'md5' => [], 'sha1' => [], 'sha256' => [] ],
			'ign'       => [],
			'body'      => [],
			'gram'      => [ 'raw' => [], 'n7' => [], 'n3' => [] ],
			'gram_ci'   => [ 'raw' => [], 'n7' => [], 'n3' => [] ],
			'variants'  => [],
			'counts'    => [ 'hash' => 0, 'ndb' => 0, 'ldb' => 0, 'fp' => 0, 'ign' => 0, 'skipped' => 0, 'rejected' => 0, 'files' => 0 ],
			'errors'    => [],
			'skipped_files' => [],
			'mem0'      => memory_get_usage(),
			'full'      => false,
		];
		if ( '' === $dir || ! is_dir( $dir ) ) {
			return self::$cache[ $dir ] = $db;
		}
		$names = @scandir( $dir );
		if ( ! is_array( $names ) ) {
			return self::$cache[ $dir ] = $db;
		}
		// Ignore lists first, so a signature named in one is dropped as it is read.
		usort(
			$names,
			static function ( $a, $b ) {
				$ia = in_array( strtolower( pathinfo( $a, PATHINFO_EXTENSION ) ), [ 'ign', 'ign2' ], true ) ? 0 : 1;
				$ib = in_array( strtolower( pathinfo( $b, PATHINFO_EXTENSION ) ), [ 'ign', 'ign2' ], true ) ? 0 : 1;
				return $ia === $ib ? strcmp( $a, $b ) : $ia - $ib;
			}
		);
		foreach ( $names as $name ) {
			if ( '.' === $name[0] ) {
				continue;
			}
			$path = $dir . '/' . $name;
			$ext  = strtolower( pathinfo( $name, PATHINFO_EXTENSION ) );
			if ( is_link( $path ) || ! is_file( $path ) ) {
				continue;
			}
			if ( in_array( $ext, self::SKIP_EXTS, true ) ) {
				$db['skipped_files'][] = $name;
				continue;
			}
			if ( ! in_array( $ext, self::READ_EXTS, true ) ) {
				continue;
			}
			$size = (int) @filesize( $path );
			if ( $size > self::MAX_DB_BYTES ) {
				self::error( $db, $name, 0, 'file is larger than ' . ( self::MAX_DB_BYTES / 1048576 ) . ' MB, not read' );
				continue;
			}
			$fh = @fopen( $path, 'rb' );
			if ( ! $fh ) {
				continue;
			}
			++$db['counts']['files'];
			$ln = 0;
			while ( false !== ( $line = fgets( $fh, self::MAX_LINE + 2 ) ) ) {
				++$ln;
				$line = trim( $line );
				if ( '' === $line || '#' === $line[0] ) {
					continue;
				}
				if ( strlen( $line ) > self::MAX_LINE ) {
					self::error( $db, $name, $ln, 'line too long' );
					continue;
				}
				self::read_line( $db, $ext, $line, $name, $ln );
			}
			fclose( $fh );
		}
		return self::$cache[ $dir ] = $db;
	}

	/** Forget a loaded folder (tests, and after the operator changes files). */
	public static function forget( string $dir = '' ): void {
		if ( '' === $dir ) {
			self::$cache = [];
		} else {
			unset( self::$cache[ rtrim( $dir, '/\\' ) ] );
		}
	}

	private static function dir_key( string $dir ): string {
		$parts = [];
		foreach ( (array) @scandir( $dir ) as $n ) {
			if ( is_string( $n ) && '.' !== $n[0] && in_array( strtolower( pathinfo( $n, PATHINFO_EXTENSION ) ), self::READ_EXTS, true ) ) {
				$parts[] = $n . ':' . (int) @filemtime( $dir . '/' . $n ) . ':' . (int) @filesize( $dir . '/' . $n );
			}
		}
		return md5( implode( '|', $parts ) );
	}

	private static function error( array &$db, string $file, int $line, string $why ): void {
		++$db['counts']['rejected'];
		if ( count( $db['errors'] ) < self::MAX_ERRORS ) {
			$db['errors'][] = $file . ( $line ? ':' . $line : '' ) . ' ' . $why;
		}
	}

	private static function valid_name( string $n ): bool {
		return 1 === preg_match( '/^[A-Za-z0-9._+\-\/]{1,160}$/', $n );
	}

	private static function read_line( array &$db, string $ext, string $line, string $file, int $ln ): void {
		// A database that would take more than 64 MB of memory is loaded no further: a settings page
		// or a scan must not be able to run the site out of memory because of a file in this folder.
		if ( $db['full'] ) {
			return;
		}
		if ( memory_get_usage() - $db['mem0'] > self::MAX_DB_MEMORY ) {
			$db['full'] = true;
			self::error( $db, $file, $ln, 'memory budget of ' . ( self::MAX_DB_MEMORY / 1048576 ) . ' MB reached, the rest of the database is not loaded' );
			return;
		}
		switch ( $ext ) {
			case 'hdb':
			case 'hsb':
				self::read_hash( $db, $line, $file, $ln, 'hdb' === $ext, false );
				return;
			case 'fp':
			case 'sfp':
				self::read_hash( $db, $line, $file, $ln, 'fp' === $ext, true );
				return;
			case 'ign':
			case 'ign2':
				$name = trim( explode( ':', $line )[0] );
				if ( self::valid_name( $name ) ) {
					$db['ign'][ $name ] = true;
					++$db['counts']['ign'];
				}
				return;
			case 'ndb':
				self::read_ndb( $db, $line, $file, $ln );
				return;
			case 'ldb':
				self::read_ldb( $db, $line, $file, $ln );
				return;
		}
	}

	private static function read_hash( array &$db, string $line, string $file, int $ln, bool $md5_only, bool $exception ): void {
		$f = explode( ':', $line );
		if ( count( $f ) < 3 || count( $f ) > 4 ) {
			self::error( $db, $file, $ln, 'expected hash:size:name' );
			return;
		}
		[ $hash, $size, $name ] = $f;
		$hash = strtolower( $hash );
		$type = [ 32 => 'md5', 40 => 'sha1', 64 => 'sha256' ][ strlen( $hash ) ] ?? '';
		if ( '' === $type || ! ctype_xdigit( $hash ) || ( $md5_only && 'md5' !== $type ) ) {
			self::error( $db, $file, $ln, 'not a ' . ( $md5_only ? 'MD5' : 'MD5, SHA-1 or SHA-256' ) . ' hash' );
			return;
		}
		if ( '*' !== $size && ! ctype_digit( $size ) ) {
			self::error( $db, $file, $ln, 'size is neither a number nor *' );
			return;
		}
		if ( ! self::valid_name( $name ) ) {
			self::error( $db, $file, $ln, 'bad name' );
			return;
		}
		if ( isset( $db['ign'][ $name ] ) && ! $exception ) {
			return;
		}
		if ( ! $exception && $db['counts']['hash'] >= self::MAX_HASH_SIGS ) {
			return;
		}
		$bucket = $exception ? 'fp' : 'hash';
		$db[ $bucket ][ $type ][ $hash ][ '*' === $size ? '*' : (string) (int) $size ] = $name;
		++$db['counts'][ $exception ? 'fp' : 'hash' ];
	}

	/** @return array{0:string,1:int,2:int}|null mode (abs|eof|any), n, max; null when unsupported or malformed */
	private static function parse_offset( string $o ): ?array {
		if ( '*' === $o || '' === $o ) {
			return [ 'any', 0, 0 ];
		}
		if ( ! preg_match( '/^(EOF-)?(\d{1,9})(?:,(\d{1,9}))?$/', $o, $m ) ) {
			return null; // EP+n, Sx+n, SL+n, SEx: executable offsets are not supported
		}
		return [ '' !== $m[1] ? 'eof' : 'abs', (int) $m[2], (int) ( $m[3] ?? 0 ) ];
	}

	/** Target types this engine reads: 0 any, 3 HTML, 7 text. Others are executables, documents, images, mail. */
	private static function variant_for( int $target ): string {
		return [ 0 => 'raw', 3 => 'n3', 7 => 'n7' ][ $target ] ?? '';
	}

	private static function read_ndb( array &$db, string $line, string $file, int $ln ): void {
		$f = explode( ':', $line );
		if ( count( $f ) < 4 ) {
			self::error( $db, $file, $ln, 'expected Name:Target:Offset:HexSig' );
			return;
		}
		[ $name, $target, $off, $hex ] = $f;
		if ( ! self::valid_name( $name ) || ! ctype_digit( $target ) ) {
			self::error( $db, $file, $ln, 'bad name or target type' );
			return;
		}
		// minFL above the level this engine claims (255), or maxFL below it (a signature the author
		// retired for newer engines), means the signature is not meant for this reader.
		if ( ( isset( $f[4] ) && ctype_digit( $f[4] ) && (int) $f[4] > 255 ) || ( isset( $f[5] ) && ctype_digit( $f[5] ) && (int) $f[5] < 255 ) ) {
			++$db['counts']['skipped'];
			return;
		}
		$variant = self::variant_for( (int) $target );
		if ( '' === $variant ) {
			++$db['counts']['skipped'];
			return;
		}
		$offset = self::parse_offset( $off );
		if ( null === $offset ) {
			++$db['counts']['skipped'];
			return;
		}
		if ( isset( $db['ign'][ $name ] ) ) {
			return;
		}
		if ( count( $db['body'] ) >= self::MAX_BODY_SIGS ) {
			return;
		}
		$sub = self::compile_sub( $hex, '', $offset, self::MIN_FIXED_NDB, $why );
		if ( null === $sub ) {
			self::error( $db, $file, $ln, $why );
			return;
		}
		self::add_body(
			$db,
			[
				'name'    => $name,
				'kind'    => 'ndb',
				'variant' => $variant,
				'subs'    => [ $sub ],
				'expr'    => [ 'n', 0 ],
				'size'    => null,
			]
		);
		++$db['counts']['ndb'];
	}

	private static function read_ldb( array &$db, string $line, string $file, int $ln ): void {
		$f = explode( ';', $line );
		if ( count( $f ) < 4 ) {
			self::error( $db, $file, $ln, 'expected Name;Target;Expression;Subsig...' );
			return;
		}
		$name = array_shift( $f );
		$td   = array_shift( $f );
		$expr = array_shift( $f );
		if ( ! self::valid_name( $name ) ) {
			self::error( $db, $file, $ln, 'bad name' );
			return;
		}
		if ( count( $f ) > self::MAX_SUBSIGS ) {
			self::error( $db, $file, $ln, 'more than ' . self::MAX_SUBSIGS . ' subsignatures' );
			return;
		}
		$target = null;
		$size   = null;
		foreach ( explode( ',', $td ) as $kv ) {
			$kv = explode( ':', $kv, 2 );
			if ( 2 !== count( $kv ) ) {
				continue;
			}
			switch ( $kv[0] ) {
				case 'Engine':
					if ( preg_match( '/^(\d+)(?:-\d+)?$/', $kv[1], $m ) && (int) $m[1] > 255 ) {
						++$db['counts']['skipped'];
						return;
					}
					break;
				case 'Target':
					$target = ctype_digit( $kv[1] ) ? (int) $kv[1] : -1;
					break;
				case 'FileSize':
					if ( preg_match( '/^(\d+)-(\d+)$/', $kv[1], $m ) && (int) $m[1] <= (int) $m[2] ) {
						$size = [ (int) $m[1], (int) $m[2] ];
					} else {
						self::error( $db, $file, $ln, 'bad FileSize range' );
						return;
					}
					break;
				default:
					// EntryPoint, NumberOfSections, Container, Intermediates, IconGroup, HandlerType.
					++$db['counts']['skipped'];
					return;
			}
		}
		$variant = null === $target ? 'raw' : self::variant_for( $target );
		if ( '' === $variant ) {
			++$db['counts']['skipped'];
			return;
		}
		if ( isset( $db['ign'][ $name ] ) ) {
			return;
		}
		if ( count( $db['body'] ) >= self::MAX_BODY_SIGS ) {
			return;
		}
		$subs = [];
		foreach ( $f as $i => $raw ) {
			if ( false !== strpos( $raw, '${' ) || false !== strpos( $raw, '/' ) ) {
				++$db['counts']['skipped']; // macro or PCRE subsignature (a hex signature never holds a slash)
				return;
			}
			$mods = '';
			if ( false !== ( $p = strrpos( $raw, '::' ) ) ) {
				$mods = substr( $raw, $p + 2 );
				$raw  = substr( $raw, 0, $p );
			}
			$offset = [ 'any', 0, 0 ];
			if ( preg_match( '/^([^:]+):(.+)$/s', $raw, $m ) ) {
				$offset = self::parse_offset( $m[1] );
				if ( null === $offset ) {
					++$db['counts']['skipped'];
					return;
				}
				$raw = $m[2];
			}
			$sub = self::compile_sub( $raw, $mods, $offset, self::MIN_FIXED_SUB, $why );
			if ( null === $sub ) {
				self::error( $db, $file, $ln, 'subsignature ' . $i . ': ' . $why );
				return;
			}
			$subs[] = $sub;
		}
		$ast = self::parse_expr( $expr, count( $subs ) );
		if ( null === $ast ) {
			self::error( $db, $file, $ln, 'bad logical expression' );
			return;
		}
		self::add_body(
			$db,
			[
				'name'    => $name,
				'kind'    => 'ldb',
				'variant' => $variant,
				'subs'    => $subs,
				'expr'    => $ast,
				'size'    => $size,
			]
		);
		++$db['counts']['ldb'];
	}

	private static function add_body( array &$db, array $sig ): void {
		$id                = count( $db['body'] );
		$db['body'][ $id ] = $sig;
		$db['variants'][ $sig['variant'] ] = true;
		foreach ( $sig['subs'] as $sub ) {
			foreach ( $sub['variants'] as $v ) {
				$lit = $v['lit'];
				if ( strlen( $lit ) < self::MIN_ANCHOR ) {
					continue;
				}
				if ( $sub['ci'] ) {
					$db['gram_ci'][ $sig['variant'] ][ strtolower( substr( $lit, 0, 3 ) ) ][ $id ] = true;
				} else {
					$db['gram'][ $sig['variant'] ][ substr( $lit, 0, 3 ) ][ $id ] = true;
				}
			}
		}
	}

	// -------------------------------------------------------- hex signature compile

	/**
	 * Compile one subsignature (a hex signature plus offset and modifiers).
	 *
	 * @param array{0:string,1:int,2:int} $offset
	 * @return array<string, mixed>|null
	 */
	private static function compile_sub( string $hex, string $mods, array $offset, int $min_fixed, ?string &$why = null ): ?array {
		$ci   = false !== strpos( $mods, 'i' );
		$wide = false !== strpos( $mods, 'w' );
		$asc  = false !== strpos( $mods, 'a' ) || ! $wide;
		$full = false !== strpos( $mods, 'f' );
		if ( '' !== $mods && '' !== preg_replace( '/[iwfa]/', '', $mods ) ) {
			$why = 'unknown modifier';
			return null;
		}
		$variants = [];
		$modes    = [];
		if ( $asc ) {
			$modes[] = false;
		}
		if ( $wide ) {
			$modes[] = true;
		}
		foreach ( $modes as $is_wide ) {
			$c = self::compile_hex( $hex, $is_wide, $ci, $full, $why );
			if ( null === $c ) {
				return null;
			}
			$variants[] = $c;
		}
		if ( ! $variants ) {
			$why = 'empty';
			return null;
		}
		foreach ( $variants as $v ) {
			if ( $v['fixed'] < $min_fixed ) {
				$why = 'too generic (fewer than ' . $min_fixed . ' fixed bytes)';
				return null;
			}
			if ( strlen( $v['lit'] ) < self::MIN_ANCHOR ) {
				$why = 'no run of ' . self::MIN_ANCHOR . ' fixed bytes to anchor on';
				return null;
			}
		}
		return [ 'variants' => $variants, 'offset' => $offset, 'ci' => $ci ];
	}

	private static function byte_re( int $b ): string {
		return sprintf( '\\x%02x', $b );
	}

	/**
	 * Hex signature to a list of parts matched in order.
	 *
	 * @return array{parts:array<int,array{re:string}>,gaps:int[],lit:string,fixed:int}|null
	 */
	private static function compile_hex( string $hex, bool $wide, bool $ci, bool $full, ?string &$why ): ?array {
		$hex = preg_replace( '/\s+/', '', $hex );
		$n   = strlen( $hex );
		if ( 0 === $n || $n > 8192 ) {
			$why = 'empty or too long';
			return null;
		}
		$parts = [];
		$gaps  = [];
		$re    = '';
		$run   = '';
		$best  = '';
		$fixed = 0;
		$neg   = false;
		$flush = static function () use ( &$run, &$best ): void {
			if ( strlen( $run ) > strlen( $best ) ) {
				$best = $run;
			}
			$run = '';
		};
		$i = 0;
		while ( $i < $n ) {
			$c = $hex[ $i ];
			if ( '*' === $c ) {
				$flush();
				$parts[] = $re;
				$gaps[]  = 0;
				$re      = '';
				++$i;
				continue;
			}
			if ( '{' === $c ) {
				$e = strpos( $hex, '}', $i );
				if ( false === $e || ! preg_match( '/^(\d*)(-?)(\d*)$/', substr( $hex, $i + 1, $e - $i - 1 ), $m ) || ( '' === $m[1] && '' === $m[3] ) ) {
					$why = 'bad {} range';
					return null;
				}
				$lo = (int) $m[1];
				$hi = (int) $m[3];
				$flush();
				if ( '' === $m[2] ) {
					if ( $lo > self::MAX_GAP ) {
						$why = 'a fixed gap larger than ' . self::MAX_GAP . ' bytes is not supported';
						return null;
					}
					$re .= '.{' . $lo . '}';
				} elseif ( '' === $m[3] ) {
					$parts[] = $re;
					$gaps[]  = $lo; // at least $lo bytes
					$re      = '';
				} else {
					if ( $hi < $lo || $hi > self::MAX_GAP ) {
						$why = 'range out of bounds';
						return null;
					}
					$re .= '.{' . $lo . ',' . $hi . '}';
				}
				$i = $e + 1;
				continue;
			}
			if ( '[' === $c ) {
				$e = strpos( $hex, ']', $i );
				if ( false === $e || ! preg_match( '/^(\d+)-(\d+)$/', substr( $hex, $i + 1, $e - $i - 1 ), $m ) || (int) $m[2] > 32 || (int) $m[2] < (int) $m[1] ) {
					$why = 'bad [] range';
					return null;
				}
				$flush();
				$re .= '.{' . (int) $m[1] . ',' . (int) $m[2] . '}';
				$i   = $e + 1;
				continue;
			}
			if ( '!' === $c ) {
				$neg = true;
				++$i;
				if ( $i >= $n || '(' !== $hex[ $i ] ) {
					$why = '! must be followed by an alternate';
					return null;
				}
				continue;
			}
			if ( '(' === $c ) {
				$e = strpos( $hex, ')', $i );
				if ( false === $e ) {
					$why = 'unclosed (';
					return null;
				}
				$body = substr( $hex, $i + 1, $e - $i - 1 );
				$i    = $e + 1;
				$flush();
				if ( ! $neg && 1 === strlen( $body ) && false !== strpos( 'BLW', $body ) ) {
					$re .= [ 'B' => '\\b', 'L' => '(?:\\r\\n|\\r|\\n|^|$)', 'W' => '[^A-Za-z0-9]' ][ $body ];
					continue;
				}
				$alt = self::compile_alt( $body, $neg, $wide, $why );
				$neg = false;
				if ( null === $alt ) {
					return null;
				}
				$re .= $alt;
				continue;
			}
			$tok = substr( $hex, $i, 2 );
			if ( 2 !== strlen( $tok ) ) {
				$why = 'odd number of hex digits';
				return null;
			}
			if ( '??' === $tok ) {
				$flush();
				$re .= '.';
			} elseif ( '?' === $tok[1] && ctype_xdigit( $tok[0] ) ) {
				$flush();
				$hi  = hexdec( $tok[0] ) << 4;
				$re .= '[' . self::byte_re( $hi ) . '-' . self::byte_re( $hi | 15 ) . ']';
			} elseif ( '?' === $tok[0] && ctype_xdigit( $tok[1] ) ) {
				$flush();
				$lo  = hexdec( $tok[1] );
				$set = '';
				for ( $h = 0; $h < 16; $h++ ) {
					$set .= self::byte_re( ( $h << 4 ) | $lo );
				}
				$re .= '[' . $set . ']';
			} elseif ( ctype_xdigit( $tok ) ) {
				$b    = hexdec( $tok );
				$re  .= self::byte_re( $b ) . ( $wide ? '\\x00' : '' );
				$run .= chr( $b ) . ( $wide ? "\0" : '' );
				++$fixed;
			} else {
				$why = 'bad hex digits';
				return null;
			}
			$i += 2;
		}
		if ( $neg ) {
			$why = 'dangling !';
			return null;
		}
		$flush();
		$parts[] = $re;
		$out     = [];
		foreach ( $parts as $k => $p ) {
			if ( '' === $p ) {
				$why = 'a part between * or {n-} wildcards is empty';
				return null;
			}
			if ( $full ) {
				if ( 0 === $k ) {
					$p = '(?<![A-Za-z0-9])' . $p;
				}
				if ( count( $parts ) - 1 === $k ) {
					$p .= '(?![A-Za-z0-9])';
				}
			}
			$out[] = [ 're' => '/' . $p . '/s' . ( $ci ? 'i' : '' ) ];
		}
		return [ 'parts' => $out, 'gaps' => $gaps, 'lit' => $ci ? strtolower( $best ) : $best, 'fixed' => $fixed ];
	}

	private static function compile_alt( string $body, bool $neg, bool $wide, ?string &$why ): ?string {
		$items = explode( '|', $body );
		if ( count( $items ) < 1 || count( $items ) > 64 ) {
			$why = 'alternate has too many members';
			return null;
		}
		$plain = true;
		$len   = null;
		foreach ( $items as $it ) {
			if ( '' === $it || 0 !== strlen( $it ) % 2 || ! ctype_xdigit( $it ) ) {
				$plain = false;
			} else {
				$l = strlen( $it ) / 2;
				if ( null === $len ) {
					$len = $l;
				} elseif ( $len !== $l ) {
					$plain = false;
				}
			}
		}
		if ( $neg && ! $plain ) {
			$why = 'a negated alternate needs fixed-length plain members';
			return null;
		}
		if ( $plain ) {
			$alts = [];
			foreach ( $items as $it ) {
				$s = '';
				foreach ( str_split( $it, 2 ) as $h ) {
					$s .= self::byte_re( hexdec( $h ) ) . ( $wide ? '\\x00' : '' );
				}
				$alts[] = $s;
			}
			if ( 1 === $len && ! $wide ) {
				$set = implode( '', $alts );
				return $neg ? '[^' . $set . ']' : '[' . $set . ']';
			}
			$g = '(?:' . implode( '|', $alts ) . ')';
			return $neg ? '(?!' . $g . ').{' . ( $wide ? 2 * $len : $len ) . '}' : $g;
		}
		// Generic alternate: members may hold ?? and nibble wildcards and small {n} gaps, not *.
		$alts = [];
		foreach ( $items as $it ) {
			if ( false !== strpos( $it, '*' ) || false !== strpos( $it, '(' ) || '' === $it ) {
				$why = 'unsupported generic alternate';
				return null;
			}
			$c = self::compile_hex( $it, $wide, false, false, $why );
			if ( null === $c || count( $c['parts'] ) > 1 ) {
				$why = $why ?: 'unsupported generic alternate';
				return null;
			}
			$alts[] = substr( $c['parts'][0]['re'], 1, -2 );
		}
		return '(?:' . implode( '|', $alts ) . ')';
	}

	// ------------------------------------------------------- logical expressions

	/** @return array<int, mixed>|null */
	private static function parse_expr( string $e, int $nsubs ): ?array {
		$e = preg_replace( '/\s+/', '', $e );
		if ( '' === $e || $nsubs < 1 || strlen( $e ) > 1024 ) {
			return null;
		}
		$pos   = 0;
		$depth = 0;
		$p_or  = null;
		$num   = static function () use ( &$pos, $e ): ?int {
			if ( ! preg_match( '/\G\d{1,9}/', $e, $m, 0, $pos ) ) {
				return null;
			}
			$pos += strlen( $m[0] );
			return (int) $m[0];
		};
		$p_prim = static function () use ( &$pos, &$p_or, &$depth, $e, $num, $nsubs ) {
			if ( $pos >= strlen( $e ) ) {
				return null;
			}
			if ( '(' === $e[ $pos ] ) {
				if ( ++$depth > 32 ) {
					return null;
				}
				++$pos;
				$n = $p_or();
				if ( null === $n || $pos >= strlen( $e ) || ')' !== $e[ $pos ] ) {
					return null;
				}
				++$pos;
				--$depth;
				return $n;
			}
			$i = $num();
			return ( null === $i || $i >= $nsubs ) ? null : [ 'n', $i ];
		};
		$p_mod = static function () use ( &$pos, $e, $num, $p_prim ) {
			$n = $p_prim();
			if ( null === $n ) {
				return null;
			}
			if ( $pos < strlen( $e ) && false !== strpos( '=<>', $e[ $pos ] ) ) {
				$op = $e[ $pos++ ];
				$x  = $num();
				if ( null === $x ) {
					return null;
				}
				$y = null;
				if ( $pos < strlen( $e ) && ',' === $e[ $pos ] ) {
					++$pos;
					$y = $num();
					if ( null === $y ) {
						return null;
					}
				}
				return [ 'mod', $n, $op, $x, $y ];
			}
			return $n;
		};
		$p_and = static function () use ( &$pos, $e, $p_mod ) {
			$kids = [ $p_mod() ];
			while ( null !== $kids[0] && $pos < strlen( $e ) && '&' === $e[ $pos ] ) {
				++$pos;
				$k = $p_mod();
				if ( null === $k ) {
					return null;
				}
				$kids[] = $k;
			}
			return null === $kids[0] ? null : ( 1 === count( $kids ) ? $kids[0] : [ 'and', $kids ] );
		};
		$p_or = static function () use ( &$pos, $e, $p_and ) {
			$kids = [ $p_and() ];
			while ( null !== $kids[0] && $pos < strlen( $e ) && '|' === $e[ $pos ] ) {
				++$pos;
				$k = $p_and();
				if ( null === $k ) {
					return null;
				}
				$kids[] = $k;
			}
			return null === $kids[0] ? null : ( 1 === count( $kids ) ? $kids[0] : [ 'or', $kids ] );
		};
		$ast = $p_or();
		return ( null !== $ast && $pos === strlen( $e ) ) ? $ast : null;
	}

	/**
	 * @param array<int, mixed> $n
	 * @param int[]             $counts
	 * @return array{0:bool,1:int,2:array<int,bool>}
	 */
	private static function eval_expr( array $n, array $counts ): array {
		switch ( $n[0] ) {
			case 'n':
				$c = $counts[ $n[1] ] ?? 0;
				return [ $c > 0, $c, $c > 0 ? [ $n[1] => true ] : [] ];
			case 'and':
			case 'or':
				$ok = 'and' === $n[0];
				$cn = 0;
				$d  = [];
				foreach ( $n[1] as $k ) {
					[ $b, $c, $dk ] = self::eval_expr( $k, $counts );
					$ok             = 'and' === $n[0] ? ( $ok && $b ) : ( $ok || $b );
					$cn            += $c;
					$d             += $dk;
				}
				return [ $ok, $cn, $d ];
			default: // mod
				[ , $child, $op, $x, $y ] = $n;
				[ , $c, $d ]              = self::eval_expr( $child, $counts );
				$ok                        = '=' === $op ? $c === $x : ( '>' === $op ? $c > $x : $c < $x );
				if ( null !== $y ) {
					$ok = $ok && count( $d ) >= $y;
				}
				return [ $ok, $c, $d ];
		}
	}

	// ----------------------------------------------------------------- scanning

	/** Lower-case and collapse whitespace (target 7); HTML comments are also dropped (target 3). */
	public static function normalize( string $data, string $mode ): string {
		if ( 'n3' === $mode ) {
			$d = preg_replace( '/<!--.*?-->/s', '', $data );
			$data = is_string( $d ) ? $d : $data;
		}
		$data = strtr( $data, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz' );
		$d    = preg_replace( '/[ \t\r\n\f\v]+/', ' ', $data );
		return trim( is_string( $d ) ? $d : $data );
	}

	/** Names reported but never removed. */
	public static function is_report_only( string $name ): bool {
		foreach ( self::REPORT_ONLY_PREFIXES as $p ) {
			if ( 0 === strpos( $name, $p ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Scan one file. Returns the first match, or null.
	 *
	 * @param array<string, mixed> $db Loaded with load().
	 * @return array{name:string,kind:string,sha256:string}|null kind is hash, ndb or ldb; sha256 is of the bytes scanned
	 */
	public static function scan_file( array $db, string $path ): ?array {
		$size = @filesize( $path );
		if ( false === $size || is_link( $path ) ) {
			return null;
		}
		$hashes = [];
		$want   = [];
		foreach ( [ 'md5' => 'md5', 'sha1' => 'sha1', 'sha256' => 'sha256' ] as $k => $algo ) {
			if ( $db['hash'][ $k ] || $db['fp'][ $k ] ) {
				$want[ $k ] = $algo;
			}
		}
		if ( $want && $size <= self::MAX_HASH_BYTES ) {
			foreach ( $want as $k => $algo ) {
				$h = @hash_file( $algo, $path );
				if ( is_string( $h ) ) {
					$hashes[ $k ] = $h;
				}
			}
		}
		foreach ( $hashes as $k => $h ) {
			if ( isset( $db['fp'][ $k ][ $h ] ) && ( isset( $db['fp'][ $k ][ $h ][ (string) $size ] ) || isset( $db['fp'][ $k ][ $h ]['*'] ) ) ) {
				return null; // listed as a known-clean file
			}
		}
		foreach ( $hashes as $k => $h ) {
			$hit = $db['hash'][ $k ][ $h ] ?? null;
			if ( null !== $hit ) {
				$name = $hit[ (string) $size ] ?? ( $hit['*'] ?? null );
				if ( null !== $name ) {
					return [ 'name' => $name, 'kind' => 'hash', 'sha256' => $hashes['sha256'] ?? (string) @hash_file( 'sha256', $path ) ];
				}
			}
		}
		if ( ! $db['body'] || $size > self::MAX_SCAN_BYTES || $size < 1 ) {
			return null;
		}
		$data = @file_get_contents( $path );
		$hit  = is_string( $data ) ? self::scan_data( $db, $data ) : null;
		if ( null !== $hit ) {
			$hit['sha256'] = hash( 'sha256', $data );
		}
		return $hit;
	}

	/**
	 * Match the body signatures against a string.
	 *
	 * @param array<string, mixed> $db
	 * @return array{name:string,kind:string}|null
	 */
	public static function scan_data( array $db, string $data, float $budget = self::MAX_FILE_SECS ): ?array {
		$raw_len  = strlen( $data );
		$deadline = microtime( true ) + $budget;
		self::$deadline = $deadline; // 1.4.155: count_variant() honours the same budget
		foreach ( [ 'raw', 'n7', 'n3' ] as $variant ) {
			if ( empty( $db['variants'][ $variant ] ) ) {
				continue;
			}
			$subject = 'raw' === $variant ? $data : self::normalize( $data, $variant );
			$lower   = ( 'raw' === $variant && $db['gram_ci']['raw'] ) ? strtr( $data, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz' ) : $subject;
			$cand    = [];
			foreach ( [ [ 'gram', $subject ], [ 'gram_ci', $lower ] ] as [ $bucket, $text ] ) {
				$index = $db[ $bucket ][ $variant ];
				if ( ! $index ) {
					continue;
				}
				// 1.4.153: the "seen" set holds only grams the index knows, so it is bounded by the
				// database rather than the file (one entry per distinct gram of a 1 MiB high-entropy
				// file took about 70 MB), while a common indexed gram still merges its bucket once.
				$seen = [];
				$len  = strlen( $text ) - 2;
				for ( $i = 0; $i < $len; $i++ ) {
					$g = substr( $text, $i, 3 );
					if ( isset( $index[ $g ] ) && ! isset( $seen[ $g ] ) ) {
						$seen[ $g ] = true;
						$cand      += $index[ $g ];
					}
				}
			}
			ksort( $cand );
			foreach ( array_keys( $cand ) as $id ) {
				// A database full of signatures with wide ranged gaps could otherwise hold one file for a
				// long time: past the budget the remaining signatures are not tried on this file.
				if ( microtime( true ) > $deadline ) {
					return null;
				}
				$sig = $db['body'][ $id ];
				if ( null !== $sig['size'] && ( $raw_len < $sig['size'][0] || $raw_len > $sig['size'][1] ) ) {
					continue;
				}
				$counts = [];
				foreach ( $sig['subs'] as $k => $sub ) {
					$counts[ $k ] = self::count_sub( $sub, $subject, $lower );
				}
				if ( self::eval_expr( $sig['expr'], $counts )[0] ) {
					return [ 'name' => $sig['name'], 'kind' => $sig['kind'] ];
				}
			}
		}
		return null;
	}

	/** @param array<string, mixed> $sub */
	private static function count_sub( array $sub, string $subject, string $lower ): int {
		$total = 0;
		foreach ( $sub['variants'] as $v ) {
			$hay = $sub['ci'] ? $lower : $subject;
			if ( false === strpos( $hay, $v['lit'] ) ) {
				continue;
			}
			$total += self::count_variant( $v, $sub['offset'], $subject );
		}
		return $total;
	}

	/**
	 * @param array<string, mixed> $v
	 * @param array{0:string,1:int,2:int} $off
	 */
	/** The current scan_data() deadline, for the loops below it (1.4.155). */
	private static $deadline = 0.0;

	private static function count_variant( array $v, array $off, string $data ): int {
		$dlen = strlen( $data );
		if ( 1 === count( $v['parts'] ) && 'any' === $off[0] ) {
			$r = @preg_match_all( $v['parts'][0]['re'], $data );
			return false === $r ? 0 : $r;
		}
		$count = 0;
		$from  = 0;
		for ( $round = 0; $round < 4096; $round++ ) { // 1.4.155: was 64, which misjudged counts such as =65
			if ( 0 === ( $round & 63 ) && $round > 0 && self::$deadline > 0 && microtime( true ) > self::$deadline ) {
				return $count; // out of time: the scan's own deadline check reports it
			}
			$pos   = $from;
			$first = -1;
			$end   = -1;
			foreach ( $v['parts'] as $k => $part ) {
				$m = [];
				if ( 0 === $k && 'any' !== $off[0] ) {
					$at = 'eof' === $off[0] ? max( 0, $dlen - $off[1] ) : $off[1];
					$at = max( $at, $from );
					if ( $at > $dlen ) {
						return $count;
					}
					$re = 0 === $off[2] ? '/\\G' . substr( $part['re'], 1 ) : $part['re'];
					$r  = @preg_match( $re, $data, $m, PREG_OFFSET_CAPTURE, $at );
					if ( 1 !== $r || ( $off[2] > 0 && $m[0][1] > $at + $off[2] ) ) {
						return $count;
					}
				} else {
					if ( $pos > $dlen ) {
						return $count;
					}
					$r = @preg_match( $part['re'], $data, $m, PREG_OFFSET_CAPTURE, $pos );
					if ( 1 !== $r ) {
						return $count;
					}
				}
				if ( 0 === $k ) {
					$first = $m[0][1];
				}
				$end = $m[0][1] + strlen( $m[0][0] );
				$pos = $end + ( $v['gaps'][ $k ] ?? 0 );
			}
			++$count;
			if ( 'any' !== $off[0] || $end <= $first ) {
				return $count; // an offset signature counts once
			}
			$from = $end;
		}
		return $count;
	}

	// ------------------------------------------------------------------- status

	/**
	 * What a folder holds, for the settings screen and the diagnostics.
	 *
	 * @return array<string, mixed>
	 */
	public static function status( string $dir ): array {
		$db = self::load( $dir );
		return [
			'dir'           => $db['dir'],
			'exists'        => is_dir( $db['dir'] ),
			'files'         => $db['counts']['files'],
			'hash'          => $db['counts']['hash'],
			'ndb'           => $db['counts']['ndb'],
			'ldb'           => $db['counts']['ldb'],
			'fp'            => $db['counts']['fp'],
			'ignored'       => $db['counts']['ign'],
			'skipped'       => $db['counts']['skipped'],
			'rejected'      => $db['counts']['rejected'],
			'errors'        => $db['errors'],
			'skipped_files' => $db['skipped_files'],
			'usable'        => ( $db['counts']['hash'] + $db['counts']['ndb'] + $db['counts']['ldb'] ) > 0,
		];
	}
}
