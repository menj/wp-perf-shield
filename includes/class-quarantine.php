<?php
/**
 * WP Perf Shield - Quarantine store.
 *
 * Remediation moves a malicious file or directory here instead of destroying it:
 * the threat leaves the live path (so it can no longer execute or be served),
 * every file is neutralised by appending a `.wpsq` suffix (nothing runs as PHP,
 * and no content/structure detector matches), a JSON manifest records what came
 * from where, and the entry is restorable for a retention window before it is
 * purged. This makes auto-remediation reversible and preserves forensic evidence.
 *
 * The store lives at wp-content/wps-quarantine so it survives plugin reinstalls,
 * is hardened against web execution, and is excluded from the scanners.
 *
 * @package WP_Perf_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPS_Quarantine {

	const RETENTION_DAYS = 30;
	const SUFFIX         = '.wpsq';

	/** Absolute path to the quarantine store. */
	public static function store_dir(): string {
		return rtrim( str_replace( '\\', '/', WP_CONTENT_DIR ), '/' ) . '/wps-quarantine';
	}

	/**
	 * True when $path is the store or lives inside it. Used by the scanners to
	 * skip the store, and by quarantine() to avoid re-quarantining.
	 */
	public static function is_quarantine_path( string $path ): bool {
		$store = str_replace( '\\', '/', self::store_dir() );
		$real  = realpath( $path );
		$norm  = $real ? str_replace( '\\', '/', $real ) : rtrim( str_replace( '\\', '/', $path ), '/' );
		return $norm === $store || strpos( $norm, $store . '/' ) === 0;
	}

	/** Paths that must never be moved into quarantine. */
	private static function protected_paths(): array {
		$candidates = [
			ABSPATH,
			WP_CONTENT_DIR,
			defined( 'WP_PLUGIN_DIR' ) ? WP_PLUGIN_DIR : ABSPATH . 'wp-content/plugins',
			defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : '',
			ABSPATH . 'wp-admin',
			ABSPATH . 'wp-includes',
			defined( 'WPS_DIR' ) ? WPS_DIR : '',
			self::store_dir(),
		];
		if ( function_exists( 'get_theme_root' ) ) {
			$candidates[] = get_theme_root();
		}
		$out = [];
		foreach ( $candidates as $c ) {
			if ( ! $c ) {
				continue;
			}
			$r = realpath( $c );
			if ( $r ) {
				$out[] = str_replace( '\\', '/', $r );
			}
		}
		return array_unique( $out );
	}

	/**
	 * A target is quarantinable only if it resolves, lives inside ABSPATH, is not
	 * the store, and is neither a protected path nor an ancestor of one (so we can
	 * never move a directory that contains wp-admin, the active theme, etc.).
	 */
	private static function is_quarantinable( string $real ): bool {
		$real = str_replace( '\\', '/', $real );
		$abs  = realpath( ABSPATH );
		if ( ! $abs ) {
			return false;
		}
		$abs = str_replace( '\\', '/', $abs );
		if ( strpos( $real . '/', $abs . '/' ) !== 0 ) {
			return false; // outside the install
		}
		if ( self::is_quarantine_path( $real ) ) {
			return false;
		}
		foreach ( self::protected_paths() as $p ) {
			if ( $real === $p ) {
				return false; // IS a protected path
			}
			if ( strpos( $p . '/', $real . '/' ) === 0 ) {
				return false; // target is an ancestor of a protected path
			}
		}
		return true;
	}

	/** Create and harden the store. */
	private static function ensure_store(): bool {
		$dir = self::store_dir();
		if ( ! is_dir( $dir ) ) {
			if ( ! @mkdir( $dir, 0755, true ) && ! is_dir( $dir ) ) {
				return false;
			}
		}
		$ht = $dir . '/.htaccess';
		if ( ! is_file( $ht ) ) {
			@file_put_contents( $ht, "Require all denied\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\nphp_flag engine off\n" );
		}
		$idx = $dir . '/index.php';
		if ( ! is_file( $idx ) ) {
			@file_put_contents( $idx, "<?php // Silence is golden.\n" );
		}
		return is_dir( $dir ) && is_writable( $dir );
	}

	/**
	 * Move a malicious file or directory into quarantine.
	 *
	 * @param string $path Absolute path to the offending file or directory.
	 * @param array  $meta Extra manifest fields (finding type, severity, ...).
	 * @return string|null Quarantine id on success, null on refusal/failure.
	 */
	public static function quarantine( string $path, array $meta = [], bool $move = true ): ?string {
		$real = realpath( $path );
		if ( ! $real || ! file_exists( $real ) ) {
			return null;
		}
		if ( ! self::is_quarantinable( $real ) ) {
			self::log( 'quarantine_refused', $real );
			return null;
		}
		if ( ! self::ensure_store() ) {
			return null;
		}

		$is_dir = is_dir( $real );
		$sha    = ! $is_dir ? ( @hash_file( 'sha256', $real ) ?: '' ) : '';
		$id     = gmdate( 'Ymd-His' ) . '-' . substr( md5( $real . microtime( true ) ), 0, 8 );
		$dest   = self::store_dir() . '/' . $id;
		if ( ! @mkdir( $dest, 0755, true ) && ! is_dir( $dest ) ) {
			return null;
		}
		$payload = $dest . '/payload';

		// Move the item under payload/. For a single file, payload/ is a folder
		// holding that one file; for a directory, payload/ IS the moved tree.
		// $move === false copies instead of moving: used for pre-clean backups,
		// where the live file must stay in place to receive its cleaned bytes
		// while the pre-clean (possibly infected) snapshot is captured here.
		$moved = false;
		if ( $is_dir ) {
			$moved = $move ? self::move( $real, $payload ) : self::rcopy( $real, $payload );
		} else {
			if ( @mkdir( $payload, 0755, true ) || is_dir( $payload ) ) {
				$dst   = $payload . '/' . basename( $real );
				$moved = $move ? self::move( $real, $dst ) : @copy( $real, $dst );
			}
		}
		if ( ! $moved ) {
			self::rrmdir( $dest );
			return null;
		}

		// Neutralise every file so nothing can execute and no detector matches.
		$rel_files = [];
		self::neutralise( $payload, $payload, $rel_files );

		$manifest = array_merge(
			[
				'id'               => $id,
				'original_path'    => $real,
				'kind'             => $is_dir ? 'dir' : 'file',
				'basename'         => basename( $real ),
				'files'            => $rel_files, // relative paths WITHOUT the .wpsq suffix
				'sha256'           => $sha,
				'quarantined_at'   => time(),
				'restorable_until' => time() + ( self::RETENTION_DAYS * 86400 ),
				'stored_by'        => self::current_user_login(),
			],
			$meta
		);
		@file_put_contents( $dest . '/manifest.json', wp_json_encode( $manifest ) );
		self::log( 'quarantined', $real . ' -> ' . $id );
		return $id;
	}

	/**
	 * Restore a quarantined entry to its original path. Refuses if the original
	 * path is occupied again (never overwrite a live file).
	 */
	public static function restore( string $id ): bool {
		$dest     = self::entry_dir( $id );
		$manifest = $dest ? self::read_manifest( $dest ) : null;
		if ( ! $manifest || empty( $manifest['original_path'] ) ) {
			return false;
		}

		// Option snapshots carry no filesystem payload: write the value back.
		if ( ( $manifest['kind'] ?? '' ) === 'option' ) {
			$name = (string) ( $manifest['option_name'] ?? '' );
			if ( $name === '' || ! function_exists( 'update_option' ) ) {
				return false;
			}
			$b64      = (string) ( $manifest['option_value_b64'] ?? '' );
			$value    = '';
			if ( $b64 !== '' ) {
				// allowed_classes=false: never instantiate objects from a stored
				// (formerly malicious) option value during recovery.
				$value = @unserialize( base64_decode( $b64 ), [ 'allowed_classes' => false ] );
			}
			$autoload = ( $manifest['option_autoload'] ?? 'yes' ) === 'no' ? false : true;
			update_option( $name, $value, $autoload );
			self::rrmdir( $dest );
			self::log( 'option_restored', $name . ' <- ' . $id );
			return true;
		}

		$payload = $dest . '/payload';
		if ( ! is_dir( $payload ) ) {
			return false;
		}
		$original = $manifest['original_path'];
		if ( file_exists( $original ) ) {
			self::log( 'quarantine_restore_blocked_exists', $original );
			return false;
		}

		// Reverse the neutralisation in place, then move the payload back.
		self::denormalise( $payload );

		$ok = false;
		if ( ( $manifest['kind'] ?? '' ) === 'dir' ) {
			$ok = self::move( $payload, $original );
		} else {
			$src = $payload . '/' . ( $manifest['basename'] ?? basename( $original ) );
			$ok  = is_file( $src ) && self::move( $src, $original );
		}
		if ( $ok ) {
			self::rrmdir( $dest );
			self::log( 'quarantine_restored', $original . ' <- ' . $id );
		}
		return $ok;
	}

	/**
	 * Snapshot a wp_options row into the store before it is deleted, so a
	 * removed DB payload stays recoverable and available for later analysis
	 * rather than vanishing on delete_option(). kind=option entries carry the
	 * serialised value in the manifest (no filesystem payload) and restore by
	 * writing the value back with update_option().
	 */
	public static function quarantine_option( string $name, array $meta = [] ): ?string {
		if ( $name === '' || ! function_exists( 'get_option' ) ) {
			return null;
		}
		$value = get_option( $name, null );
		if ( $value === null ) {
			return null; // nothing stored under this key
		}
		if ( ! self::ensure_store() ) {
			return null;
		}

		$id   = gmdate( 'Ymd-His' ) . '-' . substr( md5( $name . microtime( true ) ), 0, 8 );
		$dest = self::store_dir() . '/' . $id;
		if ( ! @mkdir( $dest, 0755, true ) && ! is_dir( $dest ) ) {
			return null;
		}

		$serialized = serialize( $value );
		$manifest   = array_merge(
			[
				'id'               => $id,
				'kind'             => 'option',
				'option_name'      => $name,
				'option_autoload'  => self::option_autoload( $name ),
				'option_value_b64' => base64_encode( $serialized ),
				'sha256'           => hash( 'sha256', $serialized ),
				'original_path'    => '(wp_options) ' . $name,
				'basename'         => $name,
				'quarantined_at'   => time(),
				'restorable_until' => time() + ( self::RETENTION_DAYS * 86400 ),
				'stored_by'        => self::current_user_login(),
			],
			$meta
		);
		@file_put_contents( $dest . '/manifest.json', wp_json_encode( $manifest ) );
		self::log( 'option_quarantined', $name . ' -> ' . $id );
		return $id;
	}

	/** Best-effort autoload flag for an option; defaults to 'yes' when unknown. */
	private static function option_autoload( string $name ): string {
		if ( isset( $GLOBALS['wpdb'] ) && is_object( $GLOBALS['wpdb'] ) ) {
			$wpdb = $GLOBALS['wpdb'];
			try {
				$val = $wpdb->get_var( $wpdb->prepare( "SELECT autoload FROM {$wpdb->options} WHERE option_name = %s LIMIT 1", $name ) );
				if ( $val === 'no' || $val === 'off' ) {
					return 'no';
				}
				if ( $val === 'yes' || $val === 'on' ) {
					return 'yes';
				}
			} catch ( \Throwable $e ) {}
		}
		return 'yes';
	}

	/** Login of the user driving the current action, or a system marker. */
	private static function current_user_login(): string {
		if ( function_exists( 'wp_get_current_user' ) ) {
			$u = wp_get_current_user();
			if ( $u && ! empty( $u->user_login ) ) {
				return (string) $u->user_login;
			}
		}
		if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
			return '(cron)';
		}
		return '(system)';
	}

	/** List quarantine entries (manifest data), newest first. */
	public static function list_entries(): array {
		$store = self::store_dir();
		if ( ! is_dir( $store ) ) {
			return [];
		}
		$out = [];
		foreach ( (array) @scandir( $store ) as $name ) {
			if ( $name === '.' || $name === '..' ) {
				continue;
			}
			$dir = $store . '/' . $name;
			if ( ! is_dir( $dir ) ) {
				continue;
			}
			$m = self::read_manifest( $dir );
			if ( $m ) {
				$out[] = $m;
			}
		}
		usort( $out, static function ( $a, $b ) {
			return ( $b['quarantined_at'] ?? 0 ) <=> ( $a['quarantined_at'] ?? 0 );
		} );
		return $out;
	}

	/** Permanently delete one entry. */
	public static function purge( string $id ): bool {
		$dir = self::entry_dir( $id );
		if ( ! $dir ) {
			return false;
		}
		$ok = self::rrmdir( $dir );
		if ( $ok ) {
			self::log( 'quarantine_purged', $id );
		}
		return $ok;
	}

	/** Delete every entry past its retention window. Returns count purged. */
	public static function purge_expired(): int {
		$n = 0;
		foreach ( self::list_entries() as $m ) {
			if ( ! empty( $m['restorable_until'] ) && time() > (int) $m['restorable_until'] && ! empty( $m['id'] ) ) {
				if ( self::purge( (string) $m['id'] ) ) {
					$n++;
				}
			}
		}
		return $n;
	}

	/** Empty the entire store (keeps the hardened store dir + guards). */
	public static function purge_all(): int {
		$n = 0;
		foreach ( self::list_entries() as $m ) {
			if ( ! empty( $m['id'] ) && self::purge( (string) $m['id'] ) ) {
				$n++;
			}
		}
		return $n;
	}

	// --- internals -----------------------------------------------------------

	private static function entry_dir( string $id ): ?string {
		if ( $id === '' || ! preg_match( '/^[0-9]{8}-[0-9]{6}-[0-9a-f]{8}$/', $id ) ) {
			return null;
		}
		$dir = self::store_dir() . '/' . $id;
		return is_dir( $dir ) ? $dir : null;
	}

	private static function read_manifest( string $dir ): ?array {
		$f = $dir . '/manifest.json';
		if ( ! is_file( $f ) ) {
			return null;
		}
		$data = json_decode( (string) @file_get_contents( $f ), true );
		return is_array( $data ) ? $data : null;
	}

	/** Append the neutralising suffix to every file under $dir (recursively). */
	private static function neutralise( string $dir, string $base, array &$rel_files ): void {
		foreach ( (array) @scandir( $dir ) as $name ) {
			if ( $name === '.' || $name === '..' ) {
				continue;
			}
			$path = $dir . '/' . $name;
			if ( is_dir( $path ) ) {
				self::neutralise( $path, $base, $rel_files );
			} elseif ( is_file( $path ) ) {
				$rel         = ltrim( substr( $path, strlen( $base ) ), '/' );
				$rel_files[] = $rel;
				@rename( $path, $path . self::SUFFIX );
			}
		}
	}

	/** Strip the neutralising suffix from every file under $dir (recursively). */
	private static function denormalise( string $dir ): void {
		foreach ( (array) @scandir( $dir ) as $name ) {
			if ( $name === '.' || $name === '..' ) {
				continue;
			}
			$path = $dir . '/' . $name;
			if ( is_dir( $path ) ) {
				self::denormalise( $path );
			} elseif ( is_file( $path ) && substr( $path, -strlen( self::SUFFIX ) ) === self::SUFFIX ) {
				@rename( $path, substr( $path, 0, -strlen( self::SUFFIX ) ) );
			}
		}
	}

	/** rename() with a copy+delete fallback for cross-device moves. */
	private static function move( string $src, string $dst ): bool {
		if ( @rename( $src, $dst ) ) {
			return true;
		}
		if ( is_dir( $src ) ) {
			if ( ! self::rcopy( $src, $dst ) ) {
				return false;
			}
			return self::rrmdir( $src );
		}
		if ( @copy( $src, $dst ) ) {
			return @unlink( $src );
		}
		return false;
	}

	private static function rcopy( string $src, string $dst ): bool {
		if ( ! is_dir( $dst ) && ! @mkdir( $dst, 0755, true ) && ! is_dir( $dst ) ) {
			return false;
		}
		foreach ( (array) @scandir( $src ) as $name ) {
			if ( $name === '.' || $name === '..' ) {
				continue;
			}
			$s = $src . '/' . $name;
			$d = $dst . '/' . $name;
			if ( is_dir( $s ) ) {
				if ( ! self::rcopy( $s, $d ) ) {
					return false;
				}
			} elseif ( ! @copy( $s, $d ) ) {
				return false;
			}
		}
		return true;
	}

	private static function rrmdir( string $dir ): bool {
		if ( ! is_dir( $dir ) ) {
			return false;
		}
		foreach ( (array) @scandir( $dir ) as $name ) {
			if ( $name === '.' || $name === '..' ) {
				continue;
			}
			$p = $dir . '/' . $name;
			if ( is_dir( $p ) ) {
				self::rrmdir( $p );
			} else {
				@unlink( $p );
			}
		}
		return @rmdir( $dir );
	}

	private static function log( string $event, string $subject ): void {
		if ( class_exists( 'WPS_Logger' ) ) {
			WPS_Logger::log_event( $event, $subject );
		}
	}
}
