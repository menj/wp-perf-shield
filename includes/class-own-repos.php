<?php
/**
 * The operator's own repositories (1.4.158).
 *
 * The operator writes plugins and themes, publishes them on GitHub, and uploads them to the site.
 * The scanner, which has no baseline for code that was never on wordpress.org, kept reporting them:
 * a hidden folder here, a self-concealing pattern there, "cannot be checksum-verified" every scan.
 * Declaring a folder first-party (1.4.11) silenced one report and left the rest.
 *
 * This is the baseline that was missing. The operator names the GitHub accounts that are theirs;
 * for every installed plugin or theme whose folder name is a repository under one of those
 * accounts, the repository's file tree (one API call, cached for six hours) becomes the manifest,
 * and each file is verified the way git itself identifies it: the blob hash of its content. A file
 * identical to the repository is the operator's own work and no finding against it is reported; a
 * file that differs is MODIFIED and a file the repository does not know is FOREIGN, and both keep
 * every finding they earn, because "my own plugin" is exactly where an intruder adds a file.
 *
 * Nothing here trusts a header. A dropped plugin that claims to be the operator's would have to be
 * byte for byte what the operator published.
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPS_Own_Repos {

	const TTL           = 6 * 3600;        // tree cache
	const BACKOFF       = 3600;            // after GitHub refuses for rate limiting
	const MAX_REQUESTS  = 25;              // per process: GitHub allows sixty an hour without a token
	const MAX_SECONDS   = 30.0;            // per process, spent waiting on GitHub; a scan has its own budget
	const TIMEOUT       = 6;               // per request
	const MAX_FILE      = 8 * 1024 * 1024; // larger files are not hashed
	const TREE_API      = 'https://api.github.com/repos/%s/%s/git/trees/HEAD?recursive=1';

	/** Trees already resolved this process, by owner/slug; null for a miss or a failure. @var array<string, array|null> */
	private static $trees = [];

	/** Requests made this process, and seconds spent waiting on them. */
	private static $requests = 0;
	private static $spent    = 0.0;

	/** Forget the per-process memo (a scan calls this when it finishes). */
	public static function reset(): void {
		self::$trees    = [];
		self::$requests = 0;
		self::$spent    = 0.0;
	}

	/**
	 * May another request be made now? Not past the request or time budget, not while GitHub has
	 * asked for a pause, and not once the scan itself is out of time.
	 */
	public static function may_request(): bool {
		if ( self::$requests >= self::MAX_REQUESTS || self::$spent >= self::MAX_SECONDS ) {
			return false;
		}
		if ( get_transient( 'wps_gh_backoff' ) ) {
			return false;
		}
		if ( class_exists( 'WPS_Scanner' ) && method_exists( 'WPS_Scanner', 'out_of_time' ) && WPS_Scanner::out_of_time() ) {
			return false;
		}
		return true;
	}

	// ---------------------------------------------------------------
	//  Settings
	// ---------------------------------------------------------------

	/** @return string[] GitHub account names the operator declared as their own. */
	public static function owners(): array {
		$s   = get_option( WPS_OPTION, [] );
		$raw = is_array( $s ) ? (string) ( $s['own_repo_owners'] ?? '' ) : '';
		return self::parse_owners( $raw );
	}

	/** @return string[] */
	public static function parse_owners( string $raw ): array {
		$out = [];
		foreach ( preg_split( '/[\s,]+/', $raw ) ?: [] as $o ) {
			$o = trim( $o, "/ \t" );
			// A pasted profile URL is fine: the last path segment is the account.
			if ( false !== strpos( $o, 'github.com/' ) ) {
				$o = trim( (string) substr( $o, strpos( $o, 'github.com/' ) + 11 ), '/' );
				$o = (string) strtok( $o, '/' );
			}
			if ( '' !== $o && preg_match( '/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/', $o ) ) {
				$out[ strtolower( $o ) ] = $o;
			}
		}
		return array_values( $out );
	}

	/** A token for private repositories, or ''. */
	public static function token(): string {
		$s = get_option( WPS_OPTION, [] );
		return is_array( $s ) ? trim( (string) ( $s['own_repo_token'] ?? '' ) ) : '';
	}

	public static function enabled(): bool {
		return [] !== self::owners();
	}

	// ---------------------------------------------------------------
	//  Which folder is which repository
	// ---------------------------------------------------------------

	/**
	 * The slug (folder name) and kind of the plugin or theme a path belongs to, or null.
	 *
	 * @return array{slug: string, kind: string, root: string}|null
	 */
	public static function package_of( string $path ): ?array {
		$real = realpath( $path );
		$real = str_replace( '\\', '/', is_string( $real ) ? $real : $path );
		foreach ( self::roots() as $kind => $root ) {
			if ( 0 === strpos( $real, $root . '/' ) ) {
				$rel  = substr( $real, strlen( $root ) + 1 );
				$slug = (string) strtok( $rel, '/' );
				if ( '' !== $slug && is_dir( $root . '/' . $slug ) ) {
					return [ 'slug' => $slug, 'kind' => $kind, 'root' => $root ];
				}
			}
		}
		return null;
	}

	/** @return array<string, string> kind => real root path, forward slashes, no trailing slash */
	public static function roots(): array {
		$roots = [];
		if ( defined( 'WP_PLUGIN_DIR' ) ) {
			$r = realpath( WP_PLUGIN_DIR );
			if ( is_string( $r ) ) {
				$roots['plugin'] = str_replace( '\\', '/', rtrim( $r, '/\\' ) );
			}
		}
		if ( function_exists( 'get_theme_root' ) ) {
			$r = realpath( (string) get_theme_root() );
			if ( is_string( $r ) ) {
				$roots['theme'] = str_replace( '\\', '/', rtrim( $r, '/\\' ) );
			}
		}
		return $roots;
	}

	/**
	 * The manifest for a slug from the operator's repositories: path => [type, hashes], or null when
	 * no declared account has a repository of that name (or it could not be read).
	 *
	 * @return array<string, array{type: string, hashes: string[]}>|null
	 */
	public static function manifest_for( string $slug ): ?array {
		if ( '' === $slug || ! preg_match( '/^[A-Za-z0-9._-]{1,100}$/', $slug ) ) {
			return null;
		}
		foreach ( self::owners() as $owner ) {
			$m = self::tree( $owner, $slug );
			if ( is_array( $m ) ) {
				return $m;
			}
		}
		return null;
	}

	/** The owner whose repository verified this slug, or ''. */
	public static function owner_of( string $slug ): string {
		foreach ( self::owners() as $owner ) {
			if ( is_array( self::tree( $owner, $slug ) ) ) {
				return $owner;
			}
		}
		return '';
	}

	/**
	 * The repository's file tree as a manifest, cached six hours. A missing or unusable repository
	 * is also cached (as 'none'); a transport failure or a refusal is remembered for this process
	 * only, so one scan asks once and the next scan retries. A rate-limit refusal stops all
	 * requests for an hour, and a process never makes more than MAX_REQUESTS.
	 *
	 * @return array<string, array{type: string, hashes: string[]}>|null
	 */
	public static function tree( string $owner, string $slug ): ?array {
		$memo = $owner . '/' . $slug;
		if ( array_key_exists( $memo, self::$trees ) ) {
			return self::$trees[ $memo ];
		}
		$key    = 'wps_gh_' . md5( $memo );
		$cached = get_transient( $key );
		if ( is_array( $cached ) ) {
			return self::$trees[ $memo ] = $cached;
		}
		if ( 'none' === $cached ) {
			return self::$trees[ $memo ] = null;
		}
		if ( ! function_exists( 'wp_remote_get' ) || ! self::may_request() ) {
			return self::$trees[ $memo ] = null;
		}
		++self::$requests;
		$headers = [ 'Accept' => 'application/vnd.github+json', 'User-Agent' => 'WP-Perf-Shield' ];
		$token   = self::token();
		if ( '' !== $token ) {
			$headers['Authorization'] = 'Bearer ' . $token;
		}
		$t0   = microtime( true );
		$resp = wp_remote_get( sprintf( self::TREE_API, rawurlencode( $owner ), rawurlencode( $slug ) ), [ 'timeout' => self::TIMEOUT, 'redirection' => 2, 'headers' => $headers ] );
		self::$spent += microtime( true ) - $t0;
		if ( ! is_array( $resp ) || ( function_exists( 'is_wp_error' ) && is_wp_error( $resp ) ) ) {
			return self::$trees[ $memo ] = null; // transport failure: not asked again this scan, retried next
		}
		$code = (int) ( function_exists( 'wp_remote_retrieve_response_code' ) ? wp_remote_retrieve_response_code( $resp ) : ( $resp['response']['code'] ?? 0 ) );
		if ( 404 === $code ) {
			set_transient( $key, 'none', self::TTL ); // no such repository under this account
			return self::$trees[ $memo ] = null;
		}
		if ( 403 === $code || 429 === $code ) {
			set_transient( 'wps_gh_backoff', 1, self::BACKOFF ); // rate limited, or a token without access: wait an hour
			return self::$trees[ $memo ] = null;
		}
		if ( 200 !== $code ) {
			return self::$trees[ $memo ] = null; // 401, 5xx: retry next scan
		}
		$body = function_exists( 'wp_remote_retrieve_body' ) ? wp_remote_retrieve_body( $resp ) : ( $resp['body'] ?? '' );
		$m    = self::tree_to_manifest( json_decode( (string) $body, true ) );
		if ( null === $m ) {
			set_transient( $key, 'none', self::TTL ); // truncated (a repository too large to list) or malformed: no basis for a verdict
			return self::$trees[ $memo ] = null;
		}
		set_transient( $key, $m, self::TTL );
		return self::$trees[ $memo ] = $m;
	}

	/**
	 * A git tree listing as a manifest. Pure of side effects.
	 *
	 * @param mixed $json
	 * @return array<string, array{type: string, hashes: string[]}>|null null when truncated or malformed
	 */
	public static function tree_to_manifest( $json ): ?array {
		if ( ! is_array( $json ) || ! isset( $json['tree'] ) || ! is_array( $json['tree'] ) || ! empty( $json['truncated'] ) ) {
			return null;
		}
		$out = [];
		foreach ( $json['tree'] as $entry ) {
			if ( ! is_array( $entry ) || 'blob' !== ( $entry['type'] ?? '' ) ) {
				continue;
			}
			$path = (string) ( $entry['path'] ?? '' );
			$sha  = strtolower( (string) ( $entry['sha'] ?? '' ) );
			if ( '' === $path || ! preg_match( '/^[0-9a-f]{40}$/', $sha ) ) {
				continue;
			}
			$out[ $path ] = [ 'type' => 'gitblob', 'hashes' => [ $sha ] ];
		}
		return $out;
	}

	// ---------------------------------------------------------------
	//  Hashing the way git does
	// ---------------------------------------------------------------

	/**
	 * The git blob id of a file: sha1 of "blob <size>\0" followed by the content. With $normalise,
	 * CRLF line endings are read as LF first, which is what a checkout on Windows does to a
	 * repository that stores LF.
	 */
	public static function git_blob_sha( string $file, bool $normalise = false ): string {
		$content = self::read( $file );
		if ( null === $content ) {
			return '';
		}
		return self::blob_id( $normalise ? str_replace( "\r\n", "\n", $content ) : $content );
	}

	/** The blob id of content. Pure of side effects. */
	public static function blob_id( string $content ): string {
		return sha1( 'blob ' . strlen( $content ) . "\0" . $content );
	}

	/** A file's content, or null when it is missing, unreadable or too large to hash. */
	private static function read( string $file ): ?string {
		if ( ! is_file( $file ) || ! is_readable( $file ) ) {
			return null;
		}
		$size = filesize( $file );
		if ( false === $size || $size > self::MAX_FILE ) {
			return null;
		}
		$content = @file_get_contents( $file );
		return is_string( $content ) ? $content : null;
	}

	/** Does this file's content match one of the git blob ids? Raw first, then with CRLF read as LF. */
	public static function blob_matches( string $file, array $hashes ): bool {
		$content = self::read( $file );
		if ( null === $content ) {
			return false;
		}
		$want = array_map( static fn( $h ) => strtolower( (string) $h ), $hashes );
		$raw  = self::blob_id( $content );
		foreach ( $want as $h ) {
			if ( hash_equals( $h, $raw ) ) {
				return true;
			}
		}
		if ( false === strpos( $content, "\r\n" ) ) {
			return false;
		}
		$norm = self::blob_id( str_replace( "\r\n", "\n", $content ) );
		foreach ( $want as $h ) {
			if ( hash_equals( $h, $norm ) ) {
				return true;
			}
		}
		return false;
	}

	// ---------------------------------------------------------------
	//  Findings against the operator's own code
	// ---------------------------------------------------------------

	/**
	 * Is this path the operator's own, published code? A file: identical to the repository. A
	 * folder: every file in it identical to the repository, PHP or not, since an `.htaccess` or a
	 * `.user.ini` changes what runs as surely as code does. Only the `.git` folder an FTP upload
	 * drags along is not judged.
	 */
	public static function is_own_code( string $path ): bool {
		if ( ! self::enabled() || ! class_exists( 'WPS_Integrity' ) ) {
			return false;
		}
		$pkg = self::package_of( $path );
		if ( null === $pkg || null === self::manifest_for( $pkg['slug'] ) ) {
			return false;
		}
		$real = realpath( $path );
		if ( ! is_string( $real ) ) {
			return false;
		}
		if ( is_file( $real ) ) {
			return WPS_Integrity::VERIFIED === WPS_Integrity::verify( $real );
		}
		if ( ! is_dir( $real ) ) {
			return false;
		}
		$n = 0;
		try {
			$iter = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $real, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::LEAVES_ONLY
			);
			foreach ( $iter as $f ) {
				if ( ! ( $f instanceof SplFileInfo ) || ! $f->isFile() ) {
					continue;
				}
				$p = str_replace( '\\', '/', $f->getPathname() );
				if ( false !== strpos( $p, '/.git/' ) ) {
					continue;
				}
				if ( ++$n > 4000 ) {
					return false;
				}
				if ( WPS_Integrity::VERIFIED !== WPS_Integrity::verify( $p ) ) {
					return false;
				}
			}
		} catch ( \Throwable $t ) {
			return false;
		}
		return $n > 0;
	}

	/**
	 * Drop the findings that point at the operator's own, verified code, and say so once per
	 * folder in the log. Findings with no path, findings on files that differ from the repository,
	 * and findings that enforce the site's own policy (a banned plugin is banned whoever wrote it)
	 * stay.
	 *
	 * @param array<int, array<string, mixed>> $findings
	 * @return array<int, array<string, mixed>>
	 */
	public static function filter_findings( array $findings ): array {
		if ( ! self::enabled() ) {
			return $findings;
		}
		$kept    = [];
		$dropped = [];
		foreach ( $findings as $f ) {
			if ( self::is_policy_finding( $f ) ) {
				$kept[] = $f;
				continue;
			}
			$path = (string) ( $f['delete_path'] ?? '' );
			if ( '' === $path ) {
				$path = (string) ( $f['path'] ?? '' );
			}
			if ( '' !== $path && self::is_own_code( $path ) ) {
				$pkg = self::package_of( $path );
				$key = is_array( $pkg ) ? $pkg['kind'] . ' ' . $pkg['slug'] : $path;
				$dropped[ $key ] = ( $dropped[ $key ] ?? 0 ) + 1;
				continue;
			}
			$kept[] = $f;
		}
		if ( $dropped && class_exists( 'WPS_Logger' ) ) {
			foreach ( $dropped as $key => $n ) {
				$slug  = (string) substr( $key, (int) strpos( $key, ' ' ) + 1 );
				$owner = self::owner_of( $slug );
				WPS_Logger::log_event( 'own_code_verified', $n . ' finding' . ( 1 === $n ? '' : 's' ) . ' against ' . $key . ' not reported: the files are identical to github.com/' . $owner . '/' . $slug );
			}
		}
		return $kept;
	}

	/** A finding that states the operator's own policy rather than a judgement about the code. @param array<string, mixed> $f */
	public static function is_policy_finding( array $f ): bool {
		$text = strtolower( (string) ( $f['type'] ?? '' ) . ' ' . (string) ( $f['subject'] ?? '' ) );
		return false !== strpos( $text, 'banned by site policy' ) || false !== strpos( $text, 'site policy' );
	}

	/** Installed plugin and theme folders that have a repository under a declared account. @return string[] */
	public static function verified_slugs(): array {
		if ( ! self::enabled() ) {
			return [];
		}
		$out = [];
		foreach ( self::roots() as $root ) {
			foreach ( (array) @scandir( $root ) as $d ) {
				if ( '.' === $d || '..' === $d || ! is_dir( $root . '/' . $d ) ) {
					continue;
				}
				if ( null !== self::manifest_for( $d ) ) {
					$out[ strtolower( $d ) ] = true;
				}
			}
		}
		return array_keys( $out );
	}
}
