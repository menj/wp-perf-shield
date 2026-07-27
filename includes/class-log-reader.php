<?php
/**
 * WP Perf Shield  read-only server-log reader and IOC scanner (1.3.73).
 *
 * Surfaces the web-server access/error logs and the WordPress debug log inside
 * the admin so an operator can correlate a finding's timestamp (a planted
 * drop-in's mtime, a dropin_watch event) against the request that wrote it,
 * and can grep all readable logs for this campaign's indicators in one click.
 *
 * SECURITY MODEL  this class reads files and shows them to an administrator,
 * so it is built defensively:
 *
 *   - Candidate log paths are CODE-DEFINED (a fixed set of conventional
 *     locations derived from ABSPATH). User input never becomes a path that is
 *     read; the read handler re-validates any requested path through
 *     is_safe_log() before opening it, so there is no arbitrary-file-read.
 *   - is_safe_log() requires the resolved real path to be a readable regular
 *     file under an allow-listed root (the account home, the WP tree, or a
 *     short list of standard web-log roots), and refuses non-log-like names
 *     or sensitive extensions such as .php, .env, SQL dumps, archives, and
 *     config backups.
 *   - Only the tail is read (MAX_BYTES / MAX_LINES), never a whole multi-GB log.
 *   - Nothing is written. The class has no write path.
 *   - Callers MUST render every returned line as text, not HTML. Access logs
 *     are full of attacker-controlled user-agent and URL strings; treating a
 *     line as markup would turn the viewer into a stored-XSS sink. The admin
 *     JS inserts lines via textContent for exactly this reason.
 *
 * @package WP_Perf_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPS_Log_Reader {

	const MAX_BYTES = 262144; // 256 KB tail
	const MAX_LINES = 800;
	const MAX_HITS  = 300;

	/** Allow-listed roots a log file may resolve within. @return list<string> */
	private static function allowed_roots(): array {
		$roots = [];
		$abs = defined( 'ABSPATH' ) ? realpath( rtrim( ABSPATH, '/\\' ) ) : false;
		if ( $abs ) {
			$roots[] = $abs;
			$parent = realpath( dirname( $abs ) ); // account home on most cPanel/Plesk layouts
			if ( $parent ) {
				$roots[] = $parent;
			}
		}
		if ( defined( 'WP_CONTENT_DIR' ) ) {
			$wc = realpath( rtrim( WP_CONTENT_DIR, '/\\' ) );
			if ( $wc ) {
				$roots[] = $wc;
			}
		}
		// Standard web-server log roots (cPanel domlogs are usually symlinked here).
		foreach ( [ '/usr/local/apache/domlogs', '/var/log/apache2', '/var/log/httpd', '/var/log/nginx' ] as $sys ) {
			$r = realpath( $sys );
			if ( $r ) {
				$roots[] = $r;
			}
		}
		return array_values( array_unique( $roots ) );
	}

	private static function is_allowed_log_filename( string $real ): bool {
		$base = strtolower( basename( $real ) );
		$path = strtolower( str_replace( '\\', '/', $real ) );

		if ( $base === '.env' || strpos( $base, 'wp-config' ) === 0 ) {
			return false;
		}
		if ( preg_match( '/\.(php|phtml|phar|env|sql|bak|backup|zip|tar|gz|tgz|ini|json|config)$/i', $base ) ) {
			return false;
		}

		if ( in_array( $base, [ 'error_log', 'access_log', 'debug.log', 'php_errorlog' ], true ) ) {
			return true;
		}
		if ( preg_match( '/\.(log|log\.\d+)$/i', $base ) ) {
			return true;
		}
		if ( preg_match( '/(^|[._-])(error|access|debug|php[_-]?error|error_log|access_log)([._-]|$)/i', $base ) ) {
			return true;
		}

		return preg_match( '#/(access-logs|domlogs)/#i', $path ) === 1;
	}

	/**
	 * Security boundary: a path is a safe log target only if it resolves to a
	 * readable regular file under an allow-listed root and has a log-like name.
	 */
	public static function is_safe_log( string $path ): bool {
		if ( $path === '' ) {
			return false;
		}
		$real = realpath( $path );
		if ( $real === false || ! is_file( $real ) || ! is_readable( $real ) ) {
			return false;
		}
		if ( ! self::is_allowed_log_filename( $real ) ) {
			return false;
		}
		foreach ( self::allowed_roots() as $root ) {
			if ( $real === $root || strpos( $real, $root . DIRECTORY_SEPARATOR ) === 0 ) {
				return true;
			}
		}
		return false;
	}

	/** Code-defined candidate log locations. @return list<string> */
	private static function candidate_paths(): array {
		$paths = [];
		$abs    = defined( 'ABSPATH' ) ? rtrim( ABSPATH, '/\\' ) : '';
		$home   = $abs !== '' ? dirname( $abs ) : '';
		$wc     = defined( 'WP_CONTENT_DIR' ) ? rtrim( WP_CONTENT_DIR, '/\\' ) : '';

		// WordPress + PHP error logs (reliably readable: inside the WP tree).
		if ( $wc !== '' ) {
			$paths[] = $wc . '/debug.log';
			$paths[] = $wc . '/error_log';
		}
		if ( $abs !== '' ) {
			$paths[] = $abs . '/error_log';
		}

		// cPanel-style per-account log directories (globbed; readability filtered later).
		$glob_dirs = [];
		if ( $home !== '' ) {
			$glob_dirs[] = $home . '/access-logs';
			$glob_dirs[] = $home . '/logs';
			$glob_dirs[] = $home . '/ssl/logs';
		}
		foreach ( $glob_dirs as $d ) {
			$matches = @glob( $d . '/*' );
			if ( is_array( $matches ) ) {
				foreach ( $matches as $m ) {
					$paths[] = $m;
				}
			}
		}
		return $paths;
	}

	/**
	 * Discover readable log files. Returns a list of [path, label, size].
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function discover(): array {
		$out  = [];
		$seen = [];
		foreach ( self::candidate_paths() as $path ) {
			if ( ! self::is_safe_log( $path ) ) {
				continue;
			}
			$real = realpath( $path );
			if ( isset( $seen[ $real ] ) ) {
				continue;
			}
			$seen[ $real ] = true;
			$out[] = [
				'path'  => $real,
				'label' => self::label_for( $real ),
				'size'  => (int) @filesize( $real ),
			];
			if ( count( $out ) >= 40 ) {
				break;
			}
		}
		return $out;
	}

	private static function label_for( string $real ): string {
		$base = basename( $real );
		if ( $base === 'debug.log' ) {
			return 'WordPress debug log';
		}
		if ( $base === 'error_log' ) {
			return 'PHP error log';
		}
		if ( strpos( $real, 'access-logs' ) !== false || strpos( $real, 'domlogs' ) !== false ) {
			return 'Web access log';
		}
		if ( strpos( $real, '/logs/' ) !== false ) {
			return 'Server log';
		}
		return 'Log file';
	}

	/**
	 * Read the tail of a log file as an array of lines (most recent last).
	 * Path is re-validated through is_safe_log() before opening.
	 *
	 * @return list<string>
	 */
	public static function tail( string $path ): array {
		if ( ! self::is_safe_log( $path ) ) {
			return [];
		}
		$real = realpath( $path );
		$size = (int) @filesize( $real );
		$fh   = @fopen( $real, 'rb' );
		if ( ! $fh ) {
			return [];
		}
		if ( $size > self::MAX_BYTES ) {
			@fseek( $fh, -self::MAX_BYTES, SEEK_END );
			@fgets( $fh ); // discard the partial first line
		}
		$lines = [];
		while ( ( $line = fgets( $fh ) ) !== false ) {
			$lines[] = rtrim( $line, "\r\n" );
		}
		@fclose( $fh );
		if ( count( $lines ) > self::MAX_LINES ) {
			$lines = array_slice( $lines, -self::MAX_LINES );
		}
		return $lines;
	}

	/**
	 * IOC terms used to grep logs: campaign C2 hosts, the static token, and a
	 * fixed set of request/payload fingerprints for this family.
	 *
	 * @return list<string>
	 */
	public static function ioc_terms(): array {
		$terms = [];
		if ( method_exists( 'WPS_Indicators', 'clickfix_download_c2_domains' ) ) {
			$terms = array_merge( $terms, WPS_Indicators::clickfix_download_c2_domains() );
		}
		if ( method_exists( 'WPS_Indicators', 'clickfix_campaign_tokens' ) ) {
			$terms = array_merge( $terms, WPS_Indicators::clickfix_campaign_tokens() );
		}
		if ( method_exists( 'WPS_Indicators', 'tds_c2_domains' ) ) {
			$terms = array_merge( $terms, WPS_Indicators::tds_c2_domains() );
		}
		// Static request / delivery fingerprints. Lowercased; matching is ci.
		$static = [
			'a=dl&token=',
			'mode=cloudflare',
			'frombase64string',
			'fromcharcode',
			'powershell',
			'-enc ',
			'-encodedcommand',
			'wp-perf-analytics',
			'connector.minimal.php',  // wp-file-manager RCE endpoint
			'elfinder',
			'/wp-file-manager/',
		];
		return array_values( array_unique( array_merge( $terms, $static ) ) );
	}

	/**
	 * Scan a single (re-validated) log for IOC terms. Returns matching lines
	 * with the term that matched. Lines are returned RAW; the caller renders
	 * them as text.
	 *
	 * @return array<int, array<string, string>>
	 */
	public static function scan( string $path ): array {
		$hits  = [];
		$terms = array_map( 'strtolower', self::ioc_terms() );
		foreach ( self::tail( $path ) as $line ) {
			$hay = strtolower( $line );
			foreach ( $terms as $t ) {
				if ( $t !== '' && strpos( $hay, $t ) !== false ) {
					$hits[] = [
						'matched' => $t,
						'line'    => $line,
					];
					break;
				}
			}
			if ( count( $hits ) >= self::MAX_HITS ) {
				break;
			}
		}
		return $hits;
	}

	/**
	 * Scan every discovered log for IOC terms.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function scan_all(): array {
		$results = [];
		foreach ( self::discover() as $log ) {
			$hits = self::scan( $log['path'] );
			if ( ! empty( $hits ) ) {
				$results[] = [
					'path' => $log['path'],
					'hits' => $hits,
				];
			}
		}
		return $results;
	}

	/**
	 * Detect the automated-login signature documented by GoDaddy for this
	 * campaign: the operator logs in with stolen credentials by POSTing
	 * directly to wp-login.php (or hitting xmlrpc.php) without ever GETting the
	 * login page first, because there is no browser, just a script replaying
	 * credentials. A human login always GETs wp-login.php before POSTing it.
	 *
	 * Parses Common/Combined Log Format lines, groups by client IP, and returns
	 * the IPs that POSTed to wp-login.php (or used xmlrpc.php) with zero
	 * preceding GETs of the login page. Path is re-validated through
	 * is_safe_log() before opening.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function scan_login_posts( string $path ): array {
		if ( ! self::is_safe_log( $path ) ) {
			return [];
		}
		$ips = [];
		foreach ( self::tail( $path ) as $line ) {
			// IP is the first token; the request line sits in the first quoted field.
			if ( ! preg_match( '#^(\S+).*?"(GET|POST|HEAD|PUT|DELETE)\s+([^"\s]+)#', $line, $m ) ) {
				continue;
			}
			$ip      = $m[1];
			$method  = strtoupper( $m[2] );
			$reqpath = $m[3];
			$is_login  = ( stripos( $reqpath, '/wp-login.php' ) !== false );
			$is_xmlrpc = ( stripos( $reqpath, '/xmlrpc.php' ) !== false );
			if ( ! $is_login && ! $is_xmlrpc ) {
				continue;
			}
			if ( ! isset( $ips[ $ip ] ) ) {
				$ips[ $ip ] = [ 'get' => 0, 'post' => 0, 'xmlrpc' => 0 ];
			}
			if ( $is_xmlrpc ) {
				$ips[ $ip ]['xmlrpc']++;
			} elseif ( $method === 'POST' ) {
				$ips[ $ip ]['post']++;
			} elseif ( $method === 'GET' ) {
				$ips[ $ip ]['get']++;
			}
		}

		$suspect = [];
		foreach ( $ips as $ip => $c ) {
			// Direct login POSTs with no page load, or any xmlrpc auth attempts.
			if ( ( $c['post'] > 0 && $c['get'] === 0 ) || $c['xmlrpc'] > 0 ) {
				$suspect[] = [
					'ip'     => $ip,
					'posts'  => $c['post'],
					'xmlrpc' => $c['xmlrpc'],
				];
			}
		}
		// Heaviest offenders first.
		usort(
			$suspect,
			static function ( $a, $b ) {
				return ( $b['posts'] + $b['xmlrpc'] ) <=> ( $a['posts'] + $a['xmlrpc'] );
			}
		);
		return $suspect;
	}

	/**
	 * Run the automated-login scan across every discovered access log.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function scan_login_posts_all(): array {
		$results = [];
		foreach ( self::discover() as $log ) {
			$suspect = self::scan_login_posts( $log['path'] );
			if ( ! empty( $suspect ) ) {
				$results[] = [
					'path'    => $log['path'],
					'suspect' => $suspect,
				];
			}
		}
		return $results;
	}
}
