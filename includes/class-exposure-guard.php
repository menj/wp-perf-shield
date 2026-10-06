<?php
/**
 * XML-RPC and site-exposure controls.
 *
 * Merged in 1.4.131 from the feature set of the "Disable XML-RPC-API" plugin
 * (Neatma, GPLv2), re-implemented rather than copied. What WP Perf Shield already
 * did is not repeated here: blocking xmlrpc.php in .htaccess (Hardening tab),
 * stripping system.multicall and the pingback methods and disabling XML-RPC
 * sign-in (Settings, Sign-in), removing the post-writing methods (Posting) and
 * DISALLOW_FILE_EDIT (Hardening tab). This class adds what was missing:
 *
 *   - X-Pingback header, open pings and the pingback <link>
 *   - disabling an operator-chosen list of XML-RPC methods
 *   - serving XML-RPC from a renamed endpoint, with xmlrpc.php answering 404
 *   - an IP allow list and deny list for XML-RPC requests (single addresses and CIDR)
 *   - hiding the WordPress version, the RSD and wlwmanifest links and the feeds
 *   - REST API for signed-in users only, with an exemption list
 *   - slower heartbeat, no emoji scripts, no oEmbed script
 *
 * Every option is OFF by default, so installing this version changes nothing
 * until an operator turns something on in Settings, XML-RPC and exposure.
 *
 * Deliberately NOT carried over from that plugin, and why:
 *   - making .htaccess read-only (0444): it stops WordPress and this plugin's own
 *     Hardening tab from writing their rules.
 *   - its hotlink-protection rule: the rule contains an en dash where Apache
 *     needs a hyphen, so it never worked as written, and a correct one can block
 *     legitimate image use (feeds, social previews, CDNs).
 *   - its hard-coded Jetpack address list: stale ranges in deprecated Apache 2.2
 *     syntax. The allow list accepts any address or range the operator needs.
 *   - its IP-list parser returned after the first address, so only one entry of a
 *     list ever took effect. The parser here applies every entry.
 *
 * @package WP_Perf_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPS_Exposure_Guard {

	/** Well-known methods an operator can switch off with one click. */
	const CURATED_METHODS = [
		'pingback.ping'                    => 'Receive pingbacks',
		'pingback.extensions.getPingbacks' => 'List pingbacks',
		'system.multicall'                 => 'Batch many calls in one request',
		'system.listMethods'               => 'List available methods',
		'system.getCapabilities'           => 'Report server capabilities',
		'wp.getUsersBlogs'                 => 'List the sites a login can manage',
		'wp.getUsers'                      => 'List users',
		'wp.getProfile'                    => 'Read the signed-in profile',
		'wp.getOptions'                    => 'Read site options',
		'wp.uploadFile'                    => 'Upload a file',
		'metaWeblog.newMediaObject'        => 'Upload a file (MetaWeblog)',
		'wp.getPosts'                      => 'List posts',
	];

	/** Endpoint names that would collide with WordPress itself. */
	const RESERVED_SLUGS = [
		'xmlrpc', 'xmlrpc.php', 'index', 'index.php', 'wp-login', 'wp-login.php', 'wp-admin', 'wp-json',
		'wp-content', 'wp-includes', 'wp-cron', 'wp-cron.php', 'wp-config', 'feed', 'admin', 'login',
		'robots.txt', 'sitemap.xml',
	];

	// ---------------------------------------------------------------
	//  Settings access
	// ---------------------------------------------------------------

	/** @return array<string, mixed> */
	private static function settings(): array {
		$s = get_option( WPS_OPTION, [] );
		return is_array( $s ) ? $s : [];
	}

	public static function get( string $key, string $default = '' ): string {
		$s = self::settings();
		return isset( $s[ $key ] ) ? (string) $s[ $key ] : $default;
	}

	public static function on( string $key ): bool {
		return '1' === self::get( $key, '0' );
	}

	// ---------------------------------------------------------------
	//  Registration
	// ---------------------------------------------------------------

	/**
	 * Registers only what the operator has switched on. With every option at its
	 * default this adds no hooks at all.
	 */
	public static function register_hooks(): void {
		if ( self::on( 'xr_no_pingback' ) ) {
			add_filter( 'wp_headers', [ __CLASS__, 'strip_pingback_header' ] );
			add_filter( 'pings_open', '__return_false', PHP_INT_MAX );
			add_filter( 'bloginfo_url', [ __CLASS__, 'blank_pingback_url' ], 10, 2 );
			add_filter( 'xmlrpc_methods', [ __CLASS__, 'strip_pingback_methods' ], 99 );
		}
		if ( '' !== trim( self::get( 'xr_disabled_methods', '' ) ) ) {
			add_filter( 'xmlrpc_methods', [ __CLASS__, 'filter_methods' ], 99 );
		}
		if ( '' !== self::get( 'xr_slug', '' ) ) {
			add_action( 'wp_loaded', [ __CLASS__, 'route_endpoint' ] );
		}
		if ( '' !== trim( self::get( 'xr_allow_ips', '' ) ) || '' !== trim( self::get( 'xr_deny_ips', '' ) ) ) {
			add_action( 'init', [ __CLASS__, 'maybe_enforce_ip_policy' ], 0 );
		}

		if ( self::on( 'xr_hide_version' ) ) {
			add_filter( 'the_generator', '__return_empty_string' );
			add_filter( 'script_loader_src', [ __CLASS__, 'strip_version_param' ] );
			add_filter( 'style_loader_src', [ __CLASS__, 'strip_version_param' ] );
			add_action( 'init', [ __CLASS__, 'remove_generator' ] );
		}
		if ( self::on( 'xr_remove_discovery_links' ) ) {
			add_action( 'init', [ __CLASS__, 'remove_discovery_links' ] );
		}
		if ( self::on( 'xr_disable_feeds' ) ) {
			add_action( 'init', [ __CLASS__, 'remove_feed_links' ] );
			foreach ( [ 'do_feed', 'do_feed_rdf', 'do_feed_rss', 'do_feed_rss2', 'do_feed_atom', 'do_feed_rss2_comments', 'do_feed_atom_comments' ] as $hook ) {
				add_action( $hook, [ __CLASS__, 'refuse_feed' ], 1 );
			}
		}
		if ( self::on( 'xr_rest_logged_in_only' ) ) {
			add_filter( 'rest_authentication_errors', [ __CLASS__, 'rest_gate' ] );
		}
		if ( self::on( 'xr_slow_heartbeat' ) ) {
			add_filter( 'heartbeat_settings', [ __CLASS__, 'slow_heartbeat' ] );
		}
		if ( self::on( 'xr_remove_emoji' ) ) {
			add_action( 'init', [ __CLASS__, 'remove_emoji' ] );
		}
		if ( self::on( 'xr_disable_oembed' ) ) {
			add_action( 'wp_footer', [ __CLASS__, 'dequeue_oembed' ], 11 );
		}
	}

	// ---------------------------------------------------------------
	//  Pingbacks
	// ---------------------------------------------------------------

	/** @param array<string, mixed> $headers */
	public static function strip_pingback_header( $headers ) {
		if ( is_array( $headers ) ) {
			unset( $headers['X-Pingback'] );
		}
		return $headers;
	}

	/** The theme's <link rel="pingback"> reads this; return nothing. */
	public static function blank_pingback_url( $output, $show = '' ) {
		return 'pingback_url' === $show ? '' : $output;
	}

	/** @param array<string, mixed> $methods */
	public static function strip_pingback_methods( $methods ) {
		if ( is_array( $methods ) ) {
			unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
		}
		return $methods;
	}

	// ---------------------------------------------------------------
	//  Method list
	// ---------------------------------------------------------------

	/** @return string[] */
	public static function disabled_methods(): array {
		return self::parse_method_list( self::get( 'xr_disabled_methods', '' ) );
	}

	/** @return string[] the method names in a stored newline- or comma-separated list */
	public static function parse_method_list( string $raw ): array {
		return array_values( array_filter( array_map( 'trim', preg_split( '/[\r\n,]+/', $raw ) ?: [] ) ) );
	}

	/** @param array<string, mixed> $methods */
	public static function filter_methods( $methods ) {
		if ( ! is_array( $methods ) ) {
			return $methods;
		}
		foreach ( self::disabled_methods() as $m ) {
			unset( $methods[ $m ] );
		}
		return $methods;
	}

	// ---------------------------------------------------------------
	//  Renamed endpoint
	// ---------------------------------------------------------------

	/**
	 * The last path segment of a request, without query string or trailing slash.
	 * "/blog/wp-rpc-1a2b/?x=1" with home path "/blog/" is "wp-rpc-1a2b".
	 */
	public static function endpoint_of( string $request_uri, string $home_path = '/' ): string {
		$path = (string) parse_url( $request_uri, PHP_URL_PATH );
		$home = '/' . trim( $home_path, '/' );
		if ( '/' !== $home && 0 === strpos( $path, $home . '/' ) ) {
			$path = substr( $path, strlen( $home ) );
		}
		$path = str_replace( 'index.php/', '', trim( $path, '/' ) );
		$parts = explode( '/', $path );
		return strtolower( (string) end( $parts ) );
	}

	/**
	 * With a custom endpoint set, xmlrpc.php answers 404 and the endpoint serves
	 * XML-RPC. Needs pretty permalinks so the path reaches WordPress.
	 */
	public static function route_endpoint(): void {
		$slug = self::get( 'xr_slug', '' );
		if ( '' === $slug ) {
			return;
		}
		$home = (string) parse_url( (string) get_option( 'home' ), PHP_URL_PATH );
		$page = self::endpoint_of( (string) ( $_SERVER['REQUEST_URI'] ?? '' ), '' === $home ? '/' : $home );

		if ( 'xmlrpc.php' === $page ) {
			if ( function_exists( 'status_header' ) ) {
				status_header( 404 );
			}
			if ( function_exists( 'nocache_headers' ) ) {
				nocache_headers();
			}
			exit;
		}
		if ( $page !== $slug ) {
			return;
		}
		self::enforce_ip_policy();
		if ( ! defined( 'XMLRPC_REQUEST' ) ) {
			define( 'XMLRPC_REQUEST', true );
		}
		include ABSPATH . 'xmlrpc.php';
		exit;
	}

	// ---------------------------------------------------------------
	//  IP allow and deny lists
	// ---------------------------------------------------------------

	/**
	 * Valid single addresses and CIDR ranges from free text, one per line or
	 * comma separated. Every valid entry is kept.
	 *
	 * @return string[]
	 */
	public static function parse_rules( string $raw ): array {
		$out = [];
		foreach ( preg_split( '/[\r\n,\s]+/', $raw ) ?: [] as $entry ) {
			$entry = trim( (string) $entry );
			if ( '' === $entry ) {
				continue;
			}
			if ( false !== strpos( $entry, '/' ) ) {
				[ $addr, $bits ] = array_pad( explode( '/', $entry, 2 ), 2, '' );
				$bin = @inet_pton( $addr );
				if ( false === $bin || '' === $bits || ! ctype_digit( $bits ) ) {
					continue;
				}
				if ( (int) $bits > strlen( $bin ) * 8 ) {
					continue;
				}
				$out[ $addr . '/' . (int) $bits ] = true;
			} elseif ( false !== filter_var( $entry, FILTER_VALIDATE_IP ) ) {
				$out[ $entry ] = true;
			}
			if ( count( $out ) >= 200 ) {
				break;
			}
		}
		return array_keys( $out );
	}

	public static function sanitize_rules( string $raw ): string {
		return implode( "\n", self::parse_rules( $raw ) );
	}

	/** Does $ip fall inside any single address or CIDR range in $rules? */
	public static function ip_matches( string $ip, array $rules ): bool {
		$bin = @inet_pton( $ip );
		if ( false === $bin ) {
			return false;
		}
		foreach ( $rules as $rule ) {
			$rule = (string) $rule;
			if ( false === strpos( $rule, '/' ) ) {
				if ( @inet_pton( $rule ) === $bin ) {
					return true;
				}
				continue;
			}
			[ $addr, $bits ] = explode( '/', $rule, 2 );
			$net = @inet_pton( $addr );
			if ( false === $net || strlen( $net ) !== strlen( $bin ) ) {
				continue; // an IPv4 range never matches an IPv6 address
			}
			$bits  = (int) $bits;
			$bytes = intdiv( $bits, 8 );
			if ( $bytes > 0 && substr( $bin, 0, $bytes ) !== substr( $net, 0, $bytes ) ) {
				continue;
			}
			$rem = $bits % 8;
			if ( 0 === $rem ) {
				return true;
			}
			$mask = ( 0xFF << ( 8 - $rem ) ) & 0xFF;
			if ( ( ord( $bin[ $bytes ] ) & $mask ) === ( ord( $net[ $bytes ] ) & $mask ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The deny list always wins. An empty allow list allows everyone; a
	 * non-empty one allows only its members, and an address that cannot be
	 * determined is refused when an allow list exists.
	 */
	public static function ip_allowed( string $ip, array $allow, array $deny ): bool {
		if ( '' !== $ip && $deny && self::ip_matches( $ip, $deny ) ) {
			return false;
		}
		if ( ! $allow ) {
			return true;
		}
		return '' !== $ip && self::ip_matches( $ip, $allow );
	}

	public static function maybe_enforce_ip_policy(): void {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			self::enforce_ip_policy();
		}
	}

	public static function enforce_ip_policy(): void {
		$allow = self::parse_rules( self::get( 'xr_allow_ips', '' ) );
		$deny  = self::parse_rules( self::get( 'xr_deny_ips', '' ) );
		if ( ! $allow && ! $deny ) {
			return;
		}
		$ip = class_exists( 'WPS_Blocker' ) ? WPS_Blocker::client_ip() : (string) ( $_SERVER['REMOTE_ADDR'] ?? '' );
		if ( self::ip_allowed( $ip, $allow, $deny ) ) {
			return;
		}
		// One log line per address per ten minutes: a flood must not become a log flood.
		$tkey = 'wps_xr_' . md5( $ip );
		if ( class_exists( 'WPS_Logger' ) && ! ( function_exists( 'get_transient' ) && get_transient( $tkey ) ) ) {
			WPS_Logger::log_event( 'xmlrpc_ip_refused', 'XML-RPC request refused by the address rules', $ip );
			if ( function_exists( 'set_transient' ) ) {
				set_transient( $tkey, 1, 600 );
			}
		}
		if ( function_exists( 'status_header' ) ) {
			status_header( 403 );
		}
		exit( 'XML-RPC access is not permitted from this address.' );
	}

	// ---------------------------------------------------------------
	//  Exposure
	// ---------------------------------------------------------------

	public static function remove_generator(): void {
		remove_action( 'wp_head', 'wp_generator' );
	}

	/**
	 * Remove ?ver= only when it is the WordPress version itself. Plugin and theme
	 * versions are left alone so browser cache busting keeps working.
	 */
	public static function strip_version_param( $src ) {
		if ( ! is_string( $src ) || false === strpos( $src, 'ver=' ) ) {
			return $src;
		}
		global $wp_version;
		$parts = parse_url( $src );
		if ( empty( $parts['query'] ) ) {
			return $src;
		}
		parse_str( $parts['query'], $q );
		if ( isset( $q['ver'] ) && (string) $q['ver'] === (string) ( $wp_version ?? '' ) && '' !== (string) ( $wp_version ?? '' ) ) {
			return remove_query_arg( 'ver', $src );
		}
		return $src;
	}

	public static function remove_discovery_links(): void {
		remove_action( 'wp_head', 'rsd_link' );
		remove_action( 'wp_head', 'wlwmanifest_link' );
	}

	public static function remove_feed_links(): void {
		remove_action( 'wp_head', 'feed_links', 2 );
		remove_action( 'wp_head', 'feed_links_extra', 3 );
	}

	public static function refuse_feed(): void {
		wp_die( 'No feed is available on this site.', '', [ 'response' => 404 ] );
	}

	/**
	 * Signed-in users only for the REST API, with an exemption list of namespace
	 * prefixes (for example "contact-form-7/") for public integrations.
	 *
	 * @param mixed $result
	 * @return mixed
	 */
	public static function rest_gate( $result ) {
		if ( ! empty( $result ) ) {
			return $result;
		}
		if ( function_exists( 'is_user_logged_in' ) && is_user_logged_in() ) {
			return $result;
		}
		$route = self::rest_route_of_request();
		foreach ( self::rest_exemptions() as $prefix ) {
			if ( '' !== $prefix && 0 === strpos( ltrim( $route, '/' ), $prefix ) ) {
				return $result;
			}
		}
		return new WP_Error( 'wps_rest_signed_out', 'You must be signed in to use the REST API on this site.', [ 'status' => 401 ] );
	}

	/** @return string[] */
	public static function rest_exemptions(): array {
		return array_values( array_filter( array_map( 'trim', preg_split( '/[\r\n,]+/', self::get( 'xr_rest_exempt_namespaces', '' ) ) ?: [] ) ) );
	}

	public static function rest_route_of_request(): string {
		if ( isset( $_GET['rest_route'] ) ) {
			return (string) $_GET['rest_route'];
		}
		$path   = (string) parse_url( (string) ( $_SERVER['REQUEST_URI'] ?? '' ), PHP_URL_PATH );
		$prefix = function_exists( 'rest_get_url_prefix' ) ? rest_get_url_prefix() : 'wp-json';
		$pos    = strpos( $path, '/' . $prefix . '/' );
		return false === $pos ? '' : substr( $path, $pos + strlen( $prefix ) + 2 );
	}

	/** Namespace prefixes: letters, digits, dash, underscore, slash; one per line. */
	public static function sanitize_namespaces( string $raw ): string {
		$out = [];
		foreach ( preg_split( '/[\r\n,\s]+/', $raw ) ?: [] as $entry ) {
			$entry = strtolower( trim( (string) $entry ) );
			if ( preg_match( '#^[a-z0-9][a-z0-9_-]*(?:/[a-z0-9_.-]*)?$#', $entry ) ) {
				$out[ $entry ] = true;
			}
			if ( count( $out ) >= 50 ) {
				break;
			}
		}
		return implode( "\n", array_keys( $out ) );
	}

	// ---------------------------------------------------------------
	//  Speed
	// ---------------------------------------------------------------

	public static function slow_heartbeat( $settings ) {
		if ( is_array( $settings ) ) {
			$settings['interval'] = 60;
		}
		return $settings;
	}

	public static function remove_emoji(): void {
		remove_action( 'wp_head', 'print_emoji_detection_script', 7 );
		remove_action( 'wp_print_styles', 'print_emoji_styles' );
		remove_action( 'admin_print_scripts', 'print_emoji_detection_script' );
		remove_action( 'admin_print_styles', 'print_emoji_styles' );
		remove_filter( 'the_content_feed', 'wp_staticize_emoji' );
		remove_filter( 'comment_text_rss', 'wp_staticize_emoji' );
		remove_filter( 'wp_mail', 'wp_staticize_emoji_for_email' );
	}

	public static function dequeue_oembed(): void {
		wp_dequeue_script( 'wp-embed' );
	}

	// ---------------------------------------------------------------
	//  Sanitizers used by the Settings handler
	// ---------------------------------------------------------------

	/** Method names: letters, digits, dot, underscore. Anything else is dropped. */
	public static function sanitize_methods( string $raw ): string {
		$out = [];
		foreach ( preg_split( '/[\r\n,\s]+/', $raw ) ?: [] as $m ) {
			$m = trim( (string) $m );
			if ( preg_match( '/^[A-Za-z][A-Za-z0-9_.]{0,63}$/', $m ) ) {
				$out[ $m ] = true;
			}
			if ( count( $out ) >= 100 ) {
				break;
			}
		}
		return implode( "\n", array_keys( $out ) );
	}

	/** An endpoint name: lower-case letters, digits, dash, underscore; 4 to 40 characters; never a reserved name. Empty means "not set". */
	public static function sanitize_slug( string $raw ): string {
		$slug = strtolower( trim( $raw ) );
		$slug = (string) preg_replace( '/\.php$/', '', $slug );
		$slug = (string) preg_replace( '/[^a-z0-9_-]+/', '', $slug );
		if ( strlen( $slug ) < 4 || strlen( $slug ) > 40 || in_array( $slug, self::RESERVED_SLUGS, true ) ) {
			return '';
		}
		return $slug;
	}
}
