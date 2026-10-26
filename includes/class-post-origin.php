<?php
/**
 * Post provenance (1.4.157): how every post came to be written.
 *
 * The question an operator asks when a post appears that nobody wrote is "what wrote it?". The
 * usual advice is to find the post's exact time and read the server's access log for that minute,
 * which needs the host's log viewer, the right time zone, and a guess at which line matters. This
 * class answers the question at the moment of writing instead, and keeps the answer on the post:
 *
 *   - the channel (dashboard, REST API, XML-RPC, WP-Cron, WP-CLI, admin-ajax, front end);
 *   - how the actor was signed in (cookie session, application password and its name, none);
 *   - the address and user agent;
 *   - the cron hook, when WP-Cron did the writing;
 *   - the file that called the save, when it is not WordPress itself: a plugin, a theme, or
 *     something that should not be calling wp_insert_post() at all, such as a PHP file in uploads.
 *
 * A post that carries no record at all, yet is newer than this feature, was not written through
 * WordPress: it went straight into the database, from a server cron, another site on the same
 * account, or SQL access. The scanner reports those. Posts are observations here; nothing is
 * removed.
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPS_Post_Origin {

	const META         = '_wps_origin';
	const LAST         = '_wps_last_write';
	const SINCE_OPTION = 'wps_origin_since';

	/** Post types WordPress writes on its own behalf, which carry no story worth keeping. */
	const SKIP_TYPES = [
		'revision', 'nav_menu_item', 'customize_changeset', 'custom_css', 'oembed_cache', 'user_request',
		'wp_block', 'wp_template', 'wp_template_part', 'wp_global_styles', 'wp_navigation', 'wp_font_face', 'wp_font_family',
	];

	/** Core files at the web root that a request passes through before any plugin code runs. */
	const ROOT_CORE_FILES = [
		'index.php', 'wp-cron.php', 'xmlrpc.php', 'wp-load.php', 'wp-blog-header.php', 'wp-settings.php', 'wp-config.php',
		'wp-comments-post.php', 'wp-login.php', 'wp-mail.php', 'wp-trackback.php', 'wp-signup.php', 'wp-activate.php', 'wp-links-opml.php',
	];

	public static function register_hooks(): void {
		// The date tracking began. A post newer than this with no record was not written through WordPress.
		if ( ! get_option( self::SINCE_OPTION ) ) {
			update_option( self::SINCE_OPTION, time() );
		}
		add_action( 'wp_insert_post', [ __CLASS__, 'on_insert' ], 1, 3 );
		if ( function_exists( 'is_admin' ) && is_admin() ) {
			foreach ( [ 'posts', 'pages' ] as $screen ) {
				add_filter( 'manage_' . $screen . '_columns', [ __CLASS__, 'add_column' ] );
				add_action( 'manage_' . $screen . '_custom_column', [ __CLASS__, 'render_column' ], 10, 2 );
			}
			add_action( 'admin_enqueue_scripts', [ __CLASS__, 'enqueue' ] );
		}
	}

	// ---------------------------------------------------------------
	//  Recording
	// ---------------------------------------------------------------

	/**
	 * `wp_insert_post`, priority 1: runs for every insert and update that goes through WordPress.
	 *
	 * @param mixed $post_id
	 * @param mixed $post
	 * @param mixed $update
	 */
	public static function on_insert( $post_id, $post = null, $update = false ): void {
		$post_id = (int) $post_id;
		if ( $post_id <= 0 ) {
			return;
		}
		if ( ! is_object( $post ) && function_exists( 'get_post' ) ) {
			$post = get_post( $post_id );
		}
		if ( ! is_object( $post ) ) {
			return;
		}
		$type   = (string) ( $post->post_type ?? '' );
		$status = (string) ( $post->post_status ?? '' );
		if ( in_array( $type, self::SKIP_TYPES, true ) || in_array( $status, [ 'auto-draft', 'inherit' ], true ) ) {
			return;
		}
		if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
			return;
		}
		$origin = self::describe();
		if ( ! $update || ! is_array( get_post_meta( $post_id, self::META, true ) ) ) {
			update_post_meta( $post_id, self::META, $origin );
		}
		update_post_meta( $post_id, self::LAST, $origin );
		self::report( $post_id, $type, $status, $origin );
	}

	/**
	 * Everything known about the request writing right now.
	 *
	 * @return array<string, mixed>
	 */
	public static function describe(): array {
		$ip = filter_var( (string) ( $_SERVER['REMOTE_ADDR'] ?? '' ), FILTER_VALIDATE_IP );
		$cron   = defined( 'DOING_CRON' ) && DOING_CRON;
		$caller = self::caller_of( debug_backtrace( DEBUG_BACKTRACE_IGNORE_ARGS, 60 ) ); // phpcs:ignore
		return [
			'at'      => gmdate( 'Y-m-d H:i:s' ),
			'channel' => self::channel_of(
				defined( 'WP_CLI' ) && WP_CLI,
				$cron,
				defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST,
				defined( 'REST_REQUEST' ) && REST_REQUEST,
				function_exists( 'wp_doing_ajax' ) && wp_doing_ajax(),
				function_exists( 'is_admin' ) && is_admin()
			),
			'auth'    => class_exists( 'WPS_EDR' ) && method_exists( 'WPS_EDR', 'auth_method' ) ? (string) WPS_EDR::auth_method() : '',
			'user'    => function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0,
			'ip'      => false === $ip ? '' : (string) $ip,
			'ua'      => substr( (string) ( $_SERVER['HTTP_USER_AGENT'] ?? '' ), 0, 120 ),
			'request' => substr( strtoupper( (string) ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) . ' ' . (string) ( $_SERVER['REQUEST_URI'] ?? '' ), 0, 160 ),
			'cron'    => self::cron_hook_of( $cron, isset( $GLOBALS['wp_current_filter'] ) && is_array( $GLOBALS['wp_current_filter'] ) ? $GLOBALS['wp_current_filter'] : [] ),
			'caller'  => $caller['file'],
			'odd'     => $caller['odd'],
		];
	}

	/** Which door the request came through. Pure of side effects. */
	public static function channel_of( bool $cli, bool $cron, bool $xmlrpc, bool $rest, bool $ajax, bool $admin ): string {
		if ( $cli ) {
			return 'wp-cli';
		}
		if ( $cron ) {
			return 'cron';
		}
		if ( $xmlrpc ) {
			return 'xmlrpc';
		}
		if ( $rest ) {
			return 'rest';
		}
		if ( $ajax ) {
			return 'ajax';
		}
		return $admin ? 'admin' : 'front';
	}

	/**
	 * The cron hook being run, from the hook stack: WP-Cron runs each event with
	 * do_action_ref_array( $hook ), so the outermost entry is the event's hook. Pure of side effects.
	 *
	 * @param string[] $stack
	 */
	public static function cron_hook_of( bool $doing_cron, array $stack ): string {
		if ( ! $doing_cron || [] === $stack ) {
			return '';
		}
		$hook = (string) reset( $stack );
		return in_array( $hook, [ 'wp_insert_post', 'save_post', 'init', 'wp_loaded' ], true ) ? '' : $hook;
	}

	/**
	 * The first file in the call stack that is not WordPress itself and not this plugin: the plugin,
	 * theme or stray file that asked for the save. 'odd' is true when that file sits somewhere code
	 * has no business living (uploads, the wp-content root, a non-core file at the web root, or
	 * outside the installation). Pure of side effects.
	 *
	 * @param array<int, array<string, mixed>> $frames
	 * @return array{file: string, odd: bool}
	 */
	public static function caller_of( array $frames ): array {
		$abs   = self::norm( defined( 'ABSPATH' ) ? ABSPATH : '' );
		$selfs = [ self::norm( dirname( __DIR__ ) . '/' ) ]; // this plugin, wherever it is loaded from
		if ( defined( 'WPS_DIR' ) ) {
			$selfs[] = self::norm( WPS_DIR );
		}
		$code  = [];
		foreach ( [ 'WP_PLUGIN_DIR', 'WPMU_PLUGIN_DIR' ] as $c ) {
			if ( defined( $c ) ) {
				$code[] = self::norm( constant( $c ) );
			}
		}
		if ( function_exists( 'get_theme_root' ) ) {
			$code[] = self::norm( (string) get_theme_root() );
		}
		$code = array_values( array_filter( $code ) );
		foreach ( $frames as $frame ) {
			$file = isset( $frame['file'] ) ? self::norm( (string) $frame['file'] ) : '';
			if ( '' === $file ) {
				continue;
			}
			foreach ( $selfs as $self ) {
				if ( '' !== $self && 0 === strpos( $file, $self ) ) {
					continue 2;
				}
			}
			if ( '' !== $abs ) {
				if ( 0 === strpos( $file, $abs . 'wp-admin/' ) || 0 === strpos( $file, $abs . 'wp-includes/' ) ) {
					continue;
				}
				if ( dirname( $file ) . '/' === $abs && in_array( basename( $file ), self::ROOT_CORE_FILES, true ) ) {
					continue;
				}
			}
			$odd = true;
			foreach ( $code as $dir ) {
				if ( 0 === strpos( $file, $dir ) ) {
					$odd = false;
					break;
				}
			}
			return [ 'file' => self::rel( $file ), 'odd' => $odd ];
		}
		return [ 'file' => '', 'odd' => false ];
	}

	/** A path with forward slashes and a trailing slash, or '' for none. */
	private static function norm( string $path ): string {
		$path = str_replace( '\\', '/', $path );
		if ( '' === $path ) {
			return '';
		}
		$real = @realpath( $path );
		if ( is_string( $real ) && '' !== $real ) {
			$path = str_replace( '\\', '/', $real );
		}
		return is_dir( $path ) ? rtrim( $path, '/' ) . '/' : $path;
	}

	/** A file's path as the operator knows it: below wp-content, below the web root, or as given. */
	private static function rel( string $file ): string {
		$content = defined( 'WP_CONTENT_DIR' ) ? self::norm( WP_CONTENT_DIR ) : '';
		if ( '' !== $content && 0 === strpos( $file, $content ) ) {
			return 'wp-content/' . substr( $file, strlen( $content ) );
		}
		$abs = defined( 'ABSPATH' ) ? self::norm( ABSPATH ) : '';
		if ( '' !== $abs && 0 === strpos( $file, $abs ) ) {
			return substr( $file, strlen( $abs ) );
		}
		return $file;
	}

	/**
	 * An event for a write that deserves one: a file that should not be writing posts, or WP-Cron.
	 * Each is recorded once an hour per file or per hook, since a kit that writes a hundred posts
	 * would otherwise fill the log with one story told a hundred times.
	 *
	 * @param array<string, mixed> $origin
	 */
	private static function report( int $post_id, string $type, string $status, array $origin ): void {
		if ( ! class_exists( 'WPS_EDR' ) || ! method_exists( 'WPS_EDR', 'record' ) ) {
			return;
		}
		$what = ucfirst( $type ) . ' #' . $post_id . ' (' . $status . ')';
		if ( ! empty( $origin['odd'] ) && '' !== (string) $origin['caller'] ) {
			$key = 'wps_po_' . md5( 'file|' . (string) $origin['caller'] );
			if ( ! get_transient( $key ) ) {
				set_transient( $key, 1, 3600 );
				WPS_EDR::record( 'post_written_by_unexpected_file', [
					'object_type' => 'post',
					'object_name' => $what,
					'severity'    => 'high',
					'risk'        => 120,
					'notes'       => 'written by ' . (string) $origin['caller'] . ', which is not a plugin, theme or WordPress file, over ' . self::channel_name( (string) $origin['channel'] )
						. ( '' !== (string) $origin['ip'] ? ' from ' . (string) $origin['ip'] : '' )
						. '. That file is the thing to look at, whatever the scanner says about it.',
				] );
			}
			return;
		}
		if ( 'cron' === (string) ( $origin['channel'] ?? '' ) ) {
			$hook = (string) ( $origin['cron'] ?? '' );
			$key  = 'wps_po_' . md5( 'cron|' . $hook );
			if ( ! get_transient( $key ) ) {
				set_transient( $key, 1, 3600 );
				WPS_EDR::record( 'post_written_by_cron', [
					'object_type' => 'post',
					'object_name' => $what,
					'severity'    => 'info',
					'notes'       => 'written by a scheduled event' . ( '' !== $hook ? ' (hook ' . $hook . ')' : '' )
						. ( '' !== (string) $origin['caller'] ? ', called from ' . (string) $origin['caller'] : '' )
						. '. Scheduled writing is normal for an importer or auto-poster; if you run neither, the hook name says what to remove.',
				] );
			}
		}
	}

	// ---------------------------------------------------------------
	//  Reading
	// ---------------------------------------------------------------

	public static function channel_name( string $channel ): string {
		$names = [ 'wp-cli' => 'WP-CLI', 'cron' => 'WP-Cron', 'xmlrpc' => 'XML-RPC', 'rest' => 'REST API', 'ajax' => 'admin-ajax', 'admin' => 'Dashboard', 'front' => 'front end' ];
		return $names[ $channel ] ?? $channel;
	}

	/**
	 * One line for the Posts screen. Pure of side effects.
	 *
	 * @param mixed $origin The stored record, or '' for none.
	 * @param bool  $tracked Whether the post is newer than the start of tracking.
	 */
	public static function origin_label( $origin, bool $tracked ): string {
		if ( ! is_array( $origin ) || '' === (string) ( $origin['channel'] ?? '' ) ) {
			return $tracked ? 'Not through WordPress' : 'Before tracking';
		}
		$parts = [ self::channel_name( (string) $origin['channel'] ) ];
		if ( 'cron' === $origin['channel'] && '' !== (string) ( $origin['cron'] ?? '' ) ) {
			$parts[] = 'hook ' . (string) $origin['cron'];
		}
		if ( '' !== (string) ( $origin['auth'] ?? '' ) && ! in_array( $origin['channel'], [ 'cron', 'wp-cli' ], true ) ) {
			$parts[] = (string) $origin['auth'];
		}
		if ( '' !== (string) ( $origin['ip'] ?? '' ) ) {
			$parts[] = (string) $origin['ip'];
		}
		if ( ! empty( $origin['odd'] ) && '' !== (string) ( $origin['caller'] ?? '' ) ) {
			$parts[] = 'by ' . (string) $origin['caller'];
		}
		return implode( ' · ', $parts );
	}

	/** @param mixed $columns @return mixed */
	public static function add_column( $columns ) {
		if ( is_array( $columns ) ) {
			$columns['wps_origin'] = 'Written via';
		}
		return $columns;
	}

	/** @param mixed $column @param mixed $post_id */
	public static function render_column( $column, $post_id = 0 ): void {
		if ( 'wps_origin' !== $column ) {
			return;
		}
		$post_id = (int) $post_id;
		$origin  = get_post_meta( $post_id, self::META, true );
		$since   = (int) get_option( self::SINCE_OPTION, 0 );
		$post    = function_exists( 'get_post' ) ? get_post( $post_id ) : null;
		$written = is_object( $post ) ? max( strtotime( (string) ( $post->post_date_gmt ?? '' ) . ' UTC' ) ?: 0, strtotime( (string) ( $post->post_modified_gmt ?? '' ) . ' UTC' ) ?: 0 ) : 0;
		$tracked = $since > 0 && $written > $since;
		$label   = self::origin_label( $origin, $tracked );
		$class   = 'wps-origin';
		if ( ! is_array( $origin ) ) {
			$class .= $tracked ? ' wps-origin-missing' : ' wps-origin-muted';
		} elseif ( ! empty( $origin['odd'] ) ) {
			$class .= ' wps-origin-missing';
		}
		$title = is_array( $origin ) ? trim( (string) ( $origin['at'] ?? '' ) . ' UTC ' . (string) ( $origin['request'] ?? '' ) ) : '';
		echo '<span class="' . esc_attr( $class ) . '"' . ( '' !== $title ? ' title="' . esc_attr( $title ) . '"' : '' ) . '>' . esc_html( $label ) . '</span>';
	}

	/** The column's styles ride the plugin's stylesheet; only the Posts and Pages lists need it. */
	public static function enqueue( string $hook_suffix = '' ): void {
		if ( 'edit.php' !== $hook_suffix || ! defined( 'WPS_URL' ) ) {
			return;
		}
		wp_enqueue_style( 'wps-admin', WPS_URL . 'assets/css/admin.css', [], defined( 'WPS_VERSION' ) ? WPS_VERSION : null );
	}

	// ---------------------------------------------------------------
	//  Posts that never passed through WordPress
	// ---------------------------------------------------------------

	/**
	 * Posts and pages newer than $since with no origin record: written straight into the database.
	 *
	 * @param object $wpdb
	 * @return array<int, object>
	 */
	public static function find_untracked( $wpdb, int $since, int $limit = 50 ): array {
		if ( $since <= 0 || ! is_object( $wpdb ) || ! method_exists( $wpdb, 'get_results' ) ) {
			return [];
		}
		$posts = (string) ( $wpdb->posts ?? 'wp_posts' );
		$meta  = (string) ( $wpdb->postmeta ?? 'wp_postmeta' );
		$sql   = $wpdb->prepare(
			"SELECT p.ID, p.post_title, p.post_type, p.post_status, p.post_author, p.post_date_gmt, p.post_modified_gmt FROM {$posts} p LEFT JOIN {$meta} m ON m.post_id = p.ID AND m.meta_key = %s WHERE m.meta_id IS NULL AND p.post_type IN ('post','page') AND p.post_status IN ('publish','future','draft','pending','private') AND GREATEST(p.post_date_gmt, p.post_modified_gmt) > %s ORDER BY p.ID DESC LIMIT %d",
			self::META,
			gmdate( 'Y-m-d H:i:s', $since ),
			max( 1, $limit )
		);
		$rows = $wpdb->get_results( (string) $sql );
		return is_array( $rows ) ? array_values( array_filter( $rows, 'is_object' ) ) : [];
	}

	/**
	 * The scanner finding for those posts, or [] when there are none. Pure of side effects.
	 *
	 * @param array<int, object> $rows
	 * @return array<int, array<string, mixed>>
	 */
	public static function untracked_finding( array $rows, int $since ): array {
		if ( [] === $rows ) {
			return [];
		}
		$lines = [];
		foreach ( array_slice( $rows, 0, 10 ) as $r ) {
			$lines[] = '#' . (int) ( $r->ID ?? 0 ) . ' "' . substr( trim( (string) ( $r->post_title ?? '' ) ), 0, 60 ) . '" (' . (string) ( $r->post_type ?? 'post' ) . ', ' . (string) ( $r->post_status ?? '' ) . ', author #' . (int) ( $r->post_author ?? 0 ) . ', ' . (string) ( $r->post_modified_gmt ?? $r->post_date_gmt ?? '' ) . ' UTC)';
		}
		$n = count( $rows );
		return [
			[
				'severity' => 'high',
				'type'     => 'Posts written without going through WordPress',
				'subject'  => $n . ' post' . ( 1 === $n ? '' : 's' ) . ' since ' . gmdate( 'Y-m-d H:i', $since ) . ' UTC carry no record of what wrote them: ' . implode( '; ', $lines ) . ( $n > 10 ? '; and ' . ( $n - 10 ) . ' more' : '' ),
				'path'     => 'wp_posts',
				'action'   => 'Every post saved through WordPress since ' . gmdate( 'Y-m-d', $since ) . ' carries a "Written via" record (see the Posts screen). These do not, so they were put into the database directly: by a server cron job, by another site on the same hosting account, by SQL access, or by code that writes to the posts table itself. Nothing on this site\'s web log will show the moment they appeared. Check the hosting panel\'s cron jobs and the other sites on the account, change the database password, and look at the author column: a kit usually hard-codes author 1, so posts under your name do not prove your account was used.',
			],
		];
	}
}
