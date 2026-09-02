<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * WPS_Admin  admin orchestrator.
 *
 * Phase 3 (1.3.30) split this file from a 2115-line tab-rendering monolith
 * into an ~85-line orchestrator that prepares shared context and dispatches
 * to the seven tab classes:
 *
 *   WPS_Admin_Overview      Overview
 *   WPS_Admin_Diagnostics   Diagnostics  (owns analytics + Source Trace helpers)
 *   WPS_Admin_Forensics     Forensics    (owns render_forensics + helpers)
 *   WPS_Admin_Remediation   Remediation
 *   WPS_Admin_Hardening     Hardening
 *   WPS_Admin_Events        Events
 *   WPS_Admin_Settings      Settings
 *
 * Tab order, alias mapping, button IDs, JS configuration, and the wrapping
 * `.wrap` markup are unchanged. Each tab class receives a `$context` array
 * with only the data it needs.
 */
class WPS_Admin {

	public static function register_hooks(): void {
		add_action( 'admin_menu', [ self::class, 'add_menu' ] );
		add_action( 'admin_enqueue_scripts', [ self::class, 'enqueue_assets' ] );
		add_action( 'admin_post_wps_verify_akismet', [ __CLASS__, 'handle_verify_akismet' ] );
		add_action( 'admin_post_wps_report_ip', [ __CLASS__, 'handle_report_ip' ] );
		add_action( 'admin_post_wps_unblock_permanent', [ __CLASS__, 'handle_unblock_permanent' ] );
		add_action( 'admin_post_wps_permanent_block', [ __CLASS__, 'handle_permanent_block' ] );
		add_action( 'admin_post_wps_mark_safe', [ __CLASS__, 'handle_mark_safe' ] );
		add_action( 'admin_post_wps_revoke_safe', [ __CLASS__, 'handle_revoke_safe' ] );
		add_action( 'admin_post_wps_reset_breaker', [ __CLASS__, 'handle_reset_breaker' ] );
		add_action( 'admin_post_wps_chain_selftest', [ __CLASS__, 'handle_chain_selftest' ] );
		add_action( 'admin_post_wps_save_settings', [ self::class, 'save_settings' ] );
	}

	public static function add_menu(): void {
		add_management_page(
			'WP Perf Shield',
			'Perf Shield',
			'manage_options',
			'wp-perf-shield',
			[ self::class, 'render_page' ]
		);
	}

	public static function enqueue_assets( string $hook_suffix ): void {
		if ( $hook_suffix !== 'tools_page_wp-perf-shield' ) {
			return;
		}

		wp_enqueue_style(
			'wps-admin',
			WPS_URL . 'assets/css/admin.css',
			[],
			WPS_VERSION
		);

		wp_enqueue_script(
			'wps-admin',
			WPS_URL . 'assets/js/admin.js',
			[ 'jquery' ],
			WPS_VERSION,
			true
		);

		wp_localize_script( 'wps-admin', 'WPS_ADMIN', [
			'nonce' => wp_create_nonce( 'wps_nonce' ),
			'ajaxUrl' => admin_url( 'admin-ajax.php' ),
		] );
	}

	public static function save_settings(): void {
		check_admin_referer( 'wps_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden' );
		}
		/*
		 * 1.4.55: merge, do not replace.
		 *
		 * This handler used to hand update_option() a literal array, which
		 * silently destroyed every key the Settings tab does not own. The CSP
		 * mode and policy live in this same option and are edited on a
		 * different tab, so saving any unrelated setting reverted csp_mode to
		 * 'off' - a security control switched off by an action that had
		 * nothing to do with it, with no message and no trace.
		 *
		 * Read first, overwrite only what this form owns, and anything added
		 * later by another component survives by default rather than by
		 * somebody remembering to add it here.
		 */
		$existing = get_option( WPS_OPTION, [] );
		if ( ! is_array( $existing ) ) {
			$existing = [];
		}

		update_option( WPS_OPTION, array_merge( $existing, [
			'extra_slugs' => self::sanitize_slug_list( (string) wp_unslash( $_POST['extra_slugs'] ?? '' ) ),
			// 1.4.11: operator-declared first-party plugins. Same shape as the slug
			// list, so the same sanitiser applies.
			'first_party_plugins' => self::sanitize_slug_list( (string) wp_unslash( $_POST['first_party_plugins'] ?? '' ) ),
			// 1.4.17: login guard.
			'login_guard_enabled'  => isset( $_POST['login_guard_enabled'] ) ? '1' : '0',
			'xmlrpc_auth_disabled' => isset( $_POST['xmlrpc_auth_disabled'] ) ? '1' : '0',
			'xmlrpc_strip_multicall' => isset( $_POST['xmlrpc_strip_multicall'] ) ? '1' : '0',
			'post_guard_enabled'   => isset( $_POST['post_guard_enabled'] ) ? '1' : '0',
			'login_network_guard'  => isset( $_POST['login_network_guard'] ) ? '1' : '0',
			'login_report_spam'    => isset( $_POST['login_report_spam'] ) ? '1' : '0',
			'akismet_report_all_blocks' => isset( $_POST['akismet_report_all_blocks'] ) ? '1' : '0',
			// 1.4.60: was read by akismet_available() but never written, so the
			// opt-out it implied was unreachable.
			'akismet_enrichment'   => isset( $_POST['akismet_enrichment'] ) ? '1' : '0',
			'login_ip_allowlist'   => self::sanitize_ip_list( (string) wp_unslash( $_POST['login_ip_allowlist'] ?? '' ) ),
			'extra_hashes' => self::sanitize_hash_list( (string) wp_unslash( $_POST['extra_hashes'] ?? '' ) ),
			'auto_delete_enabled' => isset( $_POST['auto_delete_enabled'] ) ? '1' : '0',
			'quarantine_enabled' => isset( $_POST['quarantine_enabled'] ) ? '1' : '0',
			'appearance' => in_array( sanitize_key( wp_unslash( $_POST['appearance'] ?? 'light' ) ), [ 'auto', 'light', 'dark' ], true ) ? sanitize_key( wp_unslash( $_POST['appearance'] ?? 'light' ) ) : 'light',
			'auto_ip_block_enabled' => isset( $_POST['auto_ip_block_enabled'] ) ? '1' : '0',
			'strict_upload_gate_enabled' => isset( $_POST['strict_upload_gate_enabled'] ) ? '1' : '0',
			// 1.4.62: site-policy plugin denylist. Enforced by default; the
			// textarea holds operator additions on top of the built-in bans.
			'policy_ban_enabled'  => isset( $_POST['policy_ban_enabled'] ) ? '1' : '0',
			'policy_banned_slugs' => self::sanitize_slug_list( (string) wp_unslash( $_POST['policy_banned_slugs'] ?? '' ) ),
			// 1.4.52: public identification marker. Off unless ticked.
			'public_marker' => isset( $_POST['public_marker'] ) ? '1' : '0',
		] ) );
		wp_safe_redirect( admin_url( 'tools.php?page=wp-perf-shield&saved=1&tab=settings' ) );
		exit;
	}

	/** 1.4.17: one validated IP per line; anything unparseable is dropped. */
	private static function sanitize_ip_list( string $raw ): string {
		$out = [];
		foreach ( preg_split( '/[\r\n,\s]+/', $raw ) ?: [] as $line ) {
			$ip = filter_var( trim( (string) $line ), FILTER_VALIDATE_IP );
			if ( false !== $ip ) {
				$out[ $ip ] = true;
			}
		}
		return implode( "\n", array_keys( $out ) );
	}

	private static function sanitize_slug_list( string $raw ): string {
		$lines = preg_split( '/\R+/', $raw ) ?: [];
		$slugs = [];

		foreach ( $lines as $line ) {
			$slug = sanitize_title( trim( $line ) );
			if ( $slug !== '' ) {
				$slugs[] = $slug;
			}
		}

		return implode( "\n", array_values( array_unique( $slugs ) ) );
	}

	private static function sanitize_hash_list( string $raw ): string {
		$lines = preg_split( '/\R+/', strtolower( $raw ) ) ?: [];
		$hashes = [];

		foreach ( $lines as $line ) {
			$hash = trim( $line );
			if ( preg_match( '/^[a-f0-9]{32}$/', $hash ) || preg_match( '/^[a-f0-9]{64}$/', $hash ) ) {
				$hashes[] = $hash;
			}
		}

		return implode( "\n", array_values( array_unique( $hashes ) ) );
	}

	/**
	 * 1.4.18: on-demand Akismet check, so the operator gets a definite answer
	 * now rather than after the next attack.
	 */
	/**
	 * 1.4.27: operator-initiated spam report for a blocked address.
	 *
	 * The trusted path: a human picked this row. It still checks a nonce and
	 * the manage_options capability, and reports each address at most once.
	 */
	/**
	 * 1.4.31: remove an address from the permanent sign-in denylist.
	 *
	 * A permanent block with no way to undo it is a trap, not a feature -
	 * addresses get reassigned, and the operator must be able to correct it
	 * without touching the database.
	 */
	public static function handle_unblock_permanent(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Insufficient permissions.' );
		}
		check_admin_referer( 'wps_unblock_permanent' );
		$ip = isset( $_POST['ip'] ) ? sanitize_text_field( (string) wp_unslash( $_POST['ip'] ) ) : '';
		$ok = class_exists( 'WPS_Login_Guard' ) ? WPS_Login_Guard::unblock_permanently( $ip ) : false;
		wp_safe_redirect(
			add_query_arg(
				[ 'page' => 'wp-perf-shield', 'tab' => 'diagnostics', 'wps_unblocked' => $ok ? '1' : '0' ],
				admin_url( 'tools.php' )
			)
		);
		exit;
	}

	public static function handle_chain_selftest(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Insufficient permissions.' );
		}
		check_admin_referer( 'wps_chain_selftest' );
		$result = class_exists( 'WPS_Chain_Selftest' ) ? WPS_Chain_Selftest::run() : null;
		if ( is_array( $result ) ) {
			// Short-lived: just long enough to survive the redirect and render once.
			set_transient( 'wps_chain_selftest_result', $result, 60 );
		}
		wp_safe_redirect(
			add_query_arg(
				[ 'page' => 'wp-perf-shield', 'tab' => 'diagnostics', 'wps_selftest' => is_array( $result ) ? 'done' : 'unavailable' ],
				admin_url( 'tools.php' )
			)
		);
		exit;
	}


	/**
	 * 1.4.91: mark a target Safe from the dashboard.
	 *
	 * The veto has existed since 1.4.88 with no way for an operator to use it,
	 * which made it a promise rather than a control: the plugin could refuse to
	 * remove something, but nobody could tell it to. This is that control.
	 *
	 * Scope is taken from the operator, not inferred. A file decision protects
	 * that file; a directory decision protects what is inside it. Nothing is
	 * broadened silently.
	 */
	public static function handle_mark_safe(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Insufficient permissions.' );
		}
		check_admin_referer( 'wps_mark_safe' );
		$path   = isset( $_POST['path'] ) ? sanitize_text_field( (string) wp_unslash( $_POST['path'] ) ) : '';
		$scope  = isset( $_POST['scope'] ) ? sanitize_key( (string) wp_unslash( $_POST['scope'] ) ) : 'file';
		$reason = isset( $_POST['reason'] ) ? sanitize_text_field( (string) wp_unslash( $_POST['reason'] ) ) : '';
		$ok     = false;
		if ( class_exists( 'WPS_Remediation_Policy' ) && '' !== $path ) {
			$ok = WPS_Remediation_Policy::mark_safe( $path, $scope, $reason );
		}
		wp_safe_redirect( add_query_arg(
			[ 'page' => 'wp-perf-shield', 'tab' => 'diagnostics', 'wps_safe' => $ok ? 'marked' : 'failed' ],
			admin_url( 'tools.php' )
		) );
		exit;
	}

	/** Revoke a Safe decision. Explicit act only - nothing revokes it implicitly. */
	public static function handle_revoke_safe(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Insufficient permissions.' );
		}
		check_admin_referer( 'wps_revoke_safe' );
		$path = isset( $_POST['path'] ) ? sanitize_text_field( (string) wp_unslash( $_POST['path'] ) ) : '';
		$ok   = class_exists( 'WPS_Remediation_Policy' ) && '' !== $path && WPS_Remediation_Policy::revoke_safe( $path );
		wp_safe_redirect( add_query_arg(
			[ 'page' => 'wp-perf-shield', 'tab' => 'diagnostics', 'wps_safe' => $ok ? 'revoked' : 'failed' ],
			admin_url( 'tools.php' )
		) );
		exit;
	}

	/** Clear the automatic-removal halt after the operator has reviewed it. */
	public static function handle_reset_breaker(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Insufficient permissions.' );
		}
		check_admin_referer( 'wps_reset_breaker' );
		if ( class_exists( 'WPS_Remediation_Policy' ) ) {
			WPS_Remediation_Policy::reset_breaker();
		}
		wp_safe_redirect( add_query_arg(
			[ 'page' => 'wp-perf-shield', 'tab' => 'diagnostics', 'wps_safe' => 'resumed' ],
			admin_url( 'tools.php' )
		) );
		exit;
	}

	public static function handle_permanent_block(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Insufficient permissions.' );
		}
		check_admin_referer( 'wps_permanent_block' );
		$target = isset( $_POST['target'] ) ? sanitize_text_field( (string) wp_unslash( $_POST['target'] ) ) : '';
		$target = trim( $target );
		$result = 'invalid';
		if ( class_exists( 'WPS_Login_Guard' ) && '' !== $target ) {
			if ( false !== strpos( $target, '/' ) ) {
				// A whole range. Cannot be reported to Akismet (per-address
				// model); its attacking members are reported when the guard
				// blocks them.
				$result = WPS_Login_Guard::block_permanently_cidr( $target, 'permanent range ban from Diagnostics', wp_get_current_user()->user_login ?? '' );
			} elseif ( false !== filter_var( $target, FILTER_VALIDATE_IP ) ) {
				if ( WPS_Login_Guard::block_permanently( $target, 'permanent ban from Diagnostics', wp_get_current_user()->user_login ?? '' ) ) {
					$result = 'blocked';
					// Trusted manual path: report the single address to Akismet.
					WPS_Login_Guard::report_ip_manually( $target, '' );
				} else {
					$result = 'protected';
				}
			}
		}
		wp_safe_redirect(
			add_query_arg(
				[ 'page' => 'wp-perf-shield', 'tab' => 'diagnostics', 'wps_pban' => $result ],
				admin_url( 'tools.php' )
			)
		);
		exit;
	}

	public static function handle_report_ip(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Insufficient permissions.' );
		}
		check_admin_referer( 'wps_report_ip' );		$ip   = isset( $_POST['ip'] ) ? sanitize_text_field( (string) wp_unslash( $_POST['ip'] ) ) : '';
		$user = isset( $_POST['user'] ) ? sanitize_text_field( (string) wp_unslash( $_POST['user'] ) ) : '';
		$result = class_exists( 'WPS_Login_Guard' ) ? WPS_Login_Guard::report_ip_manually( $ip, $user ) : 'failed';
		wp_safe_redirect(
			add_query_arg(
				[ 'page' => 'wp-perf-shield', 'tab' => 'diagnostics', 'wps_report' => $result ],
				admin_url( 'tools.php' )
			)
		);
		exit;
	}

	public static function handle_verify_akismet(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Insufficient permissions.' );
		}
		check_admin_referer( 'wps_verify_akismet' );
		$result = class_exists( 'WPS_Login_Guard' ) ? WPS_Login_Guard::verify_akismet() : 'unavailable';
		// 1.4.20: refresh the cached usage figure at the same time, so the
		// button reports one consistent picture rather than a fresh verdict
		// beside an hour-old number.
		if ( class_exists( 'WPS_Login_Guard' ) ) {
			WPS_Login_Guard::akismet_usage( true );
		}
		wp_safe_redirect(
			add_query_arg(
				[ 'page' => 'wp-perf-shield', 'tab' => 'settings', 'wps_ak' => $result ],
				admin_url( 'tools.php' )
			)
		);
		exit;
	}

	public static function render_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden' );
		}

		$stored_version = (string) get_option( 'wps_version', '' );
		if ( $stored_version !== WPS_VERSION ) {
			delete_option( 'wps_forensics_report' );
			update_option( 'wps_version', WPS_VERSION );
		}

		$context = self::build_context();
		$active_tab = $context['active_tab'];
		$tabs = $context['tabs'];
		$saved = $context['saved'];
		$findings = $context['findings'];
		?>
		<?php
		// 1.3.63: header pills moved from inline styles to CSS classes for two
		// reasons. (1) The previous `#c00` red on the magenta-tinted right
		// portion of the gradient header rendered as a muted lavender after
		// JPEG compression, which read as decorative rather than alerting.
		// (2) The version pill and the issue-count pill had identical pill
		// shapes and near-identical sizes, so they looked like equal-weight
		// metadata when in fact one is informational and the other is
		// actionable. The new CSS classes give the issue alert a stronger
		// visual signature (drop shadow, larger padding, pulsing alert dot)
		// and severity-aware colour so a critical finding looks materially
		// different from a medium finding. Severity ranking: critical > high
		// > medium > low > unknown. The highest severity present in the
		// findings array drives the alert colour.
		$severity_rank = [ 'critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1 ];
		$top_severity  = 'medium'; // safe default if no severity field is set
		$top_score     = 0;
		foreach ( $findings as $f ) {
			$sev   = strtolower( (string) ( $f['severity'] ?? '' ) );
			$score = $severity_rank[ $sev ] ?? 0;
			if ( $score > $top_score ) {
				$top_score    = $score;
				$top_severity = $sev;
			}
		}
		?>
		<div class="wrap wps-app" data-wps-scheme="<?php echo esc_attr( $context['appearance'] ?? 'light' ); ?>">
		<h1 class="wps-app-title">
			<img class="wps-app-mark" src="<?php echo esc_url( WPS_URL . 'assets/img/wp-perf-shield.svg' ); ?>" alt="" width="28" height="28">
			WP Perf Shield
			<span class="wps-version-pill">v<?php echo esc_html( WPS_VERSION ); ?></span>
			<?php if ( count( $findings ) > 0 ) : ?>
				<span class="wps-issue-alert wps-sev-<?php echo esc_attr( sanitize_html_class( $top_severity ) ); ?>">
					<span class="wps-issue-dot" aria-hidden="true"></span>
					<?php echo (int) count( $findings ); ?> issue<?php echo count( $findings ) !== 1 ? 's' : ''; ?>
				</span>
			<?php endif; ?>
		</h1>

		<?php if ( $saved ) : ?>
			<div class="notice notice-success is-dismissible" style="margin:8px 0"><p>Settings saved.</p></div>
		<?php endif; ?>

		<!-- Tab nav -->
		<nav class="nav-tab-wrapper">
			<?php
			// 1.3.66: $tab_group_starts marks tabs that begin a new functional
			// band (action -> observability -> config). The renderer adds a
			// `wps-tab-group-start` class that admin.css turns into a small
			// vertical separator.
			$tab_group_starts = $context['tab_group_starts'] ?? [];
			foreach ( $tabs as $slug => $label ) :
				$is_active      = ( $active_tab === $slug );
				$is_group_start = in_array( $slug, $tab_group_starts, true );
				$url            = admin_url( 'tools.php?page=wp-perf-shield&tab=' . $slug );
				$classes        = 'nav-tab';
				if ( $is_active )      $classes .= ' nav-tab-active';
				if ( $is_group_start ) $classes .= ' wps-tab-group-start';
				?>
				<a href="<?php echo esc_url( $url ); ?>"
				 class="<?php echo esc_attr( $classes ); ?>"
				 <?php echo $is_active ? 'aria-current="page"' : ''; ?>
				>
					<?php echo esc_html( $label ); ?>
				</a>
			<?php endforeach; ?>
		</nav>

		<?php
		switch ( $active_tab ) {
			case 'overview':
				WPS_Admin_Overview::render( $context );
				break;
			case 'diagnostics':
				WPS_Admin_Diagnostics::render( $context );
				break;
			case 'remediation':
				WPS_Admin_Remediation::render( $context );
				break;
			case 'forensics':
				WPS_Admin_Forensics::render( $context );
				break;
			case 'hardening':
				WPS_Admin_Hardening::render( $context );
				break;
			case 'events':
				WPS_Admin_Events::render( $context );
				break;
			case 'logs':
				WPS_Admin_Logs::render( $context );
				break;
			case 'settings':
				WPS_Admin_Settings::render( $context );
				break;
			case 'docs':
				WPS_Admin_Docs::render( $context );
				break;
		}
		?>

		</div><!-- .wrap -->
		<?php
	}

	/**
	 * Build the shared context array passed to every tab renderer. Centralising
	 * the data assembly here keeps tab classes stateless and lets future tabs
	 * pull only what they need.
	 */
	private static function build_context(): array {
		$settings              = get_option( WPS_OPTION, [] );
		// 1.3.99: the Events tab prefers the tamper-evident store; the file log
		// remains the fallback when the DB store is unavailable.
		$event_log_status = null;
		if ( class_exists( 'WPS_Event_Log' ) && WPS_Event_Log::available() ) {
			$store_rows = WPS_Event_Log::latest( 200 );
			$events     = array_map( static function ( $r ) {
				return [
					'time'    => (string) ( $r['ts'] ?? '' ) . ' UTC',
					'type'    => (string) ( $r['event_type'] ?? '' ),
					'subject' => (string) ( $r['notes'] ?? ( $r['object_name'] ?? '' ) ),
					'ip'      => (string) ( $r['ip'] ?? '' ),
					'user'    => (string) ( $r['username'] ?? '' ),
					'chained' => ( $r['hmac_signature'] ?? '' ) !== '',
				];
			}, $store_rows );
			$event_log_status = WPS_Event_Log::verify_chain();
		} else {
			$events = array_reverse( WPS_Logger::read_events() );
		}
		$last_scan             = get_option( 'wps_last_scan', null );
		$cached                = get_transient( 'wps_scan_results' );
		$findings              = is_array( $cached ) ? $cached : [];
		$auto_delete_enabled   = ( $settings['auto_delete_enabled'] ?? '1' ) !== '0';
		$quarantine_enabled    = ( $settings['quarantine_enabled'] ?? '1' ) !== '0';
		$appearance_raw        = $settings['appearance'] ?? 'light';
		$appearance            = in_array( $appearance_raw, [ 'auto', 'light', 'dark' ], true ) ? $appearance_raw : 'light';
		$auto_ip_block_enabled = ( $settings['auto_ip_block_enabled'] ?? '1' ) !== '0';
		$strict_upload_gate    = ( $settings['strict_upload_gate_enabled'] ?? '1' ) !== '0';
		$blocked_ips           = WPS_Blocker::get_blocked_ips();
		$saved                 = isset( $_GET['saved'] );
		$requested_tab         = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'overview';
		$tab_aliases           = [
			'dashboard' => 'overview',
			'analytics' => 'diagnostics',
			'log'       => 'events',
		];
		$active_tab            = $tab_aliases[ $requested_tab ] ?? $requested_tab;
		// 1.3.35: Forensics moved before Diagnostics. Source Trace on Diagnostics
		// requires Forensics to have run first; the old order had the dependency
		// backwards. Slugs are unchanged, so existing tab=diagnostics URLs still
		// resolve.
		// 1.3.66: tab order regrouped into three functional bands and the
		// first tab of each non-leading group is marked with a class that
		// CSS uses to render a subtle vertical separator. Previous order
		// interleaved observability tabs (Diagnostics, Events) among action
		// tabs (Overview, Forensics, Remediation, Hardening) for no good
		// reason. The new order:
		//   action band   : Overview, Forensics, Remediation, Hardening
		//   observe band  : Diagnostics, Events
		//   config band   : Settings
		// `$tab_group_starts` lists the slug of the first tab in each new
		// band after the leading band. The renderer adds a CSS class to
		// those tabs and admin.css uses left padding + a 1px line to mark
		// the group boundary.
		$tabs                  = [
			'overview'    => 'Overview',
			'forensics'   => 'Forensics',
			'remediation' => 'Remediation',
			'hardening'   => 'Hardening',
			'diagnostics' => 'Diagnostics',
			'events'      => 'Events',
			'logs'        => 'Logs',
			'settings'    => 'Settings',
			'docs'        => 'Docs',
		];
		$tab_group_starts      = [ 'diagnostics', 'settings' ];
		if ( ! isset( $tabs[ $active_tab ] ) ) {
			$active_tab = 'overview';
		}

		$system_checks = [
			[
				'label'  => 'Log directory writable',
				'ok'     => WPS_Logger::can_write(),
				'detail' => WPS_LOG_DIR,
			],
			[
				'label'  => 'Admin CSS asset present',
				'ok'     => is_readable( WPS_DIR . 'assets/css/admin.css' ),
				'detail' => 'assets/css/admin.css',
			],
			[
				'label'  => 'Admin JS asset present',
				'ok'     => is_readable( WPS_DIR . 'assets/js/admin.js' ),
				'detail' => 'assets/js/admin.js',
			],
			[
				'label'  => 'ZIP content inspection available',
				'ok'     => class_exists( 'ZipArchive' ),
				'detail' => class_exists( 'ZipArchive' ) ? 'ZipArchive enabled' : 'Enable the PHP ZipArchive extension for renamed-ZIP malware inspection',
			],
			[
				'label'  => 'wp-cron.php writable',
				'ok'     => is_writable( ABSPATH . 'wp-cron.php' ),
				'detail' => ABSPATH . 'wp-cron.php',
			],
		];

		$event_labels = [
			'activation_blocked'      => 'Activation blocked',
			'removed_from_db'         => 'Removed from active list',
			'force_deactivated'       => 'Force-deactivated',
			'upload_blocked'          => 'Upload blocked',
			'external_post_write_blocked' => 'External post write blocked',
			'injected_spam_content'       => 'Injected spam content found',
			'disguised_plugin_index_found' => 'Disguised web shell found',
			'policy_banned_plugin_found'  => 'Banned plugin found installed (site policy)',
			'htaccess_php_allowlist_found' => 'PHP allowlist in .htaccess (shell persistence)',
			'self_hiding_plugin_found'    => 'Self-concealing plugin found',
			'split_string_obfuscation_found' => 'Search-evading obfuscation found',
			'opaque_data_payload_found'   => 'Payload hidden in a data file',
			'comment_split_keywords_found' => 'Code split by junk comments',
			'remote_script_injection_found' => 'Remote script injection found',
			'hidden_admin_backdoor_found' => 'Hidden administrator backdoor found',
			'unattributed_plugin_found'   => 'Plugin appeared with no install recorded',
			'malware_source_attributed'   => 'Malware source attributed and reported',
			'db_resident_payload_found'   => 'Payload stored in the database',
			'plugin_roster_baselined'     => 'Plugin roster baselined',
			'spam_post_injection_detected' => 'Spam post injection detected',
			'upload_path_blocked'     => 'Upload pathway blocked',
			'policy_activation_blocked'        => 'Activation refused (site policy)',
			'policy_upload_blocked'            => 'Upload refused (site policy)',
			'policy_force_deactivated'         => 'Banned plugin deactivated (site policy)',
			'policy_network_force_deactivated' => 'Banned network plugin deactivated (site policy)',
			'policy_removed_from_db'           => 'Banned plugin removed from active list (site policy)',
			'policy_removed_from_network_db'   => 'Banned network plugin removed (site policy)',
			'chain_selftest'                   => 'Event-chain self-test',
			'ip_auto_blocked'         => 'IP auto-blocked',
			'ip_block_refreshed'      => 'IP block refreshed',
			'ip_request_blocked'      => 'IP request blocked',
			'ip_blocks_cleared'       => 'IP blocks cleared',
			'self_block_bypassed'     => 'Self-block bypassed (admin)',
			'scan_issues'             => 'Scan found issues',
			'scan_clean'              => 'Scan clean',
			'auto_deleted'            => 'Auto-deleted',
			'redrop_recorded'         => 'Redrop baseline recorded',
			'redrop_detected'         => 'Redrop detected (previously-cleaned hash reappeared)',
			'core_checksum_mismatch'  => 'WP core file integrity violation (api.wordpress.org sha1 mismatch)',
			'maintenance_stale'       => 'Stale .maintenance file (site locked in maintenance mode)',
			'hidden_admin_user'       => 'Hidden admin user (direct-DB count > get_users() count)',
			'malware_username_in_db'  => 'Known malware-created admin username found in wp_users',
			'malware_email_pattern_in_db' => 'Admin user with wp-security-cache.php email pattern in wp_users',
			'unknown_drop_in'         => 'WordPress drop-in PHP at wp-content/ from unknown publisher (high attack-surface)',
			'clickfix_shape_match'    => 'Fake-plugin-folder ClickFix shape detected by structural traits (1.3.58 heuristic)',
			'auto_deactivated'        => 'Auto-deactivated',
			'auto_deactivated_orphan' => 'Orphan plugin deactivated',
			'db_option_deleted'       => 'DB option deleted',
			'db_option_deleted_unknown_b64' => 'DB option deleted (unknown base64)',
			'cron_replaced'           => 'wp-cron.php replaced',
			'cron_purged'             => 'Malicious cron hook purged',
			'exfil_file_read'         => 'Exfil file read',
			'exfil_file_deleted'      => 'Exfil file deleted',
			'login_cleaned'           => 'wp-login.php cleaned',
			'functions_cleaned'       => 'functions.php cleaned',
			'sessions_invalidated'    => 'Sessions invalidated',
			'transients_cleared'      => 'Transients cleared',
			'salts_regenerated'       => 'Auth salts regenerated',
			'user_deleted'            => 'User account deleted',
			'attachment_deleted'      => 'Attachment deleted',
			'plugin_folder_deleted'   => 'Plugin folder deleted',
			'file_deleted'            => 'File deleted',
			'theme_file_deleted'      => 'Theme file deleted',
			'attacker_account_found'  => 'Suspect account detected',
			'wp_config_hash_stored'   => 'wp-config.php hash stored',
			'wp_config_modified'      => 'wp-config.php hash changed',
			'wp_config_cleaned'       => 'wp-config.php cleaned',
			'wp_config_clean_skipped' => 'wp-config.php clean skipped',
			'core_integrity_fail'     => 'Core file modified',
			'mtime_check_suppressed'  => 'Mass-event mtime suppressed',
		];

		return [
			'settings'                   => $settings,
			'events'                     => $events,
			'event_log_status'           => $event_log_status,
			'last_scan'                  => $last_scan,
			'findings'                   => $findings,
			'auto_delete_enabled'        => $auto_delete_enabled,
			'quarantine_enabled'         => $quarantine_enabled,
			'appearance'                 => $appearance,
			'auto_ip_block_enabled'      => $auto_ip_block_enabled,
			'strict_upload_gate_enabled' => $strict_upload_gate,
			'blocked_ips'                => $blocked_ips,
			'saved'                      => $saved,
			'tabs'                       => $tabs,
			'tab_group_starts'           => $tab_group_starts,
			'active_tab'                 => $active_tab,
			'system_checks'              => $system_checks,
			'event_labels'               => $event_labels,
		];
	}
}
