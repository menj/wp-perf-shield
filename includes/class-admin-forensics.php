<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Forensics tab renderer (Phase 3 split from class-admin.php).
 *
 * Renders the Run Forensics button, the cached-report status panel, and
 * the structured cards (media uploads, plugin file timestamps, admin
 * accounts, wp-cron integrity, theme tampering, DB anomalies, automated
 * PHP checks, core integrity, SSH-only command set). Markup, severity
 * colour mapping, and the inline action-button JSON payloads are unchanged
 * from the pre-split renderer.
 */
class WPS_Admin_Forensics {

	public static function render( array $context ): void {
		?>
		<div class="wps-tab">

			<div class="wps-card-head">
				<p class="wps-p0 wps-muted">Runs a forensic scan using WordPress-level data (media library, admin accounts, option table, file timestamps). Generates SSH commands to complete the trace from server access logs.</p>
				<button id="wps-forensics-btn" class="button button-primary wps-nowrap wps-mlauto"><span class="wps-icon dashicons dashicons-search" aria-hidden="true"></span>Run forensics</button>
			</div>
			<div id="wps-forensics-status" class="wps-status"></div>

			<?php if ( class_exists( 'WPS_Quarantine' ) ) { self::render_quarantine(); } ?>

			<div id="wps-forensics-results">
			<?php
			$report = get_option( 'wps_forensics_report', null );
			if ( is_array( $report ) ) {
				self::render_forensics( $report );
			} else {
				echo '<p class="wps-dim">No forensics report yet. Click "Run forensics" to analyse your site.</p>';
			}
			?>
			</div>

		</div><!-- /forensics tab -->
		<?php
	}

	/**
	 * 1.3.94: Quarantine store  recoverable removed threats. Always visible in
	 * the Forensics tab, independent of running a forensics report.
	 */
	private static function render_quarantine(): void {
		if ( ! class_exists( 'WPS_Quarantine' ) ) {
			return;
		}
		$entries   = WPS_Quarantine::list_entries();
		$retention = (int) WPS_Quarantine::RETENTION_DAYS;
		self::forensic_card( '<span class="wps-icon dashicons dashicons-lock" aria-hidden="true"></span>Quarantine (recoverable removed threats)', false );

		if ( ! $entries ) {
			echo '<p class="wps-sm wps-muted wps-p0">Empty. When a confirmed threat is removed it is moved here  neutralised and non-executable  instead of being destroyed, so a false positive can be restored. Entries are purged automatically after ' . $retention . ' days.</p>';
			echo '</div>';
			return;
		}

		echo '<p class="wps-sm wps-muted wps-p">Removed threats are moved here (neutralised, non-executable) rather than destroyed. Restore a false positive, or purge for good. Auto-purged after ' . $retention . ' days.</p>';
		echo '<div class="wps-scroll-x"><table class="wps-table wps-table--w520"><thead><tr>';
		foreach ( [ 'Quarantined (UTC)', 'Type', 'Original path', '' ] as $h ) {
			echo '<th>' . esc_html( $h ) . '</th>';
		}
		echo '</tr></thead><tbody>';
		$abs = defined( 'ABSPATH' ) ? rtrim( str_replace( '\\', '/', ABSPATH ), '/' ) . '/' : '';
		foreach ( $entries as $m ) {
			$id   = (string) ( $m['id'] ?? '' );
			$when = ! empty( $m['quarantined_at'] ) ? gmdate( 'Y-m-d H:i', (int) $m['quarantined_at'] ) : '?';
			$type = (string) ( $m['type'] ?? ( $m['kind'] ?? '' ) );
			$orig = str_replace( '\\', '/', (string) ( $m['original_path'] ?? '' ) );
			$rel  = ( $abs && strpos( $orig, $abs ) === 0 ) ? substr( $orig, strlen( $abs ) ) : $orig;
			echo '<tr>';
			echo '<td class="wps-mono wps-nowrap">' . esc_html( $when ) . '</td>';
			echo '<td>' . esc_html( $type ) . '</td>';
			echo '<td class="wps-mono wps-break">' . esc_html( $rel ) . '</td>';
			echo '<td class="wps-nowrap">';
			echo self::forensic_action_button( 'Restore', 'wps_quarantine_restore', [ 'quarantine_id' => $id ], 'Restore this item to its original location? Only do this if you are certain it is a false positive.', 'wps-btn-sm' );
			echo ' ' . self::forensic_action_button( 'Delete', 'wps_quarantine_purge', [ 'quarantine_id' => $id ], 'Permanently delete this quarantined item? This cannot be undone.' );
			echo '</td></tr>';
		}
		echo '</tbody></table></div>';
		echo '<div class="wps-mt10">' . self::forensic_action_button( 'Empty quarantine', 'wps_quarantine_empty', [], 'Permanently delete ALL quarantined items? This cannot be undone.' ) . '</div>';
		echo '</div>';
	}

	/** Render the forensics report every finding has an inline action button. */
	private static function render_forensics( array $report ): void {
		$generated = esc_html( $report['generated'] ?? 'unknown' );

		echo '<p class="wps-sm wps-dim wps-p">Generated: ' . $generated . '</p>';

		// Media uploads
		$uploads = $report['media_uploads'] ?? [];
		$mal = $uploads['malicious_uploads'] ?? [];
		$zips = $uploads['recent_zips'] ?? [];

		self::forensic_card( '<span class="wps-icon dashicons dashicons-archive" aria-hidden="true"></span>Malicious ZIP uploads in media library', count( $mal ) > 0 );
		if ( $mal ) {
			echo '<div class="wps-scroll-x"><table class="wps-table wps-table--w560"><thead><tr>';
			echo '<th>Title</th>';
			echo '<th>Upload ID</th>';
			echo '<th>Uploaded</th>';
			echo '<th>Action</th>';
			echo '</tr></thead><tbody>';
			foreach ( $mal as $u ) {
				echo '<tr>';
				echo '<td class="wps-mono">' . esc_html( $u['title'] ) . '</td>';
				echo '<td class="wps-muted">' . esc_html( (string)( $u['id'] ?? '?' ) ) . '</td>';
				echo '<td>' . esc_html( $u['uploaded_at'] ) . '</td>';
				echo '<td>';
				if ( ! empty( $u['id'] ) ) {
					echo self::forensic_action_button(
						'<span class="wps-icon dashicons dashicons-trash" aria-hidden="true"></span>Delete attachment',
						'wps_delete_attachment',
						[ 'id' => (int) $u['id'] ],
						'Permanently delete this media attachment?'
					);
				} else {
					echo '<span class="wps-xs wps-dim">Manually delete via SSH</span>';
				}
				echo '</td></tr>';
			}
			echo '</tbody></table></div>';
		} else {
			echo '<p class="wps-sm wps-muted wps-p">No matching uploads found in media library (may have been deleted check server logs).</p>';
		}
		if ( $zips ) {
			echo '<details class="wps-mt8"><summary class="wps-sm wps-muted">All recent ZIP uploads (last 14 days)</summary>';
			echo '<table class="wps-sm wps-mt8 wps-table">';
			foreach ( $zips as $z ) {
				echo '<tr><td class="wps-mono">' . esc_html( $z['title'] ) . '</td><td class="wps-muted">' . esc_html( $z['uploaded_at'] ) . '</td></tr>';
			}
			echo '</table></details>';
		}
		echo '</div>';

		// Plugin file timestamps
		$plugin_files = $report['plugin_files'] ?? [];
		self::forensic_card( '<span class="wps-icon dashicons dashicons-calendar-alt" aria-hidden="true"></span>Malicious plugin file timestamps (oldest = likely entry point)', count( $plugin_files ) > 0 );
		if ( $plugin_files ) {
			echo '<div class="wps-scroll-x"><table class="wps-table wps-table--w560"><thead><tr>';
			echo '<th>File</th>';
			echo '<th>Modified</th>';
			echo '<th>MD5</th>';
			echo '<th>Action</th>';
			echo '</tr></thead><tbody>';
			foreach ( $plugin_files as $f ) {
				echo '<tr>';
				echo '<td class="wps-mono wps-xs">' . esc_html( $f['file'] ) . '</td>';
				echo '<td>' . esc_html( $f['modified'] ) . '</td>';
				echo '<td class="wps-mono wps-xs">' . esc_html( $f['md5'] ) . '</td>';
				echo '<td>';
				echo self::forensic_action_button(
					'<span class="wps-icon dashicons dashicons-trash" aria-hidden="true"></span>Delete folder',
					'wps_delete_plugin_folder',
					[ 'path' => (string) ( $f['path'] ?? '' ) ],
					'Delete this plugin folder and all its files?'
				);
				echo '</td></tr>';
			}
			echo '</tbody></table></div>';
		} else {
			echo '<p class="wps-sm wps-good-t wps-p0"> No suspicious plugin files found on disk.</p>';
		}
		echo '</div>';

		// Admin accounts
		$admins = $report['admin_accounts'] ?? [];
		$malware_created_accounts = WPS_Indicators::hardcoded_admin_usernames();
		$suspicious_admins = array_filter( $admins, fn( $a ) => $a['suspicious'] );
		$current_user = wp_get_current_user();

		self::forensic_card( '<span class="wps-icon dashicons dashicons-admin-users" aria-hidden="true"></span>Administrator accounts', count( $suspicious_admins ) > 0 );
		if ( $admins ) {
			echo '<div class="wps-scroll-x"><table class="wps-table wps-table--w560"><thead><tr>';
			echo '<th>Username</th>';
			echo '<th>Email</th>';
			echo '<th>Registered</th>';
			echo '<th>Status</th>';
			echo '<th>Action</th>';
			echo '</tr></thead><tbody>';
			foreach ( $admins as $a ) {
				$is_malware_created = in_array( $a['login'], $malware_created_accounts, true );
				$is_self = ( $current_user->user_login === $a['login'] );
				$row_class = $is_malware_created ? 'wps-tr-alert' : ( $a['suspicious'] ? 'wps-tr-warn' : '' );
				echo '<tr class="' . esc_attr( $row_class ) . '">';
				echo '<td class="wps-mono' . ( $is_malware_created ? ' wps-strong' : '' ) . '">' . esc_html( $a['login'] ) . '</td>';
				echo '<td>' . esc_html( $a['email'] ) . '</td>';
				echo '<td>' . esc_html( $a['registered'] ) . '</td>';
				// Status column
				if ( $is_malware_created ) {
					echo '<td class="wps-bad-t wps-strong wps-xs">Known malware-created</td>';
				} elseif ( $a['flags'] ) {
					echo '<td class="wps-warn-t wps-xs"> ' . esc_html( implode( ', ', $a['flags'] ) ) . '</td>';
				} else {
					echo '<td class="wps-good-t"> ok</td>';
				}
				// Action column
				echo '<td>';
				if ( $is_self ) {
					echo '<span class="wps-xs wps-dim">Current user cannot delete self</span>';
				} elseif ( $is_malware_created || $a['suspicious'] ) {
					echo self::forensic_action_button(
						'<span class="wps-icon dashicons dashicons-trash" aria-hidden="true"></span>Delete account',
						'wps_delete_user',
						[ 'user_id' => (int) ( $a['id'] ?? 0 ) ],
						'Permanently delete user account: ' . (string) $a['login'] . '? This cannot be undone.'
					);
				}
				echo '</td></tr>';
			}
			echo '</tbody></table></div>';
		}
		echo '</div>';

		// wp-cron.php integrity
		$cron = $report['cron_integrity'] ?? [];
		$tampered = ( $cron['status'] ?? '' ) === 'TAMPERED';
		$cron_status = (string) ( $cron['status'] ?? 'unknown' );
		$cron_status_class = $tampered ? 'wps-bad-t' : ( $cron_status === 'verified_clean' ? 'wps-good-t' : 'wps-warn-t' );
		self::forensic_card( '<span class="wps-icon dashicons dashicons-clock" aria-hidden="true"></span>wp-cron.php integrity', $tampered );
		if ( $cron ) {
			echo '<table class="wps-sm wps-table">';
			echo '<tr><td class="wps-dim" style="width:90px">Status</td><td class="wps-strong ' . esc_attr( $cron_status_class ) . '">' . esc_html( $cron_status ) . '</td></tr>';
			echo '<tr><td class="wps-dim">WP version</td><td>' . esc_html( $cron['version'] ?? 'unknown' ) . '</td></tr>';
			echo '<tr><td class="wps-dim">Modified</td><td>' . esc_html( $cron['modified'] ?? 'unknown' ) . '</td></tr>';
			echo '<tr><td class="wps-dim">MD5</td><td class="wps-mono wps-xs">' . esc_html( $cron['md5'] ?? '' ) . '</td></tr>';
			if ( ! empty( $cron['expected_md5'] ) ) {
				echo '<tr><td class="wps-dim">Expected MD5</td><td class="wps-mono wps-xs">' . esc_html( $cron['expected_md5'] ) . '</td></tr>';
			}
			if ( ! empty( $cron['note'] ) ) {
				echo '<tr><td class="wps-dim">Note</td><td class="wps-muted">' . esc_html( $cron['note'] ) . '</td></tr>';
			}
			echo '</table>';
			if ( $tampered ) {
				echo '<div class="wps-mt10">';
				echo self::forensic_action_button(
					'<span class="wps-icon dashicons dashicons-update" aria-hidden="true"></span>Replace wp-cron.php now',
					'wps_clean_cron',
					[],
					'Download a clean wp-cron.php from wordpress.org and replace the tampered version?',
					'color:#a00;border-color:#a00'
				);
				echo '</div>';
			}
		}
		echo '</div>';

		// Theme file integrity
		$theme = $report['theme_tampering'] ?? [];
		$theme_issues = array_filter( $theme, fn( $t ) => $t['status'] === 'INFECTED' );
		self::forensic_card( '<span class="wps-icon dashicons dashicons-admin-appearance" aria-hidden="true"></span>Theme file integrity', count( $theme_issues ) > 0 );
		foreach ( $theme as $tf ) {
			$infected = ( $tf['status'] === 'INFECTED' );
			$status_class = $infected ? 'wps-bad-t' : 'wps-good-t';
			echo '<div class="wps-finding wps-listrow">';
			echo '<span class="wps-mono wps-sm wps-flex1">' . esc_html( $tf['file'] ) . '</span>';
			echo '<span class="wps-strong wps-xs ' . $status_class . '">' . esc_html( $tf['status'] ) . '</span>';
			echo '<span class="wps-xs wps-dim">modified ' . esc_html( $tf['modified'] ) . '</span>';
			if ( $tf['matches'] ) {
				echo '<span class="wps-bad-t wps-xs">matches: ' . esc_html( implode( ', ', $tf['matches'] ) ) . '</span>';
			}
			if ( $infected ) {
				// Determine which clean action applies
				if ( strpos( $tf['file'] ?? '', 'functions.php' ) !== false ) {
					echo self::forensic_action_button(
						'<span class="wps-icon dashicons dashicons-editor-removeformatting" aria-hidden="true"></span>Clean now',
						'wps_clean_functions',
						[],
						'Remove the credential harvester injection from functions.php?'
					);
				} else {
					echo self::forensic_action_button(
						'<span class="wps-icon dashicons dashicons-trash" aria-hidden="true"></span>Delete file',
						'wps_delete_theme_file',
						[ 'path' => (string) ( $tf['full_path'] ?? '' ) ],
						'Delete this theme file? Only do this if you are sure it is not a legitimate file.'
					);
				}
			}
			echo '</div>';
		}
		if ( ! $theme ) {
			echo '<p class="wps-sm wps-muted wps-p0">No theme files checked.</p>';
		}
		echo '</div>';

		// Database anomalies inline delete button per option
		$options = $report['option_anomalies'] ?? [];
		if ( $options ) {
			self::forensic_card( '<span class="wps-icon dashicons dashicons-warning" aria-hidden="true"></span>Database anomalies detected', true );
			foreach ( $options as $o ) {
				echo '<div class="wps-finding wps-callout-bad">';
				echo '<div class="wps-flex1 wps-sm">';
				echo '<strong class="wps-bad-t">' . esc_html( $o['type'] ) . '</strong>: ';
				echo '<code class="wps-chip">' . esc_html( $o['option_name'] ?? $o['detail'] ) . '</code>';
				if ( ! empty( $o['preview'] ) ) {
					echo '<div class="wps-xs wps-dim wps-mono wps-break">' . esc_html( $o['preview'] ) . '</div>';
				}
				echo '</div>';
				echo self::forensic_action_button(
					'<span class="wps-icon dashicons dashicons-trash" aria-hidden="true"></span>Delete now',
					'wps_delete_single_option',
					[ 'option_name' => (string) ( $o['option_name'] ?? '' ) ],
					'Delete DB option: ' . (string) ( $o['option_name'] ?? '' ) . '?',
					'color:#a00;border-color:#a00;font-size:11px;height:24px;line-height:22px;padding:0 8px;white-space:nowrap;flex-shrink:0'
				);
				echo '</div>';
			}
			echo '</div>';
		}

		// auto_prepend_file / auto_append_file sweep (1.3.40)
		$auto_prepend = $report['auto_prepend_anomalies'] ?? [];
		if ( $auto_prepend ) {
			self::forensic_card( '<span class="wps-icon dashicons dashicons-shield" aria-hidden="true"></span>Auto-prepend / auto-append directives (.user.ini / .htaccess / php.ini)', true );
			echo '<p class="wps-xs wps-dim wps-p">PHP runs the file referenced by these directives before every request. A dropper hiding under <code>auto_prepend_file</code> is invisible to plugin walkers and to scanners that only look inside the WordPress tree.</p>';
			foreach ( $auto_prepend as $a ) {
				$verdict = (string) ( $a['verdict'] ?? 'review' );
				$bg = $verdict === 'critical' ? '#fff5f5' : '#fff9de';
				$border = $verdict === 'critical' ? '#e24b4a' : '#d4af00';
				$label_class = $verdict === 'critical' ? 'wps-bad-t' : 'wps-warn-deep-t'; $box_class = $verdict === 'critical' ? 'wps-callout-bad' : 'wps-callout-warn';
				echo '<div class="wps-finding wps-mb6 ' . $box_class . '">';
				echo '<div class="wps-sm"><strong class="' . $label_class . '">' . esc_html( $a['directive'] ?? 'auto_prepend_file' ) . '</strong> in <code class="wps-xs wps-chip wps-chip--plain">' . esc_html( $a['config_file'] ?? '?' ) . '</code></div>';
				echo '<div class="wps-xs wps-muted wps-mt8 wps-mono wps-break">target: ' . esc_html( $a['target'] ?? '' ) . '</div>';
				echo '<div class="wps-xs wps-muted wps-mt8">' . esc_html( $a['action'] ?? '' ) . '</div>';
				echo '</div>';
			}
			echo '</div>';
		}

		// Cron callback resolution (1.3.40)
		$cron_callbacks = $report['cron_callbacks'] ?? [];
		if ( $cron_callbacks ) {
			self::forensic_card( '<span class="wps-icon dashicons dashicons-clock" aria-hidden="true"></span>Cron callbacks resolving outside expected directories', true );
			echo '<p class="wps-xs wps-dim wps-p">Each scheduled cron callback was resolved to its source file via Reflection. A callback that resolves to <code>wp-content/uploads/</code>, <code>wp-content/cache/</code>, <code>/tmp/</code>, or to a known backdoor filename is the redropper.</p>';
			foreach ( $cron_callbacks as $c ) {
				$verdict = (string) ( $c['verdict'] ?? 'outside_expected_dirs' );
				$is_critical = in_array( $verdict, [ 'malicious_substring', 'known_backdoor_filename' ], true );
				$bg = $is_critical ? '#fff5f5' : '#fff9de';
				$border = $is_critical ? '#e24b4a' : '#d4af00';
				$label_class = $is_critical ? 'wps-bad-t' : 'wps-warn-deep-t'; $box_class = $is_critical ? 'wps-callout-bad' : 'wps-callout-warn';
				echo '<div class="wps-finding wps-mb6 wps-flexwrap ' . $box_class . '">';
				echo '<div class="wps-flex1 wps-sm">';
				echo '<strong class="' . $label_class . '">' . esc_html( $c['hook'] ?? '?' ) . '</strong> <span class="wps-xs wps-dim">(next run: ' . esc_html( $c['next_run'] ?? '?' ) . ')</span>';
				echo '<div class="wps-xs wps-muted wps-mt8 wps-mono wps-break">callback: ' . esc_html( $c['callback'] ?? '?' ) . '</div>';
				echo '<div class="wps-xs wps-muted wps-mono wps-break">source: ' . esc_html( $c['source'] ?? '?' ) . '</div>';
				echo '<div class="wps-xs wps-muted">verdict: <em>' . esc_html( $verdict ) . '</em>  ' . esc_html( $c['action'] ?? '' ) . '</div>';
				echo '</div></div>';
			}
			echo '</div>';
		}

		// Unknown base64-encoded option values (1.3.40)
		$unknown_b64 = $report['unknown_base64_options'] ?? [];
		if ( $unknown_b64 ) {
			self::forensic_card( '<span class="wps-icon dashicons dashicons-search" aria-hidden="true"></span>Suspicious base64-encoded option values (not on known-bad list)', true );
			echo '<p class="wps-xs wps-dim wps-p">A wp_options row whose value decodes to PHP source or to the ClickFix family\'s outer JS loader is the persistence option for a campaign whose name is not yet in the indicator catalogue.</p>';
			echo '<div class="wps-p">';
			echo self::forensic_action_button(
				'<span class="wps-icon dashicons dashicons-trash" aria-hidden="true"></span>Delete all ' . count( $unknown_b64 ) . ' flagged option' . ( 1 === count( $unknown_b64 ) ? '' : 's' ),
				'wps_delete_all_unknown_b64',
				[],
				'Delete ALL ' . count( $unknown_b64 ) . ' flagged base64 options? Each one decodes to PHP source or the ClickFix JS loader. Core WordPress options are always skipped.',
				'color:#fff;background:#a00;border-color:#a00;font-size:12px;font-weight:600;height:30px;line-height:28px;padding:0 14px'
			);
			echo '</div>';
			foreach ( $unknown_b64 as $o ) {
				$verdict = (string) ( $o['verdict'] ?? 'review' );
				echo '<div class="wps-finding wps-callout-bad">';
				echo '<div class="wps-flex1 wps-sm">';
				echo '<strong class="wps-bad-t">' . esc_html( $verdict ) . '</strong> in <code class="wps-chip">' . esc_html( $o['option_name'] ?? '?' ) . '</code> <span class="wps-xs wps-dim">(' . esc_html( $o['length'] ?? '?' ) . ' bytes encoded)</span>';
				if ( ! empty( $o['preview'] ) ) {
					echo '<div class="wps-xs wps-dim wps-mono wps-break">decoded preview: ' . esc_html( $o['preview'] ) . '</div>';
				}
				echo '<div class="wps-xs wps-muted">' . esc_html( $o['action'] ?? '' ) . '</div>';
				echo '</div>';
				echo self::forensic_action_button(
					'<span class="wps-icon dashicons dashicons-trash" aria-hidden="true"></span>Delete now',
					'wps_delete_unknown_b64',
					[ 'option_name' => (string) ( $o['option_name'] ?? '' ) ],
					'Delete DB option: ' . (string) ( $o['option_name'] ?? '' ) . '? Inspect the decoded preview first.',
					'color:#a00;border-color:#a00;font-size:11px;height:24px;line-height:22px;padding:0 8px;white-space:nowrap;flex-shrink:0'
				);
				echo '</div>';
			}
			echo '</div>';
		}

		// PHP-executable forensic checks
		// Run directly from the plugin no SSH needed
		$php_checks = $report['php_checks'] ?? [];
		if ( $php_checks ) {
			self::forensic_card( '<span class="wps-icon dashicons dashicons-search" aria-hidden="true"></span>Automated checks (PHP-executable)', false );
			foreach ( $php_checks as $chk ) {
				$has_results = ! empty( $chk['results'] );
				$box_class = $has_results ? 'wps-box-alert' : 'wps-box-soft';
				echo '<div class="wps-mb6 ' . $box_class . '">';
				echo '<div class="wps-row' . ( $has_results ? ' wps-mb6' : '' ) . '">';
				echo '<span class="wps-sm wps-strong ' . ( $has_results ? 'wps-bad-t' : 'wps-good-t' ) . '">' . ( $has_results ? '' : '' ) . '</span>';
				echo '<span class="wps-sm">' . esc_html( $chk['label'] ) . '</span>';
				echo '<span class="wps-xs wps-dim wps-mlauto">' . esc_html( $chk['count'] ?? '' ) . '</span>';
				echo '</div>';
				if ( $has_results ) {
					echo '<div class="wps-scroll-box">';
					echo '<table class="wps-xs wps-mono wps-table">';
					foreach ( array_slice( $chk['results'], 0, 20 ) as $row ) {
						echo '<tr>';
						echo '<td class="wps-break">' . esc_html( $row['path'] ?? $row ) . '</td>';
						if ( ! empty( $row['modified'] ) ) {
							echo '<td class="wps-dim wps-nowrap">' . esc_html( $row['modified'] ) . '</td>';
						}
						if ( ! empty( $row['path'] ) ) {
							echo '<td>';
							echo self::forensic_action_button(
								'Delete',
								'wps_delete_file',
								[ 'path' => (string) $row['path'] ],
								'Delete this file?',
								'font-size:10px;height:20px;line-height:18px;padding:0 6px;color:#a00;border-color:#a00'
							);
							echo '</td>';
						}
						echo '</tr>';
					}
					echo '</table></div>';
					if ( count( $chk['results'] ) > 20 ) {
						echo '<p class="wps-xs wps-dim wps-p0">and ' . ( count( $chk['results'] ) - 20 ) . ' more. Run the scan again after cleaning these.</p>';
					}
				}
				echo '</div>';
			}
			echo '</div>';
		}

		// Core file integrity
		$core = $report['core_integrity'] ?? [];
		$core_status = $core['status'] ?? 'unknown';
		$core_version = $core['version'] ?? 'unknown';
		$core_modified = $core['modified'] ?? [];
		$core_alert = in_array( $core_status, [ 'modified', 'error' ], true );

		self::forensic_card( '<span class="wps-icon dashicons dashicons-lock" aria-hidden="true"></span>WordPress core file integrity (v' . esc_html( $core_version ) . ')', $core_alert );

		if ( $core_status === 'error' ) {
			echo '<p class="wps-sm wps-bad-t wps-p0">' . esc_html( $core['error'] ?? 'Checksum check failed' ) . '</p>';
		} elseif ( $core_status === 'clean' ) {
			echo '<p class="wps-sm wps-good-t wps-p0"> All core files match the official WordPress ' . esc_html( $core_version ) . ' checksums.</p>';
		} elseif ( $core_modified ) {
			echo '<p class="wps-sm wps-bad-t wps-p"> ' . count( $core_modified ) . ' core file(s) do not match the official WordPress ' . esc_html( $core_version ) . ' checksums. Modified core files are a high-confidence indicator of a backdoor injected directly into WordPress internals.</p>';
			echo '<div class="wps-scroll-x"><table class="wps-table wps-table--w400">';
			echo '<thead><tr><th>File</th><th style="width:90px">Status</th></tr></thead><tbody>';
			foreach ( array_slice( $core_modified, 0, 30 ) as $cm ) {
				$st_class = $cm['status'] === 'missing' ? 'wps-warn-t' : 'wps-bad-t';
				echo '<tr>';
				echo '<td class="wps-mono">' . esc_html( $cm['path'] ) . '</td>';
				echo '<td class="wps-strong ' . $st_class . '">' . esc_html( ucfirst( $cm['status'] ) ) . '</td>';
				echo '</tr>';
			}
			if ( count( $core_modified ) > 30 ) {
				echo '<tr><td colspan="2" class="wps-muted wps-xs">and ' . ( count( $core_modified ) - 30 ) . ' more. Replace WordPress core files via SSH: <code>wp core download --force</code></td></tr>';
			}
			echo '</tbody></table></div>';
			echo '<p class="wps-xs wps-muted wps-mt8">To repair: download a fresh WordPress ' . esc_html( $core_version ) . ' package and overwrite core files via SSH, or run <code>wp core download --force</code>.</p>';
		} else {
			echo '<p class="wps-sm wps-dim wps-p0">Checksum data not yet loaded run forensics again.</p>';
		}
		echo '</div>';

		// 1.3.92: in-plugin attack-window correlation  replaces the SSH `find`,
		// which never needed a shell (it only walks the filesystem by mtime).
		$recent       = $report['recent_modified_php'] ?? [];
		$recent_files = $recent['files'] ?? [];
		self::forensic_card( '<span class="wps-icon dashicons dashicons-category" aria-hidden="true"></span>Recently-modified executable files (attack-window correlation)', false );
		echo '<p class="wps-sm wps-muted wps-p">PHP files under plugins, mu-plugins and uploads, newest first. A cluster sharing one timestamp usually marks the drop. This runs in the plugin  no SSH or shell needed.';
		if ( ! empty( $recent['reference_mtime'] ) ) {
			echo ' For reference, wp-config.php was last modified ' . esc_html( gmdate( 'Y-m-d H:i:s', (int) $recent['reference_mtime'] ) ) . ' UTC.';
		}
		echo '</p>';
		if ( ! $recent_files ) {
			echo '<p class="wps-sm wps-good-t wps-p0">No executable files found in those directories.</p>';
		} else {
			echo '<div class="wps-scroll-x"><table class="wps-table wps-table--w400">';
			echo '<thead><tr><th style="width:160px">Modified (UTC)</th><th>File</th></tr></thead><tbody>';
			$abs = rtrim( ABSPATH, '/\\' ) . '/';
			foreach ( array_slice( $recent_files, 0, 30 ) as $rf ) {
				$rel = strpos( $rf['path'], $abs ) === 0 ? substr( $rf['path'], strlen( $abs ) ) : $rf['path'];
				echo '<tr>';
				echo '<td class="wps-mono wps-nowrap">' . esc_html( gmdate( 'Y-m-d H:i:s', (int) $rf['mtime'] ) ) . '</td>';
				echo '<td class="wps-mono wps-break">' . esc_html( $rel ) . '</td>';
				echo '</tr>';
			}
			echo '</tbody></table></div>';
			if ( count( $recent_files ) > 30 ) {
				echo '<p class="wps-xs wps-dim wps-p0">and ' . ( count( $recent_files ) - 30 ) . ' more.</p>';
			}
		}
		echo '</div>';

		// 1.3.93: re-dropper hunt  for kits flagged as RE-DROPPED that keep
		// returning under new random names. The likely vectors are not PHP-readable.
		$hunt = $report['redropper_hunt'] ?? [];
		if ( $hunt ) {
			self::forensic_card( '<span class="wps-icon dashicons dashicons-search" aria-hidden="true"></span>Re-dropper hunt (a kit keeps reappearing)', false );
			echo '<p class="wps-sm wps-muted wps-p">If a kit is flagged <strong>RE-DROPPED Nx</strong>, the scanner removes it each pass but something outside it re-plants it. The usual culprits  a <strong>system crontab</strong> or a dropper <strong>outside the WordPress install</strong>  are exactly what PHP cannot read here (no shell, and <code>open_basedir</code> confinement), so these run over SSH. The doorway kit reuses the stub names <code>canaryspillsdinky.php</code> and <code>unmadesuerscorker.php</code> across drops, which makes a precise search target:</p>';
			foreach ( $hunt as $cmd ) {
				echo '<div class="wps-mb10">';
				echo '<div class="wps-xs wps-muted">' . esc_html( $cmd['label'] ) . '</div>';
				echo '<div>';
				echo '<div class="wps-cmdbox">' . esc_html( $cmd['command'] ) . '</div>';
				echo '<button type="button" class="button wps-copy-btn" data-wps-copy="prev">Copy</button>';
				echo '</div></div>';
			}
			echo '</div>';
		}

		// Truly-SSH-only section (log files the web process can't read)
		$cmds = $report['ssh_commands'] ?? [];
		if ( $cmds ) {
			self::forensic_card( '<span class="wps-icon dashicons dashicons-desktop" aria-hidden="true"></span>Server log queries (fallback for logs PHP can&#39;t read)', false );
			echo '<p class="wps-sm wps-muted wps-p">The <strong>Logs</strong> tab already discovers and greps every log this host lets PHP read, in one click, no SSH. Use the commands below only for logs PHP cannot reach here  typically root-owned access logs under <code>/var/log</code>, or hosts where <code>open_basedir</code> or disabled shell functions block direct reads. Copy and run over SSH:</p>';
			foreach ( $cmds as $cmd ) {
				echo '<div class="wps-mb10">';
				echo '<div class="wps-xs wps-muted">' . esc_html( $cmd['label'] ) . '</div>';
				echo '<div>';
				echo '<div id="wps-cmd-' . esc_attr( md5( $cmd['command'] ) ) . '" class="wps-cmdbox">' . esc_html( $cmd['command'] ) . '</div>';
				echo '<button type="button" class="button wps-copy-btn" data-wps-copy="prev">Copy</button>';
				echo '</div></div>';
			}
			echo '</div>';
		}
	}

	/** Build a Forensics inline action button with safely escaped JSON payload. */
	private static function forensic_action_button( string $label, string $action, array $data = [], string $confirm = '', string $classes = '' ): string {
		// 1.3.95: classes + data-attributes; a delegated listener in admin.js
		// performs the action (no inline onclick, CSP-friendly).
		$classes   = $classes !== '' ? $classes : 'wps-btn-sm wps-btn-danger';
		$json_data = empty( $data ) ? new stdClass() : $data;

		return '<button type="button" class="button ' . esc_attr( $classes ) . '"'
			. ' data-wps-action="' . esc_attr( $action ) . '"'
			. ' data-wps-data="' . esc_attr( wp_json_encode( $json_data ) ) . '"'
			. ' data-wps-confirm="' . esc_attr( $confirm ) . '">'
			. $label . '</button>';
	}

	private static function forensic_card( string $title, bool $alert ): void {
		$card_class  = $alert ? ' wps-card--alert' : '';
		$title_class = $alert ? ' wps-bad-t' : '';
		echo '<div class="wps-mb10 wps-card wps-card-body' . $card_class . '">';
		echo '<div class="wps-strong wps-mb10' . $title_class . '">' . $title . '</div>';
	}
}
