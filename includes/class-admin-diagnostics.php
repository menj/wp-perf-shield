<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Diagnostics tab renderer (Phase 3 split from class-admin.php).
 *
 * Owns the analytics summary, security-posture and latest-signals tables,
 * the Source Trace timeline, the active-hostile-IP table, the daily activity
 * table, the top-attackers tables, and the event-mix grid. All build_* and
 * render_* helpers that were specific to this tab moved with it.
 *
 * Markup, table widths, severity colour mapping, command sets, and the
 * 200-event retention assumption are unchanged from the pre-split renderer.
 */
class WPS_Admin_Diagnostics {

	public static function render( array $context ): void {
		?>
		<div class="wps-tab">
			<?php
			self::render_analytics(
				$context['events'],
				$context['blocked_ips'],
				$context['findings'],
				$context['event_labels'],
				$context['auto_delete_enabled'],
				$context['auto_ip_block_enabled'],
				$context['strict_upload_gate_enabled'],
				$context['last_scan']
			);
			self::render_environment_checks( $context['system_checks'] );
			self::render_diagnostics_export();
			self::render_chain_selftest();
			?>
			<div id="wps-settings-msg" class="wps-status wps-mt8"></div>
		</div><!-- /diagnostics tab -->
		<?php
	}

	/**
	 * Environment checks subsection (1.3.35: moved here from Overview, since
	 * this is technical/diagnostic info that fits the Diagnostics character).
	 */
	private static function render_environment_checks( array $system_checks ): void {
		?>
		<div class="wps-card wps-card--flush wps-mt14">
			<div class="wps-card-head">Environment checks</div>
			<div class="wps-grid-2 wps-grid-2--cells">
				<?php foreach ( $system_checks as $check ) : ?>
				<div>
					<div class="wps-row wps-mb6">
						<span class="wps-dot <?php echo $check['ok'] ? 'wps-dot--good' : 'wps-dot--bad'; ?>"></span>
						<strong><?php echo esc_html( $check['label'] ); ?></strong>
						<span class="wps-xs wps-strong wps-mlauto <?php echo $check['ok'] ? 'wps-good2-t' : 'wps-bad2-t'; ?>"><?php echo $check['ok'] ? 'OK' : 'Needs attention'; ?></span>
					</div>
					<code class="wps-xs wps-break"><?php echo esc_html( $check['detail'] ); ?></code>
				</div>
				<?php endforeach; ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Diagnostics export panel (1.3.35: moved here from Settings, since the
	 * bundle is operator output, not a configuration value, and its name
	 * already says "Diagnostics").
	 */
	private static function render_diagnostics_export(): void {
		?>
		<div class="wps-card wps-mt14">
			<h3 class="wps-card-h">Diagnostics export</h3>
			<p class="wps-sm wps-muted wps-p">Generates a redacted JSON support bundle with plugin version, settings, active protections, recent events, blocked IP summaries, scan findings, and environment checks. Contents are downloaded directly to your browser; nothing is sent off-site. The bundle never contains raw credentials, auth salts, DB passwords, or full exfil contents.</p>
			<button id="wps-export-diag-btn" class="button"><span class="wps-icon dashicons dashicons-download" aria-hidden="true"></span>Download support bundle (JSON)</button>
			<div id="wps-export-diag-msg" class="wps-status wps-mt8"></div>
		</div>
		<?php
	}

	/**
	 * Event-chain self-test (1.4.64). Runs the CRIT-005 verification against
	 * this site's real database and renders the verdict. The heavy lifting is
	 * in WPS_Chain_Selftest; this only presents the button and the last result.
	 */
	private static function render_chain_selftest(): void {
		$result = get_transient( 'wps_chain_selftest_result' );
		if ( is_array( $result ) ) {
			delete_transient( 'wps_chain_selftest_result' );
		}
		$dot = [ 'pass' => 'wps-dot--good', 'fail' => 'wps-dot--bad', 'skip' => 'wps-dot--warn' ];
		?>
		<div class="wps-card wps-mt14">
			<h3 class="wps-card-h">Event-chain self-test</h3>
			<p class="wps-sm wps-muted wps-p">Verifies the concurrency-safe event-log append (CRIT-005) against this site's own database. It appends a batch through the real chain code path on an isolated scratch table, confirms the result is one linear, verifiable chain, and proves the append lock excludes across two live database connections. The scratch table is dropped afterwards; the real event chain is never written to or deleted from.</p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="wps_chain_selftest">
				<?php echo wp_nonce_field( 'wps_chain_selftest', '_wpnonce', true, false ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
				<button type="submit" class="button"><span class="wps-icon dashicons dashicons-shield" aria-hidden="true"></span>Run event-chain self-test</button>
			</form>
			<?php if ( is_array( $result ) ) : ?>
				<div class="wps-mt14">
					<div class="wps-row wps-mb6">
						<span class="wps-dot <?php echo esc_attr( $result['ok'] ? 'wps-dot--good' : 'wps-dot--bad' ); ?>"></span>
						<strong><?php echo esc_html( $result['summary'] ?? '' ); ?></strong>
						<span class="wps-xs wps-muted wps-mlauto"><?php echo esc_html( $result['ts'] ?? '' ); ?></span>
					</div>
					<?php foreach ( (array) ( $result['checks'] ?? [] ) as $c ) : ?>
						<div class="wps-mb6">
							<div class="wps-row">
								<span class="wps-dot <?php echo esc_attr( $dot[ $c['status'] ] ?? 'wps-dot' ); ?>"></span>
								<strong><?php echo esc_html( $c['label'] ); ?></strong>
								<span class="wps-xs wps-strong wps-mlauto"><?php echo esc_html( strtoupper( $c['status'] ) ); ?></span>
							</div>
							<code class="wps-xs wps-break"><?php echo esc_html( $c['detail'] ); ?></code>
						</div>
					<?php endforeach; ?>
				</div>
			<?php endif; ?>
		</div>
		<?php
	}

	private static function render_analytics( array $events, array $blocked_ips, array $findings, array $event_labels, bool $auto_delete_enabled, bool $auto_ip_block_enabled, bool $strict_upload_gate_enabled, $last_scan ): void {
		$analytics = self::build_analytics( $events, $blocked_ips );
		$last_scan_time = is_array( $last_scan ) ? (string) ( $last_scan['time'] ?? 'unknown' ) : 'Not yet run';
		$forensics_report = get_option( 'wps_forensics_report', [] );
		$source_trace = self::build_source_trace(
			$events,
			$blocked_ips,
			$findings,
			is_array( $forensics_report ) ? $forensics_report : [],
			$last_scan
		);

		$cards = [
			[ 'label' => 'Attack attempts', 'value' => $analytics['attack_total'], 'class' => $analytics['attack_total'] > 0 ? 'wps-bad-t' : '' ],
			[ 'label' => 'Malware uploads blocked', 'value' => $analytics['upload_blocked'], 'class' => $analytics['upload_blocked'] > 0 ? 'wps-bad-t' : '' ],
			[ 'label' => 'Pathway blocks', 'value' => $analytics['upload_path_blocked'], 'class' => $analytics['upload_path_blocked'] > 0 ? 'wps-bad-t' : '' ],
			[ 'label' => 'Active hostile IP blocks', 'value' => count( $blocked_ips ), 'class' => count( $blocked_ips ) > 0 ? 'wps-bad-t' : '' ],
			[ 'label' => 'Clearance actions', 'value' => $analytics['clearance_total'], 'class' => $analytics['clearance_total'] > 0 ? 'wps-good-t' : '' ],
			[ 'label' => 'Clean scans', 'value' => $analytics['scan_clean'], 'class' => 'wps-good-t' ],
			[ 'label' => 'Issue scans', 'value' => $analytics['scan_issues'], 'class' => $analytics['scan_issues'] > 0 ? 'wps-warn-t' : '' ],
		];
		?>
		<div class="wps-flexwrap wps-mb10">
			<div class="wps-minw280">
				<h2 class="wps-card-h">Diagnostics</h2>
				<p class="wps-muted wps-p0">Computed from the newest <?php echo esc_html( (string) count( $events ) ); ?> retained event log entries and the current hostile-IP block list.</p>
			</div>
			<div class="wps-kpi">
				<div class="wps-kpi-label">Last scan</div>
				<div class="wps-strong"><?php echo esc_html( $last_scan_time ); ?></div>
			</div>
		</div>

		<div class="wps-kpis">
			<?php foreach ( $cards as $card ) : ?>
			<div class="wps-card">
				<div class="wps-kpi-label"><?php echo esc_html( $card['label'] ); ?></div>
				<div class="wps-strong wps-kpi-value <?php echo esc_attr( $card['class'] ); ?>"><?php echo esc_html( (string) $card['value'] ); ?></div>
			</div>
			<?php endforeach; ?>
		</div>

		<?php
		// 1.3.66: the previous layout placed two cards side-by-side here:
		// "Security posture" (configuration-state summary) and "Latest signals"
		// (event-derived stats: last attack, last clearance, unique attacker
		// IPs, current blocked IP attempts). The Latest signals card was
		// removed in 1.3.66 because (a) the four metrics it showed were
		// already covered by the cards row at the top of this tab and by the
		// dedicated sections below ("Active hostile IP blocks", "Recent
		// activity by day", "Top attacking IPs"), and (b) the operator
		// reported it visually echoed the Events tab's raw event log without
		// adding distinct value. The grid was simplified to a single column
		// so Security posture takes full width. The `$analytics` array is
		// still computed by render() because other sections below use its
		// daily / per-IP / per-subject sub-keys.
		?>
		<div class="wps-mb10">
			<div class="wps-card">
				<h3 class="wps-card-h">Security posture</h3>
				<table class="wps-table">
					<?php
					// 1.4.6: tamper-protection status. Worth surfacing here rather
					// than burying it: if the must-use guard is not installed, the
					// plugin can be switched off from the database with nothing to
					// notice or record it.
					$wps_guard = class_exists( 'WPS_Guard' ) ? WPS_Guard::status() : [ 'installed' => false, 'current' => false, 'mu_writable' => false, 'version' => '' ];
					?>
					<?php
					// 1.4.32: this row used to render on every install, for ever,
					// announcing the absence of a feature withdrawn sixteen
					// releases ago. That is not a status - it is a footnote about
					// the plugin's own history, and it told the operator nothing
					// they could act on.
					//
					// It now appears only when there is genuinely something to do:
					// a leftover must-use file that could not be deleted. In every
					// other case the row is simply absent, which is the correct
					// report for a feature that no longer exists.
					if ( ! empty( $wps_guard['leftover'] ) ) :
						?>
					<tr>
						<td class="wps-muted">Leftover must-use guard file</td>
						<td class="wps-right wps-strong wps-warn-t">delete wp-content/mu-plugins/0-wps-guard.php</td>
					</tr>
					<?php endif; ?>
					<?php
					// 1.4.18: the login guard was invisible until something got
					// blocked, which made a working install look like a broken
					// one. These four rows answer "is it on, and is it doing
					// anything" without waiting for an attack.
					$wps_lg_on    = class_exists( 'WPS_Login_Guard' ) && WPS_Login_Guard::enabled();
					$wps_lg_stats = class_exists( 'WPS_Login_Guard' ) ? WPS_Login_Guard::stats() : [];
					$wps_ak       = class_exists( 'WPS_Login_Guard' ) ? WPS_Login_Guard::akismet_status() : '';
					?>
					<tr>
						<td class="wps-muted">Login protection</td>
						<td class="wps-right wps-strong <?php echo $wps_lg_on ? 'wps-good-t' : 'wps-warn-t'; ?>"><?php echo $wps_lg_on ? 'active' : 'disabled'; ?></td>
					</tr>
					<tr>
						<td class="wps-muted">&nbsp;&nbsp;Akismet block-duration input</td>
						<td class="wps-right <?php echo strpos( $wps_ak, 'not detected' ) === false ? 'wps-good-t' : 'wps-muted'; ?>"><?php echo esc_html( $wps_ak ); ?></td>
					</tr>
					<tr>
						<td class="wps-muted">&nbsp;&nbsp;Failed sign-ins seen (today / 7 days)</td>
						<td class="wps-right wps-mono"><?php echo (int) ( $wps_lg_stats['today_attempts'] ?? 0 ); ?> / <?php echo (int) ( $wps_lg_stats['week_attempts'] ?? 0 ); ?></td>
					</tr>
					<tr>
						<td class="wps-muted">&nbsp;&nbsp;Addresses blocked (today / 7 days)</td>
						<td class="wps-right wps-mono"><?php echo (int) ( $wps_lg_stats['today_blocks'] ?? 0 ); ?> / <?php echo (int) ( $wps_lg_stats['week_blocks'] ?? 0 ); ?></td>
					</tr>
					<?php
					// 1.4.20: monthly API usage for the configured key. Cached
					// for an hour, so rendering this page does not consume the
					// allowance it reports on.
					$wps_ak_usage = class_exists( 'WPS_Login_Guard' ) ? WPS_Login_Guard::akismet_usage() : [ 'state' => 'unavailable', 'throttled' => false ];
					if ( 'unavailable' !== $wps_ak_usage['state'] ) :
						?>
					<tr>
						<td class="wps-muted">&nbsp;&nbsp;Akismet calls this month</td>
						<td class="wps-right wps-mono <?php echo 'ok' === $wps_ak_usage['state'] ? '' : 'wps-warn-t'; ?>"><?php echo esc_html( WPS_Login_Guard::akismet_usage_label() ); ?></td>
					</tr>
						<?php if ( ! empty( $wps_ak_usage['throttled'] ) ) : ?>
					<tr>
						<td class="wps-muted">&nbsp;&nbsp;Akismet throttling</td>
						<td class="wps-right wps-strong wps-bad-t">active &ndash; the key is over its plan limit</td>
					</tr>
						<?php endif; ?>
					<?php endif; ?>
					<tr>
						<td class="wps-muted">&nbsp;&nbsp;Permanently blocked from signing in</td>
						<td class="wps-right wps-mono<?php echo ( $wps_lg_stats['permanent_total'] ?? 0 ) ? ' wps-strong' : ''; ?>"><?php echo (int) ( $wps_lg_stats['permanent_total'] ?? 0 ); ?></td>
					</tr>
					<tr>
						<td class="wps-muted">&nbsp;&nbsp;Reported to Akismet as spam (today / 7 days)</td>
						<td class="wps-right wps-mono"><?php echo (int) ( $wps_lg_stats['today_spam_reports'] ?? 0 ); ?> / <?php echo (int) ( $wps_lg_stats['week_spam_reports'] ?? 0 ); ?></td>
					</tr>
					<?php
					// Which rule decided a block. Range-rotation blocks are few
					// because each one covers a whole /24; the single-address
					// rule accounts for the rest of the total, and showing it
					// stops the panel reading as idle when it is not.
					$wps_lg_week_blocks   = (int) ( $wps_lg_stats['week_blocks'] ?? 0 );
					$wps_lg_week_network  = (int) ( $wps_lg_stats['week_network_blocks'] ?? 0 );
					$wps_lg_week_single   = max( 0, $wps_lg_week_blocks - $wps_lg_week_network );
					if ( $wps_lg_week_blocks > 0 ) :
						?>
					<tr>
						<td class="wps-muted">&nbsp;&nbsp;Blocks by rule (7 days)</td>
						<td class="wps-right wps-mono wps-sm"><?php echo $wps_lg_week_single; ?> single address &middot; <?php echo (int) ( $wps_lg_stats['week_multiuser_blocks'] ?? 0 ); ?> many usernames &middot; <?php echo (int) ( $wps_lg_stats['week_permanent_blocks'] ?? 0 ); ?> non-existent account &middot; <?php echo $wps_lg_week_network; ?> range rotation</td>
					</tr>
					<tr>
						<td class="wps-muted">&nbsp;&nbsp;</td>
						<td class="wps-right wps-muted wps-sm">a range-rotation block covers every address in that /24</td>
					</tr>
					<?php endif; ?>
					<?php if ( ( $wps_lg_stats['akismet_spam'] ?? 0 ) || ( $wps_lg_stats['akismet_clean'] ?? 0 ) || ( $wps_lg_stats['akismet_unavailable'] ?? 0 ) ) : ?>
					<tr>
						<td class="wps-muted">&nbsp;&nbsp;Akismet verdicts used</td>
						<td class="wps-right wps-mono wps-sm"><?php echo (int) $wps_lg_stats['akismet_spam']; ?> known-bad &middot; <?php echo (int) $wps_lg_stats['akismet_clean']; ?> clean &middot; <?php echo (int) $wps_lg_stats['akismet_unavailable']; ?> no answer</td>
					</tr>
					<?php endif; ?>
					<tr><td class="wps-muted">Auto-delete confirmed malware</td><td class="wps-right wps-strong <?php echo $auto_delete_enabled ? 'wps-good-t' : 'wps-warn-t'; ?>"><?php echo $auto_delete_enabled ? 'enabled' : 'disabled'; ?></td></tr>
					<tr><td class="wps-muted">Hostile IP auto-block</td><td class="wps-right wps-strong <?php echo $auto_ip_block_enabled ? 'wps-good-t' : 'wps-warn-t'; ?>"><?php echo $auto_ip_block_enabled ? 'enabled' : 'disabled'; ?></td></tr>
					<tr><td class="wps-muted">ZIP upload pathway guard</td><td class="wps-right wps-strong <?php echo $strict_upload_gate_enabled ? 'wps-good-t' : 'wps-warn-t'; ?>"><?php echo $strict_upload_gate_enabled ? 'enabled' : 'disabled'; ?></td></tr>
					<tr><td class="wps-muted">Event log writable</td><td class="wps-right wps-strong <?php echo WPS_Logger::can_write() ? 'wps-good-t' : 'wps-bad-t'; ?>"><?php echo WPS_Logger::can_write() ? 'ok' : 'needs attention'; ?></td></tr>
					<tr><td class="wps-muted">Current cached findings</td><td class="wps-right wps-strong <?php echo count( $findings ) > 0 ? 'wps-bad-t' : 'wps-good-t'; ?>"><?php echo esc_html( (string) count( $findings ) ); ?></td></tr>
					<tr><td class="wps-muted">Log retention used</td><td class="wps-right wps-strong"><?php echo esc_html( count( $events ) . ' / 200' ); ?></td></tr>
				</table>
			</div>
		</div>

		<?php self::render_source_trace( $source_trace, $event_labels ); ?>

		<div class="wps-card">
			<h3 class="wps-card-h">Active hostile IP blocks</h3>
			<?php self::render_blocked_ips_table( $blocked_ips ); ?>
			<?php self::render_permanent_blocks_table(); ?>
			<?php if ( ! empty( $blocked_ips ) ) : ?>
				<p class="wps-xs wps-dim wps-p0 wps-mt8">If you have moved blocking to your WAF or hosting firewall, or need to correct a false positive, clear the in-plugin block list:</p>
				<p class="wps-mt8 wps-p0">
					<button id="wps-clear-ip-blocks-btn" class="button wps-btn-danger">Clear hostile IP blocks</button>
				</p>
			<?php endif; ?>
		</div>

		<div class="wps-card">
			<h3 class="wps-card-h">Recent activity by day</h3>
			<?php if ( empty( $analytics['daily'] ) ) : ?>
				<p class="wps-muted wps-p0">No event activity recorded yet.</p>
			<?php else : ?>
				<div class="wps-scroll-x">
				<table class="wps-table wps-table--w620">
					<thead>
						<tr>
							<th>Date UTC</th>
							<th>Attacks</th>
							<th>Clearances</th>
							<th>Clean scans</th>
							<th>Issue scans</th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( $analytics['daily'] as $date => $row ) :
						$attack_width = $analytics['max_daily_attacks'] > 0 ? max( 4, (int) round( ( $row['attacks'] / $analytics['max_daily_attacks'] ) * 100 ) ) : 0;
						?>
						<tr>
							<td class="wps-mono"><?php echo esc_html( $date ); ?></td>
							<td>
								<span class="wps-bar" style="width:<?php echo esc_attr( (string) $attack_width ); ?>%"></span>
								<strong><?php echo esc_html( (string) $row['attacks'] ); ?></strong>
							</td>
							<td class="wps-good-t wps-strong"><?php echo esc_html( (string) $row['clearances'] ); ?></td>
							<td class="wps-good-t"><?php echo esc_html( (string) $row['clean'] ); ?></td>
							<td class="wps-warn-t"><?php echo esc_html( (string) $row['issues'] ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
				</div>
			<?php endif; ?>
		</div>

		<div class="wps-grid-2">
			<div class="wps-card">
				<h3 class="wps-card-h">Top attacking IPs</h3>
				<?php self::render_analytics_table( $analytics['top_ips'], [ 'IP', 'Signals', 'Last seen' ] ); ?>
			</div>
			<div class="wps-card">
				<h3 class="wps-card-h">Top attack subjects</h3>
				<?php self::render_analytics_table( $analytics['top_subjects'], [ 'Subject', 'Signals', 'Last seen' ] ); ?>
			</div>
		</div>

		<div class="wps-card wps-mt14">
			<h3 class="wps-card-h">Event mix</h3>
			<?php if ( empty( $analytics['event_mix'] ) ) : ?>
				<p class="wps-muted wps-p0">No event types recorded yet.</p>
			<?php else : ?>
				<div class="wps-grid-2 wps-grid-2--tight">
					<?php foreach ( $analytics['event_mix'] as $type => $count ) : ?>
					<div class="wps-check-row">
						<span class="wps-sm wps-flex1"><?php echo esc_html( $event_labels[ $type ] ?? $type ); ?></span>
						<strong class="wps-sm"><?php echo esc_html( (string) $count ); ?></strong>
					</div>
					<?php endforeach; ?>
				</div>
			<?php endif; ?>
		</div>
		<?php
	}

	private static function build_source_trace( array $events, array $blocked_ips, array $findings, array $report, $last_scan ): array {
		$items = [];
		$timeline_event_types = [
			'upload_blocked',
			'upload_path_blocked',
			'activation_blocked',
			'ip_auto_blocked',
			'ip_block_refreshed',
			'ip_request_blocked',
			'attacker_account_found',
			'wp_config_modified',
			'core_integrity_fail',
			'scan_issues',
			'auto_deleted',
			'db_option_deleted',
			'cron_purged',
			'wp_config_cleaned',
			'plugin_folder_deleted',
			'file_deleted',
			'theme_file_deleted',
			'attachment_deleted',
		];

		$attack_event_types = [
			'upload_blocked',
			'upload_path_blocked',
			'activation_blocked',
			'ip_auto_blocked',
			'ip_block_refreshed',
			'ip_request_blocked',
			'attacker_account_found',
			'wp_config_modified',
			'core_integrity_fail',
			'scan_issues',
		];

		foreach ( $events as $event ) {
			if ( ! is_array( $event ) ) {
				continue;
			}

			$type = sanitize_key( (string) ( $event['type'] ?? '' ) );
			if ( ! in_array( $type, $timeline_event_types, true ) ) {
				continue;
			}

			$subject = (string) ( $event['subject'] ?? '' );
			$ip = (string) ( $event['ip'] ?? '' );
			$severity = in_array( $type, $attack_event_types, true ) ? 'high' : 'low';
			if ( in_array( $type, [ 'wp_config_modified', 'core_integrity_fail' ], true ) ) {
				$severity = 'critical';
			}

			self::source_trace_add_item(
				$items,
				(string) ( $event['time'] ?? '' ),
				$type,
				'',
				$subject,
				$ip !== '' && $ip !== 'cli' ? $ip : 'Event log',
				self::source_trace_next_step( $type, $subject ),
				$severity,
				$ip,
				''
			);
		}

		foreach ( $blocked_ips as $ip => $detail ) {
			if ( ! is_array( $detail ) ) {
				continue;
			}

			$last_seen = (string) ( $detail['last_seen'] ?? $detail['first_seen'] ?? '' );
			$attempts = (int) ( $detail['attempts'] ?? 1 );
			$filename = (string) ( $detail['last_filename'] ?? '' );
			$pathway = (string) ( $detail['last_pathway'] ?? '' );
			$user = (string) ( $detail['last_user'] ?? 'guest' );
			$reason = (string) ( $detail['reason'] ?? 'malware upload attempt' );
			$subject = trim( $reason . ( $pathway !== '' ? ' via ' . $pathway : '' ) );
			$detail_line = 'attempts=' . $attempts . ( $filename !== '' ? '; file=' . $filename : '' ) . '; user=' . $user;

			self::source_trace_add_item(
				$items,
				$last_seen,
				'active_ip_block',
				'Hostile IP block active',
				$subject,
				(string) $ip,
				'Check this IP in web server logs, then patch or close the upload route if the same pathway repeats.',
				'high',
				(string) $ip,
				$detail_line
			);
		}

		$last_scan_time = is_array( $last_scan ) ? (string) ( $last_scan['time'] ?? '' ) : '';
		foreach ( $findings as $finding ) {
			if ( ! is_array( $finding ) ) {
				continue;
			}

			$type = (string) ( $finding['type'] ?? 'Scan finding' );
			$subject = (string) ( $finding['subject'] ?? $finding['path'] ?? '' );
			$detail = trim( (string) ( $finding['match'] ?? $finding['preview'] ?? '' ) );
			$severity = sanitize_key( (string) ( $finding['severity'] ?? 'high' ) );

			self::source_trace_add_item(
				$items,
				$last_scan_time,
				'scan_finding',
				'Current scan finding',
				$type . ( $subject !== '' ? ': ' . $subject : '' ),
				'Scan cache',
				'Use the matching cleanup action, then rerun scan and Forensics to confirm the finding is gone.',
				$severity !== '' ? $severity : 'high',
				'',
				$detail
			);
		}

		$generated = (string) ( $report['generated'] ?? '' );
		$uploads = is_array( $report['media_uploads'] ?? null ) ? $report['media_uploads'] : [];
		$malicious_upload_ids = [];
		foreach ( (array) ( $uploads['malicious_uploads'] ?? [] ) as $upload ) {
			if ( ! is_array( $upload ) ) {
				continue;
			}

			$ip = (string) ( $upload['uploader_ip'] ?? '' );
			$upload_id = (string) ( $upload['id'] ?? '' );
			if ( $upload_id !== '' ) {
				$malicious_upload_ids[ $upload_id ] = true;
			}
			self::source_trace_add_item(
				$items,
				(string) ( $upload['uploaded_at'] ?? '' ),
				'media_malware_upload',
				'Media library malware ZIP record',
				(string) ( $upload['title'] ?? $upload['url'] ?? 'unknown upload' ),
				$ip !== '' ? $ip : 'Media library',
				'Match this upload time against access logs to identify the route and user agent that accepted it.',
				'critical',
				filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '',
				'Upload ID ' . (string) ( $upload['id'] ?? '?' )
			);
		}

		foreach ( (array) ( $uploads['recent_zips'] ?? [] ) as $upload ) {
			if ( ! is_array( $upload ) ) {
				continue;
			}
			$upload_id = (string) ( $upload['id'] ?? '' );
			if ( $upload_id !== '' && isset( $malicious_upload_ids[ $upload_id ] ) ) {
				continue;
			}

			self::source_trace_add_item(
				$items,
				(string) ( $upload['uploaded_at'] ?? '' ),
				'media_recent_zip',
				'Recent ZIP upload record',
				(string) ( $upload['title'] ?? $upload['url'] ?? 'unknown upload' ),
				'Media library',
				'If this ZIP is unexpected, compare the timestamp with POST upload routes in access logs.',
				'medium',
				'',
				'Upload ID ' . (string) ( $upload['id'] ?? '?' )
			);
		}

		foreach ( (array) ( $report['plugin_files'] ?? [] ) as $file ) {
			if ( ! is_array( $file ) ) {
				continue;
			}

			self::source_trace_add_item(
				$items,
				(string) ( $file['modified'] ?? '' ),
				'plugin_file_mtime',
				'Suspicious plugin file mtime',
				(string) ( $file['file'] ?? $file['path'] ?? 'unknown plugin file' ),
				'Filesystem',
				'Search access logs around this modified time for plugin upload, activation, or file-manager requests.',
				'high',
				'',
				! empty( $file['md5'] ) ? 'md5=' . (string) $file['md5'] : ''
			);
		}

		foreach ( (array) ( $report['option_anomalies'] ?? [] ) as $option ) {
			if ( ! is_array( $option ) ) {
				continue;
			}

			$option_name = (string) ( $option['option_name'] ?? $option['detail'] ?? 'unknown option' );
			$type = (string) ( $option['type'] ?? 'option anomaly' );
			$is_malware_option = stripos( $type, 'malware' ) !== false || preg_match( '/^wp_[a-f0-9]{10}_cfg$/i', $option_name );
			self::source_trace_add_item(
				$items,
				$generated,
				'db_option_anomaly',
				'DB persistence option present',
				$option_name,
				'wp_options',
				'Delete the option, invalidate sessions if needed, rerun Forensics, and watch whether it reappears.',
				$is_malware_option ? 'critical' : 'high',
				'',
				$type . '. WordPress does not store option creation time by default.'
			);
		}

		foreach ( (array) ( $report['php_checks'] ?? [] ) as $check ) {
			if ( ! is_array( $check ) || empty( $check['results'] ) || ! is_array( $check['results'] ) ) {
				continue;
			}

			foreach ( array_slice( $check['results'], 0, 12 ) as $result ) {
				$row = is_array( $result ) ? $result : [ 'path' => (string) $result ];
				self::source_trace_add_item(
					$items,
					(string) ( $row['modified'] ?? $generated ),
					'php_check_result',
					(string) ( $check['label'] ?? 'PHP executable finding' ),
					(string) ( $row['path'] ?? $row['detail'] ?? 'unknown file' ),
					'Filesystem',
					'Inspect or delete the file from Forensics, then rerun checks to confirm it is gone.',
					'high',
					'',
					(string) ( $row['detail'] ?? '' )
				);
			}
		}

		$core = is_array( $report['core_integrity'] ?? null ) ? $report['core_integrity'] : [];
		if ( in_array( (string) ( $core['status'] ?? '' ), [ 'modified', 'error' ], true ) ) {
			foreach ( array_slice( (array) ( $core['modified'] ?? [] ), 0, 8 ) as $core_file ) {
				$subject = is_array( $core_file ) ? (string) ( $core_file['path'] ?? 'unknown core file' ) : (string) $core_file;
				self::source_trace_add_item(
					$items,
					$generated,
					'core_integrity_result',
					'WordPress core integrity mismatch',
					$subject,
					'Core checksum',
					'Replace WordPress core from a clean source and inspect server logs for direct file writes.',
					'critical',
					'',
					is_array( $core_file ) ? (string) ( $core_file['status'] ?? '' ) : ''
				);
			}
		}

		usort( $items, static function ( array $a, array $b ): int {
			return (int) ( $b['ts'] ?? 0 ) <=> (int) ( $a['ts'] ?? 0 );
		} );

		$items = array_slice( $items, 0, 40 );

		return [
			'items'         => $items,
			'commands'      => self::source_trace_ssh_commands( $items, (array) ( $report['ssh_commands'] ?? [] ) ),
			'has_forensics' => ! empty( $report ),
			'generated'     => $generated,
		];
	}

	private static function source_trace_add_item( array &$items, string $time, string $type, string $label, string $subject, string $source, string $next_step, string $severity = 'medium', string $ip = '', string $detail = '' ): void {
		$time = trim( $time );
		$ts = self::source_trace_timestamp( $time );
		if ( $time === '' && $ts > 0 ) {
			$time = gmdate( 'Y-m-d H:i:s', $ts ) . ' UTC';
		}

		$items[] = [
			'ts'       => $ts,
			'time'     => $time !== '' ? $time : 'unknown',
			'type'     => sanitize_key( $type ),
			'label'    => self::source_trace_text( $label, 120 ),
			'subject'  => self::source_trace_text( $subject, 520 ),
			'source'   => self::source_trace_text( $source, 180 ),
			'next'     => self::source_trace_text( $next_step, 300 ),
			'severity' => in_array( $severity, [ 'critical', 'high', 'medium', 'low' ], true ) ? $severity : 'medium',
			'ip'       => filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '',
			'detail'   => self::source_trace_text( $detail, 360 ),
		];
	}

	private static function source_trace_text( string $text, int $limit = 360 ): string {
		$text = wp_strip_all_tags( $text );
		$text = preg_replace( '/\s+/', ' ', $text );
		$text = trim( is_string( $text ) ? $text : '' );
		if ( strlen( $text ) > $limit ) {
			$text = substr( $text, 0, max( 0, $limit - 3 ) ) . '...';
		}
		return $text;
	}

	private static function source_trace_timestamp( string $time ): int {
		$time = trim( $time );
		if ( $time === '' || strtolower( $time ) === 'unknown' || strtolower( $time ) === 'not yet run' ) {
			return 0;
		}

		return self::event_timestamp( $time );
	}

	private static function source_trace_next_step( string $type, string $subject ): string {
		switch ( sanitize_key( $type ) ) {
			case 'upload_blocked':
				return 'Review this IP and filename in server access logs; keep ZIP content inspection enabled.';
			case 'upload_path_blocked':
				return 'Identify the blocked route in access logs and disable or patch that upload pathway.';
			case 'activation_blocked':
				return 'Check who triggered activation and remove the plugin folder if it still exists on disk.';
			case 'ip_auto_blocked':
			case 'ip_block_refreshed':
			case 'ip_request_blocked':
				return 'Trace POST requests from this IP and confirm whether the same route keeps being abused.';
			case 'wp_config_modified':
				return 'Review wp-config.php immediately, clean known payloads, then reset the clean baseline.';
			case 'core_integrity_fail':
				return 'Replace modified WordPress core files from a clean source and inspect upload/write routes.';
			case 'scan_issues':
			case 'auto_deleted':
			case 'plugin_folder_deleted':
			case 'file_deleted':
			case 'theme_file_deleted':
			case 'attachment_deleted':
				return 'Rerun scan and Forensics, then compare the cleanup time with earlier attack signals.';
			case 'db_option_deleted':
			case 'cron_purged':
			case 'wp_config_cleaned':
				return 'Watch for reappearance; repeated creation points to a live backdoor or scheduled task.';
			default:
				return $subject !== '' ? 'Use this timestamp as an anchor for server-log grep checks.' : 'Review adjacent events and rerun Forensics.';
		}
	}

	private static function source_trace_ssh_commands( array $items, array $existing_commands ): array {
		$ips = [];
		$terms = [
			'wp-perf-analytics',
			'native-render-toolkit',
			'total-render-profiler',
			'total-render-toolkit',
			'pro-font-optimizer',
			'site-speed-insights',
			'advanced-asset-insights',
			'page-seo-toolkit',
			'starter-image-guard',
			'wp-locale-handler',
			'session-manager',
			'wp_session_tokens_config',
		];

		foreach ( $items as $item ) {
			$ip = (string) ( $item['ip'] ?? '' );
			if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				$ips[ $ip ] = true;
			}

			$text = (string) ( ( $item['subject'] ?? '' ) . ' ' . ( $item['detail'] ?? '' ) );
			if ( preg_match_all( '/\b(?:wp_[a-f0-9]{10}_cfg|[a-z0-9][a-z0-9_-]{2,80}\.(?:zip|php))\b/i', $text, $matches ) ) {
				foreach ( $matches[0] as $term ) {
					$term = strtolower( trim( $term ) );
					if ( strlen( $term ) >= 5 && strlen( $term ) <= 90 ) {
						$terms[] = $term;
					}
				}
			}
		}

		$terms = array_values( array_unique( array_filter( $terms, static function ( string $term ): bool {
			return ! in_array( $term, [ 'unknown', 'filesystem', 'attempts', 'media', 'library', 'upload', 'record' ], true );
		} ) ) );
		$terms = array_slice( $terms, 0, 28 );
		$pattern = implode( '|', array_map( static fn( string $term ): string => preg_quote( $term, '/' ), $terms ) );

		$commands = [];
		if ( $pattern !== '' ) {
			$commands[] = [
				'label'   => 'Source Trace indicators in Apache logs',
				'command' => 'grep -R Ei "' . $pattern . '" /var/log/apache2/ 2>/dev/null | tail -150',
			];
			$commands[] = [
				'label'   => 'Source Trace indicators in nginx logs',
				'command' => 'grep -R Ei "' . $pattern . '" /var/log/nginx/ 2>/dev/null | tail -150',
			];
		}

		$commands[] = [
			'label'   => 'Upload-route POST requests across common web logs',
			'command' => 'grep -R Ei "POST .*(async-upload|admin-ajax|update\.php|plugin-install|plugins\.php|upload|wp-file-manager|elFinder|elfinder|connector)" /var/log/apache2/ /var/log/nginx/ 2>/dev/null | tail -200',
		];

		foreach ( array_slice( array_keys( $ips ), 0, 6 ) as $ip ) {
			$commands[] = [
				'label'   => 'All Apache requests from ' . $ip,
				'command' => 'grep "' . $ip . '" /var/log/apache2/access.log | tail -150',
			];
			$commands[] = [
				'label'   => 'All nginx requests from ' . $ip,
				'command' => 'grep "' . $ip . '" /var/log/nginx/access.log | tail -150',
			];
		}

		foreach ( $existing_commands as $command ) {
			if ( ! is_array( $command ) || empty( $command['command'] ) ) {
				continue;
			}
			$commands[] = [
				'label'   => (string) ( $command['label'] ?? 'Forensics command' ),
				'command' => (string) $command['command'],
			];
		}

		$deduped = [];
		$seen = [];
		foreach ( $commands as $command ) {
			$key = md5( $command['command'] );
			if ( isset( $seen[ $key ] ) ) {
				continue;
			}
			$seen[ $key ] = true;
			$deduped[] = $command;
			if ( count( $deduped ) >= 14 ) {
				break;
			}
		}

		return $deduped;
	}

	private static function render_source_trace( array $trace, array $event_labels ): void {
		$items = is_array( $trace['items'] ?? null ) ? $trace['items'] : [];
		$commands = is_array( $trace['commands'] ?? null ) ? $trace['commands'] : [];
		$has_forensics = ! empty( $trace['has_forensics'] );
		$generated = (string) ( $trace['generated'] ?? '' );
		?>
		<div class="wps-source-trace">
			<div class="wps-source-trace-head">
				<div>
					<h3>Source Trace</h3>
					<p>Correlates blocked uploads, suspicious file mtimes, database persistence findings, active hostile IPs, and SSH grep checks.</p>
				</div>
				<div class="wps-source-trace-badges">
					<span><?php echo esc_html( count( $items ) . ' signals' ); ?></span>
					<span class="<?php echo $has_forensics ? 'is-good' : 'is-warn'; ?>"><?php echo $has_forensics ? 'Forensics cached' : 'Run Forensics'; ?></span>
				</div>
			</div>

			<?php if ( ! $has_forensics ) : ?>
				<div class="wps-source-note">Run the Forensics tab once to add media upload records, plugin file timestamps, database anomalies, executable PHP checks, core integrity findings, and the fuller SSH command set.</div>
			<?php elseif ( $generated !== '' ) : ?>
				<div class="wps-source-note">Forensics snapshot: <?php echo esc_html( $generated ); ?>. WordPress does not store native creation timestamps for <code>wp_options</code>, so database rows are shown at report time unless a scan/remediation event caught them earlier.</div>
			<?php endif; ?>

			<?php if ( empty( $items ) ) : ?>
				<p class="wps-source-empty">No source-trace signals are currently recorded.</p>
			<?php else : ?>
				<div class="wps-source-list">
					<?php foreach ( $items as $item ) :
						$type = (string) ( $item['type'] ?? '' );
						$label = (string) ( $item['label'] ?? '' );
						$signal = $label !== '' ? $label : ( $event_labels[ $type ] ?? $type );
						$severity = (string) ( $item['severity'] ?? 'medium' );
						?>
						<div class="wps-source-row is-<?php echo esc_attr( $severity ); ?>">
							<div class="wps-source-time"><?php echo esc_html( (string) ( $item['time'] ?? 'unknown' ) ); ?></div>
							<div class="wps-source-main">
								<div class="wps-source-signal">
									<strong><?php echo esc_html( $signal ); ?></strong>
									<span><?php echo esc_html( strtoupper( $severity ) ); ?></span>
								</div>
								<div class="wps-source-evidence"><?php echo esc_html( (string) ( $item['subject'] ?? '' ) ); ?></div>
								<?php if ( ! empty( $item['detail'] ) ) : ?>
									<div class="wps-source-detail"><?php echo esc_html( (string) $item['detail'] ); ?></div>
								<?php endif; ?>
								<div class="wps-source-next"><?php echo esc_html( (string) ( $item['next'] ?? '' ) ); ?></div>
							</div>
							<div class="wps-source-origin"><?php echo esc_html( (string) ( $item['source'] ?? '' ) ); ?></div>
						</div>
					<?php endforeach; ?>
				</div>
			<?php endif; ?>

			<?php if ( $commands ) : ?>
				<details class="wps-source-commands">
					<summary>SSH grep commands for this trace</summary>
					<div class="wps-source-command-list">
						<?php foreach ( $commands as $command ) :
							$cmd = (string) ( $command['command'] ?? '' );
							if ( $cmd === '' ) {
								continue;
							}
							?>
							<div class="wps-source-command">
								<div class="wps-source-command-label"><?php echo esc_html( (string) ( $command['label'] ?? 'Trace command' ) ); ?></div>
								<div class="wps-source-command-box">
									<code id="wps-source-cmd-<?php echo esc_attr( md5( $cmd ) ); ?>"><?php echo esc_html( $cmd ); ?></code>
									<button type="button" data-wps-copy="prev">Copy</button>
								</div>
							</div>
						<?php endforeach; ?>
					</div>
				</details>
			<?php endif; ?>
		</div>
		<?php
	}

	private static function build_analytics( array $events, array $blocked_ips ): array {
		$attack_types = [
			'upload_blocked',
			'upload_path_blocked',
			'activation_blocked',
			'ip_auto_blocked',
			'ip_block_refreshed',
			'ip_request_blocked',
			'attacker_account_found',
			'wp_config_modified',
			'core_integrity_fail',
		];
		$clearance_types = [
			'auto_deleted',
			'auto_deactivated',
			'auto_deactivated_orphan',
			'db_option_deleted',
			'cron_replaced',
			'cron_purged',
			'exfil_file_deleted',
			'login_cleaned',
			'functions_cleaned',
			'wp_config_cleaned',
			'sessions_invalidated',
			'transients_cleared',
			'salts_regenerated',
			'user_deleted',
			'attachment_deleted',
			'plugin_folder_deleted',
			'file_deleted',
			'theme_file_deleted',
		];

		$data = [
			'attack_total'        => 0,
			'upload_blocked'      => 0,
			'upload_path_blocked' => 0,
			'clearance_total'     => 0,
			'scan_clean'          => 0,
			'scan_issues'         => 0,
			'blocked_ip_attempts' => 0,
			'last_attack'         => '',
			'last_clearance'      => '',
			'daily'               => [],
			'top_ips'             => [],
			'top_subjects'        => [],
			'event_mix'           => [],
			'max_daily_attacks'   => 0,
			'unique_ip_count'     => 0,
		];

		foreach ( $blocked_ips as $detail ) {
			if ( is_array( $detail ) ) {
				$data['blocked_ip_attempts'] += (int) ( $detail['attempts'] ?? 1 );
			}
		}

		foreach ( $events as $ev ) {
			if ( ! is_array( $ev ) ) {
				continue;
			}

			$type    = sanitize_key( (string) ( $ev['type'] ?? '' ) );
			$subject = (string) ( $ev['subject'] ?? '' );
			$ip      = (string) ( $ev['ip'] ?? '' );
			$time    = (string) ( $ev['time'] ?? '' );
			$ts      = self::event_timestamp( $time );
			$date    = $ts ? gmdate( 'Y-m-d', $ts ) : 'unknown';

			if ( ! isset( $data['daily'][ $date ] ) ) {
				$data['daily'][ $date ] = [ 'attacks' => 0, 'clearances' => 0, 'clean' => 0, 'issues' => 0 ];
			}

			$data['event_mix'][ $type ] = ( $data['event_mix'][ $type ] ?? 0 ) + 1;

			if ( in_array( $type, $attack_types, true ) ) {
				$data['attack_total']++;
				$data['daily'][ $date ]['attacks']++;
				if ( $data['last_attack'] === '' ) {
					$data['last_attack'] = $time;
				}
				if ( $ip !== '' && $ip !== 'cli' ) {
					if ( ! isset( $data['top_ips'][ $ip ] ) ) {
						$data['top_ips'][ $ip ] = [ 'label' => $ip, 'count' => 0, 'last' => $time ];
					}
					$data['top_ips'][ $ip ]['count']++;
				}
				if ( $subject !== '' ) {
					$key = substr( $subject, 0, 120 );
					if ( ! isset( $data['top_subjects'][ $key ] ) ) {
						$data['top_subjects'][ $key ] = [ 'label' => $key, 'count' => 0, 'last' => $time ];
					}
					$data['top_subjects'][ $key ]['count']++;
				}
			}

			if ( $type === 'upload_blocked' ) {
				$data['upload_blocked']++;
			} elseif ( $type === 'upload_path_blocked' ) {
				$data['upload_path_blocked']++;
			}

			if ( in_array( $type, $clearance_types, true ) ) {
				$data['clearance_total']++;
				$data['daily'][ $date ]['clearances']++;
				if ( $data['last_clearance'] === '' ) {
					$data['last_clearance'] = $time;
				}
			}

			if ( $type === 'scan_clean' ) {
				$data['scan_clean']++;
				$data['daily'][ $date ]['clean']++;
			} elseif ( $type === 'scan_issues' ) {
				$data['scan_issues']++;
				$data['daily'][ $date ]['issues']++;
			}
		}

		arsort( $data['event_mix'] );
		uasort( $data['top_ips'], [ self::class, 'sort_analytics_rows' ] );
		uasort( $data['top_subjects'], [ self::class, 'sort_analytics_rows' ] );
		krsort( $data['daily'] );
		$data['daily'] = array_slice( $data['daily'], 0, 14, true );
		foreach ( $data['daily'] as $row ) {
			$data['max_daily_attacks'] = max( $data['max_daily_attacks'], (int) $row['attacks'] );
		}
		$data['unique_ip_count'] = count( $data['top_ips'] );
		$data['top_ips'] = array_slice( $data['top_ips'], 0, 8, true );
		$data['top_subjects'] = array_slice( $data['top_subjects'], 0, 8, true );
		$data['event_mix'] = array_slice( $data['event_mix'], 0, 12, true );

		return $data;
	}

	private static function sort_analytics_rows( array $a, array $b ): int {
		return (int) ( $b['count'] ?? 0 ) <=> (int) ( $a['count'] ?? 0 );
	}

	private static function event_timestamp( string $time ): int {
		if ( $time === '' ) {
			return 0;
		}
		$ts = strtotime( str_replace( ' UTC', '', $time ) . ' UTC' );
		return $ts ? (int) $ts : 0;
	}

	private static function render_analytics_table( array $rows, array $headers ): void {
		if ( empty( $rows ) ) {
			echo '<p class="wps-muted wps-p0">No matching events recorded.</p>';
			return;
		}

		echo '<div class="wps-scroll-x"><table class="wps-table wps-table--w360">';
		echo '<thead><tr>';
		foreach ( $headers as $header ) {
			echo '<th>' . esc_html( $header ) . '</th>';
		}
		echo '</tr></thead><tbody>';
		foreach ( $rows as $row ) {
			echo '<tr>';
			echo '<td class="wps-mono wps-break">' . esc_html( (string) ( $row['label'] ?? '' ) ) . '</td>';
			echo '<td class="wps-strong">' . esc_html( (string) ( $row['count'] ?? 0 ) ) . '</td>';
			echo '<td class="wps-muted wps-nowrap">' . esc_html( (string) ( $row['last'] ?? '' ) ) . '</td>';
			echo '</tr>';
		}
		echo '</tbody></table></div>';
	}

	/**
	 * 1.4.31: the permanent sign-in denylist.
	 *
	 * Shown separately from the temporary blocks because it behaves
	 * differently: these entries do not expire, and the only way out is this
	 * table. Kept close to the temporary list so the difference is visible.
	 */
	private static function render_permanent_blocks_table(): void {
		if ( ! class_exists( 'WPS_Login_Guard' ) ) {
			return;
		}
		$list = WPS_Login_Guard::permanent_blocks();

		// 1.4.91: the Safe list.
		//
		// Rendered before the permanent denylist because it answers the more
		// urgent question for anyone who has just had their own code removed:
		// what is protected, and how do I protect something else. A veto with
		// no interface is not a control, and until this release that is exactly
		// what it was.
		if ( class_exists( 'WPS_Remediation_Policy' ) ) {
			$safe_msg = isset( $_GET['wps_safe'] ) ? sanitize_key( (string) wp_unslash( $_GET['wps_safe'] ) ) : '';
			$safe_map = [
				'marked'  => [ 'good', 'Marked Safe. It will not be removed automatically. Automatic removal is refused for it from now on, by every check.' ],
				'revoked' => [ 'muted', 'Safe decision revoked. This target can be acted on automatically again.' ],
				'resumed' => [ 'good', 'Automatic removal resumed.' ],
				'failed'  => [ 'warn', 'That path could not be resolved, so nothing was changed.' ],
			];
			if ( isset( $safe_map[ $safe_msg ] ) ) {
				echo '<div class="wps-status wps-' . esc_attr( $safe_map[ $safe_msg ][0] ) . ' wps-mb6">' . esc_html( $safe_map[ $safe_msg ][1] ) . '</div>';
			}

			if ( WPS_Remediation_Policy::breaker_tripped() ) {
				echo '<div class="wps-card wps-card--pad-lg wps-mt14">';
				echo '<h2 class="wps-card-h">Automatic removal is halted</h2>';
				echo '<p class="wps-sm wps-p">WP Perf Shield tried to remove something you had marked Safe, which should not be possible. It has stopped removing anything automatically until you clear this. Scanning and reporting continue as normal.</p>';
				echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="wps-inline-form">';
				echo '<input type="hidden" name="action" value="wps_reset_breaker">';
				echo wp_nonce_field( 'wps_reset_breaker', '_wpnonce', true, false );
				echo '<button type="submit" class="button">I have reviewed this &mdash; resume automatic removal</button>';
				echo '</form></div>';
			}

			$safe_list = WPS_Remediation_Policy::list_safe();
			echo '<div class="wps-card wps-card--pad-lg wps-mt14">';
			echo '<h2 class="wps-card-h">Protected from automatic removal</h2>';
			echo '<p class="wps-sm wps-muted wps-p">Anything listed here is never removed automatically, by any check, however confident it is. Use it for your own code and for legitimate software this plugin has misjudged. Findings for these targets are still reported so you keep the visibility &ndash; what changes is that nothing acts on them without you.</p>';

			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="wps-inline-form wps-mb6">';
			echo '<input type="hidden" name="action" value="wps_mark_safe">';
			echo wp_nonce_field( 'wps_mark_safe', '_wpnonce', true, false );
			echo '<label class="wps-sm">Protect a path <input type="text" name="path" placeholder="wp-content/mu-plugins/rest-lockdown.php" class="wps-mono wps-sm regular-text"></label> ';
			echo '<select name="scope" class="wps-sm"><option value="file">this file only</option><option value="directory">this folder and everything in it</option></select> ';
			echo '<label class="wps-sm">Reason <input type="text" name="reason" placeholder="my own code" class="wps-sm"></label> ';
			echo '<button type="submit" class="button">Protect</button>';
			echo '</form>';

			if ( empty( $safe_list ) ) {
				echo '<p class="wps-muted wps-p0">Nothing is protected yet.</p></div>';
			} else {
				echo '<div class="wps-scroll-x"><table class="wps-logs">';
				echo '<thead><tr><th>Target</th><th>Scope</th><th>Reason</th><th>Marked</th><th class="wps-logs-act"><span class="screen-reader-text">Revoke</span></th></tr></thead><tbody>';
				foreach ( $safe_list as $sid => $meta ) {
					echo '<tr><td class="wps-mono wps-sm">' . esc_html( (string) $sid ) . '</td>';
					echo '<td class="wps-sm">' . esc_html( (string) ( $meta['scope'] ?? 'file' ) ) . '</td>';
					echo '<td class="wps-sm wps-muted">' . esc_html( (string) ( $meta['reason'] ?? '' ) ) . '</td>';
					echo '<td class="wps-sm wps-muted">' . esc_html( ! empty( $meta['at'] ) ? gmdate( 'Y-m-d H:i', (int) $meta['at'] ) . ' UTC' : '' ) . '</td>';
					echo '<td class="wps-logs-act"><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
					echo '<input type="hidden" name="action" value="wps_revoke_safe">';
					echo wp_nonce_field( 'wps_revoke_safe', '_wpnonce', true, false );
					echo '<input type="hidden" name="path" value="' . esc_attr( (string) $sid ) . '">';
					echo '<button type="submit" class="button-link">Revoke</button>';
					echo '</form></td></tr>';
				}
				echo '</tbody></table></div></div>';
			}
		}

		$msg = isset( $_GET['wps_unblocked'] ) ? sanitize_key( (string) wp_unslash( $_GET['wps_unblocked'] ) ) : '';
		if ( '1' === $msg ) {
			echo '<div class="wps-status wps-good wps-mb6">Address removed from the permanent denylist. It can sign in again.</div>';
		} elseif ( '0' === $msg ) {
			echo '<div class="wps-status wps-warn wps-mb6">That address was not on the permanent denylist.</div>';
		}

		$pban = isset( $_GET['wps_pban'] ) ? sanitize_key( (string) wp_unslash( $_GET['wps_pban'] ) ) : '';
		if ( '' !== $pban ) {
			$pmap = [
				'blocked'   => [ 'good', 'Permanently blocked. It can no longer sign in; the site stays readable to it.' ],
				'exists'    => [ 'muted', 'That address or range was already on the permanent denylist.' ],
				'protected' => [ 'warn', 'Refused: that address or range holds your own or a recent administrator address. Nothing was blocked.' ],
				'too-broad' => [ 'warn', 'Refused: that range is too broad. Use a subnet no larger than a /16 (IPv4) or /32 (IPv6).' ],
				'invalid'   => [ 'warn', 'That was not a valid address or CIDR range, so nothing was blocked.' ],
			];
			if ( isset( $pmap[ $pban ] ) ) {
				echo '<div class="wps-status wps-' . esc_attr( $pmap[ $pban ][0] ) . ' wps-mb6">' . esc_html( $pmap[ $pban ][1] ) . '</div>';
			}
		}

		echo '<div class="wps-card wps-card--pad-lg wps-mt14">';
		echo '<h2 class="wps-card-h">Permanently blocked from signing in</h2>';
		echo '<p class="wps-sm wps-muted wps-p">Automatic entries are addresses that tried to sign in as an account that does not exist here &ndash; <code>admin</code>, <code>root</code> and similar. You can also add an address or a whole range by hand below: the deliberate forever-ban for a range that has proven hostile, since the automatic range guard tops out at seven days. Nothing here expires. Entries are blocked from signing in only; the site itself stays readable to them. Remove any entry if an address has been reassigned.</p>';

		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="wps-inline-form wps-mb6">';
		echo '<input type="hidden" name="action" value="wps_permanent_block">';
		echo wp_nonce_field( 'wps_permanent_block', '_wpnonce', true, false );
		echo '<label class="wps-sm">Permanently block an address or range <input type="text" name="target" placeholder="e.g. 173.239.218.0/24 or 203.0.113.5" class="wps-mono wps-sm regular-text"></label> ';
		echo '<button type="submit" class="button">Permanently block</button>';
		echo '</form>';
		echo '<p class="wps-sm wps-muted wps-p">A single address is also reported to Akismet. A whole range is not &ndash; that would flag its innocent neighbours &ndash; but the individual addresses that attack from a blocked range are reported as they are caught. A range is refused if it holds your own address or is broader than a /16.</p>';

		if ( empty( $list ) ) {
			echo '<p class="wps-muted wps-p0">Nothing on the permanent denylist yet.</p></div>';
			return;
		}

		echo '<div class="wps-scroll-x"><table class="wps-logs">';
		echo '<thead><tr><th>Address or range</th><th>Added for</th><th>Blocked</th><th class="wps-logs-act"><span class="screen-reader-text">Remove</span></th></tr></thead><tbody>';
		foreach ( $list as $ip => $row ) {
			$when = isset( $row['at'] )
				? ( class_exists( 'WPS_Utils' )
					? WPS_Utils::local_time( gmdate( 'Y-m-d H:i:s', (int) $row['at'] ) . ' UTC' )
					: gmdate( 'Y-m-d H:i:s', (int) $row['at'] ) . ' UTC' )
				: '';
			echo '<tr>';
			echo '<td class="wps-logs-path">' . esc_html( (string) $ip ) . '</td>';
			echo '<td class="wps-logs-kind">' . esc_html( (string) ( $row['user'] ?? '' ) ) . '</td>';
			echo '<td class="wps-logs-size">' . esc_html( $when ) . '</td>';
			echo '<td class="wps-logs-act">';
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="wps-inline-form">';
			echo '<input type="hidden" name="action" value="wps_unblock_permanent">';
			echo '<input type="hidden" name="ip" value="' . esc_attr( (string) $ip ) . '">';
			echo wp_nonce_field( 'wps_unblock_permanent', '_wpnonce', true, false );
			echo '<button type="submit" class="button-link">Remove</button>';
			echo '</form>';
			echo '</td></tr>';
		}
		echo '</tbody></table></div></div>';
	}

	private static function render_blocked_ips_table( array $blocked_ips ): void {
		$rep = isset( $_GET['wps_report'] ) ? sanitize_key( (string) wp_unslash( $_GET['wps_report'] ) ) : '';
		if ( '' !== $rep ) {
			$map = [
				'reported' => [ 'good', 'Address reported to Akismet as spam. Thank you for contributing to the shared database.' ],
				'already'  => [ 'muted', 'That address had already been reported.' ],
				'no-key'   => [ 'warn', 'Akismet is not active or has no key, so the address could not be reported.' ],
				'failed'   => [ 'warn', 'The report could not be sent - the address was not valid or Akismet did not accept it.' ],
			];
			if ( isset( $map[ $rep ] ) ) {
				echo '<div class="wps-status wps-' . esc_attr( $map[ $rep ][0] ) . ' wps-mb6">' . esc_html( $map[ $rep ][1] ) . '</div>';
			}
		}
		if ( empty( $blocked_ips ) ) {
			echo '<p class="wps-muted wps-p0">No IPs are currently auto-blocked.</p>';
			return;
		}

		echo '<div class="wps-scroll-x">';
		echo '<table class="wps-sm wps-table" style="min-width:760px">';
		echo '<thead><tr>';
		foreach ( [ 'IP', 'Attempts', 'Last file', 'Last pathway', 'User', 'Last seen', 'Expires', 'Report' ] as $header ) {
			echo '<th>' . esc_html( $header ) . '</th>';
		}
		echo '</tr></thead><tbody>';

		foreach ( $blocked_ips as $ip => $detail ) {
			echo '<tr>';
			echo '<td class="wps-mono wps-bad-t wps-strong">' . esc_html( (string) $ip ) . '</td>';
			echo '<td>' . esc_html( (string) ( $detail['attempts'] ?? 1 ) ) . '</td>';
			echo '<td class="wps-mono">' . esc_html( (string) ( $detail['last_filename'] ?? '' ) ) . '</td>';
			echo '<td class="wps-mono wps-break">' . esc_html( (string) ( $detail['last_pathway'] ?? '' ) ) . '</td>';
			echo '<td class="wps-mono">' . esc_html( (string) ( $detail['last_user'] ?? 'guest' ) ) . '</td>';
			echo '<td class="wps-nowrap">' . esc_html( (string) ( $detail['last_seen'] ?? '' ) ) . '</td>';
			$expires_disp = ! empty( $detail['expires'] )
				? ( class_exists( 'WPS_Utils' )
					? esc_html( WPS_Utils::local_time( gmdate( 'Y-m-d H:i:s', (int) $detail['expires'] ) . ' UTC' ) )
					: esc_html( gmdate( 'Y-m-d H:i:s', (int) $detail['expires'] ) . ' UTC' ) )
				: 'manual';
			echo '<td class="wps-nowrap">' . $expires_disp . '</td>';

			// 1.4.27: manual report control, one per row.
			$already = (bool) get_transient( 'wps_reported_' . md5( (string) $ip ) );
			echo '<td class="wps-nowrap">';
			if ( $already ) {
				echo '<span class="wps-xs wps-muted">reported</span>';
			} else {
				echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="wps-inline-form">';
				echo '<input type="hidden" name="action" value="wps_report_ip">';
				echo '<input type="hidden" name="ip" value="' . esc_attr( (string) $ip ) . '">';
				echo '<input type="hidden" name="user" value="' . esc_attr( (string) ( $detail['last_user'] ?? '' ) ) . '">';
				echo wp_nonce_field( 'wps_report_ip', '_wpnonce', true, false );
				echo '<button type="submit" class="button-link wps-report-btn">Report spam</button>';
				echo '</form>';
			}
			echo '</td>';
			echo '</tr>';
		}

		echo '</tbody></table></div>';
	}
}
