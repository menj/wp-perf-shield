<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Overview tab renderer (Phase 3 split from class-admin.php).
 *
 * Renders status cards, the run-scan button, the system readiness grid,
 * the findings panel, and a recent-events table. Markup is byte-for-byte
 * the same as it was in WPS_Admin::render_page() before the split.
 */
class WPS_Admin_Overview {

	public static function render( array $context ): void {
		$last_scan    = $context['last_scan'];
		$findings     = $context['findings'];
		$events       = $context['events'];
		$blocked_ips  = $context['blocked_ips'];
		$event_labels = $context['event_labels'];
		?>
		<div class="wps-tab">

			<!-- Status cards -->
			<div class="wps-mb10 wps-flexwrap">
				<?php
				$scan_time = is_array( $last_scan ) ? esc_html( $last_scan['time'] ) : 'Not yet run';
				$cards = [
					[ 'label' => 'Last scan', 'value' => $scan_time, 'class' => '' ],
					[ 'label' => 'Scan result', 'value' => count( $findings ) > 0 ? count( $findings ) . ' issue(s)' : 'Clean', 'class' => count( $findings ) > 0 ? 'wps-kpi-bad-t' : 'wps-good-t' ],
					[ 'label' => 'Events logged', 'value' => count( $events ), 'class' => '' ],
					[ 'label' => 'WP version', 'value' => get_bloginfo( 'version' ), 'class' => '' ],
					[ 'label' => 'Hostile IP blocks', 'value' => count( $blocked_ips ), 'class' => count( $blocked_ips ) > 0 ? 'wps-bad-t' : '' ],
				];
				foreach ( $cards as $c ) : ?>
				<div class="wps-kpi wps-kpi--sm">
					<div class="wps-kpi-label"><?php echo esc_html( $c['label'] ); ?></div>
					<div class="wps-md wps-strong <?php echo esc_attr( $c['class'] ); ?>"><?php echo esc_html( $c['value'] ); ?></div>
				</div>
				<?php endforeach; ?>
			</div>

			<!-- Scan button -->
			<div class="wps-mb10 wps-row">
				<button id="wps-scan-btn" class="button button-primary"><span class="wps-icon dashicons dashicons-search" aria-hidden="true"></span>Run scan now</button>
				<a href="<?php echo esc_url( admin_url( 'tools.php?page=wp-perf-shield&tab=diagnostics' ) ); ?>" class="button" style="margin-left:auto">Diagnostics</a>
				<a href="<?php echo esc_url( admin_url( 'tools.php?page=wp-perf-shield&tab=events' ) ); ?>" class="button">Events</a>
			</div>
			<div id="wps-msg" class="wps-mb10 wps-status"></div>

			<!-- Findings list -->
			<?php if ( $findings ) : ?>
			<div class="wps-findings-panel">
				<div class="wps-findings-head">
					<div>
						<div class="wps-findings-title"><?php echo esc_html( (string) count( $findings ) ); ?> issue<?php echo count( $findings ) !== 1 ? 's' : ''; ?> require attention</div>
						<div class="wps-findings-subtitle">Confirmed artefacts can be auto-cleared; review any remaining database or file actions.</div>
					</div>
					<span class="wps-findings-count">Action required</span>
				</div>
				<div class="wps-finding-list">
					<?php foreach ( $findings as $f ) :
						$severity = strtolower( (string) ( $f['severity'] ?? 'unknown' ) );
						$status_label = ! empty( $f['remediated'] ) ? 'Auto-deleted' : ( ! empty( $f['auto_delete_skipped'] ) ? 'Skipped' : 'Needs action' );
						$status_class = ! empty( $f['remediated'] ) ? 'is-done' : ( ! empty( $f['auto_delete_skipped'] ) ? 'is-warn' : 'is-alert' );
						$matches = [];
						if ( ! empty( $f['match'] ) ) {
							$matches = array_filter( array_map( 'trim', explode( ',', (string) $f['match'] ) ) );
						}
						?>
					<div class="wps-finding-card">
						<div class="wps-finding-severity is-<?php echo esc_attr( sanitize_html_class( $severity ) ); ?>">
							<?php echo esc_html( strtoupper( $severity ) ); ?>
						</div>
						<div class="wps-finding-main">
							<div class="wps-finding-type"><?php echo esc_html( (string) ( $f['type'] ?? 'Unknown finding' ) ); ?></div>
							<div class="wps-finding-subject"><?php echo esc_html( (string) ( $f['subject'] ?? '' ) ); ?></div>
							<?php if ( $matches ) : ?>
								<div class="wps-match-list" aria-label="Matched signatures">
									<?php foreach ( array_slice( $matches, 0, 5 ) as $match ) : ?>
										<code><?php echo esc_html( $match ); ?></code>
									<?php endforeach; ?>
									<?php if ( count( $matches ) > 5 ) : ?>
										<span class="wps-match-more">+<?php echo esc_html( (string) ( count( $matches ) - 5 ) ); ?></span>
									<?php endif; ?>
								</div>
							<?php endif; ?>
						</div>
						<div class="wps-finding-action">
							<span class="wps-resolution <?php echo esc_attr( $status_class ); ?>"><?php echo esc_html( $status_label ); ?></span>
							<div><?php echo esc_html( trim( (string) ( $f['action'] ?? '' ) ) ); ?></div>
							<?php
							// 1.3.61: inline "Delete this path" button for findings
							// that the scanner has confirmed are safe to delete via
							// one-click. The scanner only sets `delete_path` when
							// the path is contained within WP_PLUGIN_DIR (the
							// post-WPSEC-001 safe boundary). Findings at ABSPATH
							// root, in wp-content/uploads/, in mu-plugins/, or that
							// require surgical editing of a legitimate file (e.g.,
							// the wordfence-waf.php auto_prepend hijack) do NOT
							// have `delete_path` set and therefore do not render
							// this button  those still require manual operator
							// review per the action description above.
							//
							// Do not render the button for findings that are
							// already remediated (auto-deleted) or where the
							// scanner explicitly skipped auto-delete (the operator
							// has already been given the choice once and chose to
							// review).
							//
							// 1.3.65: the onclick attribute is now built PHP-side
							// as a single string and escaped via esc_attr() before
							// being placed into the rendered HTML. The 1.3.61-1.3.64
							// implementation interpolated `wp_json_encode()` output
							// directly into a double-quoted onclick attribute, which
							// was malformed because the JSON-encoded values contain
							// double quotes that prematurely closed the onclick
							// attribute. The browser stopped parsing after the first
							// inner double-quote, leaving the click handler
							// uninstalled and the button silently inert. The fix
							// matches the pattern used by the Forensics-tab
							// `forensic_action_button()` helper, which has been
							// working correctly since 1.3.x because it esc_attr()s
							// the entire onclick string after building it.
							if ( ! empty( $f['delete_path'] ) && empty( $f['remediated'] ) && empty( $f['auto_delete_skipped'] ) ) :
								$confirm_msg = 'Delete this path? This cannot be undone.' . "\n\n" . ( $f['delete_path'] ?? '' );
								?>
								<button type="button" class="button wps-finding-delete-btn"
									data-wps-action="wps_delete_file"
									data-wps-data="<?php echo esc_attr( wp_json_encode( [ 'path' => (string) $f['delete_path'] ] ) ); ?>"
									data-wps-confirm="<?php echo esc_attr( $confirm_msg ); ?>">
									Delete this path
								</button>
							<?php endif; ?>

							<?php
							// 1.3.67: surgical-edit "Clean injection" button. Rendered when the
							// finding carries a `clean_strategy` value that maps to one of our
							// surgical-edit handlers. Two strategies are supported in this
							// release:
							//   - 'wfwaf_hijack'      -> wps_clean_wfwaf_include
							//   - 'user_ini_prepend'  -> wps_clean_user_ini_prepend
							// Each handler operates on a single hard-coded file (wordfence-
							// waf.php at ABSPATH or .user.ini at ABSPATH) and uses backup-on-
							// edit + atomic write + post-write verification. The button's
							// onclick is built using the 1.3.65 esc_attr() pattern to avoid
							// the malformed-attribute bug that 1.3.61-1.3.64 had.
							$clean_action_map = [
								'wfwaf_hijack'     => 'wps_clean_wfwaf_include',
								'user_ini_prepend' => 'wps_clean_user_ini_prepend',
							];
							$strategy = $f['clean_strategy'] ?? '';
							if ( $strategy !== '' && isset( $clean_action_map[ $strategy ] ) && empty( $f['remediated'] ) ) :
								$clean_action = $clean_action_map[ $strategy ];
								$match_value  = (string) ( $f['match'] ?? '' );
								$confirm_msg  = $strategy === 'wfwaf_hijack'
									? "Remove the malicious include line referencing this path from wordfence-waf.php?\n\nA backup of the current file will be saved alongside it before any change.\n\nOffending include: " . $match_value
									: "Remove the auto_prepend_file directive referencing this path from .user.ini?\n\nA backup of the current file will be saved alongside it before any change.\n\nOffending value: " . $match_value;
								?>
								<button type="button" class="button wps-finding-clean-btn"
									data-wps-action="<?php echo esc_attr( $clean_action ); ?>"
									data-wps-data="<?php echo esc_attr( wp_json_encode( [ 'match' => $match_value ] ) ); ?>"
									data-wps-confirm="<?php echo esc_attr( $confirm_msg ); ?>">
									Clean injection
								</button>
							<?php endif; ?>
						</div>
					</div>
					<?php endforeach; ?>
				</div>
			</div>
			<?php else : ?>
			<div class="wps-mb10" style="background:#eaf3de;border:1px solid #639922;border-radius:6px;padding:12px 16px;color:#3b6d11">
				 No issues detected. Last scan: <?php echo esc_html( $scan_time ); ?>
			</div>
			<?php endif; ?>

			<!-- Recent events -->
			<?php if ( $events ) : ?>
			<div class="wps-card wps-card--flush">
				<div class="wps-cardbar">
					<span class="wps-strong wps-md">Recent security events</span>
					<a href="<?php echo esc_url( admin_url( 'tools.php?page=wp-perf-shield&tab=events' ) ); ?>" class="button wps-btn-sm">View all events</a>
				</div>
				<div class="wps-scroll-x">
				<table class="wps-events">
					<thead><tr>
						<th class="wps-ev-time">Time (<?php echo esc_html( WPS_Utils::timezone_label() ); ?>)</th>
						<th class="wps-ev-what">Event</th>
						<th>Detail</th>
						<th class="wps-ev-ip">Source</th>
					</tr></thead>
					<tbody>
					<?php
					foreach ( array_slice( $events, 0, 8 ) as $ev ) :
						$type  = (string) ( $ev['type'] ?? '' );
						$sev   = WPS_Utils::event_severity( $type );
						$label = WPS_Utils::event_label( $type, $event_labels );
						$subj  = (string) ( $ev['subject'] ?? '' );
						?>
						<tr data-wps-sev="<?php echo esc_attr( $sev ); ?>">
							<td class="wps-ev-time wps-nowrap"><?php echo esc_html( WPS_Utils::local_time( (string) ( $ev['time'] ?? '' ) ) ); ?></td>
							<td class="wps-ev-what">
								<span class="wps-sev-dot" aria-hidden="true"></span><?php echo esc_html( $label ); ?>
								<span class="screen-reader-text"><?php echo esc_html( ' (' . $sev . ')' ); ?></span>
							</td>
							<td class="wps-ev-detail"><?php echo esc_html( $subj ); ?></td>
							<td class="wps-ev-ip wps-nowrap"><?php echo esc_html( $ev['ip'] ?? '' ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
				</div>
			</div>
			<?php else : ?>
			<p class="wps-dim">No events logged yet.</p>
			<?php endif; ?>

		</div><!-- /overview tab -->
		<?php
	}
}
