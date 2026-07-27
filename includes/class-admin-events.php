<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Events tab renderer (Phase 3 split from class-admin.php).
 *
 * Renders the security event log table with row colouring for alerts and
 * clearance events, plus the Clear log button. Button IDs (wps-clear-btn-log)
 * and the wps-log-msg status div are unchanged.
 */
class WPS_Admin_Events {

	public static function render( array $context ): void {
		$events       = $context['events'];
		$event_labels = $context['event_labels'];
		$chain        = $context['event_log_status'] ?? null;
		$from_store   = is_array( $chain );
		$incidents = class_exists( 'WPS_EDR' ) ? WPS_EDR::recent_incidents( 8 ) : [];
		?>
		<div class="wps-tab">

			<?php if ( $incidents ) : ?>
			<div class="wps-card">
				<div class="wps-card-head">
					<span class="wps-strong wps-md">Incidents</span>
					<span class="wps-sm wps-dim wps-ml10">Related activity grouped by who did it and when, newest first. Risk is the sum of the events in each incident.</span>
				</div>
				<table class="wps-events wps-events--incidents">
					<thead>
						<tr>
							<th class="wps-ev-time">Started (<?php echo esc_html( WPS_Utils::timezone_label() ); ?>)</th>
							<th class="wps-ev-user">User</th>
							<th class="wps-ev-ip">IP</th>
							<th class="wps-inc-n">Events</th>
							<th class="wps-inc-risk">Risk</th>
							<th class="wps-strong wps-muted">Activity</th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( $incidents as $inc ) :
						$band  = (string) ( $inc['band'] ?? 'low' );
						$class = 'wps-ok-t';
						if ( $band === 'medium' )   { $class = 'wps-warn-t'; }
						if ( $band === 'high' )     { $class = 'wps-bad-t'; }
						if ( $band === 'critical' ) { $class = 'wps-bad-t wps-strong'; }
						$line = class_exists( 'WPS_EDR' ) ? WPS_EDR::incident_timeline( (string) $inc['incident_id'], 6 ) : [];
						$steps = [];
						foreach ( $line as $ev ) {
							$steps[] = str_replace( '_', ' ', (string) ( $ev['event_type'] ?? '' ) );
						}
						?>
						<tr>
							<td class="wps-ev-time wps-nowrap"><?php echo esc_html( WPS_Utils::local_time( (string) ( $inc['started'] ?? '' ) ) ); ?></td>
							<td class="wps-ev-user"><?php echo esc_html( (string) ( $inc['username'] ?? '-' ) ); ?></td>
							<td class="wps-ev-ip wps-nowrap"><?php echo esc_html( (string) ( $inc['ip'] ?? '-' ) ); ?></td>
							<td class="wps-inc-n"><?php echo (int) ( $inc['events'] ?? 0 ); ?></td>
							<td class="wps-inc-risk <?php echo esc_attr( $class ); ?>"><?php echo (int) ( $inc['risk'] ?? 0 ); ?> <span class="wps-xs wps-dim">(<?php echo esc_html( $band ); ?>)</span></td>
							<td class="wps-ev-activity"><?php echo esc_html( WPS_Utils::collapse_steps( $steps ) ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
				<p class="wps-xs wps-dim wps-mt8">A single sign-in is unremarkable. A sign-in followed by the user editor and a new administrator account, inside one window, is not - the cumulative score says so without anyone having to write a rule for that exact sequence. Incidents are observations: nothing here is ever removed automatically.</p>
			</div>
			<?php endif; ?>

			<div class="wps-card wps-card--flush">
				<div class="wps-card-head wps-between">
					<div>
						<span class="wps-strong wps-md">Security event log</span>
						<span class="wps-sm wps-dim wps-ml10"><?php echo count( $events ); ?> event<?php echo count( $events ) !== 1 ? 's' : ''; ?> (newest first<?php echo $from_store ? ', tamper-evident store' : ', max 200'; ?>)</span>
					</div>
					<button id="wps-clear-btn-log" class="button wps-bad-t wps-btn-danger wps-sm"> Clear log</button>
				</div>

				<?php if ( $from_store ) :
					$ok        = ( $chain['status'] ?? '' ) === 'ok';
					$pre       = (int) ( $chain['pre_chain'] ?? 0 );
					$verified  = (int) ( $chain['verified'] ?? 0 );
					?>
					<p class="wps-sm wps-p0 <?php echo $ok ? 'wps-ok-t' : 'wps-bad-t'; ?>">
						<?php if ( $ok ) : ?>
							Chain verified: <?php echo (int) $verified; ?> signed event<?php echo $verified !== 1 ? 's' : ''; ?> intact<?php echo $pre > 0 ? ', ' . (int) $pre . ' pre-chain (imported from the file log, unsigned by design)' : ''; ?>.
						<?php else : ?>
							CHAIN VERIFICATION FAILED<?php echo ! empty( $chain['first_bad_id'] ) ? ' at record #' . (int) $chain['first_bad_id'] : ( ( $chain['truncation_suspected'] ?? false ) ? ': records appear to have been removed (anchor mismatch)' : '' ); ?>. Someone has modified or deleted event records directly. Treat the log as compromised evidence and investigate database access.
						<?php endif; ?>
					</p>
				<?php endif; ?>

				<?php if ( empty( $events ) ) : ?>
					<p class="wps-p0 wps-dim wps-empty">No events recorded yet. Events are written when the scanner runs, remediations are applied, or the blocker intercepts an activation attempt.</p>
				<?php else : ?>
				<div class="wps-scroll-x">
				<table class="wps-events">
					<thead>
						<tr>
							<th class="wps-ev-time">Time (<?php echo esc_html( WPS_Utils::timezone_label() ); ?>)</th>
							<th class="wps-ev-what">Event</th>
							<th>Detail</th>
							<?php if ( $from_store ) : ?><th class="wps-ev-user">User</th><?php endif; ?>
							<th class="wps-ev-ip">Source</th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( $events as $i => $ev ) :
						$type    = (string) ( $ev['type'] ?? '' );
						// 1.4.16: one source of truth. This screen previously kept
						// its own two arrays of "alert" and "ok" event types, which
						// had already drifted from the rest of the plugin - the
						// wp-config hash event was listed under a name that is no
						// longer emitted, so the most serious event on the site
						// rendered as neutral.
						$sev     = WPS_Utils::event_severity( $type );
						$label   = WPS_Utils::event_label( $type, $event_labels );
						$subject = (string) ( $ev['subject'] ?? '' );
						$ip      = (string) ( $ev['ip'] ?? '' );
						$time    = (string) ( $ev['time'] ?? '' );
						?>
						<tr data-wps-sev="<?php echo esc_attr( $sev ); ?>">
							<td class="wps-ev-time wps-nowrap"><?php echo esc_html( WPS_Utils::local_time( $time ) ); ?></td>
							<td class="wps-ev-what">
								<span class="wps-sev-dot" aria-hidden="true"></span><?php echo esc_html( $label ); ?>
								<span class="screen-reader-text"><?php echo esc_html( ' (' . $sev . ')' ); ?></span>
							</td>
							<td class="wps-ev-detail"><?php echo esc_html( $subject ); ?></td>
							<?php if ( $from_store ) : ?><td class="wps-ev-user wps-nowrap"><?php echo esc_html( (string) ( $ev['user'] ?? '' ) ); ?></td><?php endif; ?>
							<td class="wps-ev-ip wps-nowrap"><?php echo esc_html( $ip ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
				</div>
				<?php endif; ?>
			</div>

			<p class="wps-xs wps-dim wps-mt8">Log file: <code><?php echo esc_html( WPS_LOG_FILE ); ?></code><?php if ( $from_store ) : ?> - Clear log empties this file copy only; the tamper-evident store above is append-only and rotates automatically, and the clearance itself is recorded.<?php endif; ?></p>
			<div id="wps-log-msg" class="wps-mt8 wps-status"></div>

		</div><!-- /events tab -->
		<?php
	}
}
