<?php
/**
 * WP Perf Shield  Logs tab (1.3.73).
 *
 * Read-only viewer over the server access/error logs and the WordPress debug
 * log. Two functions: a one-click "Scan all logs for campaign indicators" that
 * greps every readable log for this family's C2 hosts, static token, and
 * request fingerprints, and a per-log tail viewer for manual correlation
 * against a finding's timestamp.
 *
 * All log content is delivered as data and rendered by the admin JS via
 * textContent, never as HTML, because access logs carry attacker-controlled
 * strings.
 *
 * @package WP_Perf_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPS_Admin_Logs {

	public static function render( array $context ): void {
		$logs = class_exists( 'WPS_Log_Reader' ) ? WPS_Log_Reader::discover() : [];
		?>
		<div>
			<div class="wps-mb10 wps-card">
				<h2 class="wps-card-h">Server log inspection</h2>
				<p class="wps-muted wps-p wps-lede">
					Match a finding's timestamp against the request that wrote it. Read-only &ndash; nothing here modifies a log.
				</p>

				<?php if ( empty( $logs ) ) : ?>
					<div class="wps-note wps-note--bad">
						No readable log files were found at the conventional locations. This usually means PHP lacks read access to the access logs on this host. The WordPress debug log appears here only when <code>WP_DEBUG_LOG</code> is enabled and the file exists.
					</div>
				<?php else : ?>
					<p class="wps-p">
						<button id="wps-log-scanall-btn" class="button button-primary"><span class="wps-icon dashicons dashicons-search" aria-hidden="true"></span>Scan all logs for campaign indicators</button>
						<button id="wps-log-loginscan-btn" class="button"><span class="wps-icon dashicons dashicons-privacy" aria-hidden="true"></span>Find automated-login attempts</button>
						<span id="wps-log-scan-status" class="wps-sm wps-muted wps-ml10"></span>
					</p>

					<table class="wps-logs">
						<thead>
							<tr>
								<th>Log file</th>
								<th class="wps-logs-size">Size</th>
								<th class="wps-logs-act"><span class="screen-reader-text">Actions</span></th>
							</tr>
						</thead>
						<tbody>
							<?php
							foreach ( $logs as $log ) :
								$path  = (string) $log['path'];
								$bytes = (int) $log['size'];
								// A file this large is worth a word of warning before
								// someone scans it: the request can take a while and
								// may hit the host's execution limit.
								$heavy = $bytes > 52428800;
								?>
								<tr>
									<td class="wps-logs-file">
										<span class="wps-logs-path"><?php echo esc_html( $path ); ?></span>
										<span class="wps-logs-kind"><?php echo esc_html( (string) $log['label'] ); ?></span>
									</td>
									<td class="wps-logs-size<?php echo $heavy ? ' wps-logs-heavy' : ''; ?>">
										<?php echo esc_html( size_format( $bytes ) ); ?>
										<?php if ( $heavy ) : ?>
											<span class="wps-logs-heavy-note" title="Large file - a full scan may take a while or time out">slow to scan</span>
										<?php endif; ?>
									</td>
									<td class="wps-logs-act">
										<button class="button-link wps-log-tail-btn" data-path="<?php echo esc_attr( $path ); ?>">Tail</button>
										<span class="wps-logs-sep" aria-hidden="true">&middot;</span>
										<button class="button-link wps-log-iocscan-btn" data-path="<?php echo esc_attr( $path ); ?>">IOC scan</button>
									</td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
					<p class="wps-logs-foot">
						Only logs the web-server user can read appear here. On many hosts the raw access log is owned by the system &ndash; if the one you need is missing, point your hosting panel's log viewer at the same timestamp.
					</p>
				<?php endif; ?>
			</div>

			<div id="wps-log-output-wrap" class="wps-card" style="display:none">
				<div class="wps-between wps-mb6">
					<strong id="wps-log-output-title"></strong>
					<button id="wps-log-output-close" class="button-link wps-muted">Close</button>
				</div>
				<pre id="wps-log-output" class="wps-p0 wps-sm wps-break wps-terminal"></pre>
			</div>
		</div>
		<?php
	}
}
