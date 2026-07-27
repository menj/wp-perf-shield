<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Remediation tab renderer (Phase 3 split from class-admin.php).
 *
 * Renders the file artefact action grid (delete exfil, clean wp-login,
 * clean functions, replace wp-cron, clean wp-config), the database options
 * action, and the manual-SSH command list. All button IDs (wps-del-exfil-btn,
 * wps-clean-login-btn, wps-clean-funcs-btn, wps-clean-cron-btn,
 * wps-clean-wpconfig-btn, wps-del-db-btn) and the wps-rem-msg status div are
 * unchanged so the admin JavaScript needs no edits.
 */
class WPS_Admin_Remediation {

	public static function render( array $context ): void {
		?>
		<div class="wps-tab">

			<p class="wps-muted wps-p">
				Use the actions below to remove malware artefacts directly from the WordPress admin. Where auto-deletion during scan was not possible, use the targeted buttons here.
			</p>

			<div id="wps-rem-msg" class="wps-mb10 wps-status" role="status" aria-live="polite"></div>

			<!-- File artefacts -->
			<div class="wps-card wps-card--flush">
				<div class="wps-card-head">File artefacts</div>
				<div class="wps-card-body">
					<div class="wps-grid-2 wps-grid-2--tight">

						<div class="wps-note wps-note--outline-bad">
							<div class="wps-label"><span class="wps-icon dashicons dashicons-trash" aria-hidden="true"></span>Delete credential exfil file</div>
							<p class="wps-sm wps-muted wps-p">Finds and permanently deletes <code>Stained_Heart_Red-600x500.png</code> (fake PNG containing harvested login credentials). Contents are logged before deletion.</p>
							<button id="wps-del-exfil-btn" class="button wps-btn-danger">Delete exfil file</button>
						</div>

						<div class="wps-note wps-note--outline-bad">
							<div class="wps-label"><span class="wps-icon dashicons dashicons-editor-removeformatting" aria-hidden="true"></span>Clean wp-login.php</div>
							<p class="wps-sm wps-muted wps-p">Removes the credential-harvester injection block from <code>wp-login.php</code>. If pattern matching fails, downloads a clean copy from wordpress.org.</p>
							<button id="wps-clean-login-btn" class="button wps-btn-danger">Clean wp-login.php</button>
						</div>

						<div class="wps-note wps-note--outline-bad">
							<div class="wps-label"><span class="wps-icon dashicons dashicons-editor-removeformatting" aria-hidden="true"></span>Clean active theme functions.php</div>
							<p class="wps-sm wps-muted wps-p">Removes the "WordPress session analytics" credential-harvester block injected into your active theme's <code>functions.php</code>.</p>
							<button id="wps-clean-funcs-btn" class="button wps-btn-danger">Clean functions.php</button>
						</div>

						<div class="wps-note wps-note--outline-bad">
							<div class="wps-label"><span class="wps-icon dashicons dashicons-update" aria-hidden="true"></span>Replace wp-cron.php</div>
							<p class="wps-sm wps-muted wps-p">Downloads a clean <code>wp-cron.php</code> from official WordPress source mirrors and replaces the tampered version. Your WP version is detected automatically.</p>
							<button id="wps-clean-cron-btn" class="button wps-btn-danger">Replace wp-cron.php</button>
						</div>

						<div class="wps-note wps-note--outline-bad">
							<div class="wps-label"><span class="wps-icon dashicons dashicons-lock" aria-hidden="true"></span>Clean wp-config.php</div>
							<p class="wps-sm wps-muted wps-p">Removes only known malicious executable lines or marker blocks from <code>wp-config.php</code>. Creates a backup before writing and stores a new clean baseline after success.</p>
							<button id="wps-clean-wpconfig-btn" class="button wps-btn-danger">Clean wp-config.php</button>
						</div>

					</div>
				</div>
			</div>

			<!-- Database -->
			<div class="wps-card wps-card--flush">
				<div class="wps-card-head">Database options</div>
				<div class="wps-card-body">
					<div class="wps-note wps-note--outline-bad">
						<div class="wps-label"><span class="wps-icon dashicons dashicons-trash" aria-hidden="true"></span>Delete malicious database options</div>
						<p class="wps-sm wps-muted wps-p">
							Scans the <code>wp_options</code> table for known malware-set options and deletes any found. This covers persistence keys used by the wp-perf-analytics/session-manager ClickFix campaign, newer render-hijacker variants, and the WP-antymalwary-bot family.
						</p>
						<p class="wps-xs wps-dim wps-p">
							Checks for: <code>wp_session_tokens_config</code>, <code>session_tokens_config</code>, <code>wp_perf_ok</code>, <code>_cf_verified</code>, <code>cf_verified_token</code>, <code>wp_94d4678186_cfg</code>, <code>wp_a26c00cc40_cfg</code>, <code>wp_0b05838858_cfg</code>, <code>wp_e3ef2393dd_cfg</code>, <code>wp_204acd2d43_cfg</code>, <code>wp_antymalwary_bot</code>, <code>wpconsole_key</code>, <code>malwary_pass</code> and others.
						</p>
						<button id="wps-del-db-btn" class="button wps-btn-danger"><span class="wps-icon dashicons dashicons-trash" aria-hidden="true"></span>Delete malicious DB options</button>
					</div>
				</div>
			</div>

			<!-- Manual instructions for items the plugin cannot touch -->
			<div class="wps-card wps-card--flush">
				<div class="wps-card-head">Manual steps (SSH required)</div>
				<div style="padding:14px 16px">
					<p class="wps-p wps-muted">Some actions require SSH because they involve WP core files outside wp-content or WP-CLI. Copy these commands as needed:</p>
					<table class="wps-table">
						<?php
						$manual = [
							[ 'Replace wp-cron.php manually (fallback)', 'wget -O ' . ABSPATH . 'wp-cron.php https://core.svn.wordpress.org/tags/' . get_bloginfo( 'version' ) . '/wp-cron.php' ],
							[ 'Delete malicious DB option via WP-CLI', 'wp option delete wp_session_tokens_config' ],
							[ 'Find PHP files in uploads directory', 'find ' . ( wp_upload_dir()['basedir'] ?? ABSPATH . 'wp-content/uploads' ) . ' -name "*.php" -type f' ],
							[ 'Find recently created PHP files (last 7 days)', 'find ' . ABSPATH . ' -name "*.php" -newer ' . ABSPATH . 'wp-config.php -not -path "*/wp-admin/*" -not -path "*/wp-includes/*" | head -30' ],
						];
						foreach ( $manual as [ $label, $cmd ] ) :
						?>
						<tr>
							<td class="wps-muted" style="width:280px"><?php echo esc_html( $label ); ?></td>
							<td><code class="wps-break" style="background:#f5f5f5;padding:4px 7px;border-radius:3px;border:1px solid #ddd;display:inline-block"><?php echo esc_html( $cmd ); ?></code></td>
						</tr>
						<?php endforeach; ?>
					</table>
				</div>
			</div>

		</div><!-- /remediation tab -->
		<?php
	}
}
