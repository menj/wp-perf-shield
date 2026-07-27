<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Settings tab renderer (Phase 3 split from class-admin.php).
 *
 * Configuration-only since 1.3.35. Renders the custom-block-rules form (extra
 * slugs, hashes, auto-remediation toggle, IP auto-block toggle, strict ZIP
 * upload guard toggle) and the Save button. The previous "Danger zone" block
 * was removed in 1.3.35 and its three buttons moved to the tabs whose data
 * they act on:
 *
 *   wp-rebaseline button       Hardening Section 2 (wp-config.php hardening)
 *   wp-clear-ip-blocks button  Diagnostics, under the Active hostile IP blocks table
 *   wp-export-diag button      Diagnostics (Diagnostics export panel)
 *   wp-clear-log button         removed; the Events tab still has its own
 *
 * Form post action and nonce are unchanged so existing bookmarks continue to work.
 */
class WPS_Admin_Settings {

	public static function render( array $context ): void {
		$settings                   = $context['settings'];
		$auto_delete_enabled        = $context['auto_delete_enabled'];
		$quarantine_enabled         = $context['quarantine_enabled'] ?? true;
		$auto_ip_block_enabled      = $context['auto_ip_block_enabled'];
		$strict_upload_gate_enabled = $context['strict_upload_gate_enabled'];
		$appearance                 = $context['appearance'] ?? 'light';
		?>
		<div class="wps-tab">

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="wps_save_settings">
				<?php wp_nonce_field( 'wps_save_settings' ); ?>

				<div class="wps-card wps-card--pad-lg">
					<h2 class="wps-card-h">Detection rules</h2>
					<p class="wps-sm wps-muted wps-p">Site-specific indicators layered on top of the built-in catalogue.</p>
					<table class="form-table wps-p0">
						<tr>
							<th><label for="extra_slugs">Extra blocked slugs</label></th>
							<td>
								<textarea id="extra_slugs" name="extra_slugs" rows="4" class="wps-mono wps-sm"><?php echo esc_textarea( (string) ( $settings['extra_slugs'] ?? '' ) ); ?></textarea>
								<p class="description">One slug per line. Any plugin path containing this text is blocked from activation and flagged during scans.</p>
							</td>
						</tr>
						<tr>
							<th><label for="login_guard_enabled">Login protection</label></th>
							<td>
								<label class="wps-toggle-row">
									<input type="checkbox" id="login_guard_enabled" name="login_guard_enabled" value="1" <?php checked( ( $settings['login_guard_enabled'] ?? '1' ) !== '0' ); ?>>
									<span>
										<strong>Block addresses that repeatedly fail to sign in</strong><br>
										<span class="description">Five failures within fifteen minutes blocks an address temporarily. Addresses you have signed in from as an administrator are never blocked, and every block expires on its own.</span>
									</span>
								</label>
								<div class="wps-field-actions">
									<span class="wps-field-status">Akismet status: <strong><?php echo esc_html( WPS_Login_Guard::akismet_status() ); ?></strong></span>
									<?php
								// 1.4.18: an operator should not have to wait for an
								// attack to find out whether this works.
								$wps_ak_check = isset( $_GET['wps_ak'] ) ? sanitize_key( (string) wp_unslash( $_GET['wps_ak'] ) ) : '';
								if ( '' !== $wps_ak_check ) {
									$wps_ak_msg = [
										'valid'       => 'Akismet answered: key is valid. Block durations will use its verdicts.',
										'invalid'     => 'Akismet answered: the key is not valid. Blocks will use the default duration.',
										'failed'      => 'Could not reach Akismet. Blocks will use the default duration until it responds.',
										'unavailable' => 'Akismet is not active, or has no key configured. Blocks will use the default duration.',
									][ $wps_ak_check ] ?? '';
									if ( '' !== $wps_ak_msg ) {
										echo '<strong class="wps-field-answer">' . esc_html( $wps_ak_msg ) . '</strong>';
									}
								}
								?>
								<a class="button wps-btn-sm" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=wps_verify_akismet' ), 'wps_verify_akismet' ) ); ?>">Test Akismet connection now</a>
								<?php if ( class_exists( 'WPS_Login_Guard' ) ) : $wps_u = WPS_Login_Guard::akismet_usage(); if ( 'unavailable' !== $wps_u['state'] ) : ?>
									<span class="wps-sm wps-muted">Akismet calls this month: <strong><?php echo esc_html( WPS_Login_Guard::akismet_usage_label() ); ?></strong><?php echo ! empty( $wps_u['throttled'] ) ? ' &mdash; <strong class="wps-bad-t">this key is being throttled for exceeding its plan limit</strong>' : ''; ?>. Most of this is Akismet checking comments; login checks add roughly one call per blocked address.</span>
								<?php endif; endif; ?>
								</div>
								<p class="description wps-field-note">If you are ever locked out, add <code>define( 'WPS_DISABLE_LOGIN_GUARD', true );</code> to wp-config.php over FTP &ndash; no database access needed.</p>
							</td>
						</tr>
						<tr>
							<th><label for="login_network_guard">Rotating attackers</label></th>
							<td>
								<label class="wps-toggle-row">
									<input type="checkbox" id="login_network_guard" name="login_network_guard" value="1" <?php checked( ( $settings['login_network_guard'] ?? '1' ) !== '0' ); ?>>
									<span>
										<strong>Also block a whole address range when attempts rotate across it</strong><br>
										<span class="description">Automated attacks often spread attempts across many addresses in one range so that no single address reaches the limit. This counts them together: twelve failures from at least three different addresses in the same range within fifteen minutes blocks sign-ins from that range for thirty minutes. Ranges containing an address you have signed in from, or one on your allowlist, are never blocked. Turn this off if your visitors share a mobile carrier or corporate network where many people could be behind one range.</span>
									</span>
								</label>
							</td>
						</tr>
						<tr>
							<th><label for="xmlrpc_auth_disabled">XML-RPC sign-in</label></th>
							<td>
								<label class="wps-toggle-row">
									<input type="checkbox" id="xmlrpc_auth_disabled" name="xmlrpc_auth_disabled" value="1" <?php checked( ( $settings['xmlrpc_auth_disabled'] ?? '0' ) === '1' ); ?>>
									<span>
										<strong>Disable authentication over XML-RPC</strong><br>
										<span class="description">XML-RPC lets one request carry hundreds of credential guesses through <code>system.multicall</code>, which is why so much automated traffic goes there. Off by default because Jetpack and the WordPress mobile apps sign in this way &ndash; if you use either, leave this alone.</span>
									</span>
								</label>
							</td>
						</tr>
						<tr>
							<th><label for="login_report_spam">Report attackers to Akismet</label></th>
							<td>
								<label class="wps-toggle-row">
									<input type="checkbox" id="login_report_spam" name="login_report_spam" value="1" <?php checked( ( $settings['login_report_spam'] ?? '1' ) !== '0' ); ?>>
									<span>
										<strong>Report confirmed attacking addresses back to Akismet as spam</strong><br>
										<span class="description">When an address is blocked on conclusive evidence &ndash; many different usernames, a repeat offender, or a bot-only username &ndash; report it to Akismet so every site using Akismet benefits. <strong>On by default.</strong> This contributes to a shared database, so an address you report is flagged for every site using Akismet: the plugin therefore reports only addresses your own site has already proven to be attacking, never one blocked on a single mistyped password, and each address only once. Automatic reporting also stands down when the blocked address falls in a known CDN or proxy range (such as Cloudflare), since behind a proxy that address may not be the real attacker &ndash; you can still report those by hand from the blocked-addresses list in Diagnostics, where a human has looked first. Requires an active Akismet key.</span>
									</span>
								</label>
							</td>
						</tr>
						<tr>
							<th><label for="login_ip_allowlist">Never block these addresses</label></th>
							<td>
								<textarea id="login_ip_allowlist" name="login_ip_allowlist" rows="2" class="wps-mono wps-sm"><?php echo esc_textarea( (string) ( $settings['login_ip_allowlist'] ?? '' ) ); ?></textarea>
								<p class="description">One IP address per line. Useful where an office or VPN shares one address and several people could trip the counter together.</p>
							</td>
						</tr>
						<tr>
							<th><label for="first_party_plugins">Your own plugins</label></th>
							<td>
								<textarea id="first_party_plugins" name="first_party_plugins" rows="3" class="wps-mono wps-sm"><?php echo esc_textarea( (string) ( $settings['first_party_plugins'] ?? '' ) ); ?></textarea>
								<p class="description">One plugin folder name per line, for plugins you wrote or commissioned. These stop being reported as lacking a wordpress.org baseline &ndash; there is no baseline to be had for code never published there. They are not ignored: their PHP files are fingerprinted, and a change that arrives without a version bump is reported, since editing files in place is what both a hotfix and a planted file look like.</p>
							</td>
						</tr>
						<tr>
							<th><label for="extra_hashes">Blocked file hashes</label></th>
							<td>
								<textarea id="extra_hashes" name="extra_hashes" rows="4" class="wps-mono wps-sm"><?php echo esc_textarea( (string) ( $settings['extra_hashes'] ?? '' ) ); ?></textarea>
								<p class="description">One MD5 or SHA-256 hash per line. Get with: <code>md5sum plugin-file.php</code> or <code>sha256sum plugin-file.php</code>.</p>
							</td>
						</tr>
					</table>
				</div>

				<div class="wps-card wps-card--pad-lg">
					<h2 class="wps-card-h">Remediation</h2>
					<p class="wps-sm wps-muted wps-p">What happens when the scanner confirms malware.</p>
					<table class="form-table wps-p0">
						<tr>
							<th>Auto-remediation</th>
							<td>
								<label class="wps-toggle-row">
									<input type="checkbox" name="auto_delete_enabled" value="1" <?php checked( $auto_delete_enabled ); ?>>
									<span>
										<strong>Auto-delete confirmed malware artifacts</strong><br>
										<span class="description">Enabled by default. Applies only to findings the scanner marks as safe for automatic deletion; heuristic and review-only findings remain untouched.</span>
									</span>
								</label>
							</td>
						</tr>
						<tr>
							<th>Quarantine</th>
							<td>
								<label class="wps-toggle-row">
									<input type="checkbox" name="quarantine_enabled" value="1" <?php checked( $quarantine_enabled ); ?>>
									<span>
										<strong>Quarantine removed threats instead of deleting them</strong><br>
										<span class="description">Enabled by default. When auto-remediation removes a confirmed threat, it is moved to a hardened, non-executable store (recoverable for <?php echo (int) WPS_Quarantine::RETENTION_DAYS; ?> days from the Forensics tab) rather than destroyed  so a false positive can be restored and forensic evidence is preserved. Untick to permanently delete on removal.</span>
									</span>
								</label>
							</td>
						</tr>
					</table>
				</div>

				<div class="wps-card wps-card--pad-lg">
					<h2 class="wps-card-h">Blocking &amp; uploads</h2>
					<p class="wps-sm wps-muted wps-p">Front-door defences against hostile sources and upload paths.</p>
					<table class="form-table wps-p0">
						<tr>
							<th>Hostile IP blocking</th>
							<td>
								<label class="wps-toggle-row">
									<input type="checkbox" name="auto_ip_block_enabled" value="1" <?php checked( $auto_ip_block_enabled ); ?>>
									<span>
										<strong>Auto-block IPs that attempt known malware uploads</strong><br>
										<span class="description">Enabled by default. When an IP tries to upload a known malware filename or a renamed ZIP containing known malware folders, hashes, or payload markers, WP Perf Shield blocks future WordPress requests from that IP for 7 days and records the source in the event log.</span>
									</span>
								</label>
							</td>
						</tr>
						<tr>
							<th>Upload pathway guard</th>
							<td>
								<label class="wps-toggle-row">
									<input type="checkbox" name="strict_upload_gate_enabled" value="1" <?php checked( $strict_upload_gate_enabled ); ?>>
									<span>
										<strong>Restrict ZIP uploads to trusted admin routes</strong><br>
										<span class="description">Enabled by default. Blocks ZIP uploads unless they come from an administrator using normal WordPress upload screens such as plugin install, media upload, or async upload. Trusted routes are still inspected for known malware inside the ZIP.</span>
									</span>
								</label>
							</td>
						</tr>
					</table>
				</div>

				<div class="wps-card wps-card--pad-lg">
					<h2 class="wps-card-h">Appearance</h2>
					<p class="wps-sm wps-muted wps-p">Colour scheme for the WP Perf Shield screens only.</p>
					<table class="form-table wps-p0">
						<tr>
							<th><label for="wps_appearance">Colour scheme</label></th>
							<td>
								<select id="wps_appearance" name="appearance">
									<option value="auto"  <?php selected( $appearance, 'auto' ); ?>>Auto (follow system)</option>
									<option value="light" <?php selected( $appearance, 'light' ); ?>>Light (default)</option>
									<option value="dark"  <?php selected( $appearance, 'dark' ); ?>>Dark</option>
								</select>
								<p class="description">Auto follows the operating system's light or dark preference.</p>
							</td>
						</tr>
					</table>
				</div>

				<p class="wps-mt10"><button type="submit" class="button button-primary">Save settings</button></p>
			</form>

			<p class="description wps-mt10 wps-xs wps-dim">
				1.3.35 moved the operational reset buttons (Clear event log, Reset wp-config.php baseline, Clear hostile IP blocks) and the Diagnostics export panel to the tabs whose data they act on. Settings is now configuration only.
			</p>

		</div><!-- /settings tab -->
		<?php
	}
}
