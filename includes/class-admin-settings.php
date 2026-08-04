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
							<th><label for="xmlrpc_strip_multicall">XML-RPC multicall</label></th>
							<td>
								<label class="wps-toggle-row">
									<input type="checkbox" id="xmlrpc_strip_multicall" name="xmlrpc_strip_multicall" value="1" <?php checked( ( $settings['xmlrpc_strip_multicall'] ?? '1' ) !== '0' ); ?>>
									<span>
										<strong>Strip <code>system.multicall</code> from XML-RPC</strong><br>
										<span class="description">Removes the one method that lets a single request carry many credential guesses at once, while leaving normal XML-RPC sign-in working. On by default and safe to leave on: Jetpack and the mobile apps use direct methods, not multicall. Turn it off only if a tool you rely on batches calls through <code>system.multicall</code> on purpose.</span>
									</span>
								</label>
							</td>
						</tr>
						<tr>
							<th><label for="post_guard_enabled">External post writing</label></th>
							<td>
								<label class="wps-toggle-row">
									<input type="checkbox" id="post_guard_enabled" name="post_guard_enabled" value="1" <?php checked( ( $settings['post_guard_enabled'] ?? '0' ) === '1' ); ?>>
									<span>
										<strong>Block external post creation, editing and deletion</strong><br>
										<span class="description">Refuses writes to the posts REST routes (<code>/wp/v2/posts</code>) and unregisters the post-writing XML-RPC methods, unless the request is a genuine administrator dashboard session &ndash; a test an Application Password, Basic Auth, JWT, OAuth or an unauthenticated bot cannot pass. This is the injection route behind auto-blogging and doorway/SEO-spam posts. Dashboard publishing (Gutenberg, Classic Editor) and scheduled posts are unaffected, and blocked attempts are logged. <strong>Off by default</strong>, because it will break headless WordPress, mobile-app posting, and Zapier/IFTTT-style integrations that publish through the API &ndash; turn it on only if nothing legitimately posts to this site from outside the dashboard.</span>
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
							<th><label for="akismet_report_all_blocks">Report every blocked address</label></th>
							<td>
								<label class="wps-toggle-row">
									<input type="checkbox" id="akismet_report_all_blocks" name="akismet_report_all_blocks" value="1" <?php checked( ( $settings['akismet_report_all_blocks'] ?? '1' ) !== '0' ); ?>>
									<span>
										<strong>Report every blocked address, not only the conclusive ones</strong><br>
										<span class="description">Extends the setting above so that <em>any</em> address the login guard blocks is reported &ndash; including a first-offence block on a single username, the case otherwise held back as a possible mistyped password &ndash; and so that when a rotating range is blocked, the individual addresses that actually attacked from it are reported (never the whole range, which would flag innocent neighbours). <strong>On by default, at the operator's instruction.</strong> Be aware this is more aggressive: a wrongly-blocked address is then flagged for every site using Akismet. The two safeguards above still hold &ndash; a CDN or proxy address is never auto-reported, and each address is reported at most once. Turn this off to report only addresses proven to be attacking. Requires "Report attackers to Akismet" above to be on.</span>
									</span>
								</label>
							</td>
						</tr>
						<tr>
							<th><label for="akismet_enrichment">Ask Akismet about attackers</label></th>
							<td>
								<label class="wps-toggle-row">
									<input type="checkbox" id="akismet_enrichment" name="akismet_enrichment" value="1" <?php checked( ( $settings['akismet_enrichment'] ?? '1' ) !== '0' ); ?>>
									<span>
										<strong>Consult Akismet when deciding how long to block an address</strong><br>
										<span class="description">The opposite direction to the setting above: this asks Akismet whether an address is already known for abuse, and lengthens the block if it is. Nothing about your site is contributed by this &ndash; it is a question, not a report &ndash; so you can leave it on while turning reporting off, or the reverse. <strong>On by default.</strong> Your own site's evidence always sets the baseline duration; Akismet can only extend it, never shorten it. Requires an active Akismet key.</span>
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
					<h2 class="wps-card-h">Banned plugins</h2>
					<p class="wps-sm wps-muted wps-p">Ordinary plugins &mdash; not malware &mdash; that this site refuses to run. A banned plugin cannot be uploaded or activated while WP Perf Shield is active, and is deactivated on sight if it is already running. Every refusal is recorded as a policy decision, and the uploader's address is never added to the hostile-IP list for it.</p>
					<table class="form-table wps-p0">
						<tr>
							<th>Enforce the banned list</th>
							<td>
								<label class="wps-toggle-row">
									<input type="checkbox" name="policy_ban_enabled" value="1" <?php checked( ( $settings['policy_ban_enabled'] ?? '1' ) !== '0' ); ?>>
									<span>
										<strong>Refuse banned plugins on upload and activation</strong><br>
										<span class="description">On by default. Two plugins ship banned out of the box: <code>wp-file-manager</code> (WP File Manager &ndash; full dashboard filesystem access, with a history of critical remote-code-execution holes) and <code>filebird</code> (FileBird). Untick to switch the whole list off without clearing it.</span>
									</span>
								</label>
							</td>
						</tr>
						<tr>
							<th><label for="policy_banned_slugs">Additional banned slugs</label></th>
							<td>
								<textarea id="policy_banned_slugs" name="policy_banned_slugs" rows="3" class="wps-mono wps-sm"><?php echo esc_textarea( (string) ( $settings['policy_banned_slugs'] ?? '' ) ); ?></textarea>
								<p class="description">One plugin folder slug per line, added to the two built-in bans above. Any plugin whose folder name contains one of these is refused. Leave this empty to ban only the two defaults.</p>
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

				<div class="wps-card wps-card--pad-lg">
					<h2 class="wps-card-h">Public identification</h2>
					<p class="wps-sm wps-muted wps-p">Whether an anonymous visitor can tell that this site runs WP Perf Shield. Off by default, and nothing else about the plugin is visible on the front end.</p>
					<table class="form-table wps-p0">
						<tr>
							<th><label for="public_marker">Identify the plugin publicly</label></th>
							<td>
								<label class="wps-toggle-row">
									<input type="checkbox" id="public_marker" name="public_marker" value="1" <?php checked( ( $settings['public_marker'] ?? '0' ) === '1' ); ?>>
									<span>
										<strong>Add a generator meta tag to front-end pages</strong><br>
										<span class="description">Emits <code>&lt;meta name="generator" content="WP Perf Shield" /&gt;</code> so technology profilers such as Wappalyzer and BuiltWith can recognise the plugin. The version number is deliberately never included: releases regularly close specific evasion techniques, so publishing which one you run would tell an attacker which bypasses still work against this site. Leaving this off means an attacker cannot tell from the outside what is watching. Turning it on trades a little of that for visibility.</span>
									</span>
								</label>
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
