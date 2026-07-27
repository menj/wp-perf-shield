<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Hardening tab renderer (Phase 3 split from class-admin.php).
 *
 * Renders the hardening checklist score, immediate-cleanup actions,
 * activation-blocker status, wp-config.php constants table, .htaccess
 * rule blocks table, salt rotation, and ongoing-monitoring summary.
 *
 * The two anonymous closures from the previous inline implementation
 * (`$badge` and `$applyBtn`) are now private static methods on this
 * class. Button IDs (wps-h-transients, wps-h-sessions, wps-h-salts,
 * wps-hc-*, wps-hh-*) and the data-wps-* attribute payload format are
 * unchanged so the admin JavaScript needs no edits.
 */
class WPS_Admin_Hardening {

	public static function render( array $context ): void {
		$hs = WPS_Hardening::get_status();
		$done = count( array_filter( $hs ) );
		$total = count( $hs );
		?>

		<div class="wps-tab">

			<!-- Status overview bar -->
			<div class="wps-mb10 wps-card wps-row">
				<div class="wps-strong wps-big <?php echo $done < $total ? 'wps-bad-t' : 'wps-good-t'; ?>"><?php echo $done; ?>/<?php echo $total; ?></div>
				<div>
					<div class="wps-strong wps-md">Hardening checklist</div>
					<div class="wps-sm wps-muted"><?php echo ( $total - $done ); ?> item<?php echo ( $total - $done ) !== 1 ? 's' : ''; ?> not yet applied</div>
				</div>
			</div>

			<!-- Section 1: Immediate cleanup -->
			<div class="wps-card">
				<div class="wps-card-head">
					<span class="wps-num-dot wps-num-dot--bad">1</span>
					<strong class="wps-md">Immediate cleanup</strong>
					<span class="wps-badge wps-badge--bad wps-upper">Critical</span>
				</div>
				<table class="wps-table wps-table--md">
					<tr>
						<td class="wps-muted" style="width:200px">Malware plugin scan</td>
						<td><?php echo $hs['wps_scanner'] ? '<span class="wps-good-t wps-sm">Scanner active</span>' : '<span class="wps-bad-t wps-sm">Scanner not loaded</span>'; ?></td>
						<td class="wps-right"><a href="<?php echo esc_url( admin_url( 'tools.php?page=wp-perf-shield&tab=overview' ) ); ?>" class="button wps-sm">Open Overview</a></td>
					</tr>
					<tr>
						<td>Clear all transients &amp; object cache</td>
						<td class="wps-sm wps-muted">Malware sets cookie/transient suppressors; flush removes them.</td>
						<td class="wps-right"><?php echo self::apply_btn( 'wps-h-transients', 'Clear transients', 'wps_clear_transients' ); ?></td>
					</tr>
					<tr>
						<td>Invalidate all user sessions</td>
						<td class="wps-sm wps-muted">Forces every logged-in user to re-authenticate</td>
						<td class="wps-right"><?php echo self::apply_btn( 'wps-h-sessions', 'Invalidate sessions', 'wps_invalidate_sessions', [], true ); ?></td>
					</tr>
				</table>
			</div>

			<!-- Section 2: wp-config.php hardening (1.3.35: was Section 3; old Section 2 was info-only and removed) -->
			<div class="wps-card">
				<div class="wps-card-head">
					<span class="wps-num-dot wps-num-dot--warn">2</span>
					<strong class="wps-md">wp-config.php hardening</strong>
					<span class="wps-badge wps-badge--warn wps-upper">High</span>
				</div>
				<p class="wps-sm wps-muted wps-p">These constants are added directly to wp-config.php. A backup is created at <code>wp-config.php.wps.bak</code> before any change.</p>
				<table class="wps-table wps-table--md">
					<?php
					$constants = [
						'DISALLOW_FILE_MODS' => [
							'label' => 'DISALLOW_FILE_MODS',
							'desc' => 'Locks out all plugin/theme installs and auto-updates via admin UI. Use WP-CLI to update while this is on.',
						],
						'DISALLOW_FILE_EDIT' => [
							'label' => 'DISALLOW_FILE_EDIT',
							'desc' => 'Disables the built-in admin code editor. No downside; safe to always enable.',
						],
						'FORCE_SSL_ADMIN' => [
							'label' => 'FORCE_SSL_ADMIN',
							'desc' => 'Forces HTTPS on all admin and login pages.',
						],
					];
					foreach ( $constants as $key => $meta ) :
						$is_on = $hs[ $key ];
						?>
					<tr>
						<td class="wps-mono wps-sm" style="width:210px"><?php echo esc_html( $meta['label'] ); ?></td>
						<td><?php echo self::badge( $is_on ); ?></td>
						<td class="wps-sm wps-muted"><?php echo esc_html( $meta['desc'] ); ?></td>
						<td class="wps-right wps-nowrap">
							<?php if ( ! $is_on ) : ?>
							<?php echo self::apply_btn(
								'wps-hc-' . strtolower( $key ),
								'Apply',
								'wps_wpconfig_constant',
								[ 'constant' => $key, 'enable' => '1' ],
								true
							); ?>
							<?php else : ?>
							<span class="wps-xs wps-dim">No action needed</span>
							<?php endif; ?>
						</td>
					</tr>
					<?php endforeach; ?>
				</table>
				<div class="wps-sm wps-mt10 wps-note wps-note--amber">
					<strong>Trade-off for DISALLOW_FILE_MODS:</strong> plugin and theme updates must be done via WP-CLI (<code>wp plugin update --all</code>) or SFTP while this constant is active.
				</div>

				<!-- 1.3.35: Reset baseline button moved here from Settings  Danger Zone. -->
				<div class="wps-note wps-note--warn wps-mt8">
					<strong>Baseline:</strong> WP Perf Shield stores a SHA-256 of wp-config.php and flags any subsequent modification as a finding. After an intentional edit (adding a constant, rotating credentials, etc.), reset the stored baseline so the next scan does not flag the new content. This action stores the current file hash as the new clean state; it does not modify wp-config.php.
					<p class="wps-mt8">
						<button id="wps-rebaseline-btn" class="button wps-btn-danger"><span class="wps-icon dashicons dashicons-lock" aria-hidden="true"></span>Reset wp-config.php baseline</button>
					</p>
				</div>

				<!-- 1.3.71: drop-in integrity baseline reset. -->
				<div class="wps-note wps-note--warn wps-mt8">
					<strong>Drop-in baseline:</strong> WP Perf Shield baselines the wp-content drop-ins (db.php, object-cache.php, advanced-cache.php, sunrise.php, maintenance.php, and the rest) and flags any creation, modification, or removal against that baseline, logging the moment it happens. After an intentional change (enabling a cache plugin, switching object cache, etc.), reset this baseline so the new state becomes the clean reference. This action does not modify any drop-in file.
					<p class="wps-mt8">
						<button id="wps-rebaseline-dropins-btn" class="button wps-btn-danger"><span class="wps-icon dashicons dashicons-lock" aria-hidden="true"></span>Reset drop-in baseline</button>
					</p>
				</div>

				<!-- 1.3.87: PHP-inventory drift baseline reset. -->
				<div class="wps-note wps-note--warn wps-mt8">
					<strong>PHP-inventory baseline:</strong> WP Perf Shield records the PHP files present in <code>uploads</code> and <code>mu-plugins</code> and, on every scan, flags any PHP file that has appeared or changed since that baseline &mdash; regardless of what the file contains. This is the early-warning tripwire for a new strain dropping code into those directories before it is catalogued. It establishes itself on the first scan and only reports drift afterwards, so reset it after a confirmed cleanup so the current clean set becomes the new reference. This action does not modify any file.
					<p class="wps-mt8">
						<button id="wps-rebaseline-php-inventory-btn" class="button wps-btn-danger"><span class="wps-icon dashicons dashicons-lock" aria-hidden="true"></span>Reset PHP-inventory baseline</button>
					</p>
				</div>
			</div>

			<!-- Section 3: .htaccess rules (1.3.35: was Section 4) -->
			<div class="wps-card">
				<div class="wps-card-head">
					<span class="wps-num-dot wps-num-dot--info">3</span>
					<strong class="wps-md">.htaccess hardening (Apache)</strong>
					<span class="wps-badge wps-badge--warn wps-upper">High</span>
				</div>
				<p class="wps-sm wps-muted wps-p">Rules are inserted via WordPress marker blocks the same mechanism used for WP's own rewrite rules. Nginx users must apply these rules manually via server config.</p>
				<table class="wps-table wps-table--md">
					<?php
					$htaccess_items = [
						'php_uploads' => [
							'label' => 'Block PHP execution in uploads/',
							'desc' => 'Kills any PHP backdoor dropped into wp-content/uploads/ via file upload exploit.',
							'rule' => 'php_uploads',
						],
						'xmlrpc' => [
							'label' => 'Block direct access to xmlrpc.php',
							'desc' => 'Cuts off the most common brute-force and malware-upload vector. Disable only if you use Jetpack or mobile apps that require XML-RPC.',
							'rule' => 'xmlrpc',
						],
						'perf_analytics' => [
							'label' => 'Block ClickFix plugin folder patterns',
							'desc' => 'Regex blocks HTTP access to known ClickFix plugin folders including wp-perf-analytics, native-render-toolkit, total-render-profiler, total-render-toolkit, pro-font-optimizer, site-speed-insights, advanced-asset-insights, page-seo-toolkit, and starter-image-guard suffix variants.',
							'rule' => 'perf_analytics',
						],
					];
					foreach ( $htaccess_items as $key => $item ) :
						$is_on = $hs[ $key ];
						?>
					<tr>
						<td style="width:260px"><?php echo esc_html( $item['label'] ); ?></td>
						<td><?php echo self::badge( $is_on ); ?></td>
						<td class="wps-sm wps-muted"><?php echo esc_html( $item['desc'] ); ?></td>
						<td class="wps-right wps-nowrap">
							<?php if ( ! $is_on ) : ?>
							<?php echo self::apply_btn(
								'wps-hh-' . $key,
								'Apply',
								'wps_htaccess_rule',
								[ 'rule' => $item['rule'], 'enable' => '1' ],
								true
							); ?>
							<?php else : ?>
							<?php echo self::apply_btn(
								'wps-hh-' . $key . '-rm',
								'Remove',
								'wps_htaccess_rule',
								[ 'rule' => $item['rule'], 'enable' => '0' ]
							); ?>
							<?php endif; ?>
						</td>
					</tr>
					<?php endforeach; ?>
				</table>
				<div class="wps-sm wps-mt10 wps-note wps-note--good">
					<strong>Important:</strong> .htaccess rules block HTTP access only. WordPress loads plugins via PHP <code>require_once()</code> internally, so these rules have no effect on that path. Malware plugin folders must still be physically deleted.
				</div>
			</div>

			<!-- Section 3b: Content-Security-Policy (1.3.76) -->
			<?php
			$csp_mode    = WPS_Csp::get_mode();
			$csp_policy  = WPS_Csp::get_policy();
			$csp_reports = WPS_Csp::get_reports();
			?>
			<div class="wps-card">
				<div class="wps-card-head">
					<span class="wps-num-dot">3b</span>
					<strong class="wps-md">Content-Security-Policy (anti-ClickFix)</strong>
					<span class="wps-badge wps-upper">Advanced</span>
				</div>
				<p class="wps-sm wps-muted wps-p">
					A CSP can stop the injected ClickFix script from reaching its C2 or a Binance Smart Chain node even on an already-infected page (the <code>connect-src</code> directive), and adds low-risk hardening via <code>object-src</code>, <code>base-uri</code>, and <code>frame-ancestors</code>. It is also the easiest way to break a site, so start in <strong>Report-only</strong>: the browser blocks nothing and just posts violations below, letting you see what would break (and spot the malware's outbound calls) before enforcing.
				</p>
				<p class="wps-sm wps-muted wps-p">
					The default policy is permissive for inline script and style (so WordPress keeps working) and strict only where it is safe and useful. <code>connect-src 'self'</code> will report every external connection, including your own analytics and fonts; widen it to your legitimate third parties from the reports <em>before</em> switching to Enforce. CSP is emitted on front-end pages only, never in wp-admin.
				</p>

				<p class="wps-p">
					<label><input type="radio" name="wps-csp-mode" value="off" <?php checked( $csp_mode, 'off' ); ?>> Off</label>
					<label><input type="radio" name="wps-csp-mode" value="report" <?php checked( $csp_mode, 'report' ); ?>> Report-only <span class="wps-good-t">(recommended)</span></label>
					<label><input type="radio" name="wps-csp-mode" value="enforce" <?php checked( $csp_mode, 'enforce' ); ?>> Enforce <span class="wps-bad-t">(can break the site if untuned)</span></label>
				</p>

				<textarea id="wps-csp-policy" rows="5" class="wps-mono wps-sm" style="width:100%" spellcheck="false"><?php echo esc_textarea( $csp_policy ); ?></textarea>
				<p class="wps-mt8">
					<button id="wps-csp-save-btn" class="button button-primary">Save CSP settings</button>
					<button id="wps-csp-default-btn" class="button" type="button">Reset to default policy</button>
					<span id="wps-csp-msg" class="wps-sm wps-ml10"></span>
				</p>
				<p class="wps-xs wps-dim wps-mt8">The plugin appends its own <code>report-uri</code> automatically; do not add one. Do not put line breaks in the policy.</p>

				<div class="wps-hr-top">
					<div class="wps-between wps-mb6">
						<strong>Recent violation reports (<?php echo count( $csp_reports ); ?>)</strong>
						<button id="wps-csp-clear-btn" class="button-link wps-muted wps-sm">Clear reports</button>
					</div>
					<?php if ( empty( $csp_reports ) ) : ?>
						<p class="wps-sm wps-dim wps-p0">No reports yet. Enable Report-only, then visit the front end (or wait for traffic). A blocked-uri pointing at a host you do not recognise is the malware's callback; a host you do recognise is something to add to <code>connect-src</code> before enforcing.</p>
					<?php else : ?>
						<div class="wps-scroll-y300">
						<table class="wps-xs wps-table">
							<thead><tr>
								<th>Time (<?php echo esc_html( WPS_Utils::timezone_label() ); ?>)</th>
								<th>Directive</th>
								<th>Blocked URI</th>
								<th>Source</th>
							</tr></thead>
							<tbody>
							<?php foreach ( $csp_reports as $rep ) : ?>
								<tr>
									<td class="wps-nowrap"><?php echo esc_html( (string) ( $rep['time'] ?? '' ) ); ?></td>
									<td><code><?php echo esc_html( (string) ( $rep['directive'] ?? '' ) ); ?></code></td>
									<td class="wps-break"><?php echo esc_html( (string) ( $rep['blocked'] ?? '' ) ); ?></td>
									<td class="wps-break"><?php echo esc_html( (string) ( $rep['source'] ?? '' ) ); ?><?php echo ! empty( $rep['line'] ) ? esc_html( ':' . $rep['line'] ) : ''; ?></td>
								</tr>
							<?php endforeach; ?>
							</tbody>
						</table>
						</div>
					<?php endif; ?>
				</div>
			</div>

			<!-- Section 4: Auth salt rotation (1.3.35: was Section 5) -->
			<div class="wps-card">
				<div class="wps-card-head">
					<span class="wps-num-dot">4</span>
					<strong class="wps-md">Auth salt rotation</strong>
					<span class="wps-badge wps-upper">Medium</span>
				</div>
				<p class="wps-sm wps-muted wps-p">Replaces all eight WordPress auth salts in wp-config.php with freshly generated values from api.wordpress.org. Immediately invalidates every existing session; all users must log in again. Run this after any confirmed credential compromise.</p>
				<?php echo self::apply_btn(
					'wps-h-salts',
					'Regenerate auth salts',
					'wps_regenerate_salts',
					[],
					true
				); ?>
			</div>

			<!-- 1.3.35: status div for the moved Reset baseline button (uses the
			     existing wps_rebaseline_wpconfig handler in admin.js, which
			     writes to #wps-settings-msg). Old Section 2 (activation-blocker
			     status), Section 6 (ongoing-monitoring summary), and the
			     root-cause reminder have moved to doc/upgrading.md. -->
			<div id="wps-settings-msg" class="wps-status wps-mt8"></div>

		</div><!-- /hardening tab -->
		<?php
	}

	private static function badge( bool $ok ): string {
		return $ok
			? '<span class="wps-good-t wps-strong wps-sm">Applied</span>'
			: '<span class="wps-bad-t wps-strong wps-sm">Not applied</span>';
	}

	private static function apply_btn( string $id, string $label, string $action, array $params = [], bool $confirm = false ): string {
		return '<span class="wps-hardening-actions">'
			. '<button id="' . esc_attr( $id ) . '" class="button wps-hardening-action wps-sm"'
			. ' data-wps-label="' . esc_attr( $label ) . '"'
			. ' data-wps-action="' . esc_attr( $action ) . '"'
			. ' data-wps-payload="' . esc_attr( wp_json_encode( $params ) ) . '"'
			. ' data-wps-confirm="' . ( $confirm ? '1' : '0' ) . '">'
			. esc_html( $label ) . '</button>'
			. '<span id="' . esc_attr( $id ) . '-msg" class="wps-action-status" aria-live="polite"></span>'
			. '</span>';
	}
}
