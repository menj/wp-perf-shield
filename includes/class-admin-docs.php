<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Documentation tab renderer (1.4.2).
 *
 * Renders the plugin's own bundled markdown documentation inside the admin so
 * the changelog, upgrade notes, and reference material are readable without
 * leaving WordPress or opening files over FTP.
 *
 * Security posture, which matters more here than in a normal docs viewer
 * because this plugin's threat model explicitly assumes an attacker who
 * already has file access:
 *
 * - The document to show is chosen from a fixed WHITELIST keyed by slug. No
 *   path from the request ever reaches the filesystem, so there is no
 *   traversal surface regardless of what is submitted.
 * - Parsedown runs in safe mode, so raw HTML in a markdown file is escaped
 *   rather than emitted, and javascript: URLs are neutralised.
 * - The rendered HTML is then passed through wp_kses_post() as a second,
 *   independent layer. If a doc file were tampered with to inject admin XSS,
 *   it has to defeat both.
 * - Rendering is cached against a fingerprint of the file's size and mtime,
 *   so a modified file re-renders immediately rather than serving stale
 *   output, and the 300 KB changelog is parsed once rather than per page load.
 *
 * Doc files also joined the plugin's self-integrity baseline in this release,
 * so tampering with them is reported by the scanner as well as contained here.
 */
class WPS_Admin_Docs {

	/**
	 * Cache lifetime for rendered markdown, in seconds (one day). Deliberately
	 * a literal rather than DAY_IN_SECONDS: a class constant that depends on a
	 * WordPress constant fatals if this class is ever loaded before core
	 * constants exist, and a docs viewer must never be able to take down the
	 * admin. The fingerprint invalidates earlier whenever the file changes.
	 */
	private const CACHE_TTL = 86400;

	/** Refuse to parse anything larger than this; offer the raw view instead. */
	private const MAX_RENDER_BYTES = 2097152; // 2 MiB

	/**
	 * The whitelist. Slug => [ relative file, label, blurb ].
	 * Relative paths are resolved against WPS_DIR and re-checked with realpath.
	 *
	 * @return array<string, array<string, string>>
	 */
	public static function documents(): array {
		return [
			'readme'    => [
				'file'  => 'doc/readme.md',
				'label' => 'Readme',
				'blurb' => 'What the plugin is, what it detects, and how the pieces fit together.',
			],
			'upgrading' => [
				'file'  => 'doc/upgrading.md',
				'label' => 'Upgrading',
				'blurb' => 'What changes at upgrade time, release by release - read this before updating.',
			],
			'changelog' => [
				'file'  => 'doc/changelog.md',
				'label' => 'Changelog',
				'blurb' => 'Every release: why it happened, what changed, and how it was verified.',
			],
			'roadmap'   => [
				'file'  => 'doc/remediation-roadmap.md',
				'label' => 'Remediation roadmap',
				'blurb' => 'Current state of the security review programme: what is fixed, what is open, and what to do next.',
			],
			'variants'  => [
				'file'  => 'doc/variants.md',
				'label' => 'Variant catalogue',
				'blurb' => 'Every malware family WP Perf Shield recognises: mechanism, indicators, detection, and what stops it.',
			],
			'ssot'      => [
				'file'  => 'doc/ssot.md',
				'label' => 'Reference (SSOT)',
				'blurb' => 'The single source of truth: architecture decisions, detection rationale, and the roadmap.',
			],
		];
	}

	/** Resolve a slug to an absolute path inside WPS_DIR, or null. Never accepts a path. */
	private static function resolve( string $slug ): ?string {
		$docs = self::documents();
		if ( ! isset( $docs[ $slug ] ) ) {
			return null;
		}
		$path = WPS_DIR . $docs[ $slug ]['file'];
		$real = realpath( $path );
		$root = realpath( WPS_DIR );
		if ( ! $real || ! $root ) {
			return null;
		}
		// Belt and braces: the resolved file must still sit inside the plugin.
		if ( ! WPS_Utils::path_is_inside( $real, $root ) ) {
			return null;
		}
		return is_readable( $real ) ? $real : null;
	}

	/**
	 * Render markdown to sanitised HTML, cached against the file's fingerprint.
	 *
	 * @return array{html:string, note:string}
	 */
	private static function render_markdown( string $path ): array {
		// PHP caches stat results per request, so a file modified during this
		// request (a plugin upgrade writing new docs, say) would otherwise be
		// fingerprinted from stale size/mtime values and served from a cache
		// entry that no longer matches the file on disk.
		clearstatcache( true, $path );

		$size = (int) @filesize( $path );
		$note = '';

		if ( $size > self::MAX_RENDER_BYTES ) {
			return [
				'html' => '',
				'note' => 'This document is ' . size_format( $size ) . ', which is larger than the ' . size_format( self::MAX_RENDER_BYTES ) . ' render limit. Open it directly from the plugin folder instead.',
			];
		}

		$fingerprint = md5( $path . '|' . $size . '|' . (int) @filemtime( $path ) . '|' . WPS_VERSION );
		$cache_key   = 'wps_doc_' . substr( $fingerprint, 0, 24 );
		$cached      = get_transient( $cache_key );
		if ( is_string( $cached ) && $cached !== '' ) {
			return [ 'html' => $cached, 'note' => '' ];
		}

		$raw = @file_get_contents( $path );
		if ( $raw === false ) {
			return [ 'html' => '', 'note' => 'The file could not be read. Check file permissions in the plugin directory.' ];
		}

		if ( ! class_exists( 'WPS_Parsedown' ) ) {
			return [
				'html' => '<pre class="wps-doc-raw">' . esc_html( $raw ) . '</pre>',
				'note' => 'The markdown renderer is unavailable, so the raw source is shown instead.',
			];
		}
		if ( ! extension_loaded( 'mbstring' ) ) {
			// Parsedown 1.8 needs mbstring; degrade to readable plain text
			// rather than risking mangled output or a fatal.
			return [
				'html' => '<pre class="wps-doc-raw">' . esc_html( $raw ) . '</pre>',
				'note' => 'The PHP mbstring extension is not installed, so the raw source is shown instead of formatted documentation.',
			];
		}

		try {
			$parser = new WPS_Parsedown();
			$parser->setSafeMode( true );      // escape raw HTML, neutralise javascript: URLs
			$parser->setBreaksEnabled( false );
			$html = (string) $parser->text( $raw );
		} catch ( \Throwable $e ) {
			return [
				'html' => '<pre class="wps-doc-raw">' . esc_html( $raw ) . '</pre>',
				'note' => 'The document could not be formatted, so the raw source is shown instead.',
			];
		}

		// Second, independent layer: even with safe mode on, nothing reaches the
		// page without passing WordPress's own post-content filter.
		$html = wp_kses_post( $html );

		set_transient( $cache_key, $html, self::CACHE_TTL );
		return [ 'html' => $html, 'note' => $note ];
	}

	public static function render( array $context ): void {
		$docs = self::documents();

		$slug = isset( $_GET['doc'] ) ? sanitize_key( wp_unslash( $_GET['doc'] ) ) : 'readme';
		if ( ! isset( $docs[ $slug ] ) ) {
			$slug = 'readme';
		}

		$path = self::resolve( $slug );
		?>
		<div class="wps-card">
			<div class="wps-card-head">
				<span class="wps-strong wps-md">Documentation</span>
				<span class="wps-sm wps-dim wps-ml10">Bundled with this release (v<?php echo esc_html( WPS_VERSION ); ?>) - no internet connection needed</span>
			</div>

			<div class="wps-doc-nav">
				<?php foreach ( $docs as $key => $doc ) :
					$url = add_query_arg(
						[ 'page' => 'wp-perf-shield', 'tab' => 'docs', 'doc' => $key ],
						admin_url( 'admin.php' )
					);
					?>
					<a class="wps-doc-navlink<?php echo $key === $slug ? ' is-active' : ''; ?>"
					   href="<?php echo esc_url( $url ); ?>">
						<span class="wps-strong"><?php echo esc_html( $doc['label'] ); ?></span>
						<span class="wps-xs wps-dim"><?php echo esc_html( $doc['blurb'] ); ?></span>
					</a>
				<?php endforeach; ?>
			</div>

			<?php if ( $path === null ) : ?>
				<p class="wps-note wps-note--bad">
					<?php echo esc_html( $docs[ $slug ]['file'] ); ?> is missing from the plugin directory or is not readable.
					Re-upload the release to restore it - the scanner also reports missing plugin files as a self-integrity finding.
				</p>
			<?php else :
				$rendered = self::render_markdown( $path );
				?>
				<?php if ( $rendered['note'] !== '' ) : ?>
					<p class="wps-note wps-note--warn wps-sm"><?php echo esc_html( $rendered['note'] ); ?></p>
				<?php endif; ?>

				<?php if ( $rendered['html'] !== '' ) : ?>
					<div class="wps-doc">
						<?php
						// Already sanitised twice above: Parsedown safe mode, then
						// wp_kses_post. Escaping again here would print tags.
						echo $rendered['html']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
						?>
					</div>
				<?php endif; ?>

				<p class="wps-xs wps-dim wps-mt8">
					Source: <code><?php echo esc_html( 'wp-perf-shield/' . $docs[ $slug ]['file'] ); ?></code>
					- <?php echo esc_html( size_format( (int) @filesize( $path ) ) ); ?>,
					rendered with markdown safe mode and filtered through the WordPress content sanitiser.
				</p>
			<?php endif; ?>
		</div>
		<?php
	}
}
