<?php
/**
 * Spam content guard (1.4.101).
 *
 * Ported from a standalone emergency mu-plugin ("REST Lockdown") a site
 * operator had already hand-deployed, whose own log shows it working: over
 * one week it blocked 11 gambling/casino-spam posts at the point of REST
 * insertion, stripped injected content from several more at the save
 * boundary as a second-layer catch, and a daily cleanup cron retroactively
 * quarantined the handful that still slipped through - all cross-checked
 * against the same spam posts recovered independently from that site's
 * access logs (matching post IDs, matching timestamps).
 *
 * This is content-based, not behavioural, and that is a real trade-off
 * against WPS_Account_Guard's approach: a keyword/link-pattern scanner can
 * misfire on a site that legitimately discusses gambling (addiction
 * recovery content, gambling-law journalism, a games-industry blog) and can
 * be evaded by an attacker who simply avoids the specific vocabulary this
 * checks for. WPS_Account_Guard's rapid-write/new-device check has neither
 * problem, which is why it is the primary defence and is on by default.
 * This module is a narrower, content-specific second layer for one spam
 * vertical, kept OFF by default for that reason - turn it on if this
 * category of spam is actually what a site is fighting.
 *
 * Two layers, matching the source mu-plugin's design:
 *   1. REST insertion time (rest_pre_insert_post/page): reject the write
 *      outright with a 403, before anything is saved.
 *   2. Save boundary (wp_insert_post_data): a second, unconditional catch
 *      for anything that reached save() by another path (Classic Editor,
 *      an XML-RPC method WPS_Post_Guard has not unregistered, a different
 *      plugin's own insert call) - strips the matched markup rather than
 *      rejecting the whole save, so a legitimate post that happens to
 *      quote or reference such a link elsewhere is not lost outright.
 */

defined( 'ABSPATH' ) || exit;

final class WPS_Spam_Content_Guard {

	private const RULES = [
		'gambling-link'    => '/<a\b[^>]*href\s*=\s*["\'][^"\']*(?:casino|bet|bets|betting|gambl|slot|poker|jackpot|roulette|blackjack|kasyno|casin[oò]|aams|cruks)[^"\']*["\'][^>]*>/i',
		'gambling-anchor'  => '/<a\b[^>]*>[^<]*(?:casino|betting|gambling|jackpot|roulette|blackjack|poker|slots?|kasyno|kasyna|casin[oò]|AAMS|CRUKS)\b[^<]*<\/a>/is',
		'hidden-gambling'  => '/(?:left\s*:\s*-\s*\d+px|top\s*:\s*-\s*\d+px|display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px)?|opacity\s*:\s*0)[^>]*>.*?(?:casino|betting|gambling|jackpot|roulette|blackjack|poker|slots?)/is',
		// 1.4.102: two live, confirmed spam posts on the same site this
		// scanner was built for used no English gambling vocabulary at all
		// ("Come scegliere i migliori siti non AAMS...", "...Zonder CRUKS
		// Registratie Voor Nederlandse Spelers") - a pure English keyword
		// list was always going to miss non-English variants of the same
		// campaign. Added the multilingual stems actually seen (Polish
		// kasyno/kasyna, Italian casinò/AAMS, Dutch CRUKS) to the cluster
		// and anchor/link rules above, still gated by the same "2+ hits or
		// an actual link" requirement below - single mentions still don't
		// trigger this rule on their own.
		'gambling-cluster' => '/\b(?:casino|casinos|casin[oò]|kasyno|kasyna|betting|sportsbook|jackpot|roulette|blackjack|poker|slots?|wager|odds|bookmaker|bookie|buchmacher|wettangebote|gambling|bet\s+online|online\s+casino|AAMS|CRUKS)\b/i',
		// New: the regulatory-evasion ANGLE itself, not just gambling
		// vocabulary - "site NOT registered with the national gambling
		// regulator" is the actual pitch of every post in this campaign
		// (AAMS = Italy, CRUKS = Netherlands, Oasis = Germany's
		// self-exclusion register). These are compound, gambling-specific
		// regulatory terms with essentially no legitimate use on a site
		// that isn't about gambling regulation itself, so - unlike
		// gambling-cluster above - a single hit is enough; no 2+/link gate.
		'gambling-regulatory-evasion' => '/\b(?:non[\s-]+AAMS|senza[\s-]+AAMS|AAMS[\s-]*(?:free|escl)|ohne[\s-]+Oasis|zonder[\s-]+CRUKS|CRUKS[\s-]*(?:vrij|registratie))\b/i',
	];

	public static function register_hooks(): void {
		if ( ! self::enabled() ) {
			return;
		}
		add_filter( 'rest_pre_insert_post', [ __CLASS__, 'scan_rest_insert' ], 10, 2 );
		add_filter( 'rest_pre_insert_page', [ __CLASS__, 'scan_rest_insert' ], 10, 2 );
		add_filter( 'wp_insert_post_data', [ __CLASS__, 'scan_save_boundary' ], 10, 2 );

		add_action( 'wps_spam_content_daily_sweep', [ __CLASS__, 'sweep_existing' ] );
		if ( ! wp_next_scheduled( 'wps_spam_content_daily_sweep' ) ) {
			wp_schedule_event( time() + 3 * HOUR_IN_SECONDS, 'daily', 'wps_spam_content_daily_sweep' );
		}
	}

	/** Off by default - see the class docblock for why. */
	public static function enabled(): bool {
		$s = get_option( WPS_OPTION, [] );
		return is_array( $s ) && ( $s['spam_content_guard_enabled'] ?? '0' ) === '1';
	}

	private static function post_types(): array {
		return apply_filters( 'wps_spam_content_guard_post_types', [ 'post', 'page' ] );
	}

	/** @return string|false The matched rule name, or false if nothing matched. */
	private static function match( string $text ) {
		$text = html_entity_decode( $text, ENT_QUOTES | ENT_HTML5, 'UTF-8' );
		foreach ( self::RULES as $name => $regex ) {
			if ( ! preg_match( $regex, $text ) ) {
				continue;
			}
			if ( 'gambling-cluster' === $name ) {
				// Weakest rule on its own - a single passing mention (a news
				// piece, a policy page) is not spam. Require either a second
				// hit or an actual link before this one counts.
				$hits = preg_match_all(
					'/\b(?:casino|betting|sportsbook|jackpot|roulette|blackjack|poker|slots?|wager|bookmaker|gambling)\b/i',
					$text
				);
				if ( $hits < 2 && ! preg_match( '/<a\b[^>]+href\s*=/i', $text ) ) {
					continue;
				}
			}
			return $name;
		}
		return false;
	}

	private static function strip( string $content ): string {
		$patterns = [
			'/<a\b[^>]*href\s*=\s*["\'][^"\']*(?:casino|bet|bets|betting|gambl|slot|poker|jackpot|roulette|blackjack)[^"\']*["\'][^>]*>.*?<\/a>/is',
			'/<([a-z0-9]+)\b[^>]*style\s*=\s*["\'][^"\']*(?:left\s*:\s*-\s*\d+px|top\s*:\s*-\s*\d+px|display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px)?)[^"\']*["\'][^>]*>.*?(?:casino|betting|gambling|jackpot|roulette|blackjack|poker|slots?).*?<\/\1>/is',
		];
		foreach ( $patterns as $pattern ) {
			$content = preg_replace( $pattern, '', $content );
		}
		return $content;
	}

	public static function scan_rest_insert( $prepared, $request ) {
		if ( ! is_object( $prepared ) ) {
			return $prepared;
		}
		$text  = ( $prepared->post_title ?? '' ) . "\n" . ( $prepared->post_content ?? '' ) . "\n" . ( $prepared->post_excerpt ?? '' );
		$match = self::match( $text );
		if ( ! $match ) {
			return $prepared;
		}

		$ip = class_exists( 'WPS_Blocker' ) ? WPS_Blocker::client_ip() : (string) ( $_SERVER['REMOTE_ADDR'] ?? '' );
		if ( class_exists( 'WPS_EDR' ) && method_exists( 'WPS_EDR', 'record' ) ) {
			WPS_EDR::record( 'spam_content_blocked', [
				'object_type' => 'request',
				'object_name' => $request instanceof WP_REST_Request ? $request->get_route() : 'rest_insert',
				'severity'    => 'warning',
				'notes'       => 'Rejected a REST content write matching the ' . $match . ' spam-content rule, from '
					. ( '' !== $ip ? $ip : 'an unknown address' ) . '.',
			] );
		}

		return new WP_Error(
			'wps_spam_content_blocked',
			__( 'The submitted content was rejected by the site security filter.', 'wp-perf-shield' ),
			[ 'status' => 403 ]
		);
	}

	/**
	 * Second layer, always runs regardless of how the save was reached.
	 * Strips rather than rejects: by the time content reaches this filter a
	 * post ID may already exist (an update, not a fresh insert), so refusing
	 * outright would be a worse failure mode than quietly cleaning the
	 * specific injected markup.
	 */
	public static function scan_save_boundary( array $data, array $postarr ): array {
		$type = isset( $data['post_type'] ) ? sanitize_key( $data['post_type'] ) : '';
		if ( ! in_array( $type, self::post_types(), true ) ) {
			return $data;
		}
		$text = ( $data['post_title'] ?? '' ) . "\n" . ( $data['post_content'] ?? '' ) . "\n" . ( $data['post_excerpt'] ?? '' );
		$match = self::match( $text );
		if ( ! $match ) {
			return $data;
		}

		$post_id = isset( $postarr['ID'] ) ? absint( $postarr['ID'] ) : 0;
		if ( class_exists( 'WPS_EDR' ) && method_exists( 'WPS_EDR', 'record' ) ) {
			WPS_EDR::record( 'spam_content_stripped', [
				'object_type' => 'post',
				'object_name' => $post_id > 0 ? ( 'post #' . $post_id ) : $type,
				'severity'    => 'warning',
				'notes'       => 'Stripped content matching the ' . $match . ' spam-content rule at the save boundary '
					. '(a second, unconditional layer independent of the REST-insertion check above).',
			] );
		}

		$data['post_title']   = self::strip( (string) ( $data['post_title'] ?? '' ) );
		$data['post_content'] = self::strip( (string) ( $data['post_content'] ?? '' ) );
		$data['post_excerpt'] = self::strip( (string) ( $data['post_excerpt'] ?? '' ) );
		return $data;
	}

	/**
	 * Retroactive sweep for content that predates this feature being turned
	 * on, or that slipped through both layers above some other way. Trashes
	 * (never permanently deletes) anything matching. Intended for a manual
	 * "run once now" action or a light periodic scan - NOT hooked to run on
	 * every page load; the caller decides the cadence.
	 *
	 * @return int Number of posts quarantined.
	 */
	public static function sweep_existing( int $batch_size = 200 ): int {
		$ids = get_posts( [
			'post_type'      => self::post_types(),
			'post_status'    => 'any',
			'posts_per_page' => $batch_size,
			'fields'         => 'ids',
			'orderby'        => 'ID',
			'order'          => 'DESC',
		] );

		$count = 0;
		foreach ( $ids as $id ) {
			$post = get_post( $id );
			if ( ! $post || 'trash' === $post->post_status ) {
				continue;
			}
			$match = self::match( $post->post_title . "\n" . $post->post_content . "\n" . $post->post_excerpt );
			if ( ! $match ) {
				continue;
			}
			if ( wp_trash_post( $id ) ) {
				$count++;
				if ( class_exists( 'WPS_EDR' ) && method_exists( 'WPS_EDR', 'record' ) ) {
					WPS_EDR::record( 'spam_content_swept', [
						'object_type' => 'post',
						'object_name' => 'post #' . $id,
						'severity'    => 'warning',
						'notes'       => 'Quarantined existing content matching the ' . $match . ' spam-content rule during a retroactive sweep.',
					] );
				}
			}
		}
		return $count;
	}
}
