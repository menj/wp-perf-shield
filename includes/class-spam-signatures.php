<?php
/**
 * Injected-spam content signatures (1.4.73).
 *
 * Recognises the casino/gambling/SEO-spam content that auto-blogging injections
 * publish - the wp2shell-era casino wave, the Indonesian "slot gacor / togel"
 * family, and their English equivalents - in a post or comment body.
 *
 * The hard part is NOT catching the spam; it is not catching the operator. This
 * site's author writes about gambling in Malay and in a religious register
 * (judi as a prohibition), so a single word can never be the signal. Two
 * independent tiers guard against that:
 *
 *   - DIAGNOSTIC markers are SEO-spam tokens that do not occur in prose in any
 *     language - "slot gacor", "rtp live", "maxwin", "togel", "gacor",
 *     "situs judi". One of these is conclusive.
 *   - GENERIC gambling words - casino, judi, poker, betting - occur in ordinary
 *     writing, so they count only in bulk AND alongside a structural spam tell
 *     (hidden/cloaked markup, or a wall of outbound links). An anti-gambling
 *     essay that says "judi" and "casino" a few times, with no cloaking and no
 *     link farm, is left alone.
 *
 * Word boundaries are enforced, so "judi" never fires inside "prejudice".
 * Nothing here reproduces the matched content; callers get counts and the
 * signals that fired, not the spam itself.
 */

defined( 'ABSPATH' ) || exit;

final class WPS_Spam_Signatures {

	/** Cap the text examined per item, so a pathologically large body cannot stall a scan. */
	private const MAX_LEN = 200000;

	/** SEO-spam tokens that do not appear in prose in any language. One is conclusive. */
	private const DIAGNOSTIC = [
		'slot gacor', 'gacor', 'togel', 'rtp live', 'rtp slot', 'judi online',
		'judi bola', 'situs judi', 'situs slot', 'slot online', 'slot88',
		'slot 88', 'maxwin', 'bandar togel', 'deposit pulsa', 'bocoran',
		'pragmatic play', 'sbobet', 'dominoqq', 'bandarq', 'pkv games',
		'idn poker', 'mahjong ways', 'zeus slot', 'gates of olympus',
		'link slot', 'akun pro', 'scatter hitam',
	];

	/** Ordinary gambling words: counted only in bulk and only with a structural tell. */
	private const GENERIC = [
		'casino', 'judi', 'poker', 'betting', 'taruhan', 'sportsbook',
		'baccarat', 'roulette', 'blackjack', 'jackpot', 'gambling', 'slot',
	];

	/** Structural tells of injected/cloaked spam markup. */
	private const CLOAK = [
		'display\s*:\s*none',
		'visibility\s*:\s*hidden',
		'text-indent\s*:\s*-',
		'position\s*:\s*absolute[^;]{0,40}left\s*:\s*-',
		'left\s*:\s*-?\d{4,}px',
		'height\s*:\s*0(px|;|\s)',
		'height\s*:\s*1px',
		'base64_decode',
		'eval\s*\(',
	];

	/**
	 * @return array{spam:bool, confidence:string, signals:string[], reason:string}
	 */
	public static function evaluate( string $text ): array {
		$none = [ 'spam' => false, 'confidence' => '', 'signals' => [], 'reason' => '' ];
		if ( '' === $text ) {
			return $none;
		}
		if ( strlen( $text ) > self::MAX_LEN ) {
			$text = substr( $text, 0, self::MAX_LEN );
		}
		$hay = strtolower( $text );

		$diag = [];
		foreach ( self::DIAGNOSTIC as $term ) {
			if ( preg_match( '/(?<![a-z0-9])' . preg_quote( $term, '/' ) . '(?![a-z0-9])/', $hay ) ) {
				$diag[] = $term;
			}
		}
		if ( $diag ) {
			return [
				'spam'       => true,
				'confidence' => 'high',
				'signals'    => array_slice( $diag, 0, 6 ),
				'reason'     => 'SEO-spam gambling markers present (' . implode( ', ', array_slice( $diag, 0, 4 ) ) . ')',
			];
		}

		$gen = [];
		foreach ( self::GENERIC as $term ) {
			if ( preg_match( '/(?<![a-z0-9])' . preg_quote( $term, '/' ) . '(?![a-z0-9])/', $hay ) ) {
				$gen[] = $term;
			}
		}

		$cloaked = false;
		foreach ( self::CLOAK as $rx ) {
			if ( preg_match( '/' . $rx . '/i', $text ) ) {
				$cloaked = true;
				break;
			}
		}

		$out_links = preg_match_all( '/<a\s[^>]*href\s*=\s*["\']https?:\/\//i', $text );

		// Bulk gambling vocabulary AND a structural tell: two independent signals,
		// which ordinary prose does not combine.
		if ( count( $gen ) >= 3 && $cloaked ) {
			return [
				'spam'       => true,
				'confidence' => 'high',
				'signals'    => array_merge( array_slice( $gen, 0, 5 ), [ 'cloaked/hidden markup' ] ),
				'reason'     => count( $gen ) . ' gambling terms combined with hidden/cloaked markup',
			];
		}
		if ( count( $gen ) >= 2 && $cloaked ) {
			return [
				'spam'       => true,
				'confidence' => 'medium',
				'signals'    => array_merge( array_slice( $gen, 0, 5 ), [ 'cloaked/hidden markup' ] ),
				'reason'     => 'gambling terms combined with hidden/cloaked markup',
			];
		}
		if ( count( $gen ) >= 3 && $out_links >= 8 ) {
			return [
				'spam'       => true,
				'confidence' => 'medium',
				'signals'    => array_merge( array_slice( $gen, 0, 5 ), [ $out_links . ' outbound links' ] ),
				'reason'     => count( $gen ) . ' gambling terms with a wall of ' . $out_links . ' outbound links',
			];
		}

		return $none;
	}

	/** The SQL LIKE fragments to pre-filter candidate rows before the matcher confirms them. */
	public static function like_prefilter_terms(): array {
		return [ 'gacor', 'togel', 'judi', 'casino', 'maxwin', 'sbobet', 'slot', 'rtp live', 'bocoran' ];
	}
}
