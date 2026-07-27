<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WPS_Logger {

    private const PHP_GUARD = "<?php exit; ?>\n";

    public static function write( string $message ): void {
        self::log_event( 'debug', $message );
    }

    /**
     * Return the remote address as a validated IPv4/IPv6 string, 'cli' when
     * running outside a request context, or 'invalid' when REMOTE_ADDR is
     * present but malformed. Never trusts proxy headers.
     */
    private static function remote_ip(): string {
        if ( ! isset( $_SERVER['REMOTE_ADDR'] ) ) {
            return 'cli';
        }
        $raw = wp_unslash( $_SERVER['REMOTE_ADDR'] );
        if ( ! is_string( $raw ) || $raw === '' ) {
            return 'cli';
        }
        $valid = filter_var( $raw, FILTER_VALIDATE_IP );
        return $valid ?: 'invalid';
    }

    private static function ensure_log_dir(): bool {
        if ( ! defined( 'WPS_LOG_DIR' ) ) {
            return false;
        }

        if ( ! is_dir( WPS_LOG_DIR ) && ! wp_mkdir_p( WPS_LOG_DIR ) ) {
            return false;
        }

        $index = WPS_LOG_DIR . '/index.php';
        if ( ! file_exists( $index ) ) {
            @file_put_contents( $index, "<?php\n// Silence is golden.\n", LOCK_EX );
        }

        $htaccess = WPS_LOG_DIR . '/.htaccess';
        if ( ! file_exists( $htaccess ) ) {
            @file_put_contents( $htaccess, "Deny from all\n", LOCK_EX );
        }

        self::migrate_legacy_log();

        return true;
    }

    private static function migrate_legacy_log(): void {
        if ( file_exists( WPS_LOG_FILE ) || ! defined( 'WPS_LEGACY_LOG_FILE' ) || ! file_exists( WPS_LEGACY_LOG_FILE ) ) {
            return;
        }

        $legacy = @file_get_contents( WPS_LEGACY_LOG_FILE );
        if ( ! is_string( $legacy ) || $legacy === '' ) {
            return;
        }

        @file_put_contents( WPS_LOG_FILE, $legacy, LOCK_EX );
    }

    /** Read the JSON event log. */
    public static function read_events(): array {
        self::ensure_log_dir();

        if ( ! file_exists( WPS_LOG_FILE ) ) {
            return [];
        }

        $raw = @file_get_contents( WPS_LOG_FILE );
        if ( $raw === false || $raw === '' || $raw === '[]' || $raw === self::PHP_GUARD . '[]' ) {
            return [];
        }

        if ( strpos( $raw, self::PHP_GUARD ) === 0 ) {
            $raw = substr( $raw, strlen( self::PHP_GUARD ) );
        }

        $decoded = json_decode( $raw, true );
        return is_array( $decoded ) ? $decoded : [];
    }

    /**
     * Append a structured event to the JSON log, retaining the newest 200.
     *
     * 1.3.99: also forwards into the tamper-evident WPS_Event_Log store as a
     * schema-shaped record (the shim from the roadmap's one-schema rule), so
     * all existing call sites gain chained, enriched records without moving.
     * The file log stays as a belt-and-braces copy and the DB-unavailable
     * fallback; the Events tab prefers the store.
     */
    public static function log_event( string $type, string $subject, string $ip = '' ): void {
        if ( class_exists( 'WPS_Event_Log' ) ) {
            $fields = [
                'event_type' => $type,
                'notes'      => $subject,
                'severity'   => 'info',
            ];
            if ( $ip !== '' ) {
                $fields['ip'] = $ip;
            }
            WPS_Event_Log::record( $fields );
        }

        self::file_event( $type, $subject, $ip );
    }

    /**
     * 1.4.0: the file half of log_event(), callable on its own so enriched
     * audit records (written to the store directly by WPS_Event_Log::audit())
     * can keep their belt-and-braces file copy without double-writing the
     * store through the log_event() forward.
     */
    public static function file_event( string $type, string $subject, string $ip = '' ): void {
        if ( ! self::ensure_log_dir() ) {
            return;
        }

        $events   = self::read_events();
        $events[] = [
            'time'    => gmdate( 'Y-m-d H:i:s' ) . ' UTC',
            'type'    => sanitize_key( $type ),
            'subject' => substr( wp_strip_all_tags( $subject ), 0, 2000 ),
            'ip'      => $ip ?: self::remote_ip(),
        ];

        if ( count( $events ) > 200 ) {
            $events = array_slice( $events, -200 );
        }

        @file_put_contents( WPS_LOG_FILE, self::PHP_GUARD . wp_json_encode( $events, JSON_PRETTY_PRINT ), LOCK_EX );
    }

    public static function clear(): void {
        if ( class_exists( 'WPS_Event_Log' ) ) {
            WPS_Event_Log::record( [
                'event_type' => 'event_log_cleared',
                'severity'   => 'warning',
                'notes'      => 'file event log cleared from the admin; the tamper-evident store is append-only and retains history',
            ] );
        }
        if ( ! self::ensure_log_dir() ) {
            return;
        }

        @file_put_contents( WPS_LOG_FILE, self::PHP_GUARD . '[]', LOCK_EX );
    }

    public static function can_write(): bool {
        if ( ! self::ensure_log_dir() ) {
            return false;
        }

        if ( file_exists( WPS_LOG_FILE ) ) {
            return is_writable( WPS_LOG_FILE );
        }

        return is_writable( WPS_LOG_DIR );
    }

    /** Email the admin once per hour per unique event type+subject. */
    public static function notify_admin( string $subject, string $detail ): void {
        $cache_key = 'wps_notify_' . md5( $subject . $detail );
        if ( get_transient( $cache_key ) ) {
            return;
        }
        set_transient( $cache_key, 1, HOUR_IN_SECONDS );

        wp_mail(
            (string) get_option( 'admin_email' ),
            '[WP Perf Shield] ' . $subject,
            "WP Perf Shield - security alert\n\n"
            . "Site  : " . get_option( 'siteurl' ) . "\n"
            . "Event : {$subject}\n"
            . "Detail: {$detail}\n"
            . "Time  : " . gmdate( 'Y-m-d H:i:s' ) . " UTC\n"
            . "IP    : " . self::remote_ip() . "\n\n"
            . 'Review: ' . admin_url( 'tools.php?page=wp-perf-shield' )
        );
    }
}
