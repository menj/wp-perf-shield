<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * WPS_Forensics
 *
 * Traces the attack source using data available to a WordPress plugin:
 *  - Media library upload records (ZIP files, timestamps, uploader IP if logged)
 *  - File modification timestamps on plugin/theme files
 *  - Recently created administrator accounts
 *  - wp-cron.php integrity (WP-antymalwary-bot persistence vector)
 *  - Theme header.php tampering (known injection point)
 *  - WordPress option changes (siteurl, admin_email hijack attempts)
 *  - REST API user creation attempts via logs
 *
 * Note: Server access log parsing requires SSH access. This class provides
 * the WordPress-level forensic picture and generates the exact grep commands
 * needed to complete the trace via SSH.
 */
class WPS_Forensics {

    /** Run all forensic checks and return a structured report. */
    public static function run(): array {
        return [
            'generated'              => gmdate( 'Y-m-d H:i:s' ) . ' UTC',
            'media_uploads'          => self::trace_media_uploads(),
            'plugin_files'           => self::trace_plugin_file_timestamps(),
            'admin_accounts'         => self::trace_admin_accounts(),
            'theme_tampering'        => self::trace_theme_tampering(),
            'cron_integrity'         => self::check_cron_integrity(),
            'cron_callbacks'         => self::check_cron_callback_resolution(), // 1.3.40
            'auto_prepend_anomalies' => self::check_auto_prepend_files(),       // 1.3.40
            'option_anomalies'       => self::check_option_anomalies(),
            'unknown_base64_options' => self::check_unknown_base64_options(),   // 1.3.40
            'php_checks'             => self::run_php_checks(),
            'core_integrity'         => self::check_core_integrity(),
            'recent_modified_php'    => self::recent_modified_executables(), // 1.3.92: in-plugin attack-window correlation (no SSH)
            'redropper_hunt'         => self::build_redropper_hunt_commands(), // 1.3.93: find what re-plants a recurring kit
            'ssh_commands'           => self::build_ssh_commands(),
        ];
    }

    /**
     * Public wrapper exposing only the three 1.3.40 behavioural-detection
     * checks, used by the hourly scanner integration added in 1.3.41.
     *
     * Returning a stable subset keeps the scanner's translation layer narrow:
     * even if the broader run() report shape changes, the scanner contract
     * stays fixed at these three keys.
     *
     * @return array{auto_prepend_anomalies: array, unknown_base64_options: array, cron_callbacks: array}
     */
    public static function dropper_persistence_findings(): array {
        return [
            'auto_prepend_anomalies' => self::check_auto_prepend_files(),
            'unknown_base64_options' => self::check_unknown_base64_options(),
            'cron_callbacks'         => self::check_cron_callback_resolution(),
        ];
    }

    //  1. Media library  find ZIP uploads around attack window 

    /**
     * 1.4.29: emit a mass-modification suppression note at most once per batch.
     *
     * The note is diagnostic, not a finding - it explains why a group of files
     * was not individually reported. Repeating it on every scan added nothing
     * and cost retention in a bounded, tamper-evident log, which is the one
     * place noise is most expensive.
     *
     * The memory is a single bounded option. Entries expire, so a batch that
     * is still present months later will be mentioned again rather than
     * silently forgotten.
     */
    private static function report_suppressed_batch_once( int $bucket_mtime, int $count, int $threshold ): void {
        $option = 'wps_mtime_batches_seen';
        $ttl    = 30 * DAY_IN_SECONDS;
        $now    = time();

        $seen = get_option( $option, [] );
        if ( ! is_array( $seen ) ) {
            $seen = [];
        }

        // Expire old entries before deciding.
        foreach ( $seen as $k => $at ) {
            if ( ! is_int( $at ) || $at < ( $now - $ttl ) ) {
                unset( $seen[ $k ] );
            }
        }

        // Size is part of the key: the same timestamp with more files in it is
        // a new fact and deserves saying again.
        $key = $bucket_mtime . ':' . $count;

        if ( isset( $seen[ $key ] ) ) {
            update_option( $option, $seen, false );
            return;
        }

        $seen[ $key ] = $now;

        // Bound the store. Oldest first, so the most recent batches survive.
        if ( count( $seen ) > 200 ) {
            asort( $seen );
            $seen = array_slice( $seen, -200, null, true );
        }
        update_option( $option, $seen, false );

        WPS_Logger::write( sprintf(
            'mtime check: suppressed %d files at %s UTC (mass-event threshold %d)',
            $count,
            gmdate( 'Y-m-d H:i:s', $bucket_mtime ),
            $threshold
        ) );
    }

    private static function trace_media_uploads(): array {
        global $wpdb;

        $results = $wpdb->get_results( $wpdb->prepare(
            "SELECT ID, post_title, post_date, post_date_gmt, guid
             FROM {$wpdb->posts}
             WHERE post_type = 'attachment'
               AND (
                 post_title LIKE %s
                 OR post_title LIKE %s
                 OR post_title LIKE %s
                 OR post_title LIKE %s
                 OR post_title LIKE %s
                 OR post_title LIKE %s
                 OR post_title LIKE %s
                 OR post_title LIKE %s
                 OR post_title LIKE %s
                 OR post_title LIKE %s
                 OR post_title LIKE %s
                 OR post_title LIKE %s
                 OR guid LIKE %s
               )
             ORDER BY post_date_gmt DESC
             LIMIT 50",
            '%wp-perf-analytics%',
            '%wp-perf%',
            '%native-render-toolkit%',
            '%total-render-profiler%',
            '%total-render-toolkit%',
            '%pro-font-optimizer%',
            '%site-speed-insights%',
            '%advanced-asset-insights%',
            '%page-seo-toolkit%',
            '%starter-image-guard%',
            '%wp-locale-handler%',
            '%.zip%',
            '%.zip%'
        ), ARRAY_A );

        $found = [];
        foreach ( $results as $r ) {
            // Try to get the uploader meta (some activity log plugins store this)
            $uploader_ip = get_post_meta( (int) $r['ID'], '_upload_ip', true )
                        ?: get_post_meta( (int) $r['ID'], 'upload_ip', true )
                        ?: 'not recorded by WordPress (check server logs)';

            $found[] = [
                'id'          => $r['ID'],
                'title'       => $r['post_title'],
                'uploaded_at' => $r['post_date_gmt'] . ' UTC',
                'url'         => $r['guid'],
                'uploader_ip' => $uploader_ip,
            ];
        }

        // Also grab ALL recent zip uploads regardless of name (last 14 days)
        $recent = $wpdb->get_results( $wpdb->prepare(
            "SELECT ID, post_title, post_date_gmt, guid
             FROM {$wpdb->posts}
             WHERE post_type = 'attachment'
               AND guid LIKE %s
               AND post_date_gmt >= %s
             ORDER BY post_date_gmt DESC
             LIMIT 20",
            '%.zip%',
            gmdate( 'Y-m-d H:i:s', strtotime( '-14 days' ) )
        ), ARRAY_A );

        $recent_zips = [];
        foreach ( $recent as $r ) {
            $recent_zips[] = [
                'id'          => $r['ID'],
                'title'       => $r['post_title'],
                'uploaded_at' => $r['post_date_gmt'] . ' UTC',
                'url'         => $r['guid'],
            ];
        }

        return [
            'malicious_uploads' => $found,
            'recent_zips'       => $recent_zips,
        ];
    }

    //  2. Plugin file timestamps  pinpoint when files appeared 

    private static function trace_plugin_file_timestamps(): array {
        $found = [];
        if ( ! is_dir( WP_PLUGIN_DIR ) ) {
            return $found;
        }

        $suspicious_slugs = WPS_Blocker::get_blocked_slugs();
        // Additional forensic names (may not be blocklist slugs but are suspicious)
        $suspicious_slugs[] = 'antymalwary';
        $suspicious_slugs[] = 'wpconsole';
        $suspicious_slugs[] = 'wp-performance-booster';
        $suspicious_slugs[] = 'native-render-toolkit';
        $suspicious_slugs[] = 'total-render-profiler';
        $suspicious_slugs[] = 'total-render-toolkit';
        $suspicious_slugs[] = 'pro-font-optimizer';
        $suspicious_slugs[] = 'site-speed-insights';
        $suspicious_slugs[] = 'advanced-asset-insights'; // 1.3.39: gap-fill from 1.3.37
        $suspicious_slugs[] = 'page-seo-toolkit';        // 1.3.39
        $suspicious_slugs[] = 'starter-image-guard';     // 1.3.39
        $suspicious_slugs[] = 'session-manager'; // second plugin name in ClickFix campaign
        $suspicious_slugs[] = 'wp-locale-handler';

        try {
            $iter = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator( WP_PLUGIN_DIR, FilesystemIterator::SKIP_DOTS ),
                RecursiveIteratorIterator::LEAVES_ONLY
            );
            foreach ( $iter as $file ) {
                if ( ! ( $file instanceof SplFileInfo ) || $file->getExtension() !== 'php' ) {
                    continue;
                }
                $path  = $file->getPathname();
                $lower = strtolower( $path );
                $is_suspicious = false;
                foreach ( $suspicious_slugs as $slug ) {
                    if ( strpos( $lower, strtolower( $slug ) ) !== false ) {
                        $is_suspicious = true;
                        break;
                    }
                }
                if ( $is_suspicious ) {
                    $mtime = @filemtime( $path );
                    $found[] = [
                        'file'     => str_replace( WP_PLUGIN_DIR . '/', '', $path ),
                        'path'     => $path,
                        'modified' => $mtime ? gmdate( 'Y-m-d H:i:s', $mtime ) . ' UTC' : 'unknown',
                        'mtime'    => $mtime ?: 0,
                        'size'     => $file->getSize(),
                        'md5'      => @md5_file( $path ) ?: 'unreadable',
                    ];
                }
            }
        } catch ( \Exception $e ) {
            WPS_Logger::write( 'Forensics plugin scan error: ' . $e->getMessage() );
        }

        // Sort by modification time ascending (oldest = likely entry point)
        usort( $found, fn( $a, $b ) => $a['mtime'] <=> $b['mtime'] );

        return $found;
    }

    //  3. Admin accounts  detect recently created or suspicious accounts 

    private static function trace_admin_accounts(): array {
        $admins = get_users( [
            'role'    => 'administrator',
            'orderby' => 'registered',
            'order'   => 'DESC',
            'number'  => 20,
        ] );

        // Only include accounts confirmed as malware-created persistence users.
        // Legitimate site/domain owner usernames must not be marked as attackers
        // simply because they appeared in incident notes or credential captures.
        $malware_created_logins = WPS_Indicators::hardcoded_admin_usernames();

        // Check ALL roles for known malware-created usernames  they may not be admins.
        $malware_users = get_users( [ 'login__in' => $malware_created_logins, 'number' => 10 ] );
        foreach ( $malware_users as $au ) {
            WPS_Logger::log_event( 'attacker_account_found', 'Known malware-created account: ' . $au->user_login . ' (role: ' . implode( ',', $au->roles ) . ')' );
            // Add to admins list if not already present so it shows in the report
            $already = false;
            foreach ( $admins as $ex ) {
                if ( $ex->ID === $au->ID ) { $already = true; break; }
            }
            if ( ! $already ) $admins[] = $au;
        }

        $found = [];
        $cutoff = strtotime( '-30 days' );

        foreach ( $admins as $user ) {
            $registered = strtotime( $user->user_registered );
            $is_recent  = $registered > $cutoff;

            // Check for suspicious patterns: generic names, no display name, random-looking emails
            $email       = $user->user_email;
            $login       = $user->user_login;
            $is_generic  = preg_match( '/^(admin|administrator|root|wp-admin|webmaster|support|test|user)[0-9]*$/i', $login );
            $is_random   = preg_match( '/^[a-z]{6,12}[0-9]{3,6}@/i', $email ); // varuvlzh123@ pattern
            $last_login  = get_user_meta( $user->ID, 'last_login', true )
                        ?: get_user_meta( $user->ID, 'wfls-last-login', true )
                        ?: 'not recorded';

            $flags = [];
            if ( in_array( $login, $malware_created_logins, true ) ) $flags[] = 'known malware-created account';
            if ( $is_recent ) $flags[] = 'recently created';
            if ( $is_generic ) $flags[] = 'generic username';
            if ( $is_random ) $flags[] = 'random-pattern email';

            $found[] = [
                'id'         => $user->ID,
                'login'      => $login,
                'email'      => $email,
                'registered' => $user->user_registered . ' UTC',
                'last_login' => $last_login,
                'flags'      => $flags,
                'suspicious' => ! empty( $flags ),
            ];
        }

        return $found;
    }

    //  4. Theme file tampering 

    private static function trace_theme_tampering(): array {
        $findings = [];
        $theme    = get_template_directory();

        // Check header.php  primary injection target per WP-antymalwary-bot report
        $header = $theme . '/header.php';
        if ( file_exists( $header ) ) {
            $mtime    = @filemtime( $header );
            $contents = @file_get_contents( $header );
            $injected = false;
            $matches  = [];

            if ( $contents ) {
                // Look for known injection signatures
                $patterns = [
                    'eval(',
                    'base64_decode(',
                    'str_rot13(',
                    'gzinflate(',
                    'gzuncompress(',
                    '\\x',
                    'document.write(',
                    // wp-perf-analytics / ClickFix family
                    'polygon.drpc.org',
                    '_wp_perf_ok',
                    '_cf_verified',
                    'cf-captcha-verified',   // ClickFix fake Cloudflare postMessage
                    '38bcdc1c',
                    'session_tokens_config',
                    // WP-antymalwary-bot family
                    'WP-antymalwary',
                    'italicfonts.org',
                    'wp-performance-booster',
                ];
                foreach ( $patterns as $p ) {
                    if ( strpos( $contents, $p ) !== false ) {
                        $injected  = true;
                        $matches[] = $p;
                    }
                }
            }

            $findings[] = [
                'file'      => str_replace( ABSPATH, '', $header ),
                'full_path' => $header,
                'modified'  => $mtime ? gmdate( 'Y-m-d H:i:s', $mtime ) . ' UTC' : 'unknown',
                'status'    => $injected ? 'INFECTED' : 'clean',
                'matches'   => $matches,
            ];
        }

        // Check functions.php too
        $functions = $theme . '/functions.php';
        if ( file_exists( $functions ) ) {
            $mtime    = @filemtime( $functions );
            $contents = @file_get_contents( $functions );
            $injected = false;
            $matches  = [];

            if ( $contents ) {
                $bad = [ 'eval(', 'base64_decode(', 'gzinflate(', 'str_rot13(' ];
                foreach ( $bad as $b ) {
                    if ( strpos( $contents, $b ) !== false ) {
                        $injected  = true;
                        $matches[] = $b;
                    }
                }
            }
            $findings[] = [
                'file'      => str_replace( ABSPATH, '', $functions ),
                'full_path' => $functions,
                'modified'  => $mtime ? gmdate( 'Y-m-d H:i:s', $mtime ) . ' UTC' : 'unknown',
                'status'    => $injected ? 'INFECTED' : 'clean',
                'matches'   => $matches,
            ];
        }

        return $findings;
    }

    //  5. wp-cron.php integrity 
    // WP-antymalwary-bot persistence: modifies wp-cron.php to auto-reinstall

    private static function get_wp_version(): string {
        global $wp_version;

        if ( empty( $wp_version ) ) {
            $ver_file = ABSPATH . WPINC . '/version.php';
            if ( file_exists( $ver_file ) ) {
                include $ver_file;
            }
        }

        return empty( $wp_version ) ? '' : (string) $wp_version;
    }

    private static function get_core_checksums( string $wp_version ) {
        if ( $wp_version === '' ) {
            return new WP_Error( 'wps_no_wp_version', 'Could not determine WordPress version' );
        }

        $locale    = get_locale() ?: 'en_US';
        $cache_key = 'wps_core_checksums_' . md5( $wp_version . '|' . $locale );
        $checksums = get_transient( $cache_key );

        if ( is_array( $checksums ) ) {
            return $checksums;
        }

        $api_url  = 'https://api.wordpress.org/core/checksums/1.0/?version=' . rawurlencode( $wp_version ) . '&locale=' . rawurlencode( $locale );
        $response = wp_safe_remote_get( $api_url, [ 'timeout' => 10 ] );

        if ( is_wp_error( $response ) ) {
            return $response;
        }

        $code = (int) wp_remote_retrieve_response_code( $response );
        if ( $code < 200 || $code >= 300 ) {
            return new WP_Error( 'wps_checksum_http_error', 'Checksum API returned HTTP ' . $code );
        }

        $body      = json_decode( wp_remote_retrieve_body( $response ), true );
        $checksums = $body['checksums'] ?? null;

        if ( ! is_array( $checksums ) ) {
            return new WP_Error( 'wps_checksum_error', 'Checksum API returned no data' );
        }

        // Cache for 24 hours  checksums for a given version never change.
        set_transient( $cache_key, $checksums, DAY_IN_SECONDS );

        return $checksums;
    }

    private static function check_cron_integrity(): array {
        $cron_file = ABSPATH . 'wp-cron.php';
        if ( ! file_exists( $cron_file ) ) {
            return [ 'status' => 'missing', 'note' => 'wp-cron.php not found  already removed or path incorrect' ];
        }

        $mtime    = @filemtime( $cron_file );
        $contents = @file_get_contents( $cron_file );
        $md5      = @md5_file( $cron_file ) ?: 'unreadable';

        $wp_version      = self::get_wp_version();
        $expected_md5    = '';
        $checksum_error  = '';
        $checksums       = self::get_core_checksums( $wp_version );

        if ( is_wp_error( $checksums ) ) {
            $checksum_error = $checksums->get_error_message();
        } else {
            $expected_md5 = (string) ( $checksums['wp-cron.php'] ?? '' );
        }

        // Legacy fallback for older installs when the WordPress checksum API is unreachable.
        $known_good = [
            // WP 6.5.x
            'a9a94be774c687c777d9df67af3e3e79',
            // WP 6.4.x
            '1e3ab20d4c3e58cd40a95e5d9e76d3e1',
            // WP 6.3.x
            '5e36da05c3b0b36da3d2e8e7c3b0a5d2',
        ];

        $suspicious_strings = [
            'wp-antymalwary',
            'wp-performance-booster',
            'wpconsole',
            // require_once / include_once removed in v1.2.1: stock WordPress
            // wp-cron.php contains require_once( ABSPATH . 'wp-load.php' ),
            // so these strings fired on every clean install. Detection of a
            // tampered cron is now driven by the malware-family names above
            // and the eval / base64 / file-write markers below.
            'base64_decode',
            'eval(',
            'file_put_contents',
        ];

        $bad_found = [];
        if ( $contents ) {
            foreach ( $suspicious_strings as $s ) {
                if ( strpos( $contents, $s ) !== false ) {
                    $bad_found[] = $s;
                }
            }
        }

        $is_official          = $expected_md5 !== '' && $md5 !== 'unreadable' && hash_equals( $expected_md5, $md5 );
        $is_legacy_known_good = in_array( $md5, $known_good, true );
        $is_known_good        = $is_official || $is_legacy_known_good;
        $is_tampered          = ! empty( $bad_found );

        if ( $is_tampered ) {
            $note = 'wp-cron.php contains suspicious code  replace with a clean copy immediately';
        } elseif ( $is_official ) {
            $note = 'MD5 matches the official WordPress checksum for this installed version';
        } elseif ( $is_legacy_known_good ) {
            $note = 'MD5 matches a legacy known-clean fallback hash';
        } elseif ( $checksum_error !== '' ) {
            $note = 'Could not verify against the official WordPress checksum API: ' . $checksum_error;
        } elseif ( $expected_md5 !== '' ) {
            $note = 'MD5 does not match the official WordPress checksum for this installed version';
        } else {
            $note = 'Official WordPress checksum data did not include wp-cron.php for this version';
        }

        return [
            'file'         => 'wp-cron.php',
            'version'      => $wp_version !== '' ? $wp_version : 'unknown',
            'modified'     => $mtime ? gmdate( 'Y-m-d H:i:s', $mtime ) . ' UTC' : 'unknown',
            'md5'          => $md5,
            'expected_md5' => $expected_md5,
            'status'       => $is_tampered ? 'TAMPERED' : ( $is_known_good ? 'verified_clean' : 'unverified' ),
            'matches'      => $bad_found,
            'note'         => $note,
        ];
    }

    //  6. Option anomalies 

    private static function check_option_anomalies(): array {
        global $wpdb;
        $findings = [];

        // Check for unexpected REST API user creation capability
        $active = get_option( 'active_plugins', [] );
        foreach ( $active as $p ) {
            if ( ! is_string( $p ) ) continue;
            // WP-antymalwary-bot family names
            foreach ( [ 'antymalwary', 'wpconsole', 'wp-performance-booster', 'native-render-toolkit', 'total-render-profiler', 'total-render-toolkit', 'pro-font-optimizer', 'site-speed-insights', 'advanced-asset-insights', 'page-seo-toolkit', 'starter-image-guard', 'wp-locale-handler' ] as $slug ) {
                if ( strpos( strtolower( $p ), $slug ) !== false ) {
                    $findings[] = [
                        'type'    => 'suspicious_active_plugin',
                        'detail'  => $p,
                        'action'  => 'Deactivate and delete immediately',
                    ];
                }
            }
        }

        // Check for emergency login option set by WP-antymalwary-bot
        // Malware-set DB options to check for; loaded from versioned indicators (Phase 4).
        $bad_options = WPS_Indicators::malware_option_keys();

        // Check for credential exfil file by known path AND by searching uploads by name
        $exfil_paths = [
            'wp-content/uploads/2024/06/Stained_Heart_Red-600x500.png',
        ];
        foreach ( $exfil_paths as $rel ) {
            $abs = rtrim( ABSPATH, '/' ) . '/' . $rel;
            if ( file_exists( $abs ) ) {
                $findings[] = [
                    'type'   => 'credential_exfil_file',
                    'detail' => $rel . ' (' . filesize( $abs ) . ' bytes)  contains harvested login credentials',
                    'action' => 'Read contents before deleting, then delete: rm ' . $abs,
                ];
            }
        }
        // Also search all of uploads by filename  attacker may vary the path by year/month
        $upload_base = wp_upload_dir()['basedir'] ?? '';
        if ( $upload_base && is_dir( $upload_base ) ) {
            $exfil_names = WPS_Indicators::exfil_filenames();
            foreach ( $exfil_names as $name ) {
                $hits = [];
                try {
                    $iter = new RecursiveIteratorIterator(
                        new RecursiveDirectoryIterator( $upload_base, FilesystemIterator::SKIP_DOTS )
                    );
                    foreach ( $iter as $f ) {
                        if ( $f instanceof SplFileInfo && $f->getFilename() === $name ) {
                            $hits[] = $f->getPathname();
                        }
                    }
                } catch ( \Exception $e ) {}
                foreach ( $hits as $hit ) {
                    $findings[] = [
                        'type'   => 'credential_exfil_file',
                        'detail' => str_replace( ABSPATH, '', $hit ) . ' (' . @filesize( $hit ) . ' bytes)',
                        'action' => 'Read contents before deleting: cat ' . $hit . ' && rm ' . $hit,
                    ];
                }
            }
        }

        // Check for known backdoor filenames anywhere under wp-content.
        // Combines the historical short list with the secondary toolkit
        // filenames added in 1.3.33.
        $backdoor_names = array_merge(
            [
                'wp-backup-verify.php',
                'wc-report-handler.php',
                'wp-locale-handler.php',
            ],
            WPS_Indicators::secondary_backdoor_filenames()
        );
        foreach ( $backdoor_names as $bn ) {
            $hits = glob( WP_CONTENT_DIR . '/**/' . $bn ) ?: [];
            // Also check root of wp-content subdirs directly
            $hits = array_merge( $hits, glob( WP_CONTENT_DIR . '/*/' . $bn ) ?: [] );
            foreach ( $hits as $hit ) {
                $findings[] = [
                    'type'   => 'known_backdoor_file',
                    'detail' => str_replace( ABSPATH, '', $hit ) . '  PHP RCE backdoor, delete immediately',
                    'action' => 'rm ' . $hit,
                ];
            }
        }
        foreach ( $bad_options as $opt ) {
            $val = get_option( $opt, null );
            if ( $val !== null ) {
                $is_mu = in_array( $opt, WPS_Indicators::mu_persistence_option_keys(), true );
                $findings[] = [
                    'type'        => $is_mu
                        ? 'malware_option_in_db (MU plugin backup  RAT auto-restores mu-plugin from this)'
                        : 'malware_option_in_db',
                    'option_name' => $opt,
                    'detail'      => $opt,
                    'preview'     => is_string( $val ) ? substr( $val, 0, 80 ) : '(non-string value)',
                    'action'      => 'Deleted via Forensics inline button',
                ];
            }
        }

        // Check for unexpected cron jobs
        $crons = _get_cron_array();
        if ( is_array( $crons ) ) {
            foreach ( $crons as $timestamp => $hooks ) {
                foreach ( $hooks as $hook => $args ) {
                    $lower_hook = strtolower( $hook );
                    foreach ( [ 'antymalwary', 'perf_analytics', 'wpconsole', 'malwary', 'wp_perf_ok' ] as $bad ) {
                        if ( strpos( $lower_hook, $bad ) !== false ) {
                            $findings[] = [
                                'type'   => 'suspicious_cron_hook',
                                'detail' => $hook . ' (next: ' . gmdate( 'Y-m-d H:i:s', (int) $timestamp ) . ' UTC)',
                                'action' => 'Remove: wp cron event delete ' . $hook,
                            ];
                        }
                    }
                }
            }
        }

        return $findings;
    }

    //  6b. auto_prepend_file / auto_append_file sweep (1.3.40) 
    //
    // The most common dropper hideout that earlier versions did not check:
    // a per-host or per-directory PHP configuration file silently registers
    // a custom script to run before every PHP request. The dropper itself
    // can sit completely outside wp-content/, making it invisible to plugin
    // walkers and to file scanners that only look inside the WordPress tree.
    //
    // We sweep three configuration sources:
    //   - .user.ini files at any depth under ABSPATH
    //   - .htaccess files at any depth under ABSPATH (php_value/php_admin_value)
    //   - php.ini at the WordPress root (rare; some hosts allow it)
    //
    // We treat the directive as suspicious unless the resolved target lives
    // in one of the conventional safe locations used by hosting agents
    // (New Relic, Plesk, Bitnami, Hostinger, LiteSpeed, etc.).

    /**
     * Walk the WordPress tree for .user.ini / .htaccess / php.ini files and
     * return any auto_prepend_file / auto_append_file directive whose target
     * does not resolve to a known-safe hosting-agent path.
     *
     * @return list<array<string, string>>
     */
    private static function check_auto_prepend_files(): array {
        $findings = [];
        $config_files = self::collect_php_config_files();

        foreach ( $config_files as $cfg ) {
            $contents = @file_get_contents( $cfg );
            if ( $contents === false || $contents === '' ) continue;

            // .htaccess form: php_value / php_admin_value auto_prepend_file "/path"
            // .user.ini form: auto_prepend_file = /path
            // php.ini form:   auto_prepend_file = "/path"
            $patterns = [
                '~^\s*php_(?:admin_)?value\s+auto_(prepend|append)_file\s+["\']?([^"\'\r\n]+)["\']?~mi',
                '~^\s*auto_(prepend|append)_file\s*=\s*["\']?([^"\'\r\n;]+)["\']?~mi',
            ];

            foreach ( $patterns as $pat ) {
                if ( ! preg_match_all( $pat, $contents, $m, PREG_SET_ORDER ) ) continue;
                foreach ( $m as $hit ) {
                    $directive = strtolower( $hit[1] ) === 'append' ? 'auto_append_file' : 'auto_prepend_file';
                    $target    = trim( $hit[2] );
                    if ( $target === '' || $target === 'none' ) continue;

                    $verdict = self::classify_auto_prepend_target( $target );
                    if ( $verdict === 'safe' ) continue;

                    $rel_cfg = str_replace( ABSPATH, '', $cfg );
                    $findings[] = [
                        'type'        => 'auto_prepend_directive',
                        'config_file' => $rel_cfg,
                        'directive'   => $directive,
                        'target'      => $target,
                        'verdict'     => $verdict, // 'critical' | 'review'
                        'action'      => $verdict === 'critical'
                            ? 'Open ' . $rel_cfg . ' and remove the ' . $directive . ' line. The file at ' . $target . ' is the dropper or its loader.'
                            : 'Verify ' . $target . ' is from your hosting agent (New Relic / Plesk / etc.); if not, treat as critical.',
                    ];
                }
            }
        }

        return $findings;
    }

    /**
     * Recursively gather .user.ini / .htaccess / php.ini files under ABSPATH.
     * Bounded to depth 6 and at most 2000 files to avoid runaway iteration on
     * sites with very deep wp-content/uploads/ trees.
     *
     * @return list<string>
     */
    private static function collect_php_config_files(): array {
        $abspath = rtrim( ABSPATH, '/\\' );
        $found = [];
        $count = 0;
        $max   = 2000;

        $targets = [ '.user.ini', '.htaccess', 'php.ini' ];
        try {
            $iter = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator( $abspath, FilesystemIterator::SKIP_DOTS ),
                RecursiveIteratorIterator::LEAVES_ONLY
            );
            $iter->setMaxDepth( 6 );
            foreach ( $iter as $f ) {
                if ( ++$count > $max ) break;
                if ( ! ( $f instanceof SplFileInfo ) ) continue;
                if ( ! in_array( $f->getFilename(), $targets, true ) ) continue;
                $found[] = $f->getPathname();
            }
        } catch ( \Exception $e ) {}

        return $found;
    }

    /**
     * Classify an auto_prepend_file / auto_append_file target path.
     *
     * Returns:
     *   'safe'     target matches a hosting-agent convention; suppress.
     *   'review'   target looks plausible but is not on the safe list.
     *   'critical' target lives in wp-content/, /tmp, ABSPATH, or any
     *              directory commonly abused by ClickFix / RAT droppers.
     */
    private static function classify_auto_prepend_target( string $target ): string {
        $abs = ltrim( str_replace( '\\', '/', $target ), '"\'' );
        $abs_norm = strtolower( $abs );

        // Host-agent install paths. Conservative and explicit; do not broaden
        // without verifying the path belongs to a real hosting tool.
        $safe_prefixes = [
            '/usr/lib/php/',
            '/usr/share/php/',
            '/opt/newrelic/',
            '/usr/lib/newrelic-php',
            '/etc/php/',
            '/usr/local/lsws/',         // LiteSpeed Web Server
            '/usr/local/lscache/',
            '/opt/plesk/',
            '/opt/bitnami/',
            '/opt/cpanel/',
            '/usr/local/cpanel/',
            '/var/cpanel/',
            '/opt/hostinger/',
        ];
        foreach ( $safe_prefixes as $sp ) {
            if ( strpos( $abs_norm, $sp ) === 0 ) return 'safe';
        }

        // High-risk locations: any dropper using auto_prepend will park its
        // payload inside the WordPress tree (so a hosting password rotation
        // cannot kill it) or in /tmp.
        $abspath_norm = strtolower( str_replace( '\\', '/', rtrim( ABSPATH, '/\\' ) ) );
        if ( $abspath_norm !== '' && strpos( $abs_norm, $abspath_norm ) === 0 ) return 'critical';

        $critical_substrings = [
            '/wp-content/',
            '/wp-includes/',
            '/wp-admin/',
            '/tmp/',
            '/dev/shm/',
            '/var/tmp/',
        ];
        foreach ( $critical_substrings as $cs ) {
            if ( strpos( $abs_norm, $cs ) !== false ) return 'critical';
        }

        return 'review';
    }

    //  6c. Generic wp_options sweep for base64-encoded PHP (1.3.40) 
    //
    // Catches the family without needing a name match. Each ClickFix variant
    // stores its base64 payload under a per-variant option key
    // (wp_b6786d21cb_cfg, wp_a326b31e44_cfg, etc.). The current
    // malware_option_keys() catalogue lists the names we have seen, but the
    // next campaign will use a name we have not catalogued. This check
    // looks for the structural fingerprint instead: a long pure-base64
    // option_value whose decoded bytes contain a PHP marker or a JS opener
    // consistent with the family's encoded payload.

    /**
     * Find wp_options rows whose value is a long pure-base64 string that
     * decodes to PHP source or to the ClickFix family's outer JS loader.
     *
     * Skips:
     *   - option_name already on the known-malware list (option_anomalies
     *     already reports those)
     *   - WordPress core option names that legitimately store long values
     *
     * @return list<array<string, string>>
     */
    private static function check_unknown_base64_options(): array {
        global $wpdb;
        $findings = [];

        $known_bad = WPS_Indicators::malware_option_keys();
        // Core / framework option names that legitimately store long values.
        // Conservative list any not-listed option still passes through and is
        // judged on content, so a false negative here means more checks, not
        // missed detection.
        $core_safe_substrings = [
            'rewrite_rules',
            'cron',
            'active_plugins',
            'recently_activated',
            'theme_mods_',
            'widget_',
            'transient_',
            'site_transient_',
            'wp_user_roles',
            'wpseo_',         // Yoast
            '_wc_',           // WooCommerce
            'jetpack_',
            'akismet_',
            'wordfence_',
            'mailchimp_',
            'jp_sync_',
            'el_dashboard_data',
        ];

        // Pure-base64: only A-Z, a-z, 0-9, +, /, =. We require at least 200
        // chars and at most 200000 to avoid pulling massive blobs into memory.
        // We also LIMIT the candidate set to 60 rows; on a healthy site this
        // returns zero or a handful of legitimate hits (Akismet, etc.).
        $rows = $wpdb->get_results(
            "SELECT option_name, option_value, LENGTH(option_value) AS len
             FROM {$wpdb->options}
             WHERE LENGTH(option_value) BETWEEN 200 AND 200000
               AND option_value REGEXP '^[A-Za-z0-9+/=]+$'
             LIMIT 60",
            ARRAY_A
        );
        if ( ! is_array( $rows ) ) return [];

        foreach ( $rows as $r ) {
            $name = (string) $r['option_name'];
            if ( in_array( $name, $known_bad, true ) ) continue;

            $skip = false;
            foreach ( $core_safe_substrings as $needle ) {
                if ( strpos( $name, $needle ) !== false ) { $skip = true; break; }
            }
            if ( $skip ) continue;

            $decoded = @base64_decode( (string) $r['option_value'], true );
            if ( $decoded === false || $decoded === '' ) continue;

            $verdict = self::classify_decoded_option_blob( $decoded );
            if ( $verdict === '' ) continue;

            $findings[] = [
                'type'        => 'unknown_base64_option',
                'option_name' => $name,
                'length'      => (string) $r['len'],
                'verdict'     => $verdict, // 'php_payload' | 'clickfix_js'
                'preview'     => self::safe_decoded_preview( $decoded ),
                'action'      => 'Inspect manually before deleting; this option key is not on the known-bad list yet.',
            ];
        }

        return $findings;
    }

    /**
     * Decide whether a decoded option blob looks like a PHP payload or
     * the ClickFix family's JS outer loader. Returns '' for benign blobs.
     */
    private static function classify_decoded_option_blob( string $decoded ): string {
        // PHP payload: opener tag plus an executor or loader call.
        if ( ( strpos( $decoded, '<?php' ) !== false || strpos( $decoded, '<?=' ) !== false )
             && preg_match( '/eval\s*\(|base64_decode\s*\(|gzinflate\s*\(|file_put_contents\s*\(|shell_exec\s*\(|system\s*\(|passthru\s*\(|assert\s*\(/i', $decoded ) ) {
            return 'php_payload';
        }

        // ClickFix family's outer-JS shape: an IIFE that builds an array of
        // small ints and indexes into it via String.fromCharCode. We look for
        // the structural fingerprint, not for any specific token.
        if ( ( strpos( $decoded, '(function()' ) !== false || strpos( $decoded, '(function ()' ) !== false )
             && strpos( $decoded, 'String.fromCharCode' ) !== false
             && strpos( $decoded, 'new Function' ) !== false ) {
            return 'clickfix_js';
        }

        return '';
    }

    /**
     * 1.3.85: Re-validate a single LIVE option as a confirmed malicious base64
     * blob. Used by the automatic remediation path, which must not trust a
     * possibly-stale cached forensics report before deleting a DB row. Mirrors
     * the gating in check_unknown_base64_options(): same core/framework safe
     * skiplist, same length and pure-base64 constraints, same content classifier.
     * Returns the verdict ('php_payload'|'clickfix_js') or '' when the option is
     * gone, not pure-base64, on the safe list, or does not classify as a payload.
     */
    public static function confirm_base64_option_verdict( string $name ): string {
        if ( $name === '' ) {
            return '';
        }
        $core_safe_substrings = [
            'rewrite_rules', 'cron', 'active_plugins', 'recently_activated',
            'theme_mods_', 'widget_', 'transient_', 'site_transient_',
            'wp_user_roles', 'wpseo_', '_wc_', 'jetpack_', 'akismet_',
            'wordfence_', 'mailchimp_', 'jp_sync_', 'el_dashboard_data',
        ];
        foreach ( $core_safe_substrings as $needle ) {
            if ( strpos( $name, $needle ) !== false ) {
                return '';
            }
        }
        $value = get_option( $name, null );
        if ( ! is_string( $value ) || strlen( $value ) < 200 || strlen( $value ) > 200000 ) {
            return '';
        }
        if ( ! preg_match( '/^[A-Za-z0-9+\/=]+$/', $value ) ) {
            return '';
        }
        $decoded = @base64_decode( $value, true );
        if ( $decoded === false || $decoded === '' ) {
            return '';
        }
        return self::classify_decoded_option_blob( $decoded );
    }

    /** Build a redacted, length-bounded preview of a decoded option blob. */
    private static function safe_decoded_preview( string $decoded ): string {
        // Strip everything that is not printable ASCII so we never echo raw
        // exfil bytes or encoded credentials into the admin DOM.
        $printable = preg_replace( '/[^\x20-\x7E]+/', ' ', $decoded ) ?? '';
        $printable = trim( preg_replace( '/\s+/', ' ', $printable ) );
        if ( strlen( $printable ) > 160 ) {
            $printable = substr( $printable, 0, 157 ) . '...';
        }
        return $printable;
    }

    //  6d. Cron callback resolution (1.3.40) 
    //
    // The existing cron-hook check matches hook *names* against a substring
    // catalogue. The next campaign will use a hook name we have not seen.
    // This stronger check resolves every scheduled callback to the file/line
    // where the function or method is defined and flags any callback whose
    // source file lies outside expected WordPress directories, does not
    // exist, or already matches the active-malware signature list.

    /**
     * Walk every scheduled cron event, resolve each registered callback to
     * its source file with Reflection, and flag callbacks that point outside
     * core / plugin / theme / mu-plugin directories.
     *
     * @return list<array<string, string>>
     */
    private static function check_cron_callback_resolution(): array {
        if ( ! function_exists( '_get_cron_array' ) ) return [];
        $crons = _get_cron_array();
        if ( ! is_array( $crons ) ) return [];

        global $wp_filter;
        $findings = [];
        $expected_dirs = self::expected_callback_dirs();

        foreach ( $crons as $timestamp => $hooks ) {
            if ( ! is_array( $hooks ) ) continue;
            foreach ( $hooks as $hook => $args ) {
                if ( ! is_string( $hook ) ) continue;

                $callbacks = self::resolve_hook_callbacks( $hook, $wp_filter );
                foreach ( $callbacks as $cb ) {
                    $verdict = self::classify_callback_source( $cb['file'], $expected_dirs );
                    if ( $verdict === 'safe' ) continue;

                    $findings[] = [
                        'type'      => 'cron_callback_anomaly',
                        'hook'      => $hook,
                        'next_run'  => gmdate( 'Y-m-d H:i:s', (int) $timestamp ) . ' UTC',
                        'callback'  => $cb['signature'],
                        'source'    => $cb['file'] !== '' ? str_replace( ABSPATH, '', $cb['file'] ) : '(unresolvable)',
                        'verdict'   => $verdict,
                        'action'    => self::cron_finding_action( $hook, $verdict, (string) ( $cb['file'] ?? '' ) ),
                    ];
                }
            }
        }

        return $findings;
    }

    /**
     * Build the list of directories where a legitimate cron callback's
     * source file is expected to live.
     *
     * @return list<string>
     */
    private static function expected_callback_dirs(): array {
        $dirs = [
            rtrim( ABSPATH, '/\\' ) . '/wp-includes',
            rtrim( ABSPATH, '/\\' ) . '/wp-admin',
            WP_PLUGIN_DIR,
            WP_CONTENT_DIR . '/themes',
            WP_CONTENT_DIR . '/mu-plugins',
        ];
        $out = [];
        foreach ( $dirs as $d ) {
            $real = realpath( $d );
            if ( $real ) $out[] = str_replace( '\\', '/', $real );
        }
        return $out;
    }

    /**
     * Resolve every callback registered against a given hook name into a
     * { signature, file } pair using Reflection. Closures resolve to their
     * declaring file/line. String function names resolve via
     * ReflectionFunction. [class, method] pairs resolve via ReflectionMethod.
     *
     * @param mixed $wp_filter The WordPress global; may not exist in CLI bootstrap.
     * @return list<array{signature: string, file: string}>
     */
    private static function resolve_hook_callbacks( string $hook, $wp_filter ): array {
        $out = [];
        if ( ! is_array( $wp_filter ) && ! ( is_object( $wp_filter ) && isset( $wp_filter[ $hook ] ) ) ) {
            // Some bootstraps build $wp_filter as an array of WP_Hook instances.
            // Fall through if neither array nor object access works.
            return $out;
        }
        $hook_obj = $wp_filter[ $hook ] ?? null;
        if ( ! $hook_obj ) return $out;

        $callbacks_by_priority = is_object( $hook_obj ) && isset( $hook_obj->callbacks )
            ? $hook_obj->callbacks
            : ( is_array( $hook_obj ) ? $hook_obj : [] );

        foreach ( $callbacks_by_priority as $priority => $bucket ) {
            if ( ! is_array( $bucket ) ) continue;
            foreach ( $bucket as $cb_def ) {
                if ( ! is_array( $cb_def ) || ! isset( $cb_def['function'] ) ) continue;
                $resolved = self::reflect_callable( $cb_def['function'] );
                if ( $resolved !== null ) $out[] = $resolved;
            }
        }
        return $out;
    }

    /**
     * Reflect a single callable down to its source file and a printable
     * signature. Defensive: any reflection error returns null.
     *
     * @param mixed $callable Anything WordPress accepted as a callback.
     * @return array{signature: string, file: string}|null
     */
    private static function reflect_callable( $callable ): ?array {
        try {
            if ( $callable instanceof \Closure ) {
                $r = new \ReflectionFunction( $callable );
                return [
                    'signature' => 'Closure',
                    'file'      => (string) ( $r->getFileName() ?: '' ),
                ];
            }
            if ( is_string( $callable ) && strpos( $callable, '::' ) !== false ) {
                [ $cls, $mth ] = explode( '::', $callable, 2 );
                if ( class_exists( $cls ) && method_exists( $cls, $mth ) ) {
                    $r = new \ReflectionMethod( $cls, $mth );
                    return [ 'signature' => $cls . '::' . $mth, 'file' => (string) ( $r->getFileName() ?: '' ) ];
                }
            }
            if ( is_string( $callable ) ) {
                if ( ! function_exists( $callable ) ) return [ 'signature' => $callable . '()', 'file' => '' ];
                $r = new \ReflectionFunction( $callable );
                return [ 'signature' => $callable . '()', 'file' => (string) ( $r->getFileName() ?: '' ) ];
            }
            if ( is_array( $callable ) && count( $callable ) === 2 ) {
                [ $obj_or_cls, $mth ] = $callable;
                $cls = is_object( $obj_or_cls ) ? get_class( $obj_or_cls ) : (string) $obj_or_cls;
                if ( $cls === '' || ! method_exists( $cls, (string) $mth ) ) return null;
                $r = new \ReflectionMethod( $cls, (string) $mth );
                return [ 'signature' => $cls . '::' . $mth, 'file' => (string) ( $r->getFileName() ?: '' ) ];
            }
        } catch ( \ReflectionException $e ) {
            return null;
        }
        return null;
    }

    /**
     * WordPress core's own scheduled events. Deleting one of these is never
     * the remedy and is frequently harmful - dropping wp_version_check stops
     * the site checking for security updates, which trades a suspicious
     * callback for an unpatched WordPress.
     *
     * Core registers named functions on all of these. When something else has
     * attached itself, the schedule is not the problem and removing it does
     * not remove the attacker's code: whatever registers the callback simply
     * does so again on the next request, and now the core job is gone too.
     *
     * @return array<int, string>
     */
    private static function core_cron_hooks(): array {
        return [
            'wp_version_check', 'wp_update_plugins', 'wp_update_themes',
            'wp_scheduled_delete', 'wp_scheduled_auto_draft_delete',
            'delete_expired_transients', 'wp_privacy_delete_old_export_files',
            'recovery_mode_clean_expired_keys', 'wp_site_health_scheduled_check',
            'wp_https_detection', 'wp_update_user_counts', 'publish_future_post',
            'importer_scheduled_cleanup', 'upgrader_scheduled_cleanup', 'do_pings',
            'wp_delete_temp_updater_backups',
        ];
    }

    /**
     * 1.4.11: advice that matches the verdict AND the hook.
     *
     * Two things went wrong before this. Every non-unresolvable verdict got
     * the same "remove the cron event" instruction regardless of which hook it
     * was, including WordPress core's own. And a callback that exists only in
     * evaluated code - the most suspicious thing this check can find - was
     * given the same wording as a plugin living in an unusual folder.
     */
    private static function cron_finding_action( string $hook, string $verdict, string $file ): string {
        $is_core = in_array( $hook, self::core_cron_hooks(), true );

        if ( $verdict === 'evald_code' ) {
            $origin = trim( (string) preg_replace( "/\(\d+\)\s*:\s*eval\(\)'d code.*$/i", '', $file ) );
            return 'This handler exists only in evaluated code - there is no file on disk to inspect, because the function was created at runtime by eval(). '
                . ( $origin !== '' ? 'PHP reports it as having been evaluated from: ' . $origin . ' - start there. ' : '' )
                . 'A scheduled job whose handler has no file behind it is how persistence survives a file scan: the payload is stored somewhere else, usually a database option or an include appended to wp-config.php, and re-creates itself on every request. '
                . ( $is_core
                    ? 'Do NOT delete this cron event: ' . $hook . ' belongs to WordPress and removing it would break core functionality while leaving the code that attached to it untouched. '
                    : '' )
                . 'Find what performs the eval and remove that. To see the declaring file live, run: wp eval \'$h=$GLOBALS["wp_filter"]["' . $hook . '"]; foreach($h->callbacks as $p=>$c) foreach($c as $x){ $f=$x["function"]; if($f instanceof Closure){$r=new ReflectionFunction($f); echo $r->getFileName()."\n";}}\'';
        }

        if ( $verdict === 'unresolvable' ) {
            return 'Callback could not be resolved; the hook may rely on a class loaded from an unfamiliar path. Investigate manually'
                . ( $is_core ? ', and do not delete this event - ' . $hook . ' is a WordPress core job.' : '.' );
        }

        if ( $is_core ) {
            return 'Something other than WordPress has attached a handler to ' . $hook . ', which is one of core\'s own scheduled jobs, and its source is outside the expected directories. '
                . 'Do NOT delete this cron event - core needs it, and deleting it would not remove the handler anyway, because whatever registered it does so again on the next request. '
                . 'Identify the plugin or code that attaches to this hook and deal with that instead. Plenty of legitimate plugins extend core jobs, so confirm what it is before acting.';
        }

        return 'Source file is outside expected directories. Inspect the file, identify what registers this hook, and if it is not yours remove that code; the cron event itself can then be cleared with: wp cron event delete ' . $hook;
    }

    /** Decide whether a resolved callback file lives in an expected directory. */
    private static function classify_callback_source( string $file, array $expected_dirs ): string {
        if ( $file === '' ) return 'unresolvable';

        // 1.4.11: code with no file behind it. When a callback is a closure
        // declared inside eval()'d code, PHP reports the filename as
        // "/real/file.php(123) : eval()'d code" - a string realpath() can
        // never match, so this previously fell through to 'missing_file' and
        // was filed alongside benign resolution failures at medium severity.
        //
        // It is not benign. A scheduled event whose handler exists only in
        // evaluated code is running on a timer with nothing on disk to find,
        // which is the shape of persistence rather than the shape of a
        // plugin. The declaring file is preserved in the finding because the
        // part before the parenthesis names whatever performed the eval.
        if ( stripos( $file, "eval()'d code" ) !== false
            || stripos( $file, 'runtime-created function' ) !== false ) {
            return 'evald_code';
        }

        $real = realpath( $file );
        if ( ! $real ) return 'missing_file';
        $real = str_replace( '\\', '/', $real );

        // Hit on any malicious-cron substring -> always critical, regardless of dir.
        $low = strtolower( $real );
        foreach ( WPS_Indicators::malicious_cron_hook_substrings() as $bad ) {
            if ( strpos( $low, $bad ) !== false ) return 'malicious_substring';
        }
        // Hit on a known secondary backdoor filename -> critical.
        foreach ( WPS_Indicators::secondary_backdoor_filenames() as $bn ) {
            if ( strpos( $low, strtolower( $bn ) ) !== false ) return 'known_backdoor_filename';
        }

        foreach ( $expected_dirs as $d ) {
            if ( $d === '' ) continue;
            if ( strpos( $real, $d . '/' ) === 0 || $real === $d ) return 'safe';
        }
        return 'outside_expected_dirs';
    }

    //  7. PHP-executable filesystem checks 
    // These were previously listed as "SSH commands" but PHP can run them directly.

    private static function run_php_checks(): array {
        $checks = [];
        $abspath = rtrim( ABSPATH, '/\\' );
        $upload_base = wp_upload_dir()['basedir'] ?? ( WP_CONTENT_DIR . '/uploads' );

        //  Check 1: PHP files in uploads directory 
        $php_in_uploads = [];
        if ( is_dir( $upload_base ) ) {
            try {
                $iter = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator( $upload_base, FilesystemIterator::SKIP_DOTS ),
                    RecursiveIteratorIterator::LEAVES_ONLY
                );
                foreach ( $iter as $f ) {
                    if ( $f instanceof SplFileInfo && $f->getExtension() === 'php' ) {
                        $php_in_uploads[] = [
                            'path'     => $f->getPathname(),
                            'modified' => gmdate( 'Y-m-d H:i:s', $f->getMTime() ) . ' UTC',
                        ];
                    }
                }
            } catch ( \Exception $e ) {}
        }
        $checks[] = [
            'label'   => 'PHP files in uploads directory (should be zero)',
            'results' => $php_in_uploads,
            'count'   => count( $php_in_uploads ) . ' found',
        ];

        //  Check 2: PHP files modified more recently than wp-config.php 
        //
        // v1.2.1: Two-tier false-positive filter.
        //
        // Problem with a raw mtime comparison: any theme or plugin update
        // touches dozenshundreds of files simultaneously, all landing the
        // same Unix timestamp. That generates 200+ false positives in a
        // single scan while drowning out real findings.
        //
        // Tier 1  Mass-event suppression:
        //   Group flagged files by their exact mtime (Unix timestamp). If a
        //   bucket has  MASS_EVENT_THRESHOLD files, the whole bucket is
        //   treated as a plugin/theme/deploy update and suppressed. Real
        //   backdoors are planted individually; a legitimately suspicious
        //   mtime cluster never reaches that threshold.
        //
        // Tier 2  Content signal gate (for small clusters):
        //   Files whose mtime bucket is below the threshold are still only
        //   flagged if the file contains at least one high-risk PHP construct
        //   (eval, base64_decode, shell_exec, passthru, system). This catches
        //   individual backdrop drops while ignoring routine single-file edits
        //   such as a child-theme function addition.
        //
        // Together, these two tiers eliminate update-event noise while
        // preserving detection of individually planted backdoors.
        //
        // Comparable to: find ... -name "*.php" -newer wp-config.php
        // (but with signal gating to eliminate false positives)

        $mass_event_threshold = 5;

        // High-risk PHP constructs: rarely appear in legitimate theme/plugin
        // code, reliably indicate shell execution or code injection capability.
        $high_risk_signals = [
            'eval(',
            'base64_decode(',
            'shell_exec(',
            'passthru(',
            'system(',
        ];

        $recent_php   = [];
        $config_mtime = @filemtime( $abspath . '/wp-config.php' ) ?: ( time() - 604800 );
        $scan_dirs    = [
            WP_CONTENT_DIR . '/plugins',
            WP_CONTENT_DIR . '/themes',
            WP_CONTENT_DIR . '/mu-plugins',
            $upload_base,
        ];
        $self_dir = realpath( WPS_DIR );

        // Pass 1: collect every PHP file newer than wp-config.php.
        // Store raw mtime so we can group by bucket in pass 2.
        $candidates = []; // [ [ 'path'=>, 'mtime'=>, 'modified'=> ],  ]
        foreach ( $scan_dirs as $sd ) {
            if ( ! is_dir( $sd ) ) continue;
            try {
                $iter = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator( $sd, FilesystemIterator::SKIP_DOTS ),
                    RecursiveIteratorIterator::LEAVES_ONLY
                );
                foreach ( $iter as $f ) {
                    if ( ! ( $f instanceof SplFileInfo ) || $f->getExtension() !== 'php' ) continue;
                    $real = realpath( $f->getPathname() );
                    if ( $self_dir && $real && ( $real === $self_dir || WPS_Utils::path_is_inside( $real, WPS_DIR ) ) ) continue;
                    if ( $f->getMTime() > $config_mtime ) {
                        $candidates[] = [
                            'path'     => $f->getPathname(),
                            'mtime'    => $f->getMTime(),
                            'modified' => gmdate( 'Y-m-d H:i:s', $f->getMTime() ) . ' UTC',
                        ];
                    }
                }
            } catch ( \Exception $e ) {}
        }

        // Pass 2: bucket by mtime; apply tier-1 and tier-2 filters.
        $mtime_buckets = [];
        foreach ( $candidates as $c ) {
            $mtime_buckets[ $c['mtime'] ][] = $c;
        }

        foreach ( $mtime_buckets as $bucket_mtime => $bucket ) {
            // Tier 1: suppress mass-modification events (theme/plugin updates,
            // deploy scripts). A real backdoor is never planted in batches this
            // large with an identical timestamp.
            if ( count( $bucket ) >= $mass_event_threshold ) {
                // 1.4.29: report each suppressed batch ONCE.
                //
                // This previously wrote on every scan. The underlying file
                // mtimes do not change, so the same handful of facts were
                // re-recorded every time the scanner ran - and these go into
                // the tamper-evident store, which is capped. On a live site
                // scanning a few times an hour that was enough to flush every
                // real security event out of the retention window within
                // hours: the plugin quietly destroying its own evidence.
                //
                // Keyed on the batch's timestamp AND its size, so a batch that
                // genuinely grows is reported again rather than silenced.
                self::report_suppressed_batch_once( (int) $bucket_mtime, count( $bucket ), (int) $mass_event_threshold );
                continue;
            }

            // Tier 2: require at least one high-risk content signal.
            foreach ( $bucket as $c ) {
                if ( ! is_readable( $c['path'] ) ) continue;
                $contents = @file_get_contents( $c['path'] );
                if ( $contents === false ) continue;
                $signal_found = false;
                foreach ( $high_risk_signals as $signal ) {
                    if ( strpos( $contents, $signal ) !== false ) {
                        $signal_found = true;
                        break;
                    }
                }
                if ( $signal_found ) {
                    $recent_php[] = [
                        'path'     => $c['path'],
                        'modified' => $c['modified'],
                    ];
                }
            }
        }

        // Sort newest first.
        usort( $recent_php, fn( $a, $b ) => strcmp( $b['modified'], $a['modified'] ) );
        $checks[] = [
            'label'   => 'PHP files modified more recently than wp-config.php (possible backdoors)',
            'results' => array_slice( $recent_php, 0, 50 ),
            'count'   => count( $recent_php ) . ' found',
        ];

        //  Check 3: Known backdoor filenames anywhere under wp-content
        $backdoor_names = array_merge(
            [
                'class-wp-compat.php', 'session-manager.php', 'wp-backup-verify.php',
                'wc-report-handler.php', 'ms-file-router.php', 'wp-cache-stats.php',
                'form-cache-handler.php', 'class-cache-helper.php', 'wp-locale-handler.php',
                'object-cache-handler.php',  // v1.2.1: RAT confirmed in wp-content/cache/
            ],
            WPS_Indicators::secondary_backdoor_filenames() // 1.3.33: .sbs cookie-exfil toolkit
        );
        $known_backdoors = [];
        if ( is_dir( WP_CONTENT_DIR ) ) {
            try {
                $iter = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator( WP_CONTENT_DIR, FilesystemIterator::SKIP_DOTS ),
                    RecursiveIteratorIterator::LEAVES_ONLY
                );
                foreach ( $iter as $f ) {
                    if ( $f instanceof SplFileInfo && in_array( $f->getFilename(), $backdoor_names, true ) ) {
                        $known_backdoors[] = [
                            'path'     => $f->getPathname(),
                            'modified' => gmdate( 'Y-m-d H:i:s', $f->getMTime() ) . ' UTC',
                        ];
                    }
                }
            } catch ( \Exception $e ) {}
        }
        $checks[] = [
            'label'   => 'Known backdoor filenames found on disk',
            'results' => $known_backdoors,
            'count'   => count( $known_backdoors ) . ' found',
        ];

        //  Check 4: mu-plugins directory contents 
        $mu_files = [];
        $mu_dir   = WP_CONTENT_DIR . '/mu-plugins';
        if ( is_dir( $mu_dir ) ) {
            try {
                $iter = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator( $mu_dir, FilesystemIterator::SKIP_DOTS ),
                    RecursiveIteratorIterator::LEAVES_ONLY
                );
                foreach ( $iter as $f ) {
                    if ( $f instanceof SplFileInfo && $f->getExtension() === 'php' ) {
                        $mu_files[] = [
                            'path'     => $f->getPathname(),
                            'modified' => gmdate( 'Y-m-d H:i:s', $f->getMTime() ) . ' UTC',
                        ];
                    }
                }
            } catch ( \Exception $e ) {}
        }
        $checks[] = [
            'label'   => 'All PHP files in mu-plugins (should only be intentional must-use plugins)',
            'results' => $mu_files,
            'count'   => count( $mu_files ) . ' found',
        ];

        //  Check 5: Exfil credential file search 
        $exfil_targets = WPS_Indicators::exfil_filenames();
        $exfil_found   = [];
        if ( is_dir( WP_CONTENT_DIR ) ) {
            try {
                $iter = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator( WP_CONTENT_DIR, FilesystemIterator::SKIP_DOTS ),
                    RecursiveIteratorIterator::LEAVES_ONLY
                );
                foreach ( $iter as $f ) {
                    if ( $f instanceof SplFileInfo && in_array( $f->getFilename(), $exfil_targets, true ) ) {
                        $size = $f->getSize();
                        $lines = 0;
                        $handle = @fopen( $f->getPathname(), 'r' );
                        if ( $handle ) {
                            while ( ! feof( $handle ) ) {
                                fgets( $handle );
                                $lines++;
                            }
                            fclose( $handle );
                        }
                        $exfil_found[] = [
                            'path'     => $f->getPathname(),
                            'modified' => gmdate( 'Y-m-d H:i:s', $f->getMTime() ) . ' UTC',
                            'detail'   => $size . ' bytes, ' . $lines . ' credential lines',
                        ];
                    }
                }
            } catch ( \Exception $e ) {}
        }
        $checks[] = [
            'label'   => 'Credential exfil file (Stained_Heart_Red-600x500.png  fake PNG with harvested logins)',
            'results' => $exfil_found,
            'count'   => $exfil_found ? count( $exfil_found ) . ' found  delete immediately' : '0 found',
        ];

        return $checks;
    }

    //  8. SSH commands  only for things PHP cannot do (reading web server logs) 

    /**
     * 1.3.93: Re-dropper hunt. When a kit keeps reappearing under new random
     * names, the scanner removes it each pass but something outside it re-plants
     * it  and the likely vectors (a system crontab, a dropper outside the
     * WordPress install) are exactly the ones PHP cannot read: it has no shell and
     * open_basedir confines it to the site. These are read-only SSH commands to
     * find the re-dropper. The doorway/backdoor kit reuses the entry-stub names
     * canaryspillsdinky.php and unmadesuerscorker.php across drops, which gives a
     * precise account-wide search target.
     *
     * @return array<int, array{label:string, command:string}>
     */
    private static function build_redropper_hunt_commands(): array {
        return [
            [
                'label'   => 'List cron, user and system (the most common invisible re-dropper)',
                'command' => "crontab -l 2>/dev/null; echo '--- system ---'; cat /etc/crontab /etc/cron.d/* 2>/dev/null; cat /var/spool/cron/crontabs/* /var/spool/cron/* 2>/dev/null",
            ],
            [
                'label'   => 'Cron entries that run PHP, curl or wget (the dropper trigger)',
                'command' => "{ crontab -l 2>/dev/null; cat /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/* 2>/dev/null; } | grep -Ei \"php|curl|wget|base64\"",
            ],
            [
                'label'   => 'Find the kit and its reused stub files anywhere in your account',
                'command' => "find ~ -type f \\( -name 'canaryspillsdinky.php' -o -name 'unmadesuerscorker.php' -o -name 'backdor*.php' \\) -ls 2>/dev/null",
            ],
            [
                'label'   => 'Find any directory shaped like the kit (core/core.php)',
                'command' => "find ~ -type f -path '*/core/core.php' -ls 2>/dev/null",
            ],
            [
                'label'   => 'PHP files that embed the kit markers (this may be the re-dropper itself)',
                'command' => "grep -rliE \"canaryspillsdinky|unmadesuerscorker|IS_INCLUDED\" ~ --include='*.php' 2>/dev/null | head -30",
            ],
            [
                'label'   => 'PHP modified in the last 2 days across the whole account (not just the webroot)',
                'command' => "find ~ -name '*.php' -mtime -2 -ls 2>/dev/null | sort -k8,9 | tail -60",
            ],
        ];
    }

    private static function build_ssh_commands(): array {
        $upload_dir   = wp_upload_dir();
        $uploads_path = $upload_dir['basedir'] ?? ABSPATH . 'wp-content/uploads';
        $site_root    = ABSPATH;

        // Source the wp_<hex>_cfg option keys from the indicator catalogue rather
        // than hardcoding them, so the fallback commands stay current as new
        // variants are catalogued (the hardcoded list had drifted behind it).
        $cfg_keys = '';
        if ( class_exists( 'WPS_Indicators' ) && method_exists( 'WPS_Indicators', 'malware_option_keys' ) ) {
            $keys = array_values( array_filter(
                (array) WPS_Indicators::malware_option_keys(),
                static function ( $k ) { return is_string( $k ) && substr( $k, -4 ) === '_cfg'; }
            ) );
            $cfg_keys = implode( '|', $keys );
        }
        $slugs        = 'native-render-toolkit|total-render-profiler|total-render-toolkit|pro-font-optimizer|site-speed-insights|advanced-asset-insights|page-seo-toolkit|starter-image-guard|wp-locale-handler';
        $hijacker_pat = $slugs . ( $cfg_keys !== '' ? '|' . $cfg_keys : '' );

        return [
            [
                'label'   => 'Find the IP that uploaded known malware ZIPs (Apache)',
                'command' => "grep -E \"POST.*(wp-file-manager|elFinder|elfinder|connector|upload|admin-ajax|async-upload|update.php)\" /var/log/apache2/access.log | grep -Ei \"wp-perf-analytics|native-render-toolkit|total-render-profiler|total-render-toolkit|pro-font-optimizer|site-speed-insights|advanced-asset-insights|page-seo-toolkit|starter-image-guard|wp-locale-handler|session-manager|zip|plugin\" | tail -150",
            ],
            [
                'label'   => 'Find the IP that uploaded known malware ZIPs (nginx)',
                'command' => "grep -E \"POST.*(wp-file-manager|elFinder|elfinder|connector|upload|admin-ajax|async-upload|update.php)\" /var/log/nginx/access.log | grep -Ei \"wp-perf-analytics|native-render-toolkit|total-render-profiler|total-render-toolkit|pro-font-optimizer|site-speed-insights|advanced-asset-insights|page-seo-toolkit|starter-image-guard|wp-locale-handler|session-manager|zip|plugin\" | tail -150",
            ],
            [
                'label'   => 'Find render-hijacker plugin requests in Apache logs',
                'command' => "grep -R Ei \"{$hijacker_pat}\" /var/log/apache2/ 2>/dev/null | tail -100",
            ],
            [
                'label'   => 'Find render-hijacker plugin requests in nginx logs',
                'command' => "grep -R Ei \"{$hijacker_pat}\" /var/log/nginx/ 2>/dev/null | tail -100",
            ],
            [
                'label'   => 'Find when plugins were activated (WordPress admin actions)',
                'command' => "grep -E \"POST.*plugins\\.php.*action=activate\" /var/log/apache2/access.log | tail -50",
            ],
            [
                'label'   => 'Find all POST requests from suspect IPs (replace IP)',
                'command' => "grep \"^62.60.130\" /var/log/apache2/access.log | grep POST | tail -100",
            ],
            [
                'label'   => 'Find all POST requests from second suspect IP',
                'command' => "grep \"^185.203.28\" /var/log/apache2/access.log | grep POST | tail -100",
            ],

            [
                'label'   => 'Look for WP-antymalwary-bot C2 ping in logs (Cyprus server)',
                'command' => "grep -r \"wp-antymalwary\\|wpconsole\\|wp-performance-booster\" /var/log/apache2/ 2>/dev/null | head -20",
            ],
            [
                'label'   => 'Get full auth log for brute force source',
                'command' => "grep -E \"varuvlzh|domains@covert|Failed|Invalid\" /var/log/auth.log | tail -100",
            ],
        ];
    }

    /**
     * 1.3.92: In-plugin replacement for the "files modified in the attack window"
     * SSH find. Pure filesystem  no logs, no shell, no SSH. Lists the most
     * recently modified executable files under plugins, mu-plugins and uploads,
     * newest first, so a drop cluster (several files sharing a timestamp) is
     * visible right in the dashboard. Read-only and bounded.
     *
     * @return array{reference_mtime:int, files:list<array{path:string, mtime:int}>}
     */
    private static function recent_modified_executables(): array {
        $ref = 0;
        $cfg = rtrim( ABSPATH, '/\\' ) . '/wp-config.php';
        if ( is_file( $cfg ) ) {
            $ref = (int) @filemtime( $cfg );
        }

        $roots = [];
        if ( defined( 'WP_PLUGIN_DIR' ) )   $roots[] = WP_PLUGIN_DIR;
        if ( defined( 'WPMU_PLUGIN_DIR' ) ) $roots[] = WPMU_PLUGIN_DIR;
        if ( function_exists( 'wp_upload_dir' ) ) {
            $u = wp_upload_dir();
            if ( ! empty( $u['basedir'] ) ) $roots[] = $u['basedir'];
        }

        $exts  = [ 'php', 'phtml', 'php5', 'php7', 'phar', 'inc' ];
        $files = [];
        $count = 0;
        foreach ( array_unique( $roots ) as $root ) {
            if ( ! is_dir( $root ) ) continue;
            try {
                $it = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
                    RecursiveIteratorIterator::LEAVES_ONLY
                );
                foreach ( $it as $f ) {
                    if ( $count++ > 50000 ) break;
                    if ( ! ( $f instanceof SplFileInfo ) || ! $f->isFile() ) continue;
                    if ( ! in_array( strtolower( $f->getExtension() ), $exts, true ) ) continue;
                    $files[] = [ 'path' => $f->getPathname(), 'mtime' => (int) $f->getMTime() ];
                }
            } catch ( \Exception $e ) {} // phpcs:ignore
        }

        usort( $files, static function ( $a, $b ) { return $b['mtime'] <=> $a['mtime']; } );
        if ( count( $files ) > 100 ) {
            $files = array_slice( $files, 0, 100 );
        }

        return [ 'reference_mtime' => $ref, 'files' => $files ];
    }

    /**
     * WordPress core file integrity check (added v1.2.1).
     *
     * Fetches the official MD5 checksum list from api.wordpress.org for the
     * installed WP version and compares it against files on disk. Any core
     * file whose hash does not match is flagged  modified core files are a
     * reliable indicator of a persistent backdoor injected directly into
     * WordPress internals rather than a plugin or theme.
     *
     * Only core files are checked. Themes, plugins, uploads, and wp-config.php
     * are excluded (the scanner and the wp-config integrity monitor cover those).
     *
     * Results are cached for 24 hours to avoid hammering api.wordpress.org on
     * every forensics run.
     *
     * @return array{ status: string, version: string, modified: list<array>, error?: string }
     */
    private static function check_core_integrity(): array {
        $wp_version = self::get_wp_version();

        if ( $wp_version === '' ) {
            return [ 'status' => 'error', 'version' => 'unknown', 'modified' => [], 'error' => 'Could not determine WordPress version' ];
        }

        $checksums = self::get_core_checksums( $wp_version );
        if ( is_wp_error( $checksums ) ) {
            return [ 'status' => 'error', 'version' => $wp_version, 'modified' => [], 'error' => $checksums->get_error_message() ];
        }

        // Files to skip: wp-config.php (monitored separately), and any
        // file that legitimately differs across environments.
        $skip_prefixes = [
            'wp-config.php',
            'wp-config-sample.php',
            '.htaccess',
        ];

        $modified = [];
        $abspath  = rtrim( ABSPATH, '/\\' ) . '/';

        foreach ( $checksums as $relative_path => $expected_md5 ) {
            // Skip non-core paths (shouldn't appear in the API response, but guard)
            if ( strpos( $relative_path, 'wp-content/' ) === 0 ) continue;

            $skip = false;
            foreach ( $skip_prefixes as $prefix ) {
                if ( strpos( $relative_path, $prefix ) === 0 ) { $skip = true; break; }
            }
            if ( $skip ) continue;

            $full_path = $abspath . $relative_path;
            if ( ! file_exists( $full_path ) ) {
                // Missing core file  flag as modified/deleted
                $modified[] = [
                    'path'   => $relative_path,
                    'status' => 'missing',
                ];
                WPS_Logger::log_event( 'core_integrity_fail', "Missing: $relative_path" );
                continue;
            }

            $actual_md5 = md5_file( $full_path );
            if ( $actual_md5 !== $expected_md5 ) {
                $modified[] = [
                    'path'   => $relative_path,
                    'status' => 'modified',
                ];
                WPS_Logger::log_event( 'core_integrity_fail', "Modified: $relative_path" );
            }
        }

        return [
            'status'   => empty( $modified ) ? 'clean' : 'modified',
            'version'  => $wp_version,
            'modified' => $modified,
        ];
    }
}
