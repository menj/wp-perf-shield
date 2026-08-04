<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WPS_Blocker {

    private const IP_BLOCK_OPTION = 'wps_blocked_ips';
    private const IP_BLOCK_DAYS   = 7;
    /** A malware-uploading address that Akismet also knows as bad earns a longer hold (1.4.72). */
    private const IP_BLOCK_DAYS_KNOWN = 30;
    private const ZIP_PHP_SCAN_MAX_BYTES = 2097152;

    //  Pattern lists 

    /** @return string[] */
    public static function get_blocked_slugs(): array {
        $defaults = [
            // wp-perf-analytics family (Polygon blockchain ClickFix campaign)
            'wp-perf-analytics',
            'wp-performance-analytics',
            'wp-perf-monitor',
            'wp-site-analytics',
            'wp-page-analytics',
            'wp-perf-stats',
            // Render-hijacker ClickFix variants discovered May 2026
            'native-render-toolkit',
            'total-render-profiler',
            'total-render-toolkit',
            'pro-font-optimizer',
            'site-speed-insights',
            'advanced-asset-insights', // 1.3.37: Advanced Asset Insights / Cache Team disguise
            'page-seo-toolkit',        // 1.3.39: Page SEO Toolkit / Page Software disguise
            'starter-image-guard',     // 1.3.39: Starter Image Guard / Dev Group disguise
            'auto-content-profiler',   // 1.3.58: Auto Content Profiler / Pro Team disguise (variable-concat evasion variant)
            'pro-cache-scanner',       // 1.3.68: Pro Cache Scanner / Net IO disguise (Health_Proc_1e3d handler class)
            'total-database-optimizer', // 1.3.69: Total Database Optimizer / Cache Software disguise (WP_Manager_abc5, array-callback evasion)
            'site-security-toolkit',    // 1.4.49: Site Security Toolkit / Cache Solutions disguise (Core_Loader_c8fc, option wp_1f20bc3f7f_cfg) - catalogued 1.3.79, never blocked
            'auto-asset-helper',        // 1.4.49: Auto Asset Helper / WP Solutions disguise (Res_Helper_ad74) - catalogued 1.3.79, never blocked
            // session-manager  second plugin name confirmed in same campaign
            'session-manager',
            // WP-antymalwary-bot family
            'wp-antymalwary',
            'wpconsole',
            'wp-performance-booster',
            // wp-security-* user-hiding family (1.3.53)
            // Disguised as "WP Security Helper" by "WordPress Security Team" 
            // (same fake author as wp-security-cache.php  same operator chain).
            // Installs five filters (pre_get_users, users_list_table_query_args,
            // wp_count_users, get_users priority 999, all_plugins) that hide
            // every user except the currently-logged-in admin from the WP
            // dashboard, AND hide the plugin itself from the Plugins page
            // unless ?sp GET param is set. Pairs with wp-security-cache.php
            // to make malicious admin users invisible.
            'wp-security-helper',
        ];

        $saved = get_option( WPS_OPTION, [] );
        $extra = [];
        if ( ! empty( $saved['extra_slugs'] ) && is_string( $saved['extra_slugs'] ) ) {
            $extra = array_filter( array_map( 'trim', explode( "\n", $saved['extra_slugs'] ) ) );
            $extra = array_filter( array_map( 'sanitize_title', $extra ) );
        }

        return array_values( array_unique( array_merge( $defaults, $extra ) ) );
    }

    //  Site-policy plugin denylist (1.4.62)

    /**
     * Plugins refused by site policy rather than by malware detection.
     *
     * These are not malware. They are ordinary plugins the operator has
     * decided must never run on this site while WP Perf Shield is active. WP
     * File Manager hands full filesystem access to anyone who reaches the
     * dashboard and carries a history of critical remote-code-execution holes
     * (the CVE-2020-25213 lineage), which makes it a standing post-compromise
     * foothold; FileBird is refused here as an operator preference, nothing
     * more.
     *
     * The separation from the malware list above is the point. Routing these
     * through `is_blocked()` would log them as "matches a known malicious
     * pattern" - untrue, and a lie the tamper-evident event log would then
     * carry forever. This path labels every refusal as a policy decision, and
     * never adds the uploader's address to the hostile-IP list, because an
     * administrator uploading a plugin they are not allowed to run is not an
     * attacker.
     *
     * Built-in defaults, plus one operator-managed slug per line from Settings.
     *
     * @return string[]
     */
    public static function get_policy_banned_slugs(): array {
        $defaults = [
            'wp-file-manager', // full-filesystem file manager; CVE-2020-25213 lineage
            'filebird',        // media-library folder organiser; operator preference
        ];

        $saved = get_option( WPS_OPTION, [] );
        $extra = [];
        if ( is_array( $saved ) && ! empty( $saved['policy_banned_slugs'] ) && is_string( $saved['policy_banned_slugs'] ) ) {
            $extra = array_filter( array_map( 'trim', explode( "\n", $saved['policy_banned_slugs'] ) ) );
            $extra = array_filter( array_map( 'sanitize_title', $extra ) );
        }

        return array_values( array_unique( array_merge( $defaults, $extra ) ) );
    }

    /**
     * On by default. The whole policy denylist can be switched off from
     * Settings without clearing the list, so a control that has no legitimate
     * off state does not become one.
     */
    public static function policy_ban_enabled(): bool {
        $s = get_option( WPS_OPTION, [] );
        return ! is_array( $s ) || ( $s['policy_ban_enabled'] ?? '1' ) !== '0';
    }

    /**
     * Is this plugin file refused by site policy? Folder/slug substring match
     * only - these are named plugins, so testing the plugin path against the
     * list is the whole of it. No hashes, no payload signatures: nothing here
     * is malware, and pretending otherwise would be the mistake this method
     * exists to avoid.
     */
    public static function is_policy_banned( string $plugin_file ): bool {
        if ( ! self::policy_ban_enabled() ) {
            return false;
        }
        $lower = strtolower( $plugin_file );
        foreach ( self::get_policy_banned_slugs() as $slug ) {
            if ( $slug !== '' && strpos( $lower, $slug ) !== false ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Does this upload carry a policy-banned plugin? The upload filename is
     * matched as a substring (so a renamed `wp-file-manager-copy.zip` is still
     * caught), and for a ZIP each entry is matched as a path segment, so a
     * plugin whose own code merely mentions `filebird` in a filename is not a
     * false hit. Content is never hashed or signature-scanned here: the folder
     * name is the entire test.
     */
    private static function policy_upload_match( string $filename, array $file ): string {
        $slugs = self::get_policy_banned_slugs();
        $name  = strtolower( $filename );

        foreach ( $slugs as $slug ) {
            if ( $slug !== '' && strpos( $name, $slug ) !== false ) {
                return 'file=' . self::short_log_value( $filename );
            }
        }

        if ( ! self::is_zip_file( $filename ) || ! class_exists( 'ZipArchive' ) ) {
            return '';
        }

        $tmp_name = (string) ( $file['tmp_name'] ?? '' );
        if ( $tmp_name === '' || ! is_readable( $tmp_name ) ) {
            return '';
        }

        $zip = new ZipArchive();
        if ( $zip->open( $tmp_name ) !== true ) {
            return '';
        }

        try {
            $count = min( (int) $zip->numFiles, 500 );
            for ( $i = 0; $i < $count; $i++ ) {
                $stat = $zip->statIndex( $i );
                if ( ! is_array( $stat ) ) {
                    continue;
                }
                $entry = strtolower( str_replace( '\\', '/', (string) ( $stat['name'] ?? '' ) ) );
                if ( $entry === '' ) {
                    continue;
                }
                foreach ( $slugs as $slug ) {
                    if ( $slug === '' ) {
                        continue;
                    }
                    // Path-segment match: the plugin folder itself, not an
                    // incidental mention inside some other plugin's filename.
                    if ( $entry === $slug
                        || strpos( $entry, $slug . '/' ) === 0
                        || strpos( $entry, '/' . $slug . '/' ) !== false
                    ) {
                        return 'entry=' . self::short_log_value( $entry );
                    }
                }
            }
        } finally {
            $zip->close();
        }

        return '';
    }

    /** @return string[] */
    private static function get_patterns(): array {
        return [
            // wp-perf-analytics + random hex/alnum suffix
            '/wp-perf-analytics[-_][a-z0-9]{3,8}\//i',
            '/wp-perf-analytics[-_][a-z0-9]{3,8}\.php$/i',
            '/wp-performance-analytics[-_][a-z0-9]{3,8}\//i',
            '/native-render-toolkit[-_][a-z0-9]{3,8}\//i',
            '/native-render-toolkit[-_][a-z0-9]{3,8}\.php$/i',
            '/total-render-profiler[-_][a-z0-9]{3,8}\//i',
            '/total-render-profiler[-_][a-z0-9]{3,8}\.php$/i',
            '/total-render-toolkit[-_][a-z0-9]{3,8}\//i',
            '/total-render-toolkit[-_][a-z0-9]{3,8}\.php$/i',
            '/pro-font-optimizer[-_][a-z0-9]{3,8}\//i',
            '/pro-font-optimizer[-_][a-z0-9]{3,8}\.php$/i',
            '/site-speed-insights[-_][a-z0-9]{3,8}\//i',
            '/site-speed-insights[-_][a-z0-9]{3,8}\.php$/i',
            '/advanced-asset-insights[-_][a-z0-9]{3,8}\//i',
            '/advanced-asset-insights[-_][a-z0-9]{3,8}\.php$/i',
            '/page-seo-toolkit[-_][a-z0-9]{3,8}\//i',
            '/page-seo-toolkit[-_][a-z0-9]{3,8}\.php$/i',
            '/starter-image-guard[-_][a-z0-9]{3,8}\//i',
            '/starter-image-guard[-_][a-z0-9]{3,8}\.php$/i',
            '/auto-content-profiler[-_][a-z0-9]{3,8}\//i',     // 1.3.58
            '/auto-content-profiler[-_][a-z0-9]{3,8}\.php$/i', // 1.3.58
            '/pro-cache-scanner[-_][a-z0-9]{3,8}\//i',         // 1.3.68
            '/pro-cache-scanner[-_][a-z0-9]{3,8}\.php$/i',     // 1.3.68
            '/total-database-optimizer[-_][a-z0-9]{3,8}\//i',     // 1.3.69
            '/total-database-optimizer[-_][a-z0-9]{3,8}\.php$/i', // 1.3.69
            '/site-security-toolkit[-_][a-z0-9]{3,8}\//i',        // 1.4.49
            '/site-security-toolkit[-_][a-z0-9]{3,8}\.php$/i',    // 1.4.49
            '/auto-asset-helper[-_][a-z0-9]{3,8}\//i',            // 1.4.49
            '/auto-asset-helper[-_][a-z0-9]{3,8}\.php$/i',        // 1.4.49
            // 1.4.50: the theme-loader / RC4 JS injector family names itself
            // `Plugin-<8 hex>` rather than using a fixed slug, so it cannot live
            // in the slug list above - the name IS the shape. Two confirmed
            // samples: Plugin-7e4eb3ff (1.3.79) and Plugin-390a770b (1.4.36).
            // Exactly eight hex digits, so `Plugin-7e4eb3` and `Plugin-7e4eb3ff9`
            // do not match, and neither does an ordinary slug like
            // `plugin-directory`.
            '/(^|\/)Plugin-[0-9a-f]{8}\//i',                       // 1.4.50
            '/(^|\/)Plugin-[0-9a-f]{8}\.php$/i',                   // 1.4.50
            '/^languages\/wp-locale-handler\.php$/i',
            // session-manager + random suffix (second known campaign plugin)
            '/session-manager[-_][a-z0-9]{3,8}\//i',
            '/session-manager[-_][a-z0-9]{3,8}\.php$/i',
        ];
    }

    /**
     * Built-in MD5 hashes of confirmed malicious plugin files.
     * These are hardcoded so protection works immediately on install,
     * even if a variant renames itself but keeps the same payload.
     *
     * @return string[]
     */
    private static function get_blocked_hashes(): array {
        $builtin = [
            //  wp-perf-analytics / ClickFix family 
            '75d1b8c91600379dea5791920c192b0c', // XOR 60, v1.2.4
            'cdec71647d65e4e6542c19848e07e7bd', // XOR 84, v1.2.66 (8760 variant)
            'cefca0da4afd2816bfada89236e5011a', // XOR 113, v1.2.19 (91c6 / 9b4c variants)
            'cf0c1086cca734bbb7038f5ad9e907d5', // XOR 114, v1.2.97 (d2e9 variant)
            'c1783b8b92b0a53a65f888af75a1d688', // XOR 237, v1.2.83 (latest variant)
            '678899f67c9561f4b88d28952189467c', // native-render-toolkit-9401.php
            '06b7dc4813bdd9575bab106451b015de', // total-render-profiler-3753.php
            '0e34f31fac8662886303225484dd648a', // total-render-toolkit-adae.php
            '99c53e189239269f0197802306af236a', // pro-font-optimizer-c88b.php
            '6f6b4854cb0d71f81796ead56132c89a', // site-speed-insights-d6e7.php
            '7dbc51fa960a74a79bd2cb475a2dfd04', // advanced-asset-insights-ec06.php (1.3.37)
            'a23f9c0fb1eb85247d0f4a8264bd9c18', // page-seo-toolkit-a937.php (1.3.39)
            'bb398fb4783c7fc3647a633b51811099', // starter-image-guard-e9a2.php (1.3.39)
            'c87d8c472f827704a2ef6beb997729ff', // auto-content-profiler-0b8d.php (1.3.58, variable-concat evasion variant)
            '15e17041c615dc272d5cd5ac3bcd5d6f', // pro-cache-scanner-6d52.php (1.3.68)
            '80322b56aaec6af92d392f8daa36aee7', // total-database-optimizer-9a95.php (1.3.69, array-callback evasion variant)
            '608576a9322aab3585fe7e7eb109f368', // site-security-toolkit-1f30.php (1.4.49, 9,674 bytes, hashed from the sample in hand)
            '73f07f1438b9a710b5bf1893186d1e67', // Plugin-7e4eb3ff.php (1.4.50, 130,672 bytes, hashed from the sample in hand)
            '7bbf81ab731b59b3c0fed628c1f3cf3d', // auto-asset-helper-2763.php (1.4.53, 10,739 bytes, hashed from the sample in hand - the entry 1.4.49 deliberately left out)
            'ab86726bb8ed4527cb6ea787f9a12c1a', // Plugin-b45b652c.php (1.4.57, 129,503 bytes, hashed from the sample in hand)
            '748f6d05c328364ebf6a0cec1aec350d', // Plugin-45e0930c.php (1.4.58, 127,542 bytes, hashed from the sample in hand)
            'b86b46e36620c041a5033a8191b05f1fb744f0451beb5b9d639463de1d46d664', // SHA-256, XOR 60
            // 1.4.51: a 65-character entry sat here labelled "SHA-256, XOR 84".
            // SHA-256 is 64 characters, so it could never equal any hash and had
            // been dead since it was added. It is removed rather than corrected:
            // the XOR-84 sample is not held, and guessing which character was
            // spurious would be inventing a fingerprint. That build stays covered
            // by its MD5 (cdec71647d65e4e6542c19848e07e7bd) and by the structural
            // ClickFix checks, which never depended on this entry.
            '2a5b7a6602bc5bace45131153d665554b36404d7c40b72e7c56e06c9a6f7d15d', // SHA-256, XOR 113
            '8effe4bd104ee4716ae3fb975b6b6e37069f347dfe09c0569f9aea0c77c8a789', // SHA-256, XOR 114
            '0df2fa44c40cc0ae76fa32ebf756cfe3c4614f80a90dd8290b061d433dedc27b', // SHA-256 native-render-toolkit-9401.php
            'c403d603a0345e904d8c6bc27565905817f602647a86eab205713e0cb849a37c', // SHA-256 total-render-profiler-3753.php
            'c22bbb5144d71de9ece4c8cf52db0e9f79b70f7e77f0064fa9e06753b340f541', // SHA-256 total-render-toolkit-adae.php
            '751b9848b645f5e7ab72eab015ea6743284657cfdcfc844a9c06081400ded3b6', // SHA-256 pro-font-optimizer-c88b.php
            '9b5cc2de2e2cd968c5f69a0a6d561b37d31424f3f8c814d11a7404cc4a5bcaa8', // SHA-256 site-speed-insights-d6e7.php
            'ff96b828b345755c728cebbf3fc041290f14f12a535f693d06b520d89d106e3b', // SHA-256 advanced-asset-insights-ec06.php (1.3.37)
            'ee4b899d93655e4fc15b6ed8692a25e3b4052a005f85c5460d22a444e4245b9e', // SHA-256 page-seo-toolkit-a937.php (1.3.39)
            'acf2aaf34ceac250b03c77ab2afa221f3290508b7f876209ab332830d0ae4105', // SHA-256 starter-image-guard-e9a2.php (1.3.39)
            'd7ec2991f822bc9d8811526f83e84dad6002d8ca8471fd3a763f40252e59ea32', // SHA-256 auto-content-profiler-0b8d.php (1.3.58)
            '894108561a3b5be93a76ce2bda74602ed5b5305649aae65b43460565ca220201', // SHA-256 pro-cache-scanner-6d52.php (1.3.68)
            '1e5992209203641e6b12b309596c1eb87a46c985eded099214ea036eb316adb3', // SHA-256 total-database-optimizer-9a95.php (1.3.69)
            '3bb3738a66d94f5b5020fab817afd4fd94bbe6e11cbdaa477eec49d27a555ae9', // SHA-256 site-security-toolkit-1f30.php (1.4.49)
            'eb45ec5c13b35b4589047550e41656f5395aeb3e33b610fdd60d1473f0f3e642', // SHA-256 Plugin-7e4eb3ff.php (1.4.50)
            'de3bc67ff123719c1fa36e6d86b960f007290d84f23d4b79d39610c177cda451', // SHA-256 auto-asset-helper-2763.php (1.4.53)
            'ee72a3a0c968e3248df20d48e0c2d954e184c37fa7c283bb0625c5249448d31e', // SHA-256 Plugin-b45b652c.php (1.4.57)
            'dfe3321053f7577873b4b15d03ad40318656096c9d0280ce4aebc3cef192da66', // SHA-256 Plugin-45e0930c.php (1.4.58)

            //  Second-stage PHP backdoors (RCE + credential harvester)
            '9c77bbb0998b95f0562800b6086dd11e', // wp-backup-verify.php
            'e76d6d119445032e72e85ad52a6d83ef', // wc-report-handler.php
            'd2c9540df466434c7658d7956c5c833d', // wp-locale-handler.php

            //  Second-stage backdoors  v2 builds (same family, new hashes)
            '7d67b8a2edff4735d5dce83b7bfe3eee', // wp-backup-verify.php (v2)
            '3013ade690ede0070a4b028bec82bb6b', // wc-report-handler.php (v2)
            '70358bb32a2cf6fcbfc9edfe2848a579', // wp-locale-handler.php (variant 2026-05, muslim-apologetic-borneo XOR seed)
            '2860c80dac6f04344f9f29e306e3c88ceee14a97bb2d96bddeba83846da361f7', // SHA-256, same variant

            //  .sbs cookie-exfil + persistent-admin toolkit (added 1.3.33)
            // Container: .wp-config-cache.zip. Three files; each one ships independently in
            // some uploads so all three hashes are blocked individually.
            '2d746471df530568e76e280c6dec8c2d', // .wp-config-cache.php (cookie exfil to webanalytics-cdn.sbs)
            '3d945139f3c530f3dc872c6be10cc092fded2f92e77d3af9f4be76186197d277', // SHA-256
            '54b60e56a90d0ed4b8a4de79c0916193', // wp-security-cache.php (creates admin a7f3e9b2c4d1e5f6)
            '4e7fb5e61f8c0f1bdfbbb32d755706f81b55dda49ef7cacca87c9f5afaf002b0', // SHA-256
            'cd35f8c14a03fecba0b72e67804dd337', // wp-phpunit.php (5-fallback webshell, ?c=<base64>)
            '15144ebc1baaf5a46466cc2dfe7ca1e18f2c20363cf15b4ff73861648cc62efe', // SHA-256

            //  Standalone PHP file manager / webshell (added 1.3.36)
            // Independent campaign  separate session cookie (UMSESSID), separate
            // hardcoded credentials (admin/adminpass), full filesystem access at
            // DOCUMENT_ROOT scope, includes a setmtime action specifically for
            // forensic-timeline evasion (treat on-disk mtimes as untrustworthy
            // when this file or a rename of it is present).
            '8a92828554a087c46cc21c87fd1b15d4', // wp-default.php
            '673806e0aadc67be107217cc0e3dcf12486022fe39150ee09494236d317ee02d', // SHA-256
            //  New disguise filenames discovered April 2026 
            'bede133bf2bd823b6b3c14c19db482ea', // ms-file-router.php  (Multisite File Router)
            'd5eae8a8a0b9dc9099a92b5aceae883f', // wp-cache-stats.php  (Cache Statistics Handler)
            '6c862aabe3680ec9f4b03fbad7313f1a57b1c9d7a6f199f2ab503b28319cafab', // SHA-256 wp-locale-handler.php
            //  RAT family v1.7  hidden in .well-known/pki-validation/ (added 1.3.44) 
            // Same family as wp-locale-handler.php; rebranded with cert-check.php
            // basename and parked in the IETF .well-known/ directory at the web
            // root because most security plugins exclude .well-known/ to avoid
            // breaking ACME challenges. The XOR seed in the credential-harvester
            // payload is the XOR seed for the victim-site domain
            // (themuslimapologist.online for this build), so each victim
            // site receives a custom-built binary keyed against its own
            // domain.
            'd75140a8db6edc1147f826b7eec30812', // cert-check.php (RAT v1.7, themuslimapologist.online build)
            '7e1f7a9b622f3cc7941cf6a36c6f23682e02191ae430ccd24cb3ac5cb1d8eb82', // SHA-256
            //  Polymorphic siblings  same RAT, different victim sites (added 1.3.45) 
            // Same byte-identical wrapper across all four; only the XOR-seed
            // victim-site domain differs (~12 byte delta). Signature-
            // based detection (a3f8b2c1d4e5f607 + HMAC tail + Ci8v...
            // encoded harvester strings) catches new builds without
            // requiring a hash entry per victim site.
            '3e92c07fa807bcc3a1754c9ba3d1c142', // cert-check.php (RAT v1.7, bestofislam.com build)
            '95f0ad704e7e163b288373a94520d881b830e9d127ea1f75d72e281d56711c23', // SHA-256
            'a667e49c601d874cbacc40e158bb56c1', // cert-check.php (RAT v1.7, bismikaallahuma.org build)
            'c374f8f34b136a5021cbf0da1e1e760c5b29c430c4c49a6722c863eabfedf583', // SHA-256
            '8203c5bb61b21777519bef3af299842d', // cert-check.php (RAT v1.7, compelling-evidence.com build)
            'fba50e891764d1b8a6f7e7e2887df1d568fd818ff2e22b8db8372ffd32bfcd53', // SHA-256
            'c053446a3916beb41df3e3428c085a3c', // cert-check.php (RAT v1.7, muslim-apologetic-borneo.com build, added 1.3.59)
            '0c1d67c3d5036b5ced4f761d05326b8a3e98946ca89fb5fc0bd276c0b095cff0', // SHA-256
            //  RAT family v1.7  caught at canonical languages/ location (added 1.3.49) 
            // Same family signatures as the cert-check.php variants. The
            // file lives at wp-content/languages/wp-locale-handler.php on the
            // victim site (same canonical location that gave the family its
            // original name). XOR seed = bestofislam.com  same operator
            // target as one of the 1.3.45 cert-check.php samples, confirming
            // the operator reuses one binary across multiple victim sites.
            'a4f6a499ea1c34ae15dcf108e0fa197b', // wp-locale-handler.php (RAT v1.7, bestofislam.com build, languages/ location)
            'bae6d2e4f396b9610c11a839a9ffc9740033c7d7a482d5310af63cc45351979b', // SHA-256
            //  TDS drive-by injector family  separate malware (added 1.3.49) 
            // Disguised as "Theme JS Injector / TJI Site JavaScript" mu-plugin.
            // Injects JS on every front-end pageview (skips admin/AJAX/cron/JSON
            // for stealth), routes traffic through ntdnewtds.shop/jsrepo and
            // dnsnewtds.shop/jsrepo TDS infrastructure. NOT related to the
            // wp-locale-handler RAT family despite living on the same victim
            // site  this is a co-infection by a different operator chain
            // (or the same operator running multiple monetisation streams).
            '47ff560f2c1096757cbfad5291ccc959', // tji-site-js.php (TDS injector mu-plugin)
            '1d2699149bbb1f523cd914cbe2025de77e00dd58dedd11eaded9a04b01246d50', // SHA-256
            //  User-hiding filter installer family (added 1.3.53) 
            // wp-security-helper.php  installs five WP filters that hide every
            // user except the currently-logged-in admin from the dashboard,
            // and hides the plugin itself from the Plugins page unless ?sp
            // GET param is set. Disguises as "WP Security Helper" by
            // "WordPress Security Team" (same fake author as wp-security-cache.php
            //  confirms same operator chain). Hex/octal-obfuscated filter
            // names + goto-flow obfuscation to evade static analysis. The
            // 1.3.52 hidden-admin-user check (direct $wpdb walk bypassing
            // get_users() filters) catches the SYMPTOM regardless of whether
            // this specific installer or a different one is in use; the
            // hash and signature additions below catch this specific build.
            '50c02424e0e723c019b4d2bf849f2a9b', // wp-security-helper.php
            '0a26e477951896659dbc5b0b18929995303a9ab4e071288b40691e0b366b96a1', // SHA-256
            //  Credential exfil file (fake PNG, contains harvested logins) 
            'b466fa4c2fac736d65b343d47fd0e1d1', // Stained_Heart_Red-600x500.png (416-line)
            '09a86e4696b21391d3911b0b64a50c48', // Stained_Heart_Red-600x500.png (63-line, live)
        ];

        // Merge with user-added hashes from the settings UI
        $saved = get_option( WPS_OPTION, [] );
        $extra = [];
        if ( ! empty( $saved['extra_hashes'] ) && is_string( $saved['extra_hashes'] ) ) {
            $extra = array_filter( array_map( 'trim', explode( "\n", $saved['extra_hashes'] ) ) );
            $extra = array_filter( $extra, static function ( string $hash ): bool {
                return (bool) preg_match( '/^[a-f0-9]{32}$/i', $hash )
                    || (bool) preg_match( '/^[a-f0-9]{64}$/i', $hash );
            } );
            $extra = array_map( 'strtolower', $extra );
        }

        return array_values( array_unique( array_merge( $builtin, $extra ) ) );
    }

    //  Core check 

    public static function is_blocked( string $plugin_file ): bool {
        $lower = strtolower( $plugin_file );

        foreach ( self::get_blocked_slugs() as $slug ) {
            if ( strpos( $lower, strtolower( $slug ) ) !== false ) {
                return true;
            }
        }

        foreach ( self::get_patterns() as $pattern ) {
            if ( preg_match( $pattern, $plugin_file ) ) {
                return true;
            }
        }

        $hashes = self::get_blocked_hashes();
        if ( $hashes ) {
            $abs = WP_PLUGIN_DIR . '/' . $plugin_file;
            if ( file_exists( $abs ) ) {
                $md5    = md5_file( $abs );
                $sha256 = hash_file( 'sha256', $abs );
                if (
                    ( $md5 !== false && in_array( $md5, $hashes, true ) )
                    || ( $sha256 !== false && in_array( $sha256, $hashes, true ) )
                ) {
                    return true;
                }
            }
        }

        return false;
    }

    //  WordPress hooks 

    /** Called from main plugin file, not from class-blocker.php directly. */
    public static function register_hooks(): void {
        add_filter( 'plugin_action_links',              [ self::class, 'remove_activate_link'  ], 10, 2 );
        add_action( 'activate_plugin',                  [ self::class, 'block_on_activate'     ], 1,  1 );
        add_filter( 'pre_update_option_active_plugins', [ self::class, 'filter_active_plugins' ] );
        add_filter( 'pre_update_site_option_active_sitewide_plugins', [ self::class, 'filter_sitewide_plugins' ] );
        add_action( 'plugins_loaded',                   [ self::class, 'scrub_active_list'     ], 1    );
        add_action( 'plugins_loaded',                   [ self::class, 'scrub_sitewide_active_list' ], 1 );
        add_action( 'upgrader_process_complete',        [ self::class, 'after_upgrade'         ], 10, 2 );
        add_filter( 'wp_handle_upload_prefilter',       [ self::class, 'block_zip_upload'      ] );
    }

    public static function maybe_block_request(): void {
        if ( PHP_SAPI === 'cli' || defined( 'WP_CLI' ) ) {
            return;
        }

        if ( ! self::auto_ip_block_enabled() ) {
            return;
        }

        $ip = self::client_ip();
        if ( $ip === '' ) {
            return;
        }

        $blocked = self::get_blocked_ips();
        if ( empty( $blocked[ $ip ] ) ) {
            return;
        }

        $detail = $blocked[ $ip ];

        // Self-block recovery (1.3.32): a logged-in administrator who shares
        // an IP with the upload-block trigger (most commonly: the admin
        // themselves did the upload that triggered the block, or both
        // requests came from the same NAT/VPN egress) is allowed through to
        // admin so they can clear the list from Settings  Danger zone or the
        // top-of-admin recovery notice rendered below. The IP auto-block
        // targets unauthenticated upload scripts; an attacker who already
        // holds admin credentials does not gain anything by also dodging the
        // IP block. wp-login.php is still rejected for blocked IPs, so this
        // does not weaken brute-force defence.
        if ( is_user_logged_in() && current_user_can( 'manage_options' ) ) {
            $self_log_key = 'wps_self_block_logged_' . md5( $ip );
            if ( ! get_transient( $self_log_key ) ) {
                $user = wp_get_current_user();
                WPS_Logger::log_event(
                    'self_block_bypassed',
                    $ip . ' admin=' . ( $user ? $user->user_login : '?' ),
                    $ip
                );
                set_transient( $self_log_key, 1, HOUR_IN_SECONDS );
            }
            add_action( 'admin_notices',         [ self::class, 'render_self_block_notice' ] );
            add_action( 'network_admin_notices', [ self::class, 'render_self_block_notice' ] );
            return;
        }

        $cache_key = 'wps_ip_request_blocked_' . md5( $ip );
        if ( ! get_transient( $cache_key ) ) {
            WPS_Logger::log_event(
                'ip_request_blocked',
                $ip . ' reason=' . ( $detail['reason'] ?? 'malware upload attempt' ),
                $ip
            );
            set_transient( $cache_key, 1, HOUR_IN_SECONDS );
        }

        wp_die(
            '<h2>Request blocked by WP Perf Shield</h2><p>This address has been blocked for abusive activity.</p>',
            'Request Blocked',
            [ 'response' => 403 ]
        );
    }

    /**
     * Render the self-block recovery notice on every admin page (1.3.32).
     *
     * Surfaces an actionable message when an authenticated administrator hits
     * a hostile-IP auto-block. The Clear button calls the existing
     * wps_clear_ip_blocks AJAX handler. JavaScript is inlined here because
     * assets/js/admin.js is enqueued only on the WP Perf Shield admin screen,
     * and this notice must work on every admin page where the admin lands
     * first.
     */
    public static function render_self_block_notice(): void {
        // 1.3.95: behaviour lives in admin.js (no inline script). Enqueue the
        // plugin bundle for this notice wherever it renders.
        wp_enqueue_script( 'wps-admin', WPS_URL . 'assets/js/admin.js', [ 'jquery' ], WPS_VERSION, true );
        wp_enqueue_style( 'wps-admin', WPS_URL . 'assets/css/admin.css', [], WPS_VERSION );
        wp_localize_script( 'wps-admin', 'WPS_ADMIN', [
            'nonce'   => wp_create_nonce( 'wps_nonce' ),
            'ajaxUrl' => admin_url( 'admin-ajax.php' ),
        ] );
        $ip           = self::client_ip();
        $nonce        = wp_create_nonce( 'wps_nonce' );
        $ajax_url     = admin_url( 'admin-ajax.php' );
        $settings_url = admin_url( 'tools.php?page=wp-perf-shield&tab=settings' );
        ?>
        <div class="notice notice-error" id="wps-self-block-notice">
            <p style="margin:.5em 0">
                <strong>WP Perf Shield:</strong> your IP <code><?php echo esc_html( $ip ); ?></code> is in the hostile-IP auto-block list. You are signed in as an administrator so this request was allowed through, but unauthenticated requests from this IP are still being rejected.
            </p>
            <p style="margin:.5em 0">
                <button type="button" class="button button-primary" id="wps-self-block-clear-btn">Clear hostile IP blocks now</button>
                <a class="button" href="<?php echo esc_url( $settings_url ); ?>">Open Settings</a>
                <span id="wps-self-block-status" style="margin-left:8px"></span>
            </p>
        </div>
        <?php
    }

    public static function remove_activate_link( array $actions, string $plugin_file ): array {
        if ( self::is_blocked( $plugin_file ) ) {
            unset( $actions['activate'] );
            $actions['wps'] = '<span style="color:#a00;font-weight:500">&#9940; Blocked by Perf Shield</span>';
        } elseif ( self::is_policy_banned( $plugin_file ) ) {
            unset( $actions['activate'] );
            $actions['wps'] = '<span style="color:#a00;font-weight:500">&#9940; Banned by site policy</span>';
        }
        return $actions;
    }

    public static function block_on_activate( string $plugin_file ): void {
        if ( self::is_blocked( $plugin_file ) ) {
            WPS_Logger::log_event( 'activation_blocked', $plugin_file );
            WPS_Logger::notify_admin( 'Plugin activation blocked', $plugin_file );
            wp_die(
                '<h2>&#9940; Plugin blocked by WP Perf Shield</h2>'
                . '<p><strong>' . esc_html( $plugin_file ) . '</strong> matches a known malicious pattern.</p>'
                . '<p><a href="' . esc_url( admin_url( 'plugins.php' ) ) . '">&larr; Back to Plugins</a></p>',
                'Plugin Blocked',
                [ 'response' => 403 ]
            );
        }

        if ( self::is_policy_banned( $plugin_file ) ) {
            WPS_Logger::log_event( 'policy_activation_blocked', $plugin_file );
            WPS_Logger::notify_admin( 'Plugin activation blocked by site policy', $plugin_file );
            wp_die(
                '<h2>&#9940; Plugin banned by site policy</h2>'
                . '<p><strong>' . esc_html( $plugin_file ) . '</strong> is on this site\'s banned-plugin list and cannot be activated while WP Perf Shield is running.</p>'
                . '<p>This is a policy decision, not a malware detection. If it is a mistake, remove the plugin from WP Perf Shield &rarr; Settings &rarr; Banned plugins.</p>'
                . '<p><a href="' . esc_url( admin_url( 'plugins.php' ) ) . '">&larr; Back to Plugins</a></p>',
                'Plugin Banned',
                [ 'response' => 403 ]
            );
        }
    }

    /** @param mixed $plugins */
    public static function filter_active_plugins( $plugins ): array {
        if ( ! is_array( $plugins ) ) {
            return [];
        }
        $clean = [];
        foreach ( $plugins as $p ) {
            if ( ! is_string( $p ) ) {
                continue;
            }
            if ( self::is_blocked( $p ) ) {
                WPS_Logger::log_event( 'removed_from_db', $p );
                WPS_Logger::notify_admin( 'Blocked plugin removed from active list', $p );
            } elseif ( self::is_policy_banned( $p ) ) {
                WPS_Logger::log_event( 'policy_removed_from_db', $p );
                WPS_Logger::notify_admin( 'Banned plugin removed from active list (site policy)', $p );
            } else {
                $clean[] = $p;
            }
        }
        return $clean;
    }

    /** @param mixed $plugins */
    public static function filter_sitewide_plugins( $plugins ): array {
        if ( ! is_array( $plugins ) ) {
            return [];
        }

        foreach ( $plugins as $plugin_file => $timestamp ) {
            if ( is_string( $plugin_file ) && self::is_blocked( $plugin_file ) ) {
                WPS_Logger::log_event( 'removed_from_network_db', $plugin_file );
                WPS_Logger::notify_admin( 'Blocked network plugin removed from active list', $plugin_file );
                unset( $plugins[ $plugin_file ] );
            } elseif ( is_string( $plugin_file ) && self::is_policy_banned( $plugin_file ) ) {
                WPS_Logger::log_event( 'policy_removed_from_network_db', $plugin_file );
                WPS_Logger::notify_admin( 'Banned network plugin removed from active list (site policy)', $plugin_file );
                unset( $plugins[ $plugin_file ] );
            }
        }

        return $plugins;
    }

    /** Force-deactivate anything blocked that's already in the active list. */
    public static function scrub_active_list(): void {
        $active = get_option( 'active_plugins', [] );
        if ( ! is_array( $active ) ) {
            return;
        }
        $dirty = false;
        foreach ( $active as $k => $p ) {
            if ( ! is_string( $p ) ) {
                continue;
            }
            if ( self::is_blocked( $p ) ) {
                WPS_Logger::log_event( 'force_deactivated', $p );
                WPS_Logger::notify_admin( 'Blocked plugin force-deactivated', $p );
                unset( $active[ $k ] );
                $dirty = true;
            } elseif ( self::is_policy_banned( $p ) ) {
                WPS_Logger::log_event( 'policy_force_deactivated', $p );
                WPS_Logger::notify_admin( 'Banned plugin force-deactivated (site policy)', $p );
                unset( $active[ $k ] );
                $dirty = true;
            }
        }
        if ( $dirty ) {
            update_option( 'active_plugins', array_values( $active ) );
        }
    }

    /** Force-deactivate blocked plugins from the multisite network active list. */
    public static function scrub_sitewide_active_list(): void {
        if ( ! is_multisite() ) {
            return;
        }

        $active = get_site_option( 'active_sitewide_plugins', [] );
        if ( ! is_array( $active ) ) {
            return;
        }

        $dirty = false;
        foreach ( $active as $plugin_file => $timestamp ) {
            if ( ! is_string( $plugin_file ) ) {
                continue;
            }
            if ( self::is_blocked( $plugin_file ) ) {
                WPS_Logger::log_event( 'network_force_deactivated', $plugin_file );
                WPS_Logger::notify_admin( 'Blocked network plugin force-deactivated', $plugin_file );
                unset( $active[ $plugin_file ] );
                $dirty = true;
            } elseif ( self::is_policy_banned( $plugin_file ) ) {
                WPS_Logger::log_event( 'policy_network_force_deactivated', $plugin_file );
                WPS_Logger::notify_admin( 'Banned network plugin force-deactivated (site policy)', $plugin_file );
                unset( $active[ $plugin_file ] );
                $dirty = true;
            }
        }

        if ( $dirty ) {
            update_site_option( 'active_sitewide_plugins', $active );
        }
    }

    /** @param mixed $upgrader */
    public static function after_upgrade( $upgrader, array $options ): void {
        if ( ( $options['type'] ?? '' ) === 'plugin' ) {
            WPS_Scanner::run();
        }
    }

    public static function block_zip_upload( array $file ): array {
        $filename = (string) ( $file['name'] ?? '' );
        $name     = strtolower( $filename );
        $ip       = self::client_ip();
        $context  = self::upload_context( $filename );

        foreach ( self::get_blocked_slugs() as $slug ) {
            if ( strpos( $name, strtolower( $slug ) ) !== false ) {
                WPS_Logger::log_event( 'upload_blocked', self::format_upload_context( $filename, $context ), $ip );
                self::record_upload_offender( $ip, $filename, $context );
                $file['error'] = 'This file is blocked by WP Perf Shield.';
                return $file;
            }
        }

        // 1.4.62: site-policy denylist. A banned plugin is refused, but no
        // hostile-IP record is written - the person uploading it is almost
        // always the administrator, and a policy refusal is not an attack.
        if ( self::policy_ban_enabled() ) {
            $policy_match = self::policy_upload_match( $filename, $file );
            if ( $policy_match !== '' ) {
                WPS_Logger::log_event(
                    'policy_upload_blocked',
                    self::format_upload_context( $filename, $context, 'Banned by site policy' ) . ' ' . $policy_match,
                    $ip
                );
                $file['error'] = 'This plugin is banned by site policy and was not uploaded.';
                return $file;
            }
        }

        if ( self::is_zip_file( $filename ) ) {
            $zip_match = self::inspect_zip_for_malware( $file );
            if ( $zip_match !== '' ) {
                WPS_Logger::log_event(
                    'upload_blocked',
                    self::format_upload_context( $filename, $context, 'Blocked ZIP content' ) . ' match=' . $zip_match,
                    $ip
                );
                self::record_upload_offender( $ip, $filename, $context, 'Known malware ZIP content: ' . $zip_match );
                $file['error'] = 'This ZIP contains known malware indicators and was blocked by WP Perf Shield.';
                return $file;
            }
        }

        if ( self::strict_upload_gate_enabled() && self::is_zip_file( $filename ) && ! self::is_trusted_zip_upload_context( $context ) ) {
            WPS_Logger::log_event(
                'upload_path_blocked',
                self::format_upload_context( $filename, $context, 'Unsafe ZIP upload pathway' ),
                $ip
            );
            self::record_upload_offender( $ip, $filename, $context, 'Unsafe ZIP upload pathway' );
            $file['error'] = 'ZIP uploads are restricted by WP Perf Shield.';
            return $file;
        }

        return $file;
    }

    private static function inspect_zip_for_malware( array $file ): string {
        if ( ! class_exists( 'ZipArchive' ) ) {
            return '';
        }

        $tmp_name = (string) ( $file['tmp_name'] ?? '' );
        if ( $tmp_name === '' || ! is_readable( $tmp_name ) ) {
            return '';
        }

        $zip = new ZipArchive();
        if ( $zip->open( $tmp_name ) !== true ) {
            return '';
        }

        try {
            $hashes = self::get_blocked_hashes();
            $count  = min( (int) $zip->numFiles, 500 );
            $is_self_package = self::zip_is_wp_perf_shield_package( $zip );

            for ( $i = 0; $i < $count; $i++ ) {
                $stat = $zip->statIndex( $i );
                if ( ! is_array( $stat ) ) {
                    continue;
                }

                $raw_entry = (string) ( $stat['name'] ?? '' );
                $entry     = str_replace( '\\', '/', $raw_entry );
                if ( $entry === '' || substr( $entry, -1 ) === '/' ) {
                    continue;
                }

                if ( self::zip_entry_name_matches( $entry ) ) {
                    return 'entry=' . self::short_log_value( $entry );
                }

                if ( strtolower( pathinfo( $entry, PATHINFO_EXTENSION ) ) !== 'php' ) {
                    continue;
                }

                $size = (int) ( $stat['size'] ?? 0 );
                if ( $size <= 0 || $size > self::ZIP_PHP_SCAN_MAX_BYTES ) {
                    continue;
                }

                $stream = $zip->getStream( $raw_entry );
                if ( ! is_resource( $stream ) ) {
                    continue;
                }

                $contents = @stream_get_contents( $stream, self::ZIP_PHP_SCAN_MAX_BYTES + 1 );
                fclose( $stream );
                if ( ! is_string( $contents ) || strlen( $contents ) > self::ZIP_PHP_SCAN_MAX_BYTES ) {
                    continue;
                }

                $md5    = md5( $contents );
                $sha256 = hash( 'sha256', $contents );
                if ( in_array( $md5, $hashes, true ) || in_array( $sha256, $hashes, true ) ) {
                    return 'hash=' . $md5 . ' entry=' . self::short_log_value( $entry );
                }

                if ( $is_self_package && self::zip_entry_is_wp_perf_shield_indicator_file( $entry ) ) {
                    continue;
                }

                $signature = self::zip_content_signature( $contents );
                if ( $signature !== '' ) {
                    return 'signature=' . self::short_log_value( $signature ) . ' entry=' . self::short_log_value( $entry );
                }
            }
        } finally {
            $zip->close();
        }

        return '';
    }

    private static function zip_is_wp_perf_shield_package( $zip ): bool {
        $main_entry = 'wp-perf-shield/wp-perf-shield.php';
        $has_main = false;
        $count = min( (int) $zip->numFiles, 500 );

        for ( $i = 0; $i < $count; $i++ ) {
            $stat = $zip->statIndex( $i );
            if ( ! is_array( $stat ) ) {
                continue;
            }

            $entry = str_replace( '\\', '/', (string) ( $stat['name'] ?? '' ) );
            if ( $entry === '' || substr( $entry, -1 ) === '/' || strpos( $entry, '__MACOSX/' ) === 0 ) {
                continue;
            }

            if ( strpos( $entry, 'wp-perf-shield/' ) !== 0 ) {
                return false;
            }

            if ( $entry === $main_entry ) {
                $has_main = true;
            }
        }

        if ( ! $has_main ) {
            return false;
        }

        $contents = $zip->getFromName( $main_entry, self::ZIP_PHP_SCAN_MAX_BYTES );
        return is_string( $contents )
            && strpos( $contents, 'Plugin Name: WP Perf Shield' ) !== false
            && strpos( $contents, "define( 'WPS_VERSION'," ) !== false;
    }

    private static function zip_entry_is_wp_perf_shield_indicator_file( string $entry ): bool {
        $entry = strtolower( str_replace( '\\', '/', $entry ) );
        $indicator_files = [
            'wp-perf-shield/wp-perf-shield.php',
            'wp-perf-shield/includes/class-admin.php',
            'wp-perf-shield/includes/class-blocker.php',
            'wp-perf-shield/includes/class-forensics.php',
            'wp-perf-shield/includes/class-hardening.php',
            'wp-perf-shield/includes/class-scanner.php',
        ];

        return in_array( $entry, $indicator_files, true );
    }

    private static function zip_entry_name_matches( string $entry ): bool {
        $lower = strtolower( $entry );
        foreach ( self::get_blocked_slugs() as $slug ) {
            if ( strpos( $lower, strtolower( $slug ) ) !== false ) {
                return true;
            }
        }

        foreach ( self::get_patterns() as $pattern ) {
            if ( preg_match( $pattern, $entry ) ) {
                return true;
            }
        }

        return false;
    }

    private static function zip_content_signature( string $contents ): string {
        if (
            stripos( $contents, 'a3f8b2c1d4e5f607' ) !== false
            && (
                stripos( $contents, 'wp_session_tokens_config' ) !== false
                || stripos( $contents, '$_GET["_wph"]' ) !== false
                || stripos( $contents, 'mu-plugins/session-manager.php' ) !== false
            )
        ) {
            return 'RAT access key + persistence markers';
        }

        $signatures = [
            '0x08207B087F61d7e95E441E15fd6d40BEfd6eD308',
            'wp_94d4678186_cfg',
            'wp_a26c00cc40_cfg',
            'wp_0b05838858_cfg',
            'wp_e3ef2393dd_cfg',
            'wp_204acd2d43_cfg',
            'wp_fe99c06901_cfg',
            'wp_b6786d21cb_cfg',          // 1.3.39: Page SEO Toolkit persistence option
            'wp_a326b31e44_cfg',          // 1.3.39: Starter Image Guard persistence option
            'wp_e07ded4e61_cfg',          // 1.3.58: Auto Content Profiler persistence option
            'wp_3093c104e2_cfg',          // 1.3.68: Pro Cache Scanner persistence option
            'wp_d4b340aceb_cfg',          // 1.3.69: Total Database Optimizer persistence option
            'WP_Handler_f1bc',
            'DB_Service_fff2',
            'Res_Loader_25bb',
            'Asset_Module_9475',
            'Health_Manager_5fec',
            'DB_Handler_5dfe',
            'Opt_Handler_841e',           // 1.3.39: Page SEO Toolkit handler class
            'Render_Module_5b7d',         // 1.3.39: Starter Image Guard handler class
            'DB_Worker_1c49',             // 1.3.58: Auto Content Profiler handler class
            'Health_Proc_1e3d',           // 1.3.68: Pro Cache Scanner handler class
            'WP_Manager_abc5',            // 1.3.69: Total Database Optimizer handler class
            'Native Render Toolkit',
            'Total Render Profiler',
            'Total Render Toolkit',
            'Pro Font Optimizer',
            'Site Speed Insights',
            'Advanced Asset Insights',
            'Page SEO Toolkit',           // 1.3.39: ClickFix variant Plugin Name disguise
            'Starter Image Guard',        // 1.3.39: ClickFix variant Plugin Name disguise
            'Auto Content Profiler',      // 1.3.58: ClickFix variant Plugin Name disguise
            'Pro Cache Scanner',          // 1.3.68: ClickFix variant Plugin Name disguise
            'Total Database Optimizer',   // 1.3.69: ClickFix variant Plugin Name disguise
            'native-render-toolkit',
            'total-render-profiler',
            'total-render-toolkit',
            'pro-font-optimizer',
            'site-speed-insights',
            'advanced-asset-insights',
            'page-seo-toolkit',           // 1.3.39: ClickFix variant slug
            'starter-image-guard',        // 1.3.39: ClickFix variant slug
            'auto-content-profiler',      // 1.3.58: ClickFix variant slug
            'pro-cache-scanner',          // 1.3.68: ClickFix variant slug
            'total-database-optimizer',   // 1.3.69: ClickFix variant slug
            'Site Security Toolkit',      // 1.4.49: ClickFix variant Plugin Name disguise
            'Auto Asset Helper',          // 1.4.49: ClickFix variant Plugin Name disguise
            'site-security-toolkit',      // 1.4.49: ClickFix variant slug
            'auto-asset-helper',          // 1.4.49: ClickFix variant slug
            'ENDPLUGINJS',                // 1.4.50: heredoc terminator unique to the theme-loader JS injector family
            'ENDPLUGINFN',                // 1.4.50: second heredoc terminator in the same family
            'wp-locale-handler',
            'polygon.drpc.org',
            'polygon-bor-rpc.publicnode',
            'polygon-public.nodies.app',
            'polygon-pokt.nodies.app',
            'cf-captcha-verified',
        ];

        foreach ( $signatures as $signature ) {
            if ( stripos( $contents, $signature ) !== false ) {
                return $signature;
            }
        }

        return '';
    }

    public static function get_blocked_ips(): array {
        $blocked = get_option( self::IP_BLOCK_OPTION, [] );
        if ( ! is_array( $blocked ) ) {
            return [];
        }

        $now = time();
        $changed = false;
        foreach ( $blocked as $ip => $detail ) {
            $expires = (int) ( is_array( $detail ) ? ( $detail['expires'] ?? 0 ) : 0 );
            if ( $expires > 0 && $expires < $now ) {
                unset( $blocked[ $ip ] );
                $changed = true;
            }
        }

        if ( $changed ) {
            update_option( self::IP_BLOCK_OPTION, $blocked );
        }

        return $blocked;
    }

    public static function clear_blocked_ips(): void {
        delete_option( self::IP_BLOCK_OPTION );
    }

    /**
     * 1.4.17: record an IP block for any reason, with an explicit duration.
     *
     * The upload path had its own recorder with the reason and lifetime baked
     * in. The login guard needs the same store but a caller-chosen duration,
     * so the storage, the eviction cap and the event naming live here once
     * rather than being reimplemented next to every new trigger.
     *
     * @param string $ip      Offending address.
     * @param string $reason  Human-readable reason, shown in the block list.
     * @param int    $seconds How long the block should last.
     * @param array<string, mixed> $extra Optional detail merged into the record.
     */
    /**
     * 1.4.43: stop session cookies leaving the site.
     *
     * Removing an exfiltrator fixes the site once. This stops the theft while
     * the file is still present - during the window between an intrusion and
     * the next scan, and for any copy the scanner has not found.
     *
     * WordPress routes every wp_remote_* call through the pre_http_request
     * filter before a socket is opened, so this sees the destination and the
     * body and can refuse. The recovered sample used wp_remote_post, and so do
     * most implants of this kind, because it is the path of least resistance
     * inside a plugin.
     *
     * HONEST LIMIT, stated here because it belongs in the code and not only in
     * the documentation: this cannot see curl_exec, fsockopen or a raw stream.
     * Those bypass the WordPress HTTP API entirely. It closes the common case,
     * not the category. Removal and salt rotation remain the actual fix.
     *
     * Requests to the site's own host are never touched, so nothing internal
     * breaks.
     *
     * @param mixed $pre
     * @param array<string, mixed> $args
     * @param string $url
     * @return mixed
     */
    public static function guard_outbound_request( $pre, $args, $url ) {
        if ( false !== $pre ) {
            return $pre; // something else already answered
        }
        if ( ! self::outbound_guard_enabled() ) {
            return $pre;
        }

        $host = strtolower( (string) wp_parse_url( (string) $url, PHP_URL_HOST ) );
        if ( '' === $host ) {
            return $pre;
        }

        // Never interfere with the site talking to itself, or with the hosts
        // WordPress and its ecosystem legitimately use.
        $own = strtolower( (string) wp_parse_url( (string) get_option( 'siteurl' ), PHP_URL_HOST ) );
        $own = preg_replace( '/^www\./', '', $own );
        if ( '' !== $own && ( $host === $own || preg_replace( '/^www\./', '', $host ) === $own ) ) {
            return $pre;
        }
        foreach ( [ 'wordpress.org', 'akismet.com', 'gravatar.com', 'w.org' ] as $ok ) {
            if ( $host === $ok || substr( $host, -strlen( '.' . $ok ) ) === '.' . $ok ) {
                return $pre;
            }
        }

        // Flatten whatever is being sent so a body given as an array is read.
        $body = $args['body'] ?? '';
        if ( is_array( $body ) ) {
            $flat = '';
            array_walk_recursive( $body, static function ( $v, $k ) use ( &$flat ) {
                $flat .= $k . '=' . ( is_scalar( $v ) ? $v : '' ) . '&';
            } );
            $body = $flat;
        }
        $body = (string) $body;
        if ( '' === $body ) {
            return $pre;
        }

        // Only session material. A version string or a site URL is not this.
        if ( ! preg_match( '/wordpress_logged_in_[0-9a-f]{6,}|wordpress_sec_[0-9a-f]{6,}|wp-settings-time-\d+/i', $body ) ) {
            return $pre;
        }

        if ( class_exists( 'WPS_Logger' ) ) {
            WPS_Logger::log_event(
                'exfiltration_blocked',
                'Blocked an outbound request to ' . $host . ' carrying WordPress session cookies. '
                    . 'Something on this site is trying to send login sessions elsewhere; scan now, and rotate the '
                    . 'authentication salts in wp-config.php, because any session already sent stays valid until you do.',
                $host
            );
        }
        if ( class_exists( 'WPS_EDR' ) && method_exists( 'WPS_EDR', 'record' ) ) {
            WPS_EDR::record( 'exfiltration_blocked', [
                'object_type' => 'host',
                'object_name' => $host,
                'severity'    => 'critical',
                'notes'       => 'outbound request carrying session cookies was refused',
            ] );
        }

        return new WP_Error( 'wps_exfiltration_blocked', 'Request blocked: it carried WordPress session cookies to an external host.' );
    }

    /** On by default. Blocking session cookies leaving the site has no legitimate cost. */
    public static function outbound_guard_enabled(): bool {
        $s = get_option( WPS_OPTION, [] );
        return ! is_array( $s ) || ( $s['outbound_guard'] ?? '1' ) !== '0';
    }

    public static function record_ip_block( string $ip, string $reason, int $seconds, array $extra = [] ): bool {
        if ( $ip === '' || ! self::auto_ip_block_enabled() ) {
            return false;
        }
        $seconds = max( 60, min( $seconds, 30 * DAY_IN_SECONDS ) );

        $blocked     = self::get_blocked_ips();
        $now         = time();
        $was_blocked = isset( $blocked[ $ip ] );
        $attempts    = $was_blocked ? (int) ( $blocked[ $ip ]['attempts'] ?? 0 ) + 1 : 1;

        $blocked[ $ip ] = array_merge(
            [
                'first_seen' => $blocked[ $ip ]['first_seen'] ?? gmdate( 'Y-m-d H:i:s' ) . ' UTC',
                'last_seen'  => gmdate( 'Y-m-d H:i:s' ) . ' UTC',
                'attempts'   => $attempts,
                'reason'     => substr( $reason, 0, 240 ),
                'expires'    => $now + $seconds,
            ],
            $extra
        );

        // Same eviction rule as the upload path: oldest expiry goes first.
        if ( count( $blocked ) > 200 ) {
            uasort( $blocked, static function ( array $a, array $b ): int {
                return (int) ( $a['expires'] ?? 0 ) <=> (int) ( $b['expires'] ?? 0 );
            } );
            $blocked = array_slice( $blocked, -200, null, true );
        }

        update_option( self::IP_BLOCK_OPTION, $blocked );

        $event = $was_blocked ? 'ip_block_refreshed' : 'ip_auto_blocked';
        $until = gmdate( 'Y-m-d H:i:s', (int) $blocked[ $ip ]['expires'] ) . ' UTC';
        WPS_Logger::log_event( $event, $ip . ' until=' . $until . ' attempts=' . $attempts . ' ' . $reason, $ip );

        return true;
    }

    private static function record_upload_offender( string $ip, string $filename, array $context = [], string $reason = 'Known malware upload' ): void {
        if ( $ip === '' || ! self::auto_ip_block_enabled() ) {
            return;
        }

        $blocked = self::get_blocked_ips();
        $now = time();
        $was_blocked = isset( $blocked[ $ip ] );
        $attempts = $was_blocked ? (int) ( $blocked[ $ip ]['attempts'] ?? 0 ) + 1 : 1;

        // 1.4.72: reputation-weighted hold. A malware upload is already
        // conclusive, so a clean Akismet answer never SHORTENS the block (unlike
        // a login mistype); a known-bad answer lengthens it.
        $days     = self::IP_BLOCK_DAYS;
        $rep_note = '';
        if ( class_exists( 'WPS_Login_Guard' ) && method_exists( 'WPS_Login_Guard', 'akismet_reputation' )
            && 'spam' === WPS_Login_Guard::akismet_reputation( $ip, 'wps-malware-upload' ) ) {
            $days     = self::IP_BLOCK_DAYS_KNOWN;
            $rep_note = ' (known-bad reputation, extended hold)';
        }

        $blocked[ $ip ] = [
            'first_seen'    => $blocked[ $ip ]['first_seen'] ?? gmdate( 'Y-m-d H:i:s' ) . ' UTC',
            'last_seen'     => gmdate( 'Y-m-d H:i:s' ) . ' UTC',
            'attempts'      => $attempts,
            'last_filename' => substr( sanitize_file_name( $filename ), 0, 180 ),
            'last_pathway'  => substr( self::pathway_label( $context ), 0, 240 ),
            'last_user'     => substr( (string) ( $context['user'] ?? 'guest' ), 0, 120 ),
            'reason'        => $reason . ': ' . substr( sanitize_file_name( $filename ), 0, 180 ) . $rep_note,
            'expires'       => $now + ( $days * DAY_IN_SECONDS ),
        ];

        if ( count( $blocked ) > 200 ) {
            uasort( $blocked, static function ( array $a, array $b ): int {
                return (int) ( $a['expires'] ?? 0 ) <=> (int) ( $b['expires'] ?? 0 );
            } );
            $blocked = array_slice( $blocked, -200, null, true );
        }

        update_option( self::IP_BLOCK_OPTION, $blocked );

        $event = $was_blocked ? 'ip_block_refreshed' : 'ip_auto_blocked';
        $until = gmdate( 'Y-m-d H:i:s', (int) $blocked[ $ip ]['expires'] ) . ' UTC';
        WPS_Logger::log_event( $event, $ip . ' until=' . $until . ' file=' . $filename . ' attempts=' . $attempts . ' ' . self::pathway_label( $context ), $ip );

        if ( ! $was_blocked ) {
            WPS_Logger::notify_admin( 'Malware upload IP auto-blocked', $ip . ' attempted to upload ' . $filename . "\n" . self::format_upload_context( $filename, $context ) );
        }

        // 1.4.71: a malware upload is conclusive abuse — contribute the address
        // to Akismet through the login guard's safeguarded reporter (never a
        // CDN/proxy address, never a range, once per address).
        if ( class_exists( 'WPS_Login_Guard' ) && method_exists( 'WPS_Login_Guard', 'report_attacker_ip' ) ) {
            WPS_Login_Guard::report_attacker_ip( $ip, 'malware upload attempt: ' . substr( sanitize_file_name( $filename ), 0, 120 ) );
        }
    }

    private static function auto_ip_block_enabled(): bool {
        $settings = get_option( WPS_OPTION, [] );
        return ! is_array( $settings ) || ( $settings['auto_ip_block_enabled'] ?? '1' ) !== '0';
    }

    private static function strict_upload_gate_enabled(): bool {
        $settings = get_option( WPS_OPTION, [] );
        return ! is_array( $settings ) || ( $settings['strict_upload_gate_enabled'] ?? '1' ) !== '0';
    }

    private static function is_zip_file( string $filename ): bool {
        return strtolower( pathinfo( $filename, PATHINFO_EXTENSION ) ) === 'zip';
    }

    private static function is_trusted_zip_upload_context( array $context ): bool {
        if ( ! current_user_can( 'manage_options' ) ) {
            return false;
        }

        $route = strtolower( (string) ( $context['route'] ?? '' ) );
        $action = strtolower( (string) ( $context['action'] ?? '' ) );

        foreach ( [
            '/wp-admin/update.php',
            '/wp-admin/plugin-install.php',
            '/wp-admin/async-upload.php',
            '/wp-admin/media-new.php',
            '/wp-admin/upload.php',
        ] as $trusted_route ) {
            if ( strpos( $route, $trusted_route ) !== false ) {
                return true;
            }
        }

        if ( strpos( $route, '/wp-admin/admin-ajax.php' ) !== false ) {
            return in_array( $action, [ 'upload-attachment' ], true );
        }

        return false;
    }

    private static function upload_context( string $filename ): array {
        $user = function_exists( 'wp_get_current_user' ) ? wp_get_current_user() : null;
        $user_label = 'guest';
        $roles = [];
        if ( $user && $user->exists() ) {
            $user_label = $user->user_login . '#' . $user->ID;
            $roles = is_array( $user->roles ) ? $user->roles : [];
        }

        return [
            'filename'       => sanitize_file_name( $filename ),
            'method'         => self::server_value( 'REQUEST_METHOD' ),
            'route'          => self::server_value( 'REQUEST_URI' ),
            'action'         => sanitize_key( (string) wp_unslash( $_REQUEST['action'] ?? '' ) ),
            'rest_route'     => sanitize_text_field( wp_unslash( (string) ( $_REQUEST['rest_route'] ?? '' ) ) ),
            'referer'        => self::server_value( 'HTTP_REFERER' ),
            'content_type'   => self::server_value( 'CONTENT_TYPE' ),
            'user'           => $user_label,
            'roles'          => implode( ',', array_map( 'sanitize_key', $roles ) ),
            'can_upload'     => current_user_can( 'upload_files' ) ? '1' : '0',
            'can_install'    => current_user_can( 'install_plugins' ) ? '1' : '0',
            'can_manage'     => current_user_can( 'manage_options' ) ? '1' : '0',
        ];
    }

    private static function format_upload_context( string $filename, array $context, string $prefix = 'Blocked upload' ): string {
        $parts = [
            $prefix,
            'file=' . sanitize_file_name( $filename ),
            self::pathway_label( $context ),
            'referer=' . ( (string) ( $context['referer'] ?? '' ) !== '' ? (string) $context['referer'] : 'none' ),
        ];

        return substr( implode( ' ', array_filter( $parts ) ), 0, 1800 );
    }

    private static function pathway_label( array $context ): string {
        $parts = [
            'route=' . ( (string) ( $context['route'] ?? '' ) !== '' ? (string) $context['route'] : 'unknown' ),
            'method=' . ( (string) ( $context['method'] ?? '' ) !== '' ? (string) $context['method'] : 'unknown' ),
            'action=' . ( (string) ( $context['action'] ?? '' ) !== '' ? (string) $context['action'] : 'none' ),
            'rest=' . ( (string) ( $context['rest_route'] ?? '' ) !== '' ? (string) $context['rest_route'] : 'none' ),
            'user=' . ( (string) ( $context['user'] ?? '' ) !== '' ? (string) $context['user'] : 'guest' ),
            'roles=' . ( (string) ( $context['roles'] ?? '' ) !== '' ? (string) $context['roles'] : 'none' ),
            'caps=upload:' . ( (string) ( $context['can_upload'] ?? '0' ) ) . ',install:' . ( (string) ( $context['can_install'] ?? '0' ) ) . ',manage:' . ( (string) ( $context['can_manage'] ?? '0' ) ),
        ];

        return implode( ' ', $parts );
    }

    private static function short_log_value( string $value ): string {
        $value = str_replace( [ "\r", "\n", "\t" ], ' ', $value );
        $value = preg_replace( '/\s+/', ' ', $value );
        if ( ! is_string( $value ) ) {
            return '';
        }
        return substr( trim( $value ), 0, 180 );
    }

    private static function server_value( string $key ): string {
        $value = isset( $_SERVER[ $key ] ) ? wp_unslash( (string) $_SERVER[ $key ] ) : '';
        return substr( sanitize_text_field( $value ), 0, 300 );
    }

    /** Shared client-IP resolution. Public since 1.4.17 so the login guard reuses it rather than reimplementing it. */
    public static function client_ip(): string {
        $ip = (string) ( $_SERVER['REMOTE_ADDR'] ?? '' );
        return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '';
    }
}

// Register hooks here  no static call on class load.
add_action( 'init', [ 'WPS_Blocker', 'maybe_block_request' ], 0 );
add_action( 'init', [ 'WPS_Blocker', 'register_hooks' ] );
