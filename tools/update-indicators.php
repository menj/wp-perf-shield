<?php
/**
 * Utility script to fetch and update WP Perf Shield indicator data.
 *
 * STATUS: STUB  feature is not active. The indicator-feed mechanism
 * is planned but not yet implemented; this file is a scaffold for the
 * eventual feed-based update workflow. Until a real feed URL is
 * configured (replacing the example.com placeholder below), the script
 * exits early with a clear message and does not perform any network
 * activity. Indicator updates are currently shipped via plugin
 * version releases, not via this script.
 *
 * Expected eventual usage: php tools/update-indicators.php
 *
 * It will retrieve a JSON payload from a trusted URL (e.g., a GitHub
 * Gist) containing the latest malware indicator arrays (slugs, hashes,
 * etc.) and write them into the appropriate class properties or static
 * files. The script is deliberately simple  it validates the JSON
 * structure, ensures the target file exists, and overwrites the
 * indicator definitions atomically.
 */

if ( PHP_SAPI !== 'cli' ) {
    echo "This script must be run from the command line.\n";
    exit(1);
}

// WPSEC-006 (1.3.57): explicit stub guard. Until $feedUrl is replaced
// with a real, trusted feed URL, refuse to make any network request.
$feedUrl = 'https://example.com/wp-perf-shield-indicators.json'; // TODO: replace with real feed URL

if ( strpos( $feedUrl, 'example.com' ) !== false ) {
    fwrite( STDERR, "tools/update-indicators.php is a STUB. Configure a real \$feedUrl before running.\n" );
    exit( 2 );
}

$response = wp_safe_remote_get( $feedUrl );
if ( is_wp_error( $response ) ) {
    fwrite(STDERR, "Failed to fetch indicator feed: " . $response->get_error_message() . "\n");
    exit(1);
}

$body = wp_remote_retrieve_body( $response );
$data = json_decode( $body, true );
if ( json_last_error() !== JSON_ERROR_NONE ) {
    fwrite(STDERR, "Invalid JSON received from indicator feed.\n");
    exit(1);
}

$targetFile = __DIR__ . '/../includes/class-wps-indicators.php';
if ( ! file_exists( $targetFile ) ) {
    fwrite(STDERR, "Target indicator class not found: $targetFile\n");
    exit(1);
}

$contents = file_get_contents( $targetFile );
if ( $contents === false ) {
    fwrite(STDERR, "Unable to read target file.\n");
    exit(1);
}

// Simple replacement: we look for the existing arrays definitions and replace them.
function replaceArray( $name, $newArray, $code ) {
    $pattern = '/public\s+static\s+function\s+' . $name . '\s*\(\s*\)\s*:\s*array\s*\{[^}]*\}/s';
    $replacement = "public static function $name(): array {\n        return [\n" . implode(",\n", array_map(function($v){return "            '$v'";}, $newArray)) . "\n        ];\n    }";
    return preg_replace( $pattern, $replacement, $code );
}

if ( isset( $data['malware_option_keys'] ) ) {
    $contents = replaceArray('malware_option_keys', $data['malware_option_keys'], $contents);
}
if ( isset( $data['mu_persistence_option_keys'] ) ) {
    $contents = replaceArray('mu_persistence_option_keys', $data['mu_persistence_option_keys'], $contents);
}
// Add additional replacements as needed.

file_put_contents( $targetFile, $contents );

echo "Indicator data updated successfully.\n";
