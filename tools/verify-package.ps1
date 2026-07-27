# tools/verify-package.ps1
#
# Pre-release validation script for WP Perf Shield.
# Codifies the parser fallback that has been used through Phases 0-5 of the
# controlled development roadmap. Run from the repo root; exits non-zero if
# any check fails.
#
# Checks performed:
#   1. Every PHP file balances braces, parens, and brackets after PHP/HTML
#      mode-aware string and comment stripping.
#   2. Every PHP file opens with the <?php tag.
#   3. assets/js/admin.js balances braces, parens, and brackets.
#   4. The four declared release files all carry the same version marker.
#   5. The required directory layout matches doc/ssot.md.
#   6. doc/readme.md, doc/upgrading.md, doc/changelog.md, doc/ssot.md exist.
#   7. readme.txt exists at the package root.
#   8. assets/css/admin.css and assets/js/admin.js exist.
#
# This script does NOT call `php -l` because the dev box may not have PHP
# on PATH; the parser fallback covers structural correctness for the same
# class of bugs that bracket imbalance detects. For full semantic syntax
# validation, run `php -l` on a machine with PHP installed.

$ErrorActionPreference = 'Stop'

$root = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $root

function Strip-Php {
    param([string]$src)
    $sb = [System.Text.StringBuilder]::new()
    $i = 0; $n = $src.Length
    $inPhp = $false; $inSingle = $false; $inDouble = $false; $inLine = $false; $inBlock = $false
    $inHeredoc = $false; $heredocLabel = $null
    while ($i -lt $n) {
        $c = $src[$i]; $next = if ($i+1 -lt $n) { $src[$i+1] } else { '' }
        if (-not $inPhp) {
            if ($c -eq '<' -and $next -eq '?') {
                $i += 2
                if ($i+2 -lt $n -and $src.Substring($i,3).ToLower() -eq 'php') { $i += 3 }
                elseif ($i -lt $n -and $src[$i] -eq '=') { $i += 1 }
                $inPhp = $true; continue
            }
            $i++; continue
        }
        if ($inLine) {
            if ($c -eq "`n") { $inLine = $false; [void]$sb.Append("`n") }
            if ($c -eq '?' -and $next -eq '>') { $inLine = $false; $inPhp = $false; $i += 2; continue }
            $i++; continue
        }
        if ($inBlock) {
            if ($c -eq '*' -and $next -eq '/') { $inBlock = $false; $i += 2; continue }
            if ($c -eq "`n") { [void]$sb.Append("`n") }
            $i++; continue
        }
        if ($inSingle) {
            if ($c -eq '\') { $i += 2; continue }
            if ($c -eq "'") { $inSingle = $false; $i++; continue }
            $i++; continue
        }
        if ($inDouble) {
            if ($c -eq '\') { $i += 2; continue }
            if ($c -eq '"') { $inDouble = $false; $i++; continue }
            $i++; continue
        }
        if ($inHeredoc) {
            if ($c -eq "`n") {
                [void]$sb.Append("`n")
                $rest = $src.Substring($i+1)
                if ($rest -match "^\s*$([regex]::Escape($heredocLabel))\b") {
                    $idx = $rest.IndexOf($heredocLabel)
                    $i = $i + 1 + $idx + $heredocLabel.Length
                    $inHeredoc = $false; $heredocLabel = $null; continue
                }
            }
            $i++; continue
        }
        if ($c -eq '?' -and $next -eq '>') { $inPhp = $false; $i += 2; continue }
        if ($c -eq '/' -and $next -eq '/') { $inLine = $true; $i += 2; continue }
        if ($c -eq '#' -and $next -ne '[') { $inLine = $true; $i++; continue }
        if ($c -eq '/' -and $next -eq '*') { $inBlock = $true; $i += 2; continue }
        if ($c -eq "'") { $inSingle = $true; $i++; continue }
        if ($c -eq '"') { $inDouble = $true; $i++; continue }
        if ($c -eq '<' -and $next -eq '<' -and $i+2 -lt $n -and $src[$i+2] -eq '<') {
            $j = $i + 3
            while ($j -lt $n -and ($src[$j] -eq ' ' -or $src[$j] -eq "`t")) { $j++ }
            $quote = $null
            if ($j -lt $n -and ($src[$j] -eq "'" -or $src[$j] -eq '"')) { $quote = $src[$j]; $j++ }
            $labelStart = $j
            while ($j -lt $n -and ($src[$j] -match '[A-Za-z0-9_]')) { $j++ }
            if ($j -gt $labelStart) {
                $heredocLabel = $src.Substring($labelStart, $j - $labelStart)
                if ($quote -ne $null -and $j -lt $n -and $src[$j] -eq $quote) { $j++ }
                while ($j -lt $n -and $src[$j] -ne "`n") { $j++ }
                $inHeredoc = $true; $i = $j; continue
            }
        }
        [void]$sb.Append($c); $i++
    }
    return $sb.ToString()
}

function Strip-Js {
    param([string]$src)
    $sb = [System.Text.StringBuilder]::new()
    $i = 0; $n = $src.Length
    $inSingle = $false; $inDouble = $false; $inBack = $false
    $inLine = $false; $inBlock = $false; $inRegex = $false
    $prevSig = ''
    while ($i -lt $n) {
        $c = $src[$i]; $next = if ($i+1 -lt $n) { $src[$i+1] } else { '' }
        if ($inLine) { if ($c -eq "`n") { $inLine = $false; [void]$sb.Append("`n") }; $i++; continue }
        if ($inBlock) { if ($c -eq '*' -and $next -eq '/') { $inBlock = $false; $i += 2; continue }; if ($c -eq "`n") { [void]$sb.Append("`n") }; $i++; continue }
        if ($inSingle) { if ($c -eq '\') { $i += 2; continue }; if ($c -eq "'") { $inSingle = $false; $i++; continue }; $i++; continue }
        if ($inDouble) { if ($c -eq '\') { $i += 2; continue }; if ($c -eq '"') { $inDouble = $false; $i++; continue }; $i++; continue }
        if ($inBack) { if ($c -eq '\') { $i += 2; continue }; if ($c -eq '`') { $inBack = $false; $i++; continue }; $i++; continue }
        if ($inRegex) {
            if ($c -eq '\') { $i += 2; continue }
            if ($c -eq '[') { $j = $i+1; while ($j -lt $n -and $src[$j] -ne ']') { if ($src[$j] -eq '\') { $j += 2 } else { $j++ } }; $i = $j+1; continue }
            if ($c -eq '/') { $inRegex = $false; $i++; while ($i -lt $n -and ($src[$i] -match '[gimsuy]')) { $i++ }; continue }
            $i++; continue
        }
        if ($c -eq '/' -and $next -eq '/') { $inLine = $true; $i += 2; continue }
        if ($c -eq '/' -and $next -eq '*') { $inBlock = $true; $i += 2; continue }
        if ($c -eq "'") { $inSingle = $true; $i++; continue }
        if ($c -eq '"') { $inDouble = $true; $i++; continue }
        if ($c -eq '`') { $inBack = $true; $i++; continue }
        if ($c -eq '/') {
            if ($prevSig -eq '' -or '({[,;=!&|?:+*<>%^~'.IndexOf($prevSig) -ge 0 -or $prevSig -eq "`n") {
                $inRegex = $true; $i++; continue
            }
        }
        if ($c -notmatch '\s') { $prevSig = $c }
        [void]$sb.Append($c); $i++
    }
    return $sb.ToString()
}

function Bal {
    param([string]$s)
    $b=0;$p=0;$k=0
    foreach ($ch in $s.ToCharArray()) {
        switch ($ch) { '{' { $b++ }; '}' { $b-- }; '(' { $p++ }; ')' { $p-- }; '[' { $k++ }; ']' { $k-- } }
    }
    return [pscustomobject]@{Brace=$b;Paren=$p;Bracket=$k}
}

$pass = $true
$results = @()

# 1+2: PHP files
"=== PHP parser fallback ==="
$phpFiles = Get-ChildItem -Recurse -Filter '*.php' -File -Path '.' | Where-Object { $_.FullName -notmatch '\\node_modules\\' -and $_.FullName -notmatch '\\vendor\\' }
foreach ($f in $phpFiles) {
    $rel = $f.FullName.Replace($root.Path + '\', '').Replace('\', '/')
    $src = Get-Content $f.FullName -Raw -Encoding UTF8
    $opens = $src.TrimStart().StartsWith('<?php')
    $r = Bal (Strip-Php $src)
    $ok = $r.Brace -eq 0 -and $r.Paren -eq 0 -and $r.Bracket -eq 0 -and $opens
    if (-not $ok) { $pass = $false }
    $st = if ($ok) { 'OK  ' } else { 'FAIL' }
    "{0} {1,-50} brace={2} paren={3} bracket={4}" -f $st, $rel, $r.Brace, $r.Paren, $r.Bracket
}

# 3: JS file
""
"=== JS parser fallback ==="
$js = Join-Path $root 'assets\js\admin.js'
if (Test-Path $js) {
    $r = Bal (Strip-Js (Get-Content $js -Raw -Encoding UTF8))
    $ok = $r.Brace -eq 0 -and $r.Paren -eq 0 -and $r.Bracket -eq 0
    if (-not $ok) { $pass = $false }
    $st = if ($ok) { 'OK  ' } else { 'FAIL' }
    "{0} assets/js/admin.js                                brace={1} paren={2} bracket={3}" -f $st, $r.Brace, $r.Paren, $r.Bracket
} else {
    "FAIL assets/js/admin.js missing"
    $pass = $false
}

# 4: version markers
""
"=== Version marker consistency ==="
$markers = @{}
$fileMap = @{
    'header'      = @{ file='wp-perf-shield.php'; pattern=' \* Version: (\d+\.\d+\.\d+)' }
    'WPS_VERSION' = @{ file='wp-perf-shield.php'; pattern="define\(\s*'WPS_VERSION',\s*'(\d+\.\d+\.\d+)'\s*\)" }
    'readme.txt'  = @{ file='readme.txt'; pattern='Stable tag:\s*(\d+\.\d+\.\d+)' }
    'doc/readme'  = @{ file='doc\readme.md'; pattern='Current plugin version:\s*`(\d+\.\d+\.\d+)`' }
}
foreach ($k in $fileMap.Keys) {
    $c = $fileMap[$k]
    $content = Get-Content (Join-Path $root $c.file) -Raw -Encoding UTF8
    if ($content -match $c.pattern) {
        $markers[$k] = $matches[1]
        "{0,-14} {1}" -f $k, $matches[1]
    } else {
        "{0,-14} NOT FOUND" -f $k
        $pass = $false
    }
}
$uniqueVersions = ($markers.Values | Select-Object -Unique).Count
if ($uniqueVersions -ne 1) {
    "FAIL  version markers diverge"
    $pass = $false
} else {
    "OK    all four markers match"
}

# 5+6+7+8: required layout
""
"=== Directory and file layout ==="
$required = @(
    'wp-perf-shield.php',
    'readme.txt',
    'assets/css/admin.css',
    'assets/js/admin.js',
    'doc/readme.md',
    'doc/upgrading.md',
    'doc/changelog.md',
    'doc/ssot.md',
    'logs/index.php',
    'logs/.htaccess',
    'includes/class-wps-utils.php',
    'includes/class-wps-indicators.php',
    'includes/class-logger.php',
    'includes/class-blocker.php',
    'includes/class-scanner.php',
    'includes/class-forensics.php',
    'includes/class-hardening.php',
    'includes/class-admin.php',
    'includes/class-admin-overview.php',
    'includes/class-admin-diagnostics.php',
    'includes/class-admin-forensics.php',
    'includes/class-admin-remediation.php',
    'includes/class-admin-hardening.php',
    'includes/class-admin-events.php',
    'includes/class-admin-settings.php',
    'includes/class-dropin-guard.php',
    'includes/class-log-reader.php',
    'includes/class-quarantine.php',
    'includes/class-csp.php',
    'includes/class-admin-logs.php',
    'includes/class-remediation-controller.php'
)
foreach ($p in $required) {
    $full = Join-Path $root ($p -replace '/', '\')
    if (Test-Path $full) {
        "OK    $p"
    } else {
        "FAIL  $p missing"
        $pass = $false
    }
}

# Stray markdown at root
$rootMd = Get-ChildItem -Path $root -Filter '*.md' -File -ErrorAction SilentlyContinue
if ($rootMd) {
    "FAIL  stray markdown files at package root: $($rootMd.Name -join ', ')"
    $pass = $false
} else {
    "OK    no stray markdown at package root"
}

""
if ($pass) {
    'verify-package.ps1: ALL CHECKS PASS'
    exit 0
} else {
    'verify-package.ps1: FAILURE  see above'
    exit 1
}
