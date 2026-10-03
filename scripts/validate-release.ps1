param([string]$Tag = $env:GITHUB_REF_NAME)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if ($Tag -notmatch '^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$') {
    throw 'Release tag must be v<semver>'
}
$version = $Tag.Substring(1)
$package = Get-Content -LiteralPath (Join-Path $root 'package.json') -Raw | ConvertFrom-Json
$tauri = Get-Content -LiteralPath (Join-Path $root 'src-tauri/tauri.conf.json') -Raw | ConvertFrom-Json
foreach ($file in @('Cargo.toml', 'src-tauri/Cargo.toml')) {
    $text = Get-Content -LiteralPath (Join-Path $root $file) -Raw
    if ($text -notmatch '(?m)^version\s*=\s*"([^"]+)"' -or $matches[1] -ne $version) { throw "$file version differs from tag" }
}
if ($package.version -ne $version -or $tauri.version -ne $version) { throw 'Frontend/Tauri version differs from tag' }
if ($env:SIGNPATH_ENABLED -and $env:SIGNPATH_ENABLED -notin @('true', 'false')) { throw 'SIGNPATH_ENABLED must be true, false or absent' }
if ([bool]$env:EVERYOUT_CATALOG_PUBLIC_KEY -ne [bool]$env:EVERYOUT_CATALOG_URL) { throw 'Catalog key and URL must be configured together' }
if ($env:EVERYOUT_CATALOG_PUBLIC_KEY -and ($env:EVERYOUT_CATALOG_PUBLIC_KEY -notmatch '^[a-fA-F0-9]{64}$' -or $env:EVERYOUT_CATALOG_URL -notlike 'https://*')) {
    throw 'Invalid catalog public trust inputs'
}
if ($env:SIGNPATH_ENABLED -eq 'true') {
    foreach ($name in @('SIGNPATH_ORGANIZATION_ID', 'SIGNPATH_PROJECT_SLUG', 'SIGNPATH_SIGNING_POLICY_SLUG',
        'SIGNPATH_HELPER_CONFIGURATION', 'SIGNPATH_HOST_CONFIGURATION', 'SIGNPATH_INSTALLER_CONFIGURATION',
        'SIGNPATH_CERTIFICATE_SUBJECT', 'SIGNPATH_API_TOKEN')) {
        if (-not [Environment]::GetEnvironmentVariable($name, 'Process')) { throw "Signing enabled but $name is missing" }
    }
}
Write-Output "Validated $Tag; signing enabled: $($env:SIGNPATH_ENABLED -eq 'true')"
