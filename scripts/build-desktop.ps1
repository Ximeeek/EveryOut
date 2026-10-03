param([switch]$NoBundle)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $projectRoot
$previousPin = $env:EVERYOUT_HELPER_SHA256
try {
    # Pin only the binary just built from this checkout, before compiling the host.
    cargo build --locked --release -p everyout-elevated-helper
    if ($LASTEXITCODE -ne 0) { throw 'Helper build failed' }
    $helperPath = Join-Path $projectRoot 'target/release/everyout-elevated-helper.exe'
    $env:EVERYOUT_HELPER_SHA256 = (Get-FileHash -LiteralPath $helperPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $bundleRoot = Join-Path $projectRoot 'target/helper-bundle'
    New-Item -ItemType Directory -Path $bundleRoot -Force | Out-Null
    $bundleBase = Join-Path $bundleRoot 'everyout-elevated-helper'
    Copy-Item -LiteralPath $helperPath -Destination ($bundleBase + '-x86_64-pc-windows-msvc.exe') -Force
    $overlayPath = Join-Path $bundleRoot 'tauri.helper.json'
    $overlay = @{ bundle = @{ externalBin = @($bundleBase) } } | ConvertTo-Json -Depth 4
    [IO.File]::WriteAllText($overlayPath, $overlay)
    if ($NoBundle) { pnpm tauri build --no-bundle --config $overlayPath }
    else { pnpm tauri build --config $overlayPath }
    if ($LASTEXITCODE -ne 0) { throw 'Desktop build failed' }
} finally { $env:EVERYOUT_HELPER_SHA256 = $previousPin; Pop-Location }
