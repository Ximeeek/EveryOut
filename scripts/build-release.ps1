param(
    [ValidateSet('Helper', 'Host', 'Bundle', 'Finalize', 'Unsigned')][string]$Stage = 'Unsigned',
    [string]$WorkDir = 'target/release-work',
    [switch]$Signed,
    [string]$ReferenceHelper
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path -Parent $PSScriptRoot
$target = 'x86_64-pc-windows-msvc'
$work = [IO.Path]::GetFullPath((Join-Path $root $WorkDir))
$allowed = [IO.Path]::GetFullPath((Join-Path $root 'target')) + [IO.Path]::DirectorySeparatorChar
if (-not $work.StartsWith($allowed, [StringComparison]::OrdinalIgnoreCase)) { throw 'WorkDir must be inside target/' }
$release = Join-Path $work "cargo/$target/release"
$checkpoints = Join-Path $work 'checkpoints'
$final = Join-Path $work 'final'
$assets = Join-Path $work 'assets'
$overlay = Join-Path $work 'tauri.release.json'
function Run([string]$Command, [string[]]$Arguments) {
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Command failed ($LASTEXITCODE)" }
}
function Hash([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function NormalizeTimes([string]$Path) {
    if ($env:SOURCE_DATE_EPOCH) {
        $epoch = [DateTimeOffset]::FromUnixTimeSeconds([long]$env:SOURCE_DATE_EPOCH).UtcDateTime
        Get-ChildItem -LiteralPath $Path -File -Recurse | ForEach-Object { $_.LastWriteTimeUtc = $epoch }
    }
}
function WriteJson([string]$Path, $Value) {
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 12) + "`n", [Text.UTF8Encoding]::new($false))
}
function Inventory([string]$Path) {
    @(Get-ChildItem -LiteralPath $Path -File -Recurse | Sort-Object FullName | ForEach-Object {
        @{ path = $_.FullName.Substring($Path.Length + 1).Replace('\', '/'); sha256 = Hash $_.FullName; bytes = $_.Length }
    })
}
function Signature([string]$Path) {
    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    if ($Signed) {
        if (-not $env:SIGNPATH_CERTIFICATE_SUBJECT) { throw 'Expected certificate subject must be configured' }
        if ($sig.Status -ne 'Valid' -or $null -eq $sig.SignerCertificate -or
            $sig.SignerCertificate.Subject -ne $env:SIGNPATH_CERTIFICATE_SUBJECT -or
            $null -eq $sig.TimeStamperCertificate) { throw "Invalid publisher/signature/timestamp: $Path" }
        Run 'signtool.exe' @('verify', '/pa', '/all', '/v', $Path)
    } elseif ($sig.Status -ne 'NotSigned' -and -not ($ReferenceHelper -and (Split-Path -Leaf $Path) -eq 'everyout-elevated-helper.exe')) {
        throw "Unsigned build unexpectedly contains a signature: $Path"
    }
    @{
        status = $sig.Status.ToString()
        subject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
        thumbprint = if ($sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { $null }
        timestampSubject = if ($sig.TimeStamperCertificate) { $sig.TimeStamperCertificate.Subject } else { $null }
    }
}
function CopyFinal([string]$Name, [string]$InputDir) {
    $inputPath = Join-Path $InputDir $Name
    if (-not (Test-Path -LiteralPath $inputPath -PathType Leaf)) { throw "Missing expected artifact: $inputPath" }
    $null = Signature $inputPath
    Copy-Item -LiteralPath $inputPath -Destination (Join-Path $final $Name) -Force
}
function Helper {
    if (Test-Path -LiteralPath $checkpoints) { throw 'Use a fresh WorkDir; checkpoints already exist' }
    foreach ($dir in @($checkpoints, $final, $assets, (Join-Path $work 'helper-input'),
        (Join-Path $work 'host-input'), (Join-Path $work 'installer-input'))) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    Run 'cargo' @('build', '--locked', '--release', '--target', $target, '-p', 'everyout-elevated-helper')
    $helper = Join-Path $release 'everyout-elevated-helper.exe'
    Copy-Item -LiteralPath $helper -Destination (Join-Path $checkpoints 'everyout-elevated-helper.exe')
    Copy-Item -LiteralPath $helper -Destination (Join-Path $work 'helper-input/everyout-elevated-helper.exe')
}
function Host {
    $helperDir = if ($Signed) { Join-Path $work 'signed-helper' } else { Join-Path $work 'helper-input' }
    if ($ReferenceHelper) {
        # A signed release helper is an explicit input to an otherwise unsigned host comparison.
        Copy-Item -LiteralPath $ReferenceHelper -Destination (Join-Path $final 'everyout-elevated-helper.exe') -Force
    } else { CopyFinal 'everyout-elevated-helper.exe' $helperDir }
    $env:EVERYOUT_HELPER_SHA256 = Hash (Join-Path $final 'everyout-elevated-helper.exe')
    $sidecar = Join-Path $work 'sidecar'
    New-Item -ItemType Directory -Path $sidecar -Force | Out-Null
    $base = Join-Path $sidecar 'everyout-elevated-helper'
    Copy-Item -LiteralPath (Join-Path $final 'everyout-elevated-helper.exe') -Destination "$base-$target.exe" -Force
    # MSI only; WebView2 is a separately installed prerequisite, never a changing bundled payload.
    WriteJson $overlay @{ bundle = @{ targets = @('msi'); externalBin = @($base);
        windows = @{ webviewInstallMode = @{ type = 'skip' } } } }
    Run 'pnpm' @('tauri', 'build', '--ci', '--target', $target, '--no-bundle', '--config', $overlay, '--', '--locked')
    Copy-Item -LiteralPath (Join-Path $release 'everyout.exe') -Destination (Join-Path $checkpoints 'everyout.exe')
    Copy-Item -LiteralPath (Join-Path $release 'everyout.exe') -Destination (Join-Path $work 'host-input/everyout.exe')
    Copy-Item -LiteralPath (Join-Path $root 'dist') -Destination (Join-Path $checkpoints 'frontend') -Recurse
    Get-ChildItem -LiteralPath $release -Filter '*.pdb' -File | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $checkpoints
    }
    WriteJson (Join-Path $work 'host-inputs.json') @{
        helperSha256 = $env:EVERYOUT_HELPER_SHA256; overlay = Get-Content -LiteralPath $overlay -Raw | ConvertFrom-Json
        catalogPublicKey = $env:EVERYOUT_CATALOG_PUBLIC_KEY; catalogUrl = $env:EVERYOUT_CATALOG_URL
    }
}
function Bundle {
    $hostDir = if ($Signed) { Join-Path $work 'signed-host' } else { Join-Path $work 'host-input' }
    CopyFinal 'everyout.exe' $hostDir
    Copy-Item -LiteralPath (Join-Path $final 'everyout.exe') -Destination (Join-Path $release 'everyout.exe') -Force
    NormalizeTimes $final
    NormalizeTimes (Join-Path $work 'sidecar')
    (Get-Item -LiteralPath (Join-Path $release 'everyout.exe')).LastWriteTimeUtc = (Get-Item -LiteralPath (Join-Path $final 'everyout.exe')).LastWriteTimeUtc
    $pins = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'release-tools.json') -Raw | ConvertFrom-Json
    $wixZip = Join-Path $work 'wix314-binaries.zip'
    $wixExpected = Join-Path $work 'wix-input'
    if (Test-Path -LiteralPath $wixExpected) { throw 'Use a fresh WiX input directory' }
    Invoke-WebRequest -Uri $pins.wixUrl -OutFile $wixZip
    if ((Hash $wixZip) -ne $pins.wixSha256) { throw 'Pinned WiX download hash mismatch' }
    Expand-Archive -LiteralPath $wixZip -DestinationPath $wixExpected
    $wixCache = Join-Path $env:LOCALAPPDATA 'tauri/WixTools314'
    $expected = Inventory $wixExpected
    if (Test-Path -LiteralPath $wixCache) {
        foreach ($file in $expected) {
            $cached = Join-Path $wixCache $file.path
            if (-not (Test-Path -LiteralPath $cached -PathType Leaf) -or (Hash $cached) -ne $file.sha256) {
                throw "Cached WiX input differs from pinned archive: $($file.path)"
            }
        }
    }
    Run 'pnpm' @('tauri', 'bundle', '--ci', '--target', $target, '--bundles', 'msi', '--no-sign', '--no-binary-patching', '--config', $overlay)
    foreach ($file in $expected) {
        $cached = Join-Path $wixCache $file.path
        if (-not (Test-Path -LiteralPath $cached -PathType Leaf) -or (Hash $cached) -ne $file.sha256) {
            throw "Bundler did not use the pinned WiX input: $($file.path)"
        }
    }
    if ((Hash (Join-Path $release 'everyout.exe')) -ne (Hash (Join-Path $final 'everyout.exe'))) {
        throw 'Bundling modified the final host'
    }
    $msi = @(Get-ChildItem -LiteralPath (Join-Path $release 'bundle/msi') -Filter '*.msi' -File)
    if ($msi.Count -ne 1) { throw 'Expected exactly one MSI' }
    Copy-Item -LiteralPath $msi[0].FullName -Destination (Join-Path $work 'installer-input/EveryOut-x64.msi')
    Copy-Item -LiteralPath $msi[0].FullName -Destination (Join-Path $checkpoints 'EveryOut-x64.msi')
}
function Finalize {
    $installerDir = if ($Signed) { Join-Path $work 'signed-installer' } else { Join-Path $work 'installer-input' }
    CopyFinal 'EveryOut-x64.msi' $installerDir
    $extract = Join-Path $work 'extracted'
    if (Test-Path -LiteralPath $extract) { throw 'Use a fresh extraction directory' }
    New-Item -ItemType Directory -Path $extract | Out-Null
    # Administrative extraction only: does not install or run EveryOut.
    $installer = Join-Path $final 'EveryOut-x64.msi'
    $args = "/a `"$installer`" /qn TARGETDIR=`"$extract`" /l*v `"$(Join-Path $work 'msi-extract.log')`""
    $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $args -Wait -PassThru -WindowStyle Hidden
    if ($process.ExitCode -ne 0) { throw "MSI extraction failed ($($process.ExitCode))" }
    $signatures = @{}
    foreach ($name in @('everyout.exe', 'everyout-elevated-helper.exe')) {
        $files = @(Get-ChildItem -LiteralPath $extract -Recurse -File -Filter $name)
        if ($files.Count -ne 1 -or (Hash $files[0].FullName) -ne (Hash (Join-Path $final $name))) {
            throw "Packaged $name differs from the final input"
        }
        $signatures[$name] = Signature $files[0].FullName
    }
    $signatures['EveryOut-x64.msi'] = Signature $installer
    $inputs = Get-Content -LiteralPath (Join-Path $work 'host-inputs.json') -Raw | ConvertFrom-Json
    if ($inputs.helperSha256 -ne (Hash (Join-Path $final 'everyout-elevated-helper.exe'))) { throw 'Final helper pin mismatch' }
    Copy-Item -LiteralPath $installer -Destination $assets
    Copy-Item -LiteralPath (Join-Path $root 'LICENSE') -Destination $assets
    NormalizeTimes $checkpoints
    NormalizeTimes $final
    Compress-Archive -LiteralPath $checkpoints -DestinationPath (Join-Path $assets 'unsigned-checkpoints.zip')
    Compress-Archive -LiteralPath (Join-Path $final 'everyout.exe'), (Join-Path $final 'everyout-elevated-helper.exe') -DestinationPath (Join-Path $assets 'final-binaries.zip')
    $cache = Join-Path $env:LOCALAPPDATA 'tauri/WixTools314'
    $toolInputs = @{}
    foreach ($name in @('cl.exe', 'link.exe', 'rc.exe', 'signtool.exe')) {
        $tool = Get-Command $name -ErrorAction SilentlyContinue
        if ($tool) {
            $toolInputs[$name] = @{ path = $tool.Source; sha256 = Hash $tool.Source
                version = (Get-Item -LiteralPath $tool.Source).VersionInfo.FileVersion }
        }
    }
    WriteJson (Join-Path $assets 'build-inputs.json') @{
        source = (git rev-parse HEAD); tag = $env:GITHUB_REF_NAME; submodules = @(git submodule status)
        run = "$env:GITHUB_SERVER_URL/$env:GITHUB_REPOSITORY/actions/runs/$env:GITHUB_RUN_ID"
        runAttempt = $env:GITHUB_RUN_ATTEMPT; job = $env:GITHUB_JOB
        signing = if ($Signed) { 'signpath' } else { 'unsigned' }; signatures = $signatures
        pins = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'release-tools.json') -Raw | ConvertFrom-Json
        actual = @{ rust = (rustc -Vv); node = (node --version); pnpm = (pnpm --version); tauri = (pnpm exec tauri --version)
            imageOS = $env:ImageOS; imageVersion = $env:ImageVersion; msvc = $env:VCToolsVersion
            sdk = $env:WindowsSDKVersion; linker = (Get-Command link.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source) }
        flags = @{ target = $target; profile = 'release'; features = @(); rustflags = $env:RUSTFLAGS
            sourceDateEpoch = $env:SOURCE_DATE_EPOCH; timezone = $env:TZ; locale = $env:LANG }
        lockfiles = @{ cargo = Hash (Join-Path $root 'Cargo.lock'); pnpm = Hash (Join-Path $root 'pnpm-lock.yaml') }
        hostInputs = $inputs; unsignedCheckpoints = Inventory $checkpoints; finalBinaries = Inventory $final
        windowsTools = $toolInputs; wixArchiveSha256 = Hash (Join-Path $work 'wix314-binaries.zip')
        bundlerCache = if (Test-Path -LiteralPath $cache) { Inventory $cache } else { @() }
        commands = @('cargo build --locked --release --target x86_64-pc-windows-msvc -p everyout-elevated-helper',
            'pnpm tauri build --ci --target x86_64-pc-windows-msvc --no-bundle --config <overlay> -- --locked',
            'pnpm tauri bundle --ci --target x86_64-pc-windows-msvc --bundles msi --no-sign --no-binary-patching --config <overlay>')
        helperSigningRequest = $env:HELPER_SIGNING_REQUEST; hostSigningRequest = $env:HOST_SIGNING_REQUEST
        installerSigningRequest = $env:INSTALLER_SIGNING_REQUEST
    }
}
$saved = @{}
foreach ($name in @('CARGO_TARGET_DIR', 'EVERYOUT_HELPER_SHA256', 'RUSTFLAGS')) { $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
Push-Location -LiteralPath $root
try {
    $env:CARGO_TARGET_DIR = Join-Path $work 'cargo'
    foreach ($name in @('EVERYOUT_CATALOG_PUBLIC_KEY', 'EVERYOUT_CATALOG_URL')) {
        if (-not [Environment]::GetEnvironmentVariable($name, 'Process')) { Remove-Item -LiteralPath "Env:\$name" -ErrorAction SilentlyContinue }
    }
    if ($env:RUSTFLAGS) { $env:RUSTFLAGS += " --remap-path-prefix=`"$($work.Replace('\', '/'))=/build`"" }
    if ($Stage -eq 'Unsigned') {
        if ($Signed) { throw 'Unsigned orchestration cannot enable signing' }
        Helper; Host; Bundle; Finalize
    } else { & $Stage }
} finally {
    foreach ($name in $saved.Keys) {
        if ($null -eq $saved[$name]) { Remove-Item -LiteralPath "Env:\$name" -ErrorAction SilentlyContinue }
        else { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
    }
    Pop-Location
}
