param([switch]$Local)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$pins = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'release-tools.json') -Raw | ConvertFrom-Json
if (-not $Local -and $env:ImageOS -ne $pins.imageOS) {
    throw "windows-latest image changed: expected $($pins.imageOS), got $env:ImageOS. Review pins first."
}
if ((node --version) -ne "v$($pins.node)" -or (pnpm --version) -ne $pins.pnpm) {
    throw 'Node/pnpm versions do not match release-tools.json'
}
if ((rustc --version) -notlike "rustc $($pins.rust) *") { throw 'Rust version mismatch' }
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or -not $vs) { throw 'MSVC installation not found' }
Import-Module (Join-Path $vs 'Common7/Tools/Microsoft.VisualStudio.DevShell.dll')
Enter-VsDevShell -VsInstallPath $vs -SkipAutomaticLocation -Arch amd64 -HostArch amd64 -DevCmdArguments "-vcvars_ver=$($pins.msvc) -winsdk=$($pins.windowsSdk)"
if ($env:VCToolsVersion.TrimEnd('\') -ne $pins.msvc -or $env:WindowsSDKVersion.TrimEnd('\') -ne $pins.windowsSdk) {
    throw 'Visual Studio selected unexpected compiler/SDK versions'
}
$env:TZ = 'UTC'
$env:LANG = 'en_US.UTF-8'
$env:LC_ALL = 'en_US.UTF-8'
$env:SOURCE_DATE_EPOCH = git -C $root show -s --format=%ct HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve source epoch' }
$checkout = $root.Replace('\', '/')
$cargoRoot = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE '.cargo' }
$env:RUSTFLAGS = "--remap-path-prefix=`"$checkout=/everyout`" --remap-path-prefix=`"$($cargoRoot.Replace('\', '/'))=/cargo`""
$env:CARGO_INCREMENTAL = '0'
# Persist only release controls and compiler environment, never arbitrary process variables.
if ($env:GITHUB_ENV) {
    foreach ($name in @('PATH', 'INCLUDE', 'LIB', 'LIBPATH', 'VCToolsInstallDir', 'VCToolsVersion',
        'WindowsSdkDir', 'WindowsSDKVersion', 'WindowsSdkBinPath', 'WindowsSdkVerBinPath',
        'VCINSTALLDIR', 'VSINSTALLDIR', 'TZ', 'LANG', 'LC_ALL', 'SOURCE_DATE_EPOCH', 'RUSTFLAGS', 'CARGO_INCREMENTAL')) {
        "$name=$([Environment]::GetEnvironmentVariable($name, 'Process'))" >> $env:GITHUB_ENV
    }
}
