$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
function Assert([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
foreach ($script in Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' -File) {
    $tokens = $null; $parseErrors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile($script.FullName, [ref]$tokens, [ref]$parseErrors)
    Assert ($parseErrors.Count -eq 0) "PowerShell syntax errors: $($script.Name): $parseErrors"
}
$scratch = Join-Path $root ('target/release-tests-' + [Guid]::NewGuid().ToString('N'))
foreach ($dir in @('one', 'two', 'reference')) {
    New-Item -ItemType Directory -Path (Join-Path $scratch $dir) -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $scratch "$dir/sample.exe"), 'same')
}
$reportPath = Join-Path $scratch 'report.json'
& (Join-Path $PSScriptRoot 'compare-release.ps1') -First (Join-Path $scratch 'one') -Second (Join-Path $scratch 'two') -Reference (Join-Path $scratch 'reference') -Output $reportPath
$report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
Assert ($report.result -eq 'all-compared-bytes-match') 'Equal files must match'
[IO.File]::WriteAllText((Join-Path $scratch 'two/sample.exe'), 'changed')
[IO.File]::WriteAllText((Join-Path $scratch 'reference/missing.pdb'), 'only reference')
& (Join-Path $PSScriptRoot 'compare-release.ps1') -First (Join-Path $scratch 'one') -Second (Join-Path $scratch 'two') -Reference (Join-Path $scratch 'reference') -Output $reportPath
$report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
Assert ($report.result -eq 'differences-detected' -and $report.files.Count -eq 2) 'Changed/missing files must remain visible'
Assert (@($report.files | Where-Object match).Count -eq 0) 'No mismatched file may be reported as matching'
$readme = Get-Content -LiteralPath (Join-Path $root 'README.md') -Raw
$original = Get-Content -LiteralPath (Join-Path $root 'docs/architecture/08-not-doing.md') -Raw
$original = $original -replace '^# ', '### ' -replace '(?m)^## ', '### '
$original = [regex]::Replace($original, '\]\(([^)]+)\)', {
    param($m)
    $path = $m.Groups[1].Value
    if ($path.StartsWith('../')) { '](docs/' + $path.Substring(3) + ')' }
    else { '](docs/architecture/' + $path + ')' }
})
$copy = [regex]::Match($readme, '(?s)<!-- v1-exclusions:start -->(.*?)<!-- v1-exclusions:end -->').Groups[1].Value
Assert (($original -replace '\s+', ' ').Trim() -eq ($copy -replace '\s+', ' ').Trim()) 'README must preserve all V1 exclusion content, with only heading/link rebasing and whitespace changes'
$saved = @{}
$names = @('SIGNPATH_ENABLED', 'SIGNPATH_API_TOKEN', 'EVERYOUT_CATALOG_PUBLIC_KEY', 'EVERYOUT_CATALOG_URL')
foreach ($name in $names) { $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process'); Remove-Item -LiteralPath "Env:\$name" -ErrorAction SilentlyContinue }
try {
    $version = (Get-Content -LiteralPath (Join-Path $root 'package.json') -Raw | ConvertFrom-Json).version
    & (Join-Path $PSScriptRoot 'validate-release.ps1') -Tag "v$version"
    foreach ($case in @('bad-tag', 'wrong-version', 'missing-signing-secret', 'unpaired-catalog')) {
        $env:SIGNPATH_ENABLED = $null; $env:EVERYOUT_CATALOG_PUBLIC_KEY = $null
        $tag = "v$version"
        switch ($case) {
            'bad-tag' { $tag = 'vanything' }
            'wrong-version' { $tag = 'v999.0.0' }
            'missing-signing-secret' { $env:SIGNPATH_ENABLED = 'true' }
            'unpaired-catalog' { $env:EVERYOUT_CATALOG_PUBLIC_KEY = 'a' * 64 }
        }
        $rejected = $false
        try { & (Join-Path $PSScriptRoot 'validate-release.ps1') -Tag $tag } catch { $rejected = $true }
        Assert $rejected "Invalid case was accepted: $case"
    }
} finally {
    foreach ($name in $names) {
        if ($null -eq $saved[$name]) { Remove-Item -LiteralPath "Env:\$name" -ErrorAction SilentlyContinue }
        else { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
    }
}
& {
    $mock = @{ existing = $true; created = @() }
    # Resolve this function before gh.exe: the test never writes to GitHub.
    function gh {
        $global:LASTEXITCODE = 0
        if ($args[0] -eq 'api') { if ($mock.existing) { '123' } }
        elseif ($args[0] -eq 'release') { $mock.created = @($args) }
        else { throw 'Unexpected GitHub CLI operation' }
    }
    $envNames = @('GITHUB_REF_NAME', 'GITHUB_SHA', 'GITHUB_REPOSITORY', 'RUNNER_TEMP', 'VERIFY_RESULT')
    $previous = @{}
    foreach ($name in $envNames) { $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
    $draftRoot = Join-Path $scratch 'draft-test'
    $draftAssets = Join-Path $draftRoot 'target/draft-assets'
    New-Item -ItemType Directory -Path $draftAssets -Force | Out-Null
    $env:GITHUB_REF_NAME = 'v0.1.0'; $env:GITHUB_SHA = 'test-source'; $env:GITHUB_REPOSITORY = 'test/repository'
    $env:RUNNER_TEMP = $scratch; $env:VERIFY_RESULT = 'failure'
    @{ source = 'test-source'; tag = 'v0.1.0'; signing = 'unsigned'; run = 'test-run' } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $draftAssets 'build-inputs.json')
    [IO.File]::WriteAllText((Join-Path $draftAssets 'EveryOut-x64.msi'), 'test fixture only')
    Push-Location -LiteralPath $draftRoot
    try {
        $refused = $false
        try { & (Join-Path $PSScriptRoot 'create-release-draft.ps1') } catch { $refused = $true }
        Assert ($refused -and $mock.created.Count -eq 0) 'An existing release must never be overwritten'
        $mock.existing = $false
        & (Join-Path $PSScriptRoot 'create-release-draft.ps1')
        Assert ($mock.created -contains '--draft' -and $mock.created -contains '--verify-tag' -and
            $mock.created -contains '--prerelease' -and $mock.created -notcontains '--clobber') 'Unsigned creation must remain a verified-tag draft prerelease'
        $lines = Get-Content -LiteralPath (Join-Path $draftAssets 'SHA256SUMS.txt')
        Assert (@($lines | Where-Object { $_ -match 'SHA256SUMS.txt' }).Count -eq 0) 'Checksums must exclude themselves'
        foreach ($line in $lines) {
            Assert ($line -match '^([a-f0-9]{64})  (.+)$') 'Invalid checksum format'
            $actual = (Get-FileHash -LiteralPath (Join-Path $draftAssets $matches[2]) -Algorithm SHA256).Hash.ToLowerInvariant()
            Assert ($actual -eq $matches[1]) 'Checksum must match the final asset bytes'
        }
        $missing = Get-Content -LiteralPath (Join-Path $draftAssets 'reproducibility.json') -Raw | ConvertFrom-Json
        Assert ($missing.result -eq 'comparison-unavailable') 'Failed verification must be visible in draft evidence'
    } finally {
        Pop-Location
        foreach ($name in $envNames) {
            if ($null -eq $previous[$name]) { Remove-Item -LiteralPath "Env:\$name" -ErrorAction SilentlyContinue }
            else { [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process') }
        }
    }
}
Write-Output 'Release script checks passed (syntax, comparisons, version and signing gates).'
