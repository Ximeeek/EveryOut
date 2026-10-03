$ErrorActionPreference = 'Stop'
$assets = (Resolve-Path -LiteralPath 'target/draft-assets').Path
$tag = $env:GITHUB_REF_NAME
if ($tag -notmatch '^v[0-9A-Za-z.+-]+$') { throw 'Invalid release tag' }
if (-not (Test-Path -LiteralPath (Join-Path $assets 'reproducibility.json'))) {
    @{ result = 'comparison-unavailable'; jobResult = $env:VERIFY_RESULT; independentReproduction = $false } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $assets 'reproducibility.json')
}
$manifest = Get-Content -LiteralPath (Join-Path $assets 'build-inputs.json') -Raw | ConvertFrom-Json
$report = Get-Content -LiteralPath (Join-Path $assets 'reproducibility.json') -Raw | ConvertFrom-Json
if ($manifest.source -ne $env:GITHUB_SHA -or $manifest.tag -ne $tag) { throw 'Artifact source/tag differs from release checkout' }
$files = @(Get-ChildItem -LiteralPath $assets -File | Where-Object Name -ne 'SHA256SUMS.txt' | Sort-Object Name)
$checksums = @($files | ForEach-Object {
    "{0}  {1}" -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $_.Name
})
[IO.File]::WriteAllLines((Join-Path $assets 'SHA256SUMS.txt'), $checksums, [Text.UTF8Encoding]::new($false))
$notes = @"
EveryOut $tag — $($manifest.signing)

Draft only. Maintainer review and disposable-VM validation are required before publication.
Permanent data loss is possible; local clearing does not invalidate server-side sessions.
Reproducibility comparison: $($report.result). Inspect reproducibility.json; no independent
bit-reproducibility claim is made. Verify SHA256SUMS.txt and build-inputs.json before installation.
Source: $($manifest.source)
Build: $($manifest.run)

Review CHANGELOG.md at this tag, the code signing policy and docs/oss/release-process.md.
An unsigned draft is marked as a prerelease, including tags without a prerelease suffix.
"@
$notesFile = Join-Path $env:RUNNER_TEMP 'everyout-release-notes.md'
[IO.File]::WriteAllText($notesFile, $notes, [Text.UTF8Encoding]::new($false))
# List drafts using the authenticated API. Never edit or replace an existing release.
$existing = gh api --paginate "repos/$env:GITHUB_REPOSITORY/releases" --jq '.[] | select(.tag_name == env.GITHUB_REF_NAME) | .id'
if ($LASTEXITCODE -ne 0) { throw 'Could not inspect existing releases' }
if ($existing) { throw 'Release already exists; review it manually instead of replacing assets' }
$arguments = @('release', 'create', $tag, '--repo', $env:GITHUB_REPOSITORY, '--verify-tag', '--draft',
    '--title', "EveryOut $tag ($($manifest.signing))", '--notes-file', $notesFile)
if ($manifest.signing -eq 'unsigned' -or $tag.Contains('-')) { $arguments += '--prerelease' }
$arguments += @(Get-ChildItem -LiteralPath $assets -File | Sort-Object Name | Select-Object -ExpandProperty FullName)
& gh @arguments
if ($LASTEXITCODE -ne 0) { throw 'Draft creation failed' }
