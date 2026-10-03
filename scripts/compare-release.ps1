param(
    [Parameter(Mandatory)][string]$First,
    [Parameter(Mandatory)][string]$Second,
    [Parameter(Mandatory)][string]$Reference,
    [Parameter(Mandatory)][string]$Output
)
$ErrorActionPreference = 'Stop'
function Files([string]$Root) {
    $rootPath = (Resolve-Path -LiteralPath $Root).Path
    $result = @{}
    Get-ChildItem -LiteralPath $rootPath -File -Recurse | ForEach-Object {
        $name = $_.FullName.Substring($rootPath.Length + 1).Replace('\', '/')
        $result[$name] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $result
}
function PeMetadata([string]$Path) {
    if (-not $Path.EndsWith('.exe') -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $bytes = [IO.File]::ReadAllBytes([IO.Path]::GetFullPath($Path))
    if ($bytes.Length -lt 64 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) { return $null }
    $offset = [BitConverter]::ToInt32($bytes, 0x3c)
    if ($offset -lt 0 -or $offset + 24 -gt $bytes.Length -or [BitConverter]::ToUInt32($bytes, $offset) -ne 0x4550) { return $null }
    @{ machine = [BitConverter]::ToUInt16($bytes, $offset + 4)
        coffTimestamp = [BitConverter]::ToUInt32($bytes, $offset + 8) }
}
$one = Files $First
$two = Files $Second
$referenceFiles = Files $Reference
$rows = @(@($one.Keys) + @($two.Keys) + @($referenceFiles.Keys) | Sort-Object -Unique | ForEach-Object {
    $name = $_
    $match = $one.ContainsKey($name) -and $two.ContainsKey($name) -and $referenceFiles.ContainsKey($name) -and
        $one[$name] -eq $two[$name] -and $one[$name] -eq $referenceFiles[$name]
    $category = if ($name -like '*.msi' -or $name -like '*.pdb') { 'excluded-from-bit-reproducibility-claim' } else { 'unsigned-candidate' }
    @{ path = $name; first = $one[$name]; second = $two[$name]; release = $referenceFiles[$name]
        match = $match; category = $category
        firstPe = PeMetadata (Join-Path $First $name); secondPe = PeMetadata (Join-Path $Second $name)
        releasePe = PeMetadata (Join-Path $Reference $name) }
})
$failed = @($rows | Where-Object { -not $_.match })
$report = @{
    scope = 'two fresh target directories on one runner, plus the released unsigned checkpoints'
    independentReproduction = $false
    result = if ($failed.Count) { 'differences-detected' } else { 'all-compared-bytes-match' }
    files = $rows
    limitations = @('not independent environments', 'signed files are verified separately',
        'installer/PDB bytes are unverified candidates with path, identifier and timestamp inputs',
        'every mismatch remains a failed byte comparison, including unexplained unsigned PE/frontend differences')
}
[IO.File]::WriteAllText([IO.Path]::GetFullPath($Output), ($report | ConvertTo-Json -Depth 8) + "`n", [Text.UTF8Encoding]::new($false))
$summary = "Reproducibility: $($report.result). Compared $($rows.Count) files; $($failed.Count) differences."
Write-Output $summary
foreach ($row in $failed) { Write-Output "Difference: $($row.path) [$($row.category)]" }
if ($env:GITHUB_STEP_SUMMARY) {
    $summary >> $env:GITHUB_STEP_SUMMARY
    'This advisory comparison does not establish independent bit reproducibility. Review reproducibility.json before publication.' >> $env:GITHUB_STEP_SUMMARY
}
