$ErrorActionPreference = 'Stop'
function Check([string]$Command, [string[]]$Arguments) {
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Command failed ($LASTEXITCODE)" }
}
foreach ($name in @('EVERYOUT_CATALOG_PUBLIC_KEY', 'EVERYOUT_CATALOG_URL')) {
    if (-not [Environment]::GetEnvironmentVariable($name, 'Process')) { Remove-Item -LiteralPath "Env:\$name" -ErrorAction SilentlyContinue }
}
Check 'cargo' @('fmt', '--all', '--', '--check')
Check 'cargo' @('build', '--locked', '--workspace')
Check 'cargo' @('clippy', '--locked', '--workspace', '--all-targets', '--', '-D', 'warnings')
Check 'cargo' @('test', '--locked', '--workspace')
Check 'cargo' @('run', '--locked', '-p', 'xtask', '--', 'catalog-validate')
Check 'cargo' @('run', '--locked', '-p', 'xtask', '--', 'catalog-table', '--check')
Check 'cargo' @('run', '--locked', '-p', 'everyout', '--example', 'bindings', '--', '--check')
foreach ($task in @('lint', 'typecheck', 'test', 'format:check', 'build')) { Check 'pnpm' @($task) }
& (Join-Path $PSScriptRoot 'test-release.ps1')
