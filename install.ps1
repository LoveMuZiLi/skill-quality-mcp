# Install the skill-quality plugin (MCP server + skill) into Cursor and/or Codex.
#   Local:  powershell -ExecutionPolicy Bypass -File install.ps1
#   Remote: irm https://raw.githubusercontent.com/LoveMuZiLi/skill-quality-mcp/main/install.ps1 | iex
param(
    [string]$Repo = 'LoveMuZiLi/skill-quality-mcp',
    [string]$Ref = 'main',
    [switch]$CursorOnly,
    [switch]$CodexOnly
)
# Not 'Stop' globally: in Windows PowerShell 5.1 any stderr line from pip/codex would abort the script.
# Native commands are checked through $LASTEXITCODE instead.
$ErrorActionPreference = 'Continue'
$PluginName = 'skill-quality'
$Marketplace = 'skill-quality-mcp'

# git and codex ignore the Windows system proxy; hand it to them when github.com is only reachable through it.
if (-not $env:HTTPS_PROXY) {
    $inet = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    if ($inet -and $inet.ProxyEnable -eq 1 -and $inet.ProxyServer -match '^[\w\.\-]+:\d+$') {
        $env:HTTPS_PROXY = "http://$($inet.ProxyServer)"
        $env:HTTP_PROXY = $env:HTTPS_PROXY
        Write-Host "Using system proxy $env:HTTPS_PROXY"
    }
}

function Find-Python {
    foreach ($name in 'python', 'py') {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source -notlike '*WindowsApps*') { return $cmd.Source }
    }
    throw 'Python 3.10+ not found on PATH. Install it from https://www.python.org/downloads/ (tick "Add to PATH").'
}

function Find-Codex {
    $cmd = Get-Command codex -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $bin = Join-Path $env:LOCALAPPDATA 'OpenAI\Codex\bin'
    if (Test-Path $bin) {
        $exe = Get-ChildItem $bin -Recurse -Filter codex.exe -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($exe) { return $exe.FullName }
    }
    return $null
}

# 1. Source: this repo if run from a clone, otherwise download it from GitHub.
$Root = $PSScriptRoot
$IsLocal = $Root -and (Test-Path (Join-Path $Root "plugins\$PluginName\server.py"))
if (-not $IsLocal) {
    $tmp = Join-Path $env:TEMP "skill-quality-mcp-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $tmp -ErrorAction Stop | Out-Null
    $zip = Join-Path $tmp 'repo.zip'
    Write-Host "Downloading $Repo@$Ref ..."
    Invoke-WebRequest "https://codeload.github.com/$Repo/zip/refs/heads/$Ref" -OutFile $zip -UseBasicParsing -ErrorAction Stop
    Expand-Archive $zip -DestinationPath $tmp -ErrorAction Stop
    $Root = (Get-ChildItem $tmp -Directory | Select-Object -First 1).FullName
}
$Plugin = Join-Path $Root "plugins\$PluginName"

# 2. Python dependency.
$py = Find-Python
Write-Host "Using Python: $py"
& $py -m pip install --user --quiet --disable-pip-version-check 'mcp>=2.3'
if ($LASTEXITCODE -ne 0) { throw 'pip install mcp failed' }

# 3. Cursor: local plugin folder (must be a real copy, symlinks outside plugins/local are ignored).
if (-not $CodexOnly) {
    $dest = Join-Path $env:USERPROFILE ".cursor\plugins\local\$PluginName"
    if (Test-Path $dest) { Remove-Item $dest -Recurse -Force -ErrorAction Stop }
    New-Item -ItemType Directory -Path $dest -Force -ErrorAction Stop | Out-Null
    robocopy $Plugin $dest /E /XD __pycache__ /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "Copy to $dest failed" }
    Write-Host "Cursor: installed to $dest  ->  run 'Developer: Reload Window' in Cursor"
}

# 4. Codex: add this repo as a plugin marketplace, then install the plugin.
if (-not $CursorOnly) {
    $codex = Find-Codex
    if (-not $codex) {
        Write-Warning 'Codex CLI not found; skipped Codex. Install Codex, then re-run with -CodexOnly.'
    } else {
        $source = if ($IsLocal) { $Root } else { $Repo }
        & $codex plugin marketplace remove $Marketplace 2>$null | Out-Null
        & $codex plugin marketplace add $source
        if ($LASTEXITCODE -ne 0) { throw 'codex plugin marketplace add failed' }
        & $codex plugin add "$PluginName@$Marketplace"
        if ($LASTEXITCODE -ne 0) { throw 'codex plugin add failed' }
        Write-Host 'Codex: plugin installed  ->  open a NEW Codex thread to use it'
    }
}
Write-Host 'Done. Optional: set SONAR_HOST_URL / SONAR_TOKEN / SONAR_PROJECT_KEY environment variables for SonarQube.'
