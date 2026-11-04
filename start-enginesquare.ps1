param(
    [string]$MiddlewareUrl,
    [string]$Python = 'python'
)
$ErrorActionPreference = 'Stop'
# Read simple KEY=value settings as data, never execute .env contents.
# Existing process variables win; an explicit -MiddlewareUrl wins over both.
$envFile = Join-Path $PSScriptRoot '.env'
if (Test-Path -LiteralPath $envFile) {
    foreach ($line in Get-Content -LiteralPath $envFile -Encoding UTF8) {
        if ($line -match '^\s*(#|$)') { continue }
        if ($line -notmatch '^\s*([A-Z][A-Z0-9_]*)\s*=(.*)$') {
            throw 'Invalid .env line. Use KEY=value; values are not printed.'
        }
        $name, $value = $Matches[1], $Matches[2].Trim()
        if ($name -notmatch '^(MIDDLEWARE_(INGEST_URL|API_KEY)|ENGINESQUARE_(DB_(HOST|PORT|USER|PASSWORD|NAME)|KEY_DELIVERY_SECRET))$') {
            throw "Unsupported .env setting: $name"
        }
        if ($value.Length -ge 2 -and (($value.StartsWith('"') -and $value.EndsWith('"')) -or
                                      ($value.StartsWith("'") -and $value.EndsWith("'")))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        if (-not [Environment]::GetEnvironmentVariable($name, 'Process')) {
            [Environment]::SetEnvironmentVariable($name, $value, 'Process')
        }
    }
}
# Secrets stay in the ignored .env or process environment, never this script/logs.
if (-not $env:MIDDLEWARE_API_KEY) {
    $secret = Read-Host 'Middleware API key' -AsSecureString
    $credential = [PSCredential]::new('ingest', $secret)
    $env:MIDDLEWARE_API_KEY = $credential.GetNetworkCredential().Password
}
if ($MiddlewareUrl) { $env:MIDDLEWARE_INGEST_URL = $MiddlewareUrl }
elseif (-not $env:MIDDLEWARE_INGEST_URL) { $env:MIDDLEWARE_INGEST_URL = 'http://localhost:8000/ingest' }
$env:ENGINESQUARE_DEBUG = '0'
$pythonExe = (Get-Command $Python -ErrorAction Stop).Source
$logDir = Join-Path $PSScriptRoot '.runtime-logs'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$children = @()
try {
    # Start the follower before the API so startup requests are not missed.
    $children += Start-Process -FilePath $pythonExe `
        -ArgumentList '-u', 'scenario3-api-key-compromised/wazuh/forward_api_logs.py' `
        -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $logDir 'wazuh.out.log') `
        -RedirectStandardError (Join-Path $logDir 'wazuh.err.log')
    foreach ($server in @(@{Name='web'; Directory='web-app'}, @{Name='api'; Directory='.'})) {
        $children += Start-Process -FilePath $pythonExe -ArgumentList '-u', 'app.py' `
            -WorkingDirectory (Join-Path $PSScriptRoot $server.Directory) `
            -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput (Join-Path $logDir ($server.Name + '.out.log')) `
            -RedirectStandardError (Join-Path $logDir ($server.Name + '.err.log'))
    }
    Write-Host 'Web: http://127.0.0.1:5001/   API: http://127.0.0.1:5000/health'
    Write-Host 'Wazuh API log forwarding is also launched (new events only).'
    Write-Host "Logs: $logDir (including wazuh.out.log / wazuh.err.log). Docker/MySQL/Middleware/Wazuh must already be running."
    Start-Sleep -Seconds 1
    foreach ($child in $children) {
        if ($child.HasExited) { throw "A launched process exited. Check logs in $logDir" }
    }
    Read-Host 'Press Enter to stop API, Web and Wazuh forwarding' | Out-Null
}
finally {
    foreach ($child in $children) {
        if (-not $child.HasExited) { Stop-Process -Id $child.Id -ErrorAction SilentlyContinue }
    }
}
