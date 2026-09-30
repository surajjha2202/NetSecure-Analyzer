$ErrorActionPreference = "Stop"
# Railway CLI is installed on D:
$env:Path = "D:\npm-global;$env:Path"

# ============================================================
# NetSecure Analyzer - Automatic Live Scan Startup
# ============================================================

$ProjectRoot = "D:\NetSecure-Analyzer"
$ScannerDir  = "$ProjectRoot\scanner-agent"

$TunnelExe   = "D:\NetSecure-Analyzer\tools\cloudflared.exe"
$PythonExe = "$ScannerDir\.venv\Scripts\python.exe"

$ScannerHost = "127.0.0.1"
$ScannerPort = 8787

$TokenFile = "$ScannerDir\.scanner-token"

$TunnelOut = "$env:TEMP\netsecure-cloudflared-out.log"
$TunnelErr = "$env:TEMP\netsecure-cloudflared-err.log"

$RailwayHealth = "https://netsecure-analyzer-production.up.railway.app/api/health"

Write-Host ""
Write-Host "=================================================="
Write-Host "     NETSECURE ANALYZER - LIVE SCAN STARTUP"
Write-Host "=================================================="
Write-Host ""

# ------------------------------------------------------------
# 1. Check required files
# ------------------------------------------------------------

if (-not (Test-Path $PythonExe)) {
    Write-Host "ERROR: Scanner agent Python environment not found:"
    Write-Host $PythonExe
    exit 1
}

if (-not (Test-Path $TunnelExe)) {
    Write-Host "ERROR: cloudflared.exe not found:"
    Write-Host $TunnelExe
    exit 1
}

# ------------------------------------------------------------
# 2. Load scanner token
# ------------------------------------------------------------

if (Test-Path $TokenFile) {

    Write-Host "[1/6] Loading saved scanner token..."

    try {
        $encryptedToken = Get-Content $TokenFile -Raw
        $secureToken = $encryptedToken | ConvertTo-SecureString

        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)

        try {
            $env:SCANNER_TOKEN =
                [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
    catch {
        Write-Host "ERROR: Could not load saved scanner token."
        exit 1
    }

}
else {

    Write-Host "[1/6] First-time scanner setup."
    Write-Host ""

    $secureToken = Read-Host "Enter your SCANNER_TOKEN" -AsSecureString

    $secureToken |
        ConvertFrom-SecureString |
        Set-Content $TokenFile

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)

    try {
        $env:SCANNER_TOKEN =
            [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }

    Write-Host "Scanner token saved."
}

if (-not $env:SCANNER_TOKEN) {
    Write-Host "ERROR: SCANNER_TOKEN is empty."
    exit 1
}

# ------------------------------------------------------------
# 3. Start scanner agent
# ------------------------------------------------------------

Write-Host ""
Write-Host "[2/6] Checking scanner agent..."

$scannerRunning = $false

try {
    $health = Invoke-RestMethod `
        -Uri "http://$ScannerHost`:$ScannerPort/health" `
        -TimeoutSec 3

    if ($health.status -eq "ok") {
        $scannerRunning = $true
    }
}
catch {
    $scannerRunning = $false
}

if ($scannerRunning) {

    Write-Host "Scanner agent already running."

}
else {

    Write-Host "Starting scanner agent..."

    Start-Process `
        -FilePath $PythonExe `
        -ArgumentList "-m uvicorn agent:app --host $ScannerHost --port $ScannerPort" `
        -WorkingDirectory $ScannerDir `
        -WindowStyle Minimized

    $ready = $false

    for ($i = 1; $i -le 30; $i++) {

        Start-Sleep -Seconds 1

        try {

            $health = Invoke-RestMethod `
                -Uri "http://$ScannerHost`:$ScannerPort/health" `
                -TimeoutSec 3

            if ($health.status -eq "ok") {
                $ready = $true
                break
            }

        }
        catch {
        }
    }

    if (-not $ready) {
        Write-Host "ERROR: Scanner agent failed to start."
        exit 1
    }

    Write-Host "Scanner agent started successfully."
}

# ------------------------------------------------------------
# 4. Start Cloudflare Quick Tunnel
# ------------------------------------------------------------

Write-Host ""
Write-Host "[3/6] Starting Cloudflare Quick Tunnel..."
Write-Host "Using: $TunnelExe"

Remove-Item $TunnelOut, $TunnelErr -Force -ErrorAction SilentlyContinue

Start-Process `
    -FilePath $TunnelExe `
    -ArgumentList "tunnel --url http://$ScannerHost`:$ScannerPort" `
    -RedirectStandardOutput $TunnelOut `
    -RedirectStandardError $TunnelErr `
    -WindowStyle Minimized

# ------------------------------------------------------------
# 5. Detect Cloudflare URL
# ------------------------------------------------------------

Write-Host ""
Write-Host "[4/6] Waiting for Cloudflare URL..."

$tunnelUrl = $null

for ($i = 1; $i -le 60; $i++) {

    Start-Sleep -Seconds 1

    $content = ""

    if (Test-Path $TunnelOut) {
        $content += Get-Content $TunnelOut -Raw -ErrorAction SilentlyContinue
    }

    if (Test-Path $TunnelErr) {
        $content += Get-Content $TunnelErr -Raw -ErrorAction SilentlyContinue
    }

    if ($content) {

        $match = [regex]::Match(
            $content,
            'https://[a-zA-Z0-9-]+\.trycloudflare\.com'
        )

        if ($match.Success) {
            $tunnelUrl = $match.Value
            break
        }
    }
}

if (-not $tunnelUrl) {

    Write-Host ""
    Write-Host "ERROR: Could not detect Cloudflare Tunnel URL."
    Write-Host ""

    if (Test-Path $TunnelOut) {
        Write-Host "Cloudflare output:"
        Get-Content $TunnelOut
    }

    if (Test-Path $TunnelErr) {
        Write-Host ""
        Write-Host "Cloudflare errors:"
        Get-Content $TunnelErr
    }

    exit 1
}

Write-Host ""
Write-Host "Cloudflare URL:"
Write-Host $tunnelUrl

# ------------------------------------------------------------
# 6. Test public scanner
# ------------------------------------------------------------

Write-Host ""
Write-Host "[5/6] Waiting for public scanner to become reachable..."

$publicScannerReady = $false

# Quick Tunnels can take some time to become reachable
# after the hostname is created.
for ($i = 1; $i -le 60; $i++) {

    try {

        $publicHealth = Invoke-RestMethod `
            -Uri "$tunnelUrl/health" `
            -TimeoutSec 10

        if ($publicHealth.status -eq "ok") {
            $publicScannerReady = $true
            break
        }

    }
    catch {
        Write-Host "  Waiting for Cloudflare tunnel... attempt $i/60"
        Start-Sleep -Seconds 2
    }
}

if (-not $publicScannerReady) {

    Write-Host ""
    Write-Host "ERROR: Public scanner did not become reachable within 120 seconds."
    Write-Host ""
    Write-Host "Tunnel URL:"
    Write-Host $tunnelUrl
    Write-Host ""
    Write-Host "Test manually with:"
    Write-Host "Invoke-RestMethod $tunnelUrl/health -TimeoutSec 30"

    exit 1
}

Write-Host "Public scanner: OK"

# ------------------------------------------------------------
# 7. Update Railway
# ------------------------------------------------------------

Write-Host ""
Write-Host "[6/6] Updating Railway..."

Push-Location $ProjectRoot

try {

    railway variable set "SCAN_AGENT_URL=$tunnelUrl" --skip-deploys

    if ($LASTEXITCODE -ne 0) {
        throw "Railway variable update failed."
    }

    Write-Host "SCAN_AGENT_URL updated successfully."

    Write-Host ""
    Write-Host "Redeploying Railway..."

    railway redeploy --yes

    if ($LASTEXITCODE -ne 0) {
        throw "Railway redeploy failed."
    }

}
finally {

    Pop-Location
}

# ------------------------------------------------------------
# 8. Wait for Railway
# ------------------------------------------------------------

Write-Host ""
Write-Host "Waiting for Railway deployment..."

$productionReady = $false

for ($i = 1; $i -le 60; $i++) {

    Start-Sleep -Seconds 2

    try {

        $apiHealth = Invoke-RestMethod `
            -Uri $RailwayHealth `
            -TimeoutSec 10

        if ($apiHealth) {
            $productionReady = $true
            break
        }

    }
    catch {
    }
}

Write-Host ""
Write-Host "=================================================="

if ($productionReady) {

    Write-Host "       NETSECURE LIVE SCAN IS READY"
    Write-Host ""
    Write-Host "Scanner Agent:"
    Write-Host "http://127.0.0.1:$ScannerPort"
    Write-Host ""
    Write-Host "Cloudflare:"
    Write-Host $tunnelUrl
    Write-Host ""
    Write-Host "Railway: UPDATED"
    Write-Host "Production: ONLINE"

}
else {

    Write-Host "Railway deployment is still starting."
    Write-Host "Check Railway before running Live Scan."
}

Write-Host ""
Write-Host "=================================================="
Write-Host ""
Write-Host "Keep this PowerShell window open while using Live Scan."
Write-Host ""

