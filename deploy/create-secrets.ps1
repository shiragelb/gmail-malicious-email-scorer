# Create / update Secret Manager secrets used by deploy-cloud-run.ps1.
# Generates API_KEY and REQUEST_SIGNING_SECRET if you do not pass them.
#
# Usage:
#   .\deploy\create-secrets.ps1 -ProjectId YOUR_PROJECT
#   .\deploy\create-secrets.ps1 -ProjectId YOUR_PROJECT -AnthropicKey "sk-..."

param(
    [Parameter(Mandatory = $true)][string]$ProjectId,
    [string]$ApiKey = "",
    [string]$SigningSecret = "",
    [string]$AccountTokenSecret = "",
    [string]$FirebaseProjectId = "",
    [string]$AnthropicKey = "",
    [string]$SafeBrowsingKey = "",
    [string]$UrlhausKey = ""
)

# gcloud writes info to stderr; do not treat that as a terminating error.
$ErrorActionPreference = "Continue"

function Invoke-GCloud {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    & gcloud @Args
    if ($LASTEXITCODE -ne 0) {
        throw "gcloud failed ($LASTEXITCODE): gcloud $($Args -join ' ')"
    }
}

Invoke-GCloud config set project $ProjectId
Invoke-GCloud services enable secretmanager.googleapis.com run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com

function Ensure-Secret([string]$Name, [string]$Value) {
    if (-not $Value) {
        Write-Host "Skipping empty secret $Name"
        return
    }
    gcloud secrets describe $Name 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Invoke-GCloud secrets create $Name --replication-policy=automatic
    }
    # Write without a trailing newline — a LF would make API key auth fail against Apps Script.
    $tmp = Join-Path $env:TEMP ("gcloud-secret-" + $Name + ".txt")
    [System.IO.File]::WriteAllText($tmp, $Value)
    try {
        & gcloud secrets versions add $Name --data-file=$tmp
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to add version for secret $Name"
        }
    } finally {
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    }
    Write-Host "Updated secret $Name"
}

if (-not $ApiKey) {
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $ApiKey = ([Convert]::ToBase64String($bytes) -replace '[^A-Za-z0-9]', '').Substring(0, 32)
    Write-Host "Generated API_KEY (save this for Apps Script User property API_KEY):"
    Write-Host $ApiKey
}
if (-not $SigningSecret) {
    $bytes = New-Object byte[] 48
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $SigningSecret = ([Convert]::ToBase64String($bytes) -replace '[^A-Za-z0-9]', '').Substring(0, 48)
    Write-Host "Generated REQUEST_SIGNING_SECRET (save for Apps Script Script property REQUEST_SIGNING_SECRET):"
    Write-Host $SigningSecret
}
if (-not $AccountTokenSecret) {
    $bytes = New-Object byte[] 48
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $AccountTokenSecret = ([Convert]::ToBase64String($bytes) -replace '[^A-Za-z0-9]', '').Substring(0, 48)
    Write-Host "Generated ACCOUNT_TOKEN_SECRET (Cloud Run only; not needed in Apps Script)"
}

$outFile = Join-Path (Split-Path -Parent $PSScriptRoot) ".deploy-credentials.txt"
@"
# Generated $(Get-Date -Format o) — DO NOT COMMIT. Paste into Apps Script.
API_KEY=$ApiKey
REQUEST_SIGNING_SECRET=$SigningSecret
ACCOUNT_TOKEN_SECRET=$AccountTokenSecret
PROJECT_ID=$ProjectId
"@ | Set-Content -Path $outFile -Encoding UTF8
Write-Host "Also saved credentials to $outFile (gitignored)."

Ensure-Secret "scorer-api-key" $ApiKey
Ensure-Secret "scorer-signing-secret" $SigningSecret
Ensure-Secret "account-token-secret" $AccountTokenSecret
Ensure-Secret "anthropic-api-key" $AnthropicKey
Ensure-Secret "safe-browsing-api-key" $SafeBrowsingKey
Ensure-Secret "urlhaus-auth-key" $UrlhausKey

if ($FirebaseProjectId) {
    Write-Host "Remember to set Cloud Run env FIREBASE_PROJECT_ID=$FirebaseProjectId"
}

Write-Host "Done. Grant the Cloud Run runtime service account Secret Manager Secret Accessor on these secrets if deploy fails on secrets."
