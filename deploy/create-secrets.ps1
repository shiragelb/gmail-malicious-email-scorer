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

$ErrorActionPreference = "Stop"
gcloud config set project $ProjectId
gcloud services enable secretmanager.googleapis.com run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com

function Ensure-Secret([string]$Name, [string]$Value) {
    if (-not $Value) {
        Write-Host "Skipping empty secret $Name"
        return
    }
    $exists = $false
    gcloud secrets describe $Name 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { $exists = $true }
    if (-not $exists) {
        gcloud secrets create $Name --replication-policy=automatic | Out-Null
    }
    $Value | gcloud secrets versions add $Name --data-file=-
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
