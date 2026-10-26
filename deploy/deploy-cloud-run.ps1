# Deploy the FastAPI scorer to Cloud Run (request-based billing / free-tier friendly).
# Prerequisites: gcloud CLI, a GCP project with billing (free tier OK).
#
# Usage (from repo root):
#   .\deploy\deploy-cloud-run.ps1 -ProjectId YOUR_PROJECT -Region us-central1

param(
    [Parameter(Mandatory = $true)][string]$ProjectId,
    [string]$Region = "us-central1",
    [string]$Service = "gmail-scorer",
    [string]$Image = "",
    [string]$FirebaseProjectId = "",
    [switch]$SkipSecrets
)

$ErrorActionPreference = "Continue"
$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not $Image) {
    $Image = "gcr.io/$ProjectId/${Service}:latest"
}

function Invoke-GCloud {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    & gcloud @Args
    if ($LASTEXITCODE -ne 0) {
        throw "gcloud failed ($LASTEXITCODE): gcloud $($Args -join ' ')"
    }
}

Write-Host "Project=$ProjectId Region=$Region Service=$Service"
Invoke-GCloud config set project $ProjectId

Write-Host "Building $Image ..."
Invoke-GCloud builds submit $RepoRoot --tag $Image

$fb = if ($FirebaseProjectId) { $FirebaseProjectId } else { $ProjectId }
$envVars = @(
    "DEV_MODE=false",
    "ENABLE_WHOIS=false",
    "ENABLE_LIVE_DNS=false",
    "USE_TRANSFORMERS=false",
    "LLM_MODE=redacted",
    "LOG_LEVEL=WARNING",
    "FIREBASE_PROJECT_ID=$fb"
) -join ","

$deployArgs = @(
    "run", "deploy", $Service,
    "--image", $Image,
    "--region", $Region,
    "--platform", "managed",
    "--allow-unauthenticated",
    "--port", "8080",
    "--memory", "512Mi",
    "--cpu", "1",
    "--min-instances", "0",
    "--max-instances", "5",
    "--concurrency", "20",
    "--cpu-throttling",
    "--set-env-vars", $envVars
)

if (-not $SkipSecrets) {
    $wanted = @(
        @{ Env = "API_KEY"; Secret = "scorer-api-key" },
        @{ Env = "REQUEST_SIGNING_SECRET"; Secret = "scorer-signing-secret" },
        @{ Env = "ACCOUNT_TOKEN_SECRET"; Secret = "account-token-secret" },
        @{ Env = "ANTHROPIC_API_KEY"; Secret = "anthropic-api-key" },
        @{ Env = "SAFE_BROWSING_API_KEY"; Secret = "safe-browsing-api-key" },
        @{ Env = "URLHAUS_AUTH_KEY"; Secret = "urlhaus-auth-key" }
    )
    $pairs = @()
    foreach ($item in $wanted) {
        gcloud secrets describe $item.Secret 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $pairs += "$($item.Env)=$($item.Secret):latest"
        } else {
            Write-Host "Secret $($item.Secret) missing - skipping env $($item.Env)"
        }
    }
    if ($pairs.Count -eq 0) {
        throw "No secrets found. Run .\deploy\create-secrets.ps1 first."
    }
    $deployArgs += @("--set-secrets", ($pairs -join ","))
}

# Cloud Run default compute SA needs Secret Accessor on each mounted secret.
$projectNumber = & gcloud projects describe $ProjectId --format "value(projectNumber)"
$runtimeSa = "serviceAccount:${projectNumber}-compute@developer.gserviceaccount.com"
if (-not $SkipSecrets) {
    foreach ($pair in $pairs) {
        $secretName = ($pair -split "=")[1] -replace ":latest$", ""
        gcloud secrets add-iam-policy-binding $secretName --member=$runtimeSa --role="roles/secretmanager.secretAccessor" --project=$ProjectId 2>$null | Out-Null
    }
}

Write-Host "Deploying to Cloud Run ..."
Invoke-GCloud @deployArgs

$url = & gcloud run services describe $Service --region $Region --format "value(status.url)"
Write-Host ""
Write-Host "Service URL: $url"
Write-Host "Set Apps Script property BACKEND_URL to that URL (no trailing slash)."
Write-Host "Health check: $url/health"
