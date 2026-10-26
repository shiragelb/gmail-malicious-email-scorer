# Deploy the FastAPI scorer to Cloud Run (request-based billing / free-tier friendly).
# Prerequisites: gcloud CLI, Docker (or Cloud Build), a GCP project with billing (free tier OK).
#
# Usage (from repo root):
#   .\deploy\deploy-cloud-run.ps1 -ProjectId YOUR_PROJECT -Region us-central1
#
# Secrets must already exist in Secret Manager (or pass -SkipSecrets and set env vars in console):
#   scorer-api-key, scorer-signing-secret, anthropic-api-key (optional),
#   safe-browsing-api-key (optional), urlhaus-auth-key (optional)

param(
    [Parameter(Mandatory = $true)][string]$ProjectId,
    [string]$Region = "us-central1",
    [string]$Service = "gmail-scorer",
    [string]$Image = "",
    [string]$FirebaseProjectId = "",
    [switch]$SkipSecrets
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not $Image) {
    $Image = "gcr.io/$ProjectId/${Service}:latest"
}

Write-Host "Project=$ProjectId Region=$Region Service=$Service"
gcloud config set project $ProjectId

Write-Host "Building $Image ..."
gcloud builds submit $RepoRoot --tag $Image

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
    $secrets = @(
        "API_KEY=scorer-api-key:latest",
        "REQUEST_SIGNING_SECRET=scorer-signing-secret:latest",
        "ACCOUNT_TOKEN_SECRET=account-token-secret:latest",
        "ANTHROPIC_API_KEY=anthropic-api-key:latest",
        "SAFE_BROWSING_API_KEY=safe-browsing-api-key:latest",
        "URLHAUS_AUTH_KEY=urlhaus-auth-key:latest"
    ) -join ","
    $deployArgs += @("--set-secrets", $secrets)
}

Write-Host "Deploying to Cloud Run ..."
& gcloud @deployArgs

$url = gcloud run services describe $Service --region $Region --format "value(status.url)"
Write-Host ""
Write-Host "Service URL: $url"
Write-Host "Set Apps Script property BACKEND_URL to that URL (no trailing slash)."
Write-Host "Health check: $url/health"
