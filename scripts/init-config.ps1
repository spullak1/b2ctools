param(
    [Parameter(Mandatory)]
    [string]$Project,

    [Parameter(Mandatory)]
    [ValidateSet("nprd","xqa","pqa","prd")]
    [string]$Environment
)

$projectPath = Join-Path $PSScriptRoot "..\tools\$Project\config"

$templateFile = Join-Path $projectPath "env.template"
$envFile = Join-Path $projectPath "$Environment.env"

if (!(Test-Path $templateFile)) {
    throw "Template not found: $templateFile"
}

if (Test-Path $envFile) {
    Write-Host ".env already exists."
    exit
}

Copy-Item $templateFile $envFile

Write-Host "Created:"
Write-Host "  $envFile"
Write-Host ""
Write-Host "Environment selected: $Environment"
Write-Host "Update any remaining values before running the tool."
