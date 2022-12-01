$ErrorActionPreference = "Stop"

"Loading config"
$config = Get-Content .\config.json | ConvertFrom-Json

"Deploying Azure resources"
New-AzSubscriptionDeployment `
    -Location $config.location `
    -Name ("platform-" + (Get-Date).ToString("yyyyMMddHHmmss")) `
    -TemplateFile .\infrastructure\platform\main.bicep `
    -TemplateParameterObject @{
    deployGitHubIdentity = $false
} `
    -Verbose | Out-Null
