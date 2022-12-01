[CmdletBinding()]
Param (

    [Parameter(Mandatory = $True)]
    [string]$Environment,

    [Parameter(Mandatory = $True)]
    [string]$ServiceName,

    [Parameter(Mandatory = $True)]
    [string]$BuildNumber
)

$ErrorActionPreference = "Stop"

"Loading config"
$config = Get-Content .\infrastructure\config.json | ConvertFrom-Json


"Deploying Azure resources"
New-AzSubscriptionDeployment `
    -Location $config.location `
    -Name ("svc-" + (Get-Date).ToString("yyyyMMddHHmmss")) `
    -TemplateFile .\infrastructure\service\main.bicep `
    -TemplateParameterObject @{
    environment = $Environment
    serviceName = $ServiceName
    buildNumber = $buildNumber
} `
    -Verbose | Out-Null
