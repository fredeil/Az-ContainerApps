# Deploys all Azure resources that are used by one single service.
# It also adds some resources to the environment (e.g. SQL database) and platform (role assignments).
[CmdletBinding()]
Param (

    [Parameter(Mandatory=$True)]
    [string]$Environment,

    [Parameter(Mandatory=$True)]
    [string]$ServiceName,

    [Parameter(Mandatory=$True)]
    [string]$BuildNumber
)

$ErrorActionPreference = "Stop"

"Loading config"
$config = Get-Content .\infrastructure\config.json | ConvertFrom-Json


"Deploying Azure resources"
New-AzSubscriptionDeployment `
    -Location $config.location `
    -Name ("svc-" + (Get-Date).ToString("yyyyMMddHHmmss")) `
    -TemplateFile .\service\main.bicep `
    -TemplateParameterObject @{
        environment = $Environment
        serviceName = $ServiceName
        buildNumber = $buildNumber
    } `
    -Verbose | Out-Null
