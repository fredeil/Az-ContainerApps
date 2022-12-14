[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)]
    [string]$ServiceName,
    [Parameter(Mandatory = $true)]
    [string]$ServicePath,
    [Parameter(Mandatory = $true)]
    [string]$HostProjectName,
    [Parameter(Mandatory = $true)]
    [string]$BuildNumber,
    [Parameter(Mandatory = $false)]
    [bool]$UploadArtifacts
)

$ErrorActionPreference = "Stop"

. .\_includes\helpers.ps1

"Loading config"
$names = Get-Content .\infrastructure\names.json | ConvertFrom-Json
$config = Get-Content .\infrastructure\config.json | ConvertFrom-Json
$serviceDefaults = $config.services | Select-Object -ExpandProperty $ServiceName

# Naming conventions
$platformGroupName = $($names.platformGroupName).Replace("{platform}", $config.platformAbbreviation)
$platformContainerRegistryName = $($names.platformContainerRegistryName).Replace("{platform}", $config.platformAbbreviation).Replace("-", "")
$platformStorageAccountName = $($names.platformStorageAccountName).Replace("{platform}", $config.platformAbbreviation).Replace("-", "").ToLower()
$platformSqlMigrationStorageContainerName = $names.platformSqlMigrationStorageContainerName
$svcArtifactContainerImageName = $($names.svcArtifactContainerImageName).Replace("{platform}", $config.platformAbbreviation).Replace("{service}", $serviceName)
$svcArtifactSqlMigrationFile = $($names.svcArtifactSqlMigrationFile).Replace("{platform}", $config.platformAbbreviation).Replace("{service}", $serviceName).Replace("{buildNumber}", $BuildNumber)

$registryServer = $platformContainerRegistryName + '.azurecr.io'

$solutionFolder = (Get-Item (Join-Path "../" $ServicePath)).FullName
$projectFolder = (Get-Item (Join-Path $solutionFolder $HostProjectName)).FullName

"Restoring .NET tools"
Exekute { dotnet tool restore }

"Restoring dependencies"
Exekute { dotnet restore "$solutionFolder" }

"Building solution"
Exekute { dotnet build "$solutionFolder" -c Release --no-restore }


# TODO: Running tests


"Creating SQL migration file"
if ($serviceDefaults.sqlDatabaseEnabled) {
    Exekute { dotnet ef migrations script --configuration Release --no-build --idempotent -p "$projectFolder" -o "../artifacts/migration.sql" }
}
else {
    ".. SKIPPED (sqlDatabaseEnabled=false)"
}

"Creating docker image"
Exekute { dotnet publish "$projectFolder" -c Release --os linux --arch x64 -p:PublishProfile=DefaultContainer -p:ContainerImageName=$svcArtifactContainerImageName -p:ContainerImageTag=$BuildNumber }

"Tagging docker image with Azure Container Registry"
if ($UploadArtifacts) {
    Exekute { docker tag "$($svcArtifactContainerImageName):$BuildNumber" "$registryServer/$($svcArtifactContainerImageName):$BuildNumber" }
}
else {
    ".. SKIPPED (UploadArtifacts=false)"
}


"Uploading SQL migration file"
if (!$serviceDefaults.sqlDatabaseEnabled) {
    ".. SKIPPED (sqlDatabaseEnabled=false)"
}
elseif (!$UploadArtifacts) {
    ".. SKIPPED (UploadArtifacts=false)"
}
else {
    Get-AzStorageAccount -ResourceGroupName $platformGroupName -Name $platformStorageAccountName `
    | Get-AzStorageContainer -Container $platformSqlMigrationStorageContainerName `
    | Set-AzStorageBlobContent -File "../artifacts/migration.sql" -Blob $svcArtifactSqlMigrationFile -Force `
    | Out-Null
}

"Pushing docker image to Azure Container Registry"
if ($UploadArtifacts) {
    Exekute { docker push "$registryServer/$($svcArtifactContainerImageName):$BuildNumber" }
}
else {
    ".. SKIPPED (UploadArtifacts=false)"
}
