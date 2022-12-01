[CmdletBinding()]
Param ()

"This script will set up the initial resources in the Azure Account you are logged into and in GitHub repository that its run from, to allow for automated deployments."
$decision = $Host.UI.PromptForChoice($null, "Are you sure you want to execute this script?", ('&Yes', '&No'), 1)
if ($decision -ne 0) {
    Write-Error "Script aborted."
    exit
}

$ErrorActionPreference = "Stop"

. .\_includes\helpers.ps1

"Ensuring required tools are installed"
if (Get-Command Get-AzContext -ErrorAction Ignore) {
    Write-Host "Azure PowerShell module"
}
else {
    throw "'Azure PowerShell' is not installed. See https://docs.microsoft.com/en-us/powershell/azure/install-az-ps"
}
if (Get-Command bicep -ErrorAction Ignore) {
    Write-Host "Bicep CLI"
}
else {
    throw "'Bicep CLI' is not installed. See https://docs.microsoft.com/en-us/azure/azure-resource-manager/bicep/install"
}
if (Get-Command gh -ErrorAction Ignore) {
    Write-Host "GitHub CLI"
}
else {
    throw "'GitHub CLI' is not installed. See https://github.com/cli/cli#installation"
}



"Confirming Azure Subscription"
$azContext = Get-AzContext
if (!$azContext) {
    throw "You are not signed in to an Azure subscription. Please login using 'Connect-AzAccount'"
}

$subscriptionInfo = "You are connected to the subscription '$($azContext.Name)'. Are you sure you want to install the necessary resources here?"
$decision = $Host.UI.PromptForChoice($null, $subscriptionInfo, ('&Yes', '&No'), 1)
if ($decision -ne 0) {
    Write-Error "Script aborted. Please use 'Connect-AzAccount' to sign in to a different subscription and re-run the script."
    exit
}


"Confirming GitHub account"
gh auth status
if ($LASTEXITCODE -ne 0) {
    exit
}
else {
    $decision = $Host.UI.PromptForChoice($null, 'Are you sure you this is the correct GitHub account?', ('&Yes', '&No'), 1)
    if ($decision -ne 0) {
        Write-Error "Script aborted. Please use 'gh auth login' to sign in to a different account and re-run the script."
        exit
    }
}


"Confirming GitHub repo"
$ghRepo = (gh repo view --json name, nameWithOwner, defaultBranchRef, url) | ConvertFrom-Json

if ($LASTEXITCODE -ne 0) {
    Write-Error "Script aborted. Please run this script in a folder that is connected with a GitHub repository."
    exit
}
else {
    $repoInfo = "You are connected to the GitHub repo '$($ghRepo.url)'. Are you sure you want to install the necessary resources here?"
    $decision = $Host.UI.PromptForChoice($null, $repoInfo, ('&Yes', '&No'), 1)
    if ($decision -ne 0) {
        Write-Error "Script aborted. Please run this script in a folder that is connected with a GitHub repository."
        exit
    }
}


"Ensuring user is a 'Global Administrator'"
$currentUser = Get-AzADUser -SignedIn
$graphAccessToken = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/"
$globalAdminRoleId = (Invoke-RestMethod -Method Get -Headers @{ Authorization = "Bearer $($graphAccessToken.Token)" } -Uri "https://graph.microsoft.com/v1.0/directoryRoles?`$filter=displayName eq 'Global Administrator'").value.id
$globalAdminMembers = (Invoke-RestMethod -Method Get -Headers @{ Authorization = "Bearer $($graphAccessToken.Token)" } -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($globalAdminRoleId)/members").value
$isGlobalAdmin = $globalAdminMembers | Where-Object { $_.id -eq $currentUser.Id }

if ($isGlobalAdmin) {
    Write-Host "User '$($currentUser.UserPrincipalName)' is a 'Global Administrator'"
}
else {
    throw "Current user ($($currentUser.UserPrincipalName)) is not a 'Global Administrator' in Azure AD. You must run this script as a Global Administrator."
}


"Loading config"
$names = Get-Content .\infrastructure\names.json | ConvertFrom-Json
$config = Get-Content .\infrastructure\config.json | ConvertFrom-Json
$environments = $config.environments | Get-Member -MemberType NoteProperty | ForEach-Object { $_.Name }

$githubIdentityMsGraphPermissions = @(
    "Group.Read.All" # Required to get the SQL Admins AAD group in `deploy-environment.ps1`
)

# https://docs.microsoft.com/en-us/azure/azure-sql/database/authentication-azure-ad-user-assigned-managed-identity?view=azuresql#permissions
$sqlIdentityMsGraphPermissions = @(
    "Application.Read.All",
    "GroupMember.Read.All",
    "User.Read.All"
)

Write-Host "Config loaded"


"------------------------"
"Azure platform resources"
"------------------------"
"Creating Azure platform resources (this may take some time..)"

$platformDeployment = New-AzSubscriptionDeployment `
    -Location $config.location `
    -Name ("init-platform-" + (Get-Date).ToString("yyyyMMddHHmmss")) `
    -TemplateFile .\infrastructure\platform\main.bicep `
    -TemplateParameterObject @{
    deployGitHubIdentity    = $true
    githubRepoNameWithOwner = $ghRepo.nameWithOwner
    githubDefaultBranchName = $ghRepo.defaultBranchRef.name
}

Write-Host "Azure platform resources deployed"

# AAD replicates data so future queries might not immediately recognize the newly created object
$githubIdentity = $null
for ($i = 1; $i -le 12; $i++) {
    $githubIdentity = Get-AzADServicePrincipal -ObjectId $platformDeployment.Outputs.githubIdentityPrincipalId.Value -ErrorAction Ignore
    if ($githubIdentity) {
        if ($i -gt 1) { Write-Host "GitHub identity found in Azure AD API" }
        break
    }
    else {
        "  GitHub identity not yet available in Azure AD API. Waiting for 10 seconds"
        Start-Sleep -Seconds 10
    }
}


"Assigning MS Graph API permissions to the GitHub identity"
# There is no Bicep-feature or Azure-PowerShell command, so we have to manually call the URL
# (There would be a separate AzureAD PowerShell-module but this would require a separate login, so it's easier to just call the Graph API directly)

$msGraphSp = Get-AzAdServicePrincipal -ApplicationId "00000003-0000-0000-c000-000000000000"
$graphAccessToken = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/"
$apiUrl = "https://graph.microsoft.com/v1.0/servicePrincipals/$($githubIdentity.Id)/appRoleAssignments"
$existingAssignments = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers @{ Authorization = "Bearer $($graphAccessToken.Token)" }

foreach ($permissionName in $githubIdentityMsGraphPermissions) {
    #$permissionName = "GroupMember.ReadWrite.All"
    $appRoleId = ($msGraphSp.AppRole | Where-Object { $_.Value -eq $permissionName } | Select-Object).Id

    $exists = $existingAssignments.value | Where-Object { $_.appRoleId -eq $appRoleId }
    if ($exists) {
        Write-Host "Permission '$permissionName' already exists"
    }
    else {
        $body = @{
            appRoleId   = $appRoleId
            resourceId  = $msGraphSp.Id
            principalId = $githubIdentity.Id
        }
        Invoke-RestMethod -Uri $apiUrl -Method Post -ContentType "application/json" `
            -Headers @{ Authorization = "Bearer $($graphAccessToken.Token)" } `
            -Body $($body | convertto-json) | Out-Null

        Write-Host "Permission '$permissionName' created"
    }
}


"-------------------"
"SQL Server identity"
"-------------------"
foreach ($environment in $environments) {

    $envConfig = $config.environments | Select-Object -ExpandProperty $environment
    $sqlAdminAdGroupName = $($names.sqlAdminAdGroupName).Replace("{environment}", $envConfig.environmentAbbreviation)

    "Environment '$environment': Creating SQL Admins AAD group"

    $sqlAdminAdGroup = Get-AzAdGroup -DisplayName $sqlAdminAdGroupName
    if ($sqlAdminAdGroup) {
        Write-Host "AAD group '$sqlAdminAdGroupName' already exists"
    }
    else {
        $sqlAdminAdGroup = New-AzAdGroup -DisplayName $sqlAdminAdGroupName -MailNickname $sqlAdminAdGroupName -IsAssignableToRole
        Write-Host "AAD group '$sqlAdminAdGroupName' created"
    }

    "Environment '$environment': Creating SQL identity (this may take a minute)"
    $sqlDeployment = New-AzSubscriptionDeployment `
        -Location $config.location `
        -Name ("init-sql-" + (Get-Date).ToString("yyyyMMddHHmmss")) `
        -TemplateFile .\infrastructure\environment\sql-identity.bicep `
        -TemplateParameterObject @{
        environment = $environment
    }

    Write-Host "SQL identity for environment '$environment' created"

    # AAD replicates data so future queries might not immediately recognize the newly created object
    $sqlIdentity = $null
    for ($i = 1; $i -le 12; $i++) {
        $sqlIdentity = Get-AzADServicePrincipal -ObjectId $sqlDeployment.Outputs.sqlIdentityPrincipalId.Value -ErrorAction Ignore
        if ($sqlIdentity) {
            if ($i -gt 1) { Write-Host "Identity found in AAD API" }
            break
        }
        else {
            "  Identity not yet available in AAD API. Waiting for 10 seconds"
            Start-Sleep -Seconds 10
        }
    }


    "Environment '$environment': Assigning MS Graph API permissions to the SQL identity"

    # https://docs.microsoft.com/en-us/azure/azure-sql/database/authentication-azure-ad-user-assigned-managed-identity?view=azuresql#permissions
    $msGraphSp = Get-AzAdServicePrincipal -ApplicationId "00000003-0000-0000-c000-000000000000"
    $graphAccessToken = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/"
    $apiUrl = "https://graph.microsoft.com/v1.0/servicePrincipals/$($sqlIdentity.Id)/appRoleAssignments"

    $existingAssignments = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers @{ Authorization = "Bearer $($graphAccessToken.Token)" }

    foreach ($permissionName in $sqlIdentityMsGraphPermissions) {
        $appRoleId = ($msGraphSp.AppRole | Where-Object { $_.Value -eq $permissionName } | Select-Object).Id
        $exists = $existingAssignments.value | Where-Object { $_.appRoleId -eq $appRoleId }
        if ($exists) {
            Write-Host "Permission '$permissionName' already exists"
        }
        else {
            $body = @{
                appRoleId   = $appRoleId
                resourceId  = $msGraphSp.Id
                principalId = $sqlIdentity.Id
            }

            Invoke-RestMethod -Uri $apiUrl -Method Post -ContentType "application/json" `
                -Headers @{ Authorization = "Bearer $($graphAccessToken.Token)" } `
                -Body $($body | convertto-json) | Out-Null

            Write-Host "Permission '$permissionName' created"
        }
    }

    "Environment '$environment': Adding SQL server identity to SQL Admins AAD group"
    $sqlAdminAdGroupMembers = Get-AzADGroupMember -GroupObjectId $sqlAdminAdGroup.Id
    if ($sqlAdminAdGroupMembers | Where-Object { $_.Id -eq $sqlIdentity.Id }) {
        Write-Host "Membership for SQL identity already exists in group"
    }
    else {
        Add-AzADGroupMember -TargetGroupObjectId $sqlAdminAdGroup.Id -MemberObjectId $sqlIdentity.Id
        Write-Host "Member for SQL identity added to group"
    }
}


"-----------------"
"GitHub repository"
"-----------------"

"Creating GitHub environments"
$gitHubEnvironments = $environments
$gitHubEnvironments += "platform" # A special environment for deploying the platform resources

# There are no CLI methods for managing environments, so we have to use the REST API: https://github.com/cli/cli/issues/5149
$ghEnvironments = Exekute { gh api "/repos/$($ghRepo.nameWithOwner)/environments" -H "Accept: application/vnd.github+json" } | ConvertFrom-Json
$ghUser = Exekute { gh api "/user" -H "Accept: application/vnd.github+json" } | ConvertFrom-Json

foreach ($environment in $gitHubEnvironments) {
    if ($ghEnvironments.environments | Where-Object { $_.name -eq $environment }) {
        Write-Host "Environment '$environment' already exists"
    }
    else {
        $body = @{
            reviewers = @(
                @{ type = "User"; id = $ghUser.id }
            )
        } | ConvertTo-Json -Compress

        $ghEnv = Exekute { $body | gh api "/repos/$($ghRepo.nameWithOwner)/environments/$environment" -X PUT -H "Accept: application/vnd.github+json" --input - } | ConvertFrom-Json

        Write-Host "Environment '$environment' created with YOU ($($ghUser.login)) as a required reviewer."
        "    You can modify the protection rules here: $($ghRepo.url)/settings/environments/$($ghEnv.id)/edit"
    }
}


"Creating GitHub secrets"
Exekute { gh secret set "AZURE_CLIENT_ID" -b $githubIdentity.AppId }
Exekute { gh secret set "AZURE_SUBSCRIPTION_ID" -b $((Get-AzContext).Subscription.Id) }
Exekute { gh secret set "AZURE_TENANT_ID" -b $((Get-AzContext).Subscription.TenantId) }
Exekute { gh secret set "REGISTRY_SERVER" -b $platformDeployment.Outputs.platformContainerRegistryUrl.Value }

"Script finished"
