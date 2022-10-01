
# Best Practices for Automating Azure with PowerShell and Azure CLI

<#
 Automating and managing Azure can become complex very quickly. This webinar will explain how to best automate and manage Azure resources with PowerShell. We will cover best practices in the following areas: installation, preview modules, coexistence with AzureRM modules, authentication, troubleshooting, reporting the issues... Focus will be on running Azure PowerShell commands locally, in Azure Cloud Shell, and in Azure Functions and Azure Automation.
 #>

 
#region Installation, release notes, breaking changes...

# Azure PowerShell works with PowerShell 5.1 or higher on Windows, or PowerShell 7 or higher on any platform.
# If you are using PowerShell 5 on Windows, you also need .NET Framework 4.7.2 installed.

# https://github.com/Azure/azure-powershell

# https://docs.microsoft.com/powershell/azure/install-az-ps
# https://www.powershellgallery.com/packages/Az/

# Install-Module -Name Az -Repository PSGallery -Scope CurrentUser -AllowClobber 

# Release notes and the .MSI files (the MSI installer only works for PowerShell 5.1 on Windows)
# https://github.com/Azure/azure-powershell/releases/tag/v8.3.0-September2022

# Release notes and the breaking changes (migration guides)
# https://learn.microsoft.com/en-us/powershell/azure/release-notes-azureps
# https://learn.microsoft.com/en-us/powershell/azure/upcoming-breaking-changes
# https://learn.microsoft.com/en-us/powershell/azure/migrate-az-8.0.0

# Azure AD to Microsoft Graph migration changes in Azure PowerShell
# https://learn.microsoft.com/en-us/powershell/azure/azps-msgraph-migration-changes

# Update-Module installs the new version side-by-side with previous versions
# It does not uninstall the previous versions
# It's a good idea to have the last 2 versions
Update-Module -Name Az

# Check a version
Get-Module az -ListAvailable
Get-InstalledModule -Name Az

# Az and AzureRM coexistence
# Microsoft doesn't support having both the AzureRM and Az modules installed for PowerShell 5.1 on Windows at the same time.
 
# In a scenario where you want to install both AzureRM and the Az PowerShell module on the same system, AzureRM must be installed only in the user scope for Windows PowerShell.
# Install the Az PowerShell module on PowerShell 7 or higher on the same system.

https://github.com/Azure/azure-cli
https://learn.microsoft.com/en-us/cli/azure/install-azure-cli
https://learn.microsoft.com/en-us/cli/azure/release-notes-azure-cli
https://learn.microsoft.com/en-us/cli/azure/microsoft-graph-migration

# Upgrade Azure CLI and extensions
az upgrade

#endregion

#region Migration from AzureRM to Az cmdlets

# Microsoft will retire AzureRM PowerShell modules on 29 February 2024.
# To avoid service interruptions, update your scripts that use AzureRM PowerShell modules to use Az PowerShell modules 

# Enable-AzureRmAlias enables AzureRm prefix aliases for Az modules.

# Azure PowerShell Tools extension

code .\AzureRM_samples\sqldb-create-and-configure-database.ps1

# -ResourceNameEquals parameter doesn't exist
code .\AzureRM_samples\devtestlab-add-marketplace-image-to-lab.ps1
 
# Az.Tools.Migration module

Get-Command -Module Az.Tools.Migration

# Get a dictionary containing cmdlet alias mappings for the specified Az module version
# Currently, only Az PowerShell module version 8.0.0 is supported as a target.
 (Get-AzUpgradeAliasSpec -ModuleVersion 8.0.0).GetEnumerator() | Select-Object -First 20

# Get-AzUpgradeCmdletSpec returns a dictionary containing cmdlet specification objects for the specified module
# This is not very helpful
Get-AzUpgradeCmdletSpec -ModuleName 'AzureRM' -ModuleVersion '8.0.0'

# Much better when we specify a specific cmdlet
 (Get-AzUpgradeCmdletSpec -ModuleName 'AzureRM' -ModuleVersion '6.13.1')['New-AzureRmVM']

 (Get-AzUpgradeCmdletSpec -ModuleName 'Az' -ModuleVersion '8.0.0')['New-AzVM']

 (Get-AzUpgradeCmdletSpec -ModuleName 'Az' -ModuleVersion '8.0.0')['New-AzVM'] |
Select-Object -ExpandProperty parameters |
Sort-Object Name

# Search for AzureRM PowerShell command references in the specified file or folder
Find-AzUpgradeCommandReference -FilePath C:\demo\AzureRM_samples\sqldb-create-and-configure-database.ps1 -AzureRmVersion 6.13.1

# Generate an upgrade plan for all the scripts and module files in the specified folder and save it to a variable
# The New-AzUpgradeModulePlan cmdlet doesn't execute the plan, it only generates the upgrade steps
$Plan = New-AzUpgradeModulePlan -FromAzureRmVersion 6.13.1 -ToAzVersion 8.0.0 -DirectoryPath 'C:\demo\AzureRM_samples'

# Show the generated upgrade plan
$Plan

# Filter plan results to only show warnings and errors
$Plan | Where-Object PlanResult -NE ReadyToUpgrade | Format-List

# Execute the automatic upgrade plan and save the results to a variable
# Invoke-AzUpgradeModulePlan requires you to specify if the files should be modified in place ( -FileEditMode ModifyExistingFiles) or if new files should be saved alongside your original files (leaving originals unmodified; -FileEditMode SaveChangesToNewFiles).
$Results = Invoke-AzUpgradeModulePlan -Plan $Plan -FileEditMode SaveChangesToNewFiles

# Show the results for the upgrade operation
$Results

# Filter results to show only errors
$Results | Where-Object UpgradeResult -NE UpgradeCompleted | Format-List

#endregion

#region How to uninstall Azure PowerShell modules

# Uninstallation can be complicated if you have more than one version of the Az PowerShell module installed.
# Because of this complexity, Microsoft only supports uninstalling all versions of the Az PowerShell module that are currently installed.

# A list of all the Az PowerShell module versions installed on a system
Get-InstalledModule -Name Az -AllVersions -OutVariable AzVersions

# A list of all the Az PowerShell modules that need to be uninstalled in addition to the Az module
($AzVersions | ForEach-Object {
  Import-Clixml -Path (Join-Path -Path $_.InstalledLocation -ChildPath PSGetModuleInfo.xml)
}).Dependencies.Name | Sort-Object -Unique -OutVariable AzModules

# Remove the Az modules from memory and then uninstall them
$AzModules | ForEach-Object {
  Remove-Module -Name $_ -ErrorAction SilentlyContinue
  Write-Output "Attempting to uninstall module: $_"
  Uninstall-Module -Name $_ -AllVersions
}

# The final step is to remove the Az PowerShell module
Remove-Module -Name Az -ErrorAction SilentlyContinue
Uninstall-Module -Name Az -AllVersions

#endregion

#region Login experience

Connect-AzAccount

# Converting a SecureString to a string

$cred = Get-Credential -UserName $env:USERNAME -Message 'Enter Azure password'
$plainText = $cred.GetNetworkCredential().Password
"Your password is: $plainText"

$password = Read-Host -Prompt 'Enter Azure password' -AsSecureString
$password -is [SecureString]

$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
[System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

[System.Net.NetworkCredential]::new('', $password).Password

[System.Net.NetworkCredential]::new

# If you have managed identity enabled
# Connect-AzAccount -Identity

<# Azure DevOps Pipeline
# Create a service connection to Azure
$servicePrincipal = New-AzAdServicePrincipal -DisplayName 'tm2021c' -Role Contributor -Scope /subscriptions/0b1e6544-da36-4abf-8c92-86a434d5047b

# In interactive mode, the az devops service-endpoint azurerm create command asks for a service principal password/secret using a prompt message. For automation purposes, set the service principal password/secret using the AZURE_DEVOPS_EXT_AZURE_RM_SERVICE_PRINCIPAL_KEY environment variable.
$servicePrincipalKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($servicePrincipal.Secret))
$env:AZURE_DEVOPS_EXT_AZURE_RM_SERVICE_PRINCIPAL_KEY = $servicePrincipalKey

$serviceConnectionName = 'tm2021-conn'
$AzContext = Get-AzContext

az devops service-endpoint azurerm create --name $serviceConnectionName --azure-rm-service-principal-id $servicePrincipal.ApplicationId --azure-rm-subscription-id $AzContext.Subscription.Id --azure-rm-subscription-name $AzContext.Subscription.Name --azure-rm-tenant-id $AzContext.Tenant.Id       

# NOTE: Add permissions for the service connection using a web interface

<# GitHub Actions
$ServicePrincipal = az ad sp create-for-rbac --name "kd2021ga" --role contributor --scopes /subscriptions/XXXX-XXXX-XXXX-XXXX-XXXX --sdk-auth

$PublicKey = ConvertFrom-Json (gh api /repos/:owner/:repo/actions/secrets/public-key)

$encryptedvalue = ConvertTo-SodiumEncryptedString -Text "$ServicePrincipal" -PublicKey $PublicKey.key

gh api /repos/:owner/:repo/actions/secrets/AZURE_CREDENTIALS --method PUT -f encrypted_value=$EncryptedValue -f key_id=$($PublicKey.key_id)
#>

#endregion

#region Service coverage, default values, feedback...

# Service coverage
Get-Module Az.* -ListAvailable

# Default values
# $PSDefaultParameterValues vs Set-AzDefault
# Set-AzDefault only sets default resource group, but it's tied to the context so it changes when you switch accounts or subscriptions. It doesn't work in Azure Cloud Shell.
Get-Command Set-AzDefault -Syntax

$PSDefaultParameterValues
$PSDefaultParameterValues['Get-AzVM:ResourceGroupName'] = 'lab-rg'
$PSDefaultParameterValues.Add("*:Verbose", { $verbose -eq $true })

az config get
# Hide warnings and only show errors with `core.only_show_errors`
az config set core.only_show_errors=true
# Turn on client-side telemetry.
az config set core.collect_telemetry=true
# Turn on file logging and set its location.
az config set logging.enable_log_file=true
az config set logging.log_dir=~/az-logs
# Set the default location to `westeurope` and default resource group to `lab-rg`.
az config set defaults.location=westeurope defaults.group=lab-rg
az find "az config"

az config set extension.use_dynamic_install=no # this is default value
az graph query -q "resources"
az config set extension.use_dynamic_install=yes_prompt
az graph query -q "resources"
# for automation
az config set extension.use_dynamic_install=yes_without_prompt

# Feedback
Send-Feedback
Resolve-AzError

# Send feedback to the Azure CLI Team.
# This command is interactive.
# If possible, it launches the default web browser to open GitHub issue creation page with the body auto-generated and pre-filled.
az feedback

# To suppress breaking change warning messages, set the environment variable 'SuppressAzurePowerShellBreakingChangeWarnings' to 'true'.
Set-Item Env:\SuppressAzurePowerShellBreakingChangeWarnings "true"

#endregion

#region Use persisted parameters

# When you are using a local install of the Azure CLI, persisted parameter values are stored in the working directory on your machine.
mkdir azcli && cd azcli

# Using persisted parameters
# Reminder: function app and storage account names must be unique.

# Turn persisted parameters on.
az config param-persist on

# Create a resource group.
az group create --name RG2forTutorial --location westeurope

# See the stored parameter values.
az config param-persist show

# Create an Azure storage account in the resource group omitting "--location" and "--resource-group" parameters.
az storage account create `
  --name sa3fortutorialntk `
  --sku Standard_LRS

# Create a serverless function app in the resource group omitting "--storage-account" and "--resource-group" parameters.
az functionapp create `
  --name FAforTutorial `
  --consumption-plan-location westeurope `
  --functions-version 2

# See the stored parameter values.
az config param-persist show

# Without persisted parameters

# Reminder: function app and storage account names must be unique.

# turn persisted parameters off
az config param-persist off

# Create a resource group.
az group create --name RG2forTutorial --location westeurope

# Create an Azure storage account in the resource group.
az storage account create `
  --name sa3fortutorialntk `
  --location westeurope `
  --resource-group RG2forTutorial `
  --sku Standard_LRS

# Create a serverless function app in the resource group.
az functionapp create `
  --name FAforTutorial `
  --storage-account sa3fortutorialntk `
  --consumption-plan-location westeurope `
  --resource-group RG2forTutorial `
  --functions-version 2

#endregion


#region LET POWERSHELL HELP AND TELL YOU WHAT TO TYPE

# Windows PowerShell

Find-Module psreadline -AllowPrerelease
Install-Module psreadline -AllowPrerelease -Scope CurrentUser -Verbose
# Install-Module psreadline -AllowPrerelease -Scope CurrentUser -Verbose -Force

# When the cursor is at the end of a fully expanded cmdlet, pressing F1 displays the help for that cmdlet.
# When the cursor is at the end of a fully expanded parameter, pressing F1 displays the help beginning at the parameter.
# Pressing the Alt-h key combination provides dynamic help for parameters.

Get-PSReadLineKeyHandler | where function -Match help

# Press Alt-a to rapidly select and change the arguments of a command

Get-AzConnectedMachineExtension -ResourceGroupName hybrid2-rg -MachineName luka-winvm | fl *

# Predictive IntelliSense
# matching predictions from the user’s history and additional domain specific plugins

Set-PSReadLineOption -PredictionSource History

Get-PSReadLineOption | fl *prediction*
Get-PSReadLineOption

# The default light-grey prediction text color
Set-PSReadLineOption -Colors @{ InlinePrediction = "$([char]0x1b)[48;5;238m" }

Set-PSReadLineOption -Colors @{ InlinePrediction = '#8A0303' }
Set-PSReadLineOption -Colors @{ InlinePrediction = '#2F7004' }
Set-PSReadLineOption -Colors @{ InlinePrediction = "$([char]0x1b)[36;7;238m" }

# By default, pressing RightArrow accepts an inline suggestion when the cursor is at the end of the current line.

# Predictions are displayed in one of two views depending on the user preference

# InlineView – This is the default view and displays the prediction inline with the user’s typing. This view is similar to other shells Fish and ZSH.
# ListView – ListView provides a dropdown list of predictions below the line the user is typing.

# You can change the view at the command line using the keybinding F2 or
# Set-PSReadLineOption -PredictionViewStyle ListView

# Start PowerShell 7.2 and show Az Predictor (use Windows Terminal)
Import-Module Az.Tools.Predictor

#endregion


#region POWERSHELL IN AZURE CLOUD SHELL

# Azure PSDrive

Get-PSDrive 

cd azure:

# Select a subscription and browse to the lab-rg resource group

# Context-aware commands
Get-AzVM
$PSDefaultParameterValues

Get-Module -ListAvailable
Get-Command -Module PSCloudShellUtility

Get-CloudDrive
dir ~/clouddrive/.cloudconsole/acc_mas.img
5368709120 / 1GB

Get-PackageVersion

# Open a resource in the Azure portal
Get-AzVM -ResourceGroupName lab-rg | select id | portal
Get-AzVM -ResourceGroupName lab-rg | fl id | portal
Get-AzVM -ResourceGroupName lab-rg -Name lon-cl1 | select -expand id | portal

# Open a link in new tab from the Cloud Shell
browse https://microsoft.com/powershell

#region PowerShell remoting in Azure Cloud Shell
# needs 2 minutes to complete
Enable-AzVMPSRemoting -Name winvm -ResourceGroupName ps-rg -OsType Windows -Protocol https

# needs a minute to complete
Enable-AzVMPSRemoting -Name myvm -ResourceGroupName ps-rg -OsType Linux -Protocol ssh
<# What is happening on a Linux VM?

 # 1) Install powershell in linux, if not already present
# 2) backup current sshd_config, configure sshd_config to enable PasswordAuthentication, register powershell subsystem with ssh daemon
# (#2 is required to support interactive username/password authentication over powershell-ssh)
# 3) Restart the ssh daemon service to pick up the new config changes
sudo wget -q https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt-get update
sudo apt-get install -y powershell
sshdconfigfile=/etc/ssh/sshd_config
sudo sed -re "s/^(\#)(PasswordAuthentication)([[:space:]]+)(.*)/\2\3\4/" -i.`date -I` "$sshdconfigfile"
sudo sed -re "s/^(PasswordAuthentication)([[:space:]]+)no/\1\2yes/" -i.`date -I` "$sshdconfigfile"
subsystem="Subsystem powershell /usr/bin/pwsh -sshs -NoLogo -NoProfile"
sudo grep -qF -- "$subsystem" "$sshdconfigfile" || sudo echo "$subsystem" | sudo tee --append "$sshdconfigfile"
sudo service sshd restart
#>

$cred = Get-Credential azureuser
Invoke-AzVMCommand -Name winvm -ResourceGroupName ps-rg -ScriptBlock { Get-Process } -Credential $cred

Invoke-AzVMCommand -Name myvm -ResourceGroupName ps-rg -ScriptBlock { Get-Process } -UserName azureuser -KeyFilePath ~/.ssh/id_rsa

New-PSSession -HostName 20.232.188.131 -UserName azureuser -KeyFilePath $HOME/.ssh/id_rsa -OutVariable session
$session | Enter-PSSession

#endregion


# Increase a font size in command palette
# Map a file share
# Run it in a local container

#endregion

#region STOP STORING ENCRYPTED CREDENTIALS IN YOUR POWERSHELL SCRIPTS

# How we used to do it
# Encrypt an exported credential object on Windows

# The Export-Clixml cmdlet encrypts credential objects by using the Windows Data Protection API.
# The encryption ensures that only your user account on only that computer can decrypt the contents of the credential object.
# The exported CLIXML file can't be used on a different computer or by a different user.

$Credential = Get-Credential
$Credxmlpath = Join-Path (Split-Path $Profile) TestScript.ps1.credential
$Credential | Export-Clixml $Credxmlpath
Get-Content $Credxmlpath

# Later, in TestScript.ps1, you recreate the credentials
$Credxmlpath = Join-Path (Split-Path $Profile) TestScript.ps1.credential
$Credential = Import-Clixml $Credxmlpath

# Export-Clixml only exports encrypted credentials on Windows.
# On non-Windows operating systems such as macOS and Linux, credentials are exported as a plain text
# stored as a Unicode character array. This provides some obfuscation but does not provide encryption.

# Start PowerShell on Linux (WSL)
$Credential = Get-Credential

$Credential | Export-Clixml ./credentials.xml
Get-Content ./credentials.xml

#  The value is encoded but not encrypted
$Credential.GetNetworkCredential().Password | Format-Hex -Encoding unicode

-join ([Text.Encoding]::Unicode.GetBytes('SuperSecret') | ForEach-Object { [Convert]::ToString($_, 16).PadLeft(2, '0') })

$bytes = '53007500700065007200530065006300720065007400' -split '(?<=\G.{2})(?=.)' | ForEach-Object { [Convert]::ToByte($_, 16) }
[Text.Encoding]::Unicode.GetString($bytes)

[Text.Encoding]::Unicode.GetString(( -split ('53007500700065007200530065006300720065007400' -replace '..', '0x$& ')) -as [byte[]])

# SecretManagement and SecretStore

Install-Module Microsoft.PowerShell.SecretManagement

# The SecretManagement module provides the following cmdlets for accessing secrets and managing SecretVaults

Get-Command -Module Microsoft.PowerShell.SecretManagement | Sort-Object noun | Format-Table -GroupBy noun

# SecretManagement becomes useful once you install and register extension vaults.
# Extension vaults, which are PowerShell modules with a particular structure,
# provide the connection between the SecretManagement module and any local or remote Secret Vault.
Find-Module -Tag "SecretManagement" -Repository PSGallery

Install-Module Microsoft.PowerShell.SecretStore

# The SecretStore vault stores secrets locally on file for the current user,
# and uses .NET Core cryptographic APIs to encrypt file contents. 
Get-Command -Module Microsoft.PowerShell.SecretStore | Sort-Object noun | Format-Table -GroupBy noun

# Getting started with SecretStore

Register-SecretVault -Name MySecretStore -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
Get-SecretStoreConfiguration

Set-Secret -Name DemoSecret -Secret "SuperSecret"
Get-Secret -Name DemoSecret
Get-Secret -Name DemoSecret -AsPlainText

# To see the names all of your secrets
Get-SecretInfo -Vault MySecretStore
Set-SecretInfo -Name DemoSecret -Vault MySecretStore -Metadata @{Purpose = "A password for demos" }
Get-SecretInfo -Vault MySecretStore | Format-Table *

<# Using the SecretStore in Automation
$password = Import-CliXml -Path $securePasswordPath

Set-SecretStoreConfiguration -Scope CurrentUser -Authentication Password -PasswordTimeout 3600 -Interaction None -Password $password -Confirm:$false

Register-SecretVault -Name SecretStore -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault

Unlock-SecretStore -Password $password
#>

Get-Command -Module SecretManagement.Chromium | Sort-Object noun | Format-Table -GroupBy noun

# Getting Started with Azure Key Vault
$azKeyVault = Get-AzKeyVault -Name githubkv
$vaultName = ($azKeyVault.ResourceId -split '/')[-1]
$subID = ($azKeyVault.ResourceId -split '/')[2]

Register-SecretVault -Module Az.KeyVault -Name AzKV -VaultParameters  @{ AZKVaultName = $vaultName; SubscriptionId = $subID }

Get-SecretInfo -Vault AzKV
Get-Secret -Name PAT4CloudShell -Vault AzKV # -AsPlainText
#endregion

#region Filtering the result

#output
# AzPS > an object
# AzCLI > JSON string
# --output -o : Output format. Allowed values: json, jsonc, none, table, tsv, yaml, yamlc. Default: json.

# filtering
# --query : JMESPath query string. See http://jmespath.org/ for more information and examples.

az account list-locations --query "sort_by([].{DisplayName: displayName, ARMName:name}, &DisplayName)" --output table

Get-AzLocation | Select-Object DisplayName, Location | Sort-Object DisplayName

az webapp list --query "[].{resource:resourceGroup, name:name, defaultHostName:defaultHostName}" -o table
# az webapp list --query "[].{resource:resourceGroup, name, defaultHostName}" -o table
Get-AzWebApp | Select-Object @{n = 'resource'; e = { $_.resourceGroup } }, name, defaultHostName

az webapp list | ConvertFrom-Json | Select-Object @{n = 'resource'; e = { $_.resourceGroup } }, name, defaultHostName

az webapp list --query "[?state=='Running'].{resource:resourceGroup, name:name, defaultHostName:defaultHostName}" -o table
Get-AzWebApp | Where-Object { $_.State -eq 'Running' } | Format-Table resourceGroup, name, defaultHostName
Get-AzWebApp | where State -EQ 'Running' | ft resourceGroup, name, defaultHostName

az webapp list --query-examples
az vm list --query-examples

#endregion


#region Tab-completion, IntelliSense

# Completers in Azure PowerShell
# Get-AzVm -Name L<TAB> -ResourceGroupName <Ctrl+Space> 
# Get-AzVm -ResourceGroupName l<TAB> -Name <Ctrl+Space>
# Stop-AzVM -Id *demovm*<TAB>

#endregion

#region Troubleshooting

# -Debug or $DebugPreference are crucial for troubleshooting

#endregion

#region Idempotency

#Azure CLI
az group create --name pwsh24lin-rg --location eastus

az storage account create --name pwsh2cli --resource-group pwsh24lin-rg --location eastus
az storage account create --name pwsh2cli --resource-group pwsh24lin-rg --location eastus

# Azure PowerShell
New-AzResourceGroup -Name pwsh24win -Location eastus
New-AzResourceGroup -Name pwsh24win -Location eastus -Force

New-AzStorageAccount -Name pwsh24ps -ResourceGroupName pwsh24win -Location eastus -SkuName Standard_LRS 
New-AzStorageAccount -Name pwsh24ps -ResourceGroupName pwsh24win -Location eastus -SkuName Standard_LRS 
# New-AzStorageAccount: The storage account named pwsh24ps is already taken. (Parameter 'Name')

#endregion

 
# VARIOUS TIPS

#region Discovering Public IP Address

Invoke-RestMethod -Uri 'ipinfo.io/json'

#endregion

#region Redisplay a header

# The output now is paused per page until you press SPACE. 
# However, the column headers are displayed only on the first page.

Get-AzVM | Out-Host -Paging 
 
# A better output can be produced like this:
Get-AzVM | Format-Table -RepeatHeader | Out-Host -Paging 

$PSDefaultParameterValues["Format-Table:RepeatHeader"] = $true
Get-AzVM | Format-Table | Out-Host -Paging 
#endregion

#region A List of HTTP Response Codes

[Enum]::GetValues([System.Net.HttpStatusCode]) |
ForEach-Object {
  [PSCustomObject]@{
    Code        = [int]$_
    Description = $_.toString()
  }
}

#endregion

#region Manage Azure resources with the Invoke-AzRestMethod cmdlet

# Invoke-AzRestMethod is a new Azure PowerShell cmdlet. 
# It allows you to make custom HTTP requests to the Azure Resource Management (ARM) endpoint using the Az context.
# This cmdlet is useful when you want to manage Azure services for features that aren’t yet available in the Az PowerShell modules.

# Define variables
$ResourceGroupName = 'prva2020'
$functionAppName = 'funcappportal2020'

$functionApp = Get-AzFunctionApp -ResourceGroupName $ResourceGroupName -Name $functionAppName

# Make the HTTP request and convert the Content property to a PSCustomObject
Invoke-AzRestMethod -Path ($functionApp.Id + "\functions?api-version=2020-06-01") -Method GET -OutVariable response

$response.content
$response.content | code - 

$functions = $response.content | ConvertFrom-Json
$functions | Get-Member
Get-Member -InputObject $functions.value
$functions.value | Get-Member
$functions.value

# Get the info

$functions.value.properties
# Get the invoke URL for a HTTP Trigger function
$functions.value.properties.invoke_url_template

# Retrieving the function keys
foreach ($functionName in $functions.value.properties.name) {
  Invoke-AzRestMethod -Path ($functionApp.Id + "\functions\$functionName\listkeys?api-version=2020-06-01") -Method POST -OutVariable response2
  $keys = $response2.content | ConvertFrom-Json
  [PSCustomObject]@{FunctionName = $functionName; DefaultKey = $keys.default }
}
#endregion

#region POWERSHELL AZURE FUNCTIONS

func --version

cd c:\azfunctions

$functionAppName = 'demo-app-cs'
$resourceGroupName = "$functionAppName-rg"
$storageAccountName = 'storacc' + (Get-Random)
$location = 'westeurope'

func init $functionAppName --powershell

cd ./$functionAppName
# take a look at requirements.psd1
code . -n 

func new --name HttpExample --template "HTTP trigger" --authlevel "anonymous"

func start

New-AzResourceGroup -Name $resourceGroupName -Location $location
New-AzStorageAccount -ResourceGroupName $resourceGroupName -Name $storageAccountName -SkuName Standard_LRS -Location $location
New-AzFunctionApp -Name $functionAppName -ResourceGroupName $resourceGroupName -StorageAccount $storageAccountName -Runtime PowerShell -FunctionsVersion 3 -Location $location

func azure functionapp publish $functionAppName

# Run it in another session
Invoke-RestMethod https://demo-app-cs.azurewebsites.net/api/httpexample?name=PowerShellers

#endregion


# AZURE CLI

#region Output formatting

# Three common output formats are used with Azure CLI commands:

<#
The json format shows information as a JSON string.

JSON gives you the most comprehensive information.
This format is the default but you can use the --output parameter to specify a different option.
Change the global default format to one of your personal preference by using az config such as az config set core.output=table.
Note that JSON format preserves the double quotes, generally making in unsuitable for scripting purposes.
#>

<#
The table format presents output as a readable table.
You can specify which values appear in the table and use queries to customize the output as shown here:
#>

az vm show --resource-group lab-rg --name lon-cl1 --query "{name: name, os:storageProfile.imageReference.offer}" --output table

<#
The tsv format returns tab-separated and newline-separated values without extra formatting, keys, or other symbols.

The TSV format is useful for concise output and scripting purposes.
The TSV will strip double quotes that the JSON format preserves.
To specify the format you want for TSV, use the --query parameter.
#>

export vm_ids=$(az vm list --show-details --resource-group lab-rg --query "[?powerState=='VM running'].id" --output tsv)
az vm stop --ids $vm_ids
#endregion

#region Pass values to another command

# If the value will be used more than once, assign it to a variable.
# Variables allow you to use values more than once or to create more general scripts.
# This example assigns an ID found by the az vm list command to a variable.

# assign the list of running VMs to a variable
running_vm_ids=$(az vm list --resource-group MyResourceGroup --show-details \
    --query "[?powerState=='VM running'].id" --output tsv)

# verify the value of the variable
echo $running_vm_ids

# If the value is used only once, consider piping.
az vm list --query "[?powerState=='VM running'].name" --output tsv | grep my_vm

# For multi-value lists, consider the following options:

# 1. If you need more controls on the result, use a "for" loop:

#!/usr/bin/env bash
for vmList in $(az vm list --resource-group MyResourceGroup --show-details --query "[?powerState=='VM running'].id"   --output tsv); do
    echo stopping $vmList
    az vm stop --ids $vmList
    if [ $? -ne 0 ]; then
        echo "Failed to stop $vmList"
        exit 1
    fi
    echo $vmList stopped
done

# 2. Alternatively, use xargs and consider using the -P flag to run the operations in parallel for improved performance:

az vm list --resource-group MyResourceGroup --show-details \
  --query "[?powerState=='VM stopped'].id" \
  --output tsv | xargs -I {} -P 10 az vm start --ids "{}"

# 3. Finally, Azure CLI has built-in support to process commands with multiple --ids in parallel to achieve the same effect of xargs. 
# Note that @- is used to get values from the pipe:

az vm list --resource-group lab-rg --show-details \
  --query "[?powerState=='VM deallocated'].id" \
  --output tsv | az vm start --ids @-

#endregion

#region Use hyphen characters in parameters
<#
If a parameter's value begins with a hyphen, Azure CLI tries to parse it as a parameter name. 
To parse it as value, use = to concatenate the parameter name and value: --password="-VerySecret".
#>
#endregion

#region Asynchronous operations

# Operations in Azure can take a noticeable amount of time.
# For instance, configuring a virtual machine at a data center isn't instantaneous.
# Azure CLI waits until the command has finished to accept other commands.
# Many commands therefore offer a --no-wait parameter as shown here:

az group delete --name MyResourceGroup --no-wait

# When deleting a resource group, all the resources that belong to it are also removed.
# Removing these resources can take a long time.
# Running the command with the --no-wait parameter, allows the console to accept new commands without interrupting the removal.

# Many commands offer a wait option, pausing the console until some condition is met.
# The following example uses the az vm wait command to support creating independent resources in parallel:

az vm create --resource-group VMResources --name virtual-machine-01 --image centos --no-wait
az vm create --resource-group VMResources --name virtual-machine-02 --image centos --no-wait

subscription=$(az account show --query "id" -o tsv)
vm1_id="/subscriptions/$subscription/resourceGroups/VMResources/providers/Microsoft.Compute/virtualMachines/virtual-machine-01"
vm2_id="/subscriptions/$subscription/resourceGroups/VMResources/providers/Microsoft.Compute/virtualMachines/virtual-machine-02"
az vm wait --created --ids $vm1_id $vm2_id

# After both IDs are created, you can use the console again.

#endregion