
#region NEW: Get Started with PowerShell (in Visual Studio Code) Walkthrough
#endregion

#region Find out what's new

Install-Module -Name Microsoft.PowerShell.WhatsNew -Repository PSGallery

# Use Get-WhatsNew with a nice utility on GitHub called glow and it renders the markdown at the console better than Show-Markdown.
# https://github.com/charmbracelet/glow

Get-WhatsNew | glow -

#endregion

#region IMPROVE POWERSHELL EXPERIENCE IN WINDOWS TERMINAL AND VISUAL STUDIO CODE

https://ohmyposh.dev/

https://www.nerdfonts.com/font-downloads
"Caskaydia Code Nerd Font"
# For PowerShell console, change a font in Properties
# For Visual Studio Code, go to Settings > Terminal > Integrated: Font Family 'CaskaydiaCove NF'
# For Windows Terminal, go to Settings > Profiles > PowerShell > Appearance > Font face: 'CaskaydiaCove NF'

Install-Module -Name Terminal-Icons -Repository PSGallery
Import-Module -Name Terminal-Icons

# Content of the Microsoft.PowerShell_profile.ps1 and Microsoft.VSCode_profile.ps1 files
# & ([ScriptBlock]::Create((oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH\jandedobbeleer.omp.json" --print) -join "`n"))
& ([ScriptBlock]::Create((oh-my-posh init pwsh --config "$HOME\Documents\my-night-owl.omp.json" --print) -join "`n"))
Enable-PoshTransientPrompt

Import-Module Terminal-Icons
# Import-Module posh-git

function Show-Repo { gh repo view --web }
# EOF

#endregion

#region Out-ConsoleGridView

Install-Module -Name Microsoft.PowerShell.ConsoleGuiTools -Repository PSGallery
# Out-ConsoleGridView  

#endregion

#region STOP STORING ENCRYPTED CREDENTIALS IN YOUR POWERSHELL SCRIPTS

# Uber
https://github.com/thycotic-ps/thycotic.secretserver/blob/dev/docs/getting_started/authentication.md#automated-login
https://github.com/thycotic-ps/thycotic.secretserver/commit/7ce840d1975aa36175fc6080691b5f8abe8e276a

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
Set-SecretInfo -Name DemoSecret -Vault MySecretStore -Metadata @{Purpose = "A password for demos"}
Get-SecretInfo -Vault MySecretStore | Format-Table *

<# Using the SecretStore in Automation
$credential = Get-Credential -UserName 'whoever'
$securePasswordPath = 'C:\automation\passwd.xml'
$credential.Password |  Export-Clixml -Path $securePasswordPath

Register-SecretVault -Name SecretStore -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
$password = Import-CliXml -Path $securePasswordPath
Set-SecretStoreConfiguration -Scope CurrentUser -Authentication Password -PasswordTimeout 3600 -Interaction None -Password $password -Confirm:$false
Set-Secret -Name CIJobSecret -Secret "SuperSecret"

$password = Import-CliXml -Path $securePasswordPath
Unlock-SecretStore -Password $password
$automationPassword = Get-Secret -Name CIJobSecret
#>

Get-Command -Module SecretManagement.Chromium | Sort-Object noun | Format-Table -GroupBy noun
Register-ChromiumSecretVault
Get-SecretInfo -Vault Edge-Profile2 | Format-Table *

# Getting Started with Azure Key Vault
$azKeyVault = Get-AzKeyVault -Name githubkv
$vaultName = ($azKeyVault.ResourceId -split '/')[-1]
$subID = ($azKeyVault.ResourceId -split '/')[2]

Register-SecretVault -Module Az.KeyVault -Name AzKV -VaultParameters  @{ AZKVaultName = $vaultName; SubscriptionId = $subID}

Get-SecretInfo -Vault AzKV
Get-Secret -Name PAT4CloudShell -Vault AzKV # -AsPlainText

#region THIS IS BUILT-IN NOW: Significantly mitigate information disclosure concerns in your PowerShell PSReadline history

# BEFORE
# Remove-Item (Get-PSReadLineOption).HistorySavePath

Get-PSReadLineOption | Select-Object *history*
# Set-PSReadLineOption -HistorySaveStyle SaveIncrementally

$pass = ConvertTo-SecureString "Sup3rS3cr3t2" -AsPlainText -Force

Select-String Sup3rS3cr3t2 ((Get-PSReadLineOption).HistorySavePath)


# Significantly mitigate information disclosure concerns in your PowerShell PSReadline history:

Set-PSReadLineOption -AddToHistoryHandler {
    param([string]$line)

    $sensitive = "password|asplaintext|token|key|secret"
    return ($line -notmatch $sensitive)
}

# AFTER
[PSCustomObject]@{ UserName = 'Aleksandar'; Password = "P@ssw0rd" }

Select-String UserName ((Get-PSReadLineOption).HistorySavePath)

#endregion

# What happens when you type a sensitive information interactively
$username = 'ssadmin'
$password = ConvertTo-SecureString -String 'Y02$r(0m#l3xP@ssw%rd' -AsPlainText -Force
$cred = [pscredential]::new($username,$password)
$session = New-TssSession -SecretServer https://vault.company/SecretServer -Credential $session
"This is not a sensitive information."
[PSCustomObject]@{ UserName = 'Aleksandar'; Password = "P@ssw0rd" }
[PSCustomObject]@{ UserName = 'Aleksandar'; Token = "ef23gvyh4546fvbk563kkd3" }

Get-Content (Get-PSReadLineOption).HistorySavePath -Tail 7

#endregion

#region SAVE YOUR POWERSHELL COMMANDS TOGETHER WITH THEIR RESULTS, AND SHARE IT WITH OTHERS

# PowerShell notebooks!
# .NET Interactive notebooks in Visual Studio Code and Azure Data Studio support PowerShell
# https://github.com/dfinke/powershell-notebooks

cd C:\gh\powershell-notebooks && Show-Repo 

cd C:\gh\powershell-notebooks\powershell-101 && dir

code .\14-Hashtables.dib
#endregion

#region LET POWERSHELL HELP AND TELL YOU WHAT TO TYPE

# Windows PowerShell

Find-Module psreadline -AllowPrerelease
Install-Module psreadline -AllowPrerelease -Scope CurrentUser -Verbose
# Install-Module psreadline -AllowPrerelease -Scope CurrentUser -Verbose -Force

# When the cursor is at the end of a fully expanded cmdlet, pressing F1 displays the help for that cmdlet.
# When the cursor is at the end of a fully expanded parameter, pressing F1 displays the help beginning at the parameter.
# Pressing the Alt-h key combination provides dynamic help for parameters.

# Set-PSReadLineKeyHandler -chord "Ctrl-l" -Function ShowParameterHelp

Get-PSReadLineKeyHandler | where function -match help

# Press Alt-a to rapidly select and change the arguments of a command

Invoke-Command -ComputerName Server1 -ScriptBlock {Get-Service -Name win* -OutVariable services} -SessionName $so

# An example profile for PSReadLine
psedit (Join-Path (Split-Path (Get-Module psreadline).Path) SamplePSReadLineProfile.ps1)

# Predictive IntelliSense
# matching predictions from the user’s history and additional domain specific plugins

Set-PSReadLineOption -PredictionSource HistoryAndPlugin

Get-PSReadLineOption | fl *prediction*
Get-PSReadLineOption

# The default light-grey prediction text color
Set-PSReadLineOption -Colors @{ InlinePrediction = "$([char]0x1b)[48;5;238m"}

Set-PSReadLineOption -Colors @{ InlinePrediction = '#8A0303'}
Set-PSReadLineOption -Colors @{ InlinePrediction = '#2F7004'}
Set-PSReadLineOption -Colors @{ InlinePrediction = "$([char]0x1b)[36;7;238m"}

# By default, pressing RightArrow accepts an inline suggestion when the cursor is at the end of the current line.

# Predictions are displayed in one of two views depending on the user preference

# InlineView – This is the default view and displays the prediction inline with the user’s typing. This view is similar to other shells Fish and ZSH.
# ListView – ListView provides a dropdown list of predictions below the line the user is typing.

# You can change the view at the command line using the keybinding F2 or
# Set-PSReadLineOption -PredictionViewStyle ListView

# Start PowerShell 7.2.x and show Az Predictor (use Windows Terminal)
#  Import-Module Az.Tools.Predictor

#endregion

#region VARIOUS POWERSHELL TIPS AND TRICKS

$global:PSDefaultParameterValues["Out-Default:OutVariable"] = '__'

#region Sysinternals Tools and PowerShell

$destinationZipPath = "$env:temp\pstools.zip"
$destinationFolder = "$env:temp\pstools"

$link = "https://download.sysinternals.com/files/PSTools.zip "
Invoke-RestMethod -Uri $link -OutFile $destinationZipPath -UseBasicParsing
Unblock-File -Path $destinationZipPath
Expand-Archive -Path $destinationZipPath -DestinationPath $destinationFolder -Force
Remove-Item -Path $destinationZipPath

explorer /select,$destinationFolder

#endregion

#region Recently installed software

$item = Get-WinEvent -FilterHashtable @{ ProviderName= "MSIInstaller"; ID=1033 } -MaxEvents 1
 
$item 

$__.message

# However, if you are more comfortable using XML, 
# you can always turn the event objects into pure XML (as XML is the native event format anyway)

$xml = [xml]$item.ToXml() 
$xml.Event.EventData.Data

####

$name = @{
    Name = 'Name'
    Expression = { ($_.ToXml() -as [xml ]).Event.EventData.Data[0 ] }
}
 
$version = @{
    Name = 'Version'
    Expression = { ($_.ToXml() -as [xml ]).Event.EventData.Data[1 ] -as [Version] }
}
 
$vendor = @{
    Name = 'Vendor'
    Expression = { ($_.ToXml() -as [xml ]).Event.EventData.Data[4 ] }
}
 
$result = @{
    Name = 'Result'
    Expression = { ($_.ToXml() -as [xml ]).Event.EventData.Data[3 ] -as [int] }
}
 
Get-WinEvent -FilterHashtable @{ ProviderName="MSIInstaller"; ID=1033 } |
Select-Object -Property TimeCreated, $name, $version, $vendor

#endregion

#region Reading Windows Product Key

(Get-CimInstance -ClassName SoftwareLicensingService).OA3xOriginalProductKey

#endregion

#region ArrayList

$myArray = New-Object System.Collections.ArrayList
[void] $myArray.Add("Hello")
[void] $myArray.AddRange( ("World","How","Are","You") )
$myArray

$myArray.RemoveAt(1)
$myArray

#endregion

#region Using Invoke-RestMethod with the StackOverflow API

$url = "https://api.stackexchange.com/2.0/questions/unanswered" + "?order=desc&sort=activity&tagged=powershell&pagesize=10&site=stackoverflow"

$result = Invoke-RestMethod $url

$result.Items | ForEach-Object { $_.Title; $_.Link; "" }

# Searching StackOverflow for answers to a PowerShell question

function Search-StackOverflow {

<#
.SYNOPSIS
Searches Stack Overflow for PowerShell questions that relate to your
search term, and provides the link to the accepted answer.
.EXAMPLE
PS > Search-StackOverflow upload ftp
Searches StackOverflow for questions about how to upload FTP files
.EXAMPLE
PS > $answers = Search-StackOverflow.ps1 upload ftp
PS > $answers | Out-GridView -PassThru | Foreach-Object { start $_ }
Launches Out-GridView with the answers from a search. Select the URLs
that you want to launch, and then press OK. PowerShell then launches
your default web browser for those URLs.
#>
Set-StrictMode -Off
Add-Type -Assembly System.Web
$query = $args -join " "
$query = [System.Web.HttpUtility]::UrlEncode($query)
## Use the StackOverflow API to retrieve the answer for a question
$url = "https://api.stackexchange.com/2.0/search?order=desc&sort=relevance" + "&pagesize=5&tagged=powershell&intitle=$query&site=stackoverflow"
$question = Invoke-RestMethod $url
## Now go through and show the questions and answers
$question.Items | Where-Object accepted_answer_id | Foreach-Object {
 "Question: " + $_.Title
 "https://www.stackoverflow.com/questions/$($_.accepted_answer_id)"
 ""
}
}

Search-StackOverflow remoting

#endregion

#region Various tips I've received from my Twitter followers

<# Launch Regedit at a specific location from the command line (regedit-dot.ps1)
   @Lee_Holmes

function regedit. {
    $currentPath = Get-Item . | ForEach-Object Name
    $launchLocation = "COMPUTER\$currentPath"
    Set-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Regedit -Name LastKey -Value $launchLocation
    regedit
}

#>

cd HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion
regedit.

<#
Was talking to a friend about Perf Counters today, and it's incredible how much data is at our fingertips in Windows.
Here's a trivial example of finding out which process is currently consuming the most disk I/O.
#Lee_Holmes
#>

(Get-Counter -Counter "\Process(*)\IO Data Bytes/sec" -ErrorAction Ignore).CounterSamples |
Sort-Object -Descending CookedValue | Select-Object -First 10

# Splatting

# @duckgoop
$query = "select * from table where name = 'user'"
$invokeSqlCmdSplat = @{
    ServerInstance = 'ServerName'
    Database   = 'MyDB'
    Query        = $query
}
Invoke-SqlCmd @invokeSqlCmdSplat

# Use some long command and show splatting in VSCode Insiders (I have an older version of PS extension there)
Get-Command -Module SecretManagement -CommandType Cmdlet -Verbose

# @REOScotte
hostname | clip

# @mbsnl
function Connect-MyAzureAD { 
    Connect-AzureAD -AadAccessToken (Get-AzAccessToken -ResourceUrl https://graph.windows.net).token -AccountId (Get-AzContext).Account.Id -TenantId (Get-AzContext).Tenant.Id | Out-Null 
}

# @JustinWgrote
# using [version] to sort IP addresses by octet :)
[string[]]('222.1.3.4','1.2.3.4' | ForEach-Object {[Version]$_} | Sort-Object)

# @rjmholt
# I like to abuse the fact that @(...) will flatten a series of statements
# into an array to conditionally add array entries without lists or +=. 
# Example 1

$statArgs = @(
    '-c'
    if ($IsMacOS) { '%A' } else { '%a' }
    '/etc/passwd'
)

# Also note that this is an example of array splatting with a native command
/bin/stat @statArgs

# Example 2

# Naturally this is a bit contrived, since you could do gci ./PowerShell,./WindowsPowerShell with some extra logic
$FilesToCopy = @(
    Get-ChildItem -Path ~/Documents/PowerShell -Recurse -Filter '*.json.xml'
    if (Test-Path -Path ~/Documents/WindowsPowerShell) { Get-ChildItem -Path ~/Documents/WindowsPowerShell -Recurse -Filter '*.json.xml' }
)

# @sassdawe
$Array[6..8]

$Array[-1]

# Variables

'Hello, PowerShellers!' > TEMP:\hello.txt
Get-Content TEMP:\hello.txt
${TEMP:\hello.txt}
${function:help}

# @ProfessorLogout
$PSDefaultParameterValues.Add("*:Verbose", {$verbose -eq $true})

# @JustinWGrote
# I've become very partial to:

$item1,$item2 = $arrayoftwoitems

$email = 'aleksandar@gmail.com'
$user,$domain = $email.split('@')

$first,$second,$therest = $array


# @IISResetMe
# You can swap variable values with a single assignment
$a,$b = $b,$a

# Quick way to create a test array
,"powershell"*7

#endregion

# @deadlydog
# When still using PS5, include this before any web requests.
# Many websites block TLS 1.0 and 1.1 now, including the PSGallery,
# so your requests will fail, often with a non-obvious error message.

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# @ryanyates1990
# Inline command execution like this which is really nifty when running interactively
Invoke-Command -ComputerName (Get-content C .\comp.txt) -Credential (Get-credential)

# @
# Speedy hash tables
$UsersAll = Get-ADUser -Properties Manager, DisplayName, EmailAddress -Filter '*'
# This time we will prepare Hashtable that will keep DistinguishedName as a key
$Optimize = @{}
foreach ($item in $UsersAll) {
    $Optimize[$item.DistinguishedName] = $item
}
# End of preparations

$UsersWithManagers = foreach ($User in $UsersAll) {
    if ($null -ne $User.Manager) {
        $Manager = $Optimize[$User.Manager]
    } else {
        $Manager = $null
    }
    [PSCustomobject] @{
        SamAccountName = $User.SamAccountName
        Manager        = $User.Manager
        ManagerDisplay = $Manager.DisplayName
        ManagerEmail   = $Manager.EmailAddress
    }
}
$UsersWithManagers | Format-Table -AutoSize

Measure-Command {$a = @{}; 1..10000 | ForEach-Object {$a.$_ = $_}}

Measure-Command {$b = @{}; 1..10000 | ForEach-Object {$b.add($_, $_)}}

Measure-Command {$c = @{}; 1..10000 | ForEach-Object {$c[$_] = $_}}

Measure-Command {
    $b = @{}
    for ($i = 1; $i -le 10000; $i++) {

        $b.add($i, $i)
    }
}

#region Windows Module Compatibility
$env:PSModulePath -split ';'
Get-Module -ListAvailable
Get-Module *pnpp* -list
Connect-PnPOnline https://mo3ak.sharepoint.com

Import-Module SharePointPnPPowerShellOnline -UseWindowsPowerShell
Get-PSSession

Connect-PnPOnline https://mo3ak.sharepoint.com
Get-PnPUser
Get-PnPUser | Get-Member

#endregion

#region foreach -parallel
$testHosts = @(
    'google.com',
    'facebook.com',
    'amazon.com',
    'office.com'
)

$testHosts |
ForEach-Object { Test-Connection $_ -Count 2 -Delay 1 } |
Select-Object destination, status

$testHosts |
ForEach-Object -parallel { Test-Connection $_ -Count 2 -Delay 1 } |
Select-Object destination, status

$logNames = 'Security', 'Application', 'System', 'Windows PowerShell', 'Microsoft-Windows-Store/Operational'

$logEntries = $logNames | ForEach-Object -Parallel {
    Get-WinEvent -LogName $_ -MaxEvents 1000
} -ThrottleLimit 5

$logEntries.Count

$logNames = 'Security', 'Application', 'System', 'Windows PowerShell', 'Microsoft-Windows-Store/Operational'

$logEntries = $logNames | ForEach-Object {
    Get-WinEvent -LogName $_ -MaxEvents 1000
}

$logEntries.Count

# Let's check the duration
Get-History

#endregion

#region $ErrorActionPreference, $ErrorView, and Get-Error
$ErrorActionPreference = "Break"
. .\'Show me some errors.ps1'
$ErrorActionPreference = "Continue"

1/0
# $errorview ="[TAB]
$errorview = "foo"
Get-Error
Get-Error -Newest 3
#endregion

#region New operators

# Pipeline chain operators
cd c:\foo || mkdir c:\foo && cd c:\foo
cd..
cd c:\foo || mkdir c:\foo && cd c:\foo
cd.. && Remove-Item c:\foo

# Ternary operator
(Test-Path c:\foo) ? (cd c:\foo) : "Path not found"

# Background operator
Get-Process -Name pwsh &
# Start-Job -ScriptBlock {Get-Process -Name pwsh}

$job = Get-Process -Name pwsh & Receive-Job $job -Wait
# $job = Start-Job -ScriptBlock {Get-Process -Name pwsh}
# Receive-Job $job -Wait

Get-Process -Name pwsh & Get-Service -Name BITS & Get-CimInstance -ClassName Win32_ComputerSystem &
Get-Job | Remove-Job
#endregion

#region .NET to the rescue!

# Use .NET Core types' properties and methods instead of hardcoded values
# On Windows: $env:PSModulePath -split ';'
# On Linux:   $env:PSModulePath -split ':'

$env:PSModulePath -split [IO.Path]::PathSeparator

if([System.IO.Path]::DirectorySeparatorChar -eq '\'){'\\'}else{'/'}

<#
PS C:\> [IO.Path]::Combine("$HOME","scripts")
C:\Users\aleksandar\scripts

PS /home> [IO.Path]::Combine("$HOME","scripts")
/home/aleksandar/scripts
#>

Join-Path $HOME "scripts"

#endregion