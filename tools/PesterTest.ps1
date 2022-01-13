<#
.SYNOPSIS
Run Pester test

.PARAMETER TestPath
The path to the tests to run

.PARAMETER OutputFile
The path to write the Pester test results to.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [String]
    $TestPath,

    [Parameter(Mandatory)]
    [String]
    $OutputFile
)

$requirements = Import-PowerShellDataFile ([IO.Path]::Combine($PSScriptRoot, '..', 'requirements-dev.psd1'))
foreach ($req in $requirements.GetEnumerator()) {
    Import-Module -Name ([IO.Path]::Combine($PSScriptRoot, 'Modules', $req.Key))
}

[PSCustomObject]$PSVersionTable |
    Select-Object -Property *, @{N='Architecture';E={
        switch ([IntPtr]::Size) {
            4 { 'x86' }
            8 { 'x64' }
            default { 'Unknown' }
        }
    }} |
    Format-List |
    Out-Host

$configuration = [PesterConfiguration]::Default
$configuration.Output.Verbosity = 'Detailed'
$configuration.Run.Exit = $true
$configuration.Run.Path = $TestPath
$configuration.TestResult.Enabled = $true
$configuration.TestResult.OutputPath = $OutputFile
$configuration.TestResult.OutputFormat = 'NUnitXml'

$moduleName   = (Get-Item ([IO.Path]::Combine($PSScriptRoot, '..', 'module', '*.psd1'))).BaseName
$manifestPath = [IO.Path]::Combine($PSScriptRoot, '..', 'output', $moduleName)

if (-not (Get-Module -Name $moduleName -ErrorAction SilentlyContinue)) {
    Import-Module $manifestPath -ErrorAction Stop
}

class PSOpenADCredential {
    [string]$Username
    [SecureString]$Password
    [bool]$Cached = $false
}

class PSOpenADSettings {
    [string]$Server
    [PSOpenADCredential[]]$Credentials = @()
    [bool]$TlsAvailable = $false
    [bool]$TlsTrusted = $false
    [bool]$SupportsNegotiateAuth = $false
}

$settingsPath = [IO.Path]::Combine($PSScriptRoot, '..', 'test.settings.json')
if (Test-Path -LiteralPath $settingsPath) {
    $settingsJson = Get-Content -LiteralPath $settingsPath -Raw
    $settingsRaw = ConvertFrom-Json -InputObject $settingsJson

    [PSOpenADCredential[]]$credentials = @($settingsRaw.credentials | ForEach-Object {
        $pass = ConvertTo-SecureString -AsPlainText -Force -String $_.password
        [PSOpenADCredential]@{
            Username = $_.username
            Password = $pass
            Cached = $_.cached
        }
    })

    $global:PSOpenADSettings = [PSOpenADSettings]@{
        Server = $settingsRaw.server
        Credentials = $credentials
        TlsAvailable = ([bool]$settingsRaw.tls)
        TlsTrusted = $settingsRaw.tls.trusted
        SupportsNegotiateAuth = $settingsRaw.features.negotiate_auth
    }
}
else {
    $global:PSOpenADSettings = [PSOpenADSettings]::new()
}

Invoke-Pester -Configuration $configuration -WarningAction Ignore
