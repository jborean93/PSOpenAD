$ErrorActionPreference = 'Stop'

$moduleName = (Get-Item ([IO.Path]::Combine($PSScriptRoot, '..', 'module', '*.psd1'))).BaseName
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
    [int]$Port
    [PSOpenADCredential[]]$Credentials = @()
    [bool]$DefaultCredsAvailable = $false
    [bool]$TlsAvailable = $false
    [bool]$TlsTrusted = $false
    [int]$TlsPort
    [bool]$SupportsNegotiateAuth = $false
    [bool]$ImplicitServerAvailable = $false
}

if (-not $global:PSOpenADSettings) {
    $settingsPath = [IO.Path]::Combine($PSScriptRoot, '..', 'test.settings.json')
    if (Test-Path -LiteralPath $settingsPath) {
        $settingsJson = Get-Content -LiteralPath $settingsPath -Raw
        $settingsRaw = ConvertFrom-Json -InputObject $settingsJson

        $cached = $false
        [PSOpenADCredential[]]$credentials = @($settingsRaw.credentials | ForEach-Object {
                if ($_.cached) { $cached = $true }
                $pass = ConvertTo-SecureString -AsPlainText -Force -String $_.password
                [PSOpenADCredential]@{
                    Username = $_.username
                    Password = $pass
                    Cached = $_.cached
                }
            })

        $global:PSOpenADSettings = [PSOpenADSettings]@{
            Server = $settingsRaw.server
            Port = $settingsRaw.port
            Credentials = $credentials
            DefaultCredsAvailable = $cached
            TlsAvailable = ([bool]$settingsRaw.tls)
            TlsTrusted = $settingsRaw.tls.trusted
            TlsPort = $settingsRaw.tls.port
            SupportsNegotiateAuth = $settingsRaw.features.negotiate_auth
            ImplicitServerAvailable = $settingsRaw.features.implicit_server
        }
    }
    else {
        $global:PSOpenADSettings = [PSOpenADSettings]::new()
    }
}

Function Global:Complete {
    [OutputType([System.Management.Automation.CompletionResult])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]
        $Expression
    )

    [System.Management.Automation.CommandCompletion]::CompleteInput(
        $Expression,
        $Expression.Length,
        $null).CompletionMatches
}

Function Global:New-TestOpenADSession {
    [OutputType([PSOpenAD.OpenADSession])]
    param(
        [Parameter()]
        [System.Collections.IDictionary]
        $SessionOptions = @{}
    )

    $selectedCred = $PSOpenADSettings.Credentials | Select-Object -First 1
    $cred = [pscredential]::new($selectedCred.Username, $selectedCred.Password)

    $sessionParams = @{
        ComputerName = $PSOpenADSettings.Server
        Credential = $cred
    }

    if (-not $PSOpenADSettings.SupportsNegotiateAuth) {
        $sessionParams.AuthType = 'Simple'

        if ($PSOpenADSettings.TlsAvailable) {
            $sessionParams.UseTLS = $true
            if ($PSOpenADSettings.TlsPort) {
                $sessionParams.Port = $PSOpenADSettings.TlsPort
            }

            $SessionOptions.SkipCertificateCheck = -not $PSOpenADSettings.TlsTrusted
        }
        else {
            $SessionOptions.NoEncryption = $true
            $SessionOptions.NoSigning = $true

        }
        $sessionParams.SessionOption = $so
    }
    elseif ($PSOpenADSettings.Port) {
        $sessionParams.Port = $PSOpenADSettings.Port
    }
    $sessionParams.SessionOption = New-OpenADSessionOption @SessionOptions

    New-OpenADSession @sessionParams
}
