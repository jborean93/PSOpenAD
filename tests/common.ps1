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
    [PSOpenADCredential[]]$Credentials = @()
    [bool]$DefaultCredsAvailable = $false
    [bool]$TlsAvailable = $false
    [bool]$TlsTrusted = $false
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
                    Cached   = $_.cached
                }
            })

        $global:PSOpenADSettings = [PSOpenADSettings]@{
            Server                  = $settingsRaw.server
            Credentials             = $credentials
            DefaultCredsAvailable   = $cached
            TlsAvailable            = ([bool]$settingsRaw.tls)
            TlsTrusted              = $settingsRaw.tls.trusted
            SupportsNegotiateAuth   = $settingsRaw.features.negotiate_auth
            ImplicitServerAvailable = $settingsRaw.features.implicit_server
        }
    }
    else {
        $global:PSOpenADSettings = [PSOpenADSettings]::new()
    }

}
