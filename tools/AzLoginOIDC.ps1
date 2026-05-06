[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]
    $ClientId,

    [Parameter(Mandatory)]
    [string]
    $TenantId,

    [Parameter()]
    [string]
    $SubscriptionId
)

$ErrorActionPreference = 'Stop'

$token = $env:ACTIONS_ID_TOKEN_REQUEST_TOKEN
if (-not $token) {
    throw "ID token not found in environment variable: ACTIONS_ID_TOKEN_REQUEST_TOKEN"
}

$uri = $env:ACTIONS_ID_TOKEN_REQUEST_URL
if (-not $uri) {
    throw "ID token request URL not found in environment variable: ACTIONS_ID_TOKEN_REQUEST_URL"
}

$irmParams = @{
    Uri = $uri
    Authentication = 'Bearer'
    Token = (ConvertTo-SecureString -AsPlainText $token)
    Body = @{ audience = 'api://AzureADTokenExchange' }
}
$jwtResponse = Invoke-Restmethod @irmParams
$fedToken = $jwtResponse.value
if (-not $fedToken) {
    throw "Federated token not found in response: $($jwtResponse | ConvertTo-Json -Depth 10)"
}

$azLoginParams = @(
    '--service-principal'
    '--username', $ClientId
    '--tenant', $TenantId
    '--federated-token', $fedToken
)
az login @azLoginParams
if ($LASTEXITCODE) {
    throw "Azure login failed with exit code $LASTEXITCODE"
}

if ($SubscriptionId) {
    az account set --subscription $SubscriptionId
    if ($LASTEXITCODE) {
        throw "Azure account set failed with exit code $LASTEXITCODE"
    }
}
