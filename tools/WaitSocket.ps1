[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [String]
    $TargetHost,

    [Parameter(Mandatory)]
    [int]
    $Port,

    [int]
    $Timeout = 0
)


$client = [System.Net.Sockets.TcpClient]::new()

$currentWait = 0
$connectTask = $client.ConnectAsync($TargetHost, $Port)
while (-not $connectTask.AsyncWaitHandle.WaitOne(200)) {
    $currentWait += 200

    if ($Timeout -ne 0 -and $currentWait -gt $Timeout) {
        throw "Timed out waiting for $($TargetHost):$Port"
    }
}
