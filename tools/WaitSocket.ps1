<#
.SYNOPSIS
Waits for the port on the target host to be reachable.

.PARAMETER TargetHost
The hostname or IP of the target host to connect to.

.PARAMETER Port
The port on TargetHost to connect to.

.PARAMETER Timeout
The time to wait in milliseconds before failing.
Set to 0 to wait indefinitely.
#>
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

$start = Get-Date

while ($true) {
    $client = [System.Net.Sockets.TcpClient]::new()
    $connectTask = $client.ConnectAsync($TargetHost, $Port)
    while (-not $connectTask.AsyncWaitHandle.WaitOne(200)) {}

    try {
        [void]$connectTask.GetAwaiter().GetResult()
        break
    }
    catch {
        $end = (Get-Date) - $start
        if ($Timeout -ne 0 -and $end.TotalMilliseconds -gt $Timeout) {
            throw "Timed out waiting for connection $($TargetHost):$($Port)"
        }
    }
}
