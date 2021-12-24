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
        $connectTask.GetAwaiter().GetResult()
        break
    }
    catch {
        $end = (Get-Date) - $start
        if ($Timeout -ne 0 -and $end.TotalMilliseconds -gt $Timeout) {
            throw "Timed out waiting for connection $($TargetHost):$($Port)"
        }
    }
}
