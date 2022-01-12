BeforeAll {
    . ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))
}

Describe "New-OpenADSession" {
    It "Creates a session using default credentials" {
        $s = New-OpenADSession -ComputerName $env:PSOPENAD_DC
        $s | Remove-OpenADSession
    }
}
