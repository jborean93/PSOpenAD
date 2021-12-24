BeforeAll {
    . ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))
}

Describe "New-OpenADSession" {
    It "Creates a session using default credentials" {
        $s = New-OpenADSession -ComputeName $env:PSOPENAD_DC -Verbose
        $s | Remove-OpenADSession
    }
}
