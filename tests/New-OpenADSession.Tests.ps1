BeforeAll {
    . ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))
}

Describe "New-OpenADSession to actual host" -Skip:(-not $PSOpenADSettings.Server) {
    It "Creates a session using default credentials" {
        $s = New-OpenADSession -ComputerName $PSOpenADSettings.Server
        $s | Remove-OpenADSession
    }
}
