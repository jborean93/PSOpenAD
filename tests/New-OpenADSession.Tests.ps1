BeforeAll {
    . ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))
}

Describe "New-OpenADSession" {
    It "Runs test" {
        "a" | Should -Be "a"
    }
}
