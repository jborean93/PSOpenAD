. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "Get-OpenADAuthSupport" {
    It "It gets auth support details" {
        $actual = Get-OpenADAuthSupport
        $actual.Count | Should -BeGreaterThan 0
        $actual | ForEach-Object {
            $_ -is ([PSOpenAD.AuthenticationProvider]) | Should -BeTrue
        }
    }
}
