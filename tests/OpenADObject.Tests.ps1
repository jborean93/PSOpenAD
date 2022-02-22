. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "Get-OpenADComputer" -Skip:(-not $PSOpenADSettings.Server) {
    BeforeAll {
        $selectedCred = $PSOpenADSettings.Credentials | Select-Object -First 1
        $cred = [pscredential]::new($selectedCred.Username, $selectedCred.Password)

        $session = New-OpenADSession -ComputerName $PSOpenADSettings.Server -Credential $cred
    }

    AfterAll {
        $session | Remove-OpenADSession
    }

    It "Finds ADComputer by -Identity sAMAccountName without ending $" {
        $dcName = @($PSOpenADSettings.Server -split '\.')[0]
        $actual = Get-OpenADComputer -Session $session -Identity $dcName
        $actual.Name | Should -Be $dcName
        $actual.SamAccountName | Should -Be "$dcName$"
    }

    It "Finds ADComputer by -Identity sAMAccountName" {
        $dcName = @($PSOpenADSettings.Server -split '\.')[0]
        $actual = Get-OpenADComputer -Session $session -Identity $dcName$
        $actual.Name | Should -Be $dcName
        $actual.SamAccountName | Should -Be "$dcName$"
    }
}
