. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "Get-OpenADObject cmdlets" -Skip:(-not $PSOpenADSettings.Server) {
    BeforeAll {
        $selectedCred = $PSOpenADSettings.Credentials | Select-Object -First 1
        $cred = [pscredential]::new($selectedCred.Username, $selectedCred.Password)

        $session = New-OpenADSession -ComputerName $PSOpenADSettings.Server -Credential $cred
        $dcName = @($PSOpenADSettings.Server -split '\.')[0]
    }

    AfterAll {
        Get-OpenADSession | Remove-OpenADSession
    }

    Context "Get-OpenADObject" {
        It "Creates session using hostname" {
            Get-OpenADObject -Server $PSOpenADSettings.Server | Out-Null
        }

        It "Creates sessoin using hostname:port" {
            Get-OpenADObject -Server "$($PSOpenADSettings.Server):389" | Out-Null
        }

        It "Fails to create server with invalid hostname:port" {
            $expected = "Expecting server in the format of hostname or hostname:port with port as an integer"
            {
                Get-OpenADObject -Server hostname:port -ErrorAction Stop
            } | Should -Throw -ExceptionType ([ArgumentException]) -ExpectedMessage $expected
        }
    }

    Context "Get-OpenADComputer" {
        It "Finds ADComputer by -Identity sAMAccountName without ending $" {
            $actual = Get-OpenADComputer -Session $session -Identity $dcName
            $actual.Name | Should -Be $dcName
            $actual.SamAccountName | Should -Be "$dcName$"
        }

        It "Finds ADComputer by -Identity sAMAccountName" {
            $actual = Get-OpenADComputer -Session $session -Identity $dcName$
            $actual.Name | Should -Be $dcName
            $actual.SamAccountName | Should -Be "$dcName$"
        }

        It "Finds ADComputer through pipeline input" {
            $actual = $dcName, "$dcName$" | Get-OpenADComputer -Session $session
            $actual.Count | Should -Be 2
            $actual[0] | Should -BeOfType ([PSOpenAD.OpenADComputer])
            $actual[1] | Should -BeOfType ([PSOpenAD.OpenADComputer])
            $actual[0].ObjectGuid | Should -Be $actual[1].ObjectGuid
        }
    }

    Context "Get-OpenADGroup" {
        It "Finds ADGroup through pipeline input" {
            $actual = "Domain Admins", "Domain Users" | Get-OpenADGroup -Session $session
            $actual.Count | Should -Be 2
            $actual[0] | Should -BeOfType ([PSOpenAD.OpenADGroup])
            $actual[1] | Should -BeOfType ([PSOpenAD.OpenADGroup])
        }
    }
}
