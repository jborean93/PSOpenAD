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
            $actual = Get-OpenADObject -Server $PSOpenADSettings.Server
            $actual | ForEach-Object {
                $_.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
                $_.PSObject.Properties.Name | Should -Contain 'Name'
                $_.PSObject.Properties.Name | Should -Contain 'ObjectClass'
                $_.PSObject.Properties.Name | Should -Contain 'ObjectGuid'
                $_.DomainController | Should -Be $PSOpenADSettings.Server
            }
        }

        It "Creates session using hostname:port" {
            Get-OpenADObject -Server "$($PSOpenADSettings.Server):389" | Out-Null
        }

        It "Fails to create server with invalid hostname:port" {
            $expected = "Expecting server in the format of hostname or hostname:port with port as an integer"
            {
                Get-OpenADObject -Server hostname:port -ErrorAction Stop
            } | Should -Throw -ExceptionType ([ArgumentException]) -ExpectedMessage $expected
        }

        It "Uses default ldap filter with -SearchBase" {
            $allObjects = Get-OpenADObject -Session $session
            $searchObjects = Get-OpenADObject -Session $session -SearchBase $session.DefaultNamingContext

            $allObjects.Count | Should -Be $searchObjects.Count
        }
    }

    Context "Get-OpenADComputer" {
        It "Finds ADComputer by -Identity sAMAccountName without ending $" {
            $actual = Get-OpenADComputer -Session $session -Identity $dcName
            $actual.Name | Should -Be $dcName
            $actual.SamAccountName | Should -Be "$dcName$"

            $actual | ForEach-Object {
                $_.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
                $_.PSObject.Properties.Name | Should -Contain 'Name'
                $_.PSObject.Properties.Name | Should -Contain 'ObjectClass'
                $_.PSObject.Properties.Name | Should -Contain 'ObjectGuid'
                $_.PSObject.Properties.Name | Should -Contain 'DNSHostName'
                $_.PSObject.Properties.Name | Should -Contain 'Enabled'
                $_.PSObject.Properties.Name | Should -Contain 'UserPrincipalName'
                $_.PSObject.Properties.Name | Should -Contain 'SamAccountName'
                $_.PSObject.Properties.Name | Should -Contain 'SID'
                $_.DomainController | Should -Be $PSOpenADSettings.Server
            }
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

        It "Uses default ldap filter with -SearchBase" {
            $allObjects = Get-OpenADComputer -Session $session
            $searchObjects = Get-OpenADComputer -Session $session -SearchBase $session.DefaultNamingContext

            $allObjects.Count | Should -Be $searchObjects.Count
        }
    }

    Context "Get-OpenADGroup" {
        It "Finds ADGroup through pipeline input" {
            $actual = "Domain Admins", "Domain Users" | Get-OpenADGroup -Session $session
            $actual.Count | Should -Be 2
            $actual[0] | Should -BeOfType ([PSOpenAD.OpenADGroup])
            $actual[1] | Should -BeOfType ([PSOpenAD.OpenADGroup])

            $actual | ForEach-Object {
                $_.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
                $_.PSObject.Properties.Name | Should -Contain 'Name'
                $_.PSObject.Properties.Name | Should -Contain 'ObjectClass'
                $_.PSObject.Properties.Name | Should -Contain 'ObjectGuid'
                $_.PSObject.Properties.Name | Should -Contain 'GroupCategory'
                $_.PSObject.Properties.Name | Should -Contain 'GroupScope'
                $_.PSObject.Properties.Name | Should -Contain 'SamAccountName'
                $_.PSObject.Properties.Name | Should -Contain 'SID'
                $_.DomainController | Should -Be $PSOpenADSettings.Server
            }
        }
    }

    Context "Get-OpenADUser" {
        It "Finds ADUser" {
            $actual = Get-OpenADUser -Session $session
            $actual | ForEach-Object {
                $_.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
                $_.PSObject.Properties.Name | Should -Contain 'Name'
                $_.PSObject.Properties.Name | Should -Contain 'ObjectClass'
                $_.PSObject.Properties.Name | Should -Contain 'ObjectGuid'
                $_.PSObject.Properties.Name | Should -Contain 'GivenName'
                $_.PSObject.Properties.Name | Should -Contain 'Surname'
                $_.PSObject.Properties.Name | Should -Contain 'Enabled'
                $_.PSObject.Properties.Name | Should -Contain 'UserPrincipalName'
                $_.PSObject.Properties.Name | Should -Contain 'SamAccountName'
                $_.PSObject.Properties.Name | Should -Contain 'SID'
                $_.DomainController | Should -Be $PSOpenADSettings.Server
            }
        }

        It "Uses default ldap filter with -SearchBase" {
            $allObjects = Get-OpenADGroup -Session $session
            $searchObjects = Get-OpenADGroup -Session $session -SearchBase $session.DefaultNamingContext

            $allObjects.Count | Should -Be $searchObjects.Count
        }
    }
}
