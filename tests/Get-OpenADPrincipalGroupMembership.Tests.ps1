. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "Get-OpenADPrincipalGroupMembership cmdlet" -Skip:(-not $PSOpenADSettings.Server) {
    BeforeAll {
        $selectedCred = $PSOpenADSettings.Credentials | Select-Object -First 1
        $cred = [pscredential]::new($selectedCred.Username, $selectedCred.Password)

        $session = New-OpenADSession -ComputerName $PSOpenADSettings.Server -Credential $cred
        $dcName = @($PSOpenADSettings.Server -split '\.')[0]
        $dn = Get-OpenADComputer -Session $session -Identity $dcName | Select-Object -ExpandProperty DistinguishedName
    }

    AfterAll {
        Get-OpenADSession | Remove-OpenADSession
    }

    Context "Get-OpenADPrincipalGroupMembership" {
        It "Finds group" {
            $actual = Get-OpenADPrincipalGroupMembership -Identity $dn -Session $session
            $actual.Count | Should -BeGreaterOrEqual 1
            $actual[0] | Should -BeOfType [PSOpenAD.OpenADGroup]
        }

        # Finding the object's primary group works differently, so test it separately.
        # Use Domain Controllers as it is all DCs' primary group by default
        It "Finds principal's primary group" {
            $actual = Get-OpenADPrincipalGroupMembership -Identity $dn -Session $session
            $actual.name | Should -Contain 'Domain Controllers'
        }

        It "Finds a computer's group membership through pipeline input" {
            $actual = Get-OpenADComputer -Session $session -Identity $dcName |
                Get-OpenADPrincipalGroupMembership -Session $session
            $actual.Count | Should -BeGreaterOrEqual 1
            $actual.name | Should -Contain 'Domain Controllers'
        }

        It "Finds a user's group membership through pipeline input" {
            $actual = Get-OpenADUser -Session $session -Identity 'Administrator' |
                Get-OpenADPrincipalGroupMembership -Session $session
            $actual.Count | Should -BeGreaterOrEqual 1
            $actual.name | Should -Contain 'Administrators'
        }

        It "Finds a group's group membership through pipeline input" {
            $actual = Get-OpenADGroup -Session $session -Identity 'Domain Users' |
                Get-OpenADPrincipalGroupMembership -Session $session
            $actual.Count | Should -BeGreaterOrEqual 1
            $actual.name | Should -Contain 'Users'
        }
        It "Finds an object's group membership through pipeline input" {
            $actual = Get-OpenADObject -Session $session -LDAPFilter '(name=Read-only Domain Controllers)' |
                Get-OpenADPrincipalGroupMembership -Session $session
            $actual.Count | Should -BeGreaterOrEqual 1
            $actual.name | Should -Contain 'Denied RODC Password Replication Group'
        }

        It "Handles principals with no group memberships" {
            $actual = Get-OpenADPrincipalGroupMembership -Session $session -LDAPFilter 'name=Administrators'
            $actual | Should -BeNullOrEmpty
        }

        It "Finds group membership recursively" {
            $standard = Get-OpenADPrincipalGroupMembership -Identity 'Administrator' -Session $session
            $actual = Get-OpenADPrincipalGroupMembership -Identity 'Administrator' -Recursive -Session $session
            $actual.Count | Should -BeGreaterThan $standard.Count
            $actual[0] | Should -BeOfType ([PSOpenAD.OpenADPrincipal])
        }

        It "Finds test user's groups" {
            $user = Get-OpenADUser -Identity 'TestGroupSubMember'
            $actual = $user | Get-OpenADPrincipalGroupMembership -Session $session |
                Sort-Object -Property SamAccountName
            $actual.Count | Should -Be 2

            $actual[0] | Should -BeOfType ([PSOpenAD.OpenADGroup])
            $actual[0].QueriedPrincipal | Should -Be $user.DistinguishedName
            $actual[0].SamAccountName | Should -Be 'Domain Users'
            $actual[0].ObjectClass | Should -Be 'group'

            $actual[1] | Should -BeOfType ([PSOpenAD.OpenADGroup])
            $actual[1].QueriedPrincipal | Should -Be $user.DistinguishedName
            $actual[1].SamAccountName | Should -Be 'TestGroupSub'
            $actual[1].ObjectClass | Should -Be 'group'
        }

        It "Finds test user's groups recursively" {
            $user = Get-OpenADUser -Identity 'TestGroupSubMember'
            $actual = $user | Get-OpenADPrincipalGroupMembership -Recursive -Session $session |
                Sort-Object -Property SamAccountName
            $actual.Count | Should -Be 3

            $actual[0] | Should -BeOfType ([PSOpenAD.OpenADGroup])
            $actual[0].QueriedPrincipal | Should -Be $user.DistinguishedName
            $actual[0].SamAccountName | Should -Be 'Domain Users'
            $actual[0].ObjectClass | Should -Be 'group'

            $actual[1] | Should -BeOfType ([PSOpenAD.OpenADGroup])
            $actual[1].QueriedPrincipal | Should -Be $user.DistinguishedName
            $actual[1].SamAccountName | Should -Be 'TestGroup'
            $actual[1].ObjectClass | Should -Be 'group'

            $actual[2] | Should -BeOfType ([PSOpenAD.OpenADGroup])
            $actual[2].QueriedPrincipal | Should -Be $user.DistinguishedName
            $actual[2].SamAccountName | Should -Be 'TestGroupSub'
            $actual[2].ObjectClass | Should -Be 'group'
        }

        It "Find multiple principals' groups" {
            $groups = Get-OpenADPrincipalGroupMembership -Session $session -LDAPFilter "(|(name=TestGroupMember)(name=$dcName))"
            ($groups | Select-Object -ExpandProperty QueriedPrincipal | Sort-Object -Unique).Count | Should -Be 2
        }
    }
}
