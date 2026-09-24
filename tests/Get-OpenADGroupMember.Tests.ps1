. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "Get-OpenADGroupMember cmdlet" -Skip:(-not $PSOpenADSettings.Server) {
    BeforeAll {
        $session = New-TestOpenADSession
    }

    AfterAll {
        Get-OpenADSession | Remove-OpenADSession
    }

    Context "Get-OpenADGroupMember" {
        It "Finds group members" {
            $actual = Get-OpenADGroupMember -Identity 'Administrators' -Session $session
            $actual.Count | Should -Be 3
            $actual[0] | Should -BeOfType ([PSOpenAD.OpenADPrincipal])

            $actual | ForEach-Object {
                $_.PSObject.Properties.Name | Should -Contain 'QueriedGroup'
                $_.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
                $_.PSObject.Properties.Name | Should -Contain 'Name'
                $_.PSObject.Properties.Name | Should -Contain 'ObjectClass'
                $_.PSObject.Properties.Name | Should -Contain 'ObjectGuid'
                $_.PSObject.Properties.Name | Should -Contain 'SamAccountName'
                $_.PSObject.Properties.Name | Should -Contain 'SID'
                $_.DomainController | Should -Be $session.DomainController
            }
        }

        # Finding the objects with a group as their primary group works differently, so test it separately.
        # Use Domain Controllers as it is all DCs' primary group by default, and unlikely to have other members.
        It "Finds group members in their primary group" {
            $actual = Get-OpenADGroupMember -Identity 'Domain Controllers' -Session $session
            $actual.Count | Should -Be 1
            $actual[0] | Should -BeOfType ([PSOpenAD.OpenADPrincipal])

            $actual | ForEach-Object {
                $_.PSObject.Properties.Name | Should -Contain 'QueriedGroup'
                $_.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
                $_.PSObject.Properties.Name | Should -Contain 'Name'
                $_.PSObject.Properties.Name | Should -Contain 'ObjectClass'
                $_.PSObject.Properties.Name | Should -Contain 'ObjectGuid'
                $_.PSObject.Properties.Name | Should -Contain 'SamAccountName'
                $_.PSObject.Properties.Name | Should -Contain 'SID'
                $_.DomainController | Should -Be $session.DomainController
            }
        }

        It "Finds group members through pipeline input" {
            $actual = "Administrators" | Get-OpenADGroupMember -Session $session
            $actual.Count | Should -Be 3
            $actual[0] | Should -BeOfType ([PSOpenAD.OpenADPrincipal])

            $actual | ForEach-Object {
                $_.PSObject.Properties.Name | Should -Contain 'QueriedGroup'
                $_.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
                $_.PSObject.Properties.Name | Should -Contain 'Name'
                $_.PSObject.Properties.Name | Should -Contain 'ObjectClass'
                $_.PSObject.Properties.Name | Should -Contain 'ObjectGuid'
                $_.PSObject.Properties.Name | Should -Contain 'SamAccountName'
                $_.PSObject.Properties.Name | Should -Contain 'SID'
                $_.DomainController | Should -Be $session.DomainController
            }
        }

        It "Finds group members recursively" {
            $actual = Get-OpenADGroupMember -Identity 'Administrators' -Recursive -Session $session
            $actual.Count | Should -Be 1
            $actual[0] | Should -BeOfType ([PSOpenAD.OpenADPrincipal])

            $actual | ForEach-Object {
                $_.PSObject.Properties.Name | Should -Contain 'QueriedGroup'
                $_.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
                $_.PSObject.Properties.Name | Should -Contain 'Name'
                $_.PSObject.Properties.Name | Should -Contain 'ObjectClass'
                $_.PSObject.Properties.Name | Should -Contain 'ObjectGuid'
                $_.PSObject.Properties.Name | Should -Contain 'SamAccountName'
                $_.PSObject.Properties.Name | Should -Contain 'SID'
                $_.DomainController | Should -Be $session.DomainController
            }
        }

        It "Finds test group" {
            $group = Get-OpenADGroup -Identity 'TestGroup' -Session $session
            $actual = $group | Get-OpenADGroupMember -Session $session |
                Sort-Object -Property SamAccountName
            $actual.Count | Should -Be 2

            $actual[0] | Should -BeOfType ([PSOpenAD.OpenADPrincipal])
            $actual[0].QueriedGroup | Should -Be $group.DistinguishedName
            $actual[0].SamAccountName | Should -Be 'TestGroupMember'
            $actual[0].ObjectClass | Should -Be 'user'

            $actual[1] | Should -BeOfType ([PSOpenAD.OpenADPrincipal])
            $actual[1].QueriedGroup | Should -Be $group.DistinguishedName
            $actual[1].SamAccountName | Should -Be 'TestGroupSub'
            $actual[1].ObjectClass | Should -Be 'group'
        }

        It "Finds members of a group with parentheses in its name" {
            $group = Get-OpenADGroup -Identity 'TestGroupParen (G1)' -Session $session
            $group.DistinguishedName | Should -BeLike 'CN=TestGroupParen (G1),*'

            $actual = $group | Get-OpenADGroupMember -Session $session
            $actual.Count | Should -Be 1
            $actual[0] | Should -BeOfType ([PSOpenAD.OpenADPrincipal])
            $actual[0].QueriedGroup | Should -Be $group.DistinguishedName
            $actual[0].SamAccountName | Should -Be 'TestParenMember (E1234)'
            $actual[0].DistinguishedName | Should -BeLike 'CN=TestParenMember (E1234),*'

            $recursive = $group | Get-OpenADGroupMember -Recursive -Session $session
            $recursive.Count | Should -Be 1
            $recursive[0].SamAccountName | Should -Be 'TestParenMember (E1234)'
        }

        It "Finds test group recursively" {
            $group = Get-OpenADGroup -Identity 'TestGroup' -Session $session
            $actual = $group | Get-OpenADGroupMember -Recursive -Session $session |
                Sort-Object -Property SamAccountName
            $actual.Count | Should -Be 2

            $actual[0] | Should -BeOfType ([PSOpenAD.OpenADPrincipal])
            $actual[0].QueriedGroup | Should -Be $group.DistinguishedName
            $actual[0].SamAccountName | Should -Be 'TestGroupMember'
            $actual[0].ObjectClass | Should -Be 'user'

            $actual[1] | Should -BeOfType ([PSOpenAD.OpenADPrincipal])
            $actual[1].QueriedGroup | Should -Be $group.DistinguishedName
            $actual[1].SamAccountName | Should -Be 'TestGroupSubMember'
            $actual[1].ObjectClass | Should -Be 'user'
        }

        It "Requests a property that is not set" {
            $actual = Get-OpenADGroupMember -Session $session -Identity 'Administrators' -Property adminCount | Select-Object -First 1
            $actual.PSObject.Properties.Name | Should -Contain 'QueriedGroup'
            $actual.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
            $actual.PSObject.Properties.Name | Should -Contain 'Name'
            $actual.PSObject.Properties.Name | Should -Contain 'ObjectClass'
            $actual.PSObject.Properties.Name | Should -Contain 'ObjectGuid'
            $actual.PSObject.Properties.Name | Should -Contain 'SamAccountName'
            $actual.PSObject.Properties.Name | Should -Contain 'SID'
            $actual.DomainController | Should -Be $session.DomainController
            $actual.PSObject.Properties.Name | Should -Contain 'AdminCount'
        }

        It "Requests a property that is not valid" {
            {
                Get-OpenADGroupMember -Identity 'Administrators' -Session $session -Property sAMAccountName, invalid1, objectSid, invalid2 -ErrorAction Stop
            } | Should -Throw -ExpectedMessage "One or more properties for person are not valid: 'invalid1', 'invalid2'"
        }

        It "Does not error on empty group" {
            $actual = Get-OpenADGroupMember -Identity 'TestGroupEmpty' -Session $session
            $actual | Should -BeNullOrEmpty
        }

        It "Errors when group is not found" {
            {
                Get-OpenADGroupMember -Identity 'ThisGroupDoesNotExist' -Session $session -ErrorAction Stop
            } | Should -Throw -ExpectedMessage "Cannot find an object with identity filter '(&(objectCategory=group)(sAMAccountName=ThisGroupDoesNotExist))' under search base '*' with scope Subtree"
        }

        It "Completes the properties selected" {
            $actual = Complete 'Get-OpenADGroupMember -Identity "Administrators" -Session $session -Property '
            $actual.Count | Should -BeGreaterThan 0
        }

        It "Completes the property with partial name" {
            $actual = Complete 'Get-OpenADGroupMember -Identity "Administrators" -Session $session -Property msDS'
            $actual.Count | Should -BeGreaterThan 0
            $actual | ForEach-Object {
                $_.CompletionText -like 'msDS*'
            }
        }

        # A contact is a valid group member and has no objectSid, so the member
        # has to come back with a null SID rather than failing the whole command.
        It "Returns a member that has no objectSid" {
            $contact = New-OpenADObject -Session $session -Name MemberNoSid -Type contact -PassThru
            $group = New-OpenADObject -Session $session -Name GroupWithContact -Type group -PassThru -OtherAttributes @{
                sAMAccountName = 'GroupWithContact'
                member = @($contact.DistinguishedName)
            }
            try {
                $actual = @(Get-OpenADGroupMember -Session $session -Identity GroupWithContact)

                $actual.Count | Should -Be 1
                $actual[0].Name | Should -Be MemberNoSid
                $actual[0].ObjectClass | Should -Be contact
                $actual[0].SID | Should -BeNullOrEmpty
            }
            finally {
                $group | Remove-OpenADObject -Session $session
                $contact | Remove-OpenADObject -Session $session
            }
        }
    }
}
