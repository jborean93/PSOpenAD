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

        It "Fails to find entry with identity" {
            $actual = Get-OpenADObject -Session $session -Identity invalid-id -ErrorAction SilentlyContinue -ErrorVariable err
            $actual | Should -BeNullOrEmpty
            $err.Count | Should -Be 1
            $err[0].Exception.Message | Should -BeLike "Cannot find an object with identity filter: '(&(objectClass=*)(distinguishedName=invalid-id))' under: *"
        }

        It "Does not fail if no match on filter" {
            $actual = Get-OpenADObject -Session $session -LDAPFilter '(objectClass=some-invalid-class)'
            $actual | Should -BeNullOrEmpty
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

        It "Requests a property that is not set" {
            $comp = Get-OpenADComputer -Session $session | Select-Object -ExpandProperty DistinguishedName -First 1
            $actual = Get-OpenADComputer -Session $session -Identity $comp -Property operatingSystem
            $actual.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
            $actual.PSObject.Properties.Name | Should -Contain 'Name'
            $actual.PSObject.Properties.Name | Should -Contain 'ObjectClass'
            $actual.PSObject.Properties.Name | Should -Contain 'ObjectGuid'
            $actual.PSObject.Properties.Name | Should -Contain 'DNSHostName'
            $actual.PSObject.Properties.Name | Should -Contain 'Enabled'
            $actual.PSObject.Properties.Name | Should -Contain 'UserPrincipalName'
            $actual.PSObject.Properties.Name | Should -Contain 'SamAccountName'
            $actual.PSObject.Properties.Name | Should -Contain 'SID'
            $actual.DomainController | Should -Be $PSOpenADSettings.Server
            $actual.PSObject.Properties.Name | Should -Contain 'OperatingSystem'
        }

        It "Requests a property that is not valid" {
            {
                Get-OpenADComputer -Session $session -Property sAMAccountName, invalid1, objectSid, invalid2 -ErrorAction Stop
            } | Should -Throw -ExpectedMessage "One or more properties for computer are not valid: 'invalid1', 'invalid2'"
        }

        It "Completes the properties selected" {
            $actual = Complete 'Get-OpenADComputer -Session $session -Property '
            $actual.Count | Should -BeGreaterThan 0
        }

        It "Completes the property with partial name" {
            $actual = Complete 'Get-OpenADComputer -Session $session -Property operating'
            $actual.Count | Should -BeGreaterThan 0
            $actual | ForEach-Object {
                $_.CompletionText -like 'operating*'
            }
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

        It "Requests a property that is not set" {
            $group = Get-OpenADGroup -Session $session | Select-Object -ExpandProperty DistinguishedName -First 1
            $actual = Get-OpenADGroup -Session $session -Identity $group -Property adminCount
            $actual.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
            $actual.PSObject.Properties.Name | Should -Contain 'Name'
            $actual.PSObject.Properties.Name | Should -Contain 'ObjectClass'
            $actual.PSObject.Properties.Name | Should -Contain 'ObjectGuid'
            $actual.PSObject.Properties.Name | Should -Contain 'GroupCategory'
            $actual.PSObject.Properties.Name | Should -Contain 'GroupScope'
            $actual.PSObject.Properties.Name | Should -Contain 'SamAccountName'
            $actual.PSObject.Properties.Name | Should -Contain 'SID'
            $actual.DomainController | Should -Be $PSOpenADSettings.Server
            $actual.PSObject.Properties.Name | Should -Contain 'AdminCount'
        }

        It "Requests a property that is not valid" {
            {
                Get-OpenADGroup -Session $session -Property sAMAccountName, invalid1, objectSid, invalid2 -ErrorAction Stop
            } | Should -Throw -ExpectedMessage "One or more properties for group are not valid: 'invalid1', 'invalid2'"
        }

        It "Completes the properties selected" {
            $actual = Complete 'Get-OpenADGroup -Session $session -Property '
            $actual.Count | Should -BeGreaterThan 0
        }

        It "Completes the property with partial name" {
            $actual = Complete 'Get-OpenADGroup -Session $session -Property msDS'
            $actual.Count | Should -BeGreaterThan 0
            $actual | ForEach-Object {
                $_.CompletionText -like 'msDS*'
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

        It "Requests a property that is not set" {
            $user = Get-OpenADUser -Session $session | Select-Object -ExpandProperty DistinguishedName -First 1
            $actual = Get-OpenADUser -Session $session -Identity $user -Property title
            $actual.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
            $actual.PSObject.Properties.Name | Should -Contain 'Name'
            $actual.PSObject.Properties.Name | Should -Contain 'ObjectClass'
            $actual.PSObject.Properties.Name | Should -Contain 'ObjectGuid'
            $actual.PSObject.Properties.Name | Should -Contain 'GivenName'
            $actual.PSObject.Properties.Name | Should -Contain 'Surname'
            $actual.PSObject.Properties.Name | Should -Contain 'Enabled'
            $actual.PSObject.Properties.Name | Should -Contain 'UserPrincipalName'
            $actual.PSObject.Properties.Name | Should -Contain 'SamAccountName'
            $actual.PSObject.Properties.Name | Should -Contain 'SID'
            $actual.DomainController | Should -Be $PSOpenADSettings.Server
            $actual.PSObject.Properties.Name | Should -Contain 'Title'
            $actual.Title | Should -BeNullOrEmpty
        }

        It "Requests a property that is not valid" {
            {
                Get-OpenADUser -Session $session -Property sAMAccountName, invalid1, objectSid, invalid2 -ErrorAction Stop
            } | Should -Throw -ExpectedMessage "One or more properties for person are not valid: 'invalid1', 'invalid2'"
        }

        It "Completes the properties selected" {
            $actual = Complete 'Get-OpenADUser -Session $session -Property '
            $actual.Count | Should -BeGreaterThan 0
        }

        It "Completes the property with partial name" {
            $actual = Complete 'Get-OpenADUser -Session $session -Property last'
            $actual.Count | Should -BeGreaterThan 0
            $actual | ForEach-Object {
                $_.CompletionText -like 'last*'
            }
        }
    }
}
