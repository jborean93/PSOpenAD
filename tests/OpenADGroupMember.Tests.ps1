. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "Get-OpenADGroupMember cmdlet" -Skip:(-not $PSOpenADSettings.Server) {
    BeforeAll {
        $selectedCred = $PSOpenADSettings.Credentials | Select-Object -First 1
        $cred = [pscredential]::new($selectedCred.Username, $selectedCred.Password)

        $session = New-OpenADSession -ComputerName $PSOpenADSettings.Server -Credential $cred
        $dcName = @($PSOpenADSettings.Server -split '\.')[0]
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
                $_.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
                $_.PSObject.Properties.Name | Should -Contain 'Name'
                $_.PSObject.Properties.Name | Should -Contain 'ObjectClass'
                $_.PSObject.Properties.Name | Should -Contain 'ObjectGuid'
                $_.PSObject.Properties.Name | Should -Contain 'SamAccountName'
                $_.PSObject.Properties.Name | Should -Contain 'SID'
                $_.DomainController | Should -Be $PSOpenADSettings.Server
            }
        }

        It "Finds group members through pipeline input" {
            $actual = "Administrators" | Get-OpenADGroupMember -Session $session
            $actual.Count | Should -Be 3
            $actual[0] | Should -BeOfType ([PSOpenAD.OpenADPrincipal])

            $actual | ForEach-Object {
                $_.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
                $_.PSObject.Properties.Name | Should -Contain 'Name'
                $_.PSObject.Properties.Name | Should -Contain 'ObjectClass'
                $_.PSObject.Properties.Name | Should -Contain 'ObjectGuid'
                $_.PSObject.Properties.Name | Should -Contain 'SamAccountName'
                $_.PSObject.Properties.Name | Should -Contain 'SID'
                $_.DomainController | Should -Be $PSOpenADSettings.Server
            }
        }
        It "Finds group members recursively" {
            $actual = Get-OpenADGroupMember -Identity 'Administrators' -Recursive -Session $session
            $actual.Count | Should -Be 1
            $actual[0] | Should -BeOfType ([PSOpenAD.OpenADPrincipal])

            $actual | ForEach-Object {
                $_.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
                $_.PSObject.Properties.Name | Should -Contain 'Name'
                $_.PSObject.Properties.Name | Should -Contain 'ObjectClass'
                $_.PSObject.Properties.Name | Should -Contain 'ObjectGuid'
                $_.PSObject.Properties.Name | Should -Contain 'SamAccountName'
                $_.PSObject.Properties.Name | Should -Contain 'SID'
                $_.DomainController | Should -Be $PSOpenADSettings.Server
            }
        }



        It "Requests a property that is not set" {
            $actual = Get-OpenADGroupMember -Session $session -Identity 'Administrators' -Property adminCount | Select-Object -First 1
            $actual.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
            $actual.PSObject.Properties.Name | Should -Contain 'Name'
            $actual.PSObject.Properties.Name | Should -Contain 'ObjectClass'
            $actual.PSObject.Properties.Name | Should -Contain 'ObjectGuid'
            $actual.PSObject.Properties.Name | Should -Contain 'SamAccountName'
            $actual.PSObject.Properties.Name | Should -Contain 'SID'
            $actual.DomainController | Should -Be $PSOpenADSettings.Server
            $actual.PSObject.Properties.Name | Should -Contain 'AdminCount'
        }

        It "Requests a property that is not valid" {
            {
                Get-OpenADGroupMember -Identity 'Administrators' -Session $session -Property sAMAccountName, invalid1, objectSid, invalid2 -ErrorAction Stop
            } | Should -Throw -ExpectedMessage "One or more properties for 'top' class are not valid: 'invalid1', 'invalid2'"
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
    }
}
