. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "Add-OpenADGroupMember cmdlet" -Skip:(-not $PSOpenADSettings.Server) {
    BeforeAll {
        $session = New-TestOpenADSession
    }

    AfterAll {
        Get-OpenADSession | Remove-OpenADSession
    }

    BeforeEach {
        $contact = New-OpenADObject -Session $session -Name MyContact -Type contact -PassThru
        $group = New-OpenADObject -Session $session -Name MyGroup -Type group -PassThru
    }

    AfterEach {
        $contact, $group | Remove-OpenADObject -Session $session
    }

    Context "Add-OpenADGroupMember" {
        It "Adds group member" {
            Add-OpenADGroupMember -Session $session -Identity $group.DistinguishedName -Members $contact

            $actual = $group | Get-OpenADObject -Session $session -Property member
            $actual.Member | Should -Be $contact.DistinguishedName
        }

        It "Adds group member through pipeline input" {
            $group | Add-OpenADGroupMember -Session $session -Members $contact

            $actual = $group | Get-OpenADObject -Session $session -Property member
            $actual.Member | Should -Be $contact.DistinguishedName
        }

        It "Fails with non-existing objectGuid -Identity" {
            Add-OpenADGroupMember -Session $session -Identity ([Guid]::Empty) -Members $contact -ErrorAction SilentlyContinue -ErrorVariable err
            $err.Count | Should -Be 1
            [string]$err[0] | Should -Be "Failed to find object to set using the filter '(objectGUID=\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00)'"
        }

        It "Fails with invalid dn -Identity" {
            Add-OpenADGroupMember -Session $session -Identity "CN=Fake" -Members $contact -ErrorAction SilentlyContinue -ErrorVariable err
            $err.Count | Should -Be 1
            [string]$err[0] | Should -BeLike "Failed to modify 'CN=Fake': No such object *"
        }

        It "Runs with -PassThru" {
            $actual1 = $group | Add-OpenADGroupMember -Session $session -Members $contact -PassThru
            $actual2 = $group | Get-OpenADObject -Session $session -Property member

            $actual1.ObjectGuid | Should -Be $actual2.ObjectGuid
            $actual2.Member | Should -Be $contact.DistinguishedName
        }

        It "Runs with -WhatIf" {
            $group | Add-OpenADGroupMember -Session $session -Members $contact -WhatIf

            $actual = $group | Get-OpenADObject -Session $session -Property member
            $actual.Member | Should -BeNullOrEmpty
        }

        It "Runs with -WhatIf and -PassThru" {
            $actual1 = $group | Add-OpenADGroupMember -Session $session -Members $contact -WhatIf -PassThru
            $actual2 = $group | Get-OpenADObject -Session $session -Property member

            $actual1.DistinguishedName | Should -Be $actual2.DistinguishedName
            $actual2.Member | Should -BeNullOrEmpty
        }
    }
}
