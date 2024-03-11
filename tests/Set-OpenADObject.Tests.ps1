. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "Set-OpenADObject cmdlets" -Skip:(-not $PSOpenADSettings.Server) {
    BeforeAll {
        $session = New-TestOpenADSession
    }

    AfterAll {
        Get-OpenADSession | Remove-OpenADSession
    }

    BeforeEach {
        $contact = New-OpenADObject -Name MyContact -Type contact -Session $session -PassThru
    }

    AfterEach {
        $contact | Remove-OpenADObject -Session $session
    }

    It "Adds property value" {
        $contact | Set-OpenADObject -Session $session -Add @{
            psopenadStringSingle = 'value'
            psopenadStringMulti = 1, 'abc'
        }
        $actual = $contact | Get-OpenADObject -Session $session -Property psopenadStringSingle, psopenadStringMulti
        $actual.PsopenadStringSingle | Should -Be value
        $actual.PsopenadStringMulti.Count | Should -Be 2
        $actual.PsopenadStringMulti[0] | Should -Be 1
        $actual.PsopenadStringMulti[1] | Should -Be abc

        $contact | Set-OpenADObject -Session $session -Add @{
            psopenadStringMulti = 'def', '2'
        }
        $actual = $contact | Get-OpenADObject -Session $session -Property psopenadStringMulti
        $actual.PsopenadStringMulti.Count | Should -Be 4
        $actual.PsopenadStringMulti[0] | Should -Be 1
        $actual.PsopenadStringMulti[1] | Should -Be abc
        $actual.PsopenadStringMulti[2] | Should -Be def
        $actual.PsopenadStringMulti[3] | Should -Be 2
    }

    It "Replaces property value" {
        $contact | Set-OpenADObject -Session $session -Replace @{
            psopenadStringSingle = 'value'
            psopenadStringMulti = 1, 'abc'
        }
        $actual = $contact | Get-OpenADObject -Session $session -Property psopenadStringSingle, psopenadStringMulti
        $actual.PsopenadStringSingle | Should -Be value
        $actual.PsopenadStringMulti.Count | Should -Be 2
        $actual.PsopenadStringMulti[0] | Should -Be 1
        $actual.PsopenadStringMulti[1] | Should -Be abc

        $contact | Set-OpenADObject -Session $session -Replace @{
            psopenadStringSingle = 'bar'
            psopenadStringMulti = 'def', '2'
        }
        $actual = $contact | Get-OpenADObject -Session $session -Property psopenadStringSingle, psopenadStringMulti
        $actual.PsopenadStringSingle | Should -Be bar
        $actual.PsopenadStringMulti.Count | Should -Be 2
        $actual.PsopenadStringMulti[0] | Should -Be def
        $actual.PsopenadStringMulti[1] | Should -Be 2
    }

    It "Sets boolean values" {
        $contact | Set-OpenADObject -Session $session -Replace @{
            psopenadBoolSingle = $false
            psopenadBoolMulti = $true, $false
        }
        $actual = $contact | Get-OpenADObject -Session $session -Property psopenadBoolSingle, psopenadBoolMulti
        $actual.PsopenadBoolSingle | Should -BeFalse
        $actual.PsopenadBoolMulti.Count | Should -Be 2
        $actual.PsopenadBoolMulti[0] | Should -BeTrue
        $actual.PsopenadBoolMulti[1] | Should -BeFalse

        $contact | Set-OpenADObject -Session $session -Replace @{
            psopenadBoolSingle = $true
            psopenadBoolMulti = $false, $true
        }
        $actual = $contact | Get-OpenADObject -Session $session -Property psopenadBoolSingle, psopenadBoolMulti
        $actual.PsopenadBoolSingle | Should -BeTrue
        $actual.PsopenadBoolMulti.Count | Should -Be 2
        $actual.PsopenadBoolMulti[0] | Should -BeFalse
        $actual.PsopenadBoolMulti[1] | Should -BeTrue
    }

    It "Sets bytes values" {
        $raw1 = [byte[]]@(1, 2, 3, 4)
        $raw2 = [byte[]]@(5, 6, 7, 8)
        $raw3 = [byte[]]@(9, 10, 11, 12)
        $contact | Set-OpenADObject -Session $session -Replace @{
            psopenadBytesSingle = $raw1
            psopenadBytesMulti = $raw2, $raw3
        }
        $actual = $contact | Get-OpenADObject -Session $session -Property psopenadBytesSingle, psopenadBytesMulti
        [Convert]::ToHexString($actual.PsopenadBytesSingle) | Should -Be 01020304
        $actual.PsopenadBytesMulti.Count | Should -Be 2
        [Convert]::ToHexString($actual.PsopenadBytesMulti[0]) | Should -Be 05060708
        [Convert]::ToHexString($actual.PsopenadBytesMulti[1]) | Should -Be 090A0B0C

        $contact | Set-OpenADObject -Session $session -Replace @{
            psopenadBytesSingle = $raw3
            psopenadBytesMulti = $raw2, $raw1
        }
        $actual = $contact | Get-OpenADObject -Session $session -Property psopenadBytesSingle, psopenadBytesMulti
        [Convert]::ToHexString($actual.PsopenadBytesSingle) | Should -Be 090A0B0C
        $actual.PsopenadBytesMulti.Count | Should -Be 2
        [Convert]::ToHexString($actual.PsopenadBytesMulti[0]) | Should -Be 05060708
        [Convert]::ToHexString($actual.PsopenadBytesMulti[1]) | Should -Be 01020304
    }

    It "Sets DateTime values" {
        # While it should accept TZ offsets and fractions I cannot get it to work with Samba
        $dt1 = [DateTimeOffset]::new([DateTime]::new(1970, 1, 1), 0)
        $dt2 = [DateTimeOffset]::new([DateTime]::new(2024, 3, 13, 10, 49, 12), 0)
        $dt3 = [DateTimeOffset]::new([DateTime]::new(1985, 10, 1, 23, 32, 10), 0)

        $contact | Set-OpenADObject -Session $session -Replace @{
            psopenadDateTimeSingle = '19700101000000.0Z'
            psopenadDateTimeMulti = '20240313104912.0Z', '19851001233210.0Z'
        }
        $actual = $contact | Get-OpenADObject -Session $session -Property psopenadDateTimeSingle, psopenadDateTimeMulti
        $actual.PsopenadDateTimeSingle | Should -Be $dt1
        $actual.PsopenadDateTimeMulti.Count | Should -Be 2
        $actual.PsopenadDateTimeMulti[0] | Should -Be $dt2
        $actual.PsopenadDateTimeMulti[1] | Should -Be $dt3

        $contact | Set-OpenADObject -Session $session -Replace @{
            psopenadDateTimeSingle = '19851001233210.0Z'
            psopenadDateTimeMulti = '19700101000000.0Z', '20240313104912.0Z'
        }
        $actual = $contact | Get-OpenADObject -Session $session -Property psopenadDateTimeSingle, psopenadDateTimeMulti
        $actual.PsopenadDateTimeSingle | Should -Be $dt3
        $actual.PsopenadDateTimeMulti.Count | Should -Be 2
        $actual.PsopenadDateTimeMulti[0] | Should -Be $dt1
        $actual.PsopenadDateTimeMulti[1] | Should -Be $dt2
    }

    It "Sets integer values" {
        $contact | Set-OpenADObject -Session $session -Replace @{
            psopenadIntSingle = 1
            psopenadIntMulti = 2, 3
        }
        $actual = $contact | Get-OpenADObject -Session $session -Property psopenadIntSingle, psopenadIntMulti
        $actual.PsopenadIntSingle | Should -Be 1
        $actual.PsopenadIntMulti.Count | Should -Be 2
        $actual.PsopenadIntMulti[0] | Should -Be 2
        $actual.PsopenadIntMulti[1] | Should -Be 3

        $contact | Set-OpenADObject -Session $session -Replace @{
            psopenadIntSingle = 4
            psopenadIntMulti = 5, 6
        }
        $actual = $contact | Get-OpenADObject -Session $session -Property psopenadIntSingle, psopenadIntMulti
        $actual.PsopenadIntSingle | Should -Be 4
        $actual.PsopenadIntMulti.Count | Should -Be 2
        $actual.PsopenadIntMulti[0] | Should -Be 5
        $actual.PsopenadIntMulti[1] | Should -Be 6
    }

    It "Sets SD values" {
        $sd1 = [PSOpenAD.Security.CommonSecurityDescriptor]@{
            Owner = [PSOpenAD.Security.SecurityIdentifier]::new('S-1-5-18')
        }
        $sd2 = [PSOpenAD.Security.CommonSecurityDescriptor]@{
            Owner = [PSOpenAD.Security.SecurityIdentifier]::new('S-1-5-19')
        }
        $sd3 = [PSOpenAD.Security.CommonSecurityDescriptor]@{
            Owner = [PSOpenAD.Security.SecurityIdentifier]::new('S-1-5-20')
        }

        $contact | Set-OpenADObject -Session $session -Replace @{
            psopenadSDSingle = $sd1
            psopenadSDMulti = $sd2, $sd3
        }
        $actual = $contact | Get-OpenADObject -Session $session -Property psopenadSDSingle, psopenadSDMulti
        $actual.PsopenadSDSingle.Owner | Should -Be 'S-1-5-18'
        $actual.PsopenadSDMulti.Count | Should -Be 2
        $actual.PsopenadSDMulti[0].Owner | Should -Be 'S-1-5-19'
        $actual.PsopenadSDMulti[1].Owner | Should -Be 'S-1-5-20'

        $contact | Set-OpenADObject -Session $session -Replace @{
            psopenadSDSingle = $sd3
            psopenadSDMulti = $sd1, $sd2
        }
        $actual = $contact | Get-OpenADObject -Session $session -Property psopenadSDSingle, psopenadSDMulti
        $actual.PsopenadSDSingle.Owner | Should -Be 'S-1-5-20'
        $actual.PsopenadSDMulti.Count | Should -Be 2
        $actual.PsopenadSDMulti[0].Owner | Should -Be 'S-1-5-18'
        $actual.PsopenadSDMulti[1].Owner | Should -Be 'S-1-5-19'
    }

    It "Removes property value" {
        $contact | Set-OpenADObject -Session $session -Replace @{
            psopenadStringSingle = 'value'
            psopenadStringMulti = 1, 'abc', 'def'
        }

        $contact | Set-OpenADObject -Session $session -Remove @{
            psopenadStringSingle = 'value'
            psopenadStringMulti = 1, 'abc'
        }
        $actual = $contact | Get-OpenADObject -Session $session -Property psopenadStringSingle, psopenadStringMulti
        $actual.PsopenadStringSingle | Should -BeNullOrEmpty
        $actual.PsopenadStringMulti.Count | Should -Be 1
        $actual.PsopenadStringMulti[0] | Should -Be def
    }

    It "Clears property value" {
        $contact | Set-OpenADObject -Session $session -Replace @{
            psopenadStringSingle = 'value'
            psopenadStringMulti = 1, 'abc', 'def'
        }

        $contact | Set-OpenADObject -Session $session -Clear psopenadStringSingle, psopenadStringMulti, psopenadIntSingle
        $actual = $contact | Get-OpenADObject -Session $session -Property psopenadStringSingle, psopenadStringMulti
        $actual.PsopenadStringSingle | Should -BeNullOrEmpty
        $actual.PsopenadStringMulti | Should -BeNullOrEmpty
    }

    It "Clears a property in -Replace" {
        $contact | Set-OpenADObject -Session $session -Replace @{
            psopenadStringSingle = 'value'
            psopenadStringMulti = 1, 'abc', 'def'
        } -Clear psopenadStringMulti

        $actual = $contact | Get-OpenADObject -Session $session -Property psopenadStringSingle, psopenadStringMulti
        $actual.PsopenadStringSingle | Should -Be value
        $actual.PsopenadStringMulti | Should -BeNullOrEmpty
    }

    It "Adds, Removes, Replaces, and Clears at the same time" {
        $contact | Set-OpenADObject -Session $session -Replace @{
            psopenadStringMulti = 'abc', 'def', 'ghi'
            psopenadIntMulti = 1, 2, 3
            psopenadBoolMulti = $true, $false
            psopenadBytesMulti = [byte[]]@(1, 2, 3, 4)
        }
        $setParams = @{
            Session = $session
            Remove = @{
                psopenadStringMulti = 'def'
                psopenadIntMulti = 2, 3
                psopenadBytesMulti = [byte[]]@(1, 2, 3, 4)
            }
            Add = @{
                psopenadStringMulti = 'jkl', 'def'
                psopenadIntMulti = 4
            }
            Replace = @{
                psopenadBoolMulti = $true
                psopenadBytesMulti = [byte[]]@(5, 6, 7)
            }
            Clear = 'psopenadBoolMulti'
        }
        $contact | Set-OpenADObject @setParams

        $actual = $contact | Get-OpenADObject -Session $session -Property @(
            'psopenadStringMulti',
            'psopenadIntMulti',
            'psopenadBoolMulti',
            'psopenadBytesMulti'
        )
        $actual.psopenadStringMulti.Count | Should -Be 4
        $actual.psopenadStringMulti[0] | Should -Be abc
        $actual.psopenadStringMulti[1] | Should -Be ghi
        $actual.psopenadStringMulti[2] | Should -Be jkl
        $actual.psopenadStringMulti[3] | Should -Be def

        $actual.psopenadIntMulti.Count | Should -Be 2
        $actual.psopenadIntMulti[0] | Should -Be 1
        $actual.psopenadIntMulti[1] | Should -Be 4

        $actual.psopenadBoolMulti | Should -BeNullOrEmpty

        $actual.psopenadBytesMulti.Count | Should -Be 1
        $actual.psopenadBytesMulti[0].Count | Should -Be 3
        $actual.psopenadBytesMulti[0][0] | Should -Be 5
        $actual.psopenadBytesMulti[0][1] | Should -Be 6
        $actual.psopenadBytesMulti[0][2] | Should -Be 7
    }

    It "Sets DisplayName" {
        $contact | Set-OpenADObject -Session $session -DisplayName 'New Display Name'

        $actual = $contact | Get-OpenADObject -Session $session -Property displayName
        $actual.DisplayName | Should -Be 'New Display Name'
    }

    It "Favours add/remove/set displayName over parameter" {
        $contact | Set-OpenADObject -Session $session -DisplayName DP1 -Replace @{ displayName = 'DP2' }

        $actual = $contact | Get-OpenADObject -Session $session -Property displayName
        $actual.DisplayName | Should -Be DP2
    }

    It "Sets Description" {
        $contact | Set-OpenADObject -Session $session -Description 'New Description'

        $actual = $contact | Get-OpenADObject -Session $session -Property description
        $actual.Description | Should -Be 'New Description'
    }

    It "Favours add/remove/set description over parameter" {
        $contact | Set-OpenADObject -Session $session -Description desc1 -Replace @{ description = 'desc2' }

        $actual = $contact | Get-OpenADObject -Session $session -Property description
        $actual.Description | Should -Be desc2
    }

    It "Uses OpenADEntity as Identity" {
        Set-OpenADObject -Session $session -Identity $contact -DisplayName 'New Display Name'

        $actual = $contact | Get-OpenADObject -Session $session -Property displayName
        $actual.DisplayName | Should -Be 'New Display Name'
    }

    It "Uses distinguishedName as Identity" {
        Set-OpenADObject -Session $session -Identity $contact.DistinguishedName -DisplayName 'New Display Name'

        $actual = $contact | Get-OpenADObject -Session $session -Property displayName
        $actual.DisplayName | Should -Be 'New Display Name'
    }

    It "Uses objectGuid as Identity" {
        Set-OpenADObject -Session $session -Identity $contact.ObjectGuid -DisplayName 'New Display Name'

        $actual = $contact | Get-OpenADObject -Session $session -Property displayName
        $actual.DisplayName | Should -Be 'New Display Name'
    }

    It "Pipes in identity guid" {
        $contact.ObjectGuid | Set-OpenADObject -Session $session -DisplayName 'New Display Name'

        $actual = $contact | Get-OpenADObject -Session $session -Property displayName
        $actual.DisplayName | Should -Be 'New Display Name'
    }

    It "Pipes in identity guid as string" {
        $contact.ObjectGuid.ToString() | Set-OpenADObject -Session $session -DisplayName 'New Display Name'

        $actual = $contact | Get-OpenADObject -Session $session -Property displayName
        $actual.DisplayName | Should -Be 'New Display Name'
    }

    It "Pipes in identity distinguishedName" {
        $contact.DistinguishedName | Set-OpenADObject -Session $session -DisplayName 'New Display Name'

        $actual = $contact | Get-OpenADObject -Session $session -Property displayName
        $actual.DisplayName | Should -Be 'New Display Name'
    }

    It "Fails with non-existing objectGuid -Identity" {
        Set-OpenADObject -Session $session -Identity ([Guid]::Empty) -ErrorAction SilentlyContinue -ErrorVariable err
        $err.Count | Should -Be 1
        [string]$err[0] | Should -Be "Failed to find object to set using the filter '(objectGUID=\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00)'"
    }

    It "Fails with invalid dn -Identity" {
        Set-OpenADObject -Session $session -Identity "CN=Fake" -Description desc -ErrorAction SilentlyContinue -ErrorVariable err
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike "Failed to modify 'CN=Fake': No such object *"
    }

    It "Writes error with empty property key" {
        $contact | Set-OpenADObject -Session $session -Description desc -Replace @{
            '' = 'desc2'
            displayName = 'foo'
        } -ErrorAction SilentlyContinue -ErrorVariable err

        $err.Count | Should -Be 1
        [string]$err[0] | Should -Be '-Replace key must not be empty/whitespace, skipping entry'

        $actual = $contact | Get-OpenADObject -Session $session -Property description, displayName
        $actual.Description | Should -Be desc
        $actual.DisplayName | Should -Be foo
    }

    It "Sets with -PassThru" {
        $actual1 = $contact | Set-OpenADObject -Session $session -DisplayName 'New Display Name' -PassThru
        $actual2 = $contact | Get-OpenADObject -Session $session -Property displayName

        $actual1.ObjectGuid | Should -Be $actual2.ObjectGuid
        $actual1.DisplayName | Should -Be 'New Display Name'
        $actual2.DisplayName | Should -Be 'New Display Name'
    }

    It "Runs with -WhatIf" {
        $contact | Set-OpenADObject -Session $session -DisplayName 'New Display Name' -WhatIf

        $actual = $contact | Get-OpenADObject -Session $session -Property displayName
        $actual.DisplayName | Should -BeNullOrEmpty
    }

    It "Runs with -WhatIf and -PassThru" {
        $actual1 = $contact | Set-OpenADObject -Session $session -DisplayName 'New Display Name' -WhatIf -PassThru
        $actual2 = $contact | Get-OpenADObject -Session $session -Property displayName

        $actual1.DistinguishedName | Should -Be $actual2.DistinguishedName
        $actual1.ObjectGuid | Should -Be ([Guid]::Empty)
        $actual2.DisplayName | Should -BeNullOrEmpty
    }
}
