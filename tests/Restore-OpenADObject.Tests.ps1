. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "Restore-OpenADObject cmdlets" -Skip:(-not $PSOpenADSettings.Server) {
    BeforeAll {
        $session = New-TestOpenADSession

        Function New-DeletedObject {
            param (
                [string]$Name = "PSOpenADTest-$([Guid]::NewGuid().Guid)",
                [string]$Type = 'container',
                [string]$Path,
                [System.Collections.IDictionary]$OtherAttributes
            )

            $newParams = @{
                Session = $session
                Name = $Name
                Type = $Type
                PassThru = $true
            }
            if ($Path) {
                $newParams.Path = $Path
            }
            if ($OtherAttributes) {
                $newParams.OtherAttributes = $OtherAttributes
            }
            $obj = New-OpenADObject @newParams

            Remove-OpenADObject -Session $session -Identity $obj.ObjectGuid
            Get-OpenADObject -Session $session -Identity $obj.ObjectGuid -ErrorAction SilentlyContinue |
                Should -BeNullOrEmpty

            [PSCustomObject]@{
                Original = $obj
                Deleted = Get-OpenADObject -Session $session -Identity $obj.ObjectGuid -IncludeDeletedObjects
            }
        }
    }

    AfterAll {
        Get-OpenADSession | Remove-OpenADSession
    }

    Context "Restore-OpenADObject" {
        It "Fails when the identity is not a distinguished name" {
            $actual = Restore-OpenADObject -Session $session -Identity ([Guid]::NewGuid()) -ErrorAction SilentlyContinue -ErrorVariable err
            $actual | Should -BeNullOrEmpty
            $err.Count | Should -Be 1
            [string]$err[0].FullyQualifiedErrorId | Should -BeLike 'RestoreOpenADObjectIdentityNotDN*'
        }

        It "Fails to find a deleted object" {
            $dn = "CN=Fake\0ADEL:$([Guid]::NewGuid().Guid),CN=Deleted Objects,$($session.DefaultNamingContext)"
            $actual = Restore-OpenADObject -Session $session -Identity $dn -ErrorAction SilentlyContinue -ErrorVariable err
            $actual | Should -BeNullOrEmpty
            $err.Count | Should -Be 1
            [string]$err[0].FullyQualifiedErrorId | Should -BeLike 'RestoreOpenADObjectNotFound*'
        }

        It "Restores a deleted object - piped" {
            $obj = New-DeletedObject
            $obj.Deleted.DistinguishedName | Should -BeLike '*CN=Deleted Objects,*'

            $actual = $obj.Deleted | Restore-OpenADObject -Session $session
            try {
                $actual | Should -BeNullOrEmpty
                $restored = Get-OpenADObject -Session $session -Identity $obj.Original.ObjectGuid
                $restored.DistinguishedName | Should -Be $obj.Original.DistinguishedName
            }
            finally {
                Remove-OpenADObject -Session $session -Identity $obj.Original.ObjectGuid
            }
        }

        It "Restores a deleted object - DN parameter with PassThru" {
            $obj = New-DeletedObject

            $actual = Restore-OpenADObject -Session $session -Identity $obj.Deleted.DistinguishedName -PassThru
            try {
                $actual | Should -BeOfType ([PSOpenAD.OpenADObject])
                $actual.DistinguishedName | Should -Be $obj.Original.DistinguishedName
                $actual.ObjectGuid | Should -Be $obj.Original.ObjectGuid
            }
            finally {
                Remove-OpenADObject -Session $session -Identity $obj.Original.ObjectGuid
            }
        }

        It "Restores a user with its objectSid" {
            $sam = "PSOpenAD$([Guid]::NewGuid().Guid.Substring(0, 8))"
            $user = New-OpenADObject -Session $session -Name $sam -Type user -OtherAttributes @{ sAMAccountName = $sam } -PassThru
            $sid = (Get-OpenADObject -Session $session -Identity $user.ObjectGuid -Property objectSid).ObjectSid
            Remove-OpenADObject -Session $session -Identity $user.ObjectGuid

            $actual = Get-OpenADObject -Session $session -Identity $user.ObjectGuid -IncludeDeletedObjects |
                Restore-OpenADObject -Session $session -PassThru
            try {
                $actual.DistinguishedName | Should -Be $user.DistinguishedName
                $restored = Get-OpenADObject -Session $session -Identity $user.ObjectGuid -Property objectSid
                $restored.ObjectSid | Should -Be $sid
            }
            finally {
                Remove-OpenADObject -Session $session -Identity $user.ObjectGuid
            }
        }

        It "Restores a name that needs escaping" {
            $obj = New-DeletedObject -Name "PSOpenADTest, Restore (1) $([Guid]::NewGuid().Guid)"

            $actual = $obj.Deleted | Restore-OpenADObject -Session $session -PassThru
            try {
                $actual.DistinguishedName | Should -Be $obj.Original.DistinguishedName
                $actual.Name | Should -Be $obj.Original.Name
            }
            finally {
                Remove-OpenADObject -Session $session -Identity $obj.Original.ObjectGuid
            }
        }

        It "Restores an organizational unit as an OU" {
            $obj = New-DeletedObject -Type organizationalUnit

            $actual = $obj.Deleted | Restore-OpenADObject -Session $session -PassThru
            try {
                $actual.DistinguishedName | Should -BeLike 'OU=*'
                $actual.DistinguishedName | Should -Be $obj.Original.DistinguishedName
            }
            finally {
                Remove-OpenADObject -Session $session -Identity $obj.Original.ObjectGuid
            }
        }

        It "Restores into a different container with -TargetPath" {
            $target = New-OpenADObject -Session $session -Name "PSOpenADTest-$([Guid]::NewGuid().Guid)" -Type container -PassThru
            try {
                $obj = New-DeletedObject

                $actual = $obj.Deleted | Restore-OpenADObject -Session $session -TargetPath $target.DistinguishedName -PassThru
                $actual.DistinguishedName | Should -Be "CN=$($obj.Original.Name),$($target.DistinguishedName)"

                Remove-OpenADObject -Session $session -Identity $obj.Original.ObjectGuid
            }
            finally {
                Remove-OpenADObject -Session $session -Identity $target.ObjectGuid
            }
        }

        It "Restores under a different name with -NewName" {
            $obj = New-DeletedObject
            $newName = "PSOpenADTest-$([Guid]::NewGuid().Guid)"

            $actual = $obj.Deleted | Restore-OpenADObject -Session $session -NewName $newName -PassThru
            try {
                $actual.Name | Should -Be $newName
                $actual.ObjectGuid | Should -Be $obj.Original.ObjectGuid
            }
            finally {
                Remove-OpenADObject -Session $session -Identity $obj.Original.ObjectGuid
            }
        }

        It "Fails to restore into a container that does not exist" {
            $obj = New-DeletedObject
            $target = "CN=Missing-$([Guid]::NewGuid().Guid),$($session.DefaultNamingContext)"

            $actual = $obj.Deleted | Restore-OpenADObject -Session $session -TargetPath $target -ErrorAction SilentlyContinue -ErrorVariable err
            $actual | Should -BeNullOrEmpty
            $err.Count | Should -Be 1
            [string]$err[0].FullyQualifiedErrorId | Should -BeLike 'RestoreOpenADObjectFailure*'
            $err[0].Exception.Message | Should -BeLike "Failed to restore '*'*"

            Get-OpenADObject -Session $session -Identity $obj.Original.ObjectGuid -ErrorAction SilentlyContinue |
                Should -BeNullOrEmpty
        }

        It "Restores with -WhatIf" {
            $obj = New-DeletedObject

            $actual = $obj.Deleted | Restore-OpenADObject -Session $session -WhatIf -PassThru
            $actual | Should -BeNullOrEmpty
            Get-OpenADObject -Session $session -Identity $obj.Original.ObjectGuid -ErrorAction SilentlyContinue |
                Should -BeNullOrEmpty
        }
    }
}
