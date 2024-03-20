. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "Rename-OpenADObject cmdlets" -Skip:(-not $PSOpenADSettings.Server) {
    BeforeAll {
        $session = New-TestOpenADSession
        $container = (New-OpenADObject -Session $session -Name "PSOpenAD-Test-$([Guid]::NewGuid().Guid)" -Type container -PassThru).DistinguishedName
    }

    AfterAll {
        if ($container) {
            Get-OpenADObject -Session $session -LDAPFilter '(objectClass=*)' -SearchBase $container |
                Sort-Object -Property { $_.DistinguishedName.Length } -Descending |
                Remove-OpenADObject -Session $session
        }
        Get-OpenADSession | Remove-OpenADSession
    }

    Context "Rename-OpenADObject" {
        It "Renames normal object by -Identity DN" {
            $obj = New-OpenADObject -Session $session -Name ParamByDN -Path $container -Type container -PassThru

            Rename-OpenADObject -Session $session -Identity $obj.DistinguishedName -NewName ParamByDN2

            $obj = Get-OpenADObject -Session $session -Identity $obj.ObjectGuid
            $obj | Should -Not -BeNullOrEmpty
            $obj.Name | Should -Be ParamByDN2
            $obj.DistinguishedName | Should -Be "CN=ParamByDN2,$container"
        }

        It "Renames normal object by -Identity ObjectGuid" {
            $obj = New-OpenADObject -Session $session -Name ParamByGuid -Path $container -Type container -PassThru

            Rename-OpenADObject -Session $session -Identity $obj.ObjectGuid -NewName ParamByGuid2

            $obj = Get-OpenADObject -Session $session -Identity $obj.ObjectGuid
            $obj | Should -Not -BeNullOrEmpty
            $obj.Name | Should -Be ParamByGuid2
            $obj.DistinguishedName | Should -Be "CN=ParamByGuid2,$container"
        }

        It "Renames normal object by -Identity OpenADObject" {
            $obj = New-OpenADObject -Session $session -Name ParamByObj -Path $container -Type container -PassThru

            Rename-OpenADObject -Session $session -Identity $obj -NewName ParamByObj2

            $obj = Get-OpenADObject -Session $session -Identity $obj.ObjectGuid
            $obj | Should -Not -BeNullOrEmpty
            $obj.Name | Should -Be ParamByObj2
            $obj.DistinguishedName | Should -Be "CN=ParamByObj2,$container"
        }

        It "Renames normal object by pipeline" {
            $obj = New-OpenADObject -Session $session -Name PipelineObj -Path $container -Type container -PassThru

            $obj | Rename-OpenADObject -Session $session -NewName { "$($_.Name)2" }

            $obj = Get-OpenADObject -Session $session -Identity $obj.ObjectGuid
            $obj | Should -Not -BeNullOrEmpty
            $obj.Name | Should -Be PipelineObj2
            $obj.DistinguishedName | Should -Be "CN=PipelineObj2,$container"
        }

        It "Renames object with OU DN type" {
            $obj = New-OpenADObject -Session $session -Name OUObj -Type organizationalUnit -PassThru
            try {
                $obj | Rename-OpenADObject -Session $session -NewName OUObjNewName

                $obj = Get-OpenADObject -Session $session -Identity $obj.ObjectGuid
                $obj | Should -Not -BeNullOrEmpty
                $obj.Name | Should -Be OUObjNewName
                $obj.DistinguishedName | Should -Be "OU=OUObjNewName,$($session.DefaultNamingContext)"
            }
            finally {
                $obj | Remove-OpenADObject -Session $session
            }
        }

        It "Renames object with complex name" {
            $obj = New-OpenADObject -Session $session -Name '#Test=Obj\With,Complex+Name ' -Path $container -Type container -PassThru

            $obj | Rename-OpenADObject -Session $session -NewName { "$($_.Name)2 " }

            $obj = Get-OpenADObject -Session $session -Identity $obj.ObjectGuid
            $obj | Should -Not -BeNullOrEmpty
            $obj.Name | Should -Be '#Test=Obj\With,Complex+Name 2 '
            $obj.DistinguishedName | Should -Be "CN=\#Test\3DObj\\With\,Complex\+Name 2\ ,$container"
        }

        It "Renames with -PassThru" {
            $obj = New-OpenADObject -Session $session -Name PassThruObj -Path $container -Type container -PassThru

            $actual = $obj | Rename-OpenADObject -Session $session -NewName PassThruObj2 -PassThru

            $obj = Get-OpenADObject -Session $session -Identity $obj.ObjectGuid
            $obj | Should -Not -BeNullOrEmpty
            $obj.Name | Should -Be PassThruObj2
            $obj.DistinguishedName | Should -Be "CN=PassThruObj2,$container"
            $actual.DistinguishedName | Should -Be $obj.DistinguishedName
            $actual.ObjectGuid | Should -Be $obj.ObjectGuid
        }

        It "Renames with -WhatIf" {
            $obj = New-OpenADObject -Session $session -Name WhatIfObj -Path $container -Type container -PassThru

            $obj | Rename-OpenADObject -Session $session -NewName WhatIfObj2 -WhatIf

            $obj = Get-OpenADObject -Session $session -Identity $obj.ObjectGuid
            $obj | Should -Not -BeNullOrEmpty
            $obj.Name | Should -Be WhatIfObj
            $obj.DistinguishedName | Should -Be "CN=WhatIfObj,$container"
        }

        It "Renames with -WhatIf -PassThru" {
            $obj = New-OpenADObject -Session $session -Name WhatIfPassThruObj -Path $container -Type container -PassThru

            $actual = $obj | Rename-OpenADObject -Session $session -NewName WhatIfPassThruObj2 -WhatIf -PassThru

            $obj = Get-OpenADObject -Session $session -Identity $obj.ObjectGuid
            $obj | Should -Not -BeNullOrEmpty
            $obj.Name | Should -Be WhatIfPassThruObj
            $obj.DistinguishedName | Should -Be "CN=WhatIfPassThruObj,$container"

            $actual.DistinguishedName | Should -Be "CN=WhatIfPassThruObj2,$container"
            $actual.Name | Should -Be WhatIfPassThruObj2
            $actual.ObjectGuid | Should -Be ([Guid]::Empty)
        }

        It "Fails with non-existing objectGuid -Identity" {
            Rename-OpenADObject -Session $session -Identity ([Guid]::Empty) -NewName test -ErrorAction SilentlyContinue -ErrorVariable err
            $err.Count | Should -Be 1
            [string]$err[0] | Should -Be "Failed to find object to set using the filter '(objectGUID=\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00)'"
        }

        It "Fails with invalid dn -Identity" {
            Rename-OpenADObject -Session $session -Identity "CN=Fake" -NewName test -ErrorAction SilentlyContinue -ErrorVariable err
            $err.Count | Should -Be 1
            [string]$err[0] | Should -BeLike "Failed to modify DN 'CN=Fake'->'CN=test': *"
        }
    }
}
