. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "Move-OpenADObject cmdlets" -Skip:(-not $PSOpenADSettings.Server) {
    BeforeAll {
        $session = New-TestOpenADSession
        $container = (New-OpenADObject -Session $session -Name "PSOpenAD-Test-$([Guid]::NewGuid().Guid)" -Type container -PassThru).DistinguishedName
        $sub1 = (New-OpenADOBject -Session $session -Name "Container1" -Type container -Path $container -PassThru).DistinguishedName
        $sub2 = (New-OpenADOBject -Session $session -Name "Container2" -Type container -Path $container -PassThru).DistinguishedName
    }

    AfterAll {
        if ($container) {
            Get-OpenADObject -Session $session -LDAPFilter '(objectClass=*)' -SearchBase $container |
                Sort-Object -Property { $_.DistinguishedName.Length } -Descending |
                Remove-OpenADObject -Session $session
        }
        Get-OpenADSession | Remove-OpenADSession
    }

    Context "Move-OpenADObject" {
        It "Move normal object by -Identity DN" {
            $obj = New-OpenADObject -Session $session -Name ParamByDN -Path $sub1 -Type container -PassThru

            Move-OpenADObject -Session $session -Identity $obj.DistinguishedName -TargetPath $sub2

            $obj = Get-OpenADObject -Session $session -Identity $obj.ObjectGuid
            $obj | Should -Not -BeNullOrEmpty
            $obj.DistinguishedName | Should -Be "CN=ParamByDN,$sub2"
        }

        It "Moves normal object by -Identity ObjectGuid" {
            $obj = New-OpenADObject -Session $session -Name ParamByGuid -Path $sub1 -Type container -PassThru

            Move-OpenADObject -Session $session -Identity $obj.ObjectGuid -TargetPath $sub2

            $obj = Get-OpenADObject -Session $session -Identity $obj.ObjectGuid
            $obj | Should -Not -BeNullOrEmpty
            $obj.DistinguishedName | Should -Be "CN=ParamByGuid,$sub2"
        }

        It "Moves normal object by -Identity OpenADObject" {
            $obj = New-OpenADObject -Session $session -Name ParamByObj -Path $sub1 -Type container -PassThru

            Move-OpenADObject -Session $session -Identity $obj -TargetPath $sub2

            $obj = Get-OpenADObject -Session $session -Identity $obj.ObjectGuid
            $obj | Should -Not -BeNullOrEmpty
            $obj.DistinguishedName | Should -Be "CN=ParamByObj,$sub2"
        }

        It "Moves normal object by pipeline" {
            $obj = New-OpenADObject -Session $session -Name PipelineObj -Path $sub1 -Type container -PassThru

            $obj | Move-OpenADObject -Session $session -TargetPath $sub2

            $obj = Get-OpenADObject -Session $session -Identity $obj.ObjectGuid
            $obj | Should -Not -BeNullOrEmpty
            $obj.DistinguishedName | Should -Be "CN=PipelineObj,$sub2"
        }

        It "Moves object with complex name" {
            $obj = New-OpenADObject -Session $session -Name '#Test=Obj\With,Complex+Name ' -Path $sub1 -Type container -PassThru

            $obj | Move-OpenADObject -Session $session -TargetPath $sub2

            $obj = Get-OpenADObject -Session $session -Identity $obj.ObjectGuid
            $obj | Should -Not -BeNullOrEmpty
            $obj.Name | Should -Be '#Test=Obj\With,Complex+Name '
            $obj.DistinguishedName | Should -Be "CN=\#Test\3DObj\\With\,Complex\+Name\ ,$sub2"
        }

        It "Moves with -PassThru" {
            $obj = New-OpenADObject -Session $session -Name PassThruObj -Path $sub1 -Type container -PassThru

            $actual = $obj | Move-OpenADObject -Session $session -TargetPath $sub2 -PassThru

            $obj = Get-OpenADObject -Session $session -Identity $obj.ObjectGuid
            $obj | Should -Not -BeNullOrEmpty
            $obj.DistinguishedName | Should -Be "CN=PassThruObj,$sub2"
            $actual.DistinguishedName | Should -Be $obj.DistinguishedName
            $actual.ObjectGuid | Should -Be $obj.ObjectGuid
        }

        It "Moves with -WhatIf" {
            $obj = New-OpenADObject -Session $session -Name WhatIfObj -Path $sub1 -Type container -PassThru

            $obj | Move-OpenADObject -Session $session -TargetPath $sub2 -WhatIf

            $obj = Get-OpenADObject -Session $session -Identity $obj.ObjectGuid
            $obj | Should -Not -BeNullOrEmpty
            $obj.DistinguishedName | Should -Be "CN=WhatIfObj,$sub1"
        }

        It "Moves with -WhatIf -PassThru" {
            $obj = New-OpenADObject -Session $session -Name WhatIfPassThruObj -Path $sub1 -Type container -PassThru

            $actual = $obj | Move-OpenADObject -Session $session -TargetPath $sub2 -WhatIf -PassThru

            $obj = Get-OpenADObject -Session $session -Identity $obj.ObjectGuid
            $obj | Should -Not -BeNullOrEmpty
            $obj.DistinguishedName | Should -Be "CN=WhatIfPassThruObj,$sub1"

            $actual.DistinguishedName | Should -Be "CN=WhatIfPassThruObj,$sub2"
            $actual.ObjectGuid | Should -Be ([Guid]::Empty)
        }

        It "Fails with non-existing objectGuid -Identity" {
            Move-OpenADObject -Session $session -Identity ([Guid]::Empty) -TargetPath $sub1 -ErrorAction SilentlyContinue -ErrorVariable err
            $err.Count | Should -Be 1
            [string]$err[0] | Should -Be "Failed to find object to set using the filter '(objectGUID=\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00)'"
        }

        It "Fails with invalid dn -Identity" {
            Move-OpenADObject -Session $session -Identity "CN=Fake" -TargetPath 'CN=Foo,DC=domain' -ErrorAction SilentlyContinue -ErrorVariable err
            $err.Count | Should -Be 1
            [string]$err[0] | Should -BeLike "Failed to modify DN 'CN=Fake'->'CN=Fake,CN=Foo,DC=domain': *"
        }
    }
}
