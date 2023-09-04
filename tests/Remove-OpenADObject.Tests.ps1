. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "Remove-OpenADObject cmdlets" -Skip:(-not $PSOpenADSettings.Server) {
    BeforeAll {
        $selectedCred = $PSOpenADSettings.Credentials | Select-Object -First 1
        $cred = [pscredential]::new($selectedCred.Username, $selectedCred.Password)

        $session = New-OpenADSession -ComputerName $PSOpenADSettings.Server -Credential $cred
        $dcName = @($PSOpenADSettings.Server -split '\.')[0]
    }

    AfterAll {
        Get-OpenADSession | Remove-OpenADSession
    }

    Context "Remove-OpenADObject" {
        It "Fails to find by GUID" {
            $actual = Remove-OpenADObject -Identity ([Guid]::Empty) -ErrorAction SilentlyContinue -ErrorVariable err
            $actual | Should -BeNullOrEmpty
            $err.Count | Should -Be 1
            $err[0].Exception.Message | Should -BeLike "Failed to find object for deletion with the filter '(objectGUID=*)'"
        }

        It "Fails to find by OU" {
            $actual = Remove-OpenADObject -Identity 'CN=Fake,DC=fake,DC=test' -ErrorAction SilentlyContinue -ErrorVariable err
            $actual | Should -BeNullOrEmpty
            $err.Count | Should -Be 1
            $err[0].Exception.Message | Should -BeLike "Failed to delete 'CN=Fake,DC=fake,DC=test': *"
        }

        It "Removes by GUID - parameter" {
            $obj = New-OpenADObject -Name "PSOpenADTest-$([Guid]::NewGuid().Guid)" -Type container -PassThru
            Remove-OpenADObject -Identity $obj.ObjectGuid
            Get-OpenADObject -Identity $obj.ObjectGuid -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }

        It "Removes by GUID - piped" {
            $obj = New-OpenADObject -Name "PSOpenADTest-$([Guid]::NewGuid().Guid)" -Type container -PassThru
            $obj.ObjectGuid | Remove-OpenADObject
            Get-OpenADObject -Identity $obj.ObjectGuid -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }

        It "Removes by DN - parameter" {
            $obj = New-OpenADObject -Name "PSOpenADTest-$([Guid]::NewGuid().Guid)" -Type container -PassThru
            Remove-OpenADObject -Identity $obj.DistinguishedName
            Get-OpenADObject -Identity $obj.ObjectGuid -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }

        It "Removes by DN - piped" {
            $obj = New-OpenADObject -Name "PSOpenADTest-$([Guid]::NewGuid().Guid)" -Type container -PassThru
            $obj.DistinguishedName | Remove-OpenADObject
            Get-OpenADObject -Identity $obj.ObjectGuid -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }

        It "Removes by OpenADObject - parameter" {
            $obj = New-OpenADObject -Name "PSOpenADTest-$([Guid]::NewGuid().Guid)" -Type container -PassThru
            Remove-OpenADObject -Identity $obj
            Get-OpenADObject -Identity $obj.ObjectGuid -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }

        It "Removes by OpenADObject - piped" {
            $obj = New-OpenADObject -Name "PSOpenADTest-$([Guid]::NewGuid().Guid)" -Type container -PassThru
            $obj | Remove-OpenADObject
            Get-OpenADObject -Identity $obj.ObjectGuid -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }

        It "Removes with -WhatIf" {
            $obj = New-OpenADObject -Name "PSOpenADTest-$([Guid]::NewGuid().Guid)" -Type container -PassThru
            try {
                $obj | Remove-OpenADObject -WhatIf
                Get-OpenADObject -Identity $obj.ObjectGuid | Should -Not -BeNullOrEmpty
            }
            finally {
                $obj | Remove-OpenADObject
            }
        }
    }
}
