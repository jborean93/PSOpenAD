. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "New-OpenADObject cmdlets" -Skip:(-not $PSOpenADSettings.Server) {
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

    Context "New-OpenADObject" {
        It "Creates object without -PassThru" {
            $actual = New-OpenADObject -Session $session -Name "NoPassThru" -Path $container -Type container
            $actual | Should -BeNullOrEmpty

            $obj = Get-OpenADObject -Session $session -Identity "CN=NoPassThru,$container"
            $obj | Should -Not -BeNullOrEmpty
            $obj.ObjectClass | Should -Be container
        }

        It "Creates object with -PassThru" {
            $actual = New-OpenADObject -Session $session -Name "PassThru" -Path $container -Type container -PassThru
            $actual | Should -BeOfType ([PSOpenAD.OpenADObject])
            $actual.DistinguishedName | Should -Be "CN=PassThru,$container"
            $actual.ObjectClass | Should -Be container

            $obj = Get-OpenADObject -Session $session -Identity "CN=PassThru,$container"
            $obj | Should -Not -BeNullOrEmpty
            $obj.ObjectGuid | Should -Be $actual.ObjectGuid
            $obj.ObjectClass | Should -Be container
        }

        It "Creates organizationalUnit object" {
            $actual = New-OpenADObject -Session $session -Name "OUTest" -Type organizationalUnit -PassThru
            try {
                $domainDN = $container.Substring(54)
                $actual | Should -BeOfType ([PSOpenAD.OpenADObject])
                $actual.DistinguishedName | Should -Be "OU=OUTest,$domainDN"
                $actual.ObjectClass | Should -Be organizationalUnit

                $obj = Get-OpenADObject -Session $session -Identity "OU=OUTest,$domainDN"
                $obj | Should -Not -BeNullOrEmpty
                $obj.ObjectGuid | Should -Be $actual.ObjectGuid
                $obj.ObjectClass | Should -Be organizationalUnit
            }
            finally {
                $actual | Remove-OpenADObject -Session $session
            }
        }

        It "Creates object with description" {
            $actual = New-OpenADObject -Session $session -Name "With Description" -Description 'test desc' -Path $container -Type container -PassThru
            $actual | Should -BeOfType ([PSOpenAD.OpenADObject])
            $actual.DistinguishedName | Should -Be "CN=With Description,$container"
            $actual.ObjectClass | Should -Be container
            $actual.Description | Should -Be 'test desc'

            $obj = Get-OpenADObject -Session $session -Identity "CN=With Description,$container" -Property description
            $obj | Should -Not -BeNullOrEmpty
            $obj.ObjectGuid | Should -Be $actual.ObjectGuid
            $obj.ObjectClass | Should -Be container
            $obj.Description | Should -Be 'test desc'
        }

        It "Creates object with display name" {
            $actual = New-OpenADObject -Session $session -Name "With Display Name" -DisplayName 'test display name' -Path $container -Type container -PassThru
            $actual | Should -BeOfType ([PSOpenAD.OpenADObject])
            $actual.DistinguishedName | Should -Be "CN=With Display Name,$container"
            $actual.ObjectClass | Should -Be container
            $actual.DisplayName | Should -Be 'test display name'

            $obj = Get-OpenADObject -Session $session -Identity "CN=With Display Name,$container" -Property displayName
            $obj | Should -Not -BeNullOrEmpty
            $obj.ObjectGuid | Should -Be $actual.ObjectGuid
            $obj.ObjectClass | Should -Be container
            $obj.DisplayName | Should -Be 'test display name'
        }

        It "Creates object with -WhatIf" {
            $actual = New-OpenADObject -Session $session -Name "WhatIf" -Path $container -Type container -WhatIf
            $actual | Should -BeNullOrEmpty

            Get-OpenADObject -Session $session -Identity "CN=WhatIf,$container" -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }

        It "Creates object with -WhatIf and -PassThru" {
            $actual = New-OpenADObject -Session $session -Name "WhatIf+PassThru" -Path $container -Type container -WhatIf -PassThru
            $actual | Should -BeOfType ([PSOpenAD.OpenADObject])
            $actual.DistinguishedName | Should -Be "CN=WhatIf\+PassThru,$container"
            $actual.ObjectClass | Should -Be container
            $actual.ObjectGuid | Should -Be ([Guid]::Empty)

            Get-OpenADObject -Session $session -Identity "CN=WhatIf\+PassThru,$container" -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }

        It "Creates user with extra attributes" {
            $newParams = @{
                Name = 'My+User<123>'
                Type = 'user'
                Path = $container
                OtherAttributes = @{
                    sAMAccountName = 'MyUser'
                    # It is important the password string is surrounded by the double quotes
                    unicodePwd = [System.Text.Encoding]::Unicode.GetBytes('"Password123!"')
                    givenName = 'First Name'
                    sn = 'Last Name'
                    userAccountControl = [PSOpenAD.UserAccountControl]::NormalAccount
                }
                PassThru = $true
            }
            $actual = New-OpenADObject -Session $session @newParams
            $actual | Should -BeOfType ([PSOpenAD.OpenADObject])
            $actual.DistinguishedName | Should -Be "CN=My\+User\<123\>,$container"
            $actual.ObjectClass | Should -Be user
            $actual.SAMAccountName | Should -Be 'MyUser'
            $actual.GivenName | Should -Be 'First Name'
            $actual.Sn | Should -Be 'Last Name'

            $obj = Get-OpenADObject -Session $session -Identity $actual.DistinguishedName -Property sAMAccountName, givenName, sn, userAccountControl
            $obj | Should -Not -BeNullOrEmpty
            $obj.ObjectGuid | Should -Be $actual.ObjectGuid
            $obj.ObjectClass | Should -Be user
            $obj.SAMAccountName | Should -Be MyUser
            $obj.GivenName | Should -Be 'First Name'
            $obj.Sn | Should -Be 'Last Name'
            $obj.UserAccountControl | Should -Be ([PSOpenAD.UserAccountControl]::NormalAccount)
        }

        It "Creates container with extra attributes" {
            $newParams = @{
                Name = "My`nContainer"
                Type = 'container'
                Path = $container
                OtherAttributes = @{
                    showInAdvancedViewOnly = $true
                }
                PassThru = $true
            }
            $actual = New-OpenADObject -Session $session @newParams
            $actual | Should -BeOfType ([PSOpenAD.OpenADObject])
            $actual.DistinguishedName | Should -Be "CN=My\0AContainer,$container"
            $actual.ObjectClass | Should -Be container
            $actual.ShowInAdvancedViewOnly | Should -BeTrue

            $obj = Get-OpenADObject -Session $session -Identity $actual.DistinguishedName -Property showInAdvancedViewOnly
            $obj | Should -Not -BeNullOrEmpty
            $obj.ObjectGuid | Should -Be $actual.ObjectGuid
            $obj.ObjectClass | Should -Be container
            $obj.ShowInAdvancedViewOnly | Should -BeTrue
        }

        It "Emits error with attribute key being null/empty" {
            $newParams = @{
                Name = '#Sub Container '
                Type = 'container'
                Path = $container
                OtherAttributes = @{
                    '' = 'fail'
                }
                PassThru = $true
                ErrorAction = 'SilentlyContinue'
                ErrorVariable = 'err'
            }
            $actual = New-OpenADObject -Session $session @newParams
            $actual | Should -BeOfType ([PSOpenAD.OpenADObject])
            $actual.DistinguishedName | Should -Be "CN=\#Sub Container\ ,$container"
            $actual.ObjectClass | Should -Be container
            $err.Count | Should -Be 1
            $err[0].Exception.Message | Should -BeLike "OtherAttributes key '' must not be empty/whitespace or declared multiple times"

            $obj = Get-OpenADObject -Session $session -Identity $actual.DistinguishedName
            $obj | Should -Not -BeNullOrEmpty
            $obj.ObjectGuid | Should -Be $actual.ObjectGuid
            $obj.ObjectClass | Should -Be container
        }

        It "Emits error when attempting to create a bad object" {
            $actual = New-OpenADObject -Session $session -Name TestFail -Type invalidType -ErrorAction SilentlyContinue -ErrorVariable err -PassThru
            $actual | Should -BeNullOrEmpty
            $err.Count | Should -Be 1
            $err[0].Exception.Message | Should -BeLike "Failed to add 'CN=TestFail,*': *"
        }
    }
}
