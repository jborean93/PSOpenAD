. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "Get-OpenADObject cmdlets" -Skip:(-not $PSOpenADSettings.Server) {
    BeforeAll {
        $selectedCred = $PSOpenADSettings.Credentials | Select-Object -First 1
        $cred = [pscredential]::new($selectedCred.Username, $selectedCred.Password)

        $session = New-OpenADSession -ComputerName $PSOpenADSettings.Server -Credential $cred
    }

    AfterAll {
        Get-OpenADSession | Remove-OpenADSession
    }

    Context "Get-OpenADRootDSE" {
        It "Gets default properties" {
            $actual = Get-OpenADRootDSE
            $actual | Should -BeOfType ([PSOpenAD.OpenADEntity])
            $actual.PSObject.Properties.Name | Should -Contain 'ConfigurationNamingContext'
            $actual.PSObject.Properties.Name | Should -Contain 'CurrentTime'
            $actual.PSObject.Properties.Name | Should -Contain 'DefaultNamingContext'
            $actual.PSObject.Properties.Name | Should -Contain 'DnsHostName'
            $actual.PSObject.Properties.Name | Should -Contain 'DomainControllerFunctionality'
            $actual.PSObject.Properties.Name | Should -Contain 'DomainFunctionality'
            $actual.PSObject.Properties.Name | Should -Contain 'DsServiceName'
            $actual.PSObject.Properties.Name | Should -Contain 'ForestFunctionality'
            $actual.PSObject.Properties.Name | Should -Contain 'HighestCommittedUSN'
            $actual.PSObject.Properties.Name | Should -Contain 'IsGlobalCatalogReady'
            $actual.PSObject.Properties.Name | Should -Contain 'IsSynchronized'
            $actual.PSObject.Properties.Name | Should -Contain 'LdapServiceName'
            $actual.PSObject.Properties.Name | Should -Contain 'NamingContexts'
            $actual.PSObject.Properties.Name | Should -Contain 'RootDomainNamingContext'
            $actual.PSObject.Properties.Name | Should -Contain 'SchemaNamingContext'
            $actual.PSObject.Properties.Name | Should -Contain 'ServerName'
            $actual.PSObject.Properties.Name | Should -Contain 'SubschemaSubentry'
            $actual.PSObject.Properties.Name | Should -Contain 'SupportedCapabilities'
            $actual.PSObject.Properties.Name | Should -Contain 'SupportedControl'
            $actual.PSObject.Properties.Name | Should -Contain 'SupportedLDAPPolicies'
            $actual.PSObject.Properties.Name | Should -Contain 'SupportedLDAPVersion'
            $actual.PSObject.Properties.Name | Should -Contain 'SupportedSASLMechanisms'
            $actual.DomainController | Should -Be $PSOpenADSettings.Server
        }

        It "Gets extra properties" {
            $actual = Get-OpenADRootDSE -Property supportedExtension
            $actual | Should -BeOfType ([PSOpenAD.OpenADEntity])
            $actual.PSObject.Properties.Name | Should -Contain 'ConfigurationNamingContext'
            $actual.PSObject.Properties.Name | Should -Contain 'CurrentTime'
            $actual.PSObject.Properties.Name | Should -Contain 'DefaultNamingContext'
            $actual.PSObject.Properties.Name | Should -Contain 'DnsHostName'
            $actual.PSObject.Properties.Name | Should -Contain 'DomainControllerFunctionality'
            $actual.PSObject.Properties.Name | Should -Contain 'DomainFunctionality'
            $actual.PSObject.Properties.Name | Should -Contain 'DsServiceName'
            $actual.PSObject.Properties.Name | Should -Contain 'ForestFunctionality'
            $actual.PSObject.Properties.Name | Should -Contain 'HighestCommittedUSN'
            $actual.PSObject.Properties.Name | Should -Contain 'IsGlobalCatalogReady'
            $actual.PSObject.Properties.Name | Should -Contain 'IsSynchronized'
            $actual.PSObject.Properties.Name | Should -Contain 'LdapServiceName'
            $actual.PSObject.Properties.Name | Should -Contain 'NamingContexts'
            $actual.PSObject.Properties.Name | Should -Contain 'RootDomainNamingContext'
            $actual.PSObject.Properties.Name | Should -Contain 'SchemaNamingContext'
            $actual.PSObject.Properties.Name | Should -Contain 'ServerName'
            $actual.PSObject.Properties.Name | Should -Contain 'SubschemaSubentry'
            $actual.PSObject.Properties.Name | Should -Contain 'SupportedCapabilities'
            $actual.PSObject.Properties.Name | Should -Contain 'SupportedControl'
            $actual.PSObject.Properties.Name | Should -Contain 'SupportedLDAPPolicies'
            $actual.PSObject.Properties.Name | Should -Contain 'SupportedLDAPVersion'
            $actual.PSObject.Properties.Name | Should -Contain 'SupportedSASLMechanisms'
            $actual.PSObject.Properties.Name | Should -Contain 'SupportedExtension'
            $actual.DomainController | Should -Be $PSOpenADSettings.Server

            # Samba doesn't return this value so will be $null
            if ($actual.SupportedExtension) {
                $actual.SupportedExtension | ForEach-Object {
                    $_ | Should -BeOfType ([System.Security.Cryptography.Oid])
                    $_.ToString() | Should -BeLike '* (*)'
                }
            }
        }
    }
}
