. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "New-OpenADSession over LDAP" -Skip:(-not $PSOpenADSettings.Server) {
    It "Creates a session using default credentials - <AuthType>" -Skip:(-not $PSOpenADSettings.DefaultCredsAvailable) -TestCases @(
        @{ AuthType = 'Negotiate' }
        @{ AuthType = 'Kerberos' }
    ) {
        param ([string]$AuthType)

        $s = New-OpenADSession -ComputerName $PSOpenADSettings.Server -AuthType $AuthType
        try {
            $s.IsClosed | Should -BeFalse
        }
        finally {
            $s | Remove-OpenADSession
        }
    }

    It "Creates session using explicit username - <AuthType>" -Skip:(-not $PSOpenADSettings.DefaultCredsAvailable) -TestCases @(
        @{ AuthType = 'Negotiate' }
        @{ AuthType = 'Kerberos' }
    ) {
        param ([string]$AuthType)

        $selectedCred = $PSOpenADSettings.Credentials | Where-Object Cached -Eq $true | Select-Object -First 1
        $cred = [pscredential]::new($selectedCred.Username, [securestring]::new())

        $s = New-OpenADSession -ComputerName $PSOpenADSettings.Server -AuthType $AuthType -Credential $cred
        try {
            $s.IsClosed | Should -BeFalse
        }
        finally {
            $s | Remove-OpenADSession
        }
    }

    It "Creates session using explicit username and password - <AuthType>" -TestCases @(
        @{ AuthType = 'Negotiate' }
        @{ AuthType = 'Kerberos' }
    ) {
        param ([string]$AuthType)

        $selectedCred = $PSOpenADSettings.Credentials | Select-Object -First 1
        $cred = [pscredential]::new($selectedCred.Username, $selectedCred.Password)

        $s = New-OpenADSession -ComputerName $PSOpenADSettings.Server -AuthType $AuthType -Credential $cred
        try {
            $s.IsClosed | Should -BeFalse
        }
        finally {
            $s | Remove-OpenADSession
        }
    }
}

Describe "New-OpenADSession over StartTLS" -Skip:(-not $PSOpenADSettings.Server -or -not $PSOpenADSettings.TlsAvailable) {
    It "Creates StartTLS session ignoring cert checks - <AuthType>" -TestCases @(
        @{ AuthType = 'Simple' }
        @{ AuthType = 'Negotiate' }
        @{ AuthType = 'Kerberos' }
    ) {
        param ([string]$AuthType)

        $selectedCred = $PSOpenADSettings.Credentials | Select-Object -First 1

        $sessionParams = @{
            ComputerName  = $PSOpenADSettings.Server
            AuthType      = $AuthType
            Credential    = [pscredential]::new($selectedCred.Username, $selectedCred.Password)
            StartTLS      = $true
            SessionOption = (New-OpenADSessionOption -SkipCertificateCheck)
        }

        $s = New-OpenADSession @sessionParams
        try {
            $s.IsClosed | Should -BeFalse
        }
        finally {
            $s | Remove-OpenADSession
        }
    }
}
