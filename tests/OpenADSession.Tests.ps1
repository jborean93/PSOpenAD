. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "New-OpenADSession over LDAP" -Skip:(-not $PSOpenADSettings.Server) {
    BeforeEach {
        Get-OpenADSession | Remove-OpenADSession
    }

    AfterEach {
        Get-OpenADSession | Remove-OpenADSession
    }

    It "Creates a new session using implicit server" -Skip:(-not $PSOpenADSettings.DefaultCredsAvailable -or -not $PSOpenADSettings.ImplicitServerAvailable) {
        $null = Get-OpenADObject -ErrorAction Stop
        $sessions = Get-OpenADSession
        $sessions.Count | Should -Be 1
        $sessions -is ([PSOpenAD.OpenADSession]) | Should -BeTrue
    }

    It "Creates a session using default credentials - <AuthType>" -Skip:(-not $PSOpenADSettings.DefaultCredsAvailable) -TestCases @(
        @{ AuthType = 'Negotiate' }
        @{ AuthType = 'Kerberos' }
    ) {
        param ([string]$AuthType)

        $s = New-OpenADSession -ComputerName $PSOpenADSettings.Server -AuthType $AuthType
        try {
            $s.IsClosed | Should -BeFalse
            $s.IsEncrypted | Should -BeTrue
            $s.IsSigned | Should -BeTrue
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
            $s.IsEncrypted | Should -BeTrue
            $s.IsSigned | Should -BeTrue
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
            $s.IsEncrypted | Should -BeTrue
            $s.IsSigned | Should -BeTrue
        }
        finally {
            $s | Remove-OpenADSession
        }
    }

    It "Connects using a URI - <AuthType>" -TestCases @(
        @{ AuthType = 'Negotiate' }
        @{ AuthType = 'Kerberos' }
    ) {
        param ([string]$AuthType)

        $selectedCred = $PSOpenADSettings.Credentials | Select-Object -First 1

        $sessionParams = @{
            Uri        = "ldap://$($PSOpenADSettings.Server)"
            AuthType   = $AuthType
            Credential = [pscredential]::new($selectedCred.Username, $selectedCred.Password)
        }

        $s = New-OpenADSession @sessionParams
        try {
            $s.IsClosed | Should -BeFalse
            $s.IsEncrypted | Should -BeTrue
            $s.IsSigned | Should -BeTrue
        }
        finally {
            $s | Remove-OpenADSession
        }
    }

    It "Disables encryption over Kerberos" {
        $selectedCred = $PSOpenADSettings.Credentials | Select-Object -First 1

        $sessionParams = @{
            ComputerName  = $PSOpenADSettings.Server
            AuthType      = "Kerberos"
            Credential    = [pscredential]::new($selectedCred.Username, $selectedCred.Password)
            SessionOption = (New-OpenADSessionOption -NoEncryption)
        }
        $s = New-OpenADSession @sessionParams
        try {
            $s.IsClosed | Should -BeFalse
            $s.IsEncrypted | Should -BeFalse
            $s.IsSigned | Should -BeTrue
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
            ComputerName = $PSOpenADSettings.Server
            AuthType     = $AuthType
            Credential   = [pscredential]::new($selectedCred.Username, $selectedCred.Password)
            StartTLS     = $true
        }
        if (-not $PSOpenADSettings.TlsTrusted) {
            $sessionParams.SessionOption = (New-OpenADSessionOption -SkipCertificateCheck)
        }

        $s = New-OpenADSession @sessionParams
        try {
            $s.IsClosed | Should -BeFalse
            $s.IsEncrypted | Should -BeTrue
            $s.IsSigned | Should -BeTrue
        }
        finally {
            $s | Remove-OpenADSession
        }
    }
}

Describe "New-OpenADSession over TLS" -Skip:(-not $PSOpenADSettings.Server -or -not $PSOpenADSettings.TlsAvailable) {
    It "Creates TLS session ignoring cert checks - <AuthType>" -TestCases @(
        @{ AuthType = 'Simple' }
        @{ AuthType = 'Negotiate' }
        @{ AuthType = 'Kerberos' }
    ) {
        param ([string]$AuthType)

        $selectedCred = $PSOpenADSettings.Credentials | Select-Object -First 1

        $sessionParams = @{
            ComputerName = $PSOpenADSettings.Server
            AuthType     = $AuthType
            Credential   = [pscredential]::new($selectedCred.Username, $selectedCred.Password)
            UseTLS       = $true
        }
        if (-not $PSOpenADSettings.TlsTrusted) {
            $sessionParams.SessionOption = (New-OpenADSessionOption -SkipCertificateCheck)
        }

        $s = New-OpenADSession @sessionParams
        try {
            $s.IsClosed | Should -BeFalse
            $s.IsEncrypted | Should -BeTrue
            $s.IsSigned | Should -BeTrue
        }
        finally {
            $s | Remove-OpenADSession
        }
    }

    It "Connects using a URI - <AuthType>" -TestCases @(
        @{ AuthType = 'Simple' }
        @{ AuthType = 'Negotiate' }
        @{ AuthType = 'Kerberos' }
    ) {
        param ([string]$AuthType)

        $selectedCred = $PSOpenADSettings.Credentials | Select-Object -First 1

        $sessionParams = @{
            Uri        = "ldaps://$($PSOpenADSettings.Server):636"
            AuthType   = $AuthType
            Credential = [pscredential]::new($selectedCred.Username, $selectedCred.Password)
        }
        if (-not $PSOpenADSettings.TlsTrusted) {
            $sessionParams.SessionOption = (New-OpenADSessionOption -SkipCertificateCheck)
        }

        $s = New-OpenADSession @sessionParams
        try {
            $s.IsClosed | Should -BeFalse
            $s.IsEncrypted | Should -BeTrue
            $s.IsSigned | Should -BeTrue
        }
        finally {
            $s | Remove-OpenADSession
        }
    }
}
