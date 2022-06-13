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

    It "Creates session with trace logging" {
        $selectedCred = $PSOpenADSettings.Credentials | Select-Object -First 1

        $logPath = "temp:/PSOpenAD-$([Guid]::NewGuid())"
        $sessionParams = @{
            Uri           = "ldap://$($PSOpenADSettings.Server)"
            Credential    = [pscredential]::new($selectedCred.Username, $selectedCred.Password)
            SessionOption = (New-OpenADSessionOption -TracePath $logPath)
        }

        $s = New-OpenADSession @sessionParams
        try {
            Test-Path -LiteralPath $logPath | Should -BeTrue
            $currentSize = (Get-Item -LiteralPath $logPath).Size
            $currentSize | Should -BeGreaterThan 0

            $null = Get-OpenADUser -Session $s
            (Get-Item -LiteralPath $logPath).Size | Should -BeGreaterThan $currentSize
        }
        finally {
            $s | Remove-OpenADSession
            if (Test-Path -LiteralPath $logPath) {
                Remove-Item -LiteralPath $logPath -Force
            }
        }
    }

    It "Fails to create cert auth session without certificate set" {
        $sessionParams = @{
            ComputerName = $PSOpenADSettings.Server
            AuthType     = "Certificate"
        }
        $result = New-OpenADSession @sessionParams -ErrorAction SilentlyContinue -ErrorVariable err
        $result | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        $err[0].Exception.Message | Should -Be "Certificate authentication is requested but ClientCertificate has not been set"
    }

    It "Fails to create cert auth that's not using StartTLS or LDAP" {
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem(@'
-----BEGIN CERTIFICATE-----
MIICsDCCAhmgAwIBAgIJALwzrJEIBOaeMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTEwOTMwMTUyNjM2WhcNMjEwOTI3MTUyNjM2WjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
gQC88Ckwru9VR2p2KJ1WQyqesLzr95taNbhkYfsd0j8Tl0MGY5h+dczCaMQz0YY3
xHXuU5yAQQTZjiks+D3KA3cx+iKDf2p1q77oXxQcx5CkrXBWTaX2oqVtHm3aX23B
AIORGuPk00b4rT3cld7VhcEFmzRNbyI0EqLMAxIwceUKSQIDAQABo4GnMIGkMB0G
A1UdDgQWBBSGmOdvSXKXclic5UOKPW35JLMEEjB1BgNVHSMEbjBsgBSGmOdvSXKX
clic5UOKPW35JLMEEqFJpEcwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgTClNvbWUt
U3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZIIJALwzrJEI
BOaeMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADgYEAcPfWn49pgAX54ji5
SiUPFFNCuQGSSTHh2I+TMrs1G1Mb3a0X1dV5CNLRyXyuVxsqhiM/H2veFnTz2Q4U
wdY/kPxE19Auwcz9AvCkw7ol1LIlLfJvBzjzOjEpZJNtkXTx8ROSooNrDeJl3HyN
cciS5hf80XzIFqwhzaVS9gmiyM8=
-----END CERTIFICATE-----
'@)
        $sessionParams = @{
            ComputerName  = $PSOpenADSettings.Server
            AuthType      = "Certificate"
            SessionOption = (New-OpenADSessionOption -ClientCertificate $cert)
        }
        $result = New-OpenADSession @sessionParams -ErrorAction SilentlyContinue -ErrorVariable err
        $result | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        $err[0].Exception.Message | Should -Be "Certificate authentication is requested but TLS is not being used"
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
