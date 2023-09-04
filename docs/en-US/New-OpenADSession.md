---
external help file: PSOpenAD.Module.dll-Help.xml
Module Name: PSOpenAD
online version: https://www.github.com/jborean93/PSOpenAD/blob/main/docs/en-US/New-OpenADSession.md
schema: 2.0.0
---

# New-OpenADSession

## SYNOPSIS
Creates an authenticated connection to an AD/LDAP host.

## SYNTAX

### ComputerName (Default)
```
New-OpenADSession [-ComputerName] <String> [-Port <Int32>] [-UseTLS] [-Credential <PSCredential>]
 [-AuthType <AuthenticationMethod>] [-StartTLS] [-SessionOption <OpenADSessionOptions>] [<CommonParameters>]
```

### Uri
```
New-OpenADSession [-Uri] <Uri> [-Credential <PSCredential>] [-AuthType <AuthenticationMethod>] [-StartTLS]
 [-SessionOption <OpenADSessionOptions>] [<CommonParameters>]
```

## DESCRIPTION
Connects and authenticates the client to an LDAP/AD host.
The session created can then be used by other cmdlets to get/set data from the LDAP connection.
When creating an `OpenAD` session, PowerShell will:

+ Open a connection to the endpoint configured

+ Perform the `StartTLS` extended operation if `-StartTLS` is specified.

+ Bind/authenticate the client with the method specified

+ Get the default naming context from the Root DSE used for subsequent queries on that connection

+ Get the schema attribute and class object information used to parse the raw data returned by the server

When the session is no longer needed, dispose of the connection using `Remove-OpenADSession`.

For more information on Open AD sessions, see [about_OpenADSessions](./about_OpenADSessions.md).

## EXAMPLES

### Example 1: Create a session using the defaults
```powershell
PS C:\> $session = New-OpenADSession -ComputerName dc01.domain.test
```

Creates an `OpenAD` session to the domain controller at `dc01.domain.test`.

### Example 2: Create a session with explicit credentials
```powershell
PS C:\> $cred = Get-Credential
PS C:\> $session = New-OpenADSession -ComputerName dc01 -Credential $cred
```

Creates an `OpenAD` session to the domain controller at `dc01` using the credentials specified.

### Example 3: Create a connection with SIMPLE auth and StartTLS
```powershell
PS C:\> $cred = Get-Credential
PS C:\> $session = New-OpenADSession -ComputerName dc -AuthType Simple -StartTLS -Credential $cred
```

Creates an `OpenAD` session and upgrades the connection using `StartTLS`.
Once the TLS handshake occurs the user is authenticated using the credentials specified.
Because `StartTLS` is used, the SIMPLE auth exchange is encrypted and the credentials are not exposed on the network.

### Example 4: Create an LDAPS connection
```powershell
PS C:\> $session = New-OpenADSession -ComputerName dc -UseTLS
```

Creates an `OpenAD` session using LDAPS.

### Example 5: Create a connection as an anonymous user
```powershell
PS C:\> $session = New-OpenADSession -ComputerName dc -AuthType Anonymous
```

Creates an `OpenAD` session as an anonymous user.
An anonymous user is typically limited in what it can do on the remote host.

## PARAMETERS

### -AuthType
The authentication type to use when authenticating the user.
The available options are:

+ `Default` - The default auth type used when one isn't explicitly defined

+ `Anonymous` - No credentials are used, the user is treated as an anonymous user on the server

+ `Simple` - Like HTTP Basic auth, the credentials are sent in plaintext to the server

+ `Kerberos` - Uses the SASL `GSSAPI` mech which is configured for Kerberos authentication

+ `Negotiate` - Uses the SASL `GSS-SPNEGO` mech which is configured for SPNEGO/Negotiate authentication

The `Default` auth type will attempt to use `Negotiate` if it's available on the client.
If it is not then it will fallback to `Simple` if both a credential is provided and TLS is used on the connection.
Finally it falls back to `Anonymous` auth if all else fails.

The `Anonymous` and `Simple` auth types are always available as the functionality is builtin to the LDAP client.
When using `Simple` you should always use LDAPS or specify `-StartTLS` to encrypt the data.
Failure to do so will expose both the username and password in plaintext on the network.

The `Negotiate` authentication type will attempt to use `Kerberos` but potentially fallback to `NTLM` if it's available (Windows only).
On non-Windows platforms `Negotiate` is essentially `Kerberos` but requires less requests to the server to complete the authentication phase.

The `Kerberos` and `Negotiate` options both rely on a few factors before they are ready to use:

+ Windows and macOS will always include support for both but may not be able to use `Kerberos` is the client cannot communicate with a domain

+ Linux requires a GSSAPI library to be installed and configured for both `Negotiate` and `Kerberos` to work

Use `Get-OpenADAuthSupport` to get more information around authentication.


```yaml
Type: AuthenticationMethod
Parameter Sets: (All)
Aliases:
Accepted values: Default, Anonymous, Simple, Negotiate, Kerberos, Certificate

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ComputerName
The LDAP/AD host to connect to.
This should be just the hostname, use `-ConnectionUri` to connect with a full LDAP URI.

```yaml
Type: String
Parameter Sets: ComputerName
Aliases: Server

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Credential
The username and password to authenticate with.
This is only required when using `-AuthType Simple` other mechanisms can still use explicit credentials but can also rely on system wide caches, like `kinit`.

If using `Negotiate` or `Kerberos` on non-Windows with an explicit credential the username should be in the `UPN` form `username@DOMAIN.COM`.
The neglogon form `DOMAIN\username` will typically only work for Windows.
A credential with a blank password (`[SecureString]::new()`) will attempt to lookup the username specified in the credential cache of the host and use that if present or fail if not present.

```yaml
Type: PSCredential
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Port
The LDAP port to connect to.
This defaults to `389` for LDAP and `636` for LDAPS.

```yaml
Type: Int32
Parameter Sets: ComputerName
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SessionOption
Advanced sessions options to use when creating the connection.
These session options can be generated by `New-OpenADSessionOption`.

```yaml
Type: OpenADSessionOptions
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -StartTLS
Use `StartTLS` over a standard LDAP connection.
This is used to encrypt data sent over an LDAP connection before any subsequent traffic, like authentication details.
Either `StartTLS` or an LDAPS connection should be used when `-AuthType Simple` to ensure the data exchanged is encrypted and the server's identity is verified.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Uri
Connect using the full LDAP URI.
This is mutually exclusive with the `-ComputerName`, `-Port`, and `-UseTLS` options.

```yaml
Type: Uri
Parameter Sets: Uri
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -UseTLS
Connect over LDAPS rather than standard LDAP.
Either `StartTLS` or an LDAPS connection should be used when `-AuthType Simple` to ensure the data exchanged is encrypted and the server's identity is verified.

```yaml
Type: SwitchParameter
Parameter Sets: ComputerName
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.Uri
The full LDAP URI to connect to.

### System.String
The LDAP/AD server name to connect to.

## OUTPUTS

### PSOpenAD.OpenADSession
The connected AD session that can be used as an explicit connection on the various `OpenAD` cmdlets. This object contains the following properties:

+ `Id`: The unique identifier for this session in the process

+ `Uri`: The full URI used to connect to the host

+ `Authentication`: The authentication method used

+ `DomainController`: The DNS hostname of the domain controller that the session is connected to

+ `IsSigned`: Whether the data on this connection will be signed

+ `IsEncrypted`: Whether the data on this connection will be encrypted

+ `OperationTimeout`: The timeout, in milliseconds, that set the maximum time to wait for a response for each LDAP operation

+ `DefaultNamingContext`: The default naming context of the connected LDAP host used as the search base for future queries

+ `IsClosed`: Whether the session is closed or not.

## NOTES
Once the connection has been successfully made the connection is placed in a cache and reused for any subsequent requests to the same URI.
This will be removed from the cache when it is closed with `Remove-OpenADSession`.

## RELATED LINKS
