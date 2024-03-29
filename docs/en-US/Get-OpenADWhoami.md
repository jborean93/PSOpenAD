---
external help file: PSOpenAD.Module.dll-Help.xml
Module Name: PSOpenAD
online version: https://www.github.com/jborean93/PSOpenAD/blob/main/docs/en-US/Get-OpenADWhoami.md
schema: 2.0.0
---

# Get-OpenADWhoami

## SYNOPSIS
Performs an LDAP Whoami extended operation on the target server.

## SYNTAX

### Server (Default)
```
Get-OpenADWhoami [-Server <String>] [-AuthType <AuthenticationMethod>] [-SessionOption <OpenADSessionOptions>]
 [-StartTLS] [-Credential <PSCredential>] [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

### Session
```
Get-OpenADWhoami -Session <OpenADSession> [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION
Performs the LDAP Whoami extended operation and outputs the username the server has authenticated the user as.
This is useful for debugging purposes and just to test out a connection.
Because this is an extended operation not all servers implement support for this.
Active Directory based LDAP connections should work but this is not a guarantee for any other LDAP hosts.

The cmdlet communicates with the LDAP server in one of three ways:

+ Using the implicit AD connection based on the current environment

+ Using the `-Session` object specified

+ Using a new or cached connection to the `-Server` specified

For more information on Open AD sessions, see [about_OpenADSessions](./about_OpenADSessions.md).

## EXAMPLES

### Example 1: Get connection username
```powershell
PS C:\> $session = New-OpenADSession -ComputerName dc01.domain.test
PS C:\> Get-OpenADWhoami -Session $session
```

Creates a session and returns the Whoami result for that authenticated session.

### Example 2: Create cached session and get the username
```powershell
PS C:\> Get-OpenADWhoami -Server dc.contoso.com -StartTLS
```

Creates a new connection with `StartTLS` to `dc.contoso.com`, caches the connection for future use.
Once connected the LDAP Whoami operation is performed and the username is output to the caller.

## PARAMETERS

### -AuthType
The authentication type to use when creating the `OpenAD` session.
This is used when the cmdlet creates a new connection to the `-Server` specified`.

```yaml
Type: AuthenticationMethod
Parameter Sets: Server
Aliases:
Accepted values: Default, Anonymous, Simple, Negotiate, Kerberos, Certificate

Required: False
Position: Named
Default value: Default
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
The explicit credentials to use when creating the `OpenAD` session.
This is used when the cmdlet creates a new connection to the `-Server` specified.

```yaml
Type: PSCredential
Parameter Sets: Server
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ProgressAction
New common parameter introduced in PowerShell 7.4.

```yaml
Type: ActionPreference
Parameter Sets: (All)
Aliases: proga

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Server
The Active Directory server to connect to.
This can either be the name of the server or the LDAP connection uri starting with `ldap://` or `ldaps://`.
The derived URI of this value is used to find any existing connections that are available for use or will be used to create a new session if no cached session exists.
If both `-Server` and `-Session` are not specified then the default Kerberos realm is used if available otherwise it will generate an error.
This option supports tab completion based on the existing OpenADSessions that have been created.

This option is mutually exclusive with `-Session`.

```yaml
Type: String
Parameter Sets: Server
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Session
The `OpenAD` session to use for the query rather than trying to create a new connection or reuse a cached connection.
This session is generated by `New-OpenADSession` and can be used in situations where the global defaults should not be used.

This option is mutually exclusive with `-Server`.

```yaml
Type: OpenADSession
Parameter Sets: Session
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SessionOption
Advanced session options used when creating a new session with `-Server`.
These options can be generated with `New-OpenADSessionOption`.

```yaml
Type: OpenADSessionOptions
Parameter Sets: Server
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -StartTLS
Use `StartTLS` when creating a new session with `-Server`.

```yaml
Type: SwitchParameter
Parameter Sets: Server
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

### None
## OUTPUTS

### PSOpenAD.WhoamiResult
The `WhoamiResult` object representing the result returned by the LDAP Whoami extended operation plus extra properties to provide extract context on the session. This object will always have the following properties set:

+ `UserName`: The username, typically in the netlogon form `DOMAIN\username`, of the authenticated session.

+ `Uri`: The LDAP URI used for the connection.

+ `DomainController`: The DNS hostname of the domain controller the session is connected to.

+ `Authentication`: The authentication method used to authenticate with the session.

+ `RawUserName`: The raw string returned from the LDAP whoami extended operation.

The `RawUserName` is not part of the default property sets and will display unless explicitly requested with `Select-Object *` or accessed manually `$result.RawUserName`.

## NOTES

## RELATED LINKS

[Who Am I Extended Operation](https://ldapwiki.com/wiki/Who%20Am%20I%20Extended%20Operation)
