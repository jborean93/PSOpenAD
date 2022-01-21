---
external help file: PSOpenAD.dll-Help.xml
Module Name: PSOpenAD
online version:
schema: 2.0.0
---

# Get-OpenADWhoami

## SYNOPSIS
Performs an LDAP Whoami extended operation on the target server.

## SYNTAX

### Server (Default)
```
Get-OpenADWhoami [-Server <String>] [-AuthType <AuthenticationMethod>] [-SessionOption <OpenADSessionOptions>]
 [-StartTLS] [-Credential <PSCredential>] [<CommonParameters>]
```

### Session
```
Get-OpenADWhoami -Session <OpenADSession> [<CommonParameters>]
```

## DESCRIPTION
Performs the LDAP Whoami extended operation and outputs the username the server has authenticated the user as.
This is useful for debugging purposes and just to test out a connection.
Because this is an extended operation not all servers implement support for this.
Active Directory based LDAP connections should work but this is not a guarantee for any other LDAP hosts.

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
{{ Fill AuthType Description }}

```yaml
Type: AuthenticationMethod
Parameter Sets: Server
Aliases:
Accepted values: Default, Anonymous, Simple, Negotiate, Kerberos

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
{{ Fill Credential Description }}

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

### -Server
{{ Fill Server Description }}

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
{{ Fill Session Description }}

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
{{ Fill SessionOption Description }}

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
{{ Fill StartTLS Description }}

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

### System.String
## NOTES

## RELATED LINKS

[Who Am I Extended Operation](https://ldapwiki.com/wiki/Who%20Am%20I%20Extended%20Operation)
