---
external help file: PSOpenAD.dll-Help.xml
Module Name: PSOpenAD
online version: github.com/jborean93/PSOpenAD/blob/main/docs/en-US/New-OpenADSession.md
schema: 2.0.0
---

# New-OpenADSession

## SYNOPSIS
Creates an authenticated connection to an LDAP/AD host.

## SYNTAX

### ComputerName (Default)
```
New-OpenADSession [-ComputerName] <String> [-Port <Int32>] [-UseSSL] [-StartTLS] [-Credential <PSCredential>]
 [-Authentication <AuthenticationMethod>] [-NoEncryption] [-NoSigning] [-NoChannelBinding]
 [-SkipCertificateCheck] [<CommonParameters>]
```

### Uri
```
New-OpenADSession [-Uri] <Uri> [-StartTLS] [-Credential <PSCredential>]
 [-Authentication <AuthenticationMethod>] [-NoEncryption] [-NoSigning] [-NoChannelBinding]
 [-SkipCertificateCheck] [<CommonParameters>]
```

## DESCRIPTION
Connects and authenticates the client to an LDAP/AD host.
The session created can then be used by other cmdlets to get/set data from the LDAP connection.

## EXAMPLES

### Example 1
```powershell
PS C:\> {{ Add example code here }}
```

{{ Add example description here }}

## PARAMETERS

### -Authentication
The authentication method to use.
The default is `Simple` auth which sends the credentials in plaintext and should only be used with `LDAPS` or `-StartTLS`.
The `Negotiate` or `Kerberos` auth require both an install of SASL and GSSAPI on the client, use `Get-OpenADAuthSupport` to learn more.
The `-Credential` parameter must be used when using `Simple` auth.
The `-Credential` parameter is optional if using `Kerberos` or `Negotiate` auth as it will attempt to use the cached Kerberos ticket if available.

```yaml
Type: AuthenticationMethod
Parameter Sets: (All)
Aliases:
Accepted values: Anonymous, Simple, Negotiate, Kerberos

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ComputerName
The host to connect to.

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
This is optional if using `-Authentication Kerberos|Negotiate` and there is an available cached Kerberos ticket.

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

### -NoChannelBinding
Disable channel binding when connecting over LDAPS or using `-StartTLS`.
This should only be used for compatibility support.

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

### -NoEncryption
Disable `Negotiate` or `Kerberos` encryption when connecting over LDAP.
The authentication token will still be secure but subsequent communication will only be signed and not encrypted allowing others to see the traffic.
The `-Authentication Negotiate` option must also set `-NoSigning` to disable encryption.

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

### -NoSigning
Disable `Negotiate` or `Kerberos` signatures when connecting over LDAP.
This must be combined with `-NoEncryption` as encryption takes priority over signing.

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

### -SkipCertificateCheck
Skip certificate verification when using LDAPS or `-StartTLS`.

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

### -StartTLS
Use `StartTLS` over a standard LDAP connection.
This is used to encrypt data sent over an LDAP connection.

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
This can be used instead of `-ComputerName`, `-Port`, and `-UseSSL`.

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

### -UseSSL
Connect over LDAPS rather than standard LDAP.

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
The connected AD session that can be used for subsequent operations of that host. This object contains the following properties:

+ `Uri`: The full URI used to connect to the host

+ `Authentication`: The authentication method used

+ `IsSigned`: Whether the data on this connection will be signed

+ `IsEncrypted`: Whether the data on this connection will be encrypted

+ `IsClosed`: Whether the session is closed or not.

## NOTES

## RELATED LINKS
