---
external help file: PSOpenAD.dll-Help.xml
Module Name: PSOpenAD
online version: https://www.github.com/jborean93/PSOpenAD/blob/main/docs/en-US/New-OpenADSessionOption.md
schema: 2.0.0
---

# New-OpenADSessionOption

## SYNOPSIS
Creates an object that contains advanced options for an `OpenAD` session.

## SYNTAX

```
New-OpenADSessionOption [-NoEncryption] [-NoSigning] [-NoChannelBinding] [-SkipCertificateCheck]
 [<CommonParameters>]
```

## DESCRIPTION
The cmdlet creates an object that contains advanced options for creating an LDAP connection.
You can use this object as the value of `-SessionOption` parameter on cmdlets that create an `OpenAD` session.
If no parameters are specified then the default `OpenAD` session options are used.

## EXAMPLES

### Example 1: Create default session options
```powershell
PS C:\> New-OpenADSessionOption
```

Creates the default session options for an `OpenADSession`.
These options can be manually edited and then used with a `-SessionOption` parameter.

### Example 2: Disable certificate verification
```powershell
PS C:\> $so = New-OpenADSessionOption -SkipCertificateCheck
PS C:\> Get-OpenADUser -Server dc -StartTLS -SessionOption $so -Identity my-username
```

Creates session options that disable any certificate verification checks that are done when using `StartTLS` or connecting over an LDAP endpoint.
This should not be used in a production like environment and is designed for use with test environments where self signed certificates may be in place.

### Example 3: Disable encryption and signing
```powershell
PS C:\> $so = New-OpenADSessionOption -NoEncryption -NoSigning
PS C:\> Get-OpenADUser -Server dc -SessionOption $so -Identity my-username
```

Disables and encryption or signatures placed on the data exchanged with the LDAP server.
Encryption and signing is used by auth mechanisms, like `Negotiate` and `Kerberos` to encrypt or sign the data exchanged on the network.

## PARAMETERS

### -NoChannelBinding
Stops the LDAP client from adding channel binding data to the authentication bind operation.
This is mostly used for debugging or disabling this operation on older OpenLDAP clients that may fail outright to gather this data.
It is recommended to not use this option unless you know what you are doing.

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
Disables GSSAPI encryption used when exchanging data between the client and LDAP server.
Encryption is used by the `Negotiate` and `Kerberos` mechanisms when communicating over LDAP without `StartTLS`.
Set this option to disable the encryption done by the client, beware this means any data exchanged over the network will be in plaintext.
This does nothing for the Anonymous or Simple authentication mechanisms and also does not affect the TLS encryption done with `StartTLS` or an LDAPS connection.
The `Negotiate` mechanism must also set `-NoSigning` to disable encryption as the underlying SASL code can only disable both and not one of them.

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
Disables GSSAPI signatures used when exchanging data between the client and LDAP server.
These signatures ensure the data is not tampered with when it travelled across the network.
Set this option with `-NoEncryption` to disable both encryption and signing on an LDAP connection without `StartTLS`.
This does nothing for the Anonymous or Simple authentication mechanisms and also does not affect the TLS encryption done with `StartTLS` or an LDAPS connection.

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

### -SkipCertificateCheck
Disables the TLS certificate checks done when connecting to an LDAPS endpoint or using `StartTLS`.
This is useful when the server is using a self signed certificate for it's TLS context but should be avoided when being used in a production environment.

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
## OUTPUTS

### PSOpenAD.OpenADSessionOptions
The `OpenADSessionOptions` instance that stores the session options desired. This can be edited further to change any setting as desired.

## NOTES
Settings are only used when the session is being created.
If the cmdlet is reusing an existing session then these options are ignored and the sessions used when the connection was created will continue to be used.

## RELATED LINKS
