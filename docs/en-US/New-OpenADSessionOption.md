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
 [-ConnectTimeout <Int32>] [-OperationTimeout <Int32>] [-TracePath <String>] [<CommonParameters>]
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

### Example 4: Enable message trace logging
```powershell
PS C:\> $so = New-OpenADSessionOption -TracePath temp:/PSOpenAD-Trace.log
PS C:\> $s = New-OpenADSession -ComputerName dc -SessionOption $so
PS C:\> Get-OpenADUser -Session $s -Identity my-username
PS C:\> $s | Remove-OpenADSession
```

Creates an OpenAD session with trace message logging set to log the incoming and outgoing LDAP messages to `temp:/PSOpenAD-Trace.log`.
The path can be any location accessible by the `FileSystem` provider in PowerShell.
The logs will continue to append until the OpenAD session is closed.

## PARAMETERS

### -ConnectTimeout
The timeout in milliseconds that the client will wait to connect to the target host.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -NoChannelBinding
Stops the LDAP client from adding channel binding data to the authentication bind operation.
This is mostly used for debugging or disabling this operation on older LDAP hosts that may fail to authenticate a client with this data.
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
Disables SASL encryption used when exchanging data between the client and LDAP server over a non-TLS connection.
Encryption is used by the `Negotiate` and `Kerberos` mechanisms when communicating over LDAP without `StartTLS`.
Set this option to disable the encryption done by the client, beware this means any data exchanged over the network will be in plaintext.
For either `Anonymous` or `Simple` this option has no affect as they do not have any encryption capabilities.
For `Kerberos` this option will disable encryption but the data will still be signed for integrity checks.
For `Negotiate` on Windows this will be the same as `Kerberos` but for `NTLM` this will do nothing as `NTLM` does not offer signature only wrappings.
For `Negotiate` on non-Windows` this will do nothing as it cannot be disabled without also disabling signatures.

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
Disables SASL signatures used when exchanging data between the client and LDAP server.
These signatures ensure the data is not tampered with when it travelled across the network.
This option must be set with `-NoEncryption` as encrypiton needs to be disabled for signatures to be disabled on an LDAP connection without `StartTLS`.
This cannot be set when using `-StartTLS` or an `LDAPS` connection.

For either `Anonymous` or `Simple` this option has no affect as they do not have any signing capabilities.
For other auth methods this will disable any signatures and with encryption also disabled the messages are exchanged in plaintext.

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

### -OperationTimeout
The time, in milliseconds to wait until an individual request like a search request to take before timing out.

```yaml
Type: Int32
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

### -TracePath
The path to a local file where incoming and outgoing LDAP messages will be written to.
Each line in this path starts with either `RECV: ` or `SEND: ` and the value being the base64 encoded string of the LDAP message.
Opening a new session with a trace path will create the new file path and will overwrite the existing path if it already exists.
The directory the file is located in must already exist or else the session creation will fail.
The contents of the LDAP messages can contain sensitive values so use this only for debugging purposes.

```yaml
Type: String
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
