---
external help file: PSOpenAD.Module.dll-Help.xml
Module Name: PSOpenAD
online version: https://www.github.com/jborean93/PSOpenAD/blob/main/docs/en-US/Get-OpenADAuthSupport.md
schema: 2.0.0
---

# Get-OpenADAuthSupport

## SYNOPSIS
Get client authentication capabilities.

## SYNTAX

```
Get-OpenADAuthSupport [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION
Get the authentication methods the client can use and display the availability of optional features.

## EXAMPLES

### Example 1
```powershell
PS C:\> Get-OpenADAuthSupport
```

Get the authentication support information for the current client.

## PARAMETERS

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
## OUTPUTS

### PSOpenAD.AuthenticationProvider
The details of each authentication object. This object has the following properties:

+ `Method`: The authentication method

+ `SaslId`: The SASL mechanism name that this provider represents

+ `Available`: Whether this authentication method can be used by the client

+ `CanSign`: Whether this authentication method can sign or encrypt data over a non-TLS connection

+ `Details`: Extra details on why a feature may not be available

## NOTES
The `Anonymous` and `Simple` authentication methods are always available to the client.
These methods do not support signatures or encryption over a non-TLS connection so should be avoided in those scenarios.
The `Negotiate` and `Kerberos` methods are always available on Windows but relies on a working `GSSAPI` library on non-Windows hosts.

## RELATED LINKS
