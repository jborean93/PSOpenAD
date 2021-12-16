---
external help file: PSOpenAD.dll-Help.xml
Module Name: PSOpenAD
online version: github.com/jborean93/PSOpenAD/blob/main/docs/en-US/Get-OpenADAuthSupport.md
schema: 2.0.0
---

# Get-OpenADAuthSupport

## SYNOPSIS
Get client authentication capabilities.

## SYNTAX

```
Get-OpenADAuthSupport [<CommonParameters>]
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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
## OUTPUTS

### PSOpenAD.AuthenticationProvider
The details of each authentication object. This object has the following properties:

+ `Method`: The authentication method

+ `Available`: Whether this authentication method can be used by the client

+ `CanSign`: Whether this authentication method can sign or encrypt data over a non-TLS connection

+ `SupportsCB`: Whether this authentication method supports channel binding over a TLS connection

+ `Details`: Extra details on why a feature may not be available or why signing/encryption/channel binding support isn't available

## NOTES
The `Anonymous` and `Simple` authentication methods are always available to the client.
These methods do not support signatures or encryption over a non-TLS connection so should be avoided in those scenarios.
The `Negotiate` and `Kerberos` methods are reliant on the client having both `SASL` and `GSSAPI` installed on the host.
Depending on the version of OpenLDAP or SASL that is installed it may not support channel binding which could be enforced by an active directory server.

## RELATED LINKS
