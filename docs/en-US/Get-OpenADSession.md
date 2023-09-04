---
external help file: PSOpenAD.Module.dll-Help.xml
Module Name: PSOpenAD
online version: https://www.github.com/jborean93/PSOpenAD/blob/main/docs/en-US/Get-OpenADSession.md
schema: 2.0.0
---

# Get-OpenADSession

## SYNOPSIS
Lists all the current OpenADSessions created by the client.

## SYNTAX

```
Get-OpenADSession [<CommonParameters>]
```

## DESCRIPTION
Outputs each Open AD session that has been opened by the client.
These sessions contains connection details, such as the connection URI, authentication method used, encryption details.
A session can then be explicitly closed with `Remove-OpenADSession` or used in any of the PSOpenAD cmdlets that accepts a `-Session` object.

Each session in the pool were either created by an explicit call to `New-OpenADSession` or by any implicit sessions created when connecting to a new LDAP server.

For more information on Open AD sessions, see [about_OpenADSessions](./about_OpenADSessions.md).

## EXAMPLES

### Example 1: Get all OpenAD sessions
```powershell
PS C:\> Get-OpenADSession
```

Gets all the OpenAD session objects created by the client.

## PARAMETERS

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
## OUTPUTS

### PSOpenAD.OpenADSession
The connected AD session that can be used as an explicit connection on the various `OpenAD` cmdlets. This object contains the following properties:

+ `Id`: The unique identifier for this session in the process

+ `Uri`: The full URI used to connect to the host

+ `Authentication`: The authentication method used

+ `IsSigned`: Whether the data on this connection will be signed

+ `IsEncrypted`: Whether the data on this connection will be encrypted

+ `OperationTimeout`: The timeout, in milliseconds, that set the maximum time to wait for a response for each LDAP operation

+ `DefaultNamingContext`: The default naming context of the connected LDAP host used as the search base for future queries

+ `IsClosed`: Whether the session is closed or not.

## NOTES
Once a session has been removed with `Remove-OpenADSession` it will no longer appear in this output.

## RELATED LINKS
