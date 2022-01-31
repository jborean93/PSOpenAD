---
external help file: PSOpenAD.dll-Help.xml
Module Name: PSOpenAD
online version: https://www.github.com/jborean93/PSOpenAD/blob/main/docs/en-US/Remove-OpenADSession.md
schema: 2.0.0
---

# Remove-OpenADSession

## SYNOPSIS
Disconnects an LDAP/AD session.

## SYNTAX

```
Remove-OpenADSession [-Session] <OpenADSession[]> [<CommonParameters>]
```

## DESCRIPTION
Disconnects an LDAP/AD session and marks the session object as closed.

Once closed the sesion is removed from the process wide connection pool.

## EXAMPLES

### Example 1
```powershell
PS C:\> $s = New-OpenADSession -ComputerName domain-controller -Authentication Negotiate
PS C:\> $s | Remove-OpenADSession
```

Creates a session and then disconnects it.

## PARAMETERS

### -Session
The session to disconnect.

```yaml
Type: OpenADSession[]
Parameter Sets: (All)
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### PSOpenAD.OpenADSession[]
The session(s) to disconnect.

## OUTPUTS

### None
## NOTES
Once the session has been closed it will be removed from the pool and cannot be used for any future operations.

## RELATED LINKS
