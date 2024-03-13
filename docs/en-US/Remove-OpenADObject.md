---
external help file: PSOpenAD.Module.dll-Help.xml
Module Name: PSOpenAD
online version: https://www.github.com/jborean93/PSOpenAD/blob/main/docs/en-US/Remove-OpenADObject.md
schema: 2.0.0
---

# Remove-OpenADObject

## SYNOPSIS
Removes an Active Directory object.

## SYNTAX

### Server (Default)
```
Remove-OpenADObject [-Identity] <ADObjectIdentity> [-Server <String>] [-AuthType <AuthenticationMethod>]
 [-SessionOption <OpenADSessionOptions>] [-StartTLS] [-Credential <PSCredential>]
 [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

### Session
```
Remove-OpenADObject [-Identity] <ADObjectIdentity> -Session <OpenADSession>
 [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
The `Remove-OpenADObject` cmdlet removes an Active Directory object.
It can be used to remove any type of Active Directory object.

The `-Identity` parameter specifies the Active Directory object to remove.
It can be identified using the distinguished name or GUID, if a GUID is used the cmdlet will lookup the final distinguished name automatically.
An `OpenADObject` object retrieved by any of the `Get-OpenAD*` cmdlets can be piped directly into the cmdlet to specify the object to remove.

## EXAMPLES

### Example 1: Remove an object by distinguished name
```powershell
PS C:\> Remove-OpenADObject -Identity 'CN=WORKSTATION1,CN=Computers,DC=FABRIKAM,DC=COM'
```

This command removes the object identified by the distinguished name `CN=WORKSTATION1,CN=Computers,DC=FABRIKAM,DC=COM`.

### Example 2: Remove an object by GUID
```powershell
PS C:\> Remove-OpenADObject -Identity '65511e76-ea80-45e1-bc93-08a78d8c4853'
```

This command removes the object identified by the `objectGUID` `65511e76-ea80-45e1-bc93-08a78d8c4853`.
The cmdlet will lookup the `distinguishedName` for this GUID before performing the deletion.

### Example 3: Remove a container and its children
```powershell
PS C:\> $toDeleteDN = (Get-OpenADObject -Identity 'CN=Container,DC=domain,DC=test').DistinguishedName
PS C:\> Get-OpenADObject -LDAPFilter '(objectClass=*)' -SearchBase $toDeleteDN |
    Sort-Object -Property { $_.DistinguishedName.Length } -Descending |
    Remove-OpenADObject
```

Removes the object `CN=Container,DC=domain,DC=test` and all of its children recursively.
_Note: This will fail if any of the objects are protected from delection._

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
Default value: None
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

### -Identity
Specifies the Active Directory user object to remove using one of the following formats:

+ `DistinguishedName`

+ `ObjectGUID`

The cmdlet writes an error if no, or multiple, objects are found based on the identity specified.
If the `DistinguishedName` is given directly, the cmdlet will attempt to remove it as is, if the `ObjectGUID` is provided the cmdlet will lookup the DN based on that GUID.
The `-Identity` can be provided through pipeline input from cmdlets like `Get-OpenADObject`.

```yaml
Type: ADObjectIdentity
Parameter Sets: (All)
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
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

### -Confirm
Prompts you for confirmation before running the cmdlet.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: cf

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -WhatIf
Shows what would happen if the cmdlet runs.
The cmdlet is not run.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: wi

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### PSOpenAD.ADObjectIdentity
The identity in it's various forms can be piped into the cmdlet.

## OUTPUTS

### None
## NOTES
Currently this cmdlet does not support deleting an object that is protected from deletion or if it contains child objects.
See the examples for a way of manually deleting an object that contains child objects.

## RELATED LINKS
