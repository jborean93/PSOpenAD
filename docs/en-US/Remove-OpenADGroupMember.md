---
external help file: PSOpenAD.Module.dll-Help.xml
Module Name: PSOpenAD
online version: https://www.github.com/jborean93/PSOpenAD/blob/main/docs/en-US/Remove-OpenADGroupMember.md
schema: 2.0.0
---

# Remove-OpenADGroupMember

## SYNOPSIS
Removes one or more members from an Active Directory group.

## SYNTAX

### Server (Default)
```
Remove-OpenADGroupMember [-Identity] <ADPrincipalIdentity> [-Members] <ADPrincipalIdentity[]> [-PassThru]
 [-Server <String>] [-AuthType <AuthenticationMethod>] [-SessionOption <OpenADSessionOptions>] [-StartTLS]
 [-Credential <PSCredential>] [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

### Session
```
Remove-OpenADGroupMember [-Identity] <ADPrincipalIdentity> [-Members] <ADPrincipalIdentity[]> [-PassThru]
 -Session <OpenADSession> [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
The `Remove-OpenADGroupMember` cmdlet removes one or more users, groups, service accounts, or computers from an Active Directory group.

The `Identity` parameter specifies the Active Directory group to remove members from.
You can specify the identity of the group with the distinguished name, GUID, Security Account Manager (SAM) name, or security identifier.
The group can also be specified by passing in a group object through the pipeline.

The `Members` parameter specifies the users, groups, service accounts, and computers to remove from the group.
You can specify the identity of the members with the distinguished name, GUID, User Principal Name (UPN), Security Account Manager (SAM) name, or security identifier.
If you are specifying more than one member, use a comma-separated list.
You cannot pass users, groups, service accounts, or computers objects through the pipeline to this parameter.

## EXAMPLES

### Example 1: Remove members from a group
```powershell
PS C:\> Remove-OpenADGroupMember -Identity 'Group1' -Member 'CN=User0,OU=Factory,DC=domain,DC=test'
```

Removes the user `CN=User0,OU=Factory,DC=domain,DC=test` from the group `Group1`.

### Example 2: Remove members to piped in group
```powershell
PS C:\> Get-OpenADGroup -Identity 'CN=Group1,OU=Factory,DC=domain,DC=test' | Remove-OpenADGroupMember -Member 'User0'
```

Removes the user `User0` from the group `CN=Group1,OU=Factory,DC=domain,DC=test`.

### Example 3: Remove multiple members from a group
```powershell
PS C:\> $members = @(
    'ea7f9ab4-7099-418c-b63b-2220602d7547'
    'user1@domain.local'
    'Computer0$'
    'S-1-5-21-1167131883-1258031391-3099692586-1112'
)
PS C:\> Remove-OpenADGroupMember -Identity 'Group0' -Member $members
```

Removes the objects specified by the `$members` variable from the group `Group0`.

## PARAMETERS

### -AuthType
The authentication type to use when creating the `OpenAD` session.
This is used when the cmdlet creates a new connection to the `-Server` specified.

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

### -DisablePermissiveModify
Group membership updates use permissive modify by default. This suppresses an error when removing a member that is not member of the group. When this parameter is used, an error "Attribute member already deleted for target" is returned.

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

### -Identity
Specifies the Active Directory group to modify the members of using one of the following formats:

+ `DistinguishedName`

+ `ObjectGUID`

+ `ObjectSID`

+ `SamAccountName`

The cmdlet writes an error if no group is found based on the identity specified.
In addition the identity is filtered by the LDAP filter `(objectCategory=group)` to restrict only group objects from being searched.

```yaml
Type: ADPrincipalIdentity
Parameter Sets: (All)
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Members
Specifies an array of users, groups, service accounts, and computers in a comma-separated list to remove from a group using one of the following formats:

+ `DistinguishedName`

+ `ObjectGUID`

+ `ObjectSID`

+ `UserPrincipalName`

+ `SamAccountName`

```yaml
Type: ADPrincipalIdentity[]
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PassThru
Returns an object representing the item that was modified.
By default this cmdlet does not general any output unless `-PassThru` was specified.

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

### System.String
### PSOpenAD.ADPrincipalIdentity
The identity in its various forms can be piped into the cmdlet.

## OUTPUTS

### PSOpenAD.OpenADObject
Returns the modified Active Directory group when the `-PassThru` parameter is specified. By default, this cmdlet does not generate any output. The output object will only have the default `OpenADObject` properties. Using `-WhatIf` and `-PassThru` will output an object but the values in the result will be blank.

## NOTES

## RELATED LINKS
