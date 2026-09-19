---
external help file: PSOpenAD.Module.dll-Help.xml
Module Name: PSOpenAD
online version: https://www.github.com/jborean93/PSOpenAD/blob/main/docs/en-US/Restore-OpenADObject.md
schema: 2.0.0
---

# Restore-OpenADObject

## SYNOPSIS
Restores a deleted Active Directory object.

## SYNTAX

### Server (Default)
```
Restore-OpenADObject [-Identity] <ADObjectIdentity> [-TargetPath <String>] [-NewName <String>] [-PassThru]
 [-Server <String>] [-AuthType <AuthenticationMethod>] [-SessionOption <OpenADSessionOptions>] [-StartTLS]
 [-Credential <PSCredential>] [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

### Session
```
Restore-OpenADObject [-Identity] <ADObjectIdentity> [-TargetPath <String>] [-NewName <String>] [-PassThru]
 -Session <OpenADSession> [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
The `Restore-OpenADObject` cmdlet restores a deleted Active Directory object.
A deleted object is kept in the `Deleted Objects` container, under a changed name, until it is removed for good.
Use [Get-OpenADObject](./Get-OpenADObject.md) with `-IncludeDeletedObjects` to find it, then pipe it into this cmdlet.

The object is restored to the container it was deleted from, recorded in its `lastKnownParent` attribute, under the name recorded in its `msDS-LastKnownRDN` attribute or, when that is not set, the name kept in its deleted distinguished name.
Use `-TargetPath` to restore it into a different container and `-NewName` to restore it under a different name.
The naming attribute of the original distinguished name is kept, so an organizational unit is restored as `OU=...` and not `CN=...`.

The restore is a single LDAP modify request, sent with the `LDAP_SERVER_SHOW_DELETED_OID` control, that removes the `isDeleted` attribute and sets the new `distinguishedName`.
The account used needs the `Reanimate Tombstones` extended right on the domain as well as write access to the target container.

What comes back depends on the Active Directory Recycle Bin.
With it enabled a deleted object keeps its attributes and group memberships until its deleted object lifetime expires, and they are restored with it.
Once that lifetime has expired the object is recycled and can no longer be restored.
Without the Recycle Bin a deleted object is a tombstone, which has already had most of its attributes and all of its group memberships removed.
A tombstone can still be restored, and keeps its `objectGUID` and `objectSid`, but what was removed does not come back.

## EXAMPLES

### Example 1: Find and restore a deleted user
```powershell
PS C:\> Get-OpenADObject -IncludeDeletedObjects -LDAPFilter '(&(isDeleted=TRUE)(sAMAccountName=jsmith))' |
    Restore-OpenADObject
```

This command finds the deleted user with the `sAMAccountName` of `jsmith` and restores it to the container it was deleted from.

### Example 2: Restore a deleted object by its distinguished name
```powershell
PS C:\> $dn = 'CN=Jane Smith\0ADEL:6d8a4b1e-2f3c-4a5b-9c7d-0e1f2a3b4c5d,CN=Deleted Objects,DC=example,DC=com'
PS C:\> Restore-OpenADObject -Identity $dn -PassThru
```

This command restores the object with the specified distinguished name inside the `Deleted Objects` container and outputs the restored object.

### Example 3: Restore into a different container under a new name
```powershell
PS C:\> Get-OpenADObject -IncludeDeletedObjects -LDAPFilter '(&(isDeleted=TRUE)(sAMAccountName=jsmith))' |
    Restore-OpenADObject -TargetPath 'OU=Staff,DC=example,DC=com' -NewName 'Jane Smith (restored)'
```

This command restores the deleted user into the `Staff` organizational unit under the name `Jane Smith (restored)`.
Use `-TargetPath` when the original container has itself been deleted and `-NewName` when an object with the original name has been created since the deletion, as the restore fails in either case.

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
Specifies the deleted Active Directory object to restore by its `DistinguishedName`.
This is the name of the object inside the `Deleted Objects` container, as returned by `Get-OpenADObject -IncludeDeletedObjects`, and not the name it had before it was deleted.
The `-Identity` can be provided through pipeline input from `Get-OpenADObject -IncludeDeletedObjects`.
An `ObjectGUID` on its own is not supported and results in an error.

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

### -NewName
Restores the object under this name instead of its original name, which is taken from its `msDS-LastKnownRDN` attribute or, when that is not set, from its deleted distinguished name.
Use this when an object with the original name has been created in the target container since the deletion.
The cmdlet will automatically escape any characters in the value that need escaping in a distinguished name.

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

### -PassThru
Returns an object representing the item that was restored.
By default this cmdlet does not generate any output unless `-PassThru` was specified.

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

### -TargetPath
Restores the object into this container, specified by its distinguished name, instead of the container recorded in its `lastKnownParent` attribute.
Use this when the original container has itself been deleted, or to restore the object somewhere else.

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
The identity of the deleted object can be piped into the cmdlet.

## OUTPUTS

### PSOpenAD.OpenADObject
Returns the restored Active Directory object when the `-PassThru` parameter is specified. By default, this cmdlet does not generate any output. The output object will have all the default `OpenADObject` properties set. Using `-WhatIf` does not output an object.

## NOTES
The Active Directory Recycle Bin is an optional feature that is enabled per forest.
See the description above for what is restored with and without it.

## RELATED LINKS
