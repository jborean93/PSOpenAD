---
external help file: PSOpenAD.Module.dll-Help.xml
Module Name: PSOpenAD
online version: https://www.github.com/jborean93/PSOpenAD/blob/main/docs/en-US/Rename-OpenADObject.md
schema: 2.0.0
---

# Rename-OpenADObject

## SYNOPSIS
Changes the name of an Active Directory object.

## SYNTAX

### Server (Default)
```
Rename-OpenADObject [-Identity] <ADObjectIdentity> [-NewName] <String> [-PassThru] [-Server <String>]
 [-AuthType <AuthenticationMethod>] [-SessionOption <OpenADSessionOptions>] [-StartTLS]
 [-Credential <PSCredential>] [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

### Session
```
Rename-OpenADObject [-Identity] <ADObjectIdentity> [-NewName] <String> [-PassThru] -Session <OpenADSession>
 [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
The `Rename-OpenADObject` cmdlet renames an Active Directory object.
The cmdlet set the `name` LDAP attribute of an object.
To modify other properties like `givenName`, `surname`, etc, use the [Set-OpenADObject](./Set-OpenADObject.md) cmdlet instead.

The `-Identity` parameter specifies the object to rename.
You can identify an object or container by its `distinguishedName` or `objectGuid`, or by poviding the `OpenADObject` instance as generated by other cmdlets like [Get-OpenADUser](./Get-OpenADUser.md).

The `-NewName` parameter defines the new name for the object and must be specified.

## EXAMPLES

### Example 1: Rename a site
```powershell
PS C:\> Rename-OpenADObject -Idenitty "CN=HQ,CN=Sites,CN=Configuration,DC=FABRIKAM,DC=COM" -NewName "UnitedKingdomHQ"
```

This command renames the name of the existing site `HQ` to the new name `UnitedKingdomHQ`.

### Example 2: Rename an object by GUID
```powershell
PS C:\> Rename-ADObject -Identity "4777c8e8-cd29-4699-91e8-c507705a0966" -NewName "AmsterdamHQ"
```

This command renamed the object identified by the `objectGuid` `4777c8e8-cd29-4699-91e8-c507705a0966` to `AmsterdamHQ`.

### Example 3: Rename by piping in identities
```powershell
PS C:\> Get-OpenADUser -LDAPFilter '(company=DevsRUs)' |
    Rename-OpenADObject -NewName { "$($_.Name)-Rockstar" }
```

This command gets all the AD users under the company `DevsRUs` and renames them with the suffix `-Rockstar`.
It uses a [delay-bind script block value](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_script_blocks?view=powershell-7.4#using-delay-bind-script-blocks-with-parameters) for `-NewName` allowing the name to be generated from the input object being processed.

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
Specifies the Active Directory user object to rename using one of the following formats:

+ `DistinguishedName`

+ `ObjectGUID`

If the `DistinguishedName` is given directly, the cmdlet will attempt to rename it as is, if the `ObjectGUID` is provided the cmdlet will lookup the DN based on that GUID.
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

### -NewName
Specifies the new name of the object.
This parameter sets the `name` property of the Active Directory object.
The cmdlet will automatically escape any values needed to set this on the LDAP attribute, for example `-NewName 'User "Nickname" Name'` will become `User \"Nickname\" Name` when being set in the LDAP attribute.

This parameter supports [delay-bind scriptblock values](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_script_blocks?view=powershell-7.4#using-delay-bind-script-blocks-with-parameters) when piping in an identity object.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName)
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

### PSOpenAD.ADObjectIdentity
The identity in its various forms can be piped into the cmdlet.

## OUTPUTS

### PSOpenAD.OpenADObject
Returns the renamed Active Directory object when the `-PassThru` parameter is specified. By default, this cmdlet does not generate any output. The output object will have all the default `OpenADObject` properties set. Using `-WhatIf` and `-PassThru` will output an object but the values in the result will be blank.

## NOTES

## RELATED LINKS
