---
external help file: PSOpenAD.Module.dll-Help.xml
Module Name: PSOpenAD
online version: https://www.github.com/jborean93/PSOpenAD/blob/main/docs/en-US/Move-OpenADObject.md
schema: 2.0.0
---

# Move-OpenADObject

## SYNOPSIS
Moves an Active Directory object or a container of objects to a different container.

## SYNTAX

### Server (Default)
```
Move-OpenADObject [-Identity] <ADObjectIdentity> [-TargetPath] <String> [-PassThru] [-Server <String>]
 [-AuthType <AuthenticationMethod>] [-SessionOption <OpenADSessionOptions>] [-StartTLS]
 [-Credential <PSCredential>] [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

### Session
```
Move-OpenADObject [-Identity] <ADObjectIdentity> [-TargetPath] <String> [-PassThru] -Session <OpenADSession>
 [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
The `Move-OpenADObject` cmdlet moves an object or a container of objects from one container to another.

The `-Identity` parameter specifies the Active Directory object or container to move.
You can identify an object or container by its `distinguishedName` or `objectGuid`, or by poviding the `OpenADObject` instance as generated by other cmdlets like [Get-OpenADUser](./Get-OpenADUser.md).

The `-TargetPath` parameter must be specified and is the new location to move the identified object or container to.

## EXAMPLES

### Example 1: Move an OU to a new location
```powershell
PS C:\> Move-OpenADObject -Identity "OU=ManagedGroups,DC=Fabrikam,DC=Com" -TargetPath "OU=Managed,DC=Fabrikam,DC=Com"
```

This command moves the organizational unit (OU) `ManagedGroups` to a new location.
The OU ManagedGroups must not be protected from accidental deletion for the successful move.

### Example 2: Move a user to a new location
```powershell
PS C:\> Get-OpenADUser -LDAPFilter '(physicalDeliveryOfficeName=Site1)' |
    Move-OpenADObject -TargetPath "OU=NewSite,DC=Fabrikam,DC=Com"
```

This command moves all users under `physicalDeliveryOfficeName=Site1` to the new OU `NewSite`.

### Example 3: Move an object specified by its objectGuid
```powershell
PS C:\> Move-OpenADObject -Identity "8d0bcc44-c826-4dd8-af5c-2c69960fbd47" -TargetPath "OU=Managed,DC=Fabrikam,DC=Com"
```

This command moves the object identified by `objectGuid` `8d0bcc44-c826-4dd8-af5c-2c69960fbd47` to the new OU `OU=Managed,DC=Fabrikam,DC=Com`.

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
Specifies the Active Directory user object to move using one of the following formats:

+ `DistinguishedName`

+ `ObjectGUID`

If the `DistinguishedName` is given directly, the cmdlet will attempt to move it as is, if the `ObjectGUID` is provided the cmdlet will lookup the DN based on that GUID.
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

### -TargetPath
Specifies the new target location for the object.
This location must be the DistinguishedName/path to a container or organizational unit.

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
Returns the moved Active Directory object when the `-PassThru` parameter is specified. By default, this cmdlet does not generate any output. The output object will have all the default `OpenADObject` properties set. Using `-WhatIf` and `-PassThru` will output an object but the values in the result will be blank.

## NOTES

## RELATED LINKS
