---
external help file: PSOpenAD.Module.dll-Help.xml
Module Name: PSOpenAD
online version: https://www.github.com/jborean93/PSOpenAD/blob/main/docs/en-US/Set-OpenADObject.md
schema: 2.0.0
---

# Set-OpenADObject

## SYNOPSIS
Modifies an Active Directory object.

## SYNTAX

### Server (Default)
```
Set-OpenADObject [-Add <IDictionary>] [-Clear <String[]>] [-Description <String>] [-DisplayName <String>]
 [-Identity] <ADObjectIdentity> [-Remove <IDictionary>] [-Replace <IDictionary>] [-PassThru] [-Server <String>]
 [-AuthType <AuthenticationMethod>] [-SessionOption <OpenADSessionOptions>] [-StartTLS]
 [-Credential <PSCredential>] [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

### Session
```
Set-OpenADObject [-Add <IDictionary>] [-Clear <String[]>] [-Description <String>] [-DisplayName <String>]
 [-Identity] <ADObjectIdentity> [-Remove <IDictionary>] [-Replace <IDictionary>] [-PassThru]
 -Session <OpenADSession> [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
The `Set-OpenADObject` cmdlet modifies the properties of an Active Directory object.
Property values that are not associated with cmdlet parameters can be modified by using the `-Add`, `-Replace`, `-Clear`, and `-Remove` parameters.
Each set operation is treated as an atomic operation, if one modification fails the rest should not apply.

The `-Identity` parameter specifies the Active Directory object to modify.
You can identity and object by its distinguished name or GUID.
You can also specify the identity through an object passed through the pipeline from a cmdlet like [Get-OpenADObject] or one of the more specific `Get-OpenAD*` cmdlets.

The value(s) specified by `-Add`, `-Replace`, or `-Remove` can be set from the following types:

+ `$null` - represents no values/empty

+ `bool`

+ `CommonSecurityDescriptor` - represents a security descriptor for the `nTSecurityDescriptor` attribute

+ `Enum types` - the raw integer value of the enum is used for the value

+ `DateTime`/`DateTimeOffset` - the FILETIME integer representation is used as the value

+ `Guid` - the raw bytes of the GUID is used as the value

+ `SecurityIdentifier` - the raw bytes of the SecurityIdentifier is used as the value

+ `TimeSpan` - the number of ticks (100s of nanoseconds) is used as the value

+ `X509Certificate` - the certificate DER bytes is used as the value

Everything will be casted to a string and used as the value.

See [about_OpenADAttributeFormats](./about_OpenADAttributeFormats.md) for more information on setting attribute values.

## EXAMPLES

### Example 1: Set property by distinguished name
```powershell
PS C:\> Set-OpenADObject -Identity CN=User,OU=Factory,DC=domain,DC=test -Description 'My Description'
```

Sets the `description` LDAP attribute of the AD object `CN=User,OU=Factory,DC=domain,DC=test`

### Example 2: Add property to piped in user
```powershell
PS C:\> $addProps = @{
    'msDS-AllowedToDelegateTo' = 'CN=FileServer,OU=Servers,DC=domain,DC=test'
    networkAddress = '192.168.1.1', '192.168.1.2'
}
PS C:\> Get-OpenADUser user | Set-OpenADObject -Add $addProps
```

Adds the values to the requests attributes  to the piped in user `username`.
The `-Add` parameter will add the values to the attribute and can be set to either 1 or many attributes that are not already set.

### Example 3: Set properties to specific values
```powershell
PS C:\> $replaceProps = @{
    servicePrincipalName = 'HOST/host1', 'HOST/host1.domain.com'
}
PS C:\> Get-OpenADComputer COMPUTER | Set-OpenADObject -Replace $replaceProps
```

Replaces the existing `servicePrincipalName` for the computer account `COMPUTER$` with the provided list.
To add an entry rather than replace use `-Add`.

### Example 4: Set UAC bit on an object to set password to not expire
```powershell
PS C:\> $user = Get-OpenADUser user -Property userAccountControl
PS C:\> $newUAC = $user.UserAccountControl -bor [PSOpenAD.UserAccountControl]::DontExpirePassword
PS C:\> $user | Set-OpenADObject -Replace @{ userAccountControl = $newUAC }
```

Sets the UAC bit `DONT_EXPIRE_PASSWD` to set the user `user` with a password that never expires.

## PARAMETERS

### -Add
Specifies the values to add to an object property.
The key represents the LDAP display name of the attribute to add to.
The value for each attribute can either be a single value to add or an array of multiple values to add.
Each value must be unique and not already exist on the attribute or else the LDAP request will fail.

When you use the `-Add`, `-Replace`, `-Clear`, and `-Remove` parameters together, the operations are performed in the following order:

+ `Remove`

+ `Add`

+ `Replace`

+ `Clear`

```yaml
Type: IDictionary
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

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

### -Clear
Specifies an array of object properties to be cleared.
The value specified is the LDAP display name of the property to clear.

When you use the `-Add`, `-Replace`, `-Clear`, and `-Remove` parameters together, the operations are performed in the following order:

+ `Remove`

+ `Add`

+ `Replace`

+ `Clear`

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

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

### -Description
Sets the description of the object.
The LDAP display name of this attribute is `description`.
This parameter is ignored if `description` is set in the `-Add`, `-Clear`, `-Remove`, or `-Replace` parameters.

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

### -DisplayName
Sets the display name of the object.
The LDAP display name of this attribute is `displayName`.
This parameter is ignored if `displayName` is set in the `-Add`, `-Clear`, `-Remove`, or `-Replace` parameters.

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

### -Identity
Specifies the Active Directory user object to modify using one of the following formats:

+ `DistinguishedName`

+ `ObjectGUID`

If the `DistinguishedName` is given directly, the cmdlet will attempt to modify it as is, if the `ObjectGUID` is provided the cmdlet will lookup the DN based on that GUID.
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

### -Remove
Specifies the values to remove from an object property.
The key represents the LDAP display name of the attribute to remove from.
The value for each attribute can either be a single value to remove or an array of multiple values to remove.
The value specified must already exist on the attribute specified or else the LDAP request will fail.

When you use the `-Add`, `-Replace`, `-Clear`, and `-Remove` parameters together, the operations are performed in the following order:

+ `Remove`

+ `Add`

+ `Replace`

+ `Clear`

```yaml
Type: IDictionary
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Replace
Specifies the values to replace on an object property.
The key represents the LDAP display name of the attribute to replace.
The value for each attribute can either be a single value to set or an array of multiple values to set.

When you use the `-Add`, `-Replace`, `-Clear`, and `-Remove` parameters together, the operations are performed in the following order:

+ `Remove`

+ `Add`

+ `Replace`

+ `Clear`

```yaml
Type: IDictionary
Parameter Sets: (All)
Aliases:

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

### PSOpenAD.OpenADObject
Returns the modified Active Directory object when the `-PassThru` parameter is specified. By default, this cmdlet does not generate any output. The output object will have all the default `OpenADObject` properties set plus any of the properties set by this cmdlet. Using `-WhatIf` and `-PassThru` will output an object but the values in the result will be blank.

## NOTES

## RELATED LINKS
