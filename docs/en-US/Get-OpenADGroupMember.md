---
external help file: PSOpenAD.dll-Help.xml
Module Name: PSOpenAD
online version:
schema: 2.0.0
---

# Get-OpenADGroupMember

## SYNOPSIS
Gets the members of an Active Directory group.

## SYNTAX

### ServerIdentity (Default)
```
Get-OpenADGroupMember [-Server <String>] [-AuthType <AuthenticationMethod>]
 [-SessionOption <OpenADSessionOptions>] [-StartTLS] [-Credential <PSCredential>]
 [-Identity] <ADPrincipalIdentity> [-Property <String[]>] [<CommonParameters>]
```

### SessionIdentity
```
Get-OpenADGroupMember -Session <OpenADSession> [-Identity] <ADPrincipalIdentity> [-Property <String[]>]
 [<CommonParameters>]
```

## DESCRIPTION
The `Get-OpenADGroupMember` cmdlet returns the member objects of a group specified by `-Identity`.

The cmdlet communicates with the LDAP server in one of three ways:

+ Using the implicit AD connection based on the current environment

+ Using the `-Session` object specified

+ Using a new or cached connection to the `-Server` specified

For more information on Open AD sessions, see [about_OpenADSessions](./about_OpenADSessions.md).

The output for each object retrieves a default set of object properties as documented in the `OUTPUT` section.
Any additional properties can be requested with the `-Property` parameter in the form of the LDAP property name desired.

## EXAMPLES

### Example 1
```powershell
PS C:\> Get-OpenADGroupMember -Identity 'Domain Controllers'
```

This command retrieves the members of the Domain Controllers group from the implicit AD connection.

### Example 2
```powershell
PS C:\> Get-OpenADGroupMember -Identity 'Domain Admins' -Property badPwdCount
```

This command retrieves the members of the Domain Admins group from the implicit AD connection, including the value of the badPwdCount attribute.

### Example 3
```powershell
PS C:\> Get-OpenADGroupMember -Identity Administrators -Recursive
```

This command retrieves the members of the Administrators group from the implicit AD connection, including the members of any nested groups.

## PARAMETERS

### -AuthType
The authentication type to use when creating the `OpenAD` session.
This is used when the cmdlet creates a new connection to the `-Server` specified`.

```yaml
Type: AuthenticationMethod
Parameter Sets: ServerIdentity
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
Parameter Sets: ServerIdentity
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Identity
Specifies the Active Directory group to list the members of using one of the following formats:

+ `DistinguishedName`

+ `ObjectGUID`

+ `ObjectSID`

+ `UserPrincipalName`

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

### -Property
The attributes to retrieve for each computer object returned.
The values of each attribute is in the form of an LDAP attribute name and are case insensitive.
When no properties are specified the following attributes are retrieved:

+ `distinguishedName`

+ `name`

+ `objectClass`

+ `objectGUID`

+ `sAMAccountName`

+ `objectSid`

Any attributes specified by this parameter will be added to the list above.
Specify `*` to display all attributes that are set on the object.
Any attributes on the object that do not have a value set will not be returned with `*` unless they were also explicitly requested.
These unset attributes must be explicitly defined for it to return on the output object.

If there has been a successful connection to any LDAP server this option supports tab completion.
The possible properties shown in the tab completion are based on the schema returned by the server for the `top` object class.
If no connection has been created by the client then there is no tab completion available.


```yaml
Type: String[]
Parameter Sets: (All)
Aliases: Properties

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
Parameter Sets: ServerIdentity
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
Parameter Sets: SessionIdentity
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
Parameter Sets: ServerIdentity
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
Parameter Sets: ServerIdentity
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### PSOpenAD.ADPrincipalIdentity
The identity in its various forms can be piped into the cmdlet.

## OUTPUTS

### PSOpenAD.OpenADPrincipal
The `OpenADPrincipal` representing the member objects. This object will always have the following properties set:

+ `DistinguishedName`

+ `Name`

+ `ObjectClass`

+ `ObjectGuid`

+ `SamAccountName`

+ `SID`

+ `DomainController`: This is set to the domain controller that processed the request

Any explicit attributes requested through `-Property` are also present on the object.
If an LDAP attribute on the underlying object did not have a value set but was explicitly requested then the property will be set to `$null`.

## NOTES

## RELATED LINKS
