---
external help file: PSOpenAD.dll-Help.xml
Module Name: PSOpenAD
online version: https://www.github.com/jborean93/PSOpenAD/blob/main/docs/en-US/Get-OpenADObject.md
schema: 2.0.0
---

# Get-OpenADObject

## SYNOPSIS
Gets one or more Active Directory objects.

## SYNTAX

### ServerLDAPFilter (Default)
```
Get-OpenADObject [-IncludeDeletedObjects] [-Server <String>] [-AuthType <AuthenticationMethod>]
 [-SessionOption <OpenADSessionOptions>] [-StartTLS] [-Credential <PSCredential>] [-LDAPFilter <String>]
 [-SearchBase <String>] [-SearchScope <SearchScope>] [-Property <String[]>] [<CommonParameters>]
```

### SessionIdentity
```
Get-OpenADObject [-IncludeDeletedObjects] -Session <OpenADSession> -Identity <ADObjectIdentity>
 [-Property <String[]>] [<CommonParameters>]
```

### SessionLDAPFilter
```
Get-OpenADObject [-IncludeDeletedObjects] -Session <OpenADSession> [-LDAPFilter <String>]
 [-SearchBase <String>] [-SearchScope <SearchScope>] [-Property <String[]>] [<CommonParameters>]
```

### ServerIdentity
```
Get-OpenADObject [-IncludeDeletedObjects] [-Server <String>] [-AuthType <AuthenticationMethod>]
 [-SessionOption <OpenADSessionOptions>] [-StartTLS] [-Credential <PSCredential>] -Identity <ADObjectIdentity>
 [-Property <String[]>] [<CommonParameters>]
```

## DESCRIPTION
The `Get-OpenADObject` cmdlet gets an Active Directory object or performs a search to get multiple objects.
Specifying no `-Identity` or `-LDAPFilter` parameter will result in a query of just `(objectClass=*)`.
Otherwise that will be be used as an AND condition of the query specified by the caller, e.g. `(&(objectClass=*)(...))`.

The `-Identity` parameter specifies an individual object to retrieve.
The identity for this cmdlet can either be the distinguished name or GUID.

The `-LDAPFilter` parameter can be used to search for multiple objects using the LDAP query language.
The filter can be combined with `-SearchBase` and `-SearchScope` to refine the search parameters used.

The cmdlet communicates in one of three way:

+ Using the implicit AD connection based on the current environment

+ Using the `-Session` object specified

+ Using a new or cached connection to the `-Server` specified

For more information on Open AD sessions, see [about_OpenADSessions](./about_OpenADSessions.md).

The output for each object retrieves a default set of object properties as documented in the `OUTPUT` section.
Any additional properties can be requested with the `-Property` parameter in the form of the LDAP property name desired.

## EXAMPLES

### Example 1: Get the sites for a domain using LDAP filter syntax
```powershell
PS C:\> $getParams @{
..      LDAPFilter = "(objectClass=site)"
..      SearchBase = 'CN=Configuration,DC=Fabrikam,DC=Com'
..      Properties = "canonicalName"
..  }
PS C:\> Get-OpenADObject @getParams | Select-Object Name, canonicalName
```

This command displays a list of sites for Fabrikam using the LDAP filter syntax.

### Example 2: Get information for a specified object of an LDAP instance
```powershell
PS C:\> Get-OpenADObject -Identity "DC=AppNC" -Server "FABRIKAM-SRV1"
```

This command gets the information of the domainDNS object from an explicit Active Directory.

### Example 3: Get deleted objects
```powershell
PS C:\> Get-OpenADObject -IncludeDeletedObjects
```

This command gets all AD objects that have been deleted and are currently sitting in the recycling bin.
Please note this will not return any deleted objects if the recycling bin is disabled or the object has been removed from the bin itself.

## PARAMETERS

### -AuthType
The authentication type to use when creating the `OpenAD` session.
This is used when the cmdlet creates a new connection to the `-Server` specified`.

```yaml
Type: AuthenticationMethod
Parameter Sets: ServerLDAPFilter, ServerIdentity
Aliases:
Accepted values: Default, Anonymous, Simple, Negotiate, Kerberos

Required: False
Position: Named
Default value: Default
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
The explicit credentials to use when creating the `OpenAD` session.
This is used when the cmdlet creates a new connection to the `-Server` specified.

```yaml
Type: PSCredential
Parameter Sets: ServerLDAPFilter, ServerIdentity
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Identity
Specifies the Active Directory object to search for using one fo the following formats:

+ `DistinguishedName`

+ `ObjectGUID`

The cmdlet writes an error if no, or multiple, objects are found based on the identity specified.
The `-LDAPFilter` parameter can be used instead to query for multiple objects.

```yaml
Type: ADObjectIdentity
Parameter Sets: SessionIdentity, ServerIdentity
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -IncludeDeletedObjects
Include objects that have been deleted and are sitting in the Active Directory recycling bin.
Setting this option will include the following LDAP control codes on the query:

+ Show Deleted Objects `1.2.840.113556.1.4.417`

+ Show Deactivated Links `1.2.840.113556.1.4.2065`

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

### -LDAPFilter
Used instead of `-Identity` to specify an LDAP query used to filter objects.

```yaml
Type: String
Parameter Sets: ServerLDAPFilter, SessionLDAPFilter
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Property
The attributes to retrieve for each object returned.
The values of each attribute is in the form of an LDAP attribute name and are case insensitive.
When no properties are specified the following attributes are retrieved:

+ `distinguishedName`

+ `name`

+ `objectClass`

+ `objectGUID`

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

### -SearchBase
The base Active Directory path to search the object for.
This defaults to the `defaultNamingContext` of the session connection which is typically the root of the domain.
Combine this with `-SearchScope` to limit searches to a smaller subset of the domain.

```yaml
Type: String
Parameter Sets: ServerLDAPFilter, SessionLDAPFilter
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SearchScope
Specifies the scope of an Active Directory search.
This can be set to

+ `Base` - Only searches the object at the `-SearchBase` path specified

+ `OneLevel` - Searches the immediate children of `-SearchBase`

+ `Subtree` (default) - Searches the children of `-SearchBase` and subsquent children of them

```yaml
Type: SearchScope
Parameter Sets: ServerLDAPFilter, SessionLDAPFilter
Aliases:

Required: False
Position: Named
Default value: Subtree
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
Parameter Sets: ServerLDAPFilter, ServerIdentity
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
Parameter Sets: SessionIdentity, SessionLDAPFilter
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
Parameter Sets: ServerLDAPFilter, ServerIdentity
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
Parameter Sets: ServerLDAPFilter, ServerIdentity
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

### PSOpenAD.ADObjectIdentity
The identity to get can be passed in as an input object. This can be in the form of the Distinguished Name or Object GUID.

## OUTPUTS

### PSOpenAD.OpenADObject
The `OpenADObject` representing the object(s) found. This object will always have the following properties set:

+ `DistinguishedName`

+ `Name`

+ `ObjectClass`

+ `ObjectGuid`

+ `DomainController`: This is set to the domain controller that processed the request

Any explicit attributes requested through `-Property` are also present on the object.

If an LDAP attribute on the underlying object did not have a value set but was explicitly requested then the property will be set to `$null`.

## NOTES
Unlike `Get-ADObject`, if an computer object cannot be found based on the `-Identity` requested this cmdlet will emit an error record.
Setting `-ErrorAction Stop` on the call can turn this error into an exception and have it act like `Get-ADObject`.

## RELATED LINKS

[Active Directory: LDAP Syntax Filters](https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx)
[LDAP Filters](https://ldap.com/ldap-filters/)
