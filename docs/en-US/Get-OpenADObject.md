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

### ServerIdentity (Default)
```
Get-OpenADObject -Identity <ADObjectIdentity> [-IncludeDeletedObjects] [-Server <String>]
 [-AuthType <AuthenticationMethod>] [-SessionOption <OpenADSessionOptions>] [-StartTLS]
 [-Credential <PSCredential>] [-Property <String[]>] [<CommonParameters>]
```

### SessionIdentity
```
Get-OpenADObject -Identity <ADObjectIdentity> [-IncludeDeletedObjects] -Session <OpenADSession>
 [-Property <String[]>] [<CommonParameters>]
```

### SessionLDAPFilter
```
Get-OpenADObject [-IncludeDeletedObjects] -Session <OpenADSession> -LDAPFilter <String> [-SearchBase <String>]
 [-SearchScope <SearchScope>] [-Property <String[]>] [<CommonParameters>]
```

### ServerLDAPFilter
```
Get-OpenADObject [-IncludeDeletedObjects] [-Server <String>] [-AuthType <AuthenticationMethod>]
 [-SessionOption <OpenADSessionOptions>] [-StartTLS] [-Credential <PSCredential>] -LDAPFilter <String>
 [-SearchBase <String>] [-SearchScope <SearchScope>] [-Property <String[]>] [<CommonParameters>]
```

## DESCRIPTION
The `Get-OpenADObject` cmdlet gets an Active Directory object or performs a search to get multiple objects.

The `-Identity` parameter specifies an individual object to retreive.
The identity for this cmdlet can either be the distinguished name or GUID.

The `-LDAPFilter` parameter can be used to search for multiple obejcts using the LDAP query language.
The filter can be combined with `-SearchBase` and `-SearchScope` to refine the search parameters used.

The cmdlet communicates in one of three way:

- Using the `-Session` object specified

- Using a cached connection to the `-Server` specified

- Using a new connection to the `-Server` specified if no cached connection exists

When a new connection is created it will be cached for subsequent use.
The connection LDAP URI is used to uniquely identify the connection and is the lookup key used when searching for an existing connection.

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

### Example 2: Get information for a specified object of an LDS instance
```powershell
PS C:\> Get-OpenADObject -Identity "DC=AppNC" -Server "FABRIKAM-SRV1"
```

This command gets the information of the domainDNS object from an explicit Active Directory.

### Example 3: Get deleted objects with a specific a

## PARAMETERS

### -AuthType
The authentication type to use when creating the `OpenAD` session.
This is used when the cmdlet creates a new connection to the server.

```yaml
Type: AuthenticationMethod
Parameter Sets: ServerIdentity, ServerLDAPFilter
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
The explicit credentials to use when creating the `OpenAD` session.
This is used when the cmdlet creates a new connection to the server.

```yaml
Type: PSCredential
Parameter Sets: ServerIdentity, ServerLDAPFilter
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Identity
Specifies the Active Directory object to search for using one fo the following formats:

+ DistinguishedName - The distinguished name of the object

+ ObjectGUID - The GUID of the object

The cmdlet writes an error if no, or multiple, objects are found based on the identity specified.
The `-LDAPFilter` parameter can be used instead to query for multiple objects.

```yaml
Type: ADObjectIdentity
Parameter Sets: ServerIdentity, SessionIdentity
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -IncludeDeletedObjects
Include objects that have been deleted and are sitting in the Active Directory recycling bin.
Setting this option will include the following LDAP control codes:

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
Parameter Sets: SessionLDAPFilter, ServerLDAPFilter
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Property
The attributes to retrieve from the server.
The values of each attribute is in the form of an LDAP attribute name and are case insensitive.
By default only the `distinguishedName`, `name`, `objectClass`, and `objectGUID` attributes are retrieved in a query.
Any attributes specified by this parameter will be added to the list above.
Specify `*` to display all attributes that are set on the object.
Any attributes not set on the object will not be returned with `*` and must be explicitly defined for it to return on the output object.

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
COmbine this with `-SearchScope` to limit searches to a smaller subset of the domain.

```yaml
Type: String
Parameter Sets: SessionLDAPFilter, ServerLDAPFilter
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
Parameter Sets: SessionLDAPFilter, ServerLDAPFilter
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Server
The Active Directory server to connect to if `-Session` is not specified.
This can either be the name of the server or the LDAP connection uri starting with `ldap://` or `ldaps://`.
The derived URI of this value is used to find any existing connections that are available for use or will be used to create a new session if no cached session exists.
If both `-Server` and `-Session` are not specified then the default Kerberos realm is used if available otherwise it will generate an error.

This option is mutually exclusive with `-Session`.

```yaml
Type: String
Parameter Sets: ServerIdentity, ServerLDAPFilter
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
Parameter Sets: ServerIdentity, ServerLDAPFilter
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
Parameter Sets: ServerIdentity, ServerLDAPFilter
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

+ `DistinguishedName` - The distinguished name of the AD object

+ `Name` - The name of the AD object

+ `ObjectClass` - The class of the AD object

+ `ObjectGuid` - The GUID of the AD object

Every other attribute specified by `-Property` will also be present on the object if available. If `-Property *` was specified then all set attributes of that object will be present as a property on the output object.

## NOTES

## RELATED LINKS
