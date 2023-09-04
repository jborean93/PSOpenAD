---
external help file: PSOpenAD.Module.dll-Help.xml
Module Name: PSOpenAD
online version: https://www.github.com/jborean93/PSOpenAD/blob/main/docs/en-US/Get-OpenADServiceAccount.md
schema: 2.0.0
---

# Get-OpenADServiceAccount

## SYNOPSIS
Gets one or more Active Directory managed service accounts or group managed service accounts.

## SYNTAX

### ServerLDAPFilter (Default)
```
Get-OpenADServiceAccount [-Server <String>] [-AuthType <AuthenticationMethod>]
 [-SessionOption <OpenADSessionOptions>] [-StartTLS] [-Credential <PSCredential>] [-LDAPFilter <String>]
 [-SearchBase <String>] [-SearchScope <SearchScope>] [-Property <String[]>] [<CommonParameters>]
```

### SessionIdentity
```
Get-OpenADServiceAccount -Session <OpenADSession> [-Identity] <ADPrincipalIdentityWithDollar>
 [-Property <String[]>] [<CommonParameters>]
```

### SessionLDAPFilter
```
Get-OpenADServiceAccount -Session <OpenADSession> [-LDAPFilter <String>] [-SearchBase <String>]
 [-SearchScope <SearchScope>] [-Property <String[]>] [<CommonParameters>]
```

### ServerIdentity
```
Get-OpenADServiceAccount [-Server <String>] [-AuthType <AuthenticationMethod>]
 [-SessionOption <OpenADSessionOptions>] [-StartTLS] [-Credential <PSCredential>]
 [-Identity] <ADPrincipalIdentityWithDollar> [-Property <String[]>] [<CommonParameters>]
```

## DESCRIPTION
The `Get-OpenADServiceAccount` cmdlet gets a service account or perforams a search to retrieve multiple service accounts.
Specifying no `-Identity` or `-LDAPFilter` parameter will result in a query of just `(objectCategory=msDS-GroupManagedServiceAccount)`.
Otherwise that will be be used as an AND condition of the query specified by the caller, e.g. `(&(objectCategory=msDS-GroupManagedServiceAccount)(...))`.

The `-Identity` parameter specifies the Active Directory service account to retrieve.
You can identify a service account by its distinguished name, GUID, security identifier, user principal name, or SAM account name.

The `-LDAPFilter` parameter can be used to retrieve multiple service account objects using the filter required.
The LDAP filter value is in the form of an LDAP filter string.

The cmdlet communicates with the LDAP server in one of three ways:

+ Using the implicit AD connection based on the current environment

+ Using the `-Session` object specified

+ Using a new or cached connection to the `-Server` specified

For more information on Open AD sessions, see [about_OpenADSessions](./about_OpenADSessions.md).

The output for each service account retrieves a default set of service account object properties as documented in the `OUTPUT` section.
Any additional properties can be requested with the `-Property` parameter in the form of the LDAP property name desired.

## EXAMPLES

### Example 1: Get all service accounts in the target LDAP connection
```powershell
PS C:\> Get-OpenADServiceAccount
```

This command retrieves all AD service account objects (`(objectCategory=msDS-GroupManagedServiceAccount)`) in the implicit AD connection.

### Example 2: Get specific service account from a specific LDAP instance using the distinguished name
```powershell
PS C:\> Get-OpenADServiceAccount -Identity "CN=mygMSA,CN=Managed Service Accounts,DC=domain,DC=test" -Server dc.domain.test
```

This command retrieves the AD service account object `Workstation` under `OU=City,DC=domain,DC=test` from the specific LDAP server `dc.domain.test`.

### Example 3: Get all service accounts with a name starting with APP
```powershell
PS C:\> Get-OpenADServiceAccount -LDAPFilter "(name=APP*)"
```

This commands gets all the service accounts that have the `name` LDAP attribute that starts with `APP`.

### Example 4: Get extra properties for a service account
```powershell
PS C:\> $filter = "(&(sAMAccountName=*APP*)(logonCount>=1))"
PS C:\> Get-OpenADServiceAccount -LDAPFilter $filter -Property whenCreated, userAccountControl
```

This command gets all service accounts that match the filter and also gets the LDAP attributes `whenCreated` and `userAccountControl` in addition to the default properties.

### Example 5: Get all properties for a service account
```powershell
PS C:\> Get-OpenADServiceAccount -Property *
```

This command get all the service account objects in addition to all the properties that have a value set.

## PARAMETERS

### -AuthType
The authentication type to use when creating the `OpenAD` session.
This is used when the cmdlet creates a new connection to the `-Server` specified`.

```yaml
Type: AuthenticationMethod
Parameter Sets: ServerLDAPFilter, ServerIdentity
Aliases:
Accepted values: Default, Anonymous, Simple, Negotiate, Kerberos, Certificate

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
Specifies the Active Directory service account object to search for using one fo the following formats:

+ `DistinguishedName`

+ `ObjectGUID`

+ `ObjectSID`

+ `UserPrincipalName`

+ `SamAccountName`

The cmdlet writes an error if no, or multiple, objects are found based on the identity specified.
In addition the identity is filtered by the LDAP filter `(objectCategory=msDS-GroupManagedServiceAccount)` to restrict only service account objects from being searched.
The `-LDAPFilter` parameter can be used instead to query for multiple objects.

```yaml
Type: ADPrincipalIdentityWithDollar
Parameter Sets: SessionIdentity, ServerIdentity
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -LDAPFilter
Used instead of `-Identity` to specify an LDAP query used to filter service account objects.
The filter specified here will be used with an `AND` condition to `(objectCategory=msDS-GroupManagedServiceAccount)`.

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
The attributes to retrieve for each service account object returned.
The values of each attribute is in the form of an LDAP attribute name and are case insensitive.
When no properties are specified the following attributes are retrieved:

+ `distinguishedName`

+ `name`

+ `objectClass`

+ `objectGUID`

+ `sAMAccountName`

+ `objectSid`

+ `userPrincipalName`

+ `servicePrincipalName`

Any attributes specified by this parameter will be added to the list above.
Specify `*` to display all attributes that are set on the object.
Any attributes on the object that do not have a value set will not be returned with `*` unless they were also explicitly requested.
These unset attributes must be explicitly defined for it to return on the output object.

If there has been a successful connection to any LDAP server this option supports tab completion.
The possible properties shown in the tab completion are based on the schema returned by the server for the `msDS-GroupManagedServiceAccount` object class.
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
Accepted values: Base, OneLevel, Subtree

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

### System.String
### PSOpenAD.ADPrincipalIdentityWithDollar
The identity in it's various forms can be piped into the cmdlet.

## OUTPUTS

### PSOpenAD.OpenADServiceAccount
The `OpenADServiceAccount` representing the object(s) found. This object will always have the following properties set:

+ `DistinguishedName`

+ `Name`

+ `ObjectClass`

+ `ObjectGuid`

+ `SamAccountName`

+ `SID`

+ `Enabled`

+ `UserPrincipalName`

+ `ServicePrincipalNames`

+ `DomainController`: This is set to the domain controller that processed the request

Any explicit attributes requested through `-Property` are also present on the object.

If an LDAP attribute on the underlying object did not have a value set but was explicitly requested then the property will be set to `$null`.

## NOTES
Unlike `Get-OpenADServiceAccount`, if a service account object cannot be found based on the `-Identity` requested this cmdlet will emit an error record.
Setting `-ErrorAction Stop` on the call can turn this error into an exception and have it act like `Get-OpenADServiceAccount`.

## RELATED LINKS

[Active Directory: LDAP Syntax Filters](https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx)
[LDAP Filters](https://ldap.com/ldap-filters/)
