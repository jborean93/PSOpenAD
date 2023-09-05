---
external help file: PSOpenAD.Module.dll-Help.xml
Module Name: PSOpenAD
online version: https://www.github.com/jborean93/PSOpenAD/blob/main/docs/en-US/Get-OpenADRootDSE.md
schema: 2.0.0
---

# Get-OpenADRootDSE

## SYNOPSIS
Gets the root of a directory server information tree.

## SYNTAX

### Session
```
Get-OpenADRootDSE [-Property <String[]>] -Session <OpenADSession> [<CommonParameters>]
```

### Server
```
Get-OpenADRootDSE [-Property <String[]>] [-Server <String>] [-AuthType <AuthenticationMethod>]
 [-SessionOption <OpenADSessionOptions>] [-StartTLS] [-Credential <PSCredential>] [<CommonParameters>]
```

## DESCRIPTION
The `Get-OpenADRootDSE` cmdlet gets the object that represents the root of the directory information tree of a directory server.
This tree provides information about the configuration and capabilities of the directory server, such as the distinguished name for the configuration container, the current time on the directory server, and the functional levels of the directory server and the domain.

## EXAMPLES

### Example 1: Get the root of a directory server information tree
```powershell
PS C:\> Get-OpenADRootDSE
DomainController              : DC01.domain.test
ConfigurationNamingContext    : CN=Configuration,DC=domain,DC=test
CurrentTime                   : 4/9/2023 10:12:11pm +00:00
DefaultNamingContext          : DC=domain,DC=test
DnsHostName                   : DC01.domain.test
DomainControllerFunctionality : Windows2016
DomainFunctionality           : Windows2016Domain
DsServiceName                 : CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=domain,DC=test
ForestFunctionality           : Windows2016Forest
HighestCommittedUSN           : 1069399
IsGlobalCatalogReady          : True
IsSynchronized                : True
LdapServiceName               : domain.test:dc01$@DOMAIN.TEST
NamingContexts                : {DC=domain,DC=test, CN=Configuration,DC=domain,DC=test, CN=Schema,CN=Configuration,DC=domain,DC=test,
                                DC=DomainDnsZones,DC=domain,DC=test…}
RootDomainNamingContext       : DC=domain,DC=test
SchemaNamingContext           : CN=Schema,CN=Configuration,DC=domain,DC=test
ServerName                    : CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=domain,DC=test
SubschemaSubentry             : CN=Aggregate,CN=Schema,CN=Configuration,DC=domain,DC=test
SupportedCapabilities         : {1.2.840.113556.1.4.800 (LDAP_CAP_ACTIVE_DIRECTORY_OID), 1.2.840.113556.1.4.1670
                                (LDAP_CAP_ACTIVE_DIRECTORY_V51_OID), 1.2.840.113556.1.4.1791 (LDAP_CAP_ACTIVE_DIRECTORY_LDAP_INTEG_OID),
                                1.2.840.113556.1.4.1935 (LDAP_CAP_ACTIVE_DIRECTORY_V61_OID)…}
SupportedControl              : {1.2.840.113556.1.4.319 (LDAP_PAGED_RESULT_OID_STRING), 1.2.840.113556.1.4.801 (LDAP_SERVER_SD_FLAGS_OID),
                                1.2.840.113556.1.4.473 (LDAP_SERVER_SORT_OID), 1.2.840.113556.1.4.528 (LDAP_SERVER_NOTIFICATION_OID)…}
SupportedLDAPPolicies         : {MaxPoolThreads, MaxPercentDirSyncRequests, MaxDatagramRecv, MaxReceiveBuffer…}
SupportedLDAPVersion          : {3, 2}
SupportedSASLMechanisms       : {GSSAPI, GSS-SPNEGO, EXTERNAL, DIGEST-MD5}
```

This command gets the root of the directory server information tree of the directory server from the default domain controller.

### Example 2: Get the root of the directory server information tree with the specified property
```powershell
PS C:\> Get-OpenADRootDSE -Server Fabrikam-RODC1 -Property supportedExtension
```

This command gets the root of the directory server information, including the `supportedExtension` property for the domain controller `Fabrikam-RODC1`.

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

### -Property
Specifies the properties/attributes to retrieve for the root DSE entry.
Use this parameter to retrieve properties that are not included in the default set.

All the extra properties requested are added as note properties on the output object.

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
This cmdlet does not support any pipeline input.

## OUTPUTS

### PSOpenAD.OpenADEntity
An object that contains the AD Root DSE properties.

## NOTES

## RELATED LINKS

[MS-ADTS rootDSE Attributes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/96f7b086-1ca3-4764-9a08-33f8f7a543db)
