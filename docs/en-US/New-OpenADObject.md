---
external help file: PSOpenAD.Module.dll-Help.xml
Module Name: PSOpenAD
online version: https://www.github.com/jborean93/PSOpenAD/blob/main/docs/en-US/New-OpenADObject.md
schema: 2.0.0
---

# New-OpenADObject

## SYNOPSIS
Creates an Active Directory object.

## SYNTAX

### Server (Default)
```
New-OpenADObject [-Name] <String> [-Type] <String> [-Description <String>] [-DisplayName <String>]
 [-Path <String>] [-OtherAttributes <IDictionary>] [-PassThru] [-Server <String>]
 [-AuthType <AuthenticationMethod>] [-SessionOption <OpenADSessionOptions>] [-StartTLS]
 [-Credential <PSCredential>] [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

### Session
```
New-OpenADObject [-Name] <String> [-Type] <String> [-Description <String>] [-DisplayName <String>]
 [-Path <String>] [-OtherAttributes <IDictionary>] [-PassThru] -Session <OpenADSession>
 [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
The `New-OpenADObject` cmdlet creates an Active Directory object such as a new organizational unit (OU) or a new user account.
This cmdlet can be used to create any type of Active Directory object.

The `-Name` and `-Type` parameters must be set to create a new object.
The `-Name `parameter specifies the name of the new object.
The `-Type` parameter specifies the LDAP `objectClass` of the object to create, for example `computer`, `group`, `ou`, `contact`, `user`, etc.

The `-Path` parameter specifies the container where the object is created.
If no `-Path` is specified, the default path will be the default naming context container for the AD session.

See [about_OpenADAttributeFormats](./about_OpenADAttributeFormats.md) for more information on setting attribute values.

## EXAMPLES

### Example 1: Create a subject object
```powershell
PS C:\> $newParams = @{
    Name = "192.168.1.0/26"
    Type = "subnet"
    Description = "192.168.1.0/255.255.255.192"
    OtherAttributes = @{
        location = "Building A"
        siteObject = "CN=HQ,CN=Sites,CN=Configuration,DC=FABRIKAM,DC=COM"
    }
    Path = "CN=Subnets,CN=Sites,CN=Configuration,DC=FABRIKAM,DC=COM"
}
PS C:\> New-OpenADObject @newParams
```

This command creates a subnet object in the HQ site with the described attributes.

### Exapmle 2: Create a contact object
```powershell
PS C:\> $newParams = @{
    Name = "UserContact"
    Type = "contact"
    OtherAttributes = @{
        'msDS-SourceObjectDN' = 'CN=FabrikamContacts,DC=domain,DC=test'
    }
}
PS C:\> New-OpenADObject @newParams
```

This command creates a new contact object and sets the `msDS-SourceObjectDN` property.

### Example 3: Create a container object
```powershell
PS C:\> New-OpenADObject -Name Apps -Type container
```

This command creates a new container object named `Apps`.

### Example 4: Create a new user object
```powershell
PS C:\> $password = 'Password123!'
PS C:\> $newParams = @{
    Name = 'MyUser'
    Type = 'user'
    Path = 'CN=Users,DC=domain,DC=test'
    OtherAttributes = @{
        sAMAccountName = 'MyUser'
        userPrincipalName = 'MyUser@DOMAIN.TEST'
        # It is important the password string is surrounded by the double quotes
        unicodePwd = [System.Text.Encoding]::Unicode.GetBytes('"{0}"' -f $password)
        givenName = 'First Name'
        sn = 'Last Name'
        userAccountControl = [PSOpenAD.UserAccountControl]::NormalAccount
    }
}
PS C:\> New-OpenADObject @newParams
```

This command create a new user object named `MyUser`.
The `unicodePwd` value is a specially formatted string that must be wrapped with double quotes in the inner value and then set as the UTF-16-LE bytes of that string.
_Note: this may fail to work if the LDAP connection is not encrypted either by the authentication protocol or through TLS._

### Example 5: Create a new group object
```powershell
PS C:\> $newParams = @{
    Name = 'MyGroup'
    Type = 'group'
    Path = 'CN=Users,DC=domain,DC=test'
    OtherAttributes = @{
        sAMAccountName = 'MyGroup'
    }
}
PS C:\> New-OpenADObject @newParams
```

This command creates a new group object named `MyGroup`.

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

### -Description
Specifies the description of the object to create.
The LDAP display name of this attribute is `description`.

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
Specifies the display name of the object to create.
The LDAP display name of this attribute is `displayName`.

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

### -Name
The name of the object to create.
The LDAP display name of this attribute is `name`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -OtherAttributes
Specifies object attribute values for attributes that are not exposed by this cmdlet.
The hashtable keys are the LDAP attribute names to set and the values is one or more values to set for that attribute.
To set multiple values use an array as the value for the key.

The following types are support for the value(s):

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

### -PassThru
Returns an object representing the item that was created.
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

### -Path
Specifies the LDAP distinguished name of the OU or container where the new object is created.
If no path is specified, the default path is the default naming context of the target domain.

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

### -Type
Specifies the type of object to create.
Examples of type values include `user`, `computer`, and `group`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
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

### None
This cmdlet does not accept pipeline input.

## OUTPUTS

### PSOpenAD.OpenADObject
Returns the new Active Directory object when the `-PassThru` parameter is specified. By default, this cmdlet does not generate any output. The output object will have all the default `OpenADObject` properties set plus any of the properties specified by `-OtherAttributes`.

## NOTES

## RELATED LINKS
