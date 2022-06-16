# Open AD Comparison With ActiveDirectory
## about_OpenADComparison

# SHORT DESCRIPTION
While this module follows a similar setup to the Microsoft [ActiveDirectory module](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps) there are some differences.
This document will attempt to explain those differences and why they exist.

# LONG DESCRIPTION
On a technical perspective one of the key differences with this module compared to the `ActiveDirectory` module is that `PSOpenAD` uses LDAP for communication with the domain controller.
The `ActiveDirectory` module uses a SOAP based API to communicate through the Active Directory Web Services protocol.
In practical terms, the main difference will be the port used for communication from the client to the domain controller, LDAP runs over port `389` or `636` (TLS).

# LDAPFilter vs Filter
The `Get-OpenAD*` cmdlets do not implement the `-Filter` property that exists on the `Get-AD*` cmdlets.
There are no plans on implementing the conversion that exists for `-Filter` as the alternative `-LDAPFilter` is available.
The docs for [Active Directory: LDAP Syntax Filters](https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx) cover a lot of the various filters that are available and how they are formatted.

# Output Properties on Get Operations
There are a few differences in the output object that the `Get-OpenAD*` cmdlets have compared to their `Get-AD*` counterparts.
Some of the key differences are:

+ The requested attributes are returned in PascalCase and not the camelCase format the LDAP attributes are written as

While the ActiveDirectory module does this for some return properties there are still some others that use the camelCase format.
The PSOpenAD module will always set the return properties to be in the PascalCase format.

+ Properties explicitly requested but not set on the underlying object will still be present in the output object

The PSOpenAD cmdlets will always return a note property for any property that was explicitly requested.
This ensures that the output objects from a cmdlet call have a consistent set of properties rather than what was originally requested.
Return objects can still have a dynamic set of properties as things like `-Properties *` only return properties for attributes that have a set value.

+ Using `-Properties *` will return less

The ActiveDirectory module hard codes a set of properties to always return when requesting `-Properties *` whereas `PSOpenAD` open return the LDAP attributes that have a set value.
To ensure a property is always present on the output object it is recommended to explicitly request that property.

+ Aliased properties like `lastLogonDate` are not returned

Certain properties that the ActiveDirectory module return are not present in the PSOpenAD output objects.
PSOpenAD is designed to return the LDAP attributes as they are without aliases, with some small exceptions.

+ Some property types are different

PSOpenAD will convert the LDAP attribute values requested to .NET types that better align with what the value represents.
Some of the types that will be used are

+ Interval values that represent a date will become [DateTimeOffset](https://docs.microsoft.com/en-us/dotnet/api/system.datetimeoffset?view=net-6.0
* Interval values that represent a time span will become [TimeSpan](https://docs.microsoft.com/en-us/dotnet/api/system.timespan?view=net-6.0)
* Known enum values will be represent by an enum rather than the raw integer value
* GUID values will become [Guid](https://docs.microsoft.com/en-us/dotnet/api/system.guid?view=net-6.0)
* Security Identifiers will become a custom Security Identifier class that works on both Windows and non-Windows
  * Translating these values back to an account name is only possible on Windows with `[System.Security.Principal.SecurityIdentifier]::new($obj.ObjectSid).Translate([System.Security.Principal.NTAccount])`
* Security Descriptors will become a custom security descriptor class that works on both Windows and non-Windows

This is not a complete list but should be the main ones encountered when using the PSOpenAD modules.

# Tab Completion Support
To make the cmdlets easier to use and be more discoverable, the `Get-OpenAD*` cmdlets offer tab completion for properties like `-Properties`.
For tab completion to work there has to have been at least 1 session created by the client so the schema is cached for the completion.
Once the schema has been cached tab completion can be used to discover the various properties that are valid for the `Get-OpenAD*` cmdlet that is being used.
