# Open AD LDAP Attribute Formats
## about_OpenADAttributeFormats

# SHORT DESCRIPTION
Setting the attributes/properties of an AD object is a common scenario of this module.
This document will go through how to set values for attributes and how values are transformed over the LDAP protocol.

# LONG DESCRIPTION
The [New-OpenADObject](./New-OpenADObject.md) and [Set-OpenADObject](./Set-OpenADObject.md) cmdlets allow you to set any LDAP attribute value(s) based on a PowerShell object.
It is important to use the correct object type for the value when setting attributes that expect a specific type.
This is because the cmdlets will not transform the value based on the attribute specified but rather transform it based on the value provided.
For example trying to set a `DateTime` or `DateTimeOffset` value to an LDAP attribute that accepts a string representing the `DateTime` will fail.

## LDAP Syntaxes
Knowing what type to use when setting an LDAP attribute is key and should be the first step done when trying to manage an attribute.
As LDAP contains a schema of the data it is possible to see the available attributes as well as the type they expect.
The following script can be used to retrieve a specific or multiple attributes and see what their `attributeSyntax` and `oMSyntax` values are.

```powershell
Function Get-AttributeMetadata {
    [CmdletBinding()]
    param ([Parameter(ValueFromPipeline)][string[]]$Name)

    begin {
        $schema = (Get-OpenADRootDSE -Properties schemaNamingContext).schemaNamingContext
        $getParams = @{
            SearchBase = $schema
            LDAPFilter = '(objectClass=attributeSchema)'
            Properties = 'lDAPDisplayName', 'attributeSyntax', 'oMSyntax'
        }
        $attributes = Get-OpenADObject @getParams | Select-Object -Property @(
            @{ N = 'Name'; E = { $_.LDAPDisplayName } },
            'AttributeSyntax',
            'OMSyntax'
        )
        $queried = $false
    }

    process {
        foreach ($n in $Name) {
            $queried = $true
            $attributes | Where-Object Name -like $n
        }
    }

    end {
        if (-not $queried) {
            $attributes
        }
    }
}
```

By default this outputs all the attributes, their `attributeSyntax` and `oMSyntax`, the cmdlet can be used to filter it by name if desired.

Here are some common `attributeSyntax` and `oMSyntax` combinations and what type should be used when setting them in this module.

|Name|AttributeSyntax|OMSyntax|Type|
|-|-|-|-|
|[Object(DS-DN)](https://learn.microsoft.com/en-us/windows/win32/adschema/s-object-ds-dn)|2.5.5.1|127|LDAP DistinguishedName as a string|
|[String(Object-Identifier)](https://learn.microsoft.com/en-us/windows/win32/adschema/s-string-object-identifier)|2.5.5.2|6|OID dotted notation as a string|
|[String(Teletex)](https://learn.microsoft.com/en-us/windows/win32/adschema/s-string-teletex)|2.5.5.4|20|A string with characters restricted to the Teletex character set|
|[String(IA5)](https://learn.microsoft.com/en-us/windows/win32/adschema/s-string-ia5)|2.5.5.5|19|A string with characters restricted to the IA5 character set (ASCII)|
|[String(IA5)](https://learn.microsoft.com/en-us/windows/win32/adschema/s-string-ia5)|2.5.5.5|22|A string with characters restricted to the IA5 character set (ASCII)|
|[String(Numeric)](https://learn.microsoft.com/en-us/windows/win32/adschema/s-string-numeric)|2.5.5.6|18|A string that contains digits only, can also be set from an integer|
|[Object(DN-Binary)](https://learn.microsoft.com/en-us/windows/win32/adschema/s-object-dn-binary)|2.5.5.7|127|A string in the format `B:<char count>:<binary value>:<object DN>`, see `New-ObjectDNBinary` below|
|[Boolean](https://learn.microsoft.com/en-us/windows/win32/adschema/s-boolean)|2.5.5.8|1|A boolean value; `$true` or `$false`, can also be the string `TRUE` or `FALSE`|
|[Enumeration](https://learn.microsoft.com/en-us/windows/win32/adschema/s-enumeration)|2.5.5.9|2|An integer value with well known constants, see the documentation for each specific attribute for more information|
|[Enumeration](https://learn.microsoft.com/en-us/windows/win32/adschema/s-enumeration)|2.5.5.9|10|See above|
|[String(Generalized-Time)](https://learn.microsoft.com/en-us/windows/win32/adschema/s-string-generalized-time)|2.5.5.11|23|String in the format `YYYYMMDDHHMMSS.0Z` or `YYYYMMDDHHMMSS.0[+/-]HHMM`|
|[String(Generalized-Time)](https://learn.microsoft.com/en-us/windows/win32/adschema/s-string-generalized-time)|2.5.5.11|24|See above|
|[String(Unicode)](https://learn.microsoft.com/en-us/windows/win32/adschema/s-string-unicode)|2.5.5.12|64|A string|
|[String(NT-Sec-Desc)](https://learn.microsoft.com/en-us/windows/win32/adschema/s-string-nt-sec-desc)|2.5.5.15|66|A SecurityDescriptor object, see `CommonSecurityDescriptor` below|
|[Interval](https://learn.microsoft.com/en-us/windows/win32/adschema/s-interval)|2.5.5.16|65|A `LargeInteger` value, either use an int or `DateTime` object|
|[String(Sid)](https://learn.microsoft.com/en-us/windows/win32/adschema/s-string-sid)|2.5.5.17|4|A SecurityIdentifier object, see `SecurityIdentifier` below|

Some helper functions to create some of the more complex values are below:

```powershell
Function New-ObjectDNBinary {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [byte[]]
        $Value,

        [Parameter(Mandatory)]
        [string]
        $DN
    )

    $binaryHex = [Convert]::ToHexString($Value)

    "B:$($binaryHex.Length):${binaryHex}:$DN"
}
```

See [MS-ADTS LDAP Representations](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7cda533e-d7a4-4aec-a517-91d02ff4a1aa) for more information on how AD maps the `attributeSyntax` and `oMSyntax` to a specific type.
See [Active Directory Attributes](https://learn.microsoft.com/en-us/windows/win32/adschema/attributes-all) for definitions of every builtin class to AD and their syntax inforamtion, note they are keyed by the AD name and not `lDAPDisplayName`.
[RFC 4517](https://www.rfc-editor.org/rfc/rfc4517) and [LDAP Attribute Syntaxes](https://ldap.com/attribute-syntaxes/) contains more background information on the various syntaxes and the formats they allow.

## Type Transformers
This module includes some builtin type transformers to convert specific objects into a more friendly LDAP represetnation.
The following table demonstrates how each specific type is transformed into the raw LDAP value to set and what LDAP type they are useful for.

|Type|Behaviour|For Attribute|
|-|-|-|
|$null|No values/empty||
|bool|Either `TRUE` or `FALSE`|`Boolean`|
|CommonSecurityDescriptor|The raw byte[] representation of the SD|`String(NT-Sec-Desc)`|
|Enum|The integer value of the enum|`Enumeration`|
|DateTime|The UTC FILETIME integer value and not the string representation of the DateTime|`Interval`|
|DateTimeOffset|Will use the UTC FILETIME integer value and not the string representation of the DateTime|`Interval`|
|Guid|The raw byte[] representation of the Guid||
|SecurityIdentifier|The raw byte[] representation of the SID|`String(Sid)`|
|TimeSpan|The number of ticks (100s of nanoseconds) is used as an integer value|`Interval`|
|X509Certificate|The raw byte[] of the certificate in DER form||

If the type is not listed the value is converted to a string and sent as is.
For example setting an integer value `100` is the same as setting `'100'` as a string.

## DateTime values
Settings a `DateTime` value is a complex scenario as the value provided to the cmdlet is based on whether the underlying LDAP attribute accepts a `GeneralizedTime` or `FILETIME` value.
For a `GeneralizedTime` the `DateTime` needs to be provided as a string in a specific format:

```powershell
$dt = Get-Date
$dt.ToString("yyyyMMddhhmmss.fzzz").Replace(':', '')
```

Some LDAP implementations may differ in what format they expect but if it's an LDAP 3 compliant server then the above should work.

For a `FILETIME` value or even just a `LargeInteger` attribute the `DateTime` object can be provided as is.
The cmdlet will do `$dt.ToFileTimeUtc()` and use that raw integer value as the one to set.
