---
external help file: PSOpenAD.dll-Help.xml
Module Name: PSOpenAD
online version: https://www.github.com/jborean93/PSOpenAD/blob/main/docs/en-US/Get-OpenADUser.md
schema: 2.0.0
---

# Get-OpenADUser

## SYNOPSIS
Gets one or more Active Directory users.

## SYNTAX

### ServerIdentity (Default)
```
Get-OpenADUser [-Identity] <ADPrincipalIdentity> [-Server <String>] [-AuthType <AuthenticationMethod>]
 [-SessionOption <OpenADSessionOptions>] [-StartTLS] [-Credential <PSCredential>] [-Property <String[]>]
 [<CommonParameters>]
```

### SessionIdentity
```
Get-OpenADUser [-Identity] <ADPrincipalIdentity> -Session <OpenADSession> [-Property <String[]>]
 [<CommonParameters>]
```

### SessionLDAPFilter
```
Get-OpenADUser -Session <OpenADSession> -LDAPFilter <String> [-SearchBase <String>]
 [-SearchScope <SearchScope>] [-Property <String[]>] [<CommonParameters>]
```

### ServerLDAPFilter
```
Get-OpenADUser [-Server <String>] [-AuthType <AuthenticationMethod>] [-SessionOption <OpenADSessionOptions>]
 [-StartTLS] [-Credential <PSCredential>] -LDAPFilter <String> [-SearchBase <String>]
 [-SearchScope <SearchScope>] [-Property <String[]>] [<CommonParameters>]
```

## DESCRIPTION
{{ Fill in the Description }}

## EXAMPLES

### Example 1
```powershell
PS C:\> {{ Add example code here }}
```

{{ Add example description here }}

## PARAMETERS

### -AuthType
{{ Fill AuthType Description }}

```yaml
Type: AuthenticationMethod
Parameter Sets: ServerIdentity, ServerLDAPFilter
Aliases:
Accepted values: Default, Anonymous, Simple, Negotiate, Kerberos

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
{{ Fill Credential Description }}

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
{{ Fill Identity Description }}

```yaml
Type: ADPrincipalIdentity
Parameter Sets: ServerIdentity, SessionIdentity
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -LDAPFilter
{{ Fill LDAPFilter Description }}

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
{{ Fill Property Description }}

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
{{ Fill SearchBase Description }}

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
{{ Fill SearchScope Description }}

```yaml
Type: SearchScope
Parameter Sets: SessionLDAPFilter, ServerLDAPFilter
Aliases:
Accepted values: Base, OneLevel, Subtree

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Server
{{ Fill Server Description }}

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
{{ Fill Session Description }}

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
{{ Fill SessionOption Description }}

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
{{ Fill StartTLS Description }}

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

### PSOpenAD.ADPrincipalIdentity
### System.String
## OUTPUTS

### PSOpenAD.OpenADUser
## NOTES

## RELATED LINKS
