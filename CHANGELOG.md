# Changelog for PSOpenAD

## v0.1.0 - 2022-07-09

+ Fix up `Get-OpenAD*` calls where there is no valid metadata to calculate the valid properties.
+ Minor tweaks to error messages when using an un-authenticated bind.

## v0.1.0-preview5 - 2022-06-27

+ Fix up edge case for calculating input LDAP message lengths causing an unpack exception
+ Make the AD object properties in a `Get-*` operation return with the first character in upper case to fit the PowerShell standard
+ Validate the requested `-Properties` on `Get-OpenAD*` cmdlets are valid for the object class that is being queried
  + Invalid properties/attributes will result in a pipeling terminating error
+ Various fixes to the tab completion of `-Properties` on `Get-OpenAD*`
  + The order will now be in alphabetical order
  + Include attributes that are defined on auxiliary types as well as sub types
+ Ensures that the `-Properties` selected on `Get-OpenAD*` will exist in the output object
  + If a property was requested but not set on the LDAP object, the property will now be set to `$null` rather than be missing
  + This is a change from the Microsoft `ActiveDirectory` module which omits the properties entirely if the attribute did not have a value
+ Ensure connections that have timed out are not reused causing a deadlock
+ Ensure `Get-OpenADUser` also filtered by `(objectClass=user)` to avoid pulling in contacts

## v0.1.0-preview4 - 2022-06-15

+ Added error handling for search request that ends with a referral
  + Currently the cmdlet will emit an error record with the referral URI which is similar to what the AD cmdlets do
+ Have exceptions in the background recv thread tasks bubble up as inner exceptions to preserve the stack trace for better debugging
+ Fix authentication with explicit credential on Windows
+ Added `-TracePath` to `New-OpenADSessionOption` to help debug raw LDAP traffice exchanged in a session.
+ Fix credential prompt when specifying `-Credential my-username` for a `PSCredential` parameter
+ Have `Get-OpenADWhoami` return an object with more details on the LDAP session, like the domain controller DNS name, URI, and authentication method used.
  + The returned username value will also strip the leading `u:` prefix if it is present
+ Added the `DomainController` property to the `OpenADSession` class to help identify the domain controller the session is connected to
+ Fixed the default parameter sets of the `Get-OpenAD*` cmdlets to always use the default LDAP filter that selects all of that type unless an explicit filter or identity was provided
+ Added `-ClientCertificate` to `New-OpenADSessionOption` that is used to authenticate using a client X.509 certificate
+ Raise `UnpackLDAPMessageException` when failing to unpack a response from the server.
  + The exception contains the `LDAPMessage` property which is the raw byte string that was being unpacked.
+ Added the `DomainController` property to the results of any `Get-OpenAD*` objects to help identify what domain controller returned that information

## v0.1.0-preview3 - 2022-03-22

+ Allow using `hostname:port` syntax when using `-Server` rather than always requiring the full LDAP URI
+ Add pagination search control to search requests to retrieve large datasets back from the domain controller
+ Fix length calculation bug when parsing an LDAP control on a returned response

## v0.1.0-preview2 - 2022-02-22

+ Improve GSSAPI and Kebreros library loading
+ Added error messages to describe why PSOpenAD failed to find the implicit DC host
+ Change `-UseSSL` to `-UseTLS`
+ Always add `$` to the `-Identity` of `Get-OpenADComputer` and `Get-OpenADServiceAccount` when using a `sAMAccountName`
+ Fix piping of multiple `-Identity` values into the `Get-OpenAD*` cmdlets

## v0.1.0-preview1 - 2022-02-1

+ Initial version of the `PSOpenAD` module
