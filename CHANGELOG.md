# Changelog for PSOpenAD

## v0.1.0-preview2 - TBD

+ Improve GSSAPI and Kebreros library loading
+ Added error messages to describe why PSOpenAD failed to find the implicit DC host
+ Change `-UseSSL` to `-UseTLS`
+ Always add `$` to the `-Identity` of `Get-OpenADComputer` and `Get-OpenADServiceAccount` when using a `sAMAccountName`
+ Fix piping of multiple `-Identity` values into the `Get-OpenAD*` cmdlets

## v0.1.0-preview1 - 2022-02-1

+ Initial version of the `PSOpenAD` module
