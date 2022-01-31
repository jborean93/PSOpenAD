# PSOpenAD
## about_PSOpenAD

# SHORT DESCRIPTION
The Open AD module is a cross platform module for managing Active Directory.

# LONG DESCRIPTION
This module is a module designed to replicate the functionality in the Windows [ActiveDirectory](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps).
It does not rely on any native libraries to communicate to the LDAP server allowing it to work across the various OS platforms that PowerShell can run as.
Currently the module is limited to just getting data from an LDAP/AD environment but the goal is to eventually add in more features over time.

A list of the cmdlets in this module can be found at [PSOpenAD](./PSOpenAD.md).

The [about_OpenADAuthentication](./about_OpenADAuthentication.md) docs go into futher detail how authentication works against an LDAP/AD server.
It also explains how to set up authentication on non-Windows hosts.

The [about_OpenADSessions](./about_OpenADSessions.md) docs talk about an OpenAD session and how they are managed in this module.
