# PSOpenAD

[![Test workflow](https://github.com/jborean93/PSOpenAD/workflows/Test%20PSOpenAD/badge.svg)](https://github.com/jborean93/PSOpenAD/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/jborean93/PSOpenAD/branch/main/graph/badge.svg?token=b51IOhpLfQ)](https://codecov.io/gh/jborean93/PSOpenAD)
[![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/PSOpenAD.svg)](https://www.powershellgallery.com/packages/PSOpenAD)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jborean93/PSOpenAD/blob/main/LICENSE)

PSOpenAD aims to be a cross-platform PowerShell module alternative to Microsoft's Active Directory module, enhancing AD management with modern capabilities.

See [about_PSOpenAD](docs/en-US/about_PSOpenAD.md) for more details.

## Documentation

Documentation for this module and details on the cmdlets included can be found [here](docs/en-US/PSOpenAD.md).

## Requirements

These cmdlets have the following requirements

* PowerShell v7.4 or newer

## Installing

The easiest way to install this module is through [PowerShellGet](https://docs.microsoft.com/en-us/powershell/gallery/overview) or [PSResourceGet](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.psresourceget/?view=powershellget-3.x).

You can install this module by running either of the following `Install-PSResource` or `Install-Module` command.

```powershell
# Install for only the current user
Install-PSResource -Name PSOpenAD -Scope CurrentUser
Install-Module -Name PSOpenAD -Scope CurrentUser

# Install for all users
Install-PSResource -Name PSOpenAD -Scope AllUsers
Install-Module -Name PSOpenAD -Scope AllUsers
```

The `Install-PSResource` cmdlet is part of the new `PSResourceGet` module from Microsoft available in newer versions while `Install-Module` is present on older systems.

## Contributing

Contributing is quite easy, fork this repo and submit a pull request with the changes.
To build this module run `.\build.ps1 -Task Build` in PowerShell.
To test a build run `.\build.ps1 -Task Test` in PowerShell.
The script `./tools/run-samba.sh` can be used to run Samba inside a test container that is needed to run some of the tests locally.
This script will ensure all dependencies are installed before running the test suite.
