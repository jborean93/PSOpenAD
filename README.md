# PSOpenAD

[![Test workflow](https://github.com/jborean93/PSOpenAD/workflows/Test%20PSOpenAD/badge.svg)](https://github.com/jborean93/PSOpenAD/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/jborean93/PSOpenAD/branch/main/graph/badge.svg?token=b51IOhpLfQ)](https://codecov.io/gh/jborean93/PSOpenAD)
[![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/PSOpenAD.svg)](https://www.powershellgallery.com/packages/PSOpenAD)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jborean93/PSOpenAD/blob/main/LICENSE)

See [about_PSOpenAD](docs/en-US/about_PSOpenAD.md) for more details.

## Documentation

Documentation for this module and details on the cmdlets included can be found [here](docs/en-US/PSOpenAD.md).

## Requirements

These cmdlets have the following requirements

* PowerShell v7.0 or newer

## Installing

The easiest way to install this module is through
[PowerShellGet](https://docs.microsoft.com/en-us/powershell/gallery/overview).

You can install this module by running;

```powershell
# Install for only the current user
Install-Module -Name PSOpenAD -Scope CurrentUser

# Install for all users
Install-Module -Name PSOpenAD -Scope AllUsers
```

## Contributing

Contributing is quite easy, fork this repo and submit a pull request with the changes.
To build this module run `.\build.ps1 -Task Build` in PowerShell.
To test a build run `.\build.ps1 -Task Test` in PowerShell.
This script will ensure all dependencies are installed before running the test suite.
