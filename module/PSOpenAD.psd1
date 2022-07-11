# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)
#
# Module manifest for module 'PSOpenAD'
#
# Generated by: Jordan Borean
#
# Generated on: 2021-12-09
#

@{

    # Script module or binary module file associated with this manifest.
    RootModule             = 'bin/netcoreapp3.1/PSOpenAD.dll'

    # Version number of this module.
    ModuleVersion          = '0.1.1'

    # Supported PSEditions
    # CompatiblePSEditions = @()

    # ID used to uniquely identify this module
    GUID                   = '23973866-7420-410c-8160-5fd6bed543ca'

    # Author of this module
    Author                 = 'Jordan Borean'

    # Company or vendor of this module
    CompanyName            = 'Community'

    # Copyright statement for this module
    Copyright              = '(c) 2021 Jordan Borean. All rights reserved.'

    # Description of the functionality provided by this module
    Description            = 'Cross platform module that can get/set information in Active Directory.`nSee https://github.com/jborean93/PSOpenAD for more info'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion      = '7.0'

    # Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    DotNetFrameworkVersion = '4.7.2'

    # Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    ClrVersion             = '4.0'

    # Processor architecture (None, X86, Amd64) required by this module
    # ProcessorArchitecture = ''

    # Modules that must be imported into the global environment prior to importing this module
    # RequiredModules = @()

    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    # ScriptsToProcess = @()

    # Type files (.ps1xml) to be loaded when importing this module
    # TypesToProcess = @()

    # Format files (.ps1xml) to be loaded when importing this module
    FormatsToProcess       = @(
        'PSOpenAD.Format.ps1xml'
    )

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules          = @()

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport      = @()

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport        = @(
        'Get-OpenADAuthSupport'
        'Get-OpenADComputer'
        'Get-OpenADGroup'
        'Get-OpenADObject'
        'Get-OpenADServiceAccount'
        'Get-OpenADSession'
        'Get-OpenADUser'
        'Get-OpenADWhoami'
        'New-OpenADSession'
        'New-OpenADSessionOption'
        'Remove-OpenADSession'
    )

    # Variables to export from this module
    VariablesToExport      = @()

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport        = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData            = @{

        PSData = @{

            # Prerelease   = 'preview1'

            # Tags applied to this module. These help with module discovery in online galleries.
            Tags         = @(
                'ActiveDirectory'
                'LDAP'
                'PSEdition_Core'
            )

            # A URL to the license for this module.
            LicenseUri   = 'https://github.com/jborean93/PSOpenAD/blob/main/LICENSE'

            # A URL to the main website for this project.
            ProjectUri   = 'https://github.com/jborean93/PSOpenAD'

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
            ReleaseNotes = 'See https://github.com/jborean93/PSOpenAD/blob/main/CHANGELOG.md'

            # Prerelease string of this module
            # Prerelease = ''

            # Flag to indicate whether the module requires explicit user acceptance for install/update/save
            # RequireLicenseAcceptance = $false

            # External dependent modules of this module
            # ExternalModuleDependencies = @()

        } # End of PSData hashtable

    } # End of PrivateData hashtable

}
