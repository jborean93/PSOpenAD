@{
    DotnetProject = 'PSOpenAD.Module'
    InvokeBuildVersion = '5.11.0'
    PesterVersion = '5.5.0'
    BuildRequirements = @(
        @{
            ModuleName = 'Microsoft.PowerShell.PSResourceGet'
            ModuleVersion = '1.0.2'
        }
        @{
            ModuleName = 'OpenAuthenticode'
            RequiredVersion = '0.4.0'
        }
        @{
            ModuleName = 'platyPS'
            RequiredVersion = '0.14.2'
        }
    )
    TestRequirements = @()
}
