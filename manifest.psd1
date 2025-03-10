@{
    DotnetProject = 'PSOpenAD.Module'
    InvokeBuildVersion = '5.12.1'
    PesterVersion = '5.7.1'
    BuildRequirements = @(
        @{
            ModuleName = 'Microsoft.PowerShell.PSResourceGet'
            ModuleVersion = '1.1.1'
        }
        @{
            ModuleName = 'OpenAuthenticode'
            RequiredVersion = '0.6.1'
        }
        @{
            ModuleName = 'platyPS'
            RequiredVersion = '0.14.2'
        }
    )
    TestRequirements = @()
}
