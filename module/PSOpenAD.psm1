# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

# This is used to load the shared assembly in the Default ALC which then sets
# an ALC for the moulde and any dependencies of that module to be loaded in
# that ALC.

$importModule = Get-Command -Name Import-Module -Module Microsoft.PowerShell.Core
$moduleName = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)

$isReload = $true
if (-not ('PSOpenAD.LoadContext' -as [type])) {
    $isReload = $true
    Add-Type -Path ([System.IO.Path]::Combine($PSScriptRoot, 'bin', 'net8.0', "$moduleName.dll"))
}

$mainModule = [PSOpenAD.LoadContext]::Initialize()
$innerMod = &$importModule -Assembly $mainModule -PassThru:$isReload

if ($innerMod) {
    # Bug in pwsh, Import-Module in an assembly will pick up a cached instance
    # and not call the same path to set the nested module's cmdlets to the
    # current module scope. This is only technically needed if someone is
    # calling 'Import-Module -Name PSEtw -Force' a second time. The first
    # import is still fine.
    # https://github.com/PowerShell/PowerShell/issues/20710
    $addExportedCmdlet = [System.Management.Automation.PSModuleInfo].GetMethod(
        'AddExportedCmdlet',
        [System.Reflection.BindingFlags]'Instance, NonPublic'
    )
    foreach ($cmd in $innerMod.ExportedCmdlets.Values) {
        $addExportedCmdlet.Invoke($ExecutionContext.SessionState.Module, @(, $cmd))
    }
}
