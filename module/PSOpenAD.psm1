# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

# This is used to load the shared assembly in the Default ALC which then sets
# an ALC for the moulde and any dependencies of that module to be loaded in
# that ALC.

$moduleName = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
Add-Type -Path ([System.IO.Path]::Combine($PSScriptRoot, 'bin', 'net6.0', "$moduleName.dll"))

$mainModule = [PSOpenAD.LoadContext]::Initialize()
Import-Module -Assembly $mainModule

# Use this for testing that the dlls are loaded correctly and outside the Default ALC.
# [System.AppDomain]::CurrentDomain.GetAssemblies() |
#     Where-Object { $_.GetName().Name -like "*PSOpenAD*" } |
#     ForEach-Object {
#         $alc = [Runtime.Loader.AssemblyLoadContext]::GetLoadContext($_)
#         [PSCustomObject]@{
#             Name = $_.FullName
#             Location = $_.Location
#             ALC = $alc
#         }
#     } | Format-List
