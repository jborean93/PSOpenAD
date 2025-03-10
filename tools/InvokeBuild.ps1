using namespace System.Collections
using namespace System.IO

#Requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [Manifest]
    $Manifest
)

#region Build

task Clean {
    if (Test-Path -LiteralPath $Manifest.ReleasePath) {
        Remove-Item -LiteralPath $Manifest.ReleasePath -Recurse -Force
    }
    New-Item -Path $Manifest.ReleasePath -ItemType Directory | Out-Null
}

task BuildManaged {
    $arguments = @(
        'publish'
        '--configuration', $Manifest.Configuration
        '--verbosity', 'quiet'
        '-nologo'
        "-p:Version=$($Manifest.Module.Version)"
    )

    $csproj = (Get-Item -Path "$($Manifest.DotnetPath)/*.csproj").FullName
    foreach ($framework in $Manifest.TargetFrameworks) {
        Write-Host "Compiling for $framework" -ForegroundColor Cyan
        $outputDir = [Path]::Combine($Manifest.ReleasePath, "bin", $framework)
        New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
        dotnet @arguments --framework $framework --output $outputDir $csproj

        if ($LASTEXITCODE) {
            throw "Failed to compiled code for $framework"
        }
    }
}

task BuildModule {
    $copyParams = @{
        Path = [Path]::Combine($Manifest.PowerShellPath, '*')
        Destination = $Manifest.ReleasePath
        Recurse = $true
        Force = $true
    }
    Copy-Item @copyParams
}

task BuildDocs {
    Get-ChildItem -LiteralPath $Manifest.DocsPath -Directory | ForEach-Object {
        Write-Host "Building docs for $($_.Name)" -ForegroundColor Cyan
        $helpParams = @{
            Path = $_.FullName
            OutputPath = [Path]::Combine($Manifest.ReleasePath, $_.Name)
        }
        New-ExternalHelp @helpParams | Out-Null
    }
}

task Sign {
    $vaultName = $env:AZURE_KEYVAULT_NAME
    $vaultCert = $env:AZURE_KEYVAULT_CERT
    if (-not $vaultName -or -not $vaultCert) {
        return
    }

    Write-Host "Authenticating with Azure KeyVault '$vaultName' for signing" -ForegroundColor Cyan
    $key = Get-OpenAuthenticodeAzKey -Vault $vaultName -Certificate $vaultCert
    $signParams = @{
        Key = $key
        TimeStampServer = 'http://timestamp.digicert.com'
    }

    $toSign = Get-ChildItem -LiteralPath $Manifest.ReleasePath -Recurse -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Extension -in ".ps1", ".psm1", ".psd1", ".ps1xml" -or (
                $_.Extension -eq ".dll" -and $_.BaseName -like "$($Manifest.Module.Name)*"
            )
        } |
        ForEach-Object -Process {
            Write-Host "Signing '$($_.FullName)'"
            $_.FullName
        }

    Set-OpenAuthenticodeSignature -LiteralPath $toSign @signParams
}

task Package {
    $repoParams = @{
        Name = "$($Manifest.Module.Name)-Local"
        Uri = $Manifest.OutputPath
        Trusted = $true
        Force = $true
    }
    Register-PSResourceRepository @repoParams
    try {
        Publish-PSResource -Path $Manifest.ReleasePath -Repository $repoParams.Name -SkipModuleManifestValidate
    }
    finally {
        Unregister-PSResourceRepository -Name $repoParams.Name
    }
}

#endregion Build

#region Test

task UnitTests {
    $testsPath = [Path]::Combine($Manifest.TestPath, 'units')
    if (-not (Test-Path -LiteralPath $testsPath)) {
        Write-Host "No unit tests found, skipping" -ForegroundColor Yellow
        return
    }

    # dotnet test places the results in a subfolder of the results-directory.
    # This subfolder is based on a random guid so a temp folder is used to
    # ensure we only get the current runs results
    $tempResultsPath = [Path]::Combine($Manifest.TestResultsPath, "TempUnit")
    if (Test-Path -LiteralPath $tempResultsPath) {
        Remove-Item -LiteralPath $tempResultsPath -Force -Recurse
    }
    New-Item -Path $tempResultsPath -ItemType Directory | Out-Null

    try {
        $runSettingsPrefix = 'DataCollectionRunSettings.DataCollectors.DataCollector.Configuration'
        $arguments = @(
            'test'
            $testsPath
            '--results-directory', $tempResultsPath
            '--collect:"XPlat Code Coverage"'
            '--'
            "$runSettingsPrefix.Format=json"
            "$runSettingsPrefix.IncludeDirectory=`"$CSharpPath`""
        )

        dotnet @arguments
        if ($LASTEXITCODE) {
            throw "Unit tests failed"
        }

        $moveParams = @{
            Path = [Path]::Combine($tempResultsPath, "*", "*.json")
            Destination = [Path]::Combine($Manifest.TestResultsPath, "UnitCoverage.json")
            Force = $true
        }
        Move-Item @moveParams
    }
    finally {
        Remove-Item -LiteralPath $tempResultsPath -Force -Recurse
    }
}

task PesterTests {
    $testsPath = [Path]::Combine($Manifest.TestPath, '*.tests.ps1')
    if (-not (Test-Path -Path $testsPath)) {
        Write-Host "No Pester tests found, skipping" -ForegroundColor Yellow
        return
    }

    $dotnetTools = @(dotnet tool list --global) -join "`n"
    if (-not $dotnetTools.Contains('coverlet.console')) {
        Write-Host 'Installing dotnet tool coverlet.console' -ForegroundColor Yellow
        dotnet tool install --global coverlet.console
    }

    $pwsh = Assert-PowerShell -Version $Manifest.PowerShellVersion -Arch $Manifest.PowerShellArch
    $resultsFile = [Path]::Combine($Manifest.TestResultsPath, 'Pester.xml')
    if (Test-Path -LiteralPath $resultsFile) {
        Remove-Item $resultsFile -ErrorAction Stop -Force
    }
    $pesterScript = [Path]::Combine($PSScriptRoot, 'PesterTest.ps1')
    $pwshArguments = @(
        '-NoProfile'
        '-NonInteractive'
        if (-not $IsUnix) {
            '-ExecutionPolicy', 'Bypass'
        }
        '-File', $pesterScript
        '-TestPath', $Manifest.TestPath
        '-OutputFile', $resultsFile
    ) -join '" "'

    $watchFolder = [Path]::Combine($Manifest.ReleasePath, 'bin', $Manifest.TestFramework)
    $unitCoveragePath = [Path]::Combine($Manifest.TestResultsPath, "UnitCoverage.json")
    $coveragePath = [Path]::Combine($Manifest.TestResultsPath, "Coverage.xml")
    $sourceMappingFile = [Path]::Combine($Manifest.TestResultsPath, "CoverageSourceMapping.txt")

    $arguments = @(
        $watchFolder
        '--target', $pwsh
        '--targetargs', "`"$pwshArguments`""
        '--output', $coveragePath
        '--format', 'cobertura'
        '--verbosity', 'minimal'
        if (Test-Path -LiteralPath $unitCoveragePath) {
            '--merge-with', $unitCoveragePath
        }
        if ($env:GITHUB_ACTIONS -eq 'true') {
            Set-Content -LiteralPath $sourceMappingFile "|$($Manifest.RepositoryPath)$([Path]::DirectorySeparatorChar)=/_/"
            '--source-mapping-file', $sourceMappingFile
        }
    )
    $origEnv = $env:PSModulePath
    try {
        $pwshHome = Split-Path -Path $pwsh -Parent
        $env:PSModulePath = @(
            [Path]::Combine($pwshHome, "Modules")
            [Path]::Combine($Manifest.OutputPath, "Modules")
        ) -join ([Path]::PathSeparator)

        coverlet @arguments
    }
    finally {
        $env:PSModulePath = $origEnv
    }

    if ($LASTEXITCODE) {
        throw "Pester failed tests"
    }
}

task CoverageReport {
    $dotnetTools = @(dotnet tool list --global) -join "`n"
    if (-not $dotnetTools.Contains('dotnet-reportgenerator-globaltool')) {
        Write-Host 'Installing dotnet tool dotnet-reportgenerator-globaltool' -ForegroundColor Yellow
        dotnet tool install --global dotnet-reportgenerator-globaltool
    }

    $reportPath = [Path]::Combine($Manifest.TestResultsPath, "CoverageReport")
    $coveragePath = [Path]::Combine($Manifest.TestResultsPath, "Coverage.xml")
    $reportArgs = @(
        "-reports:$coveragePath"
        "-targetdir:$reportPath"
        '-reporttypes:Html_Dark;JsonSummary'
    )
    reportgenerator @reportArgs
    if ($LASTEXITCODE) {
        throw "reportgenerator failed with RC of $LASTEXITCODE"
    }

    $resultPath = [Path]::Combine($reportPath, "Summary.json")
    Format-CoverageInfo -Path $resultPath
}

#endregion Test

task Build -Jobs Clean, BuildManaged, BuildModule, BuildDocs, Sign, Package

task Test -Jobs UnitTests, PesterTests, CoverageReport
