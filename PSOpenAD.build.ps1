[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]
    $Configuration = 'Debug'
)

$modulePath = [IO.Path]::Combine($PSScriptRoot, 'module')
$manifestItem = Get-Item ([IO.Path]::Combine($modulePath, '*.psd1'))

$ModuleName = $manifestItem.BaseName
$Manifest = Test-ModuleManifest -Path $manifestItem.FullName -ErrorAction Ignore -WarningAction Ignore
$Version = $Manifest.Version
$BuildPath = [IO.Path]::Combine($PSScriptRoot, 'output')
$PowerShellPath = [IO.Path]::Combine($PSScriptRoot, 'module')
$CSharpPath = [IO.Path]::Combine($PSScriptRoot, 'src')
$ReleasePath = [IO.Path]::Combine($BuildPath, $ModuleName, $Version)
$IsUnix = $PSEdition -eq 'Core' -and -not $IsWindows
$UseNativeArguments = $PSVersionTable.PSVersion.Major -gt 7 -or ($PSVersionTable.PSVersion.Major -eq 7 -and $PSVersionTable.PSVersion.Minor -gt 2)

[xml]$csharpProjectInfo = Get-Content ([IO.Path]::Combine($CSharpPath, '*.csproj'))
$TargetFrameworks = @(@($csharpProjectInfo.Project.PropertyGroup)[0].TargetFrameworks.Split(
        ';', [StringSplitOptions]::RemoveEmptyEntries))
$PSFramework = $TargetFrameworks[0]

task Clean {
    if (Test-Path $ReleasePath) {
        Remove-Item $ReleasePath -Recurse -Force
    }

    New-Item -ItemType Directory $ReleasePath | Out-Null
}

task BuildDocs {
    $helpParams = @{
        Path       = [IO.Path]::Combine($PSScriptRoot, 'docs', 'en-US')
        OutputPath = [IO.Path]::Combine($ReleasePath, 'en-US')
    }
    New-ExternalHelp @helpParams | Out-Null
}

task BuildManaged {
    $arguments = @(
        'publish'
        '--configuration', $Configuration
        '--verbosity', 'q'
        '-nologo'
        "-p:Version=$Version"
    )

    Push-Location -LiteralPath $CSharpPath
    try {
        foreach ($framework in $TargetFrameworks) {
            Write-Host "Compiling for $framework"
            dotnet @arguments --framework $framework

            if ($LASTEXITCODE) {
                throw "Failed to compiled code for $framework"
            }
        }
    }
    finally {
        Pop-Location
    }
}

task CopyToRelease {
    $copyParams = @{
        Path        = [IO.Path]::Combine($PowerShellPath, '*')
        Destination = $ReleasePath
        Recurse     = $true
        Force       = $true
    }
    Copy-Item @copyParams

    foreach ($framework in $TargetFrameworks) {
        $buildFolder = [IO.Path]::Combine($CSharpPath, 'bin', $Configuration, $framework, 'publish')
        $binFolder = [IO.Path]::Combine($ReleasePath, 'bin', $framework)
        if (-not (Test-Path -LiteralPath $binFolder)) {
            New-Item -Path $binFolder -ItemType Directory | Out-Null
        }
        Copy-Item ([IO.Path]::Combine($buildFolder, "*")) -Destination $binFolder
    }
}

task Sign {
    if (-not $env:AZURE_KEYVAULT_CREDENTIALS) {
        return
    }

    $credInfo = ConvertFrom-Json -InputObject $env:AZURE_KEYVAULT_CREDENTIALS
    $vaultName = $credInfo.vaultName
    $vaultCert = $credInfo.vaultCert

    $env:AZURE_CLIENT_ID = $credInfo.clientId
    $env:AZURE_CLIENT_SECRET = $credInfo.clientSecret
    $env:AZURE_TENANT_ID = $credInfo.tenantId
    $key = Get-OpenAuthenticodeAzKey -Vault $vaultName -Certificate $vaultCert
    $env:AZURE_CLIENT_ID = ''
    $env:AZURE_CLIENT_SECRET = ''
    $env:AZURE_TENANT_ID = ''

    $signParams = @{
        Key = $key
        TimeStampServer = 'http://timestamp.digicert.com'
        HashAlgorithm = 'SHA256'
    }

    Get-ChildItem -LiteralPath $ReleasePath -Recurse -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Extension -in ".ps1", ".psm1", ".psd1", ".ps1xml" -or (
                $_.Extension -eq ".dll" -and $_.BaseName -like "$ModuleName*"
            )
        } |
        ForEach-Object -Process {
            Set-OpenAuthenticodeSignature -LiteralPath $_.FullName @signParams
        }
}

task Package {
    $nupkgPath = [IO.Path]::Combine($BuildPath, "$ModuleName.$Version*.nupkg")
    if (Test-Path $nupkgPath) {
        Remove-Item $nupkgPath -Force
    }

    $repoParams = @{
        Name               = 'LocalRepo'
        SourceLocation     = $BuildPath
        PublishLocation    = $BuildPath
        InstallationPolicy = 'Trusted'
    }
    if (Get-PSRepository -Name $repoParams.Name -ErrorAction SilentlyContinue) {
        Unregister-PSRepository -Name $repoParams.Name
    }

    Register-PSRepository @repoParams
    try {
        Publish-Module -Path $ReleasePath -Repository $repoParams.Name
    }
    finally {
        Unregister-PSRepository -Name $repoParams.Name
    }
}

task Analyze {
    $pssaSplat = @{
        Path        = $ReleasePath
        Settings    = [IO.Path]::Combine($PSScriptRoot, 'ScriptAnalyzerSettings.psd1')
        Recurse     = $true
        ErrorAction = 'SilentlyContinue'
    }
    $results = Invoke-ScriptAnalyzer @pssaSplat
    if ($null -ne $results) {
        $results | Out-String
        throw "Failed PsScriptAnalyzer tests, build failed"
    }
}


task DoUnitTest {
    $testsPath = [IO.Path]::Combine($PSScriptRoot, 'tests', 'units')
    if (-not (Test-Path -LiteralPath $testsPath)) {
        Write-Host "No unit tests found, skipping"
        return
    }

    $resultsPath = [IO.Path]::Combine($BuildPath, 'TestResults')
    if (-not (Test-Path -LiteralPath $resultsPath)) {
        New-Item $resultsPath -ItemType Directory -ErrorAction Stop | Out-Null
    }

    # dotnet test places the results in a subfolder of the results-directory. This subfolder is based on a random guid
    # so a temp folder is used to ensure we only get the current runs results
    $tempResultsPath = [IO.Path]::Combine($resultsPath, "TempUnit")
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
            if ($Configuration -eq 'Debug') {
                '--collect:"XPlat Code Coverage"'
                '--'
                "$runSettingsPrefix.Format=json"
                if ($UseNativeArguments) {
                    "$runSettingsPrefix.IncludeDirectory=`"$CSharpPath`""
                }
                else {
                    "$runSettingsPrefix.IncludeDirectory=\`"$CSharpPath\`""
                }
            }
        )

        Write-Host "Running unit tests"
        dotnet @arguments

        if ($LASTEXITCODE) {
            throw "Unit tests failed"
        }

        if ($Configuration -eq 'Debug') {
            Move-Item -Path $tempResultsPath/*/*.json -Destination $resultsPath/UnitCoverage.json -Force
        }
    }
    finally {
        Remove-Item -LiteralPath $tempResultsPath -Force -Recurse
    }
}

task DoTest {
    $resultsPath = [IO.Path]::Combine($BuildPath, 'TestResults')
    if (-not (Test-Path $resultsPath)) {
        New-Item $resultsPath -ItemType Directory -ErrorAction Stop | Out-Null
    }

    $resultsFile = [IO.Path]::Combine($resultsPath, 'Pester.xml')
    if (Test-Path $resultsFile) {
        Remove-Item $resultsFile -ErrorAction Stop -Force
    }

    $pesterScript = [IO.Path]::Combine($PSScriptRoot, 'tools', 'PesterTest.ps1')
    $pwsh = [Environment]::GetCommandLineArgs()[0] -replace '\.dll$', ''
    $arguments = @(
        '-NoProfile'
        '-NonInteractive'
        if (-not $IsUnix) {
            '-ExecutionPolicy', 'Bypass'
        }
        '-File', $pesterScript
        '-TestPath', ([IO.Path]::Combine($PSScriptRoot, 'tests'))
        '-OutputFile', $resultsFile
    )

    if ($Configuration -eq 'Debug') {
        # We use coverlet to collect code coverage of our binary
        $unitCoveragePath = [IO.Path]::Combine($resultsPath, 'UnitCoverage.json')
        $targetArgs = '"' + ($arguments -join '" "') + '"'

        if ($UseNativeArguments) {
            $watchFolder = [IO.Path]::Combine($ReleasePath, 'bin', $PSFramework)
        }
        else {
            $targetArgs = '"' + ($targetArgs -replace '"', '\"') + '"'
            $watchFolder = '"{0}"' -f ([IO.Path]::Combine($ReleasePath, 'bin', $PSFramework))
        }

        $arguments = @(
            $watchFolder
            '--target', $pwsh
            '--targetargs', $targetArgs
            '--output', ([IO.Path]::Combine($resultsPath, 'Coverage.xml'))
            '--format', 'cobertura'
            if (Test-Path -LiteralPath $unitCoveragePath) {
                '--merge-with', $unitCoveragePath
            }
        )
        $pwsh = 'coverlet'
    }

    &$pwsh $arguments
    if ($LASTEXITCODE) {
        throw "Pester failed tests"
    }
}

task Build -Jobs Clean, BuildManaged, CopyToRelease, BuildDocs, Sign, Package

# FIXME: Work out why we need the obj and bin folder for coverage to work
task Test -Jobs BuildManaged, Analyze, DoUnitTest, DoTest

task . Build
