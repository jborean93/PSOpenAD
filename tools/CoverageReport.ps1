#!/usr/bin/env pwsh
#Requires -Version 7.2

using namespace System
using namespace System.Collections.Generic
using namespace System.IO
using namespace System.Management.Automation

<#
.SYNOPSIS
Generate coverage reports from Cobertura XML coverage data.

.DESCRIPTION
Parses coverage XML and generates either a summary table (default) or detailed
report showing missing lines and branches per file.

.PARAMETER Path
Path to the coverage XML file (Cobertura format).

.PARAMETER FileFilter
Wildcard patterns to exclude files from the report. Source generated files are
always excluded. When invoking this script from the command line outside of
Powershell, use a single string with patterns separated by commas, e.g.

    -FileFilter '*.g.cs,*Test*.cs'.

.PARAMETER Detailed
Show detailed report with missing lines/branches grouped by file and method.

.EXAMPLE
./CoverageReport.ps1 -Path ./output/TestResults/Coverage.xml

.EXAMPLE
./CoverageReport.ps1 -Path ./output/TestResults/Coverage.xml -Detailed

.EXAMPLE
./CoverageReport.ps1 -Path ./output/TestResults/Coverage.xml -FileFilter '*.g.cs','*Test*.cs'

.EXAMPLE
./CoverageReport.ps1 -Path ./output/TestResults/Coverage.xml -FileFilter @()
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]
    $Path,

    [Parameter()]
    [AllowEmptyCollection()]
    [string[]]
    $FileFilter,

    [Parameter()]
    [switch]
    $Detailed
)

$ErrorActionPreference = 'Stop'

class MethodCoverageInfo {
    [string]$Name
    [int[]]$MissingLines
}

class BranchCoverageInfo {
    [int]$LineNumber
    [int]$CoveredBranches
    [int]$TotalBranches
}

class FileCoverageInfo {
    [string]$Name
    [int]$TotalLines
    [int]$CoveredLines
    [int]$TotalBranches
    [int]$CoveredBranches
    [double]$LineCoverage
    [double]$BranchCoverage
    [int[]]$MissingLines
    [int[]]$PartialBranchLines
    [BranchCoverageInfo[]]$PartialBranchInfo
    [MethodCoverageInfo[]]$Methods
}

class CoverageReport {
    [int]$TotalLines
    [int]$CoveredLines
    [int]$TotalBranches
    [int]$CoveredBranches
    [double]$LineCoverage
    [double]$BranchCoverage
    [FileCoverageInfo[]]$Files
}

function Test-FileFiltered {
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]
        $FileName,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]
        $Filters
    )

    foreach ($filter in $Filters) {
        $pattern = [WildcardPattern]::new($filter)
        if ($pattern.IsMatch($FileName)) {
            return $true
        }
    }

    return $false
}

function Get-CoverageColor {
    [OutputType([string])]
    param([double]$Percentage)

    switch ($Percentage) {
        { $_ -ge 90 } { $PSStyle.Foreground.Green; continue }
        { $_ -ge 75 } { $PSStyle.Foreground.Yellow; continue }
        default { $PSStyle.Foreground.Red }
    }
}

function Format-Percentage {
    [OutputType([string])]
    param([double]$Percentage)

    $formatted = "{0:F1}%" -f $Percentage

    $color = Get-CoverageColor -Percentage $Percentage
    "$color$formatted$($PSStyle.Reset)"
}

function Get-MissingLineRanges {
    [OutputType([string])]
    param([int[]]$MissingLines)

    if (-not $MissingLines) {
        return
    }

    $sorted = $MissingLines | Sort-Object
    $start = $sorted[0]
    $end = $sorted[0]

    for ($i = 1; $i -lt $sorted.Count; $i++) {
        if ($sorted[$i] -eq $end + 1) {
            $end = $sorted[$i]
        }
        else {
            if ($start -eq $end) {
                "$start"
            }
            else {
                "$start-$end"
            }
            $start = $sorted[$i]
            $end = $sorted[$i]
        }
    }

    # Add the last range
    if ($start -eq $end) {
        "$start"
    }
    else {
        "$start-$end"
    }
}

function Get-CoverageData {
    [OutputType([CoverageReport])]
    param(
        [Parameter(Mandatory)]
        [string]
        $Path,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]
        $FileFilter
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Coverage file not found: $Path"
    }
    [xml]$coverageXml = Get-Content -LiteralPath $Path -Raw

    # Aggregate data by filename
    $fileMap = @{}
    $totalLinesAll = 0
    $coveredLinesAll = 0
    $totalBranchesAll = 0
    $coveredBranchesAll = 0

    foreach ($package in $coverageXml.coverage.packages.package) {
        foreach ($class in $package.classes.class) {
            $filename = $class.filename

            if (Test-FileFiltered -FileName $filename -Filters $FileFilter) {
                continue
            }

            if (-not $fileMap.ContainsKey($filename)) {
                $fileMap[$filename] = @{
                    AllLines = [List[object]]::new()
                    AllMethods = [List[object]]::new()
                }
            }

            $fileMap[$filename].AllLines.AddRange(@($class.lines.line))
            $fileMap[$filename].AllMethods.AddRange(@($class.methods.method))
        }
    }

    $files = foreach ($entry in $fileMap.GetEnumerator()) {
        $filename = $entry.Key
        $lines = $entry.Value.AllLines
        $methods = $entry.Value.AllMethods

        # Single pass through lines to deduplicate and collect all stats
        $seenLineNumbers = [HashSet[int]]::new()
        $uniqueLinesList = [List[object]]::new()
        $missingLinesList = [List[int]]::new()
        $partialBranchLinesList = [List[int]]::new()
        $partialBranchInfoList = [List[BranchCoverageInfo]]::new()
        $coveredLines = 0
        $totalBranches = 0
        $coveredBranches = 0

        foreach ($line in $lines) {
            $lineNum = [int]$line.number

            # Skip duplicates
            if (-not $seenLineNumbers.Add($lineNum)) {
                continue
            }

            $uniqueLinesList.Add($line)

            # Check if line is missing coverage
            $hits = [int]$line.hits
            if ($hits -eq 0) {
                $missingLinesList.Add($lineNum)
            }
            else {
                $coveredLines++
            }

            # Check for branches
            if ($line.branch -eq 'True' -and $line.'condition-coverage' -match '\((\d+)/(\d+)\)') {
                $branchCovered = [int]$Matches[1]
                $branchTotal = [int]$Matches[2]
                $coveredBranches += $branchCovered
                $totalBranches += $branchTotal

                # Track partial branches
                if ($branchCovered -lt $branchTotal) {
                    $partialBranchLinesList.Add($lineNum)
                    $partialBranchInfoList.Add([BranchCoverageInfo]@{
                        LineNumber = $lineNum
                        CoveredBranches = $branchCovered
                        TotalBranches = $branchTotal
                    })
                }
            }
        }

        $totalLines = $uniqueLinesList.Count
        $missingLines = $missingLinesList.ToArray()
        $partialBranches = $partialBranchLinesList.ToArray()

        # Add to overall totals
        $totalLinesAll += $totalLines
        $coveredLinesAll += $coveredLines
        $totalBranchesAll += $totalBranches
        $coveredBranchesAll += $coveredBranches

        # Calculate coverage percentages
        $lineCoverage = $totalLines -gt 0 ? ($coveredLines / $totalLines) * 100 : 100
        $branchCoverage = $totalBranches -gt 0 ? ($coveredBranches / $totalBranches) * 100 : 0

        # Group missing lines by method for detailed view
        $methodInfos = [List[MethodCoverageInfo]]::new()
        foreach ($method in $methods) {
            $methodLines = @($method.lines.line | Where-Object { [int]$_.hits -eq 0 } | ForEach-Object { [int]$_.number })
            if ($methodLines.Count -gt 0) {
                $methodInfo = [MethodCoverageInfo]@{
                    Name = $method.name
                    MissingLines = $methodLines | Sort-Object -Unique
                }
                $methodInfos.Add($methodInfo)
            }
        }

        [FileCoverageInfo]@{
            Name = $filename
            TotalLines = $totalLines
            CoveredLines = $coveredLines
            TotalBranches = $totalBranches
            CoveredBranches = $coveredBranches
            LineCoverage = $lineCoverage
            BranchCoverage = $branchCoverage
            MissingLines = $missingLines
            PartialBranchLines = $partialBranches
            PartialBranchInfo = $partialBranchInfoList.ToArray()
            Methods = $methodInfos.ToArray()
        }
    }

    # Create overall report
    $overallLineCoverage = $totalLinesAll -gt 0 ? ($coveredLinesAll / $totalLinesAll) * 100 : 100
    $overallBranchCoverage = $totalBranchesAll -gt 0 ? ($coveredBranchesAll / $totalBranchesAll) * 100 : 0

    return [CoverageReport]@{
        TotalLines = $totalLinesAll
        CoveredLines = $coveredLinesAll
        TotalBranches = $totalBranchesAll
        CoveredBranches = $coveredBranchesAll
        LineCoverage = $overallLineCoverage
        BranchCoverage = $overallBranchCoverage
        Files = $files
    }
}

function Show-SummaryReport {
    param(
        [Parameter(Mandatory)]
        [CoverageReport]
        $Report
    )

    Write-Host ""
    Write-Host "$($PSStyle.Bold)Coverage Report$($PSStyle.Reset)"
    Write-Host ""

    # Show overall coverage
    Write-Host "Overall Coverage:"
    Write-Host "  Lines    $(Format-Percentage $Report.LineCoverage) ($($Report.CoveredLines) of $($Report.TotalLines))"
    Write-Host "  Branches $(Format-Percentage $Report.BranchCoverage) ($($Report.CoveredBranches) of $($Report.TotalBranches))"
    Write-Host ""

    # Filter out files with 100% coverage and prepare display data
    $fileData = $Report.Files | Where-Object {
        $_.LineCoverage -ne 100 -or ($_.TotalBranches -gt 0 -and $_.BranchCoverage -ne 100)
    } | ForEach-Object {
        $missingLineRanges = Get-MissingLineRanges -MissingLines $_.MissingLines

        [PSCustomObject]@{
            Name = $_.Name
            Stmts = $_.TotalLines
            Miss = $_.TotalLines - $_.CoveredLines
            Branch = $_.TotalBranches
            BrPart = $_.TotalBranches - $_.CoveredBranches
            LineCoverage = $_.LineCoverage
            BranchCoverage = $_.BranchCoverage
            Missing = ($missingLineRanges -join ', ')
            BranchLines = (($_.PartialBranchLines | Sort-Object) -join ', ')
        }
    } | Sort-Object LineCoverage, BranchCoverage

    if ($fileData.Count -eq 0) {
        Write-Host "$($PSStyle.Foreground.Green)All files have 100% coverage!$($PSStyle.Reset)"
        Write-Host ""
        return
    }

    # Calculate dynamic column widths based on console width
    # Fixed columns: " Stmts" + " Miss" + " Branch" + " BrPart" + " Cover"
    #                = 6 + 5 + 7 + 7 + 8 = 33 chars
    try {
        $consoleWidth = [Math]::Max([Console]::WindowWidth, 120)
    }
    catch {
        # If we can't get console width (e.g. running in non-interactive environment), use a default
        $consoleWidth = 120
    }
    $fixedColumnsWidth = 33
    $nameWidth = $consoleWidth - $fixedColumnsWidth

    Write-Host "Files with missing coverage:"
    Write-Host ""
    $header = "{0,-$nameWidth} Stmts Miss Branch BrPart Cover" -f "Name"
    Write-Host "$($PSStyle.Bold)$header$($PSStyle.Reset)"
    Write-Host ("{0}" -f ("-" * $consoleWidth))

    $projectRoot = Split-Path -Path $PSScriptRoot -Parent

    foreach ($file in $fileData) {
        # Truncate filename if too long
        $name = $file.Name
        if ($name -like "/_/*") {
            $name = $name.Substring(3)
        }
        else {
            $name = [Path]::GetRelativePath($projectRoot, $name)
        }

        if ($name.Length -gt $nameWidth) {
            $name = "..." + $name.Substring($name.Length - ($nameWidth - 3))
        }

        $branchInfo = $file.Branch -gt 0 ? ("{0,6}" -f $file.Branch) : "     -"

        $brPartInfo = if ($file.BrPart -gt 0) {
            "$($PSStyle.Foreground.Yellow){0,6}$($PSStyle.Reset)" -f $file.BrPart
        }
        else {
            $file.Branch -gt 0 ? ("{0,6}" -f $file.BrPart) : "     -"
        }

        $row = "{0,-$nameWidth} {1,5} {2,4} {3} {4} {5}" -f @(
            $name
            $file.Stmts
            $file.Miss
            $branchInfo
            $brPartInfo
            (Format-Percentage $file.LineCoverage)
        )

        Write-Host $row

        if ($file.Missing -or ($file.BrPart -gt 0 -and $file.BranchLines)) {
            $details = $file.Missing
            if ($file.BrPart -gt 0 -and $file.BranchLines) {
                if ($details) {
                    $details += " "
                }
                $details += "(br: $($file.BranchLines))"
            }
            Write-Host "  $($PSStyle.Dim)$details$($PSStyle.Reset)"
        }
    }

    Write-Host ("{0}" -f ("-" * $consoleWidth))

    $totalStmts = ($fileData | Measure-Object -Property Stmts -Sum).Sum
    $totalMiss = ($fileData | Measure-Object -Property Miss -Sum).Sum
    $totalBranch = ($fileData | Measure-Object -Property Branch -Sum).Sum
    $totalBrPart = ($fileData | Measure-Object -Property BrPart -Sum).Sum

    $summaryRow = "{0,-$nameWidth} {1,5} {2,4} {3,6} {4,6} {5}" -f @(
        "TOTAL (incomplete files)"
        $totalStmts
        $totalMiss
        $totalBranch
        $totalBrPart
        (Format-Percentage (($totalStmts - $totalMiss) / $totalStmts * 100))
    )

    Write-Host "$($PSStyle.Bold)$summaryRow$($PSStyle.Reset)"
    Write-Host ""
}

function Show-DetailedReport {
    param(
        [Parameter(Mandatory)]
        [CoverageReport]
        $Report
    )

    Write-Host ""
    Write-Host "$($PSStyle.Bold)Detailed Coverage Report$($PSStyle.Reset)"
    Write-Host ""

    Write-Host "Summary:"
    Write-Host "  Line Coverage:   $(Format-Percentage $Report.LineCoverage) ($($Report.CoveredLines) of $($Report.TotalLines))"
    Write-Host "  Branch Coverage: $(Format-Percentage $Report.BranchCoverage) ($($Report.CoveredBranches) of $($Report.TotalBranches))"
    Write-Host ""

    # Process each file (sorted by name)
    foreach ($file in ($Report.Files | Sort-Object Name)) {
        # Skip files with 100% coverage
        if ($file.LineCoverage -eq 100 -and ($file.TotalBranches -eq 0 -or $file.BranchCoverage -eq 100)) {
            continue
        }

        if ($file.MissingLines.Count -eq 0 -and $file.PartialBranchLines.Count -eq 0) {
            continue
        }

        Write-Host "$($PSStyle.Bold)$($PSStyle.Foreground.Cyan)$($file.Name)$($PSStyle.Reset)"

        $linePct = Format-Percentage $file.LineCoverage
        $missingLines = $file.TotalLines - $file.CoveredLines
        if ($file.TotalBranches -gt 0) {
            $branchPct = Format-Percentage $file.BranchCoverage
            $missingBranches = $file.TotalBranches - $file.CoveredBranches
            Write-Host "  Coverage: $linePct lines ($($file.CoveredLines)/$($file.TotalLines), $missingLines missing), $branchPct branches ($($file.CoveredBranches)/$($file.TotalBranches), $missingBranches missing)"
        }
        else {
            Write-Host "  Coverage: $linePct lines ($($file.CoveredLines)/$($file.TotalLines), $missingLines missing), no branches"
        }
        Write-Host ""

        # Group missing lines by method
        if ($file.MissingLines.Count -gt 0) {
            Write-Host "  $($PSStyle.Foreground.Yellow)Missing Lines:$($PSStyle.Reset)"

            if ($file.Methods.Count -eq 0) {
                # Lines not in any method
                $ranges = Get-MissingLineRanges -MissingLines $file.MissingLines
                Write-Host "    $($ranges -join ', ')    ($($file.MissingLines.Count) lines)"
            }
            else {
                foreach ($method in ($file.Methods | Sort-Object Name)) {
                    $ranges = Get-MissingLineRanges -MissingLines $method.MissingLines
                    $count = $method.MissingLines.Count
                    $plural = $count -eq 1 ? "line" : "lines"
                    Write-Host "    $($ranges -join ', ')".PadRight(30) "($count $plural)".PadRight(15) "Method: $($PSStyle.Dim)$($method.Name)$($PSStyle.Reset)"
                }
            }
            Write-Host ""
        }

        # Show missing branches
        if ($file.PartialBranchInfo.Count -gt 0) {
            Write-Host "  $($PSStyle.Foreground.Yellow)Missing Branches:$($PSStyle.Reset)"

            foreach ($branchInfo in ($file.PartialBranchInfo | Sort-Object LineNumber)) {
                $missing = $branchInfo.TotalBranches - $branchInfo.CoveredBranches
                Write-Host "    Line $($branchInfo.LineNumber) ($($branchInfo.CoveredBranches)/$($branchInfo.TotalBranches), $missing missing)"
            }
            Write-Host ""
        }
    }
}

if (-not $Path) {
    $Path = [Path]::GetFullPath([Path]::Combine($PSScriptRoot, '..', 'output', 'TestResults', 'Coverage.xml'))
}

if ($FileFilter -and $FileFilter.Count -eq 1 -and $FileFilter[0] -like '*,*') {
    # If FileFilter is a single comma-separated string, split it into an array
    $FileFilter = $FileFilter[0].Split(',') | ForEach-Object { $_.Trim() }
}
$FileFilter = @(
    # Always filter out source generated files.
     '*.g.cs'
    $FileFilter | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
)

$report = Get-CoverageData -Path $Path -FileFilter $FileFilter

if ($Detailed) {
    Show-DetailedReport -Report $report
}
else {
    Show-SummaryReport -Report $report
}
