[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Fail {
    param([Parameter(Mandatory)][string]$Message)
    Write-Error $Message
    exit 1
}

function Require-File {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Fail "$Description was not found: $Path"
    }
}

function Require-Text {
    param(
        [Parameter(Mandatory)][string]$Content,
        [Parameter(Mandatory)][string]$Pattern,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string]$Path
    )

    if ($Content -notmatch $Pattern) {
        Fail "$Path is missing required $Description. Expected pattern: $Pattern"
    }
}

function Get-YamlDocuments {
    param([Parameter(Mandatory)][string]$Path)

    $content = Get-Content -LiteralPath $Path -Raw

    if ([string]::IsNullOrWhiteSpace($content)) {
        Fail "YAML file is empty: $Path"
    }

    try {
        $documents = $content | ConvertFrom-Yaml -AllDocuments
    }
    catch {
        Fail "Invalid YAML in $Path. $($_.Exception.Message)"
    }

    if ($null -eq $documents -or @($documents).Count -eq 0) {
        Fail "No YAML document was found in $Path"
    }

    return @($documents)
}

Push-Location $RepositoryRoot

try {
    $sigmaDirectory = Join-Path $RepositoryRoot 'detections/sigma'
    $testDirectory = Join-Path $RepositoryRoot 'detections/tests'
    $sentinelDirectory = Join-Path $RepositoryRoot 'detections/sentinel'

    if (-not (Test-Path -LiteralPath $sigmaDirectory -PathType Container)) {
        Fail "Missing Sigma directory: $sigmaDirectory"
    }

    if (-not (Test-Path -LiteralPath $testDirectory -PathType Container)) {
        Fail "Missing test-contract directory: $testDirectory"
    }

    if (-not (Test-Path -LiteralPath $sentinelDirectory -PathType Container)) {
        Fail "Missing Sentinel Bicep directory: $sentinelDirectory"
    }

    $sigmaFiles = @(
        Get-ChildItem -LiteralPath $sigmaDirectory -Recurse -File |
        Where-Object { $_.Extension -in @('.yml', '.yaml') }
    )

    if ($sigmaFiles.Count -eq 0) {
        Fail 'No Sigma rule files were found under detections/sigma.'
    }

    foreach ($sigmaFile in $sigmaFiles) {
        if ($sigmaFile.Length -eq 0) {
            Fail "Sigma rule is empty: $($sigmaFile.FullName)"
        }

        $sigmaDocuments = Get-YamlDocuments -Path $sigmaFile.FullName
        foreach ($sigmaDocument in $sigmaDocuments) {
            foreach ($requiredProperty in @('title', 'id', 'description', 'logsource', 'detection')) {
                if ($null -eq $sigmaDocument.$requiredProperty) {
                    Fail "$($sigmaFile.FullName) is missing required Sigma property '$requiredProperty'."
                }
            }
        }
    }

    if (-not (Get-Command sigma -ErrorAction SilentlyContinue)) {
        Fail "sigma-cli is not installed or 'sigma' is not on PATH."
    }

    Write-Host 'Running Sigma validation...'
    & sigma check $sigmaDirectory
    if ($LASTEXITCODE -ne 0) {
        Fail "sigma check failed with exit code $LASTEXITCODE."
    }

    $bicepFiles = @(
        Get-ChildItem -LiteralPath $sentinelDirectory -Recurse -Filter '*.bicep' -File
    )

    if ($bicepFiles.Count -eq 0) {
        Fail 'No Sentinel Bicep rule files were found under detections/sentinel.'
    }

    foreach ($bicepFile in $bicepFiles) {
        $bicepContent = Get-Content -LiteralPath $bicepFile.FullName -Raw

        $requiredBicepChecks = @(
            @{ Pattern = '(?im)^\s*param\s+ruleGuid\s+string'; Description = 'stable ruleGuid parameter' }
            @{ Pattern = 'TimeGenerated\s*>\s*ago\('; Description = 'query time bound' }
            @{ Pattern = '\bdescription\s*:'; Description = 'rule description' }
            @{ Pattern = '\bcustomDetails\s*:'; Description = 'custom details' }
            @{ Pattern = '\bincidentConfiguration\s*:'; Description = 'incident configuration' }
            @{ Pattern = '\btactics\s*:'; Description = 'MITRE tactic mapping' }
            @{ Pattern = '\btechniques\s*:'; Description = 'MITRE technique mapping' }
            @{ Pattern = '\bqueryFrequency\s*:'; Description = 'query frequency' }
            @{ Pattern = '\bqueryPeriod\s*:'; Description = 'query period' }
        )

        foreach ($check in $requiredBicepChecks) {
            Require-Text `
                -Content $bicepContent `
                -Pattern $check.Pattern `
                -Description $check.Description `
                -Path $bicepFile.FullName
        }
    }

    $testFiles = @(
        Get-ChildItem -LiteralPath $testDirectory -Recurse -File |
        Where-Object { $_.Name -match '\.tests\.ya?ml$' }
    )

    if ($testFiles.Count -eq 0) {
        Fail 'No test contracts were found under detections/tests.'
    }

    foreach ($testFile in $testFiles) {
        $testDocuments = Get-YamlDocuments -Path $testFile.FullName

        foreach ($testDocument in $testDocuments) {
            if ($null -eq $testDocument.rule) {
                Fail "$($testFile.FullName) is missing the top-level 'rule' object."
            }

            foreach ($requiredRuleProperty in @('id', 'name', 'sentinel_bicep', 'sigma_rule')) {
                if ([string]::IsNullOrWhiteSpace([string]$testDocument.rule.$requiredRuleProperty)) {
                    Fail "$($testFile.FullName) is missing rule.$requiredRuleProperty."
                }
            }

            if ($null -eq $testDocument.telemetry) {
                Fail "$($testFile.FullName) is missing the top-level 'telemetry' object."
            }

            foreach ($requiredTelemetryProperty in @(
                'table',
                'time_window',
                'threshold',
                'grouping_field',
                'successful_result_type'
            )) {
                if ([string]::IsNullOrWhiteSpace([string]$testDocument.telemetry.$requiredTelemetryProperty)) {
                    Fail "$($testFile.FullName) is missing telemetry.$requiredTelemetryProperty."
                }
            }

            $referencedBicep = Join-Path $RepositoryRoot $testDocument.rule.sentinel_bicep
            $referencedSigma = Join-Path $RepositoryRoot $testDocument.rule.sigma_rule

            Require-File -Path $referencedBicep -Description 'Referenced Sentinel Bicep rule'
            Require-File -Path $referencedSigma -Description 'Referenced Sigma rule'

            $tests = @($testDocument.tests)
            if ($tests.Count -eq 0) {
                Fail "$($testFile.FullName) must include at least one test case."
            }

            $positiveTestCount = @($tests | Where-Object { $_.type -eq 'positive' }).Count
            $negativeTestCount = @($tests | Where-Object { $_.type -eq 'negative' }).Count

            if ($positiveTestCount -lt 1) {
                Fail "$($testFile.FullName) needs at least one positive test."
            }

            if ($negativeTestCount -lt 1) {
                Fail "$($testFile.FullName) needs at least one negative test."
            }

            foreach ($test in $tests) {
                foreach ($requiredTestProperty in @('name', 'type', 'events', 'expected')) {
                    if ($null -eq $test.$requiredTestProperty) {
                        Fail "$($testFile.FullName) has a test missing '$requiredTestProperty'."
                    }
                }

                if ($test.type -notin @('positive', 'negative')) {
                    Fail "$($testFile.FullName) test '$($test.name)' has invalid type '$($test.type)'. Use positive or negative."
                }

                if (@($test.events).Count -eq 0) {
                    Fail "$($testFile.FullName) test '$($test.name)' must include one or more events."
                }

                if ($null -eq $test.expected.matching_rows) {
                    Fail "$($testFile.FullName) test '$($test.name)' is missing expected.matching_rows."
                }
            }

        $referencedBicepContent = Get-Content -LiteralPath $referencedBicep -Raw

        $telemetryTable = [regex]::Escape([string]$testDocument.telemetry.table)
        Require-Text `
            -Content $referencedBicepContent `
            -Pattern "(?im)^\s*$telemetryTable\s*$" `
            -Description "telemetry table matching telemetry.table ($($testDocument.telemetry.table))" `
            -Path $referencedBicep
        }
    }

    if ($null -ne $testDocument.telemetry.required_query_patterns) {
        foreach ($pattern in @($testDocument.telemetry.required_query_patterns)) {
            Require-Text `
                -Content $referencedBicepContent `
                -Pattern ([regex]::Escape([string]$pattern)) `
                -Description "required query behavior: $pattern" `
                -Path $referencedBicep
        }
    }

    Write-Host ''
    Write-Host 'Detection contract validation passed.' -ForegroundColor Green
    Write-Host "Validated $($sigmaFiles.Count) Sigma rule(s), $($bicepFiles.Count) Sentinel Bicep rule(s), and $($testFiles.Count) test contract(s)." -ForegroundColor Green
}
finally {
    Pop-Location
}
