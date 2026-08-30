[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Fail {
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Error $Message
    exit 1
}

function Require-File {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Description
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Fail "$Description was not found: $Path"
    }
}

function Require-Text {
    param(
        [Parameter(Mandatory)]
        [string]$Content,

        [Parameter(Mandatory)]
        [string]$Pattern,

        [Parameter(Mandatory)]
        [string]$Description,

        [Parameter(Mandatory)]
        [string]$Path
    )

    if ($Content -notmatch $Pattern) {
        Fail "$Path is missing required $Description. Expected pattern: $Pattern"
    }
}

function Get-YamlDocuments {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $content = Get-Content -LiteralPath $Path -Raw

    if ([string]::IsNullOrWhiteSpace($content)) {
        Fail "YAML file is empty: $Path"
    }

    try {
        $document = $content | ConvertFrom-Yaml
    }
    catch {
        Fail "Invalid YAML in $Path. $($_.Exception.Message)"
    }

    if ($null -eq $document) {
        Fail "No YAML document was found in $Path"
    }

    # Return one array element, even when the YAML root is itself enumerable.
    return ,$document
}

function Get-OptionalProperty {
    param(
        [Parameter(Mandatory)]
        [object]$Object,

        [Parameter(Mandatory)]
        [string]$Name
    )

    $property = $Object.PSObject.Properties[$Name]

    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Get-RepositoryRelativePath {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$RepositoryRoot
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullRoot = [System.IO.Path]::GetFullPath($RepositoryRoot)

    return $fullPath.Substring($fullRoot.Length).TrimStart(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    ).Replace('\', '/')
}

Push-Location $RepositoryRoot

try {
    $sigmaDirectory = Join-Path $RepositoryRoot 'detections/sigma'
    $testDirectory = Join-Path $RepositoryRoot 'detections/tests'
    $sentinelDirectory = Join-Path $RepositoryRoot 'detections/sentinel'

    foreach ($directory in @(
        @{ Path = $sigmaDirectory; Description = 'Sigma directory' }
        @{ Path = $testDirectory; Description = 'test-contract directory' }
        @{ Path = $sentinelDirectory; Description = 'Sentinel Bicep directory' }
    )) {
        if (-not (Test-Path -LiteralPath $directory.Path -PathType Container)) {
            Fail "Missing $($directory.Description): $($directory.Path)"
        }
    }

    $sigmaFiles = @(
        Get-ChildItem -LiteralPath $sigmaDirectory -Recurse -File |
        Where-Object { $_.Extension -in @('.yml', '.yaml') }
    )

    if ($sigmaFiles.Count -eq 0) {
        Fail 'No Sigma rule files were found under detections/sigma.'
    }

    $sigmaByRelativePath = @{}

    foreach ($sigmaFile in $sigmaFiles) {
        if ($sigmaFile.Length -eq 0) {
            Fail "Sigma rule is empty: $($sigmaFile.FullName)"
        }

        $sigmaDocuments = @(Get-YamlDocuments -Path $sigmaFile.FullName)

        if ($sigmaDocuments.Count -ne 1) {
            Fail "$($sigmaFile.FullName) must contain exactly one Sigma rule document."
        }

        $sigmaDocument = $sigmaDocuments[0]

        foreach ($requiredProperty in @('title', 'id', 'description', 'logsource', 'detection')) {
            if ($null -eq (Get-OptionalProperty -Object $sigmaDocument -Name $requiredProperty)) {
                Fail "$($sigmaFile.FullName) is missing required Sigma property '$requiredProperty'."
            }
        }

        $relativePath = Get-RepositoryRelativePath `
            -Path $sigmaFile.FullName `
            -RepositoryRoot $RepositoryRoot

        $sigmaByRelativePath[$relativePath] = @{
            Path = $sigmaFile.FullName
            Document = $sigmaDocument
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

    $bicepByRelativePath = @{}

    $requiredBicepChecks = @(
        @{ Pattern = '(?im)^\s*param\s+ruleGuid\s+string'; Description = 'stable ruleGuid parameter' }
        @{ Pattern = '(?im)^\s*resource\s+\w+\s+[''"]Microsoft\.SecurityInsights/alertRules@'; Description = 'Sentinel alert rule resource' }
        @{ Pattern = '\bkind\s*:\s*[''"]Scheduled[''"]'; Description = 'scheduled rule kind' }
        @{ Pattern = '\bquery\s*:\s*[''"]{3}'; Description = 'multiline KQL query' }
        @{ Pattern = 'TimeGenerated\s*>\s*ago\('; Description = 'query time bound' }
        @{ Pattern = '\bdescription\s*:'; Description = 'rule description' }
        @{ Pattern = '\bcustomDetails\s*:'; Description = 'custom details' }
        @{ Pattern = '\bincidentConfiguration\s*:'; Description = 'incident configuration' }
        @{ Pattern = '\btactics\s*:'; Description = 'MITRE tactic mapping' }
        @{ Pattern = '\btechniques\s*:'; Description = 'MITRE technique mapping' }
        @{ Pattern = '\bqueryFrequency\s*:'; Description = 'query frequency' }
        @{ Pattern = '\bqueryPeriod\s*:'; Description = 'query period' }
    )

    foreach ($bicepFile in $bicepFiles) {
        $bicepContent = Get-Content -LiteralPath $bicepFile.FullName -Raw

        if ([string]::IsNullOrWhiteSpace($bicepContent)) {
            Fail "Sentinel Bicep rule is empty: $($bicepFile.FullName)"
        }

        foreach ($check in $requiredBicepChecks) {
            Require-Text `
                -Content $bicepContent `
                -Pattern $check.Pattern `
                -Description $check.Description `
                -Path $bicepFile.FullName
        }

        $relativePath = Get-RepositoryRelativePath `
            -Path $bicepFile.FullName `
            -RepositoryRoot $RepositoryRoot

        $bicepByRelativePath[$relativePath] = @{
            Path = $bicepFile.FullName
            Content = $bicepContent
        }
    }

    $testFiles = @(
        Get-ChildItem -LiteralPath $testDirectory -Recurse -File |
        Where-Object { $_.Name -match '\.tests\.ya?ml$' }
    )

    if ($testFiles.Count -eq 0) {
        Fail 'No test contracts were found under detections/tests.'
    }

    $referencedBicepPaths = @{}
    $referencedSigmaPaths = @{}
    $validatedContractCount = 0

    foreach ($testFile in $testFiles) {
        $testDocuments = Get-YamlDocuments -Path $testFile.FullName

        foreach ($testDocument in $testDocuments) {
            $rule = Get-OptionalProperty -Object $testDocument -Name 'rule'

            if ($null -eq $rule) {
                Fail "$($testFile.FullName) is missing the top-level 'rule' object."
            }

            foreach ($requiredRuleProperty in @('id', 'name', 'sentinel_bicep', 'sigma_rule')) {
                $value = Get-OptionalProperty -Object $rule -Name $requiredRuleProperty

                if ([string]::IsNullOrWhiteSpace([string]$value)) {
                    Fail "$($testFile.FullName) is missing rule.$requiredRuleProperty."
                }
            }

            $telemetry = Get-OptionalProperty -Object $testDocument -Name 'telemetry'

            if ($null -eq $telemetry) {
                Fail "$($testFile.FullName) is missing the top-level 'telemetry' object."
            }

            $telemetryTable = Get-OptionalProperty -Object $telemetry -Name 'table'

            if ([string]::IsNullOrWhiteSpace([string]$telemetryTable)) {
                Fail "$($testFile.FullName) is missing telemetry.table."
            }

            $referencedBicepRelativePath = ([string]$rule.sentinel_bicep).Replace('\', '/')
            $referencedSigmaRelativePath = ([string]$rule.sigma_rule).Replace('\', '/')

            if (-not $bicepByRelativePath.ContainsKey($referencedBicepRelativePath)) {
                Fail "$($testFile.FullName) references a missing Sentinel Bicep rule: $referencedBicepRelativePath"
            }

            if (-not $sigmaByRelativePath.ContainsKey($referencedSigmaRelativePath)) {
                Fail "$($testFile.FullName) references a missing Sigma rule: $referencedSigmaRelativePath"
            }

            $referencedBicep = $bicepByRelativePath[$referencedBicepRelativePath]
            $referencedSigma = $sigmaByRelativePath[$referencedSigmaRelativePath]

            $contractRuleId = [string](Get-OptionalProperty -Object $rule -Name 'id')
            $sigmaRuleId = [string](Get-OptionalProperty -Object $referencedSigma.Document -Name 'id')

            if ($contractRuleId -ne $sigmaRuleId) {
                Fail "$($testFile.FullName) rule.id '$contractRuleId' does not match Sigma id '$sigmaRuleId' in $($referencedSigma.Path)."
            }

            $tests = @(Get-OptionalProperty -Object $testDocument -Name 'tests')

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
                    if ($null -eq (Get-OptionalProperty -Object $test -Name $requiredTestProperty)) {
                        Fail "$($testFile.FullName) has a test missing '$requiredTestProperty'."
                    }
                }

                if ([string]$test.type -notin @('positive', 'negative')) {
                    Fail "$($testFile.FullName) test '$($test.name)' has invalid type '$($test.type)'. Use positive or negative."
                }

                if (@($test.events).Count -eq 0) {
                    Fail "$($testFile.FullName) test '$($test.name)' must include one or more events."
                }

                $expected = Get-OptionalProperty -Object $test -Name 'expected'
                $matchingRows = Get-OptionalProperty -Object $expected -Name 'matching_rows'

                if ($null -eq $matchingRows) {
                    Fail "$($testFile.FullName) test '$($test.name)' is missing expected.matching_rows."
                }

                if ([int]$matchingRows -lt 0) {
                    Fail "$($testFile.FullName) test '$($test.name)' expected.matching_rows must be zero or greater."
                }
            }

            $escapedTelemetryTable = [regex]::Escape([string]$telemetryTable)

            Require-Text `
                -Content $referencedBicep.Content `
                -Pattern "(?im)^\s*$escapedTelemetryTable\s*$" `
                -Description "telemetry table matching telemetry.table ($telemetryTable)" `
                -Path $referencedBicep.Path

            $validation = Get-OptionalProperty -Object $testDocument -Name 'validation'

            if ($null -ne $validation) {
                $requiredBicepPatterns = Get-OptionalProperty `
                    -Object $validation `
                    -Name 'required_bicep_patterns'

                foreach ($pattern in @($requiredBicepPatterns)) {
                    if ([string]::IsNullOrWhiteSpace([string]$pattern)) {
                        Fail "$($testFile.FullName) validation.required_bicep_patterns cannot contain an empty value."
                    }

                    Require-Text `
                        -Content $referencedBicep.Content `
                        -Pattern ([string]$pattern) `
                        -Description "contract-required Bicep pattern: $pattern" `
                        -Path $referencedBicep.Path
                }
            }

            $referencedBicepPaths[$referencedBicepRelativePath] = $true
            $referencedSigmaPaths[$referencedSigmaRelativePath] = $true
            $validatedContractCount++
        }
    }

    foreach ($bicepRelativePath in $bicepByRelativePath.Keys) {
        if (-not $referencedBicepPaths.ContainsKey($bicepRelativePath)) {
            Fail "Sentinel Bicep rule has no test contract: $bicepRelativePath"
        }
    }

    foreach ($sigmaRelativePath in $sigmaByRelativePath.Keys) {
        if (-not $referencedSigmaPaths.ContainsKey($sigmaRelativePath)) {
            Fail "Sigma rule has no test contract: $sigmaRelativePath"
        }
    }

    Write-Host ''
    Write-Host 'Detection contract validation passed.' -ForegroundColor Green
    Write-Host (
        "Validated {0} Sigma rule(s), {1} Sentinel Bicep rule(s), and {2} test contract(s)." -f `
        $sigmaFiles.Count,
        $bicepFiles.Count,
        $validatedContractCount
    ) -ForegroundColor Green
}
finally {
    Pop-Location
}
