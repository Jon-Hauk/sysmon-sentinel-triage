<#
.SYNOPSIS
    Proves Invoke-SysmonRedact.ps1 removes identifiers, keeps event meaning, and fails closed.

.DESCRIPTION
    Builds fake exports shaped like Log Analytics output, in both formats, and runs the real
    script on them. Every value here is invented. 198.18.0.0/15 is the RFC 2544 benchmarking
    range: not a documentation range, so the verifier treats it as real, and not routable.

    Runs offline. Exits 1 if any check fails.

.EXAMPLE
    .\tests\Test-Redactor.ps1
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts\Invoke-SysmonRedact.ps1'
$work = Join-Path ([System.IO.Path]::GetTempPath()) ('redact-test-' + [guid]::NewGuid())
$null = New-Item -ItemType Directory -Path $work
$script:failed = 0
$script:checks = 0

function Assert-True {
    param([bool]$Condition, [string]$Label)
    $script:checks++
    if ($Condition) {
        Write-Host "  ok    $Label"
    } else {
        $script:failed++
        Write-Host "  FAIL  $Label"
    }
}

function Invoke-Redactor {
    param([string[]]$Arguments)
    # With Stop, 5.1 turns the child's stderr into a terminating error, and refusals are expected.
    $ErrorActionPreference = 'Continue'
    $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script @Arguments 2>&1
    [pscustomobject]@{ Exit = $LASTEXITCODE; Output = ($output | Out-String) }
}

$eventData = '<EventData>' +
'<Data Name="Image">C:\Windows\System32\cmd.exe</Data>' +
'<Data Name="CommandLine">cmd /c copy C:\Users\alice\secret.txt \\FILESRV9\share &amp; curl https://private-thing.example.org/login?token=abc123</Data>' +
'<Data Name="User">LABHOST7\alice</Data>' +
'<Data Name="ParentImage">C:\Users\Alice Smith\AppData\Local\Temp\x.exe</Data>' +
'<Data Name="ProcessGuid">{11111111-2222-4333-8444-555555555555}</Data>' +
'<Data Name="TargetObject">HKU\S-1-5-21-1111111111-2222222222-3333333333-1001\Software\Microsoft\Windows\CurrentVersion\Run\Thing</Data>' +
'<Data Name="QueryName">tracker.private-dns.example.net</Data>' +
'<Data Name="Hashes">SHA256=ABCDEF0123456789</Data>' +
'<Data Name="SourceIp">198.18.0.77</Data>' +
'<Data Name="DestinationIp">2001:db8:1234::77</Data>' +
'<Data Name="SourceMac">AA-BB-CC-11-22-33</Data>' +
'<Data Name="Contact">alice.smith@private-mail.example.org</Data>' +
'<Data Name="SourceUser">NT AUTHORITY\SYSTEM</Data>' +
'<Data Name="UtcTime">2026-11-01 10:00:00.123</Data>' +
'</EventData>'

$rows = @(
    [pscustomobject]@{ TimeGenerated = '2026-11-01T10:00:00Z'; Computer = 'labhost7.tailabc123.ts.net'; Source = 'Microsoft-Windows-Sysmon'; EventID = 1; EventData = $eventData; _ResourceId = '/subscriptions/x/resourcegroups/my-private-rg' }
    [pscustomobject]@{ TimeGenerated = '2026-11-01T10:00:05Z'; Computer = 'LABHOST7'; Source = 'Microsoft-Windows-Sysmon'; EventID = 3; EventData = '<Data Name="ProcessGuid">{11111111-2222-4333-8444-555555555555}</Data><Data Name="User">LABHOST7\alice</Data>'; _ResourceId = '' }
)

$leaks = 'LABHOST7', 'FILESRV9', 'alice', 'Alice Smith', 'tailabc123', 'private-thing', 'token=abc123',
'tracker.private-dns', 'private-mail', '198.18.0.77', '2001:db8:1234', 'AA-BB-CC-11-22-33',
'S-1-5-21-1111111111', '11111111-2222', 'ABCDEF0123456789', 'my-private-rg'

$kept = 'C:\Windows\System32\cmd.exe', 'CurrentVersion\Run\Thing', 'NT AUTHORITY\SYSTEM',
'Microsoft-Windows-Sysmon', '2026-11-01 10:00:00.123', 'S-1-5-21-0-0-0-1001'

function Test-Format {
    param([string]$Extension)
    $source = Join-Path $work "fake$Extension"
    $target = Join-Path $work "out$Extension"
    if ($Extension -eq '.json') {
        ConvertTo-Json -InputObject $rows -Depth 8 | Set-Content -LiteralPath $source -Encoding UTF8
    } else {
        $rows | Export-Csv -LiteralPath $source -NoTypeInformation -Encoding UTF8
    }

    Write-Host "$Extension export"
    $run = Invoke-Redactor @('-Path', $source, '-OutputPath', $target)
    Assert-True ($run.Exit -eq 0) "exits 0 (got $($run.Exit))"
    Assert-True (Test-Path -LiteralPath $target) 'writes output'
    if (-not (Test-Path -LiteralPath $target)) { Write-Host $run.Output; return }

    $raw = Get-Content -LiteralPath $target -Raw -Encoding UTF8
    if ($Extension -eq '.json') {
        # ForEach-Object unrolls: on 5.1, ConvertFrom-Json emits an array as a single object.
        $decoded = @(Get-Content -LiteralPath $target -Raw -Encoding UTF8 | ConvertFrom-Json | ForEach-Object { $_ })
    } else {
        $decoded = @(Import-Csv -LiteralPath $target -Encoding UTF8)
    }
    $values = ($decoded | ForEach-Object { $_.PSObject.Properties.Value }) -join "`n"

    foreach ($needle in $leaks) {
        Assert-True ($raw.IndexOf($needle, [StringComparison]::OrdinalIgnoreCase) -lt 0) "removes $needle"
    }
    foreach ($needle in $kept) {
        Assert-True ($values.Contains($needle)) "keeps $needle"
    }

    $guids = [regex]::Matches($values, '\{00000000-0000-4000-8000-[0-9A-F]{12}\}') | ForEach-Object { $_.Value } | Select-Object -Unique
    Assert-True (@($guids).Count -eq 1) 'one GUID maps to one placeholder across events'
    Assert-True ($values.Contains('PC-01\user01')) 'same host and user map consistently'
    Assert-True ($decoded[0].Computer -eq 'PC-01.contoso.local') 'FQDN maps to its short placeholder'
}

try {
    Test-Format '.json'
    Test-Format '.csv'

    Write-Host 'fail-closed paths'
    $hidden = Join-Path $work 'hidden.json'
    $hiddenOut = Join-Path $work 'hidden-out.json'
    '[{"Computer":"LABHOST7","Note":"glued x198.18.0.7y address"}]' | Set-Content -LiteralPath $hidden -Encoding UTF8
    $run = Invoke-Redactor @('-Path', $hidden, '-OutputPath', $hiddenOut)
    Assert-True ($run.Exit -eq 1) "IP hidden from the pattern refuses (got $($run.Exit))"
    Assert-True (-not (Test-Path -LiteralPath $hiddenOut)) 'refusal writes no file'

    $inner = Join-Path $work 'inner.json'
    $innerOut = Join-Path $work 'inner-out.json'
    '[{"User":"LABHOST7\\soft","Note":"Microsoft Defender"}]' | Set-Content -LiteralPath $inner -Encoding UTF8
    $run = Invoke-Redactor @('-Path', $inner, '-OutputPath', $innerOut)
    Assert-True ($run.Exit -eq 1) 'term inside a longer word refuses'
    Assert-True ($run.Output -notmatch 'soft') 'refusal does not print the term without -ShowMap'
    $run = Invoke-Redactor @('-Path', $inner, '-OutputPath', $innerOut, '-AcceptResidual')
    Assert-True (($run.Exit -eq 0) -and (Test-Path -LiteralPath $innerOut)) '-AcceptResidual writes it'

    $shape = Join-Path $work 'api.json'
    '{"tables":[{"columns":[{"name":"Computer"}],"rows":[["LABHOST7"]]}]}' | Set-Content -LiteralPath $shape -Encoding UTF8
    $run = Invoke-Redactor @('-Path', $shape, '-OutputPath', (Join-Path $work 'api-out.json'))
    Assert-True ($run.Exit -ne 0) 'raw query API shape refuses'

    $plain = Join-Path $work 'notes.txt'
    'LABHOST7' | Set-Content -LiteralPath $plain
    $run = Invoke-Redactor @('-Path', $plain)
    Assert-True ($run.Exit -ne 0) 'unsupported extension refuses'

    Write-Host 'options'
    $extra = Join-Path $work 'extra.json'
    $extraOut = Join-Path $work 'extra-out.json'
    '[{"Note":"owner is Pat Example on my-tailnet"}]' | Set-Content -LiteralPath $extra -Encoding UTF8
    $run = Invoke-Redactor @('-Path', $extra, '-OutputPath', $extraOut, '-ExtraTerm', 'Pat Example')
    $body = if (Test-Path -LiteralPath $extraOut) { Get-Content -LiteralPath $extraOut -Raw } else { '' }
    Assert-True (($run.Exit -eq 0) -and ($body -notmatch 'Pat Example')) '-ExtraTerm removes a value no field reveals'

    $dryOut = Join-Path $work 'dry-out.json'
    $run = Invoke-Redactor @('-Path', (Join-Path $work 'fake.json'), '-OutputPath', $dryOut, '-DryRun')
    Assert-True (($run.Exit -eq 0) -and -not (Test-Path -LiteralPath $dryOut)) '-DryRun writes no file'
    Assert-True ($run.Output -notmatch 'LABHOST7|alice') 'report stays free of real values'
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force
}

Write-Host ''
Write-Host ("{0} checks, {1} failed" -f $script:checks, $script:failed)
if ($script:failed -gt 0) { exit 1 }
