<#
.SYNOPSIS
    Redacts identifying values from a CSV or JSON export of Sysmon events, or refuses to write.

.DESCRIPTION
    Parses the export first, so every rule sees decoded values. Scanning the raw file does not
    work: JSON doubles each backslash and CSV doubles each quote, so a path pattern that fits
    one format misses the other.

    1. Learn. Walk every value and collect identifying terms from the places that hold them:
       host, user and DNS fields, <Data Name="..."> elements, C:\Users\<name> paths, UNC paths,
       URLs and email addresses.
    2. Replace. Each learned term is replaced wherever it appears, including free text such as
       CommandLine. SIDs, GUIDs, MACs, IPv4 and IPv6 addresses are replaced by pattern, and URLs
       lose everything after the host. Placeholders stay consistent, so events still correlate.
    3. Verify. Search the result again with stricter rules. If anything survives, no file is
       written and the script exits 1.

    Free text can carry things no rule knows about, such as a password typed into a command
    line. Passing this script does not prove an export is safe: read the output before sharing.

.PARAMETER Path
    Input .csv or .json file. JSON must be an array of records or a single record, which is
    what the Azure portal exports. The raw query API shape (tables/columns/rows) is refused.

.PARAMETER OutputPath
    Destination for redacted output. Defaults to <input>.redacted.<ext>.

.PARAMETER ExtraTerm
    Literal values to remove that no field reveals, such as a real name or a tailnet name.

.PARAMETER DryRun
    Run all three stages and print the report, but write no file.

.PARAMETER ShowMap
    Print original-to-placeholder pairs. Off by default to keep real values out of console logs.

.PARAMETER AcceptResidual
    Write even if a learned term survives inside a longer word, such as a user named "soft"
    inside "Microsoft". Surviving IPs, SIDs, emails and user paths still refuse.

.EXAMPLE
    .\scripts\Invoke-SysmonRedact.ps1 -Path .\exports\events.json -DryRun

.EXAMPLE
    .\scripts\Invoke-SysmonRedact.ps1 -Path .\exports\events.csv -ExtraTerm 'my-tailnet'

.NOTES
    Apache-2.0. No warranty. Runs on Windows PowerShell 5.1. Tests: tests\Test-Redactor.ps1.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$Path,

    [string]$OutputPath,

    [string[]]$ExtraTerm = @(),

    [switch]$DryRun,

    [switch]$ShowMap,

    [switch]$AcceptResidual
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Field names, matched case-insensitively against CSV columns, JSON keys and <Data Name="...">.
$hostFields = 'Computer', 'ComputerName', 'Hostname', 'SourceHostname', 'Workstation', 'WorkstationName'
$siteFields = 'DestinationHostname', 'QueryName'
$userFields = 'User', 'UserName', 'SourceUser', 'TargetUser', 'Account', 'AccountName',
'SubjectUserName', 'TargetUserName'
$dropFields = 'Hashes', 'Hash', 'QueryResults', '_ResourceId', 'ResourceId'

# Values that identify nobody. Authorities are the part before the backslash in NT AUTHORITY\SYSTEM.
$authorities = 'NT AUTHORITY', 'NT SERVICE', 'NT VIRTUAL MACHINE', 'BUILTIN', 'Window Manager',
'Font Driver Host', 'APPLICATION PACKAGE AUTHORITY', 'IIS APPPOOL'
$cloudRealms = 'AzureAD', 'MicrosoftAccount'
$ignored = @('-', 'N/A', 'unknown', '<unknown>', 'localhost', 'WORKGROUP', 'SYSTEM', 'LOCAL SERVICE',
    'NETWORK SERVICE', 'ANONYMOUS LOGON', 'Administrator', 'Public', 'Default', 'Default User',
    'All Users', 'wsl$')
$placeholderShape = '^(PC-\d+|user\d+|CONTOSO\d*|contoso\.local|contoso\.onmicrosoft\.com)$'

$userPathPattern = '(?i)\b[A-Z]:\\Users\\(?:(?<n>[^\\/:*?"<>|\r\n]+)(?=\\)|(?<n>[^\\/:*?"<>|\s]+))'
$uncPattern = '(?<![\w\\])\\\\(?<h>[A-Za-z0-9][A-Za-z0-9._-]*)\\'
$urlPattern = '(?i)\b(?<s>https?|ftp)://(?:[^/@\s"''<>|]*@)?(?<h>\[[^\]\s]+\]|[^/:?#\s"''<>|]+)[^\s"''<>|]*'
$emailPattern = '(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b'
$computerXmlPattern = '(?i)<Computer>(?<v>[^<]+)</Computer>'
$dataXmlPattern = '<Data Name="(?<k>[^"]+)">(?<v>[^<]*)</Data>'
$dropXmlPattern = '(?i)(?<open><Data Name="(?:' + ($dropFields -join '|') + ')">)[^<]*(?<close></Data>)'
$sidPattern = 'S-1-(?<a>5-21|12-1)-\d+-\d+-\d+-(?<rid>\d+)'
$guidPattern = '\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?'
$macPattern = '(?i)\b(?:[0-9A-F]{2}[-:]){5}[0-9A-F]{2}\b'
$ipv4Pattern = '\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b'
$ipv6Pattern = '(?<![\w:.\\])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f.]*(?:%\w+)?(?![\w:])'

$terms = @{}
$termCounts = @{ Host = 0; Domain = 0; User = 0; Site = 0; Email = 0; Extra = 0 }
$guidMap = @{}
$macMap = @{}
$ipv4Map = @{}
$ipv6Map = @{}

function Test-IsIpAddress {
    param([string]$Value)
    $parsed = $null
    [System.Net.IPAddress]::TryParse($Value.Trim('[', ']'), [ref]$parsed)
}

function Add-Term {
    param([string]$Term, [string]$Kind)
    $t = $Term.Trim()
    if ($t.Length -lt 2 -or $ignored -contains $t -or $terms.ContainsKey($t) -or $t -match $placeholderShape) {
        return
    }
    $termCounts[$Kind]++
    $n = $termCounts[$Kind]
    $terms[$t] = switch ($Kind) {
        'Host' { 'PC-{0:D2}' -f $n }
        'Domain' { if ($n -eq 1) { 'CONTOSO' } else { "CONTOSO$n" } }
        'User' { 'user{0:D2}' -f $n }
        'Site' { 'site-{0:D2}.example.invalid' -f $n }
        'Email' { 'mail{0:D2}@contoso.onmicrosoft.com' -f $n }
        'Extra' { 'REDACTED-{0:D2}' -f $n }
    }
}

function Add-HostTerm {
    param([string]$Value)
    $v = $Value.Trim().TrimEnd('.')
    if (-not $v -or (Test-IsIpAddress $v)) { return }
    $short, $suffix = $v -split '\.', 2
    Add-Term $short 'Host'
    if ($suffix -and $terms.ContainsKey($short)) {
        # The short name, the suffix and the full name are each identifying on their own.
        if (-not $terms.ContainsKey($suffix)) { $terms[$suffix] = 'contoso.local' }
        $terms[$v] = $terms[$short] + '.contoso.local'
    }
}

function Add-SiteTerm {
    param([string]$Value)
    $v = $Value.Trim().TrimEnd('.')
    if (-not $v -or $v.StartsWith('[') -or (Test-IsIpAddress $v)) { return }
    Add-Term $v 'Site'
}

function Add-UserTerm {
    param([string]$Value)
    $v = $Value.Trim()
    if ($v -match '@') { return }
    if ($v -match '^(?<d>[^\\]+)\\(?<u>.+)$') {
        $domain = $Matches['d']
        $user = $Matches['u']
        if ($authorities -contains $domain) { return }
        if ($cloudRealms -notcontains $domain -and -not $terms.ContainsKey($domain)) {
            Add-Term $domain 'Domain'
        }
        if ($user.EndsWith('$')) { Add-HostTerm $user.TrimEnd('$') } else { Add-Term $user 'User' }
    } else {
        Add-Term $v 'User'
    }
}

function Read-Value {
    param([string]$Name, [string]$Value)
    if ($hostFields -contains $Name) { Add-HostTerm $Value }
    elseif ($siteFields -contains $Name) { Add-SiteTerm $Value }
    elseif ($userFields -contains $Name) { Add-UserTerm $Value }

    foreach ($m in [regex]::Matches($Value, $computerXmlPattern)) { Add-HostTerm $m.Groups['v'].Value }
    foreach ($m in [regex]::Matches($Value, $dataXmlPattern)) { Read-Value $m.Groups['k'].Value $m.Groups['v'].Value }
    foreach ($m in [regex]::Matches($Value, $userPathPattern)) { Add-Term $m.Groups['n'].Value 'User' }
    foreach ($m in [regex]::Matches($Value, $uncPattern)) { Add-HostTerm $m.Groups['h'].Value }
    foreach ($m in [regex]::Matches($Value, $urlPattern)) { Add-SiteTerm $m.Groups['h'].Value }
    foreach ($m in [regex]::Matches($Value, $emailPattern)) {
        if ($m.Value -notmatch '@contoso\.onmicrosoft\.com$') { Add-Term $m.Value 'Email' }
    }
}

function Get-Placeholder {
    param([hashtable]$Map, [string]$Key, [scriptblock]$Make)
    if (-not $Map.ContainsKey($Key)) { $Map[$Key] = & $Make ($Map.Count + 1) }
    $Map[$Key]
}

function Get-TestNetAddress {
    param([int]$Number)
    # RFC 5737 gives three /24s. Past 762 addresses, later ones share the last placeholder.
    $blocks = '192.0.2', '198.51.100', '203.0.113'
    $i = [Math]::Min($Number - 1, 761)
    '{0}.{1}' -f $blocks[[int][Math]::Floor($i / 254)], (($i % 254) + 1)
}

function Protect-Value {
    param([string]$Name, [string]$Value)
    if ($dropFields -contains $Name) { return 'REDACTED' }

    $out = [regex]::Replace($Value, $dropXmlPattern, '${open}REDACTED${close}')

    # A URL path or query string can hold tokens, so only the host survives, as a placeholder.
    $out = [regex]::Replace($out, $urlPattern, [System.Text.RegularExpressions.MatchEvaluator] {
            param($m)
            $h = $m.Groups['h'].Value
            if ($terms.ContainsKey($h)) { $h = $terms[$h] }
            '{0}://{1}/redacted' -f $m.Groups['s'].Value, $h
        })

    $out = [regex]::Replace($out, $sidPattern, 'S-1-${a}-0-0-0-${rid}')

    $out = [regex]::Replace($out, $guidPattern, [System.Text.RegularExpressions.MatchEvaluator] {
            param($m)
            $key = $m.Value.Trim('{', '}').ToLowerInvariant()
            $guid = Get-Placeholder $guidMap $key { param($n) '00000000-0000-4000-8000-{0:X12}' -f $n }
            if ($m.Value.StartsWith('{')) { "{$guid}" } else { $guid }
        })

    $out = [regex]::Replace($out, $macPattern, [System.Text.RegularExpressions.MatchEvaluator] {
            param($m)
            $key = ($m.Value -replace '[:-]', '').ToUpperInvariant()
            Get-Placeholder $macMap $key { param($n) '00-00-5E-00-53-{0:X2}' -f [Math]::Min($n, 255) }
        })

    # IPv6 goes first so that ::ffff:a.b.c.d is handled as one address.
    $out = [regex]::Replace($out, $ipv6Pattern, [System.Text.RegularExpressions.MatchEvaluator] {
            param($m)
            $parsed = $null
            $isAddress = [System.Net.IPAddress]::TryParse($m.Value, [ref]$parsed)
            if (-not $isAddress -or $parsed.AddressFamily -ne 'InterNetworkV6') { return $m.Value }
            if ($m.Value -eq '::' -or $m.Value -eq '::1') { return $m.Value }
            Get-Placeholder $ipv6Map $m.Value.ToLowerInvariant() { param($n) '2001:db8::{0:x}' -f $n }
        })

    $out = [regex]::Replace($out, $ipv4Pattern, [System.Text.RegularExpressions.MatchEvaluator] {
            param($m)
            if ($m.Value -eq '127.0.0.1' -or $m.Value -eq '0.0.0.0') { return $m.Value }
            Get-Placeholder $ipv4Map $m.Value { param($n) Get-TestNetAddress $n }
        })

    if ($script:termRegex) {
        $out = $script:termRegex.Replace($out, [System.Text.RegularExpressions.MatchEvaluator] {
                param($m)
                $terms[$m.Value]
            })
    }
    $out
}

function Update-Node {
    param($Node, [string]$Name, [scriptblock]$Action)
    if ($null -eq $Node) { return $null }
    if ($Node -is [string]) { return (& $Action $Name $Node) }
    if ($Node -is [System.Collections.IEnumerable]) {
        return , @(foreach ($item in $Node) { Update-Node $item $Name $Action })
    }
    if ($Node -is [System.Management.Automation.PSCustomObject]) {
        # Host fields first, so LABHOST\alice maps LABHOST to its PC-nn name, not a domain.
        $properties = $Node.PSObject.Properties | Sort-Object { $hostFields -notcontains $_.Name }
        foreach ($property in $properties) {
            $property.Value = Update-Node $property.Value $property.Name $Action
        }
    }
    $Node
}

$resolved = (Resolve-Path -LiteralPath $Path).Path
$ext = [System.IO.Path]::GetExtension($resolved).ToLowerInvariant()
if ($ext -ne '.csv' -and $ext -ne '.json') { throw "Unsupported input '$ext': expected .csv or .json." }

if (-not $OutputPath) {
    $folder = [System.IO.Path]::GetDirectoryName($resolved)
    $base = [System.IO.Path]::GetFileNameWithoutExtension($resolved)
    $OutputPath = Join-Path $folder ($base + '.redacted' + $ext)
}

if ($ext -eq '.csv') {
    $records = @(Import-Csv -LiteralPath $resolved -Encoding UTF8)
} else {
    $records = Get-Content -LiteralPath $resolved -Raw -Encoding UTF8 | ConvertFrom-Json
    $first = @($records)[0]
    if ($first -isnot [System.Management.Automation.PSCustomObject] -or $first.PSObject.Properties['tables']) {
        throw 'Unsupported JSON shape: expected records with named fields, so column names can be trusted.'
    }
}
if (@($records).Count -eq 0) { throw 'Input holds no records.' }

# Stage 1: learn.
foreach ($term in $ExtraTerm) { Add-Term $term 'Extra' }
$records = Update-Node $records '' { param($n, $v) Read-Value $n $v; $v }

# Stage 2: replace, longest term first, so a full name wins over its short form.
$script:termRegex = $null
$longestFirst = @($terms.Keys | Sort-Object -Property Length -Descending)
if ($longestFirst.Count -gt 0) {
    $alternatives = ($longestFirst | ForEach-Object { [regex]::Escape($_) }) -join '|'
    $script:termRegex = [regex]::new("(?<!\w)(?:$alternatives)(?!\w)", 'IgnoreCase')
}
$records = Update-Node $records '' { param($n, $v) Protect-Value $n $v }

# Stage 3: verify the values that would be written, with rules stricter than stage 2.
$flat = New-Object System.Text.StringBuilder
$null = Update-Node $records '' { param($n, $v) [void]$flat.AppendLine($v); $v }
$text = $flat.ToString()

$hardFailures = New-Object System.Collections.Generic.List[string]
foreach ($m in [regex]::Matches($text, '(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)')) {
    if ($m.Value -notmatch '^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|127\.0\.0\.1$|0\.0\.0\.0$)') {
        $hardFailures.Add('IPv4 address')
    }
}
foreach ($m in [regex]::Matches($text, 'S-1-(?:5-21|12-1)-(?!0-0-0-)')) { $hardFailures.Add('SID') }
foreach ($m in [regex]::Matches($text, $emailPattern)) {
    if ($m.Value -notmatch '@contoso\.onmicrosoft\.com$') { $hardFailures.Add('email address') }
}
$safeProfile = '(?i)\b[A-Z]:\\Users\\(?!user\d+\b|Public\b|Default\b|Default User\b|All Users\b)'
foreach ($m in [regex]::Matches($text, $safeProfile)) { $hardFailures.Add('user profile path') }

# Stage 2 stops at word boundaries; here a term hidden inside a longer word counts as well.
$residual = @($terms.Keys | Where-Object {
        $_.Length -ge 3 -and $text.IndexOf($_, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
    })

Write-Host "Records: $(@($records).Count)"
Write-Host ("Terms:   {0} hosts, {1} domains, {2} users, {3} sites, {4} emails, {5} extra" -f
    $termCounts.Host, $termCounts.Domain, $termCounts.User, $termCounts.Site, $termCounts.Email, $termCounts.Extra)
Write-Host ("Pattern: {0} IPv4, {1} IPv6, {2} MACs, {3} GUIDs" -f
    $ipv4Map.Count, $ipv6Map.Count, $macMap.Count, $guidMap.Count)

if ($ShowMap) {
    foreach ($key in ($terms.Keys | Sort-Object)) { Write-Host ("  {0} -> {1}" -f $key, $terms[$key]) }
    foreach ($key in ($ipv4Map.Keys | Sort-Object)) { Write-Host ("  {0} -> {1}" -f $key, $ipv4Map[$key]) }
    foreach ($term in $residual) { Write-Host "  residual: $term" }
}

$refuse = $false
if ($hardFailures.Count -gt 0) {
    $refuse = $true
    foreach ($group in ($hardFailures | Group-Object)) {
        Write-Host ("Survived redaction: {0} x {1}" -f $group.Count, $group.Name)
    }
}
if ($residual.Count -gt 0 -and -not $AcceptResidual) {
    $refuse = $true
    Write-Host ("Survived redaction: {0} learned term(s) inside longer words. Review with -ShowMap, then rerun with -AcceptResidual if they are harmless." -f $residual.Count)
}
if ($refuse) {
    Write-Host 'REFUSED: no file written.'
    exit 1
}

if ($DryRun) {
    Write-Host 'Dry run passed. No file written.'
    return
}

if ($ext -eq '.csv') {
    $content = ($records | ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine
} else {
    $content = ConvertTo-Json -InputObject $records -Depth 32
}
[System.IO.File]::WriteAllText($OutputPath, $content, (New-Object System.Text.UTF8Encoding $false))
Write-Host "Wrote: $OutputPath"
Write-Host 'Read it before sharing: free text can hold things no rule knows about.'
