# CISGuard fixed read-only Windows collector v1.0.0
# Windows PowerShell 5.1 compatible. No caller-provided commands or configuration writes.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$collectorVersion = '0.3.0'
$capturedAt = [DateTime]::UtcNow.ToString('o')
$sources = [ordered]@{}

function New-SourceResult {
    param(
        [string]$Identity,
        [string]$State,
        [Nullable[int]]$ExitStatus,
        $Data,
        [string]$ErrorCode = $null,
        [string]$Limitation = $null
    )
    return [ordered]@{
        source_identity = $Identity
        timestamp = [DateTime]::UtcNow.ToString('o')
        state = $State
        exit_status = $ExitStatus
        data = $Data
        error_code = $ErrorCode
        limitation = $Limitation
    }
}

function Get-FailureState {
    param([System.Management.Automation.ErrorRecord]$Record)
    $text = [string]$Record.Exception.Message
    if ($text -match 'access.*denied|unauthorized|privilege') { return 'denied' }
    if ($Record.Exception -is [System.Management.Automation.CommandNotFoundException]) { return 'unavailable' }
    return 'error'
}

try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $editionId = $null
    try {
        $editionId = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID).EditionID
    } catch { }
    $sources.os_identity = New-SourceResult 'Get-CimInstance:Win32_OperatingSystem' 'success' 0 ([ordered]@{
        caption = [string]$os.Caption
        version = [string]$os.Version
        build_number = [string]$os.BuildNumber
        product_type = [int]$os.ProductType
        edition_id = if ($null -eq $editionId) { $null } else { [string]$editionId }
    })
} catch {
    $state = Get-FailureState $_
    $sources.os_identity = New-SourceResult 'Get-CimInstance:Win32_OperatingSystem' $state $null $null ('CIM_' + $state.ToUpper())
}

try {
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $sources.domain_membership = New-SourceResult 'Get-CimInstance:Win32_ComputerSystem' 'success' 0 ([ordered]@{
        part_of_domain = [bool]$computerSystem.PartOfDomain
        context = if ([bool]$computerSystem.PartOfDomain) { 'domain' } else { 'workgroup' }
    }) $null 'Domain membership does not prove effective domain policy.'
} catch {
    $state = Get-FailureState $_
    $sources.domain_membership = New-SourceResult 'Get-CimInstance:Win32_ComputerSystem' $state $null $null ('CIM_' + $state.ToUpper()) 'Domain membership unknown.'
}

try {
    $netAccounts = @(& net.exe accounts 2>$null)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) { throw "net accounts exit $exitCode" }
    $sources.account_policy = New-SourceResult 'net.exe:accounts' 'success' $exitCode ([ordered]@{
        scope = 'local_or_command_reported'
        raw_lines = @($netAccounts | ForEach-Object { [string]$_ })
        parsed_values = $null
    }) $null 'Text is locale-dependent; normalization does not guess labels.'
} catch {
    $state = Get-FailureState $_
    $sources.account_policy = New-SourceResult 'net.exe:accounts' $state $LASTEXITCODE $null ('NET_ACCOUNTS_' + $state.ToUpper()) 'Locale-independent parsing unavailable.'
}

$tempDirectory = $null
try {
    $tempDirectory = Join-Path ([IO.Path]::GetTempPath()) ('cisguard-secedit-' + [Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($tempDirectory) | Out-Null
    $exportPath = Join-Path $tempDirectory 'security-policy.inf'
    & secedit.exe /export /cfg $exportPath /quiet 2>$null | Out-Null
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0 -or -not (Test-Path -LiteralPath $exportPath)) { throw "secedit export exit $exitCode" }
    $allowedKeys = @(
        'MinimumPasswordAge', 'MaximumPasswordAge', 'MinimumPasswordLength',
        'PasswordComplexity', 'PasswordHistorySize', 'LockoutBadCount',
        'ResetLockoutCount', 'LockoutDuration', 'ClearTextPassword'
    )
    $selected = [ordered]@{}
    foreach ($line in [IO.File]::ReadAllLines($exportPath, [Text.Encoding]::Unicode)) {
        if ($line -match '^\s*([^;][^=]+?)\s*=\s*(.*?)\s*$') {
            $key = $matches[1].Trim()
            if ($allowedKeys -contains $key) { $selected[$key] = $matches[2] }
        }
    }
    $sources.local_security_policy = New-SourceResult 'secedit.exe:export:selected-system-access' 'success' $exitCode $selected $null 'Configured local policy; not proof of effective domain policy.'
} catch {
    $state = Get-FailureState $_
    $sources.local_security_policy = New-SourceResult 'secedit.exe:export:selected-system-access' $state $LASTEXITCODE $null ('SECEDIT_' + $state.ToUpper()) 'Configured local policy unavailable.'
} finally {
    if ($null -ne $tempDirectory -and (Test-Path -LiteralPath $tempDirectory)) {
        Remove-Item -LiteralPath $tempDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}

try {
    $auditLines = @(& auditpol.exe /get /category:* /r 2>$null)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) { throw "auditpol exit $exitCode" }
    $redactedLines = @($auditLines | ForEach-Object {
        $line = [string]$_
        if ($env:COMPUTERNAME) { $line = $line.Replace($env:COMPUTERNAME, '[REDACTED-HOST]') }
        $line
    })
    $sources.audit_policy = New-SourceResult 'auditpol.exe:get-category-all-csv' 'success' $exitCode ([ordered]@{
        csv_lines = $redactedLines
        parsed_entries = $null
    }) $null 'CSV headers/settings can be localized; raw bounded output retained without guessing.'
} catch {
    $state = Get-FailureState $_
    $sources.audit_policy = New-SourceResult 'auditpol.exe:get-category-all-csv' $state $LASTEXITCODE $null ('AUDITPOL_' + $state.ToUpper())
}

try {
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object { @('Domain','Private','Public') -contains $_.Name } | ForEach-Object {
        [ordered]@{
            name = [string]$_.Name
            enabled = if ($null -eq $_.Enabled) { $null } else { [bool]$_.Enabled }
            default_inbound_action = [string]$_.DefaultInboundAction
            default_outbound_action = [string]$_.DefaultOutboundAction
            log_allowed = if ($null -eq $_.LogAllowed) { $null } else { [bool]$_.LogAllowed }
            log_blocked = if ($null -eq $_.LogBlocked) { $null } else { [bool]$_.LogBlocked }
        }
    })
    $sources.firewall_profiles = New-SourceResult 'Get-NetFirewallProfile:ActiveStore' 'success' 0 $profiles $null 'ActiveStore profile state; rule-level effective policy is not collected.'
} catch {
    $state = Get-FailureState $_
    $sources.firewall_profiles = New-SourceResult 'Get-NetFirewallProfile:ActiveStore' $state $null $null ('FIREWALL_' + $state.ToUpper())
}

try {
    $allowedServices = @('WinDefend','MpsSvc','EventLog','wuauserv','RemoteRegistry')
    $serviceFacts = @()
    foreach ($serviceName in $allowedServices) {
        $service = Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $serviceName + "'") -ErrorAction SilentlyContinue
        $serviceFacts += [ordered]@{
            name = $serviceName
            present = ($null -ne $service)
            start_mode = if ($null -eq $service) { $null } else { [string]$service.StartMode }
            state = if ($null -eq $service) { $null } else { [string]$service.State }
        }
    }
    $sources.services = New-SourceResult 'Get-CimInstance:Win32_Service:allowlist' 'success' 0 $serviceFacts $null 'Startup configuration and current state are separate facts.'
} catch {
    $state = Get-FailureState $_
    $sources.services = New-SourceResult 'Get-CimInstance:Win32_Service:allowlist' $state $null $null ('SERVICES_' + $state.ToUpper())
}

try {
    $registryAllowlist = @(
        @{ path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; name='EnableLUA' },
        @{ path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; name='ConsentPromptBehaviorAdmin' },
        @{ path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; name='LmCompatibilityLevel' },
        @{ path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; name='NoLMHash' },
        @{ path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; name='EnableScriptBlockLogging' }
    )
    $registryFacts = @()
    foreach ($entry in $registryAllowlist) {
        try {
            $item = Get-ItemProperty -LiteralPath $entry.path -Name $entry.name -ErrorAction Stop
            $registryFacts += [ordered]@{ path=$entry.path; name=$entry.name; state='present'; value=$item.($entry.name) }
        } catch [System.Management.Automation.ItemNotFoundException] {
            $registryFacts += [ordered]@{ path=$entry.path; name=$entry.name; state='missing'; value=$null }
        } catch [System.Management.Automation.PSArgumentException] {
            $registryFacts += [ordered]@{ path=$entry.path; name=$entry.name; state='missing'; value=$null }
        } catch [System.UnauthorizedAccessException] {
            $registryFacts += [ordered]@{ path=$entry.path; name=$entry.name; state='denied'; value=$null }
        }
    }
    $sources.registry_settings = New-SourceResult 'Get-ItemProperty:security-allowlist' 'success' 0 $registryFacts $null 'Missing, denied, and configured values remain distinct.'
} catch {
    $state = Get-FailureState $_
    $sources.registry_settings = New-SourceResult 'Get-ItemProperty:security-allowlist' $state $null $null ('REGISTRY_' + $state.ToUpper())
}

try {
    $pathAllowlist = @($env:SystemRoot, (Join-Path $env:SystemRoot 'System32'))
    $permissionFacts = @()
    foreach ($path in $pathAllowlist) {
        try {
            $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
            $permissionFacts += [ordered]@{
                path_identity = if ($path -eq $env:SystemRoot) { '%SystemRoot%' } else { '%SystemRoot%\System32' }
                state = 'success'
                access_rules_protected = [bool]$acl.AreAccessRulesProtected
                access_rule_count = @($acl.Access).Count
            }
        } catch [System.UnauthorizedAccessException] {
            $permissionFacts += [ordered]@{ path_identity=$path; state='denied'; access_rules_protected=$null; access_rule_count=$null }
        }
    }
    $sources.permissions = New-SourceResult 'Get-Acl:path-allowlist' 'success' 0 $permissionFacts $null 'Identity/SID details are intentionally omitted.'
} catch {
    $state = Get-FailureState $_
    $sources.permissions = New-SourceResult 'Get-Acl:path-allowlist' $state $null $null ('ACL_' + $state.ToUpper())
}

$capture = [ordered]@{
    schema_version = '1.0.0'
    collector_version = $collectorVersion
    captured_at = $capturedAt
    sources = $sources
}

try {
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
    $capture | ConvertTo-Json -Depth 12 -Compress
} catch {
    [Console]::Error.WriteLine('CISGuard collector serialization failed.')
    exit 1
}
