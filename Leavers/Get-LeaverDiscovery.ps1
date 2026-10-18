#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only report of everything a leaver owns, controls or has access to in Microsoft 365 / Entra ID.

.DESCRIPTION
    Run this BEFORE Invoke-UserOffboarding.ps1. It changes nothing. For each user it reports:
      * account state, manager, direct reports, last sign-in, admin roles
      * licences (direct vs inherited from a group)
      * group memberships, and groups / Teams the user owns (flagging where they are the only owner)
      * app registrations and service principals the user owns
      * Intune managed devices and Entra registered devices
      * OneDrive location and size
      * mailbox: type, size, archive, holds, forwarding, who has Full Access / Send As
      * (optional, slow) shared mailboxes the user has Full Access to
    and finishes with a list of risk flags: things to sort out before or during offboarding.

    Use -ReportPath to also save a Markdown report per user (handy to attach to the ticket).

.NOTES
    Graph delegated scopes requested (verify against current Graph docs and trim as needed):
      User.Read.All, Group.Read.All, Directory.Read.All, RoleManagement.Read.Directory,
      Files.Read.All, Organization.Read.All, DeviceManagementManagedDevices.Read.All, AuditLog.Read.All
    Exchange Online: needs ExchangeOnlineManagement and a role that can read mailboxes. Use -SkipExchange
    to leave mailbox checks out. Sections you lack permission for are skipped with a warning.

.EXAMPLE
    .\Get-LeaverDiscovery.ps1 -UserPrincipalName jane.smith@contoso.com -ReportPath .\Reports

.EXAMPLE
    .\Get-LeaverDiscovery.ps1 -UserPrincipalName a@contoso.com, b@contoso.com -IncludeMailboxAccess
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string[]]$UserPrincipalName,

    [switch]$SkipExchange,

    # Slow on large tenants: checks every shared mailbox for access by the user
    [switch]$IncludeMailboxAccess,

    # Folder for a Markdown report per user
    [string]$ReportPath,

    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint,
    [string]$ExchangeOrganization
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Pre-flight and connections
# ---------------------------------------------------------------------------
$required = 'Microsoft.Graph.Users', 'Microsoft.Graph.Groups', 'Microsoft.Graph.Identity.DirectoryManagement',
            'Microsoft.Graph.Identity.Governance', 'Microsoft.Graph.DeviceManagement', 'Microsoft.Graph.Files'
foreach ($module in $required) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        throw "Module '$module' not found. Run: Install-Module Microsoft.Graph -Scope CurrentUser"
    }
    Import-Module $module
}

if ($CertificateThumbprint) {
    if (-not $TenantId -or -not $ClientId) { throw '-TenantId and -ClientId are required with -CertificateThumbprint.' }
    Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome
}
else {
    $connect = @{
        Scopes    = 'User.Read.All', 'Group.Read.All', 'Directory.Read.All', 'RoleManagement.Read.Directory',
                    'Files.Read.All', 'Organization.Read.All', 'DeviceManagementManagedDevices.Read.All', 'AuditLog.Read.All'
        NoWelcome = $true
    }
    if ($TenantId) { $connect.TenantId = $TenantId }
    Connect-MgGraph @connect
}

if (-not $SkipExchange) {
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        throw 'Module ExchangeOnlineManagement not found. Run: Install-Module ExchangeOnlineManagement -Scope CurrentUser (or use -SkipExchange).'
    }
    Import-Module ExchangeOnlineManagement
    if ($CertificateThumbprint) {
        if (-not $ExchangeOrganization) { throw '-ExchangeOrganization (e.g. contoso.onmicrosoft.com) is required with -CertificateThumbprint.' }
        Connect-ExchangeOnline -CertificateThumbprint $CertificateThumbprint -AppId $ClientId -Organization $ExchangeOrganization -ShowBanner:$false
    }
    else {
        Connect-ExchangeOnline -ShowBanner:$false
    }
}

if ($ReportPath -and -not (Test-Path -Path $ReportPath)) {
    $null = New-Item -ItemType Directory -Path $ReportPath -Force
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
# Runs a block; on failure warns and returns $null so one missing permission does not stop the report
function Invoke-Safe {
    param([Parameter(Mandatory)][string]$What, [Parameter(Mandatory)][scriptblock]$Script)
    try { return (& $Script) }
    catch {
        Write-Warning "Skipped '$What': $($_.Exception.Message)"
        return $null
    }
}

$skuMap = @{}
try { Get-MgSubscribedSku -All | ForEach-Object { $skuMap[[string]$_.SkuId] = $_.SkuPartNumber } } catch { Write-Warning 'Could not read licence names.' }
function Get-SkuName { param([string]$Id) if ($skuMap.ContainsKey($Id)) { return $skuMap[$Id] } else { return $Id } }

# ---------------------------------------------------------------------------
# One user
# ---------------------------------------------------------------------------
function Get-UserDiscovery {
    param([Parameter(Mandatory)][string]$Upn)

    $flags = New-Object System.Collections.Generic.List[string]
    $info  = New-Object System.Collections.Generic.List[string]

    $props = 'id,displayName,userPrincipalName,mail,accountEnabled,onPremisesSyncEnabled,onPremisesSamAccountName,department,jobTitle,createdDateTime'
    $user = Get-MgUser -UserId $Upn -Property $props
    $id = $user.Id
    $synced = [bool]$user.OnPremisesSyncEnabled

    # Sign-in activity needs extra permission and licensing, so it is fetched on its own
    $lastSignIn = $null
    $sia = Invoke-Safe 'last sign-in' { (Get-MgUser -UserId $id -Property 'signInActivity').SignInActivity }
    if ($sia) { $lastSignIn = $sia.LastSignInDateTime }

    # Manager and direct reports
    $manager = Invoke-Safe 'manager' {
        try { $m = Get-MgUserManager -UserId $id -ErrorAction Stop; (Get-MgUser -UserId $m.Id -Property 'displayName,userPrincipalName') } catch { $null }
    }
    $reports = @(Invoke-Safe 'direct reports' { Get-MgUserDirectReport -UserId $id -All })

    # Admin roles
    $roles = @(Invoke-Safe 'directory roles' {
            Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$id'" -ExpandProperty 'roleDefinition' -All -ErrorAction Stop
        })
    $roleNames = @($roles | ForEach-Object { $_.RoleDefinition.DisplayName } | Where-Object { $_ })

    # Licences: direct vs inherited from a group
    $licUser = Invoke-Safe 'licences' { Get-MgUser -UserId $id -Property 'licenseAssignmentStates' }
    $states = @($licUser.LicenseAssignmentStates)
    $directLic = @($states | Where-Object { -not $_.AssignedByGroup } | ForEach-Object { Get-SkuName ([string]$_.SkuId) } | Select-Object -Unique)
    $groupLic  = @($states | Where-Object { $_.AssignedByGroup } | ForEach-Object { Get-SkuName ([string]$_.SkuId) } | Select-Object -Unique)

    # Group memberships
    $groups = @(Invoke-Safe 'group memberships' { Get-MgUserMemberOfAsGroup -UserId $id -All })
    $memberSummary = [pscustomobject]@{
        Total     = $groups.Count
        Microsoft365 = @($groups | Where-Object { $_.GroupTypes -contains 'Unified' }).Count
        Dynamic   = @($groups | Where-Object { $_.GroupTypes -contains 'DynamicMembership' }).Count
        Synced    = @($groups | Where-Object { $_.OnPremisesSyncEnabled }).Count
        LicenceGroups = @($groups | Where-Object { @($_.AssignedLicenses).Count -gt 0 }).Count
    }

    # Groups, Teams, apps owned
    $owned = @(Invoke-Safe 'owned objects' { Get-MgUserOwnedObject -UserId $id -All })
    $ownedGroups = @()
    foreach ($o in @($owned | Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.group' })) {
        $g = Invoke-Safe "owned group $($o.Id)" { Get-MgGroup -GroupId $o.Id -Property 'id,displayName,resourceProvisioningOptions,onPremisesSyncEnabled' }
        if (-not $g) { continue }
        $ownerCount = @(Invoke-Safe "owners of $($g.DisplayName)" { Get-MgGroupOwner -GroupId $g.Id -All }).Count
        $ownedGroups += [pscustomobject]@{
            Name      = $g.DisplayName
            IsTeam    = [bool]($g.ResourceProvisioningOptions -contains 'Team')
            Synced    = [bool]$g.OnPremisesSyncEnabled
            Owners    = $ownerCount
            SoleOwner = ($ownerCount -le 1)
        }
    }
    $ownedApps = @($owned | Where-Object { $_.AdditionalProperties['@odata.type'] -in '#microsoft.graph.application', '#microsoft.graph.servicePrincipal' } |
            ForEach-Object { "$($_.AdditionalProperties['displayName'])" })

    # Devices
    $managed = @(Invoke-Safe 'Intune devices' {
            Get-MgDeviceManagementManagedDevice -Filter "userPrincipalName eq '$($Upn -replace "'", "''")'" -All
        } | ForEach-Object { "$($_.DeviceName) ($($_.OperatingSystem), serial $($_.SerialNumber))" })
    $registered = @(Invoke-Safe 'registered devices' { Get-MgUserRegisteredDevice -UserId $id -All } |
            ForEach-Object { "$($_.AdditionalProperties['displayName'])" })

    # OneDrive
    $oneDrive = $null
    $drive = Invoke-Safe 'OneDrive' { Get-MgUserDrive -UserId $id -ErrorAction Stop }
    if ($drive) {
        $usedGb = if ($drive.Quota -and $drive.Quota.Used) { [math]::Round($drive.Quota.Used / 1GB, 2) } else { 0 }
        $oneDrive = [pscustomobject]@{ Url = ($drive.WebUrl -replace '/Documents/?$', ''); UsedGB = $usedGb }
    }

    # Mailbox
    $mailbox = $null
    if (-not $SkipExchange) {
        $mbx = Invoke-Safe 'mailbox' { Get-Mailbox -Identity $Upn -ErrorAction Stop }
        if ($mbx) {
            $sizeGb = $null
            $stats = Invoke-Safe 'mailbox size' { Get-MailboxStatistics -Identity $Upn -ErrorAction Stop }
            if ($stats -and "$($stats.TotalItemSize)" -match '\(([\d,]+) bytes\)') {
                $sizeGb = [math]::Round(([int64]($Matches[1] -replace ',', '')) / 1GB, 2)
            }
            $fullAccess = @(Invoke-Safe 'Full Access delegates' {
                    Get-MailboxPermission -Identity $Upn | Where-Object { $_.User -ne 'NT AUTHORITY\SELF' -and -not $_.IsInherited -and -not $_.Deny -and $_.AccessRights -contains 'FullAccess' } |
                        ForEach-Object { "$($_.User)" }
                })
            $sendAs = @(Invoke-Safe 'Send As' {
                    Get-RecipientPermission -Identity $Upn | Where-Object { $_.Trustee -ne 'NT AUTHORITY\SELF' } | ForEach-Object { "$($_.Trustee)" }
                })
            $mailbox = [pscustomobject]@{
                Type        = [string]$mbx.RecipientTypeDetails
                SizeGB      = $sizeGb
                Archive     = ("$($mbx.ArchiveStatus)" -eq 'Active')
                LitigationHold = [bool]$mbx.LitigationHoldEnabled
                RetentionHold  = [bool]$mbx.ComplianceTagHoldApplied
                ForwardingTo   = (@($mbx.ForwardingAddress, $mbx.ForwardingSmtpAddress) | Where-Object { $_ }) -join ', '
                FullAccessDelegates = $fullAccess
                SendAsDelegates     = $sendAs
                SharedMailboxAccess = @()
            }
            if ($IncludeMailboxAccess) {
                Write-Host 'Scanning shared mailboxes (this can take a while)...' -ForegroundColor DarkGray
                $shared = @(Invoke-Safe 'shared mailbox scan' {
                        Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited | ForEach-Object {
                            $p = Get-MailboxPermission -Identity $_.Identity -User $Upn -ErrorAction SilentlyContinue
                            if ($p -and ($p | Where-Object { $_.AccessRights -contains 'FullAccess' -and -not $_.Deny })) { $_.PrimarySmtpAddress.ToString() }
                        }
                    })
                $mailbox.SharedMailboxAccess = $shared
            }
        }
    }

    # ---- Risk flags ----
    if ($synced)                       { $flags.Add('Synced from on-prem AD: must be disabled on-prem (offboarding needs -IncludeOnPrem)') }
    if ($roleNames.Count -gt 0)        { $flags.Add("Holds admin role(s): $($roleNames -join ', ')") }
    $sole = @($ownedGroups | Where-Object { $_.SoleOwner })
    if ($sole.Count -gt 0)             { $flags.Add("Sole owner of $($sole.Count) group/Team(s): $((($sole | ForEach-Object { $_.Name }) -join ', '))") }
    if ($reports.Count -gt 0)          { $flags.Add("$($reports.Count) direct report(s) will lose their manager") }
    if ($ownedApps.Count -gt 0)        { $flags.Add("Owns $($ownedApps.Count) app registration(s)/service principal(s): $($ownedApps -join ', ')") }
    if ($managed.Count -gt 0)          { $flags.Add("$($managed.Count) Intune device(s) to collect or wipe") }
    if ($mailbox) {
        if ($mailbox.SizeGB -gt 49)    { $flags.Add("Mailbox is $($mailbox.SizeGB) GB: needs to stay licensed (shared mailboxes over 50 GB need a licence)") }
        if ($mailbox.Archive)          { $flags.Add('Has an archive mailbox: licence needed after conversion') }
        if ($mailbox.LitigationHold -or $mailbox.RetentionHold) { $flags.Add('Mailbox is on hold: licence needed after conversion') }
        if ($mailbox.ForwardingTo)     { $flags.Add("Mailbox forwards to: $($mailbox.ForwardingTo)") }
        if ($mailbox.FullAccessDelegates.Count -gt 0) { $info.Add("Others with Full Access to this mailbox: $($mailbox.FullAccessDelegates -join ', ')") }
        if ($mailbox.SendAsDelegates.Count -gt 0)     { $info.Add("Others with Send As on this mailbox: $($mailbox.SendAsDelegates -join ', ')") }
        if ($mailbox.SharedMailboxAccess.Count -gt 0) { $info.Add("Has Full Access to shared mailbox(es): $($mailbox.SharedMailboxAccess -join ', ')") }
    }
    if ($memberSummary.LicenceGroups -gt 0) { $info.Add("Member of $($memberSummary.LicenceGroups) licence-assigning group(s): licences end when removed from them") }
    if ($lastSignIn -and ((Get-Date) - [datetime]$lastSignIn).TotalDays -lt 7) { $info.Add("Signed in within the last 7 days (last: $lastSignIn)") }

    return [pscustomobject]@{
        UserPrincipalName = $user.UserPrincipalName
        DisplayName       = $user.DisplayName
        Enabled           = $user.AccountEnabled
        SyncedFromOnPrem  = $synced
        Department        = $user.Department
        JobTitle          = $user.JobTitle
        Manager           = if ($manager) { $manager.UserPrincipalName } else { $null }
        LastSignIn        = $lastSignIn
        DirectReports     = @($reports | ForEach-Object { "$($_.AdditionalProperties['displayName'])" })
        AdminRoles        = $roleNames
        DirectLicences    = $directLic
        GroupLicences     = $groupLic
        Memberships       = $memberSummary
        OwnedGroups       = $ownedGroups
        OwnedApps         = $ownedApps
        IntuneDevices     = $managed
        RegisteredDevices = $registered
        OneDrive          = $oneDrive
        Mailbox           = $mailbox
        RiskFlags         = @($flags)
        Notes             = @($info)
    }
}

function ConvertTo-MarkdownReport {
    param([Parameter(Mandatory)]$D)
    $l = New-Object System.Collections.Generic.List[string]
    function Add-List { param([string]$Title, $Items) $l.Add(''); $l.Add("### $Title"); if (@($Items).Count -eq 0) { $l.Add('- None') } else { foreach ($i in @($Items)) { $l.Add("- $i") } } }

    $l.Add("# Leaver discovery: $($D.DisplayName)")
    $l.Add('')
    $l.Add("Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm'). Read-only report, nothing was changed.")
    $l.Add('')
    $l.Add("- UPN: $($D.UserPrincipalName)")
    $l.Add("- Account enabled: $($D.Enabled)")
    $l.Add("- Synced from on-prem: $($D.SyncedFromOnPrem)")
    $l.Add("- Department / title: $($D.Department) / $($D.JobTitle)")
    $l.Add("- Manager: $($D.Manager)")
    $l.Add("- Last sign-in: $($D.LastSignIn)")

    Add-List 'Risk flags' $D.RiskFlags
    Add-List 'Other notes' $D.Notes
    Add-List 'Admin roles' $D.AdminRoles
    Add-List 'Direct reports' $D.DirectReports
    Add-List 'Licences assigned directly' $D.DirectLicences
    Add-List 'Licences inherited from groups' $D.GroupLicences
    $m = $D.Memberships
    Add-List 'Group memberships' @("Total $($m.Total): $($m.Microsoft365) Microsoft 365, $($m.Dynamic) dynamic, $($m.Synced) synced, $($m.LicenceGroups) licence-assigning")
    Add-List 'Groups and Teams owned' @($D.OwnedGroups | ForEach-Object { "$($_.Name)$(if ($_.IsTeam) { ' (Team)' })$(if ($_.SoleOwner) { ' - SOLE OWNER' })$(if ($_.Synced) { ' - synced' })" })
    Add-List 'App registrations / service principals owned' $D.OwnedApps
    Add-List 'Intune devices' $D.IntuneDevices
    Add-List 'Registered devices' $D.RegisteredDevices
    if ($D.OneDrive) { Add-List 'OneDrive' @("$($D.OneDrive.Url) ($($D.OneDrive.UsedGB) GB used)") }
    if ($D.Mailbox) {
        $mb = $D.Mailbox
        Add-List 'Mailbox' @("Type: $($mb.Type)", "Size: $($mb.SizeGB) GB", "Archive: $($mb.Archive)", "Litigation hold: $($mb.LitigationHold)", "Retention hold: $($mb.RetentionHold)", "Forwarding: $($mb.ForwardingTo)")
    }
    return ($l -join [Environment]::NewLine)
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
$all = foreach ($upn in $UserPrincipalName) {
    Write-Host "Discovering $upn ..." -ForegroundColor Cyan
    try {
        $d = Get-UserDiscovery -Upn $upn
    }
    catch {
        Write-Warning "Failed for ${upn}: $($_.Exception.Message)"
        continue
    }

    Write-Host ''
    Write-Host "$($d.DisplayName) ($($d.UserPrincipalName))" -ForegroundColor Green
    Write-Host ("  Enabled: {0}   Synced: {1}   Manager: {2}   Last sign-in: {3}" -f $d.Enabled, $d.SyncedFromOnPrem, $d.Manager, $d.LastSignIn)
    Write-Host ("  Licences: {0} direct, {1} via groups   Groups: {2}   Owns: {3} group(s), {4} app(s)   Devices: {5}" -f `
            @($d.DirectLicences).Count, @($d.GroupLicences).Count, $d.Memberships.Total, @($d.OwnedGroups).Count, @($d.OwnedApps).Count, @($d.IntuneDevices).Count)
    if ($d.RiskFlags.Count -gt 0) {
        Write-Host '  Risk flags:' -ForegroundColor Yellow
        $d.RiskFlags | ForEach-Object { Write-Host "    - $_" -ForegroundColor Yellow }
    }
    else {
        Write-Host '  No risk flags.' -ForegroundColor Green
    }
    $d.Notes | ForEach-Object { Write-Host "  Note: $_" -ForegroundColor DarkGray }

    if ($ReportPath) {
        $safe = $d.UserPrincipalName -replace '[^a-zA-Z0-9._@-]', '_'
        $file = Join-Path $ReportPath ('Leaver-Discovery-{0}-{1}.md' -f $safe, (Get-Date -Format 'yyyyMMdd-HHmm'))
        ConvertTo-MarkdownReport -D $d | Set-Content -Path $file -Encoding UTF8
        Write-Host "  Report saved: $file" -ForegroundColor DarkGray
    }
    $d
}

if (-not $SkipExchange) { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue }
if (-not $CertificateThumbprint) { Disconnect-MgGraph | Out-Null }

# Return the objects so they can be piped, e.g. | ConvertTo-Json -Depth 5
$all
