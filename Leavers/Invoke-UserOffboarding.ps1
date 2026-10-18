#Requires -Version 5.1
<#
.SYNOPSIS
    Offboards leavers in Microsoft 365 / Entra ID (cloud-only or hybrid) or on-premises Active Directory.

.DESCRIPTION
    Cloud (-Target Entra, the default). For each leaver, in this order:
      1. Safety checks: protected accounts and privileged role holders are refused.
         A state file (JSON, no secrets) records what was changed so it can be reviewed or reversed.
      2. Block sign-in: disable the account, reset the password, revoke sign-in sessions.
         Users synced from on-prem AD are disabled on-prem instead (use -IncludeOnPrem).
      3. Mailbox: convert to shared, set an auto-reply, give the manager Full Access.
         The mailbox stays licensed if it is over 49 GB, on hold, or has an archive.
      4. OneDrive: give the manager access (needs -SharePointAdminUrl).
      5. Hand over groups/Teams the leaver solely owns; reassign direct reports to the manager.
      6. Intune devices: reported, and optionally retired or wiped (-DeviceAction).
      7. Remove group memberships and directly assigned licences (licences are kept when the
         mailbox could not be safely converted).
      8. With -IncludeOnPrem (synced users): disable the AD account, reset its password,
         remove group memberships, stamp the description and move it to -DisabledOU.

    On-prem only (-Target OnPrem): step 8 only.

    ALWAYS RUN WITH -WhatIf FIRST. It prints the full plan for each user and changes nothing.
    A real run asks for one confirmation per user; pass -Confirm:$false for unattended runs.

    Input can come from parameters (one user), a CSV (-CsvPath) or a SharePoint list.
    CSV columns: UserPrincipalName, Manager (optional), TicketRef (optional).
    SharePoint list columns (plain text unless noted): UserPrincipalName, Manager (text, optional),
    TicketRef, LeaveDate (date and time), Status (Choice: Pending / Completed / Needs attention /
    Failed, default Pending), ProcessedOn (date and time), Notes. Only items with Status equal to
    -StatusFilter AND a LeaveDate that has passed are processed. Run it on a machine in the same time
    zone as the SharePoint site so the leave date is read correctly. Map differently named columns
    with -ColumnMap (e.g. -ColumnMap @{ LeaveDate = 'Leave_x0020_Date' }).

.NOTES
    Not yet tested against a live environment. Test on a dummy user first.

    Manager: the Entra manager is used for access handover unless the input row supplies one.

    Graph delegated scopes requested (verify against current Graph docs and trim as needed):
      User.ReadWrite.All, Group.ReadWrite.All, GroupMember.ReadWrite.All, Directory.Read.All,
      RoleManagement.Read.Directory, User.RevokeSessions.All, Files.Read.All, Organization.Read.All,
      DeviceManagementManagedDevices.Read.All (+ .PrivilegedOperations.All with -DeviceAction),
      Sites.ReadWrite.All (SharePoint list input).
    For unattended runs use an app registration with certificate auth and the equivalent APPLICATION
    permissions (-TenantId, -ClientId, -CertificateThumbprint, -ExchangeOrganization).

    Not covered here: removing MFA methods (the account is disabled and later deleted), forwarding
    rules, calendar meetings the leaver organised, and third-party apps.

.EXAMPLE
    # See exactly what would happen, nothing changes
    .\Invoke-UserOffboarding.ps1 -UserPrincipalName jane.smith@contoso.com -TicketRef INC0012345 -WhatIf

.EXAMPLE
    # Hybrid user: also do the on-prem steps, give the manager OneDrive access
    .\Invoke-UserOffboarding.ps1 -UserPrincipalName jane.smith@contoso.com -IncludeOnPrem `
        -DisabledOU 'OU=Disabled,DC=contoso,DC=local' `
        -SharePointAdminUrl 'https://contoso-admin.sharepoint.com'

.EXAMPLE
    # Daily run: process leavers whose leave date has arrived
    .\Invoke-UserOffboarding.ps1 -SharePointSiteUrl 'https://contoso.sharepoint.com/sites/IT' `
        -SharePointListName 'Leavers' -IncludeOnPrem -DisabledOU 'OU=Disabled,DC=contoso,DC=local' -Confirm:$false
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Single')]
param(
    [ValidateSet('Entra', 'OnPrem')]
    [string]$Target = 'Entra',

    # ---- Single user ----
    [Parameter(Mandatory, ParameterSetName = 'Single')]
    [string]$UserPrincipalName,

    # Overrides the Entra manager for access handover (UPN)
    [Parameter(ParameterSetName = 'Single')]
    [string]$Manager,

    [Parameter(ParameterSetName = 'Single')]
    [string]$TicketRef,

    # ---- Bulk ----
    [Parameter(Mandatory, ParameterSetName = 'Bulk')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$CsvPath,

    # ---- SharePoint list ----
    [Parameter(Mandatory, ParameterSetName = 'SharePoint')]
    [string]$SharePointSiteUrl,

    [Parameter(Mandatory, ParameterSetName = 'SharePoint')]
    [string]$SharePointListName,

    [Parameter(ParameterSetName = 'SharePoint')]
    [string]$StatusFilter = 'Pending',

    [Parameter(ParameterSetName = 'SharePoint')]
    [hashtable]$ColumnMap = @{},

    # ---- Options ----
    # Auto-reply text. {Name} and {Manager} are replaced.
    [string]$AutoReplyMessage,

    # What to do with the leaver's Intune devices. Default only reports them.
    [ValidateSet('None', 'Retire', 'Wipe')]
    [string]$DeviceAction = 'None',

    # Do not remove licences (e.g. mailbox kept as a licensed user mailbox)
    [switch]$KeepLicences,

    [switch]$SkipMailboxConversion,

    # Hybrid: also disable and tidy the on-prem AD account (needs the ActiveDirectory module)
    [switch]$IncludeOnPrem,

    # Move the disabled AD account here (DN of the OU)
    [string]$DisabledOU,

    # e.g. https://contoso-admin.sharepoint.com : needed to give the manager OneDrive access
    [string]$SharePointAdminUrl,

    # UPNs or sAMAccountNames that must never be offboarded by this script (e.g. break-glass accounts)
    [string[]]$ProtectedAccounts = @(),

    # Allow offboarding someone who holds an admin role / privileged AD group
    [switch]$AllowPrivilegedUser,

    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint,
    [string]$ExchangeOrganization,

    [string]$StatePath,
    [string]$LogPath
)

$ErrorActionPreference = 'Stop'

$base = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
if (-not $LogPath)   { $LogPath = Join-Path $base 'Invoke-UserOffboarding.log' }
if (-not $StatePath) { $StatePath = Join-Path $base 'OffboardingState' }

$script:DryRun         = $false
$script:Steps          = $null
$script:State          = $null
$script:StateFile      = $null
$script:NeedsAttention = $false

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    # -WhatIf:$false so logging still works during a -WhatIf run
    Add-Content -Path $LogPath -Value $line -WhatIf:$false
    switch ($Level) {
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'ERROR' { Write-Host $line -ForegroundColor Red }
        default { Write-Host $line }
    }
}

function Get-Field {
    param($Row, [string]$Name)
    $prop = $Row.PSObject.Properties[$Name]
    if ($prop -and $null -ne $prop.Value -and "$($prop.Value)".Trim() -ne '') { return "$($prop.Value)".Trim() }
    return $null
}

function ConvertTo-FilterLiteral {
    param([string]$Text)
    return ($Text -replace "'", "''")
}

function Get-RandomInt {
    param([Parameter(Mandatory)][int]$Max)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $bytes = New-Object byte[] 4
        $limit = [uint64]4294967296
        $threshold = $limit - ($limit % [uint64]$Max)
        do {
            $rng.GetBytes($bytes)
            $value = [uint64][BitConverter]::ToUInt32($bytes, 0)
        } while ($value -ge $threshold)
        return [int]($value % [uint64]$Max)
    }
    finally {
        $rng.Dispose()
    }
}

function New-RandomPassword {
    param([int]$Length = 24)
    $sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!#$%&*?@')
    $all = $sets -join ''
    $chars = New-Object System.Collections.Generic.List[char]
    foreach ($set in $sets) { $chars.Add($set[(Get-RandomInt -Max $set.Length)]) }
    while ($chars.Count -lt $Length) { $chars.Add($all[(Get-RandomInt -Max $all.Length)]) }
    for ($i = $chars.Count - 1; $i -gt 0; $i--) {
        $j = Get-RandomInt -Max ($i + 1)
        $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
    }
    return (-join $chars)
}

function Add-StepResult {
    param([string]$Name, [string]$Status, [string]$Detail = '')
    $script:Steps.Add([pscustomobject]@{ Step = $Name; Status = $Status; Detail = $Detail })
}

# Runs one action, or only records it in a -WhatIf run. A failed step is recorded and the run carries on.
function Invoke-Step {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action,
        [string]$Detail = ''
    )
    if ($script:DryRun) {
        Add-StepResult $Name 'WouldDo' $Detail
        Write-Log (("[WhatIf] $Name $Detail").Trim())
        return
    }
    try {
        $null = & $Action
        Add-StepResult $Name 'Done' $Detail
        Write-Log (("$Name $Detail").Trim())
    }
    catch {
        Add-StepResult $Name 'Failed' $_.Exception.Message
        Write-Log "$Name failed: $($_.Exception.Message)" 'WARN'
    }
}

function Save-State {
    if ($script:DryRun -or -not $script:State) { return }
    if (-not (Test-Path -Path $script:StatePath)) {
        $null = New-Item -ItemType Directory -Path $script:StatePath -Force -WhatIf:$false
    }
    $script:State | ConvertTo-Json -Depth 6 | Set-Content -Path $script:StateFile -Encoding UTF8 -WhatIf:$false
}

# The leading comma stops PowerShell unrolling the empty list into $null
function New-StateList { return , (New-Object System.Collections.Generic.List[object]) }

function Initialize-State {
    param([string]$Upn, [string]$Id, [string]$DisplayName, [string]$Ticket, $EnabledBefore, $Synced)
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $safe = $Upn -replace '[^a-zA-Z0-9._@-]', '_'
    $script:StateFile = Join-Path $script:StatePath ('Offboarding-{0}-{1}.json' -f $safe, $stamp)
    $script:State = [ordered]@{
        UserPrincipalName    = $Upn
        UserId               = $Id
        DisplayName          = $DisplayName
        OffboardedAt         = (Get-Date).ToUniversalTime().ToString('o')
        TicketRef            = $Ticket
        AccountEnabledBefore = $EnabledBefore
        SyncedFromOnPrem     = $Synced
        Manager              = $null
        MailboxTypeBefore    = $null
        MailboxConverted     = $false
        OneDriveUrl          = $null
        GroupsRemoved        = (New-StateList)
        GroupOwnershipChanged = (New-StateList)
        DirectReportsReassigned = (New-StateList)
        LicencesRemoved      = (New-StateList)
        Devices              = (New-StateList)
        OnPrem               = $null
    }
}

# ---------------------------------------------------------------------------
# SharePoint list (leaver queue and status write-back)
# ---------------------------------------------------------------------------
function Get-SpColumn {
    param([Parameter(Mandatory)][string]$Name)
    if ($script:ColumnMap -and $script:ColumnMap.ContainsKey($Name)) { return $script:ColumnMap[$Name] }
    return $Name
}

function Get-SpValue {
    param($Fields, [Parameter(Mandatory)][string]$Name)
    $col = Get-SpColumn $Name
    if ($Fields.ContainsKey($col) -and $null -ne $Fields[$col] -and "$($Fields[$col])".Trim() -ne '') {
        return "$($Fields[$col])".Trim()
    }
    return $null
}

function ConvertTo-LocalDateTime {
    param($Raw)
    if ($Raw -is [datetimeoffset]) { return $Raw.LocalDateTime }
    if ($Raw -is [datetime]) { if ($Raw.Kind -eq 'Utc') { return $Raw.ToLocalTime() } else { return $Raw } }
    return [datetime]::Parse([string]$Raw, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None)
}

function Get-SpSiteAndList {
    $uri = [uri]$script:SharePointSiteUrl
    $siteKey = '{0}:{1}' -f $uri.Host, $uri.AbsolutePath.TrimEnd('/')
    $site = Get-MgSite -SiteId $siteKey
    $list = @(Get-MgSiteList -SiteId $site.Id -All | Where-Object { $_.DisplayName -eq $script:SharePointListName })
    if ($list.Count -ne 1) {
        throw "SharePoint list '$($script:SharePointListName)' not found (or ambiguous) on $($script:SharePointSiteUrl)."
    }
    return [pscustomobject]@{ SiteId = $site.Id; ListId = $list[0].Id }
}

function Get-SpDueLeavers {
    $script:SpIds = Get-SpSiteAndList
    # Filtering is done client-side: non-indexed columns cannot be filtered server-side
    $items = Get-MgSiteListItem -SiteId $script:SpIds.SiteId -ListId $script:SpIds.ListId -ExpandProperty 'fields' -All
    foreach ($item in $items) {
        $f = $item.Fields.AdditionalProperties
        $status = Get-SpValue $f 'Status'
        if ($script:StatusFilter -and $status -ne $script:StatusFilter) { continue }

        $col = Get-SpColumn 'LeaveDate'
        $raw = if ($f.ContainsKey($col)) { $f[$col] } else { $null }
        if (-not $raw) {
            Write-Log "SharePoint item $($item.Id) has no LeaveDate; skipping." 'WARN'
            continue
        }
        if ((ConvertTo-LocalDateTime $raw) -gt (Get-Date)) { continue }   # not due yet

        [pscustomobject]@{
            ListItemId        = $item.Id
            UserPrincipalName = Get-SpValue $f 'UserPrincipalName'
            Manager           = Get-SpValue $f 'Manager'
            TicketRef         = Get-SpValue $f 'TicketRef'
        }
    }
}

function Update-SpListItemResult {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][string]$ListItemId,
        [Parameter(Mandatory)]$Result
    )
    # Only record real outcomes
    if ($Result.Status -notin 'Completed', 'Needs attention', 'Failed') { return }

    $notes = "$($Result.Notes)"
    if ($notes.Length -gt 250) { $notes = $notes.Substring(0, 250) }

    $body = @{}
    $body[(Get-SpColumn 'Status')]      = $Result.Status
    $body[(Get-SpColumn 'ProcessedOn')] = (Get-Date).ToUniversalTime().ToString('o')
    $body[(Get-SpColumn 'Notes')]       = $notes

    if ($PSCmdlet.ShouldProcess("list item $ListItemId", 'Write result back to SharePoint')) {
        try {
            $null = Update-MgSiteListItemField -SiteId $script:SpIds.SiteId -ListId $script:SpIds.ListId `
                -ListItemId $ListItemId -BodyParameter $body
            Write-Log "Updated SharePoint item $ListItemId with status '$($Result.Status)'."
        }
        catch {
            Write-Log "Could not update SharePoint item ${ListItemId}: $($_.Exception.Message)" 'WARN'
        }
    }
}

# ---------------------------------------------------------------------------
# On-premises AD steps
# ---------------------------------------------------------------------------
function Test-ProtectedAccount {
    param([string[]]$Names)
    foreach ($n in $Names) {
        if ($n -and ($script:ProtectedAccounts | Where-Object { $_ -eq $n })) {
            throw "'$n' is in -ProtectedAccounts and will not be offboarded."
        }
    }
}

function Test-OnPremPrivileged {
    param([Parameter(Mandatory)]$AdUser)
    if ($script:AllowPrivilegedUser) { return }
    $priv = @($AdUser.MemberOf | Where-Object { $_ -match '^CN=(Domain Admins|Enterprise Admins|Schema Admins|Administrators),' })
    if ($priv.Count -gt 0) {
        throw "Account is a member of a privileged AD group ($($priv[0])). Use -AllowPrivilegedUser if this is intended."
    }
}

function Invoke-OnPremSteps {
    param([Parameter(Mandatory)][string]$Sam, [string]$Ticket)

    $ad = Get-ADUser -Identity $Sam -Properties MemberOf, Description, Enabled, DistinguishedName
    $script:State.OnPrem = [ordered]@{
        SamAccountName    = $Sam
        DistinguishedName = $ad.DistinguishedName
        EnabledBefore     = $ad.Enabled
        DescriptionBefore = $ad.Description
        GroupsRemoved     = (New-StateList)
        MovedTo           = $null
    }

    Invoke-Step 'On-prem: disable account' { Disable-ADAccount -Identity $Sam }
    Invoke-Step 'On-prem: reset password' {
        Set-ADAccountPassword -Identity $Sam -Reset `
            -NewPassword (ConvertTo-SecureString -String (New-RandomPassword -Length 24) -AsPlainText -Force)
    }

    foreach ($dn in @($ad.MemberOf)) {
        $groupName = ($dn -split ',')[0] -replace '^CN=', ''
        $groupDn = $dn
        Invoke-Step "On-prem: remove from group '$groupName'" {
            Remove-ADGroupMember -Identity $groupDn -Members $Sam -Confirm:$false
            $script:State.OnPrem.GroupsRemoved.Add([pscustomobject]@{ Name = $groupName; DistinguishedName = $groupDn })
        }
    }

    $desc = 'Disabled {0:yyyy-MM-dd}' -f (Get-Date)
    if ($Ticket) { $desc = "$desc $Ticket" }
    Invoke-Step 'On-prem: stamp description' { Set-ADUser -Identity $Sam -Description $desc } -Detail $desc

    # Only if the Exchange schema extension exists in this forest
    try {
        $schema = (Get-ADRootDSE).schemaNamingContext
        $hasExch = [bool](Get-ADObject -SearchBase $schema -Filter "lDAPDisplayName -eq 'msExchHideFromAddressLists'" -ErrorAction Stop)
    }
    catch { $hasExch = $false }
    if ($hasExch) {
        Invoke-Step 'On-prem: hide from address lists' { Set-ADUser -Identity $Sam -Replace @{ msExchHideFromAddressLists = $true } }
    }

    if ($script:DisabledOU) {
        Invoke-Step 'On-prem: move to disabled OU' {
            Move-ADObject -Identity (Get-ADUser -Identity $Sam).DistinguishedName -TargetPath $script:DisabledOU
            $script:State.OnPrem.MovedTo = $script:DisabledOU
        } -Detail $script:DisabledOU
    }
    else {
        Add-StepResult 'On-prem: move to disabled OU' 'Skipped' 'No -DisabledOU supplied'
    }
    Save-State
}

function Invoke-OnPremOnlyOffboard {
    param([Parameter(Mandatory)]$Item, [Parameter(Mandatory)]$Result, [Parameter(Mandatory)]$Notes)

    $id = ConvertTo-FilterLiteral $Item.UserPrincipalName
    $ad = @(Get-ADUser -Filter "UserPrincipalName -eq '$id' -or SamAccountName -eq '$id'" -Properties MemberOf, Description, Enabled)
    if ($ad.Count -ne 1) { throw "User '$($Item.UserPrincipalName)' not found (or ambiguous) in AD." }

    Test-ProtectedAccount -Names @($Item.UserPrincipalName, $ad[0].SamAccountName, $ad[0].UserPrincipalName)
    Test-OnPremPrivileged -AdUser $ad[0]

    $Result.DisplayName = $ad[0].Name
    Initialize-State -Upn $Item.UserPrincipalName -Id "$($ad[0].ObjectGUID)" -DisplayName $ad[0].Name `
        -Ticket $Item.TicketRef -EnabledBefore $ad[0].Enabled -Synced $false
    Invoke-OnPremSteps -Sam $ad[0].SamAccountName -Ticket $Item.TicketRef
}

# ---------------------------------------------------------------------------
# Microsoft 365 / Entra ID
# ---------------------------------------------------------------------------
function Invoke-EntraOffboard {
    param([Parameter(Mandatory)]$Item, [Parameter(Mandatory)]$Result, [Parameter(Mandatory)]$Notes)

    $props = 'id,displayName,userPrincipalName,mail,accountEnabled,onPremisesSyncEnabled,onPremisesSamAccountName'
    $user = Get-MgUser -UserId $Item.UserPrincipalName -Property $props
    $upn = $user.UserPrincipalName
    $synced = [bool]$user.OnPremisesSyncEnabled
    $Result.UserPrincipalName = $upn
    $Result.DisplayName = $user.DisplayName

    # ---- Safety checks (before anything changes) ----
    Test-ProtectedAccount -Names @($Item.UserPrincipalName, $upn, $user.OnPremisesSamAccountName)

    $roles = @(Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($user.Id)'" -All -ErrorAction Stop)
    if ($roles.Count -gt 0 -and -not $script:AllowPrivilegedUser) {
        throw "Account holds $($roles.Count) directory role assignment(s). Use -AllowPrivilegedUser if this is intended."
    }
    if ($synced -and $script:IncludeOnPrem) {
        if (-not $user.OnPremisesSamAccountName) { throw 'Synced user has no on-premises sAMAccountName.' }
        Test-OnPremPrivileged -AdUser (Get-ADUser -Identity $user.OnPremisesSamAccountName -Properties MemberOf)
    }

    # ---- Manager (for access handover) ----
    $mgrProps = 'id,displayName,userPrincipalName,mail'
    $mgr = $null
    if ($Item.Manager) {
        $mgr = Get-MgUser -UserId $Item.Manager -Property $mgrProps
    }
    else {
        try {
            $m = Get-MgUserManager -UserId $user.Id -ErrorAction Stop
            $mgr = Get-MgUser -UserId $m.Id -Property $mgrProps
        }
        catch { $mgr = $null }
    }
    if ($mgr) { $Result.Manager = $mgr.UserPrincipalName }
    else { $Notes.Add('No manager found: access handover steps skipped') }

    Initialize-State -Upn $upn -Id $user.Id -DisplayName $user.DisplayName -Ticket $Item.TicketRef `
        -EnabledBefore $user.AccountEnabled -Synced $synced
    $script:State.Manager = $Result.Manager
    Write-Log "Offboarding $upn (Synced=$synced, Manager=$($Result.Manager), DryRun=$($script:DryRun))."

    $keepLicenceReason = $null
    if ($script:KeepLicences) { $keepLicenceReason = '-KeepLicences specified' }

    # ---- 1. Block sign-in ----
    if ($synced) {
        if ($script:IncludeOnPrem) {
            Add-StepResult 'Disable account / reset password (cloud)' 'Skipped' 'Synced user: handled in the on-prem steps'
        }
        else {
            Add-StepResult 'Disable account / reset password (cloud)' 'Skipped' 'Synced user: must be disabled on-prem'
            $Notes.Add('Synced user NOT disabled: re-run with -IncludeOnPrem or disable in AD')
            $script:NeedsAttention = $true
        }
    }
    else {
        Invoke-Step 'Disable account' { Update-MgUser -UserId $user.Id -AccountEnabled:$false }
        Invoke-Step 'Reset password' {
            Update-MgUser -UserId $user.Id -PasswordProfile @{ Password = (New-RandomPassword -Length 24); ForceChangePasswordNextSignIn = $false }
        }
    }
    Invoke-Step 'Revoke sign-in sessions' { Revoke-MgUserSignInSession -UserId $user.Id }
    Save-State

    # ---- 2. Mailbox ----
    $mailboxOk = $true
    if ($script:SkipMailboxConversion) {
        Add-StepResult 'Mailbox' 'Skipped' '-SkipMailboxConversion specified'
        if (-not $keepLicenceReason) { $keepLicenceReason = 'Mailbox conversion skipped' }
    }
    else {
        $mbx = $null
        try { $mbx = Get-Mailbox -Identity $upn -ErrorAction Stop } catch { $mbx = $null }

        if (-not $mbx) {
            Add-StepResult 'Mailbox' 'Skipped' 'No Exchange Online mailbox found'
        }
        else {
            $script:State.MailboxTypeBefore = [string]$mbx.RecipientTypeDetails

            if ($mbx.RecipientTypeDetails -eq 'SharedMailbox') {
                Add-StepResult 'Convert mailbox to shared' 'Skipped' 'Already a shared mailbox'
            }
            else {
                $bytes = [int64]0
                try {
                    $stats = Get-MailboxStatistics -Identity $upn -ErrorAction Stop
                    if ("$($stats.TotalItemSize)" -match '\(([\d,]+) bytes\)') { $bytes = [int64]($Matches[1] -replace ',', '') }
                }
                catch { Write-Log "Could not read mailbox size for ${upn}: $($_.Exception.Message)" 'WARN' }

                $reasons = @()
                if ($bytes -gt 49GB)                     { $reasons += 'mailbox over 49 GB' }
                if ($mbx.LitigationHoldEnabled)          { $reasons += 'litigation hold' }
                if ($mbx.ComplianceTagHoldApplied)       { $reasons += 'retention hold' }
                if ("$($mbx.ArchiveStatus)" -eq 'Active') { $reasons += 'archive mailbox' }

                if ($reasons.Count -gt 0) {
                    $keepLicenceReason = 'Mailbox must stay licensed: ' + ($reasons -join ', ')
                    Add-StepResult 'Convert mailbox to shared' 'Skipped' $keepLicenceReason
                    $Notes.Add($keepLicenceReason)
                }
                else {
                    Invoke-Step 'Convert mailbox to shared' { Set-Mailbox -Identity $upn -Type Shared }
                    if ($script:DryRun) { $mailboxOk = $true }
                    else {
                        $mailboxOk = $false
                        for ($i = 0; $i -lt 6 -and -not $mailboxOk; $i++) {
                            $check = Get-Mailbox -Identity $upn -ErrorAction SilentlyContinue
                            if ($check -and $check.RecipientTypeDetails -eq 'SharedMailbox') { $mailboxOk = $true } else { Start-Sleep -Seconds 5 }
                        }
                        $script:State.MailboxConverted = $mailboxOk
                        if (-not $mailboxOk) {
                            $keepLicenceReason = 'Mailbox conversion not confirmed'
                            $Notes.Add($keepLicenceReason)
                        }
                    }
                }
            }

            if ($mailboxOk) {
                $mgrLabel = if ($mgr) { "$($mgr.DisplayName) ($(if ($mgr.Mail) { $mgr.Mail } else { $mgr.UserPrincipalName }))" } else { 'the team' }
                $reply = if ($script:AutoReplyMessage) { $script:AutoReplyMessage } else { 'Thank you for your email. {Name} no longer works here. Please contact {Manager} for any queries.' }
                $reply = $reply.Replace('{Name}', $user.DisplayName).Replace('{Manager}', $mgrLabel)
                Invoke-Step 'Set auto-reply' {
                    Set-MailboxAutoReplyConfiguration -Identity $upn -AutoReplyState Enabled -InternalMessage $reply -ExternalMessage $reply
                }
                if ($mgr) {
                    Invoke-Step 'Give manager Full Access to mailbox' {
                        Add-MailboxPermission -Identity $upn -User $mgr.UserPrincipalName -AccessRights FullAccess -InheritanceType All -AutoMapping $true
                    } -Detail $mgr.UserPrincipalName
                }
                if (-not $synced) {
                    Invoke-Step 'Hide from address lists' { Set-Mailbox -Identity $upn -HiddenFromAddressListsEnabled $true }
                }
            }
        }
    }
    Save-State

    # ---- 3. OneDrive ----
    $odUrl = $null
    try {
        $drive = Get-MgUserDrive -UserId $user.Id -ErrorAction Stop
        if ($drive.WebUrl) { $odUrl = ($drive.WebUrl -replace '/Documents/?$', '') }
    }
    catch { Write-Log "No OneDrive found for ${upn}: $($_.Exception.Message)" 'WARN' }
    $script:State.OneDriveUrl = $odUrl
    $Result.OneDriveUrl = $odUrl
    if ($odUrl -and $mgr -and $script:SharePointAdminUrl) {
        Invoke-Step 'Give manager access to OneDrive' {
            Set-SPOUser -Site $odUrl -LoginName $mgr.UserPrincipalName -IsSiteCollectionAdmin $true
        } -Detail $odUrl
    }
    elseif ($odUrl) {
        Add-StepResult 'Give manager access to OneDrive' 'Skipped' "No manager or no -SharePointAdminUrl. OneDrive: $odUrl"
    }

    # ---- 4. Groups and Teams the leaver owns ----
    $owned = @(Get-MgUserOwnedObject -UserId $user.Id -All)
    $ownedGroups = @($owned | Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.group' })
    $ownedApps = @($owned | Where-Object { $_.AdditionalProperties['@odata.type'] -in '#microsoft.graph.application', '#microsoft.graph.servicePrincipal' })

    foreach ($og in $ownedGroups) {
        $g = Get-MgGroup -GroupId $og.Id -Property 'id,displayName,onPremisesSyncEnabled'
        $gid = $g.Id
        $gname = $g.DisplayName
        if ($g.OnPremisesSyncEnabled) {
            Add-StepResult "Group owner: $gname" 'Skipped' 'Synced from on-prem'
            continue
        }
        $owners = @(Get-MgGroupOwner -GroupId $gid -All)
        $sole = ($owners.Count -le 1)
        if ($sole -and -not $mgr) {
            Add-StepResult "Group owner: $gname" 'Skipped' 'Sole owner and no manager to take over'
            $Notes.Add("Group '$gname' will have no active owner")
            continue
        }
        if ($sole -and -not ($owners | Where-Object { $_.Id -eq $mgr.Id })) {
            Invoke-Step "Make manager owner of '$gname'" {
                New-MgGroupOwnerByRef -GroupId $gid -BodyParameter @{ '@odata.id' = "https://graph.microsoft.com/v1.0/users/$($mgr.Id)" }
            }
            if ($script:Steps[$script:Steps.Count - 1].Status -eq 'Failed') { continue }   # never leave a group ownerless
        }
        Invoke-Step "Remove leaver as owner of '$gname'" {
            Remove-MgGroupOwnerByRef -GroupId $gid -DirectoryObjectId $user.Id
            $script:State.GroupOwnershipChanged.Add([pscustomobject]@{ GroupId = $gid; Name = $gname; ManagerAddedAsOwner = $sole })
        }
    }
    if ($ownedApps.Count -gt 0) { $Notes.Add("Owns $($ownedApps.Count) app registration(s)/service principal(s): review ownership") }
    Save-State

    # ---- 5. Direct reports ----
    $reports = @(Get-MgUserDirectReport -UserId $user.Id -All)
    if ($reports.Count -gt 0) {
        if ($mgr -and -not $synced) {
            foreach ($r in $reports) {
                $rid = $r.Id
                $rname = "$($r.AdditionalProperties['displayName'])"
                Invoke-Step "Reassign direct report '$rname' to manager" {
                    Set-MgUserManagerByRef -UserId $rid -BodyParameter @{ '@odata.id' = "https://graph.microsoft.com/v1.0/users/$($mgr.Id)" }
                    $script:State.DirectReportsReassigned.Add([pscustomobject]@{ UserId = $rid; Name = $rname })
                }
            }
        }
        else {
            $Notes.Add("$($reports.Count) direct report(s) need a new manager (set it where the manager attribute is mastered)")
        }
    }

    # ---- 6. Intune devices ----
    $devices = @()
    try {
        $devices = @(Get-MgDeviceManagementManagedDevice -Filter "userPrincipalName eq '$(ConvertTo-FilterLiteral $upn)'" -All)
    }
    catch { Write-Log "Could not read Intune devices for ${upn}: $($_.Exception.Message)" 'WARN' }
    $Result.Devices = $devices.Count
    foreach ($d in $devices) {
        $script:State.Devices.Add([pscustomobject]@{ Id = $d.Id; Name = $d.DeviceName; OS = $d.OperatingSystem; Serial = $d.SerialNumber })
        $did = $d.Id
        $dname = $d.DeviceName
        if ($script:DeviceAction -eq 'Retire') {
            Invoke-Step "Retire device '$dname'" { Invoke-MgRetireDeviceManagementManagedDevice -ManagedDeviceId $did }
        }
        elseif ($script:DeviceAction -eq 'Wipe') {
            Invoke-Step "Wipe device '$dname'" {
                Invoke-MgWipeDeviceManagementManagedDevice -ManagedDeviceId $did -BodyParameter @{ keepEnrollmentData = $false; keepUserData = $false }
            }
        }
    }
    if ($devices.Count -gt 0 -and $script:DeviceAction -eq 'None') {
        Add-StepResult 'Intune devices' 'Skipped' "$($devices.Count) device(s) found; no -DeviceAction. Collect and reassign them."
        $Notes.Add("$($devices.Count) Intune device(s) to collect")
    }
    Save-State

    # ---- 7. Group memberships ----
    $groups = @(Get-MgUserMemberOfAsGroup -UserId $user.Id -All)
    foreach ($g in $groups) {
        $gid = $g.Id
        $gname = $g.DisplayName
        if ($g.GroupTypes -contains 'DynamicMembership') {
            Add-StepResult "Remove from '$gname'" 'Skipped' 'Dynamic group: follows user attributes'
            continue
        }
        if ($g.OnPremisesSyncEnabled) {
            Add-StepResult "Remove from '$gname'" 'Skipped' 'Synced from on-prem: removed in the on-prem step'
            continue
        }
        if ($keepLicenceReason -and @($g.AssignedLicenses).Count -gt 0) {
            Add-StepResult "Remove from '$gname'" 'Skipped' "Licence group kept: $keepLicenceReason"
            continue
        }
        Invoke-Step "Remove from group '$gname'" {
            Remove-MgGroupMemberByRef -GroupId $gid -DirectoryObjectId $user.Id
            $script:State.GroupsRemoved.Add([pscustomobject]@{ GroupId = $gid; Name = $gname })
        }
    }
    Save-State

    # ---- 8. Directly assigned licences ----
    if ($keepLicenceReason) {
        Add-StepResult 'Remove direct licences' 'Skipped' $keepLicenceReason
    }
    else {
        $lic = Get-MgUser -UserId $user.Id -Property 'licenseAssignmentStates'
        $direct = @($lic.LicenseAssignmentStates | Where-Object { -not $_.AssignedByGroup } | ForEach-Object { [string]$_.SkuId } | Select-Object -Unique)
        if ($direct.Count -eq 0) {
            Add-StepResult 'Remove direct licences' 'Skipped' 'None assigned directly (group licences end with group removal)'
        }
        else {
            $skuMap = @{}
            try { Get-MgSubscribedSku -All | ForEach-Object { $skuMap[[string]$_.SkuId] = $_.SkuPartNumber } } catch { }
            $names = ($direct | ForEach-Object { if ($skuMap.ContainsKey($_)) { $skuMap[$_] } else { $_ } }) -join ', '
            Invoke-Step 'Remove direct licences' {
                Set-MgUserLicense -UserId $user.Id -AddLicenses @() -RemoveLicenses ([string[]]$direct)
                foreach ($s in $direct) {
                    $script:State.LicencesRemoved.Add([pscustomobject]@{ SkuId = $s; Name = $(if ($skuMap.ContainsKey($s)) { $skuMap[$s] } else { $null }) })
                }
            } -Detail $names
        }
    }
    Save-State

    # ---- 9. On-prem (hybrid) ----
    if ($synced -and $script:IncludeOnPrem) {
        Invoke-OnPremSteps -Sam $user.OnPremisesSamAccountName -Ticket $Item.TicketRef
        $Notes.Add('On-prem changes reach Entra at the next sync cycle')
    }
}

# ---------------------------------------------------------------------------
# One leaver: confirmation, dry run handling, error handling, summary
# ---------------------------------------------------------------------------
function Invoke-Offboard {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)]$Item)

    $upn = $Item.UserPrincipalName
    $script:Steps = New-Object System.Collections.Generic.List[object]
    $script:State = $null
    $script:StateFile = $null
    $script:NeedsAttention = $false
    $notes = New-Object System.Collections.Generic.List[string]

    $result = [pscustomobject]@{
        Target            = $script:Target
        UserPrincipalName = $upn
        DisplayName       = $null
        Status            = 'Failed'
        Manager           = $null
        OneDriveUrl       = $null
        Devices           = 0
        Notes             = ''
        StateFile         = $null
    }

    try {
        if (-not $upn) { throw 'UserPrincipalName is required.' }

        if ($WhatIfPreference) {
            $script:DryRun = $true
            [void]$PSCmdlet.ShouldProcess($upn, 'Offboard user')
        }
        elseif ($PSCmdlet.ShouldProcess($upn, 'Offboard user: block sign-in, convert mailbox, remove access')) {
            $script:DryRun = $false
        }
        else {
            $result.Status = 'Skipped'
            return $result
        }
        $ConfirmPreference = 'None'   # one confirmation per user; inner cmdlets must not prompt again

        if ($script:Target -eq 'Entra') { $null = Invoke-EntraOffboard -Item $Item -Result $result -Notes $notes }
        else                            { $null = Invoke-OnPremOnlyOffboard -Item $Item -Result $result -Notes $notes }

        $failed = @($script:Steps | Where-Object { $_.Status -eq 'Failed' })
        if ($failed.Count -gt 0) { $notes.Add('Failed steps: ' + (($failed | ForEach-Object { $_.Step }) -join ', ')) }

        $result.Status = if ($script:DryRun) { 'WhatIf' }
                         elseif ($failed.Count -gt 0 -or $script:NeedsAttention) { 'Needs attention' }
                         else { 'Completed' }
    }
    catch {
        $result.Status = 'Failed'
        $notes.Add($_.Exception.Message)
        Write-Log "Offboarding failed for ${upn}: $($_.Exception.Message)" 'ERROR'
    }

    $result.Notes = ($notes -join '; ')
    if ($script:StateFile -and (Test-Path -Path $script:StateFile)) { $result.StateFile = $script:StateFile }

    if ($script:Steps.Count -gt 0) {
        Write-Host ''
        Write-Host "Steps for $upn" -ForegroundColor Cyan
        $script:Steps | Format-Table Step, Status, Detail -AutoSize -Wrap | Out-Host
    }
    return $result
}

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
if ($Target -eq 'OnPrem' -or $IncludeOnPrem) {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw 'ActiveDirectory module not found. Install RSAT: Active Directory Domain Services tools.'
    }
    Import-Module ActiveDirectory
    if ($DisabledOU -and -not (Get-ADObject -Identity $DisabledOU -ErrorAction SilentlyContinue)) {
        throw "OU '$DisabledOU' was not found."
    }
}

$useSharePoint = ($PSCmdlet.ParameterSetName -eq 'SharePoint')
$useExchange = ($Target -eq 'Entra' -and -not $SkipMailboxConversion)
$useGraph = ($Target -eq 'Entra' -or $useSharePoint)

if ($useGraph) {
    $required = @()
    if ($Target -eq 'Entra') {
        $required += 'Microsoft.Graph.Users', 'Microsoft.Graph.Users.Actions', 'Microsoft.Graph.Groups',
                     'Microsoft.Graph.Identity.DirectoryManagement', 'Microsoft.Graph.Identity.Governance',
                     'Microsoft.Graph.DeviceManagement', 'Microsoft.Graph.Files'
        if ($DeviceAction -ne 'None') { $required += 'Microsoft.Graph.DeviceManagement.Actions' }
    }
    if ($useSharePoint) { $required += 'Microsoft.Graph.Sites' }
    foreach ($module in @($required | Select-Object -Unique)) {
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
        $scopes = @()
        if ($Target -eq 'Entra') {
            $scopes += 'User.ReadWrite.All', 'Group.ReadWrite.All', 'GroupMember.ReadWrite.All', 'Directory.Read.All',
                       'RoleManagement.Read.Directory', 'User.RevokeSessions.All', 'Files.Read.All', 'Organization.Read.All',
                       'DeviceManagementManagedDevices.Read.All'
            if ($DeviceAction -ne 'None') { $scopes += 'DeviceManagementManagedDevices.PrivilegedOperations.All' }
        }
        if ($useSharePoint) { $scopes += 'Sites.ReadWrite.All' }
        $connect = @{ Scopes = $scopes; NoWelcome = $true }
        if ($TenantId) { $connect.TenantId = $TenantId }
        Connect-MgGraph @connect
    }
}

if ($useExchange) {
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        throw 'Module ExchangeOnlineManagement not found. Run: Install-Module ExchangeOnlineManagement -Scope CurrentUser'
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

if ($Target -eq 'Entra' -and $SharePointAdminUrl) {
    $spoModule = 'Microsoft.Online.SharePoint.PowerShell'
    if (-not (Get-Module -ListAvailable -Name $spoModule)) {
        throw "Module '$spoModule' not found. Run: Install-Module $spoModule -Scope CurrentUser"
    }
    if ($PSVersionTable.PSEdition -eq 'Core') { Import-Module $spoModule -UseWindowsPowerShell } else { Import-Module $spoModule }
    Connect-SPOService -Url $SharePointAdminUrl
}

# ---------------------------------------------------------------------------
# Build the work list
# ---------------------------------------------------------------------------
if ($useSharePoint) {
    $rows = @(Get-SpDueLeavers)
    Write-Log "Found $($rows.Count) due leaver(s) with Status '$StatusFilter' in list '$SharePointListName'."
}
elseif ($PSCmdlet.ParameterSetName -eq 'Bulk') {
    $rows = @(Import-Csv -Path $CsvPath)
}
else {
    $rows = @([pscustomobject]@{ UserPrincipalName = $UserPrincipalName; Manager = $Manager; TicketRef = $TicketRef })
}

Write-Log "Starting offboarding run: Target=$Target, Users=$($rows.Count), WhatIf=$($WhatIfPreference), DeviceAction=$DeviceAction."

$results = foreach ($row in $rows) {
    $item = [pscustomobject]@{
        UserPrincipalName = Get-Field $row 'UserPrincipalName'
        Manager           = Get-Field $row 'Manager'
        TicketRef         = Get-Field $row 'TicketRef'
        ListItemId        = Get-Field $row 'ListItemId'
    }

    # Keep only the last object emitted: the result record
    $outcome = @(Invoke-Offboard -Item $item) | Select-Object -Last 1

    if ($useSharePoint -and $item.ListItemId) {
        Update-SpListItemResult -ListItemId $item.ListItemId -Result $outcome
    }
    $outcome
}

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
Write-Host ''
$results | Format-Table UserPrincipalName, Status, Manager, Devices, Notes -AutoSize -Wrap

$completed = @($results | Where-Object { $_.Status -eq 'Completed' }).Count
$attention = @($results | Where-Object { $_.Status -eq 'Needs attention' }).Count
$failed    = @($results | Where-Object { $_.Status -eq 'Failed' }).Count
Write-Log "Run complete: $completed completed, $attention need attention, $failed failed."

if ($useExchange) { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue }
if ($useGraph -and -not $CertificateThumbprint) { Disconnect-MgGraph | Out-Null }
if ($failed -gt 0) { exit 1 }
