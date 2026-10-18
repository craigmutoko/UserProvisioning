#Requires -Version 5.1
<#
.SYNOPSIS
    Provisions a new user in on-premises Active Directory OR Microsoft Entra ID.

.DESCRIPTION
    Creates one user (parameters) or many users (CSV) in the chosen target:
      - OnPrem : New-ADUser in the OU you specify (needs the ActiveDirectory module / RSAT)
      - Entra  : New-MgUser via Microsoft Graph (needs the Microsoft.Graph modules)

    For each user it will:
      * build a unique username (first.last, with a numeric suffix if taken)
      * generate a random temporary password (forced change at next sign-in)
      * set department, job title and manager (if supplied and found)
      * add the user to the groups you list
      * (Entra only) optionally assign a licence directly

    Input can come from parameters (one user), a CSV (-CsvPath) or a SharePoint
    list (-SharePointSiteUrl / -SharePointListName). With a list, only items whose
    Status equals -StatusFilter (default 'Pending') are processed, and the outcome
    (Status, ProvisionedUPN, ProvisionedOn, Notes) is written back to each item.
    Temporary passwords are NEVER written to SharePoint.

    With -UseTemporaryAccessPass (Entra only) no password is shared. A Temporary Access Pass is
    issued instead, and that is what gets handed over. Requirements: the Temporary Access Pass
    method must be enabled for the user in Entra (Authentication methods policy), and the signed-in
    admin needs a role that can manage authentication methods (e.g. Authentication Administrator)
    plus the UserAuthenticationMethod.ReadWrite.All permission. The lifetime counts from the start
    time, so if you create accounts days before the start date, set -TapStartDateTime.
    The account still gets a random password that nobody sees.

    With -NotifyManager -MailFrom <mailbox>, the username and temporary password are emailed
    to the new user's line manager (from the Manager value) using Microsoft Graph Send-MgUserMail,
    without saving a copy to Sent Items. When the email is sent, the password is masked in the
    console output and any -OutputCsv. If the manager cannot be found or the email fails, the
    password stays in the output so you can hand it over manually.

    Supports -WhatIf. Nothing is written to the log except non-secret details.

    HYBRID NOTE: if your tenant syncs from on-prem AD (Entra Connect / Cloud Sync),
    create users with -Target OnPrem and let them sync. Creating a cloud-only twin
    in Entra will cause duplicate or conflicting accounts.

.NOTES
    Entra delegated scopes requested (verify against current Graph docs and trim as needed):
      User.ReadWrite.All, GroupMember.ReadWrite.All, Group.Read.All, Organization.Read.All
    For unattended runs use an app registration with certificate auth and the
    equivalent APPLICATION permissions (-TenantId, -ClientId, -CertificateThumbprint).

    SharePoint list: the Sites.ReadWrite.All scope is added automatically (read + write-back).
    For tighter access use an app registration with Sites.Selected granted on the one site.
    Use plain-text columns named FirstName, LastName, Username, Department, JobTitle,
    Manager, Groups (semicolon separated), plus Status (Choice: Pending / Created / Failed),
    ProvisionedUPN, ProvisionedOn (date and time) and Notes. Create the columns with no spaces
    in the name so the internal name matches, or map them with -ColumnMap
    (e.g. -ColumnMap @{ FirstName = 'First_x0020_Name' }). Manager must be a text column.
    Give Status a default of 'Pending' so new requests are picked up.

    Groups: on-prem = group name or sAMAccountName. Entra = exact display name
    (security or M365 groups with assigned membership; dynamic and synced groups are skipped).
    Manager: on-prem = sAMAccountName or UPN. Entra = UPN or mail address.

    Prefer group-based licensing in Entra where you can; use -LicenseSkuPartNumber
    only if you need direct assignment (e.g. SPE_E3, O365_BUSINESS_PREMIUM).

.EXAMPLE
    # Test first, nothing is created
    .\New-UserProvision.ps1 -Target OnPrem -FirstName Jane -LastName Smith -UpnSuffix contoso.com `
        -OrganizationalUnit 'OU=Staff,OU=Users,DC=contoso,DC=local' `
        -Department Sales -JobTitle 'Account Manager' -Manager john.doe -Groups 'SG-Sales' -WhatIf

.EXAMPLE
    # Cloud-only user in Entra with a direct licence
    .\New-UserProvision.ps1 -Target Entra -FirstName Amir -LastName Patel -UpnSuffix contoso.com `
        -Department IT -JobTitle 'Support Analyst' -Manager jane.smith@contoso.com `
        -Groups 'All Staff' -LicenseSkuPartNumber SPE_E3

.EXAMPLE
    # Bulk from CSV, save results for secure handover
    .\New-UserProvision.ps1 -Target Entra -CsvPath .\users.sample.csv -UpnSuffix contoso.com -OutputCsv .\results.csv

.EXAMPLE
    # Process pending requests from a SharePoint list (on-prem accounts), dry run first
    .\New-UserProvision.ps1 -Target OnPrem -UpnSuffix contoso.com `
        -OrganizationalUnit 'OU=Staff,OU=Users,DC=contoso,DC=local' `
        -SharePointSiteUrl 'https://contoso.sharepoint.com/sites/IT' -SharePointListName 'New Starters' -WhatIf
#>

[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Single')]
param(
    [Parameter(Mandatory)]
    [ValidateSet('OnPrem', 'Entra')]
    [string]$Target,

    # ---- Single user ----
    [Parameter(Mandatory, ParameterSetName = 'Single')]
    [string]$FirstName,

    [Parameter(Mandatory, ParameterSetName = 'Single')]
    [string]$LastName,

    [Parameter(ParameterSetName = 'Single')]
    [string]$Username,

    [Parameter(ParameterSetName = 'Single')]
    [string]$Department,

    [Parameter(ParameterSetName = 'Single')]
    [string]$JobTitle,

    [Parameter(ParameterSetName = 'Single')]
    [string]$Manager,

    [Parameter(ParameterSetName = 'Single')]
    [string[]]$Groups,

    # ---- Bulk ----
    # CSV columns: FirstName, LastName, Username, Department, JobTitle, Manager, Groups (semicolon separated)
    [Parameter(Mandatory, ParameterSetName = 'Bulk')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$CsvPath,

    # ---- SharePoint list ----
    # Site URL e.g. https://contoso.sharepoint.com/sites/IT ; list display name e.g. 'New Starters'
    [Parameter(Mandatory, ParameterSetName = 'SharePoint')]
    [string]$SharePointSiteUrl,

    [Parameter(Mandatory, ParameterSetName = 'SharePoint')]
    [string]$SharePointListName,

    # Only items whose Status column equals this value are processed
    [Parameter(ParameterSetName = 'SharePoint')]
    [string]$StatusFilter = 'Pending',

    # Map logical names to SharePoint internal column names where they differ
    [Parameter(ParameterSetName = 'SharePoint')]
    [hashtable]$ColumnMap = @{},

    # ---- Common ----
    [Parameter(Mandatory)]
    [string]$UpnSuffix,

    # On-prem only: distinguished name of the target OU
    [string]$OrganizationalUnit,

    # Entra only
    [ValidateLength(2, 2)]
    [string]$UsageLocation = 'GB',
    [string]$LicenseSkuPartNumber,
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint,

    [ValidateRange(12, 64)]
    [int]$PasswordLength = 16,

    # Create anyway when a user with the same display name already exists
    [switch]$AllowDuplicateNames,

    # Email the username and temporary password to the new user's line manager via Microsoft Graph.
    # -MailFrom is the UPN / address of the mailbox that sends it (e.g. a shared mailbox like servicedesk@contoso.com)
    [switch]$NotifyManager,
    [string]$MailFrom,

    # Entra only: issue a Temporary Access Pass instead of sharing a password.
    # The pass is one-time use by default; -TapMultiUse allows repeated use within its lifetime.
    # -TapStartDateTime sets when it becomes valid (e.g. the starter's first morning); default is now.
    [switch]$UseTemporaryAccessPass,
    [ValidateRange(10, 43200)]
    [int]$TapLifetimeMinutes = 480,
    [switch]$TapMultiUse,
    [datetime]$TapStartDateTime,

    # Optional: write results (INCLUDING temporary passwords) to this CSV
    [string]$OutputCsv,

    [string]$LogPath
)

$ErrorActionPreference = 'Stop'

if (-not $LogPath) {
    $base = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $LogPath = Join-Path $base 'New-UserProvision.log'
}

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

function ConvertTo-CleanName {
    param([string]$Text)
    $decomposed = $Text.Normalize([System.Text.NormalizationForm]::FormD)
    $decomposed = [regex]::Replace($decomposed, '\p{Mn}', '')
    return [regex]::Replace($decomposed.ToLower(), '[^a-z0-9]', '')
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
    param([int]$Length = 16)
    # Ambiguous characters (0, O, 1, l, I) removed so it can be read out over the phone
    $sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!#$%&*?@')
    $all = $sets -join ''
    $chars = New-Object System.Collections.Generic.List[char]
    foreach ($set in $sets) { $chars.Add($set[(Get-RandomInt -Max $set.Length)]) }
    while ($chars.Count -lt $Length) { $chars.Add($all[(Get-RandomInt -Max $all.Length)]) }
    # Fisher-Yates shuffle so the guaranteed characters are not always first
    for ($i = $chars.Count - 1; $i -gt 0; $i--) {
        $j = Get-RandomInt -Max ($i + 1)
        $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
    }
    return (-join $chars)
}

function Resolve-UniqueUsername {
    param(
        [Parameter(Mandatory)][string]$Base,
        [Parameter(Mandatory)][int]$MaxLength,
        [Parameter(Mandatory)][scriptblock]$Exists,
        [switch]$Strict   # fail instead of adding a numeric suffix (used when the username was supplied explicitly)
    )
    $Base = ($Base -replace '[^a-z0-9._-]', '').Trim('.')
    if (-not $Base) { throw 'Could not derive a valid username from the supplied name.' }

    for ($n = 0; $n -le 99; $n++) {
        $suffix = if ($n -eq 0) { '' } else { [string]$n }
        $stem = $Base.Substring(0, [Math]::Min($Base.Length, $MaxLength - $suffix.Length)).TrimEnd('.')
        $candidate = "$stem$suffix"
        if (-not (& $Exists $candidate)) { return $candidate }
        if ($Strict) { throw "Username '$candidate' already exists." }
    }
    throw "Could not find a free username based on '$Base'."
}

# ---------------------------------------------------------------------------
# SharePoint list (request queue and status write-back)
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

function Get-SpPendingUsers {
    $script:SpIds = Get-SpSiteAndList
    # Filtering is done client-side: non-indexed columns cannot be filtered server-side
    $items = Get-MgSiteListItem -SiteId $script:SpIds.SiteId -ListId $script:SpIds.ListId -ExpandProperty 'fields' -All
    foreach ($item in $items) {
        $f = $item.Fields.AdditionalProperties
        $status = Get-SpValue $f 'Status'
        if ($script:StatusFilter -and $status -ne $script:StatusFilter) { continue }
        [pscustomobject]@{
            ListItemId = $item.Id
            FirstName  = Get-SpValue $f 'FirstName'
            LastName   = Get-SpValue $f 'LastName'
            Username   = Get-SpValue $f 'Username'
            Department = Get-SpValue $f 'Department'
            JobTitle   = Get-SpValue $f 'JobTitle'
            Manager    = Get-SpValue $f 'Manager'
            Groups     = Get-SpValue $f 'Groups'
        }
    }
}

function Update-SpListItemResult {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][string]$ListItemId,
        [Parameter(Mandatory)]$Result
    )
    # Only record real outcomes; never write the temporary password back to SharePoint
    if ($Result.Status -notin 'Created', 'Failed') { return }

    $notes = "$($Result.Notes)"
    if ($notes.Length -gt 250) { $notes = $notes.Substring(0, 250) }

    $body = @{}
    $body[(Get-SpColumn 'Status')]         = $Result.Status
    $body[(Get-SpColumn 'ProvisionedUPN')] = "$($Result.UserPrincipalName)"
    $body[(Get-SpColumn 'ProvisionedOn')]  = (Get-Date).ToUniversalTime().ToString('o')
    $body[(Get-SpColumn 'Notes')]          = $notes

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
# Manager handover email
# ---------------------------------------------------------------------------
function Add-ResultNote {
    param([Parameter(Mandatory)]$Result, [Parameter(Mandatory)][string]$Text)
    $Result.Notes = (@($Result.Notes, $Text) | Where-Object { $_ }) -join '; '
}

function Send-ManagerHandover {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory)]$Result)

    if ($Result.Status -ne 'Created' -or -not $Result.TempPassword) { return }

    if (-not $Result.ManagerEmail) {
        Add-ResultNote -Result $Result -Text 'No manager email: hand password over manually'
        Write-Log "No manager email found for $($Result.UserPrincipalName); password not emailed." 'WARN'
        return
    }

    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    if ($Result.CredentialType -eq 'TAP') {
        $credLabel = 'Temporary Access Pass'
        $credHelp  = "This is a Temporary Access Pass ($($Result.CredentialInfo)). They use it to sign in the first time and will then be guided through setting up their own sign-in method, such as the Authenticator app."
    }
    else {
        $credLabel = 'Temporary password'
        $credHelp  = 'They will be asked to choose a new password the first time they sign in.'
    }
    $html = @"
<p>Hello,</p>
<p>An account has been created for your new team member <b>$(& $enc $Result.DisplayName)</b>.</p>
<table cellpadding="4">
<tr><td>Username</td><td><b>$(& $enc $Result.UserPrincipalName)</b></td></tr>
<tr><td>$credLabel</td><td><code>$(& $enc $Result.TempPassword)</code></td></tr>
</table>
<p>$(& $enc $credHelp)</p>
<p>Please pass these details to them in person or by phone, not by chat or email.</p>
<p>If you were not expecting this, please contact IT.</p>
"@

    $message = @{
        Subject      = "New starter account created: $($Result.DisplayName)"
        Body         = @{ ContentType = 'HTML'; Content = $html }
        ToRecipients = @(@{ EmailAddress = @{ Address = $Result.ManagerEmail } })
    }

    if ($PSCmdlet.ShouldProcess($Result.ManagerEmail, "Email handover details for $($Result.UserPrincipalName)")) {
        try {
            # SaveToSentItems = false keeps the password out of the sending mailbox
            Send-MgUserMail -UserId $script:MailFrom -BodyParameter @{ Message = $message; SaveToSentItems = 'false' }
            $Result.TempPassword = '(emailed to manager)'
            Add-ResultNote -Result $Result -Text 'Handover emailed to manager'
            Write-Log "Emailed handover details for $($Result.UserPrincipalName) to $($Result.ManagerEmail)."
        }
        catch {
            Add-ResultNote -Result $Result -Text 'Handover email failed: hand password over manually'
            Write-Log "Could not email handover for $($Result.UserPrincipalName): $($_.Exception.Message)" 'WARN'
        }
    }
}

# ---------------------------------------------------------------------------
# On-premises AD
# ---------------------------------------------------------------------------
function New-OnPremUser {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory)]$User)

    $explicit = [bool]$User.Username
    $base = if ($explicit) { $User.Username.ToLower().Trim() }
            else { '{0}.{1}' -f (ConvertTo-CleanName $User.FirstName), (ConvertTo-CleanName $User.LastName) }

    # Guard against re-runs creating a second account for the same person (jane.smith1)
    if (-not $explicit -and -not $script:AllowDuplicateNames) {
        $nameCheck = ConvertTo-FilterLiteral ('{0} {1}' -f $User.FirstName.Trim(), $User.LastName.Trim())
        $existing = @(Get-ADUser -Filter "DisplayName -eq '$nameCheck'")
        if ($existing.Count -gt 0) {
            throw "A user named '$($User.FirstName) $($User.LastName)' already exists ($($existing[0].SamAccountName)). Use -AllowDuplicateNames, or supply a Username, if this is a different person."
        }
    }

    # sAMAccountName is limited to 20 characters; the UPN uses the same value
    $sam = Resolve-UniqueUsername -Base $base -MaxLength 20 -Strict:$explicit -Exists {
        param($c)
        [bool](Get-ADUser -Filter "SamAccountName -eq '$c'") -or
        [bool](Get-ADUser -Filter "UserPrincipalName -eq '$c@$script:UpnSuffix'")
    }
    $upn = "$sam@$script:UpnSuffix"

    $displayName = '{0} {1}' -f $User.FirstName.Trim(), $User.LastName.Trim()
    $cn = $displayName
    $cnFilter = ConvertTo-FilterLiteral $cn
    if (Get-ADUser -SearchBase $script:OrganizationalUnit -SearchScope OneLevel -Filter "Name -eq '$cnFilter'") {
        $cn = "$displayName ($sam)"   # CN must be unique within the OU
    }

    $notes = New-Object System.Collections.Generic.List[string]

    $managerDn = $null
    $managerEmail = $null
    if ($User.Manager) {
        $m = ConvertTo-FilterLiteral $User.Manager
        $mgr = Get-ADUser -Filter "SamAccountName -eq '$m' -or UserPrincipalName -eq '$m'" -Properties EmailAddress
        if ($mgr) {
            $managerDn = @($mgr)[0].DistinguishedName
            $managerEmail = if (@($mgr)[0].EmailAddress) { @($mgr)[0].EmailAddress } else { @($mgr)[0].UserPrincipalName }
        }
        else {
            $notes.Add("Manager '$($User.Manager)' not found")
            Write-Log "Manager '$($User.Manager)' not found in AD; skipping manager for $upn." 'WARN'
        }
    }

    $result = [pscustomobject]@{
        Target            = 'OnPrem'
        DisplayName       = $displayName
        Username          = $sam
        UserPrincipalName = $upn
        ManagerEmail      = $managerEmail
        CredentialType    = 'Password'
        CredentialInfo    = $null
        TempPassword      = $null
        Status            = 'WhatIf'
        Notes             = ''
    }

    if ($PSCmdlet.ShouldProcess("$upn in $script:OrganizationalUnit", 'Create AD user')) {
        $password = New-RandomPassword -Length $script:PasswordLength
        $params = @{
            Name                  = $cn
            GivenName             = $User.FirstName.Trim()
            Surname               = $User.LastName.Trim()
            DisplayName           = $displayName
            SamAccountName        = $sam
            UserPrincipalName     = $upn
            EmailAddress          = $upn   # adjust if your primary SMTP address differs from the UPN
            Path                  = $script:OrganizationalUnit
            AccountPassword       = (ConvertTo-SecureString -String $password -AsPlainText -Force)
            Enabled               = $true
            ChangePasswordAtLogon = $true
        }
        if ($User.Department) { $params.Department = $User.Department }
        if ($User.JobTitle)   { $params.Title = $User.JobTitle }
        if ($managerDn)       { $params.Manager = $managerDn }

        New-ADUser @params
        Write-Log "Created AD user $upn (CN=$cn)."

        foreach ($g in $User.Groups) {
            try {
                if ($PSCmdlet.ShouldProcess($g, "Add $sam to group")) {
                    Add-ADGroupMember -Identity $g -Members $sam
                    Write-Log "Added $sam to AD group '$g'."
                }
            }
            catch {
                $notes.Add("Group '$g' failed")
                Write-Log "Could not add $sam to group '$g': $($_.Exception.Message)" 'WARN'
            }
        }

        $result.TempPassword = $password
        $result.Status = 'Created'
    }

    $result.Notes = ($notes -join '; ')
    return $result
}

# ---------------------------------------------------------------------------
# Microsoft Entra ID
# ---------------------------------------------------------------------------
function New-EntraUser {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory)]$User)

    $explicit = [bool]$User.Username
    $base = if ($explicit) { $User.Username.ToLower().Trim() }
            else { '{0}.{1}' -f (ConvertTo-CleanName $User.FirstName), (ConvertTo-CleanName $User.LastName) }

    # Guard against re-runs creating a second account for the same person (jane.smith1)
    if (-not $explicit -and -not $script:AllowDuplicateNames) {
        $nameCheck = ConvertTo-FilterLiteral ('{0} {1}' -f $User.FirstName.Trim(), $User.LastName.Trim())
        $existing = @(Get-MgUser -Filter "displayName eq '$nameCheck'")
        if ($existing.Count -gt 0) {
            throw "A user named '$($User.FirstName) $($User.LastName)' already exists ($($existing[0].UserPrincipalName)). Use -AllowDuplicateNames, or supply a Username, if this is a different person."
        }
    }

    $nick = Resolve-UniqueUsername -Base $base -MaxLength 64 -Strict:$explicit -Exists {
        param($c)
        $candidateUpn = "$c@$script:UpnSuffix"
        [bool](Get-MgUser -Filter "userPrincipalName eq '$candidateUpn'" -ErrorAction SilentlyContinue) -or
        [bool](Get-MgUser -Filter "mailNickname eq '$c'" -ErrorAction SilentlyContinue)
    }
    $upn = "$nick@$script:UpnSuffix"
    $displayName = '{0} {1}' -f $User.FirstName.Trim(), $User.LastName.Trim()

    $notes = New-Object System.Collections.Generic.List[string]

    $result = [pscustomobject]@{
        Target            = 'Entra'
        DisplayName       = $displayName
        Username          = $nick
        UserPrincipalName = $upn
        ManagerEmail      = $null
        CredentialType    = 'Password'
        CredentialInfo    = $null
        TempPassword      = $null
        Status            = 'WhatIf'
        Notes             = ''
    }

    if ($PSCmdlet.ShouldProcess($upn, 'Create Entra ID user')) {
        $password = New-RandomPassword -Length $script:PasswordLength
        $params = @{
            AccountEnabled    = $true
            DisplayName       = $displayName
            GivenName         = $User.FirstName.Trim()
            Surname           = $User.LastName.Trim()
            UserPrincipalName = $upn
            MailNickname      = $nick
            UsageLocation     = $script:UsageLocation
            PasswordProfile   = @{ Password = $password; ForceChangePasswordNextSignIn = (-not $script:UseTemporaryAccessPass) }
        }
        if ($User.Department) { $params.Department = $User.Department }
        if ($User.JobTitle)   { $params.JobTitle = $User.JobTitle }

        $new = New-MgUser @params
        Write-Log "Created Entra user $upn (Id $($new.Id))."

        # Manager
        if ($User.Manager) {
            try {
                $m = ConvertTo-FilterLiteral $User.Manager
                $mgr = @(Get-MgUser -Filter "userPrincipalName eq '$m' or mail eq '$m'")
                if ($mgr.Count -eq 1) {
                    Set-MgUserManagerByRef -UserId $new.Id -BodyParameter @{
                        '@odata.id' = "https://graph.microsoft.com/v1.0/users/$($mgr[0].Id)"
                    }
                    $result.ManagerEmail = if ($mgr[0].Mail) { $mgr[0].Mail } else { $mgr[0].UserPrincipalName }
                    Write-Log "Set manager of $upn to $($User.Manager)."
                }
                else {
                    $notes.Add("Manager '$($User.Manager)' not found or ambiguous")
                    Write-Log "Manager '$($User.Manager)' not found or ambiguous; skipping." 'WARN'
                }
            }
            catch {
                $notes.Add('Manager failed')
                Write-Log "Could not set manager for ${upn}: $($_.Exception.Message)" 'WARN'
            }
        }

        # Groups
        foreach ($g in $User.Groups) {
            try {
                $gl = ConvertTo-FilterLiteral $g
                $grp = @(Get-MgGroup -Filter "displayName eq '$gl'")
                if ($grp.Count -ne 1) {
                    $notes.Add("Group '$g' not found or ambiguous")
                    Write-Log "Group '$g' not found or ambiguous; skipping." 'WARN'
                }
                elseif (($grp[0].GroupTypes -contains 'DynamicMembership') -or $grp[0].OnPremisesSyncEnabled) {
                    $notes.Add("Group '$g' is dynamic or synced")
                    Write-Log "Group '$g' is dynamic or synced from on-prem; cannot add members here." 'WARN'
                }
                else {
                    New-MgGroupMember -GroupId $grp[0].Id -DirectoryObjectId $new.Id
                    Write-Log "Added $upn to group '$g'."
                }
            }
            catch {
                $notes.Add("Group '$g' failed")
                Write-Log "Could not add $upn to group '$g': $($_.Exception.Message)" 'WARN'
            }
        }

        # Direct licence assignment (optional)
        if ($script:LicenseSkuPartNumber) {
            try {
                $sku = Get-MgSubscribedSku -All | Where-Object { $_.SkuPartNumber -eq $script:LicenseSkuPartNumber }
                if (-not $sku) {
                    $notes.Add("Licence '$($script:LicenseSkuPartNumber)' not found")
                    Write-Log "Licence SKU '$($script:LicenseSkuPartNumber)' not found in tenant." 'WARN'
                }
                elseif (($sku.PrepaidUnits.Enabled - $sku.ConsumedUnits) -lt 1) {
                    $notes.Add('No free licences')
                    Write-Log "No free '$($script:LicenseSkuPartNumber)' licences available." 'WARN'
                }
                else {
                    # A freshly created user can take a few seconds to be visible to the licensing service
                    $assigned = $false
                    for ($attempt = 1; $attempt -le 5 -and -not $assigned; $attempt++) {
                        try {
                            $null = Set-MgUserLicense -UserId $new.Id -AddLicenses @(@{ SkuId = $sku.SkuId }) -RemoveLicenses @()
                            $assigned = $true
                        }
                        catch {
                            if ($attempt -eq 5) { throw }
                            Start-Sleep -Seconds 5
                        }
                    }
                    Write-Log "Assigned licence $($script:LicenseSkuPartNumber) to $upn."
                }
            }
            catch {
                $notes.Add('Licence failed')
                Write-Log "Could not assign licence to ${upn}: $($_.Exception.Message)" 'WARN'
            }
        }

        if ($script:UseTemporaryAccessPass) {
            try {
                $tapBody = @{
                    lifetimeInMinutes = $script:TapLifetimeMinutes
                    isUsableOnce      = (-not $script:TapMultiUse)
                }
                if ($script:TapStartDateTime) { $tapBody.startDateTime = $script:TapStartDateTime.ToUniversalTime() }

                # A freshly created user can take a few seconds to be visible to the authentication methods service
                $tap = $null
                for ($attempt = 1; $attempt -le 5 -and -not $tap; $attempt++) {
                    try {
                        $tap = New-MgUserAuthenticationTemporaryAccessPassMethod -UserId $new.Id -BodyParameter $tapBody
                    }
                    catch {
                        if ($attempt -eq 5) { throw }
                        Start-Sleep -Seconds 5
                    }
                }

                $usage = if ($script:TapMultiUse) { 'multi-use' } else { 'one-time use' }
                $from = if ($script:TapStartDateTime) { 'from ' + $script:TapStartDateTime.ToUniversalTime().ToString('yyyy-MM-dd HH:mm') + ' UTC' } else { 'from now' }
                $result.TempPassword   = $tap.TemporaryAccessPass
                $result.CredentialType = 'TAP'
                $result.CredentialInfo = "$usage, valid $($script:TapLifetimeMinutes) minutes $from"
                Write-Log "Issued Temporary Access Pass for $upn ($($result.CredentialInfo))."
            }
            catch {
                $notes.Add('TAP failed: issue one manually in Entra')
                Write-Log "Could not issue Temporary Access Pass for ${upn}: $($_.Exception.Message)" 'WARN'
            }
        }
        else {
            $result.TempPassword = $password
        }
        $result.Status = 'Created'
    }

    $result.Notes = ($notes -join '; ')
    return $result
}

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
if ($NotifyManager -and -not $MailFrom) { throw '-MailFrom is required with -NotifyManager.' }
if ($UseTemporaryAccessPass -and $Target -ne 'Entra') {
    throw '-UseTemporaryAccessPass only works with -Target Entra (the account must exist in Entra ID).'
}

if ($Target -eq 'OnPrem') {
    if (-not $OrganizationalUnit) { throw '-OrganizationalUnit is required when -Target is OnPrem.' }
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw 'ActiveDirectory module not found. Install RSAT: Active Directory Domain Services tools.'
    }
    Import-Module ActiveDirectory
    if (-not (Get-ADObject -Identity $OrganizationalUnit -ErrorAction SilentlyContinue)) {
        throw "OU '$OrganizationalUnit' was not found."
    }
}

# Graph is needed for the Entra target and/or the SharePoint list source
$useSharePoint = ($PSCmdlet.ParameterSetName -eq 'SharePoint')
if ($Target -eq 'Entra' -or $useSharePoint -or $NotifyManager) {
    $required = @()
    if ($Target -eq 'Entra') {
        $required += 'Microsoft.Graph.Users', 'Microsoft.Graph.Users.Actions', 'Microsoft.Graph.Groups', 'Microsoft.Graph.Identity.DirectoryManagement'
    }
    if ($useSharePoint) { $required += 'Microsoft.Graph.Sites' }
    if ($NotifyManager -and $Target -ne 'Entra') { $required += 'Microsoft.Graph.Users.Actions' }
    if ($UseTemporaryAccessPass) { $required += 'Microsoft.Graph.Identity.SignIns' }
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
        $scopes = @()
        if ($Target -eq 'Entra') { $scopes += 'User.ReadWrite.All', 'GroupMember.ReadWrite.All', 'Group.Read.All', 'Organization.Read.All' }
        if ($useSharePoint)      { $scopes += 'Sites.ReadWrite.All' }
        if ($NotifyManager)      { $scopes += 'Mail.Send' }
        if ($UseTemporaryAccessPass) { $scopes += 'UserAuthenticationMethod.ReadWrite.All' }
        $connect = @{
            Scopes    = $scopes
            NoWelcome = $true
        }
        if ($TenantId) { $connect.TenantId = $TenantId }
        Connect-MgGraph @connect
    }
}

# ---------------------------------------------------------------------------
# Build the work list
# ---------------------------------------------------------------------------
if ($PSCmdlet.ParameterSetName -eq 'SharePoint') {
    $rows = @(Get-SpPendingUsers)
    Write-Log "Found $($rows.Count) item(s) with Status '$StatusFilter' in list '$SharePointListName'."
}
elseif ($PSCmdlet.ParameterSetName -eq 'Bulk') {
    $rows = @(Import-Csv -Path $CsvPath)
}
else {
    $rows = @([pscustomobject]@{
            FirstName  = $FirstName
            LastName   = $LastName
            Username   = $Username
            Department = $Department
            JobTitle   = $JobTitle
            Manager    = $Manager
            Groups     = ($Groups -join ';')
        })
}

Write-Log "Starting provisioning run: Target=$Target, Users=$($rows.Count), WhatIf=$($WhatIfPreference)."

$results = foreach ($row in $rows) {
    $groupList = @()
    $rawGroups = Get-Field $row 'Groups'
    if ($rawGroups) { $groupList = @($rawGroups -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }

    $user = [pscustomobject]@{
        FirstName  = Get-Field $row 'FirstName'
        LastName   = Get-Field $row 'LastName'
        Username   = Get-Field $row 'Username'
        Department = Get-Field $row 'Department'
        JobTitle   = Get-Field $row 'JobTitle'
        Manager    = Get-Field $row 'Manager'
        ListItemId = Get-Field $row 'ListItemId'
        Groups     = $groupList
    }

    try {
        if (-not $user.FirstName -or -not $user.LastName) { throw 'FirstName and LastName are required.' }
        # Keep only the last object emitted: the result record
        if ($Target -eq 'OnPrem') { $outcome = @(New-OnPremUser -User $user) | Select-Object -Last 1 }
        else                      { $outcome = @(New-EntraUser -User $user) | Select-Object -Last 1 }
    }
    catch {
        Write-Log "Failed for '$($user.FirstName) $($user.LastName)': $($_.Exception.Message)" 'ERROR'
        $outcome = [pscustomobject]@{
            Target            = $Target
            DisplayName       = ('{0} {1}' -f $user.FirstName, $user.LastName).Trim()
            Username          = $null
            UserPrincipalName = $null
            TempPassword      = $null
            Status            = 'Failed'
            Notes             = $_.Exception.Message
        }
    }

    if ($NotifyManager) { Send-ManagerHandover -Result $outcome }

    if ($useSharePoint -and $user.ListItemId) {
        Update-SpListItemResult -ListItemId $user.ListItemId -Result $outcome
    }
    $outcome
}

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
Write-Host ''
$results | Format-Table Target, UserPrincipalName, Status, CredentialType, TempPassword, Notes -AutoSize -Wrap

if ($OutputCsv) {
    $results | Export-Csv -Path $OutputCsv -NoTypeInformation
    Write-Log "Results (INCLUDING temporary passwords) written to $OutputCsv. Hand over securely, then delete the file." 'WARN'
}

$created = @($results | Where-Object { $_.Status -eq 'Created' }).Count
$failed  = @($results | Where-Object { $_.Status -eq 'Failed' }).Count
Write-Log "Run complete: $created created, $failed failed."

if (($Target -eq 'Entra' -or $useSharePoint -or $NotifyManager) -and -not $CertificateThumbprint) { Disconnect-MgGraph | Out-Null }
if ($failed -gt 0) { exit 1 }
