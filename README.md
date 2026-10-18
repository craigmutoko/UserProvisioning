# JML-Automation

PowerShell scripts for the **joiner, mover, leaver (JML)** lifecycle in **Microsoft 365 / Entra ID** and **on-premises Active Directory**, plus helpdesk and modern workplace tooling as the repo grows.

> Not yet tested against a live environment. Always start with `-WhatIf` and a test user or test OU.

## Repo layout

| Folder | Script | What it does |
|---|---|---|
| `Joiners/` | `New-UserProvision.ps1` | Creates users in on-prem AD or Entra ID, with optional SharePoint list input, manager handover by email and Temporary Access Pass |
| `Joiners/` | `users.sample.csv` | Sample input for bulk creation (fake names) |
| `Leavers/` | `Get-LeaverDiscovery.ps1` | Read-only report of everything a leaver owns or controls, with risk flags |
| `Leavers/` | `Invoke-UserOffboarding.ps1` | Offboards leavers: blocks sign-in, converts the mailbox, hands over access, removes licences and groups, on-prem tidy-up |

Planned: leaver restore script, mover script, helpdesk user snapshot, Intune reporting.

## Joiners: New-UserProvision.ps1

- Creates one user (parameters), many users (CSV) or users requested through a SharePoint list
- Builds a unique username (`first.last`, numeric suffix if taken) and refuses to create a second account for the same display name unless told to
- Sets department, job title and manager, and adds the user to listed groups
- Entra: optional direct licence assignment, optional Temporary Access Pass
- Optionally emails the credential to the line manager (never saved to Sent Items)
- SharePoint mode writes Status, ProvisionedUPN, ProvisionedOn and Notes back to each list item (never credentials)

```powershell
# Dry run: on-prem user
.\Joiners\New-UserProvision.ps1 -Target OnPrem -FirstName Jane -LastName Smith -UpnSuffix contoso.com `
    -OrganizationalUnit 'OU=Staff,OU=Users,DC=contoso,DC=local' -Department Sales -Manager john.doe -WhatIf

# Entra user, Temporary Access Pass emailed to the manager
.\Joiners\New-UserProvision.ps1 -Target Entra -FirstName Amir -LastName Patel -UpnSuffix contoso.com `
    -Manager jane.smith@contoso.com -UseTemporaryAccessPass -NotifyManager -MailFrom servicedesk@contoso.com

# Pending requests from a SharePoint list
.\Joiners\New-UserProvision.ps1 -Target OnPrem -UpnSuffix contoso.com `
    -OrganizationalUnit 'OU=Staff,OU=Users,DC=contoso,DC=local' `
    -SharePointSiteUrl 'https://contoso.sharepoint.com/sites/IT' -SharePointListName 'New Starters' -WhatIf
```

SharePoint list columns: `FirstName`, `LastName`, `Username` (optional), `Department`, `JobTitle`, `Manager` (text: UPN or sAMAccountName), `Groups` (semicolon separated), `Status` (Choice: Pending / Created / Failed, default Pending), `ProvisionedUPN`, `ProvisionedOn` (date and time), `Notes`. Use column names without spaces, or map them with `-ColumnMap`.

## Leavers

Use the two scripts in this order.

1. **`Get-LeaverDiscovery.ps1`** is read-only. It reports licences, groups and Teams owned (flagging sole ownership), direct reports, admin roles, owned app registrations, devices, OneDrive size and mailbox details (size, archive, holds, forwarding, delegates), then lists risk flags to sort out first.
2. **`Invoke-UserOffboarding.ps1`** does the work, in this order:
   - safety checks (protected accounts and privileged users are refused)
   - disable the account, reset the password, revoke sessions
   - convert the mailbox to shared, set an auto-reply, give the manager Full Access
   - give the manager access to the OneDrive
   - transfer sole ownership of groups and Teams, reassign direct reports
   - report (or optionally retire or wipe) Intune devices
   - remove group memberships and directly assigned licences
   - on-prem: disable, reset password, remove groups, stamp description, move to a disabled OU

```powershell
.\Leavers\Get-LeaverDiscovery.ps1 -UserPrincipalName jane.smith@contoso.com -ReportPath .\Reports

# Always dry run first: prints the full plan and changes nothing
.\Leavers\Invoke-UserOffboarding.ps1 -UserPrincipalName jane.smith@contoso.com -TicketRef INC0012345 `
    -IncludeOnPrem -DisabledOU 'OU=Disabled,DC=contoso,DC=local' `
    -SharePointAdminUrl 'https://contoso-admin.sharepoint.com' -WhatIf

# Daily run from a SharePoint "Leavers" list: processes leavers whose leave date has arrived
.\Leavers\Invoke-UserOffboarding.ps1 -SharePointSiteUrl 'https://contoso.sharepoint.com/sites/IT' `
    -SharePointListName 'Leavers' -IncludeOnPrem -DisabledOU 'OU=Disabled,DC=contoso,DC=local' -Confirm:$false
```

Leavers list columns: `UserPrincipalName`, `Manager` (optional), `TicketRef`, `LeaveDate` (date and time), `Status` (Choice: Pending / Completed / Needs attention / Failed, default Pending), `ProcessedOn` (date and time), `Notes`.

Behaviour worth knowing:

- A real run asks for one confirmation per user. Use `-Confirm:$false` for unattended runs.
- A mailbox over 49 GB, on hold or with an archive stays licensed, and licence-giving groups are left alone.
- A group is never left without an owner: if handing it to the manager fails, the leaver stays as owner.
- A failed step is recorded and the run continues. The user is then marked **Needs attention**.
- Each real run saves a JSON state file (no secrets) to `OffboardingState/` listing what was removed, ready for a restore script.
- Not covered: removing MFA methods, forwarding rules, meetings the leaver organised, third-party apps.

## Requirements

| Scenario | Needs |
|---|---|
| On-prem AD steps | Windows, PowerShell 5.1+, `ActiveDirectory` module (RSAT) |
| Entra / Microsoft 365 steps | `Microsoft.Graph` modules |
| Mailbox steps | `ExchangeOnlineManagement` |
| OneDrive handover | `Microsoft.Online.SharePoint.PowerShell` (Windows PowerShell; PowerShell 7 loads it through compatibility mode) |
| SharePoint list input | `Microsoft.Graph.Sites`, `Sites.ReadWrite.All` (or `Sites.Selected` on one site) |
| Manager email | `Mail.Send`, plus rights to send as the `-MailFrom` mailbox |
| Temporary Access Pass | `Microsoft.Graph.Identity.SignIns`, `UserAuthenticationMethod.ReadWrite.All`, TAP enabled in the Authentication methods policy |

On macOS, PowerShell 7 works for the Entra, Graph and Exchange Online parts. The AD and SharePoint Online Management Shell steps need Windows.

Run `Get-Help .\<path>\<script>.ps1 -Full` for all parameters and the permissions each script asks for.

## Hybrid note

If your tenant syncs from on-prem AD, create users with `-Target OnPrem` and let Entra Connect sync them. Creating a cloud-only twin causes duplicates. Likewise, a synced leaver must be disabled on-prem, so use `-IncludeOnPrem` when offboarding. Temporary Access Pass needs the account to exist in Entra, so it only works with `-Target Entra`.

## Security notes

- Credentials are never written to the log or to SharePoint.
- Do not commit results files (`-OutputCsv`), logs, offboarding state files or discovery reports: they contain real user data. The included `.gitignore` excludes them.
- Prefer certificate-based app registrations for unattended runs, and scope them tightly.
