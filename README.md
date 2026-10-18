# User provisioning script

PowerShell script that provisions a new user in **on-premises Active Directory** or **Microsoft Entra ID**, with optional SharePoint list input, manager handover by email, and Temporary Access Pass (TAP) support.

> Not yet tested against a live environment. Always start with `-WhatIf` and a test OU or test user.

## What it does

- Creates one user (parameters), many users (CSV) or users requested through a SharePoint list
- Builds a unique username (`first.last`, numeric suffix if taken) and refuses to create a second account for the same display name unless told to
- Sets department, job title and manager, and adds the user to listed groups
- Entra: optional direct licence assignment, optional Temporary Access Pass
- Optionally emails the credential to the line manager (never saved to Sent Items)
- SharePoint mode writes Status, ProvisionedUPN, ProvisionedOn and Notes back to each list item (never credentials)

## Requirements

| Scenario | Needs |
|---|---|
| `-Target OnPrem` | PowerShell 5.1+, `ActiveDirectory` module (RSAT) |
| `-Target Entra` | `Microsoft.Graph` modules (Users, Users.Actions, Groups, Identity.DirectoryManagement) |
| SharePoint input | `Microsoft.Graph.Sites`, `Sites.ReadWrite.All` (or `Sites.Selected` on one site) |
| `-NotifyManager` | `Mail.Send`, plus rights to send as the `-MailFrom` mailbox |
| `-UseTemporaryAccessPass` | `Microsoft.Graph.Identity.SignIns`, `UserAuthenticationMethod.ReadWrite.All`, TAP enabled in the Authentication methods policy |

## Examples

```powershell
# Dry run: on-prem user
.\New-UserProvision.ps1 -Target OnPrem -FirstName Jane -LastName Smith -UpnSuffix contoso.com `
    -OrganizationalUnit 'OU=Staff,OU=Users,DC=contoso,DC=local' -Department Sales -Manager john.doe -WhatIf

# Entra user, TAP emailed to the manager
.\New-UserProvision.ps1 -Target Entra -FirstName Amir -LastName Patel -UpnSuffix contoso.com `
    -Manager jane.smith@contoso.com -UseTemporaryAccessPass -NotifyManager -MailFrom servicedesk@contoso.com

# Bulk from CSV
.\New-UserProvision.ps1 -Target Entra -CsvPath .\users.sample.csv -UpnSuffix contoso.com

# Pending requests from a SharePoint list
.\New-UserProvision.ps1 -Target OnPrem -UpnSuffix contoso.com `
    -OrganizationalUnit 'OU=Staff,OU=Users,DC=contoso,DC=local' `
    -SharePointSiteUrl 'https://contoso.sharepoint.com/sites/IT' -SharePointListName 'New Starters' -WhatIf
```

Run `Get-Help .\New-UserProvision.ps1 -Full` for all parameters.

## SharePoint list columns

`FirstName`, `LastName`, `Username` (optional), `Department`, `JobTitle`, `Manager` (text: UPN or sAMAccountName), `Groups` (semicolon separated), `Status` (Choice: Pending / Created / Failed, default Pending), `ProvisionedUPN`, `ProvisionedOn` (date and time), `Notes`.

Use column names without spaces, or map them with `-ColumnMap`.

## Hybrid note

If your tenant syncs from on-prem AD, create users with `-Target OnPrem` and let Entra Connect sync them. Creating a cloud-only twin causes duplicates. TAP needs the account to exist in Entra, so it only works with `-Target Entra`.

## Security notes

- Credentials are never written to the log or to SharePoint.
- Do not commit results files (`-OutputCsv`) or logs. The included `.gitignore` excludes them.
- Prefer certificate-based app registrations for unattended runs.
