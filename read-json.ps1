# function
function Get-InactiveAccounts {
    param([int]$Days = 30)

    $data = Get-Content -Path "ad_export.json" -Raw -Encoding UTF8 | ConvertFrom-Json
    $cutoff = (Get-Date).AddDays(-$Days)

    $inactiveUsers = $data.users | Where-Object {
        [datetime]$_.lastLogon -lt $cutoff
    } | Select-Object samAccountName, displayName, department, lastLogon,
    @{Name = "DaysInactive"; Expression = { (New-TimeSpan -Start ([datetime]$_.lastLogon) -End (Get-Date)).Days } }
    
    return $inactiveUsers
}

# --- main script ---#

# read JSON ad_export.json
$data = Get-Content -Path "ad_export.json" -Raw -Encoding UTF8 | ConvertFrom-Json

# pre-calc all metrics before report

$expiringAccounts = $data.users | Where-Object {
    [datetime]$_.accountExpires -lt (Get-Date).AddDays(30) -and $_.enabled -eq $true
}
$expiringCount = $expiringAccounts.Count

$oldPasswordsEnabled = $data.users | Where-Object {
    $_.enabled -eq $true -and (
        ($_.passwordNeverExpires -eq $true) -or
        ((New-TimeSpan -Start ([datetime]$_.passwordLastSet) -End (Get-Date)).Days -gt 90)
    )
}
$oldPasswordsDisabled = $data.users | Where-Object {
    $_.enabled -eq $false -and (
        $_.passwordNeverExpires -eq $true -or
        ((New-TimeSpan -Start ([datetime]$_.passwordLastSet) -End (Get-Date)).Days -gt 90)    
    )
}
$oldPwdCountEnabled = $oldPasswordsEnabled.Count
$oldPwdCountDisabled = $oldPasswordsDisabled.Count

$inactiveUsersEnabled = $data.users | Where-Object {
    $_.enabled -eq $true -and
    (New-TimeSpan -Start ([datetime]$_.lastLogon) -End (Get-Date)).Days -gt 30    
}
$inactiveUsersDisabled = $data.users | Where-Object {
    $_.enabled -eq $false -and
    (New-TimeSpan -Start ([datetime]$_.lastLogon) -End (Get-Date)).Days -gt 30
}
$inactiveUserCountEnabled = $inactiveUsersEnabled.Count
$inactiveUserCountDisabled = $inactiveUsersDisabled.Count

$totalComputers = $data.computers.Count
$activeComputers = ($data.computers | Where-Object {
        (New-TimeSpan -Start ([datetime]$_.lastLogon) -End (Get-Date)).Days -lt 7
    }).Count

$staleComputers = ($data.computers | Where-Object {
        (New-TimeSpan -Start ([datetime]$_.lastLogon) -End (Get-Date)).Days -ge 7 -and
        (New-TimeSpan -Start ([datetime]$_.lastLogon) -End (Get-Date)).Days -le 30
    }).Count

$inactiveComputers = ($data.computers | Where-Object {
        (New-TimeSpan -Start ([datetime]$_.lastLogon) -End (Get-Date)).Days -gt 30
    }).count

$oldOSComputersEnabled = $data.computers | Where-Object {
    $_.enabled -eq $true -and (
        $_.operatingSystem -like "windows 10*" -or $_.operatingSystem -like "windows server 2019*"
    )
}
$oldOSComputersDisabled = $data.computers | Where-Object {
    $_.enabled -eq $false -and (
        $_.operatingSystem -like "windows 10*" -or $_.operatingSystem -like "windows server 2019*"
    )
}
$oldOSCountEnabled = $oldOSComputersEnabled.count
$oldOSCountDisabled = $oldOSComputersDisabled.count

$modernClients = $data.computers | Where-Object {
    $_.operatingSystem -like "windows 11*" -and $_.enabled -eq $true
}
$modernClientCount = $modernClients.Count
$modernPercent = [math]::Round(($modernClientCount / $totalClients) * 100, 1)


# header
$header = @(
    ("=" * 80)
    ("|                         ACTIVE DIRECTORY AUDIT REPORT                        |")
    ("=" * 80)
    ("Generated: {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
    ("Domain: {0}" -f $data.domain)
    ("Export Date: {0}" -f $data.export_date)
    ""
    ""
)
$header | Out-File "ad_audit_report.txt" -Encoding UTF8

# executive summary
$summary = @(
    "EXECUTIVE SUMMARY"
    ("-" * 20)
    "⚠ CRITICAL: $expiringCount user accounts expiring within 30 days"
    "⚠ WARNING: $oldPwdCountEnabled user accounts with outdated or non-expiring passwords [+${oldPwdCountDisabled} disabled]"
    "⚠ SECURITY: $inactiveUserCountEnabled inactive user accounts (>30 days) [+${inactiveUserCountDisabled} disabled]"
    "⚠ SECURITY: $inactiveComputers inactive computers (>30 days), $staleComputers stale (7-30 days), and $oldOSCountEnabled computers on older OS [+${oldOSCountDisabled} disabled]" 
    "✓ STATUS: $modernPercent% of computers are running windows 11 23H2, domain controllers on Windows Server 2022 "
    ""
    ""
)
$summary | Add-Content "ad_audit_report.txt"

# inactive users (>30 days)
$inactiveUsers = $data.users | Where-Object {
    (New-TimeSpan -Start ([datetime]$_.lastLogon) -End (Get-Date)).Days -gt 30
}
$inactiveBlock = @(
    "INACTIVE USERS (No login >30 days)"
    ("-" * 35)
    ("{0,-19} {1,-23} {2,-18} {3,-24} {4,-22}" -f "Username", "Name", "Department", "Last Login", "Days Inactive")
)
$inactiveBlock | Add-Content "ad_audit_report.txt"

$inactiveUsers | ForEach-Object {
    "{0,-19} {1,-23} {2,-18} {3,-24} {4,-22}" -f
    $_.samAccountName, $_.displayName, $_.department, $_.lastLogon,
    (New-TimeSpan -Start ([datetime]$_.lastLogon) -End (Get-Date)).Days
} | Add-Content "ad_audit_report.txt"
Add-Content "ad_audit_report.txt" "", ""

# users per department
$deptBlock = @(
    "USERS PER DEPARTMENT"
    ("-" * 20)
)
$deptBlock | Add-Content "ad_audit_report.txt"
$data.users | Group-Object department | ForEach-Object {
    "{0,-15} {1} users" -f $_.Name, $_.Count
} | Add-Content "ad_audit_report.txt"
Add-Content "ad_audit_report.txt" "", ""

# computers per site
$siteBlock = @(
    "COMPUTERS PER SITE"
    ("-" * 19)
)
$siteBlock | Add-Content ".\ad_audit_report.txt"

$data.computers | Group-Object site | ForEach-Object {
    "{0,-20} {1} computers" -f 
    $_.Name,
    $_.Count
} | Add-Content "ad_audit_report.txt"

Add-Content "ad_audit_report.txt" "", ""

# computer status
$compStatus = @(
    "COMPUTER STATUS"
    ("-" * 16)
    ("Total Computers: {0}" -f $totalComputers)
    ("Active (<7 days): {0}" -f $activeComputers)
    ("Stale (7-30 days): {0}" -f $staleComputers)
    ("Inactive (>30 days): {0}" -f $inactiveComputers)
    ""
    ""
)
$compStatus | Add-Content "ad_audit_report.txt"

# computers by OS
$osLines = @(
    "COMPUTERS BY OPERATING SYSTEM"
    ("-" * 30)
)

$osLines += $data.computers | Group-Object operatingSystem | ForEach-Object {
    $percent = [math]::Round(($_.Count / $totalComputers) * 100, 0)
    $line = "{0,-25} {1,-3} ({2}%)" -f
    $_.Name, 
    $_.Count,
    $percent
    if ($_.Name -like "Windows 10*" -or $_.Name -like "Windows Server 2019*") {
        $line += " ⚠ Needs upgrade"
    }
    $line
}

$osLines += ""
$osLines | Add-Content "ad_audit_report.txt"


# inactive users for 30+ days (inactive_users.csv) - function
$inactiveUsers = Get-InactiveAccounts -Days 30
$inactiveUsers | Export-Csv -Path "inactive_users.csv" -NoTypeInformation -Encoding UTF8


# end of report
$footer = @(
    ""
    ("=" * 80)
    ("|                                  END OF REPORT                               |")
    ("=" * 80)
)
$footer | Add-Content "ad_audit_report.txt"


