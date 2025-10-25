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
    "⚠ SECURITY: $staleComputerCountEnabled inactive computers (>30 days) [+${staleComputerCountDisabled} disabled] and $oldOSCountEnabled computers on older OS [+${oldOSCountDisabled} disabled]" 
    "✓ STATUS: $modernPercent% of computers are running windows 11 23H2, domain controllers on Windows Server 2022 "
    ""
    ""
)
$summary | Add-Content "ad_audit_report.txt"

# user account status
$totalUsers = $data.users.Count
$activeUsers = ($data.users | Where-Object { $_.enabled -eq $true }).Count
$disabledUsers = ($data.users | Where-Object { $_.enabled -eq $false }).Count
$userStatus = @(
    "USER ACCOUNT STATUS"
    ("-" * 19)
    "Total Users: $totalUsers"
    "Active Users: $activeUsers ({0:P0})" -f ($activeUsers / $totalUsers)
    "Disabled Accounts: $disabledUsers"
    ""
    ""
)
$userStatus | Add-Content "ad_audit_report.txt"

# inactive users (>30 days)
$inactiveUsers = $data.users | Where-Object {
    (New-TimeSpan -Start ([datetime]$_.lastLogon) -End (Get-Date)).Days -gt 30
}
Add-Content "ad_audit_report.txt" "INACTIVE USERS (No login >30 days)"
Add-Content "ad_audit_report.txt" ("-" * 30)

$headerLine = "{0,-19} {1,-23} {2,-18} {3,-24} {4,-22}" -f `
    "Username", "Name", "Department", "Last Login", "Days Inactive"
Add-Content "ad_audit_report.txt" $headerLine
Add-Content "ad_audit_report.txt" ""

$inactiveUsers | ForEach-Object {
    "{0,-19} {1,-23} {2,-18} {3,-24} {4,-22}" -f `
        $_.samAccountName, 
    $_.displayName,
    $_.department,
    $_.lastLogon,
    (New-TimeSpan -Start ([datetime]$_.lastLogon) -End (Get-Date)).Days
} | Add-Content "ad_audit_report.txt"
    
Add-Content "ad_audit_report.txt" ""

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

$staleComputersEnabled = $data.computers | Where-Object {
    $_.enabled -eq $true -and
    (New-TimeSpan -Start ([datetime]$_.lastLogon) -End (Get-Date)).Days -gt 30
}
$staleComputersDisabled = $data.computers | Where-Object {
    $_.enabled -eq $false -and
    (New-TimeSpan -Start ([datetime]$_.lastLogon) -End (Get-Date)).Days -gt 30
}
$staleComputerCountEnabled = $staleComputersEnabled.Count
$staleComputerCountDisabled = $staleComputersDisabled.Count

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
$totalClients = $data.computers.Count
$modernPercent = [math]::Round(($modernClientCount / $totalClients) * 100, 1)

# inactive users for 30+ days (inactive_users.csv) - function
$inactiveUsers = Get-InactiveAccounts -Days 30
$inactiveUsers | Export-Csv -Path "inactive_users.csv" -NoTypeInformation -Encoding UTF8

# count users per department (ad_audit_report.txt)
$data.users | Group-Object department | Select-Object Name, Count |
Out-File "ad_audit_report.txt" -Append -Encoding UTF8


Add-Content "ad_audit_report.txt" ""
Add-Content "ad_audit_report.txt" ("=" * 80)
Add-Content "ad_audit_report.txt" ("|                                  END OF REPORT                               |")
Add-Content "ad_audit_report.txt" ("=" * 80)