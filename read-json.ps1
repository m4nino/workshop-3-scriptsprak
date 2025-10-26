# function

function Try-ParseDate {
    param ([string]$dateString)
    try {
        if ([string]::IsNullOrWhiteSpace($dateString)) {
            return $null
        }
        return [datetime]$dateString
    }
    catch {
        Write-Verbose "Invalid date found: $dateString"
        return $null
    }
}

function Get-InactiveAccounts {
    param([int]$Days = 30)

    $data = Get-Content -Path "ad_export.json" -Raw -Encoding UTF8 | ConvertFrom-Json
    $cutoff = (Get-Date).AddDays(-$Days)

    $inactiveUsers = $data.users | Where-Object {
        $lastLogon = Try-ParseDate $_.lastLogon
        $lastLogon -and $lastLogon -lt $cutoff
    } | Select-Object samAccountName, displayName, department, lastLogon,
    @{Name = "DaysInactive"; Expression = {
            $ll = Try-ParseDate $_.lastLogon
            if ($ll) { (New-TimeSpan -Start $ll -End (Get-Date)).Days } else { $null }
        }
    }

    return $inactiveUsers
}

# --- main script ---#

# read JSON ad_export.json
$data = Get-Content -Path "ad_export.json" -Raw -Encoding UTF8 | ConvertFrom-Json

# pre-calc all metrics before report

$expiringAccounts = $data.users | Where-Object {
    $expDate = Try-ParseDate $_.accountExpires
    $expDate -and $expDate -lt (Get-Date).AddDays(30) -and $_.enabled -eq $true
}
$expiringCount = $expiringAccounts.Count

$oldPasswordsEnabled = $data.users | Where-Object {
    $_.enabled -eq $true -and (
        ($_.passwordNeverExpires -eq $true) -or
        ((New-TimeSpan -Start (Try-ParseDate $_.passwordLastSet) -End (Get-Date)).Days -gt 90)
    )
}
$oldPasswordsDisabled = $data.users | Where-Object {
    $_.enabled -eq $false -and (
        $_.passwordNeverExpires -eq $true -or
        ((New-TimeSpan -Start (Try-ParseDate $_.passwordLastSet) -End (Get-Date)).Days -gt 90)    
    )
}
$oldPwdCountEnabled = $oldPasswordsEnabled.Count
$oldPwdCountDisabled = $oldPasswordsDisabled.Count

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
    "⚠ SECURITY: $inactiveComputers inactive computers (>30 days)"
    "⚠ WARNING: $oldPwdCountEnabled user accounts with passwords older than 90 days [+$oldPwdCountDisabled disabled]"
    ""
    ""
)
$summary | Add-Content "ad_audit_report.txt"

# inactive users (no login >30 days)
$inactiveUsers = $data.users | Where-Object {
    $ll = Try-ParseDate $_.lastLogon
    $ll -and (New-TimeSpan -Start $ll -End (Get-Date)).Days -gt 30
}
$inactiveBlock = @(
    "INACTIVE USERS (No login >30 days)"
    ("-" * 35)
    ("{0,-19} {1,-23} {2,-18} {3,-24} {4,-22}" -f "Username", "Name", "Department", "Last Login", "Days Inactive")
    ""
)
$inactiveBlock | Add-Content "ad_audit_report.txt"

$inactiveUsers | ForEach-Object {
    $ll = Try-ParseDate $_.lastLogon
    $daysInactive = if ($ll) {
        (New-TimeSpan -Start $ll -End (Get-Date)).Days 
    }
    else { 
        "N/A" 
    }
    "{0,-19} {1,-23} {2,-18} {3,-24} {4,-22}" -f `
        $_.samAccountName, $_.displayName, $_.department, $_.lastLogon, $daysInactive
} | Add-Content "ad_audit_report.txt"
Add-Content "ad_audit_report.txt" "", ""

# top 10 inactive computers (longest since last logon)
$oldestBlock = @(
    "TOP 10 INACTIVE COMPUTERS (Longest since last logon)"
    ("-" * 55)
    ("{0,-20} {1,-25} {2,-22}" -f "ComputerName", "OperatingSystem", "Last Logon")   
    ""
)
$oldestBlock | Add-Content "ad_audit_report.txt"

$data.computers |
Sort-Object { Try-ParseDate $_.lastLogon } |
Select-Object -First 10 Name, operatingSystem, lastLogon |
ForEach-Object {
    "{0,-20} {1,-25} {2,-22}" -f $_.Name, $_.operatingSystem, $_.lastLogon
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

# computer status (computer_status.csv)
$data.computers |
Group-Object site | ForEach-Object {
    [PSCustomObject]@{
        Site               = $_.Name
        TotalComputers     = $_.Count
        ActiveComputers    = ($_.Group | Where-Object { $ll = Try-ParseDate $_.lastLogon; $ll -and (New-TimeSpan -Start $ll -End (Get-Date)).Days -le 30 }).Count
        InactiveComputers  = ($_.Group | Where-Object { $ll = Try-ParseDate $_.lastLogon; $ll -and (New-TimeSpan -Start $ll -End (Get-Date)).Days -gt 30 }).Count
        Windows10Count     = ($_.Group | Where-Object { $_.OperatingSystem -like "Windows 10*" }).Count
        Windows11Count     = ($_.Group | Where-Object { $_.OperatingSystem -like "Windows 11*" }).Count
        WindowsServerCount = ($_.Group | Where-Object { $_.OperatingSystem -like "Windows Server*" }).Count
    }
} | Export-Csv -Path "computer_status.csv" -NoTypeInformation -Encoding UTF8

# end of report
$footer = @(
    ""
    ("=" * 80)
    ("|                                  END OF REPORT                               |")
    ("=" * 80)
)
$footer | Add-Content "ad_audit_report.txt"


