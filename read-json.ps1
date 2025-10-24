# read JSON ad_export.json
$data = Get-Content -Path "ad_export.json" -Raw -Encoding UTF8 | ConvertFrom-Json

# inactive users (for 30+ days)
$thirtyDaysAgo = (Get-Date).AddDays(-30)
$inactiveUsers = $data.users | Where-Object {
    [datetime]$_.lastLogon -lt $thirtyDaysAgo
}
# inactive_users.csv
$inactiveUsers | Export-Csv -Path "inactive_users.csv" -NoTypeInformation -Encoding UTF8

# count users per department, ad_audit_report.txt
$data.users | Group-Object department | Select-Object Name, Count |
Out-File "ad_audit_report.txt" -Encoding UTF8