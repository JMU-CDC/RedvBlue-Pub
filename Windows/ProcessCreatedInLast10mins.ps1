param (
    [int]$MinutesAgo = 10
)

$cutoffTime = (Get-Date).AddMinutes(-$MinutesAgo)

Write-Host "--- Processes started since $($cutoffTime.ToString('HH:mm:ss')) ---" -ForegroundColor Cyan

Get-Process | ForEach-Object {
    try {
        if ($_.StartTime -gt $cutoffTime) {
            # Use a Custom Object for a clean table view
            [PSCustomObject]@{
                StartTime = $_.StartTime.ToString('HH:mm:ss')
                PID       = $_.Id
                Name      = $_.ProcessName
                Path      = $_.MainModule.FileName # Shows exactly where the file is on disk
            }
        }
    } catch {
        # Skip system/protected processes
    }
} | Sort-Object StartTime | Format-Table -AutoSize
