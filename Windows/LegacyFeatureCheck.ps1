<# 
  Audit-LegacyWindows.ps1
  Purpose: PASSIVE identification of legacy/high-risk features.
  Action: READ-ONLY. No changes will be made to the system.
#>

[CmdletBinding()]
param(
    [string]$OutDir = "C:\Reports"
)

# UI Helpers for the console
function Write-Audit($msg) { Write-Host "[?] SCANNING: $msg" -ForegroundColor Cyan }
function Write-Found($msg) { Write-Host "[!] VULNERABLE: $msg" -ForegroundColor Red }
function Write-Safe($msg)  { Write-Host "[+] SECURE: $msg" -ForegroundColor Green }

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

$AuditData = [ordered]@{
    Hostname  = $env:COMPUTERNAME
    Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
}

# SMBv1
Write-Audit "Checking SMBv1 Feature State..."
$smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
$AuditData.SMBv1_Enabled = ($smb1.State -eq 'Enabled')
if ($AuditData.SMBv1_Enabled) { Write-Found "SMBv1 is ENABLED" } else { Write-Safe "SMBv1 is Disabled" }

# LLMNR
Write-Audit "Checking LLMNR Registry Policy..."
$llmnrPath = 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient'
$llmnrVal = (Get-ItemProperty $llmnrPath -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast
# In Windows, if the key is missing or not 0, it's effectively enabled.
$AuditData.LLMNR_Enabled = ($llmnrVal -ne 0) 
if ($AuditData.LLMNR_Enabled) { Write-Found "LLMNR is ENABLED (Responder Target)" } else { Write-Safe "LLMNR is Disabled" }

# NTLMv1
Write-Audit "Checking LSA Compatibility Level..."
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$ntlmVal = (Get-ItemProperty $lsaPath -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue).LmCompatibilityLevel
# Level 5 is the modern secure standard (NTLMv2 only). Anything less is a risk.
$AuditData.NTLMv1_Allowed = ($null -eq $ntlmVal -or $ntlmVal -lt 5)
if ($AuditData.NTLMv1_Allowed) { Write-Found "NTLMv1 potentially allowed (Level: $ntlmVal)" } else { Write-Safe "NTLMv2 Enforced" }

# NetBIOS over TCP/IP
Write-Audit "Scanning NICs for NetBIOS..."
$netbiosEnabled = $false
$nics = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
foreach ($nic in $nics) {
    if ($nic.TcpipNetbiosOptions -ne 2) { $netbiosEnabled = $true }
}
$AuditData.NetBIOS_Enabled = $netbiosEnabled
if ($AuditData.NetBIOS_Enabled) { Write-Found "NetBIOS active on one or more interfaces" } else { Write-Safe "NetBIOS Disabled" }

# MSDT
Write-Audit "Checking MSDT Protocol Handler..."
$AuditData.MSDT_Present = Test-Path 'HKCR:\ms-msdt'
if ($AuditData.MSDT_Present) { Write-Found "MSDT Protocol Handler is active" } else { Write-Safe "MSDT Handler Not Found" }

# Finalize
$row = [PSCustomObject]$AuditData
$reportFile = Join-Path $OutDir "Audit-$($env:COMPUTERNAME).csv"
$row | Export-Csv -Path $reportFile -NoTypeInformation -Append

Write-Host "`n[*] Audit Complete. Data saved to $reportFile" -ForegroundColor Gray
