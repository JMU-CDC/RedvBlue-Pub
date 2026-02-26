Import-Module GroupPolicy
Import-Module ActiveDirectory

$GPOName = "Default Domain Policy"
$Domain = (Get-ADDomain).DistinguishedName
$NetBIOSName = (Get-ADDomain).NetBIOSName

Write-Host "[*] Initializing Tactical Lockdown for $NetBIOSName..." -ForegroundColor Cyan

# 1. ENHANCED REGISTRY HARDENING
$RegistrySettings = @(
    # Security Basics
    @{ KeyPath = "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; ValueName = "RestrictNullSessAccess"; ValueType = "DWord"; ValueData = 1 },
    @{ KeyPath = "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"; ValueName = "EnableFirewall"; ValueType = "DWord"; ValueData = 1 },
    
    # Anti-Red Team / Anti-Mimikatz
    @{ KeyPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"; ValueName = "LimitBlankPasswordUse"; ValueType = "DWord"; ValueData = 1 },
    @{ KeyPath = "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"; ValueName = "UseLogonCredential"; ValueType = "DWord"; ValueData = 0 }, # Kills clear-text in memory
    
    # Disable LLMNR (Stops Responder)
    @{ KeyPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; ValueName = "EnableMulticast"; ValueType = "DWord"; ValueData = 0 },
    
    # Enable Command Line Auditing (See what they type!)
    @{ KeyPath = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"; ValueName = "ProcessCreationIncludeCmdLine_Output"; ValueType = "DWord"; ValueData = 1 }
)

foreach ($Setting in $RegistrySettings) {
    Set-GPRegistryValue -Name $GPOName -Key $Setting.KeyPath -ValueName $Setting.ValueName -Type $Setting.ValueType -Value $Setting.ValueData
}

# 2. LOGICAL PASSWORD POLICY (Competition Optimized)
# Warning: Ensure your scoring engine can handle these lengths!
$PolicyParams = @{
    Identity = $Domain
    MinPasswordLength = 20           # 20 is usually the "sweet spot" for security vs. scoring stability
    PasswordHistoryCount = 24        # FIXED: Prevents immediate reuse of old passwords
    ComplexityEnabled = $true
    LockoutDuration = "00:30:00"     # 30 mins
    LockoutObservationWindow = 30
    LockoutThreshold = 5             # Lock them out after 5 failed tries
    MaxPasswordAge = "7.00:00:00"
    MinPasswordAge = "1.00:00:00"    # Prevents "rapid-cycling" passwords to clear history
}
Set-ADDefaultDomainPasswordPolicy @PolicyParams

# 3. ADVANCED AUDITING (Success & Failure)
$AuditCategories = @("Account Logon", "Account Management", "Logon Events", "Policy Change", "Privilege Use", "System Events")
foreach ($Category in $AuditCategories) {
    Set-GPAuditPolicy -Name $GPOName -AuditCategory $Category -Success $true -Failure $true
}

# 4. RESTRICTIVE USER RIGHTS
# Scopes RDP strictly to Admins and stops guests from network access
$UserRights = @{
    "SeNetworkLogonRight"    = @("Administrators", "Authenticated Users")
    "SeRemoteInteractiveLogonRight" = @("Administrators") 
    "SeDebugPrivilege"       = @("Administrators") # Prevents non-admins from dumping memory
}

foreach ($Right in $UserRights.Keys) {
    Set-GPUserRight -Name $GPOName -PolicyName $Right -Users $UserRights[$Right]
}

# 5. EXECUTE & REPORT
Invoke-GPUpdate -Force -RandomDelayInMinutes 0
Write-Host "[!] Lockdown Complete. GPO pushed to all domain assets." -ForegroundColor Green
