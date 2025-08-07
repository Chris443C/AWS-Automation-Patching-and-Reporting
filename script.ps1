# AWS System Audit Script
# Collects running services, patch levels, and installed software

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

Write-Output "===== System Audit Started at $(Get-Date) ====="

# Running Services
Write-Output "`n===== Running Services ====="
Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, DisplayName, Status

# Installed Updates (Patch Level)
Write-Output "`n===== Installed Updates ====="
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object HotFixID, Description, InstalledOn

# Installed Software
Write-Output "`n===== Installed Software ====="
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Select-Object DisplayName, DisplayVersion, Publisher |
  Where-Object { $_.DisplayName -ne $null } |
  Sort-Object DisplayName

Write-Output "`n===== System Audit Completed ====="