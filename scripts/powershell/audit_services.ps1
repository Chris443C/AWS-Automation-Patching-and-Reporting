# AWS Automation Patching and Reporting - System Audit Script
# This script audits running services, patch levels, and installed software

param(
    [string]$OutputPath = "C:\temp\audit-report.json",
    [string]$S3Bucket = "",
    [string]$S3Key = "",
    [switch]$UploadToS3 = $false
)

# Set error action preference
$ErrorActionPreference = "Continue"

# Function to get timestamp
function Get-Timestamp {
    return Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}

# Function to get system information
function Get-SystemInfo {
    try {
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
        $operatingSystem = Get-WmiObject -Class Win32_OperatingSystem
        
        return @{
            ComputerName = $computerSystem.Name
            Manufacturer = $computerSystem.Manufacturer
            Model = $computerSystem.Model
            TotalPhysicalMemory = [math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)
            OSName = $operatingSystem.Caption
            OSVersion = $operatingSystem.Version
            OSArchitecture = $operatingSystem.OSArchitecture
            LastBootTime = $operatingSystem.LastBootUpTime
            TimeZone = (Get-TimeZone).DisplayName
        }
    }
    catch {
        Write-Error "Error getting system information: $_"
        return @{}
    }
}

# Function to get running services
function Get-RunningServices {
    try {
        $services = Get-Service | Where-Object { $_.Status -eq "Running" } | Select-Object @(
            'Name',
            'DisplayName',
            'Status',
            'StartType',
            'ServiceType'
        )
        
        $serviceList = @()
        foreach ($service in $services) {
            $serviceList += @{
                Name = $service.Name
                DisplayName = $service.DisplayName
                Status = $service.Status
                StartType = $service.StartType
                ServiceType = $service.ServiceType
            }
        }
        
        return $serviceList
    }
    catch {
        Write-Error "Error getting running services: $_"
        return @()
    }
}

# Function to get installed updates
function Get-InstalledUpdates {
    try {
        $updates = Get-HotFix | Select-Object @(
            'HotFixID',
            'Description',
            'InstalledOn',
            'InstalledBy'
        )
        
        $updateList = @()
        foreach ($update in $updates) {
            $updateList += @{
                HotFixID = $update.HotFixID
                Description = $update.Description
                InstalledOn = $update.InstalledOn.ToString("yyyy-MM-dd HH:mm:ss")
                InstalledBy = $update.InstalledBy
            }
        }
        
        return $updateList
    }
    catch {
        Write-Error "Error getting installed updates: $_"
        return @()
    }
}

# Function to get installed software
function Get-InstalledSoftware {
    try {
        $software = Get-WmiObject -Class Win32_Product | Select-Object @(
            'Name',
            'Version',
            'Vendor',
            'InstallDate',
            'InstallLocation'
        )
        
        $softwareList = @()
        foreach ($app in $software) {
            $softwareList += @{
                Name = $app.Name
                Version = $app.Version
                Vendor = $app.Vendor
                InstallDate = if ($app.InstallDate) { $app.InstallDate.ToString("yyyy-MM-dd HH:mm:ss") } else { $null }
                InstallLocation = $app.InstallLocation
            }
        }
        
        return $softwareList
    }
    catch {
        Write-Error "Error getting installed software: $_"
        return @()
    }
}

# Function to get disk information
function Get-DiskInfo {
    try {
        $disks = Get-WmiObject -Class Win32_LogicalDisk | Select-Object @(
            'DeviceID',
            'Size',
            'FreeSpace',
            'FileSystem',
            'VolumeName'
        )
        
        $diskList = @()
        foreach ($disk in $disks) {
            $diskList += @{
                DeviceID = $disk.DeviceID
                SizeGB = [math]::Round($disk.Size / 1GB, 2)
                FreeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 2)
                UsedSpaceGB = [math]::Round(($disk.Size - $disk.FreeSpace) / 1GB, 2)
                UsagePercentage = [math]::Round((($disk.Size - $disk.FreeSpace) / $disk.Size) * 100, 2)
                FileSystem = $disk.FileSystem
                VolumeName = $disk.VolumeName
            }
        }
        
        return $diskList
    }
    catch {
        Write-Error "Error getting disk information: $_"
        return @()
    }
}

# Function to get network information
function Get-NetworkInfo {
    try {
        $networkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object @(
            'Name',
            'InterfaceDescription',
            'Status',
            'LinkSpeed'
        )
        
        $networkList = @()
        foreach ($adapter in $networkAdapters) {
            $networkList += @{
                Name = $adapter.Name
                InterfaceDescription = $adapter.InterfaceDescription
                Status = $adapter.Status
                LinkSpeed = $adapter.LinkSpeed
            }
        }
        
        return $networkList
    }
    catch {
        Write-Error "Error getting network information: $_"
        return @()
    }
}

# Function to get security information
function Get-SecurityInfo {
    try {
        $securityInfo = @{
            WindowsDefender = $null
            FirewallStatus = $null
            UACStatus = $null
            BitLockerStatus = $null
        }
        
        # Check Windows Defender status
        try {
            $defender = Get-MpComputerStatus
            $securityInfo.WindowsDefender = @{
                AntivirusEnabled = $defender.AntivirusEnabled
                RealTimeProtectionEnabled = $defender.RealTimeProtectionEnabled
                BehaviorMonitorEnabled = $defender.BehaviorMonitorEnabled
                OnAccessProtectionEnabled = $defender.OnAccessProtectionEnabled
                LastQuickScan = $defender.QuickScanSignatureLastUpdated
                LastFullScan = $defender.FullScanSignatureLastUpdated
            }
        }
        catch {
            Write-Warning "Windows Defender information not available"
        }
        
        # Check Firewall status
        try {
            $firewall = Get-NetFirewallProfile
            $securityInfo.FirewallStatus = @{
                Domain = $firewall[0].Enabled
                Private = $firewall[1].Enabled
                Public = $firewall[2].Enabled
            }
        }
        catch {
            Write-Warning "Firewall information not available"
        }
        
        # Check UAC status
        try {
            $uac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
            $securityInfo.UACStatus = if ($uac.EnableLUA -eq 1) { $true } else { $false }
        }
        catch {
            Write-Warning "UAC information not available"
        }
        
        # Check BitLocker status
        try {
            $bitlocker = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
            $securityInfo.BitLockerStatus = @{
                ProtectionStatus = $bitlocker.VolumeStatus
                EncryptionPercentage = $bitlocker.EncryptionPercentage
            }
        }
        catch {
            Write-Warning "BitLocker information not available"
        }
        
        return $securityInfo
    }
    catch {
        Write-Error "Error getting security information: $_"
        return @{}
    }
}

# Function to upload to S3
function Upload-ToS3 {
    param(
        [string]$FilePath,
        [string]$Bucket,
        [string]$Key
    )
    
    try {
        # Check if AWS CLI is available
        $awsCli = Get-Command aws -ErrorAction SilentlyContinue
        if (-not $awsCli) {
            Write-Error "AWS CLI is not installed or not in PATH"
            return $false
        }
        
        # Upload file to S3
        $result = aws s3 cp $FilePath "s3://$Bucket/$Key" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Successfully uploaded to s3://$Bucket/$Key"
            return $true
        }
        else {
            Write-Error "Failed to upload to S3: $result"
            return $false
        }
    }
    catch {
        Write-Error "Error uploading to S3: $_"
        return $false
    }
}

# Main execution
Write-Host "Starting system audit at $(Get-Timestamp)" -ForegroundColor Green

# Create output directory if it doesn't exist
$outputDir = Split-Path -Parent $OutputPath
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

# Collect audit data
$auditData = @{
    Timestamp = Get-Timestamp
    SystemInfo = Get-SystemInfo
    RunningServices = Get-RunningServices
    InstalledUpdates = Get-InstalledUpdates
    InstalledSoftware = Get-InstalledSoftware
    DiskInfo = Get-DiskInfo
    NetworkInfo = Get-NetworkInfo
    SecurityInfo = Get-SecurityInfo
}

# Convert to JSON and save to file
try {
    $jsonData = $auditData | ConvertTo-Json -Depth 10
    $jsonData | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "Audit report saved to: $OutputPath" -ForegroundColor Green
    
    # Display summary
    Write-Host "`nAudit Summary:" -ForegroundColor Yellow
    Write-Host "  - Running Services: $($auditData.RunningServices.Count)"
    Write-Host "  - Installed Updates: $($auditData.InstalledUpdates.Count)"
    Write-Host "  - Installed Software: $($auditData.InstalledSoftware.Count)"
    Write-Host "  - Disk Volumes: $($auditData.DiskInfo.Count)"
    Write-Host "  - Network Adapters: $($auditData.NetworkInfo.Count)"
    
    # Upload to S3 if requested
    if ($UploadToS3 -and $S3Bucket -and $S3Key) {
        Write-Host "`nUploading to S3..." -ForegroundColor Yellow
        $uploadSuccess = Upload-ToS3 -FilePath $OutputPath -Bucket $S3Bucket -Key $S3Key
        if ($uploadSuccess) {
            Write-Host "Upload completed successfully" -ForegroundColor Green
        }
        else {
            Write-Host "Upload failed" -ForegroundColor Red
        }
    }
}
catch {
    Write-Error "Error saving audit report: $_"
    exit 1
}

Write-Host "`nSystem audit completed at $(Get-Timestamp)" -ForegroundColor Green 