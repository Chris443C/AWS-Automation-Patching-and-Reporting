# AWS Automation Patching and Reporting - Compliance Audit Script
# This script extends the existing audit capabilities with CIS and PCI compliance checks

param(
    [string]$OutputPath = "C:\temp\compliance-audit-report.json",
    [string]$S3Bucket = "",
    [string]$S3Key = "",
    [switch]$UploadToS3 = $false,
    [switch]$IncludeCISChecks = $true,
    [switch]$IncludePCIChecks = $true,
    [switch]$IncludeSecurityHubIntegration = $true
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

# Function to check CIS compliance controls
function Get-CISComplianceChecks {
    param([switch]$Detailed = $false)
    
    $cisChecks = @{
        timestamp = Get-Timestamp
        checks = @()
        summary = @{
            total_checks = 0
            passed_checks = 0
            failed_checks = 0
            compliance_score = 0
        }
    }
    
    try {
        # CIS Control 1.1 - Avoid the use of the "root" account
        $cisChecks.checks += @{
            control_id = "1.1"
            control_name = "Avoid the use of the 'root' account"
            description = "Check if root account is being used"
            status = "INFO"
            details = "This check should be performed at the AWS account level, not on individual instances"
            recommendation = "Ensure root account is not used for daily operations"
        }
        
        # CIS Control 1.2 - MFA for IAM users
        $cisChecks.checks += @{
            control_id = "1.2"
            control_name = "Multi-factor authentication (MFA) for IAM users"
            description = "Check if MFA is enabled for IAM users"
            status = "INFO"
            details = "This check should be performed at the AWS account level"
            recommendation = "Enable MFA for all IAM users"
        }
        
        # CIS Control 2.1 - CloudTrail enabled
        $cisChecks.checks += @{
            control_id = "2.1"
            control_name = "CloudTrail enabled in all regions"
            description = "Check if CloudTrail is enabled"
            status = "INFO"
            details = "This check should be performed at the AWS account level"
            recommendation = "Enable CloudTrail in all regions"
        }
        
        # CIS Control 2.5 - AWS Config enabled
        $cisChecks.checks += @{
            control_id = "2.5"
            control_name = "AWS Config enabled in all regions"
            description = "Check if AWS Config is enabled"
            status = "INFO"
            details = "This check should be performed at the AWS account level"
            recommendation = "Enable AWS Config in all regions"
        }
        
        # Local system checks
        # CIS Control 3.1 - Ensure a log profile exists
        $logProfile = Get-WmiObject -Class Win32_NTEventlogFile -ErrorAction SilentlyContinue
        if ($logProfile) {
            $cisChecks.checks += @{
                control_id = "3.1"
                control_name = "Log profile exists"
                description = "Check if Windows event logging is configured"
                status = "PASS"
                details = "Windows event logging is available"
                recommendation = "Ensure appropriate log levels are configured"
            }
        } else {
            $cisChecks.checks += @{
                control_id = "3.1"
                control_name = "Log profile exists"
                description = "Check if Windows event logging is configured"
                status = "FAIL"
                details = "Windows event logging not available"
                recommendation = "Configure Windows event logging"
            }
        }
        
        # CIS Control 3.2 - Ensure password policy is configured
        $passwordPolicy = net accounts
        if ($passwordPolicy -match "Minimum password length") {
            $cisChecks.checks += @{
                control_id = "3.2"
                control_name = "Password policy configured"
                description = "Check if password policy is configured"
                status = "PASS"
                details = "Password policy is configured"
                recommendation = "Review password policy settings"
            }
        } else {
            $cisChecks.checks += @{
                control_id = "3.2"
                control_name = "Password policy configured"
                description = "Check if password policy is configured"
                status = "FAIL"
                details = "Password policy not configured"
                recommendation = "Configure password policy"
            }
        }
        
        # CIS Control 3.3 - Ensure account lockout policy is configured
        $lockoutPolicy = net accounts
        if ($lockoutPolicy -match "Lockout threshold") {
            $cisChecks.checks += @{
                control_id = "3.3"
                control_name = "Account lockout policy configured"
                description = "Check if account lockout policy is configured"
                status = "PASS"
                details = "Account lockout policy is configured"
                recommendation = "Review lockout policy settings"
            }
        } else {
            $cisChecks.checks += @{
                control_id = "3.3"
                control_name = "Account lockout policy configured"
                description = "Check if account lockout policy is configured"
                status = "FAIL"
                details = "Account lockout policy not configured"
                recommendation = "Configure account lockout policy"
            }
        }
        
        # Calculate summary
        $cisChecks.summary.total_checks = $cisChecks.checks.Count
        $cisChecks.summary.passed_checks = ($cisChecks.checks | Where-Object { $_.status -eq "PASS" }).Count
        $cisChecks.summary.failed_checks = ($cisChecks.checks | Where-Object { $_.status -eq "FAIL" }).Count
        $cisChecks.summary.compliance_score = [math]::Round(($cisChecks.summary.passed_checks / $cisChecks.summary.total_checks) * 100, 2)
        
        return $cisChecks
    }
    catch {
        Write-Error "Error performing CIS compliance checks: $_"
        return @{
            timestamp = Get-Timestamp
            checks = @()
            summary = @{
                total_checks = 0
                passed_checks = 0
                failed_checks = 0
                compliance_score = 0
            }
            error = $_.Exception.Message
        }
    }
}

# Function to check PCI DSS compliance
function Get-PCIDSSComplianceChecks {
    param([switch]$Detailed = $false)
    
    $pciChecks = @{
        timestamp = Get-Timestamp
        checks = @()
        summary = @{
            total_checks = 0
            passed_checks = 0
            failed_checks = 0
            compliance_score = 0
        }
    }
    
    try {
        # PCI Requirement 1.1 - Firewall and router configuration standards
        $pciChecks.checks += @{
            requirement_id = "1.1"
            requirement_name = "Firewall and router configuration standards"
            description = "Check if firewall is configured"
            status = "INFO"
            details = "This check should be performed at the network level"
            recommendation = "Ensure firewall rules are properly configured"
        }
        
        # PCI Requirement 2.1 - Change vendor-supplied defaults
        $defaultAccounts = Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Name -eq "Administrator" }
        if ($defaultAccounts) {
            $pciChecks.checks += @{
                requirement_id = "2.1"
                requirement_name = "Change vendor-supplied defaults"
                description = "Check if default accounts are secured"
                status = "WARN"
                details = "Default Administrator account exists"
                recommendation = "Rename or disable default Administrator account"
            }
        } else {
            $pciChecks.checks += @{
                requirement_id = "2.1"
                requirement_name = "Change vendor-supplied defaults"
                description = "Check if default accounts are secured"
                status = "PASS"
                details = "Default Administrator account not found or renamed"
                recommendation = "Continue monitoring default accounts"
            }
        }
        
        # PCI Requirement 5.1 - Anti-virus software
        $antivirus = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue
        if ($antivirus) {
            $pciChecks.checks += @{
                requirement_id = "5.1"
                requirement_name = "Anti-virus software deployed"
                description = "Check if anti-virus software is installed"
                status = "PASS"
                details = "Anti-virus software detected: $($antivirus.displayName)"
                recommendation = "Ensure anti-virus is up to date"
            }
        } else {
            $pciChecks.checks += @{
                requirement_id = "5.1"
                requirement_name = "Anti-virus software deployed"
                description = "Check if anti-virus software is installed"
                status = "FAIL"
                details = "No anti-virus software detected"
                recommendation = "Install and configure anti-virus software"
            }
        }
        
        # PCI Requirement 6.1 - Identify security vulnerabilities
        $pciChecks.checks += @{
            requirement_id = "6.1"
            requirement_name = "Identify security vulnerabilities"
            description = "Check if vulnerability scanning is performed"
            status = "INFO"
            details = "This check should be performed at the organizational level"
            recommendation = "Implement regular vulnerability scanning"
        }
        
        # PCI Requirement 7.1 - Limit access to system components
        $localUsers = Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.LocalAccount -eq $true }
        if ($localUsers.Count -le 5) {
            $pciChecks.checks += @{
                requirement_id = "7.1"
                requirement_name = "Limit access to system components"
                description = "Check if access is limited to necessary users"
                status = "PASS"
                details = "Limited number of local users: $($localUsers.Count)"
                recommendation = "Continue monitoring user access"
            }
        } else {
            $pciChecks.checks += @{
                requirement_id = "7.1"
                requirement_name = "Limit access to system components"
                description = "Check if access is limited to necessary users"
                status = "WARN"
                details = "Multiple local users found: $($localUsers.Count)"
                recommendation = "Review and remove unnecessary user accounts"
            }
        }
        
        # PCI Requirement 8.1 - User identification
        $pciChecks.checks += @{
            requirement_id = "8.1"
            requirement_name = "User identification"
            description = "Check if unique user IDs are assigned"
            status = "INFO"
            details = "This check should be performed at the organizational level"
            recommendation = "Ensure unique user IDs are assigned"
        }
        
        # PCI Requirement 10.1 - Audit trails
        $eventLogs = Get-WmiObject -Class Win32_NTEventlogFile
        if ($eventLogs) {
            $pciChecks.checks += @{
                requirement_id = "10.1"
                requirement_name = "Audit trails"
                description = "Check if audit trails are implemented"
                status = "PASS"
                details = "Windows event logs are available"
                recommendation = "Ensure appropriate audit policies are configured"
            }
        } else {
            $pciChecks.checks += @{
                requirement_id = "10.1"
                requirement_name = "Audit trails"
                description = "Check if audit trails are implemented"
                status = "FAIL"
                details = "Windows event logs not available"
                recommendation = "Configure Windows event logging"
            }
        }
        
        # PCI Requirement 11.1 - Test for wireless access points
        $pciChecks.checks += @{
            requirement_id = "11.1"
            requirement_name = "Test for wireless access points"
            description = "Check for wireless access points"
            status = "INFO"
            details = "This check should be performed at the network level"
            recommendation = "Regularly scan for unauthorized wireless access points"
        }
        
        # Calculate summary
        $pciChecks.summary.total_checks = $pciChecks.checks.Count
        $pciChecks.summary.passed_checks = ($pciChecks.checks | Where-Object { $_.status -eq "PASS" }).Count
        $pciChecks.summary.failed_checks = ($pciChecks.checks | Where-Object { $_.status -eq "FAIL" }).Count
        $pciChecks.summary.compliance_score = [math]::Round(($pciChecks.summary.passed_checks / $pciChecks.summary.total_checks) * 100, 2)
        
        return $pciChecks
    }
    catch {
        Write-Error "Error performing PCI DSS compliance checks: $_"
        return @{
            timestamp = Get-Timestamp
            checks = @()
            summary = @{
                total_checks = 0
                passed_checks = 0
                failed_checks = 0
                compliance_score = 0
            }
            error = $_.Exception.Message
        }
    }
}

# Function to get security configuration
function Get-SecurityConfiguration {
    try {
        $securityConfig = @{
            timestamp = Get-Timestamp
            windows_defender = $null
            firewall_status = $null
            uac_status = $null
            bitlocker_status = $null
            encryption_status = $null
        }
        
        # Check Windows Defender status
        try {
            $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
            if ($defender) {
                $securityConfig.windows_defender = @{
                    enabled = $defender.AntivirusEnabled
                    real_time_protection = $defender.RealTimeProtectionEnabled
                    signature_version = $defender.AntivirusSignatureVersion
                    last_scan_time = $defender.QuickScanSignatureVersion
                }
            }
        }
        catch {
            Write-Warning "Could not retrieve Windows Defender status: $_"
        }
        
        # Check Windows Firewall status
        try {
            $firewall = Get-NetFirewallProfile -ErrorAction SilentlyContinue
            if ($firewall) {
                $securityConfig.firewall_status = @{
                    domain_profile = $firewall | Where-Object { $_.Name -eq "Domain" } | Select-Object -ExpandProperty Enabled
                    private_profile = $firewall | Where-Object { $_.Name -eq "Private" } | Select-Object -ExpandProperty Enabled
                    public_profile = $firewall | Where-Object { $_.Name -eq "Public" } | Select-Object -ExpandProperty Enabled
                }
            }
        }
        catch {
            Write-Warning "Could not retrieve Windows Firewall status: $_"
        }
        
        # Check UAC status
        try {
            $uac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
            if ($uac) {
                $securityConfig.uac_status = @{
                    enabled = $uac.EnableLUA -eq 1
                    value = $uac.EnableLUA
                }
            }
        }
        catch {
            Write-Warning "Could not retrieve UAC status: $_"
        }
        
        # Check BitLocker status
        try {
            $bitlocker = Get-BitLockerVolume -ErrorAction SilentlyContinue
            if ($bitlocker) {
                $securityConfig.bitlocker_status = @{
                    system_drive_protected = ($bitlocker | Where-Object { $_.VolumeType -eq "OperatingSystem" }).ProtectionStatus
                    data_drives_protected = ($bitlocker | Where-Object { $_.VolumeType -eq "Data" }).ProtectionStatus
                }
            }
        }
        catch {
            Write-Warning "Could not retrieve BitLocker status: $_"
        }
        
        return $securityConfig
    }
    catch {
        Write-Error "Error getting security configuration: $_"
        return @{
            timestamp = Get-Timestamp
            error = $_.Exception.Message
        }
    }
}

# Function to upload report to S3
function Upload-ReportToS3 {
    param(
        [string]$FilePath,
        [string]$S3Bucket,
        [string]$S3Key
    )
    
    try {
        if (-not (Get-Command "aws" -ErrorAction SilentlyContinue)) {
            Write-Warning "AWS CLI not found. Skipping S3 upload."
            return $false
        }
        
        if ([string]::IsNullOrEmpty($S3Bucket) -or [string]::IsNullOrEmpty($S3Key)) {
            Write-Warning "S3 bucket or key not specified. Skipping S3 upload."
            return $false
        }
        
        $s3Path = "s3://$S3Bucket/$S3Key"
        aws s3 cp $FilePath $s3Path
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Report uploaded successfully to $s3Path"
            return $true
        } else {
            Write-Error "Failed to upload report to S3"
            return $false
        }
    }
    catch {
        Write-Error "Error uploading report to S3: $_"
        return $false
    }
}

# Main execution
try {
    Write-Host "Starting compliance audit..." -ForegroundColor Green
    
    # Initialize report
    $report = @{
        audit_timestamp = Get-Timestamp
        system_info = Get-SystemInfo
        compliance_checks = @{}
        security_configuration = $null
        recommendations = @()
    }
    
    # Perform CIS compliance checks
    if ($IncludeCISChecks) {
        Write-Host "Performing CIS compliance checks..." -ForegroundColor Yellow
        $report.compliance_checks.cis = Get-CISComplianceChecks
    }
    
    # Perform PCI DSS compliance checks
    if ($IncludePCIChecks) {
        Write-Host "Performing PCI DSS compliance checks..." -ForegroundColor Yellow
        $report.compliance_checks.pci = Get-PCIDSSComplianceChecks
    }
    
    # Get security configuration
    Write-Host "Gathering security configuration..." -ForegroundColor Yellow
    $report.security_configuration = Get-SecurityConfiguration
    
    # Generate recommendations
    $recommendations = @()
    
    if ($report.compliance_checks.cis) {
        if ($report.compliance_checks.cis.summary.compliance_score -lt 80) {
            $recommendations += "CIS compliance score is below 80%. Review and remediate failed controls."
        }
    }
    
    if ($report.compliance_checks.pci) {
        if ($report.compliance_checks.pci.summary.compliance_score -lt 80) {
            $recommendations += "PCI DSS compliance score is below 80%. Review and remediate failed requirements."
        }
    }
    
    if (-not $report.security_configuration.windows_defender.enabled) {
        $recommendations += "Windows Defender is not enabled. Enable Windows Defender for endpoint protection."
    }
    
    if (-not $report.security_configuration.firewall_status.domain_profile) {
        $recommendations += "Windows Firewall domain profile is disabled. Enable Windows Firewall for network protection."
    }
    
    if (-not $report.security_configuration.uac_status.enabled) {
        $recommendations += "User Account Control (UAC) is disabled. Enable UAC for additional security."
    }
    
    if ($recommendations.Count -eq 0) {
        $recommendations += "No immediate action required. Continue monitoring compliance status."
    }
    
    $report.recommendations = $recommendations
    
    # Convert to JSON and save
    $reportJson = $report | ConvertTo-Json -Depth 10
    $reportJson | Out-File -FilePath $OutputPath -Encoding UTF8
    
    Write-Host "Compliance audit completed successfully!" -ForegroundColor Green
    Write-Host "Report saved to: $OutputPath" -ForegroundColor Cyan
    
    # Upload to S3 if requested
    if ($UploadToS3) {
        Write-Host "Uploading report to S3..." -ForegroundColor Yellow
        $uploadSuccess = Upload-ReportToS3 -FilePath $OutputPath -S3Bucket $S3Bucket -S3Key $S3Key
        if ($uploadSuccess) {
            Write-Host "Report uploaded to S3 successfully!" -ForegroundColor Green
        }
    }
    
    # Display summary
    Write-Host "`n=== COMPLIANCE AUDIT SUMMARY ===" -ForegroundColor Magenta
    
    if ($report.compliance_checks.cis) {
        Write-Host "CIS Compliance Score: $($report.compliance_checks.cis.summary.compliance_score)%" -ForegroundColor Cyan
        Write-Host "  - Passed: $($report.compliance_checks.cis.summary.passed_checks)" -ForegroundColor Green
        Write-Host "  - Failed: $($report.compliance_checks.cis.summary.failed_checks)" -ForegroundColor Red
    }
    
    if ($report.compliance_checks.pci) {
        Write-Host "PCI DSS Compliance Score: $($report.compliance_checks.pci.summary.compliance_score)%" -ForegroundColor Cyan
        Write-Host "  - Passed: $($report.compliance_checks.pci.summary.passed_checks)" -ForegroundColor Green
        Write-Host "  - Failed: $($report.compliance_checks.pci.summary.failed_checks)" -ForegroundColor Red
    }
    
    Write-Host "`n=== RECOMMENDATIONS ===" -ForegroundColor Magenta
    foreach ($rec in $report.recommendations) {
        Write-Host "- $rec" -ForegroundColor Yellow
    }
    
    exit 0
}
catch {
    Write-Error "Compliance audit failed: $_"
    exit 1
} 