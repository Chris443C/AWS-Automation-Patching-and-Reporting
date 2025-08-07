# AWS Automation Patching and Reporting - Deployment Script
# This script automates the deployment of the patching automation solution

param(
    [Parameter(Mandatory=$true)]
    [string]$Environment,
    
    [Parameter(Mandatory=$true)]
    [string]$NotificationEmail,
    
    [Parameter(Mandatory=$false)]
    [string]$S3BucketName = "aws-patching-automation-reports",
    
    [Parameter(Mandatory=$false)]
    [string]$OperatingSystem = "WINDOWS",
    
    [Parameter(Mandatory=$false)]
    [int]$PatchApprovalDelay = 7,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipInspector = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipPatchManager = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipSecurityHub = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipConfig = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipAuditManager = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$DryRun = $false
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Function to write colored output
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

# Function to check AWS CLI
function Test-AWSCLI {
    try {
        $awsVersion = aws --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "✓ AWS CLI found: $awsVersion" "Green"
            return $true
        }
    }
    catch {
        Write-ColorOutput "✗ AWS CLI not found or not in PATH" "Red"
        return $false
    }
}

# Function to check AWS credentials
function Test-AWSCredentials {
    try {
        $identity = aws sts get-caller-identity 2>&1 | ConvertFrom-Json
        if ($identity) {
            Write-ColorOutput "✓ AWS credentials valid for account: $($identity.Account)" "Green"
            return $true
        }
    }
    catch {
        Write-ColorOutput "✗ AWS credentials not configured or invalid" "Red"
        return $false
    }
}

# Function to deploy CloudFormation stack
function Deploy-CloudFormationStack {
    param(
        [string]$TemplateFile,
        [string]$StackName,
        [hashtable]$Parameters = @{}
    )
    
    Write-ColorOutput "Deploying stack: $StackName" "Yellow"
    
    if ($DryRun) {
        Write-ColorOutput "DRY RUN: Would deploy $StackName with template $TemplateFile" "Cyan"
        return $true
    }
    
    # Validate inputs to prevent injection
    if (-not $TemplateFile -match '^[a-zA-Z0-9\-\\_\./]+\.ya?ml$') {
        Write-ColorOutput "✗ Invalid template file name: $TemplateFile" "Red"
        return $false
    }
    
    if (-not $StackName -match '^[a-zA-Z0-9\-]+$') {
        Write-ColorOutput "✗ Invalid stack name: $StackName" "Red"
        return $false
    }
    
    # Build argument list securely
    $argumentList = @(
        "cloudformation", 
        "deploy", 
        "--template-file", $TemplateFile, 
        "--stack-name", $StackName,
        "--capabilities", "CAPABILITY_NAMED_IAM"
    )
    
    # Add parameters safely
    if ($Parameters.Count -gt 0) {
        $argumentList += "--parameter-overrides"
        foreach ($key in $Parameters.Keys) {
            # Validate parameter names to prevent injection
            if ($key -match '^[a-zA-Z0-9]+$') {
                $value = $Parameters[$key]
                # Escape special characters in parameter values
                $value = $value -replace '"', '\"'
                $argumentList += "$key=$value"
            } else {
                Write-ColorOutput "✗ Invalid parameter name: $key" "Red"
                return $false
            }
        }
    }
    
    Write-ColorOutput "Executing: aws $($argumentList -join ' ')" "Gray"
    
    try {
        # Use Start-Process instead of Invoke-Expression for security
        $process = Start-Process -FilePath "aws" -ArgumentList $argumentList -NoNewWindow -PassThru -Wait
        
        if ($process.ExitCode -eq 0) {
            Write-ColorOutput "✓ Successfully deployed $StackName" "Green"
            return $true
        } else {
            Write-ColorOutput "✗ Failed to deploy $StackName (Exit Code: $($process.ExitCode))" "Red"
            return $false
        }
    }
    catch {
        Write-ColorOutput "✗ Error deploying $StackName : $_" "Red"
        return $false
    }
}

# Function to validate configuration
function Test-Configuration {
    Write-ColorOutput "Validating configuration..." "Yellow"
    
    # Check if config file exists
    if (-not (Test-Path "config/patch-config.json")) {
        Write-ColorOutput "✗ Configuration file not found: config/patch-config.json" "Red"
        return $false
    }
    
    # Check if CloudFormation templates exist
    $templates = @(
        "cloudformation/main-stack.yaml",
        "cloudformation/inspector-stack.yaml",
        "cloudformation/patch-stack.yaml",
        "cloudformation/security-hub-stack.yaml",
        "cloudformation/aws-config-stack.yaml",
        "cloudformation/audit-manager-stack.yaml"
    )
    
    foreach ($template in $templates) {
        if (-not (Test-Path $template)) {
            Write-ColorOutput "✗ CloudFormation template not found: $template" "Red"
            return $false
        }
    }
    
    Write-ColorOutput "✓ Configuration validation passed" "Green"
    return $true
}

# Function to update configuration file
function Update-Configuration {
    Write-ColorOutput "Updating configuration file..." "Yellow"
    
    try {
        $config = Get-Content "config/patch-config.json" | ConvertFrom-Json
        $config.environment = $Environment
        
        # Update notification settings
        $config.notifications.email.recipients[0] = $NotificationEmail
        
        # Update S3 bucket name
        $config.reporting.s3Bucket = $S3BucketName
        
        # Convert back to JSON and save
        $config | ConvertTo-Json -Depth 10 | Set-Content "config/patch-config.json"
        
        Write-ColorOutput "✓ Configuration updated" "Green"
    }
    catch {
        Write-ColorOutput "✗ Error updating configuration: $_" "Red"
        return $false
    }
}

# Function to display deployment summary
function Show-DeploymentSummary {
    Write-ColorOutput "`n=== DEPLOYMENT SUMMARY ===" "Cyan"
    Write-ColorOutput "Environment: $Environment" "White"
    Write-ColorOutput "Notification Email: $NotificationEmail" "White"
    Write-ColorOutput "S3 Bucket: $S3BucketName" "White"
    Write-ColorOutput "Operating System: $OperatingSystem" "White"
    Write-ColorOutput "Patch Approval Delay: $PatchApprovalDelay days" "White"
    Write-ColorOutput "Skip Inspector: $SkipInspector" "White"
    Write-ColorOutput "Skip Patch Manager: $SkipPatchManager" "White"
    Write-ColorOutput "Skip Security Hub: $SkipSecurityHub" "White"
    Write-ColorOutput "Skip AWS Config: $SkipConfig" "White"
    Write-ColorOutput "Skip Audit Manager: $SkipAuditManager" "White"
    Write-ColorOutput "Dry Run: $DryRun" "White"
    Write-ColorOutput "========================`n" "Cyan"
}

# Main deployment function
function Start-Deployment {
    Write-ColorOutput "Starting AWS Automation Patching and Reporting deployment..." "Cyan"
    
    # Show deployment summary
    Show-DeploymentSummary
    
    # Validate prerequisites
    Write-ColorOutput "`nChecking prerequisites..." "Yellow"
    
    if (-not (Test-AWSCLI)) {
        Write-ColorOutput "Please install AWS CLI and add it to your PATH" "Red"
        exit 1
    }
    
    if (-not (Test-AWSCredentials)) {
        Write-ColorOutput "Please configure AWS credentials using 'aws configure'" "Red"
        exit 1
    }
    
    if (-not (Test-Configuration)) {
        Write-ColorOutput "Configuration validation failed" "Red"
        exit 1
    }
    
    # Update configuration
    Update-Configuration
    
    # Deploy main infrastructure stack
    Write-ColorOutput "`nDeploying main infrastructure..." "Yellow"
    $mainParams = @{
        "Environment" = $Environment
        "NotificationEmail" = $NotificationEmail
        "S3BucketName" = $S3BucketName
    }
    
    $mainSuccess = Deploy-CloudFormationStack -TemplateFile "cloudformation/main-stack.yaml" -StackName "aws-patching-automation-$Environment" -Parameters $mainParams
    
    if (-not $mainSuccess) {
        Write-ColorOutput "Main infrastructure deployment failed" "Red"
        exit 1
    }
    
    # Deploy Inspector stack (if not skipped)
    if (-not $SkipInspector) {
        Write-ColorOutput "`nDeploying AWS Inspector..." "Yellow"
        $inspectorParams = @{
            "Environment" = $Environment
            "EnableEC2Scanning" = "true"
            "EnableECRScanning" = "true"
            "EnableLambdaScanning" = "true"
        }
        
        $inspectorSuccess = Deploy-CloudFormationStack -TemplateFile "cloudformation/inspector-stack.yaml" -StackName "aws-inspector-setup-$Environment" -Parameters $inspectorParams
        
        if (-not $inspectorSuccess) {
            Write-ColorOutput "Inspector deployment failed" "Red"
            exit 1
        }
    }
    else {
        Write-ColorOutput "Skipping Inspector deployment" "Yellow"
    }
    
    # Deploy Patch Manager stack (if not skipped)
    if (-not $SkipPatchManager) {
        Write-ColorOutput "`nDeploying Patch Manager..." "Yellow"
        $patchParams = @{
            "Environment" = $Environment
            "OperatingSystem" = $OperatingSystem
            "PatchApprovalDelay" = $PatchApprovalDelay.ToString()
        }
        
        $patchSuccess = Deploy-CloudFormationStack -TemplateFile "cloudformation/patch-stack.yaml" -StackName "aws-patch-manager-$Environment" -Parameters $patchParams
        
        if (-not $patchSuccess) {
            Write-ColorOutput "Patch Manager deployment failed" "Red"
            exit 1
        }
    }
    else {
        Write-ColorOutput "Skipping Patch Manager deployment" "Yellow"
    }
    
    # Deploy Security Hub stack (if not skipped)
    if (-not $SkipSecurityHub) {
        Write-ColorOutput "`nDeploying Security Hub..." "Yellow"
        $securityHubParams = @{
            "Environment" = $Environment
            "NotificationEmail" = $NotificationEmail
            "S3BucketName" = $S3BucketName
        }
        
        $securityHubSuccess = Deploy-CloudFormationStack -TemplateFile "cloudformation/security-hub-stack.yaml" -StackName "aws-security-hub-$Environment" -Parameters $securityHubParams
        
        if (-not $securityHubSuccess) {
            Write-ColorOutput "Security Hub deployment failed" "Red"
            exit 1
        }
    }
    else {
        Write-ColorOutput "Skipping Security Hub deployment" "Yellow"
    }
    
    # Deploy AWS Config stack (if not skipped)
    if (-not $SkipConfig) {
        Write-ColorOutput "`nDeploying AWS Config..." "Yellow"
        $configParams = @{
            "Environment" = $Environment
            "NotificationEmail" = $NotificationEmail
            "S3BucketName" = $S3BucketName
        }
        
        $configSuccess = Deploy-CloudFormationStack -TemplateFile "cloudformation/aws-config-stack.yaml" -StackName "aws-config-$Environment" -Parameters $configParams
        
        if (-not $configSuccess) {
            Write-ColorOutput "AWS Config deployment failed" "Red"
            exit 1
        }
    }
    else {
        Write-ColorOutput "Skipping AWS Config deployment" "Yellow"
    }
    
    # Deploy Audit Manager stack (if not skipped)
    if (-not $SkipAuditManager) {
        Write-ColorOutput "`nDeploying AWS Audit Manager..." "Yellow"
        $auditManagerParams = @{
            "Environment" = $Environment
            "NotificationEmail" = $NotificationEmail
            "S3BucketName" = $S3BucketName
        }
        
        $auditManagerSuccess = Deploy-CloudFormationStack -TemplateFile "cloudformation/audit-manager-stack.yaml" -StackName "aws-audit-manager-$Environment" -Parameters $auditManagerParams
        
        if (-not $auditManagerSuccess) {
            Write-ColorOutput "Audit Manager deployment failed" "Red"
            exit 1
        }
    }
    else {
        Write-ColorOutput "Skipping Audit Manager deployment" "Yellow"
    }
    
    # Display next steps
    Write-ColorOutput "`n=== DEPLOYMENT COMPLETED ===" "Green"
    Write-ColorOutput "Next steps:" "Yellow"
    Write-ColorOutput "1. Configure target instances with Systems Manager agent" "White"
    Write-ColorOutput "2. Tag instances with PatchGroup=$Environment-servers" "White"
    Write-ColorOutput "3. Subscribe to SNS notifications" "White"
    Write-ColorOutput "4. Test the automation with a manual patch scan" "White"
    Write-ColorOutput "5. Review the deployment guide for detailed instructions" "White"
    Write-ColorOutput "6. Monitor AWS Config compliance rules" "White"
    Write-ColorOutput "7. Review Security Hub findings for CIS/PCI compliance" "White"
    Write-ColorOutput "8. Set up Audit Manager assessments and evidence collection" "White"
    Write-ColorOutput "=============================" "Green"
}

# Execute deployment
try {
    Start-Deployment
}
catch {
    Write-ColorOutput "Deployment failed with error: $_" "Red"
    exit 1
} 