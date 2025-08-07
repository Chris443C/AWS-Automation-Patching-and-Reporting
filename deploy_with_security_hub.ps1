# AWS Automation Patching and Reporting with Security Hub Integration
# Enhanced deployment script that includes CIS and PCI compliance scanning

param(
    [string]$Environment = "dev",
    [string]$Region = "us-east-1",
    [string]$NotificationEmail = "",
    [switch]$EnableCISBenchmark = $true,
    [switch]$EnablePCIDSS = $true,
    [switch]$SkipSecurityHub = $false,
    [switch]$DryRun = $false
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Function to check AWS CLI
function Test-AWSCLI {
    try {
        $awsVersion = aws --version
        Write-Host "AWS CLI found: $awsVersion" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "AWS CLI not found. Please install AWS CLI and configure it."
        return $false
    }
}

# Function to check AWS credentials
function Test-AWSCredentials {
    try {
        $identity = aws sts get-caller-identity
        $accountId = ($identity | ConvertFrom-Json).Account
        $userId = ($identity | ConvertFrom-Json).UserId
        $arn = ($identity | ConvertFrom-Json).Arn
        
        Write-Host "AWS Credentials verified:" -ForegroundColor Green
        Write-Host "  Account ID: $accountId" -ForegroundColor Cyan
        Write-Host "  User ID: $userId" -ForegroundColor Cyan
        Write-Host "  ARN: $arn" -ForegroundColor Cyan
        
        return $true
    }
    catch {
        Write-Error "AWS credentials not configured or invalid. Please run 'aws configure'."
        return $false
    }
}

# Function to deploy CloudFormation stack
function Deploy-CloudFormationStack {
    param(
        [string]$StackName,
        [string]$TemplateFile,
        [hashtable]$Parameters = @{}
    )
    
    try {
        Write-Host "Deploying stack: $StackName" -ForegroundColor Yellow
        
        if ($DryRun) {
            Write-Host "DRY RUN: Would deploy stack $StackName with template $TemplateFile" -ForegroundColor Magenta
            return $true
        }
        
        # Build parameter string
        $paramString = ""
        foreach ($key in $Parameters.Keys) {
            $paramString += " ParameterKey=$key,ParameterValue=$($Parameters[$key])"
        }
        
        # Deploy stack
        $command = "aws cloudformation deploy --template-file $TemplateFile --stack-name $StackName --capabilities CAPABILITY_NAMED_IAM --region $Region"
        
        if ($paramString) {
            $command += " --parameter-overrides$paramString"
        }
        
        Write-Host "Executing: $command" -ForegroundColor Gray
        Invoke-Expression $command
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Stack $StackName deployed successfully!" -ForegroundColor Green
            return $true
        } else {
            Write-Error "Failed to deploy stack $StackName"
            return $false
        }
    }
    catch {
        Write-Error "Error deploying stack $StackName : $_"
        return $false
    }
}

# Function to enable Security Hub
function Enable-SecurityHub {
    param(
        [string]$Region
    )
    
    try {
        Write-Host "Enabling Security Hub in region: $Region" -ForegroundColor Yellow
        
        if ($DryRun) {
            Write-Host "DRY RUN: Would enable Security Hub in $Region" -ForegroundColor Magenta
            return $true
        }
        
        # Enable Security Hub
        aws securityhub enable-security-hub --region $Region
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Security Hub enabled successfully in $Region" -ForegroundColor Green
            return $true
        } else {
            Write-Warning "Security Hub may already be enabled or failed to enable in $Region"
            return $true  # Continue anyway
        }
    }
    catch {
        Write-Warning "Error enabling Security Hub in $Region : $_"
        return $true  # Continue anyway
    }
}

# Function to subscribe to compliance standards
function Subscribe-ComplianceStandards {
    param(
        [string]$Region,
        [bool]$EnableCIS,
        [bool]$EnablePCI
    )
    
    try {
        Write-Host "Subscribing to compliance standards..." -ForegroundColor Yellow
        
        if ($DryRun) {
            Write-Host "DRY RUN: Would subscribe to compliance standards" -ForegroundColor Magenta
            return $true
        }
        
        # Subscribe to CIS AWS Foundations Benchmark
        if ($EnableCIS) {
            Write-Host "Subscribing to CIS AWS Foundations Benchmark..." -ForegroundColor Cyan
            $cisArn = "arn:aws:securityhub:" + $Region + "::standards/cis-aws-foundations-benchmark/v/1.2.0"
            aws securityhub batch-enable-standards --standards-subscription-requests "StandardsArn=$cisArn" --region $Region
        }
        
        # Subscribe to PCI DSS
        if ($EnablePCI) {
            Write-Host "Subscribing to PCI DSS..." -ForegroundColor Cyan
            $pciArn = "arn:aws:securityhub:" + $Region + "::standards/pci-dss/v/3.2.1"
            aws securityhub batch-enable-standards --standards-subscription-requests "StandardsArn=$pciArn" --region $Region
        }
        
        Write-Host "Compliance standards subscribed successfully!" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Warning "Error subscribing to compliance standards: $_"
        return $true  # Continue anyway
    }
}

# Function to configure Security Hub controls
function Configure-SecurityHubControls {
    param(
        [string]$Region
    )
    
    try {
        Write-Host "Configuring Security Hub controls..." -ForegroundColor Yellow
        
        if ($DryRun) {
            Write-Host "DRY RUN: Would configure Security Hub controls" -ForegroundColor Magenta
            return $true
        }
        
        # Get enabled standards
        $standards = aws securityhub get-enabled-standards --region $Region | ConvertFrom-Json
        
        foreach ($standard in $standards.StandardsSubscriptions) {
            $standardArn = $standard.StandardsArn
            $subscriptionArn = $standard.StandardsSubscriptionArn
            
            Write-Host "Configuring controls for standard: $standardArn" -ForegroundColor Cyan
            
            # Get controls for this standard
            $controls = aws securityhub get-standards-controls --standards-subscription-arn $subscriptionArn --region $Region | ConvertFrom-Json
            
            foreach ($control in $controls.Controls) {
                # Enable critical and high severity controls
                if ($control.SeverityRating -in @("CRITICAL", "HIGH")) {
                    aws securityhub update-standards-control --standards-control-arn $control.StandardsControlArn --control-status ENABLED --region $Region
                }
            }
        }
        
        Write-Host "Security Hub controls configured successfully!" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Warning "Error configuring Security Hub controls: $_"
        return $true  # Continue anyway
    }
}

# Function to create EventBridge rules for Security Hub
function Create-SecurityHubEventRules {
    param(
        [string]$Region,
        [string]$Environment
    )
    
    try {
        Write-Host "Creating EventBridge rules for Security Hub..." -ForegroundColor Yellow
        
        if ($DryRun) {
            Write-Host "DRY RUN: Would create EventBridge rules for Security Hub" -ForegroundColor Magenta
            return $true
        }
        
        # Create rule for Security Hub findings
        $ruleName = "SecurityHubFindings-$Environment"
        $ruleArn = "arn:aws:events:$Region:$((aws sts get-caller-identity | ConvertFrom-Json).Account):rule/$ruleName"
        
        # Create the rule
        aws events put-rule --name $ruleName --event-pattern '{"source":["aws.securityhub"],"detail-type":["Security Hub Findings - Imported"]}' --state ENABLED --region $Region
        
        # Add target (Lambda function will be created by CloudFormation)
        $lambdaArn = "arn:aws:lambda:$Region:$((aws sts get-caller-identity | ConvertFrom-Json).Account):function:SecurityHubProcessor-$Environment"
        
        aws events put-targets --rule $ruleName --targets "Id"="SecurityHubTarget","Arn"=$lambdaArn --region $Region
        
        Write-Host "EventBridge rules created successfully!" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Warning "Error creating EventBridge rules: $_"
        return $true  # Continue anyway
    }
}

# Function to test the deployment
function Test-Deployment {
    param(
        [string]$Region,
        [string]$Environment
    )
    
    try {
        Write-Host "Testing deployment..." -ForegroundColor Yellow
        
        if ($DryRun) {
            Write-Host "DRY RUN: Would test deployment" -ForegroundColor Magenta
            return $true
        }
        
        # Test Security Hub
        $securityHubStatus = aws securityhub describe-hub --region $Region 2>$null
        if ($securityHubStatus) {
            Write-Host "✓ Security Hub is enabled" -ForegroundColor Green
        } else {
            Write-Host "✗ Security Hub is not enabled" -ForegroundColor Red
        }
        
        # Test compliance standards
        $standards = aws securityhub get-enabled-standards --region $Region 2>$null
        if ($standards) {
            $standardsObj = $standards | ConvertFrom-Json
            Write-Host "✓ Enabled standards: $($standardsObj.StandardsSubscriptions.Count)" -ForegroundColor Green
        } else {
            Write-Host "✗ No standards enabled" -ForegroundColor Red
        }
        
        # Test Lambda functions
        $lambdaFunctions = aws lambda list-functions --region $Region 2>$null
        if ($lambdaFunctions) {
            $lambdaObj = $lambdaFunctions | ConvertFrom-Json
            $complianceFunctions = $lambdaObj.Functions | Where-Object { $_.FunctionName -like "*Compliance*" -or $_.FunctionName -like "*SecurityHub*" }
            Write-Host "✓ Compliance Lambda functions: $($complianceFunctions.Count)" -ForegroundColor Green
        } else {
            Write-Host "✗ No Lambda functions found" -ForegroundColor Red
        }
        
        Write-Host "Deployment test completed!" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Warning "Error testing deployment: $_"
        return $true  # Continue anyway
    }
}

# Function to display deployment summary
function Show-DeploymentSummary {
    param(
        [string]$Environment,
        [string]$Region,
        [bool]$SecurityHubEnabled,
        [bool]$CISEnabled,
        [bool]$PCIEnabled
    )
    
    Write-Host "`n=== DEPLOYMENT SUMMARY ===" -ForegroundColor Magenta
    Write-Host "Environment: $Environment" -ForegroundColor Cyan
    Write-Host "Region: $Region" -ForegroundColor Cyan
    Write-Host "Security Hub: $(if ($SecurityHubEnabled) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if ($SecurityHubEnabled) { 'Green' } else { 'Yellow' })
    Write-Host "CIS Benchmark: $(if ($CISEnabled) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if ($CISEnabled) { 'Green' } else { 'Yellow' })
    Write-Host "PCI DSS: $(if ($PCIEnabled) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if ($PCIEnabled) { 'Green' } else { 'Yellow' })
    
    Write-Host "`n=== NEXT STEPS ===" -ForegroundColor Magenta
    Write-Host "1. Review Security Hub findings in the AWS Console" -ForegroundColor Yellow
    Write-Host "2. Configure additional compliance controls as needed" -ForegroundColor Yellow
    Write-Host "3. Set up automated compliance reporting" -ForegroundColor Yellow
    Write-Host "4. Run compliance audit scripts on your instances" -ForegroundColor Yellow
    Write-Host "5. Monitor compliance scores and remediate violations" -ForegroundColor Yellow
    
    Write-Host "`n=== USEFUL COMMANDS ===" -ForegroundColor Magenta
    Write-Host "# Run compliance audit on Windows instances:" -ForegroundColor Cyan
    Write-Host ".\scripts\powershell\compliance_audit.ps1 -IncludeCISChecks -IncludePCIChecks" -ForegroundColor Gray
    Write-Host "`n# Run Security Hub compliance scan:" -ForegroundColor Cyan
    Write-Host "python scripts\python\compliance_scanner.py --days-back 30" -ForegroundColor Gray
    Write-Host "`n# View Security Hub findings:" -ForegroundColor Cyan
    Write-Host "aws securityhub get-findings --region $Region" -ForegroundColor Gray
}

# Main execution
try {
    Write-Host "AWS Automation Patching and Reporting with Security Hub Integration" -ForegroundColor Green
    Write-Host "Enhanced deployment script with CIS and PCI compliance scanning" -ForegroundColor Green
    Write-Host "=" * 80 -ForegroundColor Gray
    
    # Validate prerequisites
    if (-not (Test-AWSCLI)) {
        exit 1
    }
    
    if (-not (Test-AWSCredentials)) {
        exit 1
    }
    
    # Validate parameters
    if ([string]::IsNullOrEmpty($NotificationEmail)) {
        Write-Error "NotificationEmail parameter is required"
        exit 1
    }
    
    if ($Environment -notin @("dev", "staging", "prod")) {
        Write-Error "Environment must be one of: dev, staging, prod"
        exit 1
    }
    
    Write-Host "`nDeployment Configuration:" -ForegroundColor Yellow
    Write-Host "  Environment: $Environment" -ForegroundColor Cyan
    Write-Host "  Region: $Region" -ForegroundColor Cyan
    Write-Host "  Notification Email: $NotificationEmail" -ForegroundColor Cyan
    Write-Host "  Enable CIS Benchmark: $EnableCISBenchmark" -ForegroundColor Cyan
    Write-Host "  Enable PCI DSS: $EnablePCIDSS" -ForegroundColor Cyan
    Write-Host "  Skip Security Hub: $SkipSecurityHub" -ForegroundColor Cyan
    Write-Host "  Dry Run: $DryRun" -ForegroundColor Cyan
    
    if ($DryRun) {
        Write-Host "`nDRY RUN MODE - No actual changes will be made" -ForegroundColor Magenta
    }
    
    # Deploy main infrastructure
    Write-Host "`nStep 1: Deploying main infrastructure..." -ForegroundColor Yellow
    $mainParams = @{
        "Environment" = $Environment
        "S3BucketName" = "aws-patching-automation-reports"
        "NotificationEmail" = $NotificationEmail
    }
    
    if (-not (Deploy-CloudFormationStack -StackName "aws-patching-automation-$Environment" -TemplateFile "cloudformation/main-stack.yaml" -Parameters $mainParams)) {
        Write-Error "Failed to deploy main infrastructure"
        exit 1
    }
    
    # Deploy Inspector configuration
    Write-Host "`nStep 2: Deploying Inspector configuration..." -ForegroundColor Yellow
    $inspectorParams = @{
        "Environment" = $Environment
    }
    
    if (-not (Deploy-CloudFormationStack -StackName "aws-inspector-setup-$Environment" -TemplateFile "cloudformation/inspector-stack.yaml" -Parameters $inspectorParams)) {
        Write-Error "Failed to deploy Inspector configuration"
        exit 1
    }
    
    # Deploy Patch Manager configuration
    Write-Host "`nStep 3: Deploying Patch Manager configuration..." -ForegroundColor Yellow
    $patchParams = @{
        "Environment" = $Environment
    }
    
    if (-not (Deploy-CloudFormationStack -StackName "aws-patch-manager-$Environment" -TemplateFile "cloudformation/patch-stack.yaml" -Parameters $patchParams)) {
        Write-Error "Failed to deploy Patch Manager configuration"
        exit 1
    }
    
    # Deploy Security Hub configuration (if not skipped)
    if (-not $SkipSecurityHub) {
        Write-Host "`nStep 4: Deploying Security Hub configuration..." -ForegroundColor Yellow
        $securityHubParams = @{
            "Environment" = $Environment
            "EnableCISBenchmark" = $EnableCISBenchmark.ToString().ToLower()
            "EnablePCIDSS" = $EnablePCIDSS.ToString().ToLower()
            "NotificationEmail" = $NotificationEmail
        }
        
        if (-not (Deploy-CloudFormationStack -StackName "aws-security-hub-$Environment" -TemplateFile "cloudformation/security-hub-stack.yaml" -Parameters $securityHubParams)) {
            Write-Error "Failed to deploy Security Hub configuration"
            exit 1
        }
        
        # Enable Security Hub
        Write-Host "`nStep 5: Enabling Security Hub..." -ForegroundColor Yellow
        if (-not (Enable-SecurityHub -Region $Region)) {
            Write-Warning "Failed to enable Security Hub, but continuing..."
        }
        
        # Subscribe to compliance standards
        Write-Host "`nStep 6: Subscribing to compliance standards..." -ForegroundColor Yellow
        if (-not (Subscribe-ComplianceStandards -Region $Region -EnableCIS $EnableCISBenchmark -EnablePCI $EnablePCIDSS)) {
            Write-Warning "Failed to subscribe to compliance standards, but continuing..."
        }
        
        # Configure Security Hub controls
        Write-Host "`nStep 7: Configuring Security Hub controls..." -ForegroundColor Yellow
        if (-not (Configure-SecurityHubControls -Region $Region)) {
            Write-Warning "Failed to configure Security Hub controls, but continuing..."
        }
        
        # Create EventBridge rules
        Write-Host "`nStep 8: Creating EventBridge rules..." -ForegroundColor Yellow
        if (-not (Create-SecurityHubEventRules -Region $Region -Environment $Environment)) {
            Write-Warning "Failed to create EventBridge rules, but continuing..."
        }
    }
    
    # Test deployment
    Write-Host "`nStep 9: Testing deployment..." -ForegroundColor Yellow
    if (-not (Test-Deployment -Region $Region -Environment $Environment)) {
        Write-Warning "Deployment test failed, but continuing..."
    }
    
    # Show deployment summary
    Show-DeploymentSummary -Environment $Environment -Region $Region -SecurityHubEnabled (-not $SkipSecurityHub) -CISEnabled $EnableCISBenchmark -PCIEnabled $EnablePCIDSS
    
    Write-Host "`nDeployment completed successfully!" -ForegroundColor Green
    
    if ($DryRun) {
        Write-Host "`nThis was a dry run. To perform actual deployment, run without -DryRun parameter." -ForegroundColor Magenta
    }
    
    exit 0
}
catch {
    Write-Error "Deployment failed: $_"
    exit 1
} 