# AWS Automation Patching and Reporting - Deployment Guide

This guide provides step-by-step instructions for deploying the AWS automation patching and reporting solution.

## Prerequisites

### AWS Account Requirements
- AWS account with appropriate permissions
- AWS CLI configured with access keys
- CloudFormation permissions
- Systems Manager permissions
- Inspector permissions

### Required AWS Services
- AWS Systems Manager
- AWS Inspector v2
- AWS Lambda
- Amazon S3
- Amazon SNS
- Amazon EventBridge
- AWS CloudWatch
- AWS IAM

### Local Requirements
- Python 3.8+
- AWS CLI v2+
- PowerShell 5.1+ (for Windows instances)
- Git

## Step 1: Environment Setup

### 1.1 Clone the Repository
```bash
git clone https://github.com/your-org/aws-automation-patching-and-reporting.git
cd aws-automation-patching-and-reporting
```

### 1.2 Configure AWS CLI
```bash
aws configure
# Enter your AWS Access Key ID
# Enter your AWS Secret Access Key
# Enter your default region (e.g., us-east-1)
# Enter your default output format (json)
```

### 1.3 Update Configuration
Edit `config/patch-config.json` to match your environment:
- Update email addresses
- Modify schedules as needed
- Adjust severity thresholds
- Configure instance groups

## Step 2: Deploy Infrastructure

### 2.1 Deploy Main Infrastructure Stack
```bash
aws cloudformation deploy \
  --template-file cloudformation/main-stack.yaml \
  --stack-name aws-patching-automation \
  --parameter-overrides \
    Environment=dev \
    NotificationEmail=admin@yourcompany.com \
    S3BucketName=your-patching-reports-bucket \
  --capabilities CAPABILITY_NAMED_IAM
```

### 2.2 Deploy AWS Inspector Stack
```bash
aws cloudformation deploy \
  --template-file cloudformation/inspector-stack.yaml \
  --stack-name aws-inspector-setup \
  --parameter-overrides \
    Environment=dev \
    EnableEC2Scanning=true \
    EnableECRScanning=true \
    EnableLambdaScanning=true
```

### 2.3 Deploy Patch Manager Stack
```bash
aws cloudformation deploy \
  --template-file cloudformation/patch-stack.yaml \
  --stack-name aws-patch-manager \
  --parameter-overrides \
    Environment=dev \
    OperatingSystem=WINDOWS \
    PatchApprovalDelay=7
```

## Step 3: Configure Target Instances

### 3.1 Install Systems Manager Agent
Ensure all target instances have the AWS Systems Manager agent installed:

**For Windows:**
- The agent is typically pre-installed on Amazon Windows AMIs
- For custom AMIs, download from: https://s3.amazonaws.com/amazon-ssm-region/latest/windows_amd64/AmazonSSMAgentSetup.exe

**For Linux:**
```bash
# Amazon Linux 2
sudo yum install -y amazon-ssm-agent
sudo systemctl enable amazon-ssm-agent
sudo systemctl start amazon-ssm-agent

# Ubuntu
sudo snap install amazon-ssm-agent --classic
sudo systemctl enable snap.amazon-ssm-agent.amazon-ssm-agent.service
sudo systemctl start snap.amazon-ssm-agent.amazon-ssm-agent.service
```

### 3.2 Configure Instance IAM Role
Create an IAM role for your instances with the following policies:
- `AmazonSSMManagedInstanceCore`
- `CloudWatchAgentServerPolicy` (optional, for enhanced monitoring)

### 3.3 Tag Instances
Tag your instances for patch management:
```bash
aws ec2 create-tags \
  --resources i-1234567890abcdef0 \
  --tags Key=PatchGroup,Value=dev-servers
```

## Step 4: Deploy Automation Scripts

### 4.1 Upload PowerShell Scripts
```bash
# Create S3 bucket for scripts (if not exists)
aws s3 mb s3://your-scripts-bucket

# Upload PowerShell audit script
aws s3 cp scripts/powershell/audit_services.ps1 s3://your-scripts-bucket/scripts/audit_services.ps1
```

### 4.2 Create SSM Document for Audit Script
```bash
aws ssm create-document \
  --name "SystemAuditScript" \
  --content file://templates/audit-document.yaml \
  --document-type "Command"
```

### 4.3 Deploy Lambda Functions
```bash
# Package and deploy Inspector handler
cd lambda/inspector_processor
zip -r inspector_processor.zip .
aws lambda create-function \
  --function-name InspectorFindingsProcessor-dev \
  --runtime python3.9 \
  --role arn:aws:iam::YOUR_ACCOUNT:role/PatchingAutomationLambdaRole-dev \
  --handler index.handler \
  --zip-file fileb://inspector_processor.zip

# Package and deploy Patch approver
cd ../patch_approver
zip -r patch_approver.zip .
aws lambda create-function \
  --function-name PatchApprover-dev \
  --runtime python3.9 \
  --role arn:aws:iam::YOUR_ACCOUNT:role/PatchingAutomationLambdaRole-dev \
  --handler index.handler \
  --zip-file fileb://patch_approver.zip
```

## Step 5: Configure Monitoring and Alerts

### 5.1 Set Up CloudWatch Dashboards
The CloudFormation templates automatically create dashboards for:
- Lambda function metrics
- Inspector findings
- Patch compliance

### 5.2 Configure SNS Notifications
1. Subscribe to the SNS topic created by the main stack
2. Test notifications by running a manual patch scan

### 5.3 Set Up CloudWatch Alarms
```bash
# Create alarm for failed patch operations
aws cloudwatch put-metric-alarm \
  --alarm-name "PatchOperationFailures" \
  --alarm-description "Alarm when patch operations fail" \
  --metric-name "Errors" \
  --namespace "AWS/Lambda" \
  --statistic "Sum" \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:region:account:topic-name
```

## Step 6: Testing and Validation

### 6.1 Test Inspector Integration
```bash
# Trigger a manual Inspector scan
aws inspector2 start-scan \
  --scan-type EC2 \
  --resource-filter criteria='{"instanceTags":[{"key":"Environment","value":"dev"}]}'
```

### 6.2 Test Patch Scanning
```bash
# Run patch scan on test instance
aws ssm send-command \
  --instance-ids i-1234567890abcdef0 \
  --document-name "AWS-RunPatchBaseline" \
  --parameters '{"Operation":["Scan"]}'
```

### 6.3 Test Audit Script
```bash
# Run audit script on Windows instance
aws ssm send-command \
  --instance-ids i-1234567890abcdef0 \
  --document-name "SystemAuditScript" \
  --parameters '{"OutputPath":["C:\\temp\\test-audit.json"]}'
```

## Step 7: Production Deployment

### 7.1 Update Configuration for Production
1. Update `config/patch-config.json` with production settings
2. Modify approval workflows for production
3. Update notification recipients

### 7.2 Deploy to Production
```bash
# Deploy with production parameters
aws cloudformation deploy \
  --template-file cloudformation/main-stack.yaml \
  --stack-name aws-patching-automation-prod \
  --parameter-overrides \
    Environment=prod \
    NotificationEmail=prod-admin@yourcompany.com \
    S3BucketName=your-prod-patching-reports-bucket \
  --capabilities CAPABILITY_NAMED_IAM
```

### 7.3 Configure Production Instances
1. Tag production instances with `PatchGroup=prod-servers`
2. Ensure proper IAM roles are attached
3. Verify Systems Manager agent is running

## Step 8: Ongoing Operations

### 8.1 Monitor Dashboards
- Check CloudWatch dashboards regularly
- Review patch compliance reports
- Monitor Inspector findings

### 8.2 Review and Approve Patches
1. Check S3 bucket for pending approvals
2. Review patch details and security implications
3. Approve or reject patches as needed

### 8.3 Generate Reports
```bash
# Generate compliance report
aws ssm send-command \
  --instance-ids i-1234567890abcdef0 \
  --document-name "AWS-RunPatchBaseline" \
  --parameters '{"Operation":["Scan"]}'
```

## Troubleshooting

### Common Issues

**1. Systems Manager Agent Not Responding**
```bash
# Check agent status on Windows
Get-Service -Name AmazonSSMAgent

# Check agent status on Linux
sudo systemctl status amazon-ssm-agent
```

**2. Patch Baseline Not Found**
```bash
# List available patch baselines
aws ssm describe-patch-baselines

# Verify baseline association
aws ssm describe-patch-groups
```

**3. Lambda Function Errors**
```bash
# Check CloudWatch logs
aws logs describe-log-groups --log-group-name-prefix "/aws/lambda/PatchingAutomation"

# View recent log events
aws logs filter-log-events \
  --log-group-name "/aws/lambda/PatchingAutomationLambdaRole-dev" \
  --start-time $(date -d '1 hour ago' +%s)000
```

### Support and Maintenance

1. **Regular Updates**: Keep the solution updated with latest security patches
2. **Backup Configuration**: Regularly backup configuration files
3. **Monitor Costs**: Review AWS costs associated with the solution
4. **Security Reviews**: Conduct regular security reviews of the automation

## Security Considerations

1. **IAM Roles**: Use least privilege principle for all IAM roles
2. **Encryption**: Ensure all data is encrypted at rest and in transit
3. **Network Security**: Use VPC endpoints for AWS services when possible
4. **Audit Logging**: Enable CloudTrail for all API calls
5. **Patch Testing**: Test patches in development before production deployment

## Cost Optimization

1. **S3 Lifecycle**: Configure S3 lifecycle policies to delete old reports
2. **Lambda Optimization**: Monitor Lambda function execution times
3. **Inspector Scheduling**: Adjust Inspector scan frequency based on needs
4. **CloudWatch Retention**: Set appropriate log retention periods

## Next Steps

After successful deployment:

1. **Customize Workflows**: Adapt approval workflows to your organization's needs
2. **Integrate with SIEM**: Connect to your Security Information and Event Management system
3. **Add Compliance Reporting**: Extend reporting for specific compliance requirements
4. **Implement Change Management**: Integrate with your change management process
5. **Scale Globally**: Deploy to multiple AWS regions if needed 