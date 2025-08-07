# AWS Automation Patching and Reporting

A comprehensive AWS-native solution for automated vulnerability scanning, patch management, compliance monitoring, and reporting.

## 🎯 Overview

This solution combines AWS Inspector, Security Hub, AWS Config, AWS Audit Manager, Systems Manager Patch Manager, and custom automation scripts to create a hybrid compliance + patching pipeline that:

1. **Scans for vulnerabilities** using AWS Inspector
2. **Monitors compliance** using Security Hub (CIS & PCI DSS)
3. **Enforces infrastructure compliance** using AWS Config rules
4. **Automates evidence collection** using AWS Audit Manager
5. **Downloads patches** without installing them
6. **Audits current state** using custom PowerShell scripts
7. **Approves patches** through manual or automated workflows
8. **Installs only approved patches** with full control

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   AWS Inspector │    │  Security Hub   │    │   AWS Config    │
│   (Vulnerability│    │  (CIS & PCI     │    │  (Rule-based    │
│   Detection)    │    │   Compliance)   │    │   Compliance)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │  Audit Manager  │
                    │  (Evidence      │
                    │   Collection &  │
                    │   Assessment)   │
                    └─────────────────┘
                                 │
                    ┌─────────────────┐
                    │  Compliance     │
                    │  Integration    │
                    │  Layer          │
                    │  (Python)       │
                    └─────────────────┘
                                 │
                    ┌─────────────────┐
                    │  Custom Scripts │
                    │  (Audit &       │
                    │   Reporting)    │
                    └─────────────────┘
                                 │
                    ┌─────────────────┐
                    │  Approval       │
                    │  Workflow       │
                    │  (Manual/Auto)  │
                    └─────────────────┘
                                 │
                    ┌─────────────────┐
                    │  Patch Manager  │
                    │  (Install Mode) │
                    └─────────────────┘
```

## 🔐 Compliance Standards

### CIS AWS Foundations Benchmark v1.2.0
- **Identity and Access Management** - Root account restrictions, MFA enforcement, IAM policies
- **Logging and Monitoring** - CloudTrail, AWS Config, S3 logging, VPC flow logs
- **Networking** - VPC configuration, security groups, network ACLs

### PCI DSS v3.2.1
- **Network Security** - Firewall configuration, vendor defaults management
- **Data Protection** - Encryption, secure transmission
- **Vulnerability Management** - Anti-virus, security patches
- **Access Control** - User identification, access restrictions
- **Monitoring and Testing** - Audit trails, vulnerability scanning
- **Security Policy** - Information security policies, risk assessment

### AWS Config Rule-Based Compliance
- **Infrastructure Compliance** - Real-time monitoring of AWS resource configurations
- **Patching Automation Rules** - SSM agent installation, patch compliance, approval workflows
- **Security Configuration Rules** - Security groups, S3 encryption, CloudTrail configuration
- **Custom Compliance Rules** - Lambda-based rules for specific organizational requirements

### AWS Audit Manager Assessment Frameworks
- **Automated Evidence Collection** - Gathers evidence from AWS Config, Security Hub, and Inspector
- **Framework Mapping** - Maps evidence to CIS, PCI, SOC, HIPAA, and ISO 27001 controls
- **Assessment Workflows** - Creates and manages compliance assessments
- **Evidence Management** - Organizes and stores compliance evidence
- **Reporting** - Generates comprehensive compliance reports

## 📁 Project Structure

```
AWS-Automation-Patching-and-Reporting/
├── cloudformation/           # Infrastructure as Code
│   ├── main-stack.yaml      # Main CloudFormation stack
│   ├── inspector-stack.yaml # Inspector configuration
│   ├── patch-stack.yaml     # Patch Manager setup
│   ├── security-hub-stack.yaml # Security Hub configuration
│   ├── aws-config-stack.yaml # AWS Config rules and monitoring
│   └── audit-manager-stack.yaml # AWS Audit Manager integration
├── scripts/                  # Automation scripts
│   ├── python/              # Python automation
│   │   ├── inspector_handler.py
│   │   ├── patch_approver.py
│   │   ├── compliance_scanner.py
│   │   ├── config_compliance_integration.py
│   │   └── audit_manager_integration.py
│   └── powershell/          # PowerShell scripts
│       ├── audit_services.ps1
│       ├── compliance_audit.ps1
│       └── patch_inventory.ps1
├── lambda/                   # Lambda functions
│   ├── inspector_processor/
│   ├── patch_approver/
│   ├── security_hub_processor/
│   ├── config_compliance_processor/
│   └── audit_manager_processor/
├── templates/                # SSM document templates
│   ├── audit-document.yaml
│   └── patch-document.yaml
└── docs/                     # Documentation
    ├── deployment-guide.md
    ├── security-hub-integration.md
    ├── aws-config-integration.md
    ├── audit-manager-integration.md
    └── troubleshooting.md
```

## 🚀 Quick Start

### Prerequisites

- AWS CLI configured with appropriate permissions
- Python 3.8+
- PowerShell 5.1+ (for Windows instances)
- AWS Systems Manager agent installed on target instances

### Deployment

#### Option 1: Full Deployment with All Components

```powershell
# Deploy with Security Hub and AWS Config integration
.\deploy.ps1 -Environment "prod" -NotificationEmail "admin@company.com"

# Deploy with specific components disabled
.\deploy.ps1 -Environment "dev" -NotificationEmail "admin@company.com" -SkipConfig -SkipSecurityHub

# Dry run to see what would be deployed
.\deploy.ps1 -Environment "staging" -NotificationEmail "admin@company.com" -DryRun
```

#### Option 2: Manual Deployment

1. **Deploy the main infrastructure:**
   ```bash
   aws cloudformation deploy \
     --template-file cloudformation/main-stack.yaml \
     --stack-name aws-patching-automation \
     --capabilities CAPABILITY_NAMED_IAM
   ```

2. **Enable AWS Inspector:**
   ```bash
   aws cloudformation deploy \
     --template-file cloudformation/inspector-stack.yaml \
     --stack-name aws-inspector-setup
   ```

3. **Configure Patch Manager:**
   ```bash
   aws cloudformation deploy \
     --template-file cloudformation/patch-stack.yaml \
     --stack-name aws-patch-manager
   ```

4. **Deploy Security Hub with compliance standards:**
   ```bash
   aws cloudformation deploy \
     --template-file cloudformation/security-hub-stack.yaml \
     --stack-name aws-security-hub \
     --capabilities CAPABILITY_NAMED_IAM
   ```

5. **Deploy AWS Config with compliance rules:**
   ```bash
   aws cloudformation deploy \
     --template-file cloudformation/aws-config-stack.yaml \
     --stack-name aws-config \
     --capabilities CAPABILITY_NAMED_IAM
   ```

6. **Deploy AWS Audit Manager with assessment workflows:**
   ```bash
   aws cloudformation deploy \
     --template-file cloudformation/audit-manager-stack.yaml \
     --stack-name aws-audit-manager \
     --capabilities CAPABILITY_NAMED_IAM
   ```

## 🔍 Compliance Scanning

### Multi-Layer Compliance Monitoring

This solution provides four layers of compliance monitoring:

1. **AWS Audit Manager** - Automated evidence collection and assessment workflows
2. **AWS Config Rules** - Infrastructure-level compliance monitoring
3. **Security Hub** - Vulnerability and CIS/PCI compliance scanning  
4. **Local Scripts** - Instance-level configuration auditing

### AWS Audit Manager Integration

Automate evidence collection and compliance assessments:

```bash
# Run automated assessment
python scripts/python/audit_manager_integration.py

# Run assessment with specific framework
python scripts/python/audit_manager_integration.py --framework "CIS AWS Foundations Benchmark"

# List available frameworks
python scripts/python/audit_manager_integration.py --list-frameworks

# List existing assessments
python scripts/python/audit_manager_integration.py --list-assessments
```

**Audit Manager Features:**
- **Automated Evidence Collection** - From Config, Security Hub, and Inspector
- **Framework Mapping** - CIS, PCI, SOC, HIPAA, ISO 27001
- **Assessment Workflows** - Create and manage compliance assessments
- **Evidence Management** - Organize and store compliance evidence
- **Comprehensive Reporting** - Generate detailed compliance reports

### AWS Config Compliance Integration

Monitor infrastructure compliance with custom rules:

```bash
# Run Config compliance scan
python scripts/python/config_compliance_integration.py

# Check only patching-related rules
python scripts/python/config_compliance_integration.py --patching-only

# Scan specific Config rules
python scripts/python/config_compliance_integration.py --rule-names SSMAgentInstalled PatchCompliance
```

**Config Rules Deployed:**
- **SSMAgentInstalled** - Ensures SSM agent is installed for patch management
- **PatchCompliance** - Monitors patch baseline compliance
- **PatchApprovalWorkflow** - Validates approval workflow configuration
- **SecurityGroupRestrictedAccess** - Checks security group configurations
- **S3BucketEncryption** - Ensures S3 buckets have encryption enabled
- **CloudTrailEnabled** - Verifies CloudTrail is enabled for audit logging

### Python Compliance Scanner

Analyze Security Hub findings for CIS and PCI compliance impact:

```bash
# Basic compliance scan
python scripts/python/compliance_scanner.py

# Scan with custom parameters
python scripts/python/compliance_scanner.py --days-back 60 --region us-west-2

# Skip S3 upload and notifications
python scripts/python/compliance_scanner.py --no-s3 --no-notification
```

**Features:**
- Analyzes Security Hub findings for compliance impact
- Calculates CIS and PCI DSS compliance scores (0-100%)
- Generates detailed reports with recommendations
- Integrates with existing S3 reporting infrastructure
- Sends notifications via SNS

### PowerShell Compliance Audit

Perform local compliance checks on Windows instances:

```powershell
# Run full compliance audit
.\scripts\powershell\compliance_audit.ps1 -IncludeCISChecks -IncludePCIChecks

# Upload results to S3
.\scripts\powershell\compliance_audit.ps1 -UploadToS3 -S3Bucket "my-reports-bucket" -S3Key "compliance/audit-report.json"

# Run specific compliance checks
.\scripts\powershell\compliance_audit.ps1 -IncludeCISChecks -IncludePCIChecks:$false
```

**Local Checks:**
- Windows security configuration
- Password policies and account lockout settings
- Anti-virus status and firewall configuration
- UAC settings and BitLocker status

## 🔧 Configuration

### Patch Approval Workflow

The system supports both manual and automated approval workflows:

**Manual Approval:**
- Review findings in AWS Console
- Update approved patches list in S3
- Trigger installation via Lambda or manual execution

**Automated Approval:**
- Lambda function processes Inspector findings
- Auto-approves patches based on CVSS score
- Updates patch baseline automatically

### Compliance Configuration

Configure compliance monitoring settings:

```json
{
  "compliance_settings": {
    "cis_benchmark": {
      "enabled": true,
      "severity_filter": ["CRITICAL", "HIGH"],
      "auto_remediation": false
    },
    "pci_dss": {
      "enabled": true,
      "severity_filter": ["CRITICAL", "HIGH"],
      "auto_remediation": false
    },
    "notification_thresholds": {
      "cis_score_warning": 80,
      "cis_score_critical": 60,
      "pci_score_warning": 80,
      "pci_score_critical": 60
    }
  }
}
```

### Customization

Edit `config/patch-config.json` to customize:
- CVSS thresholds for auto-approval
- Patch classifications to include/exclude
- Approval workflow settings
- Reporting schedules
- Compliance monitoring preferences

## 📊 Monitoring and Reporting

### Available Reports

1. **Vulnerability Report** - Inspector findings with severity levels
2. **Compliance Report** - CIS and PCI DSS compliance scores and violations
3. **Patch Compliance Report** - Installed vs. available patches
4. **Service Audit Report** - Running services and software inventory
5. **Approval Workflow Report** - Patch approval/rejection history
6. **Security Configuration Report** - Local security settings

### Accessing Reports

Reports are stored in S3 and can be accessed via:
- AWS Console (S3 bucket)
- Security Hub Console (compliance dashboard)
- QuickSight dashboards
- Athena queries
- API endpoints

### Compliance Dashboard

Access compliance information through:
1. **AWS Security Hub Console** → Compliance
2. **S3 Reports** - JSON format for programmatic access
3. **CloudWatch Metrics** - Custom metrics for compliance scores

## 🔒 Security

- All IAM roles follow least privilege principle
- Patch approvals require explicit authorization
- All activities are logged to CloudTrail
- Sensitive data is encrypted at rest and in transit
- Compliance data is protected with appropriate access controls

## 🛠️ Troubleshooting

See `docs/troubleshooting.md` for common issues and solutions.

### Common Compliance Issues

1. **Security Hub Not Enabled**
   ```bash
   aws securityhub enable-security-hub --region us-east-1
   ```

2. **Compliance Standards Not Subscribed**
   ```bash
   aws securityhub get-enabled-standards --region us-east-1
   ```

3. **Lambda Function Errors**
   ```bash
   aws logs tail /aws/lambda/SecurityHubProcessor-dev --region us-east-1
   ```

## 📈 Best Practices

### Compliance Management
- Run compliance scans weekly
- Review findings within 24 hours
- Remediate critical issues within 48 hours
- Maintain compliance runbooks and documentation

### Integration Best Practices
- Automate routine compliance checks
- Use Infrastructure as Code for configurations
- Set up comprehensive alerting and monitoring
- Generate executive summaries and detailed technical reports

## 📝 License

MIT License - see LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📞 Support

For issues and questions:
- Create an issue in this repository
- Check the troubleshooting guide
- Review the Security Hub integration guide
- Review AWS documentation for Inspector, Security Hub, and Patch Manager

## 🔗 Related Documentation

- [Security Hub Integration Guide](docs/security-hub-integration.md)
- [AWS Security Hub User Guide](https://docs.aws.amazon.com/securityhub/)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services/)
- [PCI DSS Requirements](https://www.pcisecuritystandards.org/document_library)
- [AWS Systems Manager Patch Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/patch-manager.html)
- [AWS Inspector User Guide](https://docs.aws.amazon.com/inspector/) #   A W S - A u t o m a t i o n - P a t c h i n g - a n d - R e p o r t i n g  
 