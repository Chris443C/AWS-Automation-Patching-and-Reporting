# Security Hub Integration Guide

## Overview

This guide explains how to integrate AWS Security Hub with CIS and PCI DSS compliance scanning into your existing AWS Automation Patching and Reporting solution. The enhanced solution provides comprehensive compliance monitoring alongside automated patching workflows.

## 🏗️ Enhanced Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   AWS Inspector │    │  Security Hub   │    │  Patch Manager  │
│   (Vulnerability│    │  (CIS & PCI     │    │  (Download Only)│
│   Detection)    │    │   Compliance)   │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │  Compliance     │
                    │  Scanner        │
                    │  (Python)       │
                    └─────────────────┘
                                 │
                    ┌─────────────────┐
                    │  Compliance     │
                    │  Audit          │
                    │  (PowerShell)   │
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

### CIS AWS Foundations Benchmark

The solution integrates with the CIS AWS Foundations Benchmark v1.2.0, which includes:

- **Identity and Access Management (Section 1)**
  - Root account usage restrictions
  - MFA enforcement
  - IAM password policies
  - Access key management

- **Logging and Monitoring (Section 2)**
  - CloudTrail configuration
  - AWS Config setup
  - S3 bucket logging
  - VPC flow logging

- **Networking (Section 3)**
  - VPC configuration
  - Security group rules
  - Network ACLs

### PCI DSS v3.2.1

The solution also supports PCI DSS compliance with requirements including:

- **Build and Maintain a Secure Network (Requirements 1-2)**
  - Firewall configuration
  - Vendor defaults management

- **Protect Cardholder Data (Requirements 3-4)**
  - Data encryption
  - Secure transmission

- **Maintain Vulnerability Management (Requirements 5-6)**
  - Anti-virus software
  - Security patches

- **Implement Strong Access Control (Requirements 7-8)**
  - Access restrictions
  - User identification

- **Regular Monitoring and Testing (Requirements 9-11)**
  - Audit trails
  - Vulnerability scanning

- **Maintain Information Security Policy (Requirement 12)**
  - Security policies
  - Risk assessment

## 🚀 Deployment

### Prerequisites

1. **AWS CLI** installed and configured
2. **PowerShell 5.1+** (for Windows instances)
3. **Python 3.8+** (for compliance scanning)
4. **AWS Systems Manager agent** installed on target instances

### Quick Deployment

```powershell
# Deploy with Security Hub integration
.\deploy_with_security_hub.ps1 -Environment "dev" -Region "us-east-1" -NotificationEmail "admin@company.com"

# Deploy with specific compliance standards
.\deploy_with_security_hub.ps1 -Environment "prod" -Region "us-west-2" -NotificationEmail "security@company.com" -EnableCISBenchmark -EnablePCIDSS

# Dry run to see what would be deployed
.\deploy_with_security_hub.ps1 -Environment "staging" -NotificationEmail "admin@company.com" -DryRun
```

### Manual Deployment Steps

1. **Deploy Main Infrastructure**
   ```bash
   aws cloudformation deploy \
     --template-file cloudformation/main-stack.yaml \
     --stack-name aws-patching-automation-dev \
     --capabilities CAPABILITY_NAMED_IAM \
     --parameter-overrides Environment=dev NotificationEmail=admin@company.com
   ```

2. **Deploy Security Hub Configuration**
   ```bash
   aws cloudformation deploy \
     --template-file cloudformation/security-hub-stack.yaml \
     --stack-name aws-security-hub-dev \
     --capabilities CAPABILITY_NAMED_IAM \
     --parameter-overrides Environment=dev EnableCISBenchmark=true EnablePCIDSS=true NotificationEmail=admin@company.com
   ```

3. **Enable Security Hub**
   ```bash
   aws securityhub enable-security-hub --region us-east-1
   ```

4. **Subscribe to Compliance Standards**
   ```bash
   # CIS AWS Foundations Benchmark
   aws securityhub batch-enable-standards \
     --standards-subscription-requests StandardsArn="arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.2.0" \
     --region us-east-1

   # PCI DSS
   aws securityhub batch-enable-standards \
     --standards-subscription-requests StandardsArn="arn:aws:securityhub:us-east-1::standards/pci-dss/v/3.2.1" \
     --region us-east-1
   ```

## 🔍 Compliance Scanning

### Python Compliance Scanner

The `compliance_scanner.py` script provides comprehensive Security Hub integration:

```bash
# Basic compliance scan
python scripts/python/compliance_scanner.py

# Scan with custom parameters
python scripts/python/compliance_scanner.py --days-back 60 --region us-west-2

# Skip S3 upload and notifications
python scripts/python/compliance_scanner.py --no-s3 --no-notification
```

**Features:**
- Analyzes Security Hub findings for CIS and PCI compliance impact
- Calculates compliance scores (0-100%)
- Generates detailed reports with recommendations
- Integrates with existing S3 reporting infrastructure
- Sends notifications via SNS

### PowerShell Compliance Audit

The `compliance_audit.ps1` script performs local compliance checks:

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
- Password policies
- Account lockout settings
- Anti-virus status
- Firewall configuration
- UAC settings
- BitLocker status

## 📊 Monitoring and Reporting

### Compliance Dashboard

Access compliance information through:

1. **AWS Security Hub Console**
   - Navigate to Security Hub → Compliance
   - View CIS and PCI DSS compliance scores
   - Review failed controls and requirements

2. **S3 Reports**
   - Compliance reports stored in S3 bucket
   - JSON format for programmatic access
   - Historical compliance tracking

3. **CloudWatch Metrics**
   - Custom metrics for compliance scores
   - Automated alerting on compliance violations
   - Trend analysis over time

### Automated Notifications

The solution provides automated notifications for:

- **Critical Compliance Violations**
  - CIS controls with CRITICAL severity
  - PCI requirements with HIGH impact
  - Security Hub findings requiring immediate attention

- **Compliance Score Changes**
  - Score drops below 80%
  - New compliance violations detected
  - Remediation progress updates

### Integration with Existing Workflows

The compliance scanning integrates seamlessly with your existing patching workflow:

1. **Security Hub Findings** → **Patch Approval**
   - Critical findings automatically trigger patch approval
   - Compliance violations linked to specific patches
   - Risk-based patch prioritization

2. **Compliance Audits** → **System Hardening**
   - Failed compliance checks generate hardening recommendations
   - Automated remediation scripts for common issues
   - Configuration drift detection

3. **Reporting** → **Executive Dashboards**
   - Consolidated compliance and patching reports
   - Risk assessment summaries
   - Audit trail for compliance activities

## 🛠️ Configuration

### Security Hub Controls

Configure which Security Hub controls to enable:

```json
{
  "security_hub_controls": {
    "cis_benchmark": {
      "enabled": true,
      "severity_filter": ["CRITICAL", "HIGH"],
      "auto_remediation": false
    },
    "pci_dss": {
      "enabled": true,
      "severity_filter": ["CRITICAL", "HIGH"],
      "auto_remediation": false
    }
  }
}
```

### Compliance Thresholds

Set compliance score thresholds for notifications:

```json
{
  "compliance_thresholds": {
    "cis_score_warning": 80,
    "cis_score_critical": 60,
    "pci_score_warning": 80,
    "pci_score_critical": 60
  }
}
```

### EventBridge Rules

The solution creates EventBridge rules to automatically process Security Hub findings:

```json
{
  "event_pattern": {
    "source": ["aws.securityhub"],
    "detail-type": ["Security Hub Findings - Imported"],
    "detail": {
      "findings": {
        "WorkflowStatus": ["NEW", "NOTIFIED"]
      }
    }
  }
}
```

## 🔧 Troubleshooting

### Common Issues

1. **Security Hub Not Enabled**
   ```bash
   # Check Security Hub status
   aws securityhub describe-hub --region us-east-1
   
   # Enable if needed
   aws securityhub enable-security-hub --region us-east-1
   ```

2. **Compliance Standards Not Subscribed**
   ```bash
   # List enabled standards
   aws securityhub get-enabled-standards --region us-east-1
   
   # Subscribe to standards
   aws securityhub batch-enable-standards --standards-subscription-requests StandardsArn="arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.2.0" --region us-east-1
   ```

3. **Lambda Function Errors**
   ```bash
   # Check Lambda logs
   aws logs describe-log-groups --log-group-name-prefix "/aws/lambda/SecurityHubProcessor" --region us-east-1
   
   # View recent logs
   aws logs tail /aws/lambda/SecurityHubProcessor-dev --region us-east-1
   ```

### Performance Optimization

1. **Batch Processing**
   - Process findings in batches to avoid API limits
   - Use pagination for large result sets
   - Implement exponential backoff for retries

2. **Caching**
   - Cache compliance control mappings
   - Store frequently accessed findings
   - Use CloudFront for S3 report distribution

3. **Monitoring**
   - Set up CloudWatch alarms for Lambda errors
   - Monitor API call rates and limits
   - Track compliance scan performance

## 📈 Best Practices

### Compliance Management

1. **Regular Assessments**
   - Run compliance scans weekly
   - Review findings within 24 hours
   - Remediate critical issues within 48 hours

2. **Documentation**
   - Maintain compliance runbooks
   - Document remediation procedures
   - Keep audit trails for all changes

3. **Training**
   - Train teams on compliance requirements
   - Regular security awareness sessions
   - Update procedures based on findings

### Integration Best Practices

1. **Automation**
   - Automate routine compliance checks
   - Use Infrastructure as Code for configurations
   - Implement automated remediation where safe

2. **Monitoring**
   - Set up comprehensive alerting
   - Monitor compliance trends over time
   - Track remediation effectiveness

3. **Reporting**
   - Generate executive summaries
   - Provide detailed technical reports
   - Maintain historical compliance data

## 🔗 Related Documentation

- [AWS Security Hub User Guide](https://docs.aws.amazon.com/securityhub/)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services/)
- [PCI DSS Requirements](https://www.pcisecuritystandards.org/document_library)
- [AWS Systems Manager Patch Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/patch-manager.html)
- [AWS Inspector User Guide](https://docs.aws.amazon.com/inspector/)

## 📞 Support

For issues and questions:

1. **Check the troubleshooting guide** in this documentation
2. **Review AWS documentation** for Security Hub and compliance standards
3. **Create an issue** in this repository
4. **Contact AWS Support** for Security Hub-specific issues

---

*This guide covers the Security Hub integration for the AWS Automation Patching and Reporting solution. For the complete solution documentation, see the main README.md file.* 