# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common Commands

### Deployment Commands
```powershell
# Full deployment with all components
.\deploy.ps1 -Environment "dev" -NotificationEmail "admin@example.com"

# Deploy with specific components disabled  
.\deploy.ps1 -Environment "dev" -NotificationEmail "admin@example.com" -SkipConfig -SkipSecurityHub

# Dry run to preview deployment
.\deploy.ps1 -Environment "dev" -NotificationEmail "admin@example.com" -DryRun
```

### Python Script Execution
```bash
# Run compliance scanner
python scripts/python/compliance_scanner.py

# Run with custom parameters
python scripts/python/compliance_scanner.py --days-back 60 --region us-west-2

# Run AWS Config compliance integration
python scripts/python/config_compliance_integration.py --patching-only

# Run Audit Manager integration
python scripts/python/audit_manager_integration.py --framework "CIS AWS Foundations Benchmark"
```

### PowerShell Script Execution
```powershell
# Run full compliance audit
.\scripts\powershell\compliance_audit.ps1 -IncludeCISChecks -IncludePCIChecks

# Upload audit results to S3
.\scripts\powershell\compliance_audit.ps1 -UploadToS3 -S3Bucket "my-reports-bucket"
```

### AWS CLI Commands for Manual Deployment
```bash
# Deploy main stack
aws cloudformation deploy --template-file cloudformation/main-stack.yaml --stack-name aws-patching-automation --capabilities CAPABILITY_NAMED_IAM

# Deploy Inspector stack
aws cloudformation deploy --template-file cloudformation/inspector-stack.yaml --stack-name aws-inspector-setup

# Deploy Security Hub stack
aws cloudformation deploy --template-file cloudformation/security-hub-stack.yaml --stack-name aws-security-hub --capabilities CAPABILITY_NAMED_IAM
```

## Architecture Overview

This is a comprehensive AWS-native solution for automated vulnerability scanning, patch management, and compliance monitoring that integrates:

- **AWS Inspector** - Vulnerability detection and scanning
- **Security Hub** - CIS & PCI DSS compliance monitoring with automated findings aggregation
- **AWS Config** - Rule-based infrastructure compliance monitoring
- **AWS Audit Manager** - Automated evidence collection and assessment workflows
- **Systems Manager Patch Manager** - Controlled patch deployment with approval workflows
- **Custom Python Scripts** - Compliance analysis, reporting, and automation
- **PowerShell Scripts** - Local Windows instance auditing and configuration checks

### Multi-Layer Compliance Architecture

The solution implements a four-layer compliance monitoring approach:

1. **AWS Audit Manager Layer** - Automated evidence collection mapping to CIS, PCI, SOC, HIPAA, ISO 27001
2. **AWS Config Rules Layer** - Real-time infrastructure compliance (SSM agents, patch compliance, security groups)  
3. **Security Hub Layer** - Vulnerability scanning and CIS/PCI compliance findings
4. **Local Scripts Layer** - Instance-level configuration and security auditing

### Key Components

- **CloudFormation Stacks** (`cloudformation/`) - Infrastructure as Code for all AWS services
- **Python Automation** (`scripts/python/`) - Compliance scanning, patch approval, and AWS service integration
- **PowerShell Scripts** (`scripts/powershell/`) - Windows instance auditing and compliance checks
- **Lambda Functions** (`lambda/`) - Event-driven processing for Inspector, Security Hub, Config, and Audit Manager
- **Configuration** (`config/patch-config.json`) - Centralized configuration for thresholds, schedules, and workflows

### Data Flow Pattern

Inspector/Security Hub/Config → Audit Manager → Python Integration Scripts → Approval Workflow → Patch Manager → Reporting (S3/SNS)

## Configuration Management

The solution uses a hybrid configuration approach:
- **Central Config** - `config/patch-config.json` for main settings, thresholds, and schedules
- **SSM Parameter Store** - Runtime configuration and sensitive settings
- **Environment Variables** - Environment-specific overrides in deployment scripts

Key configuration patterns:
- CVSS score thresholds for auto-approval (default: 8.0)
- Patch classifications by OS (Windows: SecurityUpdates, CriticalUpdates; Linux: Security, Bugfix)
- Compliance severity levels with auto-approval rules
- Maintenance window schedules (scan: 2 AM, install: 4 AM)
- Multi-environment support (dev/staging/prod) with different approval workflows

## Security and Compliance Standards

The solution implements comprehensive compliance monitoring for:
- **CIS AWS Foundations Benchmark v1.2.0** - 50+ controls covering IAM, logging, networking
- **PCI DSS v3.2.1** - Payment card industry requirements across 6 domains
- **AWS Config Rules** - Custom infrastructure compliance rules for patching automation
- **Evidence-Based Compliance** - Automated evidence collection through Audit Manager

## Development Patterns

When working with this codebase:

1. **Environment Management** - All components support dev/staging/prod environments via parameter overrides
2. **Error Handling** - Python scripts use comprehensive logging and graceful failure handling
3. **AWS Service Integration** - Consistent boto3 client patterns with region and credential management
4. **Reporting Architecture** - Standardized S3 storage with JSON/CSV formats and lifecycle policies
5. **Approval Workflows** - Support for both manual and automated patch approval based on CVSS scores
6. **Multi-OS Support** - Separate handling for Windows and Linux patching with OS-specific configurations

The solution follows AWS Well-Architected principles with least privilege IAM roles, encryption at rest and in transit, and comprehensive audit logging through CloudTrail.