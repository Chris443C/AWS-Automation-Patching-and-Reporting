# AWS Config Integration for Compliance Automation

## Overview

This document explains how AWS Config is integrated into the AWS Automation Patching and Reporting solution to provide **rule-based compliance checks** that complement the existing Security Hub CIS/PCI scanning and local instance auditing.

## 🔍 **What AWS Config Does in This Solution**

AWS Config provides **continuous compliance monitoring** through rule-based checks that evaluate your AWS resources against security and compliance standards. Unlike Security Hub (which focuses on vulnerability scanning) or local scripts (which check instance-level configurations), AWS Config monitors **infrastructure-level compliance** in real-time.

### **Key Capabilities:**

1. **Real-time Compliance Monitoring**: Continuously monitors AWS resources for compliance violations
2. **Custom Compliance Rules**: Defines specific rules for patching automation and security requirements
3. **Automated Remediation**: Triggers notifications and actions when compliance violations are detected
4. **Integration with Existing Tools**: Works alongside Security Hub and local compliance scripts

## 🏗️ **Architecture Overview**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   AWS Config    │    │  Security Hub   │    │ Local Scripts   │
│   (Infrastructure│    │  (Vulnerability │    │ (Instance-level │
│   Compliance)    │    │   Scanning)     │    │   Compliance)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Compliance Integration Layer                 │
│  • Config Compliance Processor                                  │
│  • Security Hub Findings Analyzer                               │
│  • Local Compliance Aggregator                                  │
└─────────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Unified Compliance Dashboard                 │
│  • Combined compliance scores                                   │
│  • Cross-referenced violations                                  │
│  • Automated remediation triggers                               │
└─────────────────────────────────────────────────────────────────┘
```

## 📋 **AWS Config Rules Deployed**

### **Patching-Related Rules:**

1. **SSMAgentInstalled**
   - **Purpose**: Ensures EC2 instances have SSM agent installed for patch management
   - **CIS Control**: 1.19 (Ensure IAM instance roles are used)
   - **PCI Requirement**: 7.1 (Limit access to system components)
   - **Impact**: Critical for patch automation workflow

2. **PatchCompliance**
   - **Purpose**: Monitors if instances are compliant with patch baseline
   - **CIS Control**: 6.2 (Ensure all system components are protected)
   - **PCI Requirement**: 6.2 (Ensure all system components are protected)
   - **Impact**: Direct patch compliance status

3. **PatchApprovalWorkflow**
   - **Purpose**: Validates patch approval workflow configuration
   - **CIS Control**: 6.4 (Follow change control processes)
   - **PCI Requirement**: 6.4 (Follow change control processes)
   - **Impact**: Ensures proper change management

### **Security-Related Rules:**

4. **SecurityGroupRestrictedAccess**
   - **Purpose**: Checks if security groups allow unrestricted access
   - **CIS Controls**: 3.1, 3.2 (VPC and security group controls)
   - **PCI Requirements**: 1.1, 1.2 (Firewall and router configuration)
   - **Impact**: Network security compliance

5. **S3BucketEncryption**
   - **Purpose**: Ensures S3 buckets have encryption enabled
   - **CIS Control**: 2.7 (CloudTrail encryption)
   - **PCI Requirement**: 3.4 (Render PAN unreadable)
   - **Impact**: Data protection compliance

6. **CloudTrailEnabled**
   - **Purpose**: Verifies CloudTrail is enabled for audit logging
   - **CIS Controls**: 2.1, 2.4 (CloudTrail configuration)
   - **PCI Requirements**: 10.1, 10.2 (Audit trails)
   - **Impact**: Audit and logging compliance

## 🔧 **Custom Lambda-Based Rules**

### **PatchApprovalWorkflowRule**

This custom rule uses a Lambda function to evaluate:

- **Patch Baseline Configuration**: Checks if approval rules are properly configured
- **Maintenance Window Setup**: Validates maintenance window configuration
- **Change Control Process**: Ensures proper change management procedures

```python
def check_patch_baseline_compliance(configuration_item):
    """Check if patch baseline is properly configured"""
    baseline_config = configuration_item.get('configuration', {})
    approval_rules = baseline_config.get('ApprovalRules', {})
    
    if not approval_rules:
        return {
            'ComplianceType': 'NON_COMPLIANT',
            'Annotation': 'Patch baseline must have approval rules configured'
        }
    
    return {
        'ComplianceType': 'COMPLIANT',
        'Annotation': 'Patch baseline is properly configured with approval rules'
    }
```

## 📊 **Compliance Scoring and Reporting**

### **Multi-Layer Compliance Scoring:**

1. **Config Compliance Score**: Based on AWS Config rule evaluations
2. **Security Hub Score**: Based on CIS/PCI findings
3. **Local Compliance Score**: Based on instance-level checks
4. **Combined Score**: Weighted average of all three scores

### **Compliance Report Structure:**

```json
{
  "report_timestamp": "2024-01-15T10:30:00Z",
  "environment": "prod",
  "compliance_scores": {
    "config_score": 85.5,
    "security_hub_score": 92.3,
    "local_score": 78.9,
    "overall_score": 87.2
  },
  "config_rules": {
    "SSMAgentInstalled": {
      "compliance_summary": {
        "compliant": 45,
        "non_compliant": 3,
        "not_applicable": 0
      },
      "resources": [...]
    }
  },
  "cis_violations": [...],
  "pci_violations": [...],
  "recommendations": [...]
}
```

## 🔄 **Integration with Existing Components**

### **1. Security Hub Integration**

AWS Config findings are cross-referenced with Security Hub findings:

```python
def map_config_to_cis_pci(compliance_results):
    """Map Config rule violations to CIS controls and PCI requirements"""
    for rule_name, rule_data in compliance_results.items():
        mapping = rule_data.get('mapping', {})
        cis_controls = mapping.get('cis_controls', [])
        pci_requirements = mapping.get('pci_requirements', [])
        
        # Map violations to compliance frameworks
        for resource in non_compliant_resources:
            for control_id in cis_controls:
                cis_violations.append({
                    'control_id': control_id,
                    'config_rule': rule_name,
                    'resource_id': resource.get('resource_id'),
                    'annotation': resource.get('annotation')
                })
```

### **2. Patching Automation Integration**

Config violations can trigger patching workflow adjustments:

```python
def get_patching_related_violations():
    """Get violations specifically related to patching automation"""
    patching_violations = {
        'ssm_agent_issues': [],
        'patch_compliance_issues': [],
        'approval_workflow_issues': []
    }
    
    # Check patching-related Config rules
    compliance_results = get_config_compliance_status(patching_config_rules)
    
    for rule_name, rule_data in compliance_results.items():
        non_compliant_resources = [
            resource for resource in rule_data.get('resources', [])
            if resource.get('compliance_type') == 'NON_COMPLIANT'
        ]
        
        if rule_name == 'SSMAgentInstalled':
            patching_violations['ssm_agent_issues'] = non_compliant_resources
        elif rule_name == 'PatchCompliance':
            patching_violations['patch_compliance_issues'] = non_compliant_resources
```

### **3. Notification Integration**

Config compliance changes trigger notifications:

```python
def send_config_compliance_notification(report):
    """Send Config compliance notification via SNS"""
    subject = f"AWS Config Compliance Alert - {report['config_rule_name']}"
    
    message = f"""
AWS Config Compliance Alert

Environment: {report['environment']}
Config Rule: {report['config_rule_name']}
Resource Type: {report['resource_type']}
Resource ID: {report['resource_id']}
Compliance Status: {report['compliance_type']}

Details: {report['annotation']}
    """
    
    sns.publish(
        TopicArn=sns_topic_arn,
        Subject=subject,
        Message=message
    )
```

## 🚀 **Deployment and Configuration**

### **Deployment Options:**

1. **Full Deployment** (Default):
   ```powershell
   .\deploy.ps1 -Environment prod -NotificationEmail admin@company.com
   ```

2. **Skip Config Deployment**:
   ```powershell
   .\deploy.ps1 -Environment prod -NotificationEmail admin@company.com -SkipConfig
   ```

3. **Dry Run**:
   ```powershell
   .\deploy.ps1 -Environment prod -NotificationEmail admin@company.com -DryRun
   ```

### **Configuration Parameters:**

- **Environment**: Environment name (dev, staging, prod)
- **NotificationEmail**: Email for compliance notifications
- **S3BucketName**: S3 bucket for Config logs and reports

## 📈 **Monitoring and Alerting**

### **Real-time Monitoring:**

1. **Config Compliance Changes**: EventBridge captures compliance state changes
2. **Automated Notifications**: SNS sends alerts for non-compliant resources
3. **S3 Logging**: All compliance reports stored in S3 for audit

### **Dashboard Integration:**

```python
def generate_config_compliance_report(compliance_results, compliance_scores, cis_pci_mapping):
    """Generate comprehensive Config compliance report"""
    report = {
        'report_timestamp': datetime.now().isoformat(),
        'environment': environment,
        'compliance_scores': compliance_scores,
        'config_rules': compliance_results,
        'cis_violations': cis_pci_mapping.get('cis_violations', []),
        'pci_violations': cis_pci_mapping.get('pci_violations', []),
        'recommendations': generate_recommendations(compliance_results)
    }
    
    return report
```

## 🔍 **Troubleshooting**

### **Common Issues:**

1. **Config Rules Not Found**:
   - Ensure Config stack is deployed successfully
   - Check rule naming convention: `{RuleName}-{Environment}`
   - Verify IAM permissions for Config service

2. **Compliance Evaluations Failing**:
   - Check Lambda function logs for custom rules
   - Verify resource types are supported
   - Review Config service quotas

3. **Notifications Not Working**:
   - Verify SNS topic ARN is correct
   - Check SNS subscription is confirmed
   - Review IAM permissions for SNS publishing

### **Debugging Commands:**

```bash
# Check Config rules status
aws configservice describe-config-rules --region us-east-1

# Get compliance details for specific rule
aws configservice get-compliance-details-by-config-rule \
    --config-rule-name SSMAgentInstalled-prod

# Check Config recorder status
aws configservice describe-configuration-recorders --region us-east-1

# View Lambda function logs
aws logs describe-log-groups --log-group-name-prefix "/aws/lambda/CustomConfigRule"
```

## 📚 **Best Practices**

### **1. Rule Design:**

- **Specific and Measurable**: Rules should have clear pass/fail criteria
- **Performance Optimized**: Avoid rules that impact resource performance
- **Well Documented**: Include clear descriptions and remediation steps

### **2. Monitoring Strategy:**

- **Real-time Alerts**: Set up immediate notifications for critical violations
- **Regular Reviews**: Schedule weekly compliance reviews
- **Trend Analysis**: Track compliance trends over time

### **3. Integration Approach:**

- **Layered Defense**: Use Config alongside Security Hub and local scripts
- **Automated Remediation**: Implement automated fixes where possible
- **Continuous Improvement**: Regularly update rules based on new requirements

## 🔗 **Related Documentation**

- [Security Hub Integration](./security-hub-integration.md)
- [Local Compliance Scripts](./local-compliance-scripts.md)
- [Deployment Guide](./deployment-guide.md)
- [Troubleshooting Guide](./troubleshooting-guide.md)

## 📞 **Support**

For issues with AWS Config integration:

1. Check CloudWatch logs for Lambda functions
2. Review Config service quotas and limits
3. Verify IAM permissions and roles
4. Consult AWS Config documentation
5. Contact your AWS support team if needed 