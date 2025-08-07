# AWS Audit Manager Integration for Compliance Automation

## Overview

This document explains how AWS Audit Manager is integrated into the AWS Automation Patching and Reporting solution to provide **automated evidence collection and assessment workflows** that complement the existing Security Hub, AWS Config, and local compliance monitoring.

## 🔍 **What AWS Audit Manager Adds to This Solution**

AWS Audit Manager provides **automated compliance assessment workflows** that:

- **Automatically collect evidence** from AWS services (Config, Security Hub, Inspector)
- **Map evidence to compliance controls** in pre-built frameworks (CIS, PCI, SOC, HIPAA)
- **Generate assessment reports** with compliance scores and recommendations
- **Provide audit trails** for compliance documentation
- **Support multiple compliance frameworks** simultaneously

### **Key Capabilities:**

1. **Automated Evidence Collection**: Gathers evidence from AWS Config, Security Hub, and Inspector
2. **Framework Mapping**: Maps evidence to CIS, PCI, SOC, HIPAA, and ISO 27001 controls
3. **Assessment Workflows**: Creates and manages compliance assessments
4. **Evidence Management**: Organizes and stores compliance evidence
5. **Reporting**: Generates comprehensive compliance reports

## 🏗️ **Architecture Overview**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   AWS Config    │    │  Security Hub   │    │ AWS Inspector   │
│   (Infrastructure│    │  (CIS & PCI     │    │  (Vulnerability │
│   Compliance)    │    │   Compliance)   │    │   Detection)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │  Audit Manager  │
                    │  Integration    │
                    │  (Evidence      │
                    │   Collection)   │
                    └─────────────────┘
                                 │
                    ┌─────────────────┐
                    │  Audit Manager  │
                    │  Assessment     │
                    │  Workflow       │
                    └─────────────────┘
                                 │
                    ┌─────────────────┐
                    │  Compliance     │
                    │  Reports &      │
                    │  Documentation  │
                    └─────────────────┘
```

## 📋 **Audit Manager Components Deployed**

### **1. Evidence Collection Infrastructure**

- **S3 Bucket**: Stores audit reports and evidence files
- **Lambda Functions**: Automate evidence collection and assessment workflows
- **EventBridge Rules**: Schedule automated assessments
- **SNS Notifications**: Alert on assessment completion

### **2. Supported Compliance Frameworks**

- **CIS AWS Foundations Benchmark**: Cloud security best practices
- **PCI DSS**: Payment card industry compliance
- **SOC 2**: Service organization controls
- **HIPAA**: Healthcare data protection
- **ISO 27001**: Information security management

### **3. Evidence Sources Integrated**

- **AWS Config**: Infrastructure compliance evidence
- **Security Hub**: Vulnerability and CIS/PCI findings
- **AWS Inspector**: Vulnerability scan results
- **Custom Scripts**: Instance-level compliance data

## 🔧 **Evidence Collection Process**

### **Automated Evidence Collection:**

```python
def collect_evidence_from_config(assessment_id):
    """Collect evidence from AWS Config"""
    evidence_collection = {
        'source': 'AWS Config',
        'timestamp': datetime.now().isoformat(),
        'evidence_items': []
    }
    
    # Get Config rules and compliance evaluations
    rules_response = config.describe_config_rules()
    
    for rule in rules_response.get('ConfigRules', []):
        compliance_response = config.get_compliance_details_by_config_rule(
            ConfigRuleName=rule.get('ConfigRuleName')
        )
        
        for evaluation in compliance_response.get('EvaluationResults', []):
            evidence_item = {
                'rule_name': rule.get('ConfigRuleName'),
                'resource_id': evaluation.get('ResourceId'),
                'compliance_type': evaluation.get('ComplianceType'),
                'timestamp': evaluation.get('ResultRecordedTime'),
                'annotation': evaluation.get('Annotation', ''),
                'evidence_type': 'AWS Config Rule Evaluation'
            }
            
            evidence_collection['evidence_items'].append(evidence_item)
    
    return evidence_collection
```

### **Evidence Upload to Audit Manager:**

```python
def upload_evidence_to_audit_manager(assessment_id, evidence_collections):
    """Upload evidence to Audit Manager"""
    for collection in evidence_collections:
        for evidence_item in collection.get('evidence_items', []):
            auditmanager.create_evidence(
                assessmentId=assessment_id,
                evidenceFolderId=default_folder_id,
                dataSource=collection.get('source', 'Unknown'),
                evidenceByType='Manual',
                content=json.dumps(evidence_item),
                name=f"{collection.get('source')} - {evidence_item.get('evidence_type')}",
                description=evidence_item.get('description', 'Automated evidence collection')
            )
```

## 📊 **Assessment Workflow**

### **1. Assessment Creation**

```python
def create_assessment(framework_id, assessment_name):
    """Create a new compliance assessment"""
    response = auditmanager.create_assessment(
        name=assessment_name,
        assessmentReportsDestination={
            'destination': 's3',
            'destinationType': 'S3'
        },
        frameworkId=framework_id,
        description=f'Automated compliance assessment for {environment} environment',
        scope={
            'awsAccounts': [
                {
                    'id': account_id,
                    'emailAddress': notification_email
                }
            ]
        }
    )
    
    return response.get('assessment', {}).get('id')
```

### **2. Evidence Collection Workflow**

1. **Trigger Assessment**: Manual or scheduled (weekly)
2. **Collect Evidence**: From Config, Security Hub, Inspector
3. **Upload Evidence**: To Audit Manager assessment
4. **Generate Report**: Compliance metrics and recommendations
5. **Send Notifications**: Assessment completion alerts

### **3. Compliance Scoring**

```python
def calculate_compliance_metrics(evidence_by_control):
    """Calculate compliance metrics from evidence"""
    total_controls = len(evidence_by_control)
    compliant_controls = 0
    non_compliant_controls = 0
    
    for control in evidence_by_control:
        control_status = control.get('controlStatus', '')
        if control_status == 'COMPLIANT':
            compliant_controls += 1
        elif control_status == 'NON_COMPLIANT':
            non_compliant_controls += 1
    
    compliance_score = 0
    if total_controls > 0:
        compliance_score = (compliant_controls / total_controls) * 100
    
    return {
        'total_controls': total_controls,
        'compliant_controls': compliant_controls,
        'non_compliant_controls': non_compliant_controls,
        'compliance_score': round(compliance_score, 2)
    }
```

## 🔄 **Integration with Existing Components**

### **1. Security Hub Integration**

Audit Manager collects Security Hub findings as evidence:

```python
def collect_evidence_from_security_hub(assessment_id):
    """Collect evidence from Security Hub"""
    findings_response = securityhub.get_findings(
        MaxResults=100,
        Filters={
            'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]
        }
    )
    
    for finding in findings_response.get('Findings', []):
        evidence_item = {
            'finding_id': finding.get('Id'),
            'severity': finding.get('Severity', {}).get('Label'),
            'compliance_status': finding.get('Compliance', {}).get('Status'),
            'timestamp': finding.get('CreatedAt', '').isoformat(),
            'title': finding.get('Title', ''),
            'description': finding.get('Description', ''),
            'evidence_type': 'Security Hub Finding'
        }
        
        evidence_collection['evidence_items'].append(evidence_item)
```

### **2. AWS Config Integration**

Config rule evaluations become Audit Manager evidence:

```python
def collect_evidence_from_config(assessment_id):
    """Collect evidence from AWS Config"""
    rules_response = config.describe_config_rules()
    
    for rule in rules_response.get('ConfigRules', []):
        compliance_response = config.get_compliance_details_by_config_rule(
            ConfigRuleName=rule.get('ConfigRuleName')
        )
        
        for evaluation in compliance_response.get('EvaluationResults', []):
            evidence_item = {
                'rule_name': rule.get('ConfigRuleName'),
                'resource_id': evaluation.get('ResourceId'),
                'compliance_type': evaluation.get('ComplianceType'),
                'timestamp': evaluation.get('ResultRecordedTime'),
                'evidence_type': 'AWS Config Rule Evaluation'
            }
```

### **3. Inspector Integration**

Vulnerability findings are collected as evidence:

```python
def collect_evidence_from_inspector(assessment_id):
    """Collect evidence from AWS Inspector"""
    findings_response = inspector.list_findings(maxResults=100)
    
    for finding in findings_response.get('findings', []):
        evidence_item = {
            'finding_arn': finding.get('findingArn'),
            'severity': finding.get('severity'),
            'status': finding.get('status'),
            'timestamp': finding.get('updatedAt', '').isoformat(),
            'title': finding.get('title', ''),
            'description': finding.get('description', ''),
            'evidence_type': 'Inspector Finding'
        }
```

## 🚀 **Deployment and Configuration**

### **Deployment Options:**

1. **Full Deployment** (Default):
   ```powershell
   .\deploy.ps1 -Environment prod -NotificationEmail admin@company.com
   ```

2. **Skip Audit Manager Deployment**:
   ```powershell
   .\deploy.ps1 -Environment prod -NotificationEmail admin@company.com -SkipAuditManager
   ```

3. **Deploy Only Audit Manager**:
   ```powershell
   .\deploy.ps1 -Environment dev -NotificationEmail admin@company.com -SkipInspector -SkipPatchManager -SkipSecurityHub -SkipConfig
   ```

### **Configuration Parameters:**

- **Environment**: Environment name (dev, staging, prod)
- **NotificationEmail**: Email for audit notifications
- **S3BucketName**: S3 bucket for audit reports
- **ComplianceFrameworks**: List of frameworks to enable
- **AssessmentName**: Name for automated assessments

## 📈 **Usage Examples**

### **Run Automated Assessment:**

```bash
# Run assessment with default framework
python scripts/python/audit_manager_integration.py

# Run assessment with specific framework
python scripts/python/audit_manager_integration.py --framework "CIS AWS Foundations Benchmark"

# Run assessment with custom name
python scripts/python/audit_manager_integration.py --assessment-name "Q4 2024 Compliance Review"
```

### **List Available Frameworks:**

```bash
python scripts/python/audit_manager_integration.py --list-frameworks
```

### **List Existing Assessments:**

```bash
python scripts/python/audit_manager_integration.py --list-assessments
```

## 📊 **Assessment Reports**

### **Report Structure:**

```json
{
  "report_timestamp": "2024-01-15T10:30:00Z",
  "environment": "prod",
  "assessment_id": "assessment-1234567890",
  "assessment_name": "Automated Compliance Assessment - prod - 20240115",
  "framework": "CIS AWS Foundations Benchmark",
  "assessment_status": "ACTIVE",
  "compliance_metrics": {
    "total_controls": 45,
    "compliant_controls": 38,
    "non_compliant_controls": 7,
    "compliance_score": 84.44
  },
  "evidence_summary": {
    "total_evidence_items": 156,
    "evidence_sources": ["AWS Config", "Security Hub", "AWS Inspector"]
  },
  "s3_location": "s3://bucket/audit-reports/audit_manager_report_prod_20240115_103000.json"
}
```

### **Compliance Metrics:**

- **Total Controls**: Number of controls in the framework
- **Compliant Controls**: Controls that meet compliance requirements
- **Non-Compliant Controls**: Controls that fail compliance requirements
- **Compliance Score**: Percentage of compliant controls (0-100%)

## 🔍 **Troubleshooting**

### **Common Issues:**

1. **No Frameworks Available**:
   - Ensure Audit Manager is enabled in your AWS account
   - Check if frameworks are available in your region
   - Verify IAM permissions for Audit Manager

2. **Evidence Collection Fails**:
   - Check Lambda function logs for errors
   - Verify source services (Config, Security Hub, Inspector) are enabled
   - Review IAM permissions for evidence collection

3. **Assessment Creation Fails**:
   - Verify framework ID is correct
   - Check assessment name uniqueness
   - Review S3 bucket permissions

### **Debugging Commands:**

```bash
# Check Audit Manager frameworks
aws auditmanager list-assessment-frameworks --framework-type Standard

# List existing assessments
aws auditmanager list-assessments

# Get assessment details
aws auditmanager get-assessment --assessment-id assessment-1234567890

# Check Lambda function logs
aws logs describe-log-groups --log-group-name-prefix "/aws/lambda/AuditManagerIntegration"
```

## 📚 **Best Practices**

### **1. Assessment Planning:**

- **Regular Schedule**: Run assessments weekly or monthly
- **Framework Selection**: Choose frameworks relevant to your compliance needs
- **Evidence Review**: Regularly review collected evidence for accuracy

### **2. Evidence Management:**

- **Source Integration**: Ensure all relevant AWS services are integrated
- **Evidence Quality**: Verify evidence is accurate and up-to-date
- **Storage**: Use S3 lifecycle policies for evidence retention

### **3. Reporting Strategy:**

- **Automated Reports**: Schedule regular report generation
- **Stakeholder Notifications**: Send reports to relevant teams
- **Trend Analysis**: Track compliance trends over time

## 🔗 **Related Documentation**

- [Security Hub Integration](./security-hub-integration.md)
- [AWS Config Integration](./aws-config-integration.md)
- [Local Compliance Scripts](./local-compliance-scripts.md)
- [Deployment Guide](./deployment-guide.md)
- [Troubleshooting Guide](./troubleshooting-guide.md)

## 📞 **Support**

For issues with AWS Audit Manager integration:

1. Check CloudWatch logs for Lambda functions
2. Review Audit Manager service quotas and limits
3. Verify IAM permissions and roles
4. Consult AWS Audit Manager documentation
5. Contact your AWS support team if needed 