# AWS Patching Automation - API Documentation

## Overview

This document describes the APIs and interfaces for the AWS Patching Automation system, including microservices, workflows, and event schemas.

## Microservices APIs

### Compliance Scanner Microservice

**Function Name:** `compliance-scanner-microservice-{environment}`

**Purpose:** Scans for compliance violations across CIS, PCI DSS, and SOC2 frameworks.

#### Input Schema

```json
{
  "scanType": "string",           // "full", "targeted", "reassessment"
  "daysBack": "number",           // Days to look back for findings (default: 7)
  "frameworks": ["string"]        // ["CIS", "PCI_DSS", "SOC2"] (optional)
}
```

#### Output Schema

```json
{
  "status": "string",             // "completed", "failed"
  "correlation_id": "string",     // Unique request identifier
  "findings_count": "number",     // Total findings processed
  "violations_count": "number",   // Number of violations found
  "compliance_score": "number",   // Overall compliance score (0-100)
  "scan_timestamp": "string"      // ISO 8601 timestamp
}
```

#### Example Usage

```python
import boto3

lambda_client = boto3.client('lambda')

response = lambda_client.invoke(
    FunctionName='compliance-scanner-microservice-prod',
    Payload=json.dumps({
        "scanType": "targeted",
        "daysBack": 14,
        "frameworks": ["CIS", "PCI_DSS"]
    })
)

result = json.loads(response['Payload'].read())
```

---

### Vulnerability Scanner Microservice

**Function Name:** `vulnerability-scanner-microservice-{environment}`

**Purpose:** Scans for vulnerabilities using AWS Inspector v2 and correlates with available patches.

#### Input Schema

```json
{
  "scanType": "string",           // "patches", "targeted"
  "daysBack": "number",           // Days to look back (default: 7)
  "includeInspector": "boolean",  // Include Inspector findings (default: true)
  "includePatches": "boolean"     // Include patch correlation (default: true)
}
```

#### Output Schema

```json
{
  "status": "string",             // "completed", "failed"
  "correlation_id": "string",     // Unique request identifier
  "vulnerabilities_count": "number",
  "patches_count": "number",
  "critical_vulnerabilities": "number",
  "high_vulnerabilities": "number",
  "scan_timestamp": "string"
}
```

#### Example Usage

```python
response = lambda_client.invoke(
    FunctionName='vulnerability-scanner-microservice-prod',
    Payload=json.dumps({
        "scanType": "targeted",
        "daysBack": 1,
        "includeInspector": true,
        "includePatches": true
    })
)
```

---

## Step Functions Workflows

### Patch Approval Workflow

**State Machine Name:** `patch-approval-workflow-{environment}`

**Purpose:** Orchestrates vulnerability assessment, patch approval, and notification processes.

#### Input Schema

```json
{
  "correlation_id": "string",
  "detail-type": "string",        // Event type from EventBridge
  "detail": {
    "vulnerability_count": "number",
    "critical_count": "number",
    "high_count": "number"
  }
}
```

#### Execution Flow

1. **ValidateInput** - Validates and structures input data
2. **ScanVulnerabilities** - Invokes vulnerability scanner
3. **EvaluateVulnerabilities** - Routes based on severity
4. **ProcessCriticalVulnerabilities** - Auto-approves critical patches
5. **ProcessStandardVulnerabilities** - Standard approval process
6. **PublishApprovalEvents** - Publishes results to EventBridge

#### Example Execution

```python
stepfunctions = boto3.client('stepfunctions')

response = stepfunctions.start_execution(
    stateMachineArn='arn:aws:states:us-east-1:123456789012:stateMachine:patch-approval-workflow-prod',
    name='patch-approval-2024-01-15',
    input=json.dumps({
        "correlation_id": "uuid-12345",
        "detail-type": "Critical Vulnerabilities Detected",
        "detail": {
            "vulnerability_count": 15,
            "critical_count": 3,
            "high_count": 7
        }
    })
)
```

---

### Compliance Remediation Workflow

**State Machine Name:** `compliance-remediation-workflow-{environment}`

**Purpose:** Automates compliance violation remediation and reassessment.

#### Input Schema

```json
{
  "correlation_id": "string",
  "compliance_score": "number",   // Current compliance score
  "violations": ["object"]        // Array of violation details
}
```

#### Key States

- **AnalyzeCompliance** - Detailed compliance analysis
- **InitiateCriticalRemediation** - Emergency remediation for low scores
- **ScheduleReassessment** - Wait period before re-evaluation
- **PublishRemediationResults** - Results to EventBridge

---

### Patch Installation Workflow

**State Machine Name:** `patch-installation-workflow-{environment}`

**Purpose:** Manages batch patch installation with rollback capabilities.

#### Input Schema

```json
{
  "correlation_id": "string",
  "approved_patches": ["object"]  // Array of approved patch objects
}
```

#### Key Features

- **Batch Processing** - Processes patches in configurable batches
- **Snapshot Creation** - Creates system snapshots before installation
- **Health Validation** - Validates system health after installation
- **Automatic Rollback** - Rolls back on failure

---

## EventBridge Event Schemas

### Compliance Events

#### Compliance Violation Detected

```json
{
  "Source": "patching-automation.compliance-scanner",
  "DetailType": "Compliance Violation Detected",
  "Detail": {
    "correlation_id": "string",
    "environment": "string",
    "violations_count": "number",
    "compliance_score": "number",
    "severity_breakdown": {
      "CRITICAL": "number",
      "HIGH": "number",
      "MEDIUM": "number",
      "LOW": "number"
    },
    "framework_violations": {
      "CIS": "number",
      "PCI_DSS": "number",
      "SOC2": "number"
    },
    "timestamp": "string"
  }
}
```

#### Compliance Scan Completed

```json
{
  "Source": "patching-automation.compliance-scanner",
  "DetailType": "Compliance Scan Completed",
  "Detail": {
    "correlation_id": "string",
    "environment": "string",
    "status": "completed",
    "findings_count": "number",
    "violations_count": "number",
    "compliance_score": "number",
    "timestamp": "string"
  }
}
```

### Vulnerability Events

#### Critical Vulnerabilities Detected

```json
{
  "Source": "patching-automation.vulnerability-scanner",
  "DetailType": "Critical Vulnerabilities Detected",
  "Detail": {
    "correlation_id": "string",
    "environment": "string",
    "critical_count": "number",
    "high_count": "number",
    "total_vulnerabilities": "number",
    "patchable_vulnerabilities": "number",
    "timestamp": "string"
  }
}
```

#### Vulnerability Scan Completed

```json
{
  "Source": "patching-automation.vulnerability-scanner",
  "DetailType": "Vulnerability Scan Completed",
  "Detail": {
    "correlation_id": "string",
    "environment": "string",
    "status": "completed",
    "total_vulnerabilities": "number",
    "critical_count": "number",
    "high_count": "number",
    "patchable_count": "number",
    "timestamp": "string"
  }
}
```

### Patch Events

#### Patch Approval Completed

```json
{
  "Source": "patching-automation.patch-approval-workflow",
  "DetailType": "Patch Approval Completed",
  "Detail": {
    "correlation_id": "string",
    "environment": "string",
    "status": "approved",
    "vulnerability_count": "number",
    "patches_approved": ["object"],
    "timestamp": "string"
  }
}
```

#### Patch Installation Completed

```json
{
  "Source": "patching-automation.patch-installation",
  "DetailType": "Patch Installation Completed",
  "Detail": {
    "correlation_id": "string",
    "environment": "string",
    "total_batches": "number",
    "successful_batches": "number",
    "failed_batches": "number",
    "success_rate": "number",
    "timestamp": "string"
  }
}
```

---

## CloudWatch Metrics

### Custom Metrics Namespace

**Namespace:** `AWS/PatchingAutomation/Microservices`

#### Compliance Metrics

- **ComplianceScore** - Overall compliance score (0-100)
  - Dimensions: Environment, Service
  - Unit: Percent

- **ViolationsCount** - Number of compliance violations
  - Dimensions: Environment, Service
  - Unit: Count

- **FindingsBySeverity** - Findings count by severity level
  - Dimensions: Environment, Service, Severity
  - Unit: Count

#### Vulnerability Metrics

- **TotalVulnerabilities** - Total vulnerability count
  - Dimensions: Environment, Service
  - Unit: Count

- **CriticalVulnerabilities** - Critical vulnerability count
  - Dimensions: Environment, Service
  - Unit: Count

- **PatchableVulnerabilities** - Patchable vulnerability count
  - Dimensions: Environment, Service
  - Unit: Count

#### Failure Metrics

- **Failures** - Service failure count
  - Dimensions: Environment, Service, FailureType
  - Unit: Count

---

## Error Handling

### HTTP Status Codes

- **200** - Success
- **400** - Bad Request (invalid input)
- **403** - Forbidden (insufficient permissions)
- **500** - Internal Server Error
- **503** - Service Unavailable (temporary failure)

### Error Response Format

```json
{
  "error": "string",              // Error message
  "correlation_id": "string",     // Request correlation ID
  "error_type": "string",         // Exception class name
  "timestamp": "string"           // ISO 8601 timestamp
}
```

### Retry Logic

All microservices implement exponential backoff retry logic:
- Initial delay: 1 second
- Maximum attempts: 3
- Backoff multiplier: 2.0
- Maximum delay: 60 seconds

---

## Authentication & Authorization

### IAM Permissions

#### Required Permissions for Lambda Functions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "securityhub:GetFindings",
        "config:GetComplianceSummaryByConfigRule",
        "inspector2:ListFindings",
        "ssm:DescribeInstanceInformation",
        "ssm:DescribeInstancePatches",
        "events:PutEvents",
        "cloudwatch:PutMetricData"
      ],
      "Resource": "*"
    }
  ]
}
```

#### Required Permissions for Step Functions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "lambda:InvokeFunction",
        "events:PutEvents",
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Monitoring & Observability

### X-Ray Tracing

All services support X-Ray distributed tracing with:
- Correlation ID propagation
- Service map visualization
- Performance metrics
- Error tracking

### Structured Logging

All logs are JSON-formatted with fields:
- `timestamp` - ISO 8601 timestamp
- `level` - Log level (INFO, WARN, ERROR)
- `correlation_id` - Request correlation ID
- `service` - Service name
- `message` - Log message
- `error` - Error details (if applicable)

### CloudWatch Dashboards

Access the comprehensive monitoring dashboard:
- **URL Pattern:** `https://{region}.console.aws.amazon.com/cloudwatch/home?region={region}#dashboards:name=PatchingAutomation-{environment}`
- **Key Metrics:** Compliance scores, vulnerability counts, workflow success rates
- **Alarms:** Critical thresholds, failure rates, performance degradation

---

## Rate Limits

- **Lambda Concurrent Executions:** 1000 (default)
- **Step Functions Executions:** 2000 per second
- **EventBridge Events:** 10,000 per second
- **CloudWatch Metrics:** 150 TPS per region

---

## Support & Troubleshooting

### Common Issues

1. **Lambda Timeout Errors**
   - Increase timeout settings in CloudFormation
   - Check for infinite loops or hanging API calls

2. **IAM Permission Errors**
   - Verify IAM roles have required permissions
   - Check resource-based policies

3. **Step Functions Failures**
   - Review execution history
   - Check Lambda function logs
   - Verify input schema compliance

### Debugging

1. **Enable X-Ray Tracing** for detailed execution flow
2. **Check CloudWatch Logs** for error details
3. **Monitor Custom Metrics** for performance trends
4. **Use Correlation IDs** to trace requests across services