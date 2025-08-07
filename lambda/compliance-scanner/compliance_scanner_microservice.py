#!/usr/bin/env python3
"""
Compliance Scanner Microservice
Specialized microservice for compliance scanning and violation detection
"""

import json
import boto3
import os
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import aws_xray_sdk.core
from aws_xray_sdk.core import xray_recorder, patch_all
from botocore.exceptions import ClientError

# Configure X-Ray tracing
patch_all()

# Configure structured logging
import structlog

structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="ISO"),
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

class ComplianceScannerMicroservice:
    """Microservice for compliance scanning operations"""
    
    def __init__(self):
        self.region = os.environ.get('AWS_REGION', 'us-east-1')
        self.environment = os.environ.get('ENVIRONMENT', 'dev')
        self.event_bus_name = os.environ.get('EVENT_BUS_NAME')
        
        # AWS clients with X-Ray tracing
        self.securityhub = boto3.client('securityhub', region_name=self.region)
        self.config_client = boto3.client('config', region_name=self.region)
        self.events_client = boto3.client('events', region_name=self.region)
        self.cloudwatch = boto3.client('cloudwatch', region_name=self.region)
        
        # Correlation ID for request tracing
        self.correlation_id = str(uuid.uuid4())
    
    @xray_recorder.capture('compliance_scan')
    def scan_compliance(self, scan_params: Dict[str, Any]) -> Dict[str, Any]:
        """Perform compliance scanning"""
        logger.info(
            "compliance_scan_started",
            correlation_id=self.correlation_id,
            scan_type=scan_params.get('scan_type', 'full'),
            environment=self.environment
        )
        
        try:
            # Get compliance findings
            findings = self._get_compliance_findings(scan_params)
            
            # Analyze findings
            analysis = self._analyze_findings(findings)
            
            # Publish compliance events
            await self._publish_compliance_events(analysis)
            
            # Record metrics
            self._record_compliance_metrics(analysis)
            
            result = {
                'status': 'completed',
                'correlation_id': self.correlation_id,
                'findings_count': len(findings),
                'violations_count': analysis['violations_count'],
                'compliance_score': analysis['compliance_score'],
                'scan_timestamp': datetime.utcnow().isoformat()
            }
            
            logger.info(
                "compliance_scan_completed",
                correlation_id=self.correlation_id,
                **result
            )
            
            return result
            
        except Exception as e:
            logger.error(
                "compliance_scan_failed",
                correlation_id=self.correlation_id,
                error=str(e),
                error_type=type(e).__name__
            )
            
            # Record failure metric
            self._record_failure_metric('compliance_scan_failure')
            raise
    
    @xray_recorder.capture('get_compliance_findings')
    def _get_compliance_findings(self, scan_params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Retrieve compliance findings from Security Hub and Config"""
        findings = []
        
        with xray_recorder.in_subsegment('security_hub_findings'):
            try:
                # Get Security Hub findings
                sh_findings = self._get_security_hub_findings(scan_params)
                findings.extend(sh_findings)
                
                xray_recorder.current_subsegment().put_annotation('security_hub_findings', len(sh_findings))
            except Exception as e:
                logger.warning("failed_to_get_security_hub_findings", error=str(e))
        
        with xray_recorder.in_subsegment('config_findings'):
            try:
                # Get Config compliance findings
                config_findings = self._get_config_compliance_findings(scan_params)
                findings.extend(config_findings)
                
                xray_recorder.current_subsegment().put_annotation('config_findings', len(config_findings))
            except Exception as e:
                logger.warning("failed_to_get_config_findings", error=str(e))
        
        return findings
    
    def _get_security_hub_findings(self, scan_params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get findings from Security Hub"""
        findings = []
        days_back = scan_params.get('days_back', 7)
        
        filters = {
            'CreatedAt': [
                {
                    'Start': (datetime.utcnow() - timedelta(days=days_back)).isoformat() + 'Z'
                }
            ],
            'RecordState': [
                {
                    'Value': 'ACTIVE',
                    'Comparison': 'EQUALS'
                }
            ],
            'WorkflowStatus': [
                {
                    'Value': 'NEW',
                    'Comparison': 'EQUALS'
                }
            ]
        }
        
        paginator = self.securityhub.get_paginator('get_findings')
        
        for page in paginator.paginate(Filters=filters, MaxResults=100):
            findings.extend(page.get('Findings', []))
        
        return findings
    
    def _get_config_compliance_findings(self, scan_params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get compliance findings from AWS Config"""
        findings = []
        
        try:
            # Get non-compliant resources
            response = self.config_client.get_compliance_summary_by_config_rule()
            
            for rule_summary in response.get('ComplianceSummary', []):
                if rule_summary.get('NonCompliantResourceCount', {}).get('CappedCount', 0) > 0:
                    findings.append({
                        'Type': 'Config Compliance',
                        'RuleName': rule_summary.get('ConfigRuleName'),
                        'NonCompliantCount': rule_summary.get('NonCompliantResourceCount', {}).get('CappedCount', 0),
                        'Severity': 'HIGH' if 'security' in rule_summary.get('ConfigRuleName', '').lower() else 'MEDIUM'
                    })
        
        except Exception as e:
            logger.warning("failed_to_get_config_compliance", error=str(e))
        
        return findings
    
    @xray_recorder.capture('analyze_findings')
    def _analyze_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze compliance findings"""
        analysis = {
            'total_findings': len(findings),
            'violations_count': 0,
            'compliance_score': 100.0,
            'severity_breakdown': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0
            },
            'framework_violations': {
                'CIS': [],
                'PCI_DSS': [],
                'SOC2': []
            }
        }
        
        violations = 0
        
        for finding in findings:
            severity = self._get_finding_severity(finding)
            analysis['severity_breakdown'][severity] += 1
            
            # Check for compliance framework violations
            if self._is_compliance_violation(finding):
                violations += 1
                framework = self._identify_compliance_framework(finding)
                if framework in analysis['framework_violations']:
                    analysis['framework_violations'][framework].append(finding)
        
        analysis['violations_count'] = violations
        
        # Calculate compliance score
        if analysis['total_findings'] > 0:
            compliance_score = max(0, 100 - (violations / analysis['total_findings'] * 100))
            analysis['compliance_score'] = round(compliance_score, 2)
        
        return analysis
    
    def _get_finding_severity(self, finding: Dict[str, Any]) -> str:
        """Extract severity from finding"""
        severity = finding.get('Severity', {})
        if isinstance(severity, dict):
            return severity.get('Label', 'UNKNOWN')
        return str(severity).upper()
    
    def _is_compliance_violation(self, finding: Dict[str, Any]) -> bool:
        """Check if finding represents a compliance violation"""
        # Simple heuristic - can be expanded with more sophisticated logic
        severity = self._get_finding_severity(finding)
        return severity in ['CRITICAL', 'HIGH']
    
    def _identify_compliance_framework(self, finding: Dict[str, Any]) -> str:
        """Identify which compliance framework is affected"""
        title = finding.get('Title', '').lower()
        description = finding.get('Description', '').lower()
        
        if any(keyword in title + description for keyword in ['root', 'mfa', 'iam', 'cloudtrail']):
            return 'CIS'
        elif any(keyword in title + description for keyword in ['firewall', 'encryption', 'access control']):
            return 'PCI_DSS'
        elif any(keyword in title + description for keyword in ['logging', 'monitoring', 'audit']):
            return 'SOC2'
        else:
            return 'CIS'  # Default
    
    async def _publish_compliance_events(self, analysis: Dict[str, Any]):
        """Publish compliance events to EventBridge"""
        events = []
        
        # Publish compliance violation events
        if analysis['violations_count'] > 0:
            events.append({
                'Source': 'patching-automation.compliance-scanner',
                'DetailType': 'Compliance Violation Detected',
                'Detail': json.dumps({
                    'correlation_id': self.correlation_id,
                    'environment': self.environment,
                    'violations_count': analysis['violations_count'],
                    'compliance_score': analysis['compliance_score'],
                    'severity_breakdown': analysis['severity_breakdown'],
                    'framework_violations': {
                        k: len(v) for k, v in analysis['framework_violations'].items()
                    },
                    'timestamp': datetime.utcnow().isoformat()
                }),
                'EventBusName': self.event_bus_name
            })
        
        # Publish compliance scan completed event
        events.append({
            'Source': 'patching-automation.compliance-scanner',
            'DetailType': 'Compliance Scan Completed',
            'Detail': json.dumps({
                'correlation_id': self.correlation_id,
                'environment': self.environment,
                'status': 'completed',
                'findings_count': analysis['total_findings'],
                'violations_count': analysis['violations_count'],
                'compliance_score': analysis['compliance_score'],
                'timestamp': datetime.utcnow().isoformat()
            }),
            'EventBusName': self.event_bus_name
        })
        
        if events and self.event_bus_name:
            try:
                self.events_client.put_events(Entries=events)
                logger.info(
                    "compliance_events_published",
                    correlation_id=self.correlation_id,
                    events_count=len(events)
                )
            except Exception as e:
                logger.error(
                    "failed_to_publish_compliance_events",
                    correlation_id=self.correlation_id,
                    error=str(e)
                )
    
    def _record_compliance_metrics(self, analysis: Dict[str, Any]):
        """Record compliance metrics to CloudWatch"""
        try:
            metric_data = [
                {
                    'MetricName': 'ComplianceScore',
                    'Value': analysis['compliance_score'],
                    'Unit': 'Percent',
                    'Dimensions': [
                        {'Name': 'Environment', 'Value': self.environment},
                        {'Name': 'Service', 'Value': 'ComplianceScanner'}
                    ]
                },
                {
                    'MetricName': 'ViolationsCount',
                    'Value': analysis['violations_count'],
                    'Unit': 'Count',
                    'Dimensions': [
                        {'Name': 'Environment', 'Value': self.environment},
                        {'Name': 'Service', 'Value': 'ComplianceScanner'}
                    ]
                },
                {
                    'MetricName': 'TotalFindings',
                    'Value': analysis['total_findings'],
                    'Unit': 'Count',
                    'Dimensions': [
                        {'Name': 'Environment', 'Value': self.environment},
                        {'Name': 'Service', 'Value': 'ComplianceScanner'}
                    ]
                }
            ]
            
            # Add severity-specific metrics
            for severity, count in analysis['severity_breakdown'].items():
                metric_data.append({
                    'MetricName': 'FindingsBySeverity',
                    'Value': count,
                    'Unit': 'Count',
                    'Dimensions': [
                        {'Name': 'Environment', 'Value': self.environment},
                        {'Name': 'Service', 'Value': 'ComplianceScanner'},
                        {'Name': 'Severity', 'Value': severity}
                    ]
                })
            
            self.cloudwatch.put_metric_data(
                Namespace='AWS/PatchingAutomation/Microservices',
                MetricData=metric_data
            )
            
            logger.info(
                "compliance_metrics_recorded",
                correlation_id=self.correlation_id,
                metrics_count=len(metric_data)
            )
            
        except Exception as e:
            logger.error(
                "failed_to_record_compliance_metrics",
                correlation_id=self.correlation_id,
                error=str(e)
            )
    
    def _record_failure_metric(self, failure_type: str):
        """Record failure metrics"""
        try:
            self.cloudwatch.put_metric_data(
                Namespace='AWS/PatchingAutomation/Microservices',
                MetricData=[
                    {
                        'MetricName': 'Failures',
                        'Value': 1,
                        'Unit': 'Count',
                        'Dimensions': [
                            {'Name': 'Environment', 'Value': self.environment},
                            {'Name': 'Service', 'Value': 'ComplianceScanner'},
                            {'Name': 'FailureType', 'Value': failure_type}
                        ]
                    }
                ]
            )
        except Exception as e:
            logger.error(
                "failed_to_record_failure_metric",
                correlation_id=self.correlation_id,
                error=str(e)
            )

@xray_recorder.capture('lambda_handler')
def lambda_handler(event, context):
    """AWS Lambda handler for compliance scanner microservice"""
    
    # Add correlation ID to X-Ray
    correlation_id = str(uuid.uuid4())
    xray_recorder.current_segment().put_annotation('correlation_id', correlation_id)
    
    logger.info(
        "compliance_scanner_invoked",
        correlation_id=correlation_id,
        event=event,
        function_name=context.function_name,
        function_version=context.function_version
    )
    
    try:
        scanner = ComplianceScannerMicroservice()
        
        # Extract scan parameters from event
        scan_params = {
            'scan_type': event.get('scanType', 'full'),
            'days_back': event.get('daysBack', 7),
            'frameworks': event.get('frameworks', ['CIS', 'PCI_DSS', 'SOC2'])
        }
        
        result = scanner.scan_compliance(scan_params)
        
        logger.info(
            "compliance_scanner_completed",
            correlation_id=correlation_id,
            result=result
        )
        
        return {
            'statusCode': 200,
            'body': json.dumps(result),
            'headers': {
                'Content-Type': 'application/json',
                'X-Correlation-ID': correlation_id
            }
        }
        
    except Exception as e:
        logger.error(
            "compliance_scanner_failed",
            correlation_id=correlation_id,
            error=str(e),
            error_type=type(e).__name__
        )
        
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e),
                'correlation_id': correlation_id,
                'error_type': type(e).__name__
            }),
            'headers': {
                'Content-Type': 'application/json',
                'X-Correlation-ID': correlation_id
            }
        }