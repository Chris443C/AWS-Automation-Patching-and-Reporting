#!/usr/bin/env python3
"""
AWS Inspector Handler for Patching Automation
Processes Inspector findings and triggers patch approval workflows
"""

import json
import boto3
import os
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any
import urllib3

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class InspectorHandler:
    def __init__(self):
        """Initialize the Inspector handler with AWS clients"""
        self.inspector = boto3.client('inspector2')
        self.s3 = boto3.client('s3')
        self.sns = boto3.client('sns')
        self.ssm = boto3.client('ssm')
        self.ec2 = boto3.client('ec2')
        
        # Environment variables
        self.environment = os.environ.get('ENVIRONMENT', 'dev')
        self.s3_bucket = os.environ.get('S3_BUCKET')
        self.sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
        
        # Configuration
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from SSM Parameter Store"""
        try:
            response = self.ssm.get_parameter(
                Name=f'/inspector/{self.environment}/config',
                WithDecryption=True
            )
            return json.loads(response['Parameter']['Value'])
        except Exception as e:
            logger.warning(f"Could not load config from SSM: {e}")
            return {
                "autoApprovalThreshold": 8.0,
                "severityThreshold": "MEDIUM",
                "notificationChannels": ["sns", "s3"]
            }
    
    def get_findings(self, severity_filter: List[str] = None) -> List[Dict[str, Any]]:
        """Retrieve Inspector findings with optional severity filtering"""
        if severity_filter is None:
            severity_filter = ['CRITICAL', 'HIGH', 'MEDIUM']
        
        findings = []
        paginator = self.inspector.get_paginator('list_findings')
        
        try:
            for page in paginator.paginate(
                filterCriteria={
                    'severity': [{'comparison': 'EQUALS', 'value': sev} for sev in severity_filter]
                }
            ):
                findings.extend(page['findings'])
            
            logger.info(f"Retrieved {len(findings)} findings")
            return findings
        except Exception as e:
            logger.error(f"Error retrieving findings: {e}")
            return []
    
    def get_finding_details(self, finding_arn: str) -> Dict[str, Any]:
        """Get detailed information about a specific finding"""
        try:
            response = self.inspector.get_finding(arn=finding_arn)
            return response['finding']
        except Exception as e:
            logger.error(f"Error getting finding details for {finding_arn}: {e}")
            return {}
    
    def categorize_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Categorize findings by type and severity"""
        categorized = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'patch_related': [],
            'non_patch_related': []
        }
        
        for finding in findings:
            severity = finding.get('severity', 'UNKNOWN')
            
            # Categorize by severity
            if severity == 'CRITICAL':
                categorized['critical'].append(finding)
            elif severity == 'HIGH':
                categorized['high'].append(finding)
            elif severity == 'MEDIUM':
                categorized['medium'].append(finding)
            elif severity == 'LOW':
                categorized['low'].append(finding)
            
            # Categorize by type (patch-related vs other)
            finding_type = finding.get('type', '')
            if any(keyword in finding_type.lower() for keyword in ['cve', 'vulnerability', 'patch']):
                categorized['patch_related'].append(finding)
            else:
                categorized['non_patch_related'].append(finding)
        
        return categorized
    
    def extract_patch_information(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Extract patch-related information from a finding"""
        patch_info = {
            'finding_arn': finding.get('arn'),
            'title': finding.get('title'),
            'severity': finding.get('severity'),
            'cvss_score': finding.get('cvssScore'),
            'package_name': None,
            'package_version': None,
            'cve_id': None,
            'patch_available': False,
            'patch_id': None
        }
        
        # Extract package information
        package_details = finding.get('packageVulnerabilityDetails', {})
        if package_details:
            patch_info['package_name'] = package_details.get('packageName')
            patch_info['package_version'] = package_details.get('packageVersion')
        
        # Extract CVE information
        cve_details = finding.get('cveDetails', [])
        if cve_details:
            patch_info['cve_id'] = cve_details[0].get('cveId')
        
        # Check if patch information is available
        remediation = finding.get('remediation', {})
        if remediation:
            patch_info['patch_available'] = True
            patch_info['patch_id'] = remediation.get('recommendation', {}).get('text', '')
        
        return patch_info
    
    def auto_approve_patches(self, patch_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Automatically approve patches based on configuration"""
        auto_approval_threshold = self.config.get('autoApprovalThreshold', 8.0)
        approved_patches = []
        
        for finding in patch_findings:
            cvss_score = finding.get('cvssScore', 0)
            
            if cvss_score >= auto_approval_threshold:
                patch_info = self.extract_patch_information(finding)
                if patch_info['patch_available']:
                    approved_patches.append(patch_info)
                    logger.info(f"Auto-approved patch for {patch_info['package_name']} (CVSS: {cvss_score})")
        
        return approved_patches
    
    def store_findings_report(self, findings: List[Dict[str, Any]], categorized: Dict[str, List[Dict[str, Any]]]) -> str:
        """Store findings report in S3"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_key = f'inspector-findings/{timestamp}_comprehensive_report.json'
        
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'environment': self.environment,
            'total_findings': len(findings),
            'categorized_findings': categorized,
            'summary': {
                'critical': len(categorized['critical']),
                'high': len(categorized['high']),
                'medium': len(categorized['medium']),
                'low': len(categorized['low']),
                'patch_related': len(categorized['patch_related']),
                'non_patch_related': len(categorized['non_patch_related'])
            }
        }
        
        try:
            self.s3.put_object(
                Bucket=self.s3_bucket,
                Key=report_key,
                Body=json.dumps(report_data, indent=2),
                ContentType='application/json'
            )
            logger.info(f"Stored findings report: s3://{self.s3_bucket}/{report_key}")
            return report_key
        except Exception as e:
            logger.error(f"Error storing findings report: {e}")
            return None
    
    def send_notifications(self, findings: List[Dict[str, Any]], report_key: str = None) -> bool:
        """Send notifications about findings"""
        if not self.sns_topic_arn:
            logger.warning("SNS topic ARN not configured")
            return False
        
        critical_count = len([f for f in findings if f.get('severity') == 'CRITICAL'])
        high_count = len([f for f in findings if f.get('severity') == 'HIGH'])
        
        message = f"""
AWS Inspector Findings Report - {self.environment.upper()}

Summary:
- Critical Findings: {critical_count}
- High Findings: {high_count}
- Total Findings: {len(findings)}

Report Location: s3://{self.s3_bucket}/{report_key if report_key else 'inspector-findings/'}

Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """.strip()
        
        try:
            self.sns.publish(
                TopicArn=self.sns_topic_arn,
                Subject=f'AWS Inspector Findings - {self.environment.upper()}',
                Message=message
            )
            logger.info("Notification sent successfully")
            return True
        except Exception as e:
            logger.error(f"Error sending notification: {e}")
            return False
    
    def get_instance_information(self, resource_id: str) -> Dict[str, Any]:
        """Get EC2 instance information for a resource"""
        try:
            response = self.ec2.describe_instances(InstanceIds=[resource_id])
            if response['Reservations']:
                instance = response['Reservations'][0]['Instances'][0]
                return {
                    'instance_id': instance['InstanceId'],
                    'instance_type': instance['InstanceType'],
                    'state': instance['State']['Name'],
                    'platform': instance.get('Platform', 'linux'),
                    'tags': {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                }
        except Exception as e:
            logger.error(f"Error getting instance information for {resource_id}: {e}")
        
        return {}
    
    def process_findings(self) -> Dict[str, Any]:
        """Main method to process all Inspector findings"""
        logger.info("Starting Inspector findings processing")
        
        # Get findings
        findings = self.get_findings()
        if not findings:
            logger.info("No findings to process")
            return {'status': 'no_findings'}
        
        # Categorize findings
        categorized = self.categorize_findings(findings)
        
        # Extract patch-related findings
        patch_findings = categorized['patch_related']
        
        # Auto-approve patches based on threshold
        approved_patches = self.auto_approve_patches(patch_findings)
        
        # Store comprehensive report
        report_key = self.store_findings_report(findings, categorized)
        
        # Send notifications
        self.send_notifications(findings, report_key)
        
        # Prepare result
        result = {
            'status': 'success',
            'total_findings': len(findings),
            'patch_related_findings': len(patch_findings),
            'auto_approved_patches': len(approved_patches),
            'report_location': f"s3://{self.s3_bucket}/{report_key}" if report_key else None,
            'summary': categorized['summary']
        }
        
        logger.info(f"Processing completed: {result}")
        return result

def lambda_handler(event, context):
    """AWS Lambda handler function"""
    try:
        handler = InspectorHandler()
        result = handler.process_findings()
        
        return {
            'statusCode': 200,
            'body': json.dumps(result)
        }
    except Exception as e:
        logger.error(f"Lambda handler error: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

if __name__ == "__main__":
    # For local testing
    handler = InspectorHandler()
    result = handler.process_findings()
    print(json.dumps(result, indent=2)) 