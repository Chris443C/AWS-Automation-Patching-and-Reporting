#!/usr/bin/env python3
"""
AWS Compliance Scanner - CIS and PCI DSS Integration (Optimized Version)
Integrates with Security Hub to provide comprehensive compliance reporting
"""

import boto3
import json
import os
import sys
import re
import time
import random
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ComplianceMapper:
    """Optimized compliance mapping using structured data patterns"""
    
    def __init__(self):
        # CIS control patterns for efficient matching
        self.cis_patterns = {
            '1.1': ['root account', 'administrative access', 'root user'],
            '1.2': ['mfa', 'multi-factor', 'two-factor', '2fa'],
            '1.3': ['credentials unused', 'inactive credentials', '90 days'],
            '1.4': ['access keys', 'key rotation', 'rotate'],
            '1.5': ['password policy', 'uppercase', 'password requirements'],
            '1.6': ['password policy', 'lowercase', 'password requirements'],
            '1.7': ['password policy', 'symbol', 'special character'],
            '1.8': ['password policy', 'number', 'numeric'],
            '1.9': ['password policy', 'minimum length', '14 characters'],
            '1.10': ['password policy', 'password reuse', 'history'],
            '1.11': ['password policy', 'password expires', '90 days'],
            '1.12': ['root account', 'access key', 'root key'],
            '1.13': ['root account', 'mfa', 'multi-factor'],
            '1.14': ['root account', 'hardware mfa', 'hardware token'],
            '2.1': ['cloudtrail', 'audit trail', 'api logging', 'all regions'],
            '2.2': ['cloudtrail', 'log file validation', 'log integrity'],
            '2.3': ['cloudtrail', 's3 bucket', 'publicly accessible'],
            '2.4': ['cloudtrail', 'cloudwatch logs', 'log integration'],
            '2.5': ['aws config', 'configuration recorder', 'all regions'],
            '2.6': ['s3 bucket', 'access logging', 'cloudtrail bucket'],
            '2.7': ['cloudtrail', 'encryption', 'kms', 'cmk'],
            '2.8': ['kms', 'key rotation', 'cmk rotation'],
            '2.9': ['vpc', 'flow logging', 'vpc flow logs'],
            '3.1': ['security groups', 'ingress', '0.0.0.0/0', 'unrestricted'],
            '3.2': ['security groups', 'ingress', 'port 22', 'ssh'],
            '3.3': ['security groups', 'ingress', 'port 3389', 'rdp']
        }
        
        # PCI DSS patterns
        self.pci_patterns = {
            '1.1': ['firewall', 'router configuration', 'network security'],
            '1.2': ['firewall', 'access control', 'network restrictions'],
            '1.3': ['public access', 'internet access', 'dmz'],
            '2.1': ['vendor defaults', 'default accounts', 'default passwords'],
            '2.2': ['configuration standards', 'hardening', 'security baseline'],
            '2.3': ['encryption', 'administrative access', 'ssh', 'https'],
            '3.1': ['cardholder data', 'data storage', 'data retention'],
            '3.4': ['encryption', 'data protection', 'stored data'],
            '6.1': ['security patches', 'vulnerability management', 'patch management'],
            '8.1': ['authentication', 'user access', 'access control'],
            '10.1': ['audit trails', 'logging', 'log monitoring'],
            '11.1': ['vulnerability scanning', 'security testing', 'penetration testing']
        }
        
        # Compile regex patterns for performance
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile regex patterns for better performance"""
        self.cis_regex = {}
        self.pci_regex = {}
        
        for control_id, patterns in self.cis_patterns.items():
            pattern = '|'.join(re.escape(p) for p in patterns)
            self.cis_regex[control_id] = re.compile(pattern, re.IGNORECASE)
        
        for req_id, patterns in self.pci_patterns.items():
            pattern = '|'.join(re.escape(p) for p in patterns)
            self.pci_regex[req_id] = re.compile(pattern, re.IGNORECASE)
    
    def check_cis_compliance(self, finding: Dict[str, Any]) -> Optional[Dict[str, str]]:
        """Check if finding matches CIS controls using compiled regex patterns"""
        finding_text = self._extract_finding_text(finding)
        
        for control_id, pattern in self.cis_regex.items():
            if pattern.search(finding_text):
                matched_patterns = [p for p in self.cis_patterns[control_id] if p in finding_text.lower()]
                return {
                    'control_id': control_id,
                    'framework': 'CIS AWS Foundations Benchmark',
                    'matched_patterns': matched_patterns,
                    'severity': self._get_finding_severity(finding)
                }
        return None
    
    def check_pci_compliance(self, finding: Dict[str, Any]) -> Optional[Dict[str, str]]:
        """Check if finding matches PCI DSS requirements"""
        finding_text = self._extract_finding_text(finding)
        
        for requirement_id, pattern in self.pci_regex.items():
            if pattern.search(finding_text):
                matched_patterns = [p for p in self.pci_patterns[requirement_id] if p in finding_text.lower()]
                return {
                    'requirement_id': requirement_id,
                    'framework': 'PCI DSS v3.2.1',
                    'matched_patterns': matched_patterns,
                    'severity': self._get_finding_severity(finding)
                }
        return None
    
    def _extract_finding_text(self, finding: Dict[str, Any]) -> str:
        """Extract relevant text from Security Hub finding"""
        text_parts = [
            finding.get('Title', ''),
            finding.get('Description', ''),
            finding.get('GeneratorId', ''),
            ' '.join([r.get('Type', '') for r in finding.get('Resources', [])])
        ]
        return ' '.join(filter(None, text_parts))
    
    def _get_finding_severity(self, finding: Dict[str, Any]) -> str:
        """Extract severity from finding"""
        severity = finding.get('Severity', {})
        if isinstance(severity, dict):
            return severity.get('Label', 'UNKNOWN')
        return str(severity).upper()

class ComplianceScanner:
    """Comprehensive compliance scanner integrating Security Hub, CIS, and PCI DSS"""
    
    def __init__(self, region: str = None):
        # Validate region
        self.region = self._validate_region(region or os.environ.get('AWS_DEFAULT_REGION', 'us-east-1'))
        
        # Initialize AWS clients with retry configuration
        config = boto3.session.Config(
            retries={
                'max_attempts': 3,
                'mode': 'adaptive'
            }
        )
        
        self.securityhub = boto3.client('securityhub', region_name=self.region, config=config)
        self.s3 = boto3.client('s3', config=config)
        self.ssm = boto3.client('ssm', config=config)
        self.sns = boto3.client('sns', config=config)
        
        # Configuration with validation
        self.s3_bucket = self._validate_s3_bucket(os.environ.get('S3_BUCKET', 'aws-patching-automation-reports'))
        self.environment = self._validate_environment(os.environ.get('ENVIRONMENT', 'dev'))
        self.sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
        
        # Initialize compliance mapper
        self.compliance_mapper = ComplianceMapper()
        
        # Load compliance configuration
        self.compliance_config = self._load_compliance_config()
    
    def _validate_region(self, region: str) -> str:
        """Validate AWS region format"""
        if not region or not re.match(r'^[a-z0-9-]+$', region):
            raise ValueError(f"Invalid AWS region: {region}")
        return region
    
    def _validate_s3_bucket(self, bucket: str) -> str:
        """Validate S3 bucket name"""
        if not bucket or not re.match(r'^[a-z0-9.-]{3,63}$', bucket):
            raise ValueError(f"Invalid S3 bucket name: {bucket}")
        return bucket
    
    def _validate_environment(self, env: str) -> str:
        """Validate environment name"""
        if not env or not re.match(r'^[a-zA-Z0-9-]{1,20}$', env):
            raise ValueError(f"Invalid environment name: {env}")
        return env
    
    def _retry_with_backoff(self, func, max_retries=3, *args, **kwargs):
        """Implement exponential backoff for AWS API calls"""
        for attempt in range(max_retries):
            try:
                return func(*args, **kwargs)
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code in ['Throttling', 'RequestLimitExceeded', 'ServiceUnavailable']:
                    if attempt < max_retries - 1:
                        wait_time = (2 ** attempt) + random.uniform(0, 1)
                        logger.warning(f"Rate limited, retrying in {wait_time:.2f}s...")
                        time.sleep(wait_time)
                    else:
                        logger.error(f"Max retries exceeded for {func.__name__}")
                        raise
                else:
                    raise
            except Exception as e:
                logger.error(f"Unexpected error in {func.__name__}: {e}")
                raise
    
    def _load_compliance_config(self) -> Dict[str, Any]:
        """Load compliance configuration from SSM Parameter Store"""
        try:
            response = self._retry_with_backoff(
                self.ssm.get_parameter,
                Name=f'/patching-automation/{self.environment}/compliance-config',
                WithDecryption=True
            )
            return json.loads(response['Parameter']['Value'])
        except Exception as e:
            logger.warning(f"Could not load compliance config: {e}, using defaults")
            return {
                "cis_enabled": True,
                "pci_enabled": True,
                "severity_filter": ["CRITICAL", "HIGH", "MEDIUM"],
                "max_findings": 1000,
                "score_thresholds": {
                    "cis_warning": 80,
                    "cis_critical": 60,
                    "pci_warning": 80,
                    "pci_critical": 60
                }
            }
    
    def get_security_hub_findings(self, days_back: int = 30, max_results: int = 1000) -> List[Dict[str, Any]]:
        """Get Security Hub findings with pagination and filtering"""
        findings = []
        
        # Calculate date filter
        date_filter = datetime.now() - timedelta(days=days_back)
        
        # Build filters
        filters = {
            'CreatedAt': [
                {
                    'Start': date_filter.isoformat() + 'Z',
                    'DateRange': {
                        'Value': days_back,
                        'Unit': 'DAYS'
                    }
                }
            ],
            'RecordState': [
                {
                    'Value': 'ACTIVE',
                    'Comparison': 'EQUALS'
                }
            ]
        }
        
        # Add severity filter if configured
        severity_filter = self.compliance_config.get('severity_filter', ['CRITICAL', 'HIGH'])
        if severity_filter:
            filters['SeverityLabel'] = [
                {
                    'Value': severity,
                    'Comparison': 'EQUALS'
                } for severity in severity_filter
            ]
        
        try:
            paginator = self.securityhub.get_paginator('get_findings')
            page_iterator = paginator.paginate(
                Filters=filters,
                PaginationConfig={
                    'MaxItems': max_results,
                    'PageSize': 100
                }
            )
            
            for page in page_iterator:
                findings.extend(page.get('Findings', []))
                if len(findings) >= max_results:
                    logger.warning(f"Reached maximum findings limit: {max_results}")
                    break
            
            logger.info(f"Retrieved {len(findings)} Security Hub findings")
            return findings
            
        except Exception as e:
            logger.error(f"Error retrieving Security Hub findings: {e}")
            return []
    
    def analyze_compliance(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze findings for CIS and PCI DSS compliance"""
        analysis = {
            'total_findings': len(findings),
            'cis_findings': [],
            'pci_findings': [],
            'processed_at': datetime.now().isoformat(),
            'compliance_scores': {}
        }
        
        if not findings:
            logger.warning("No findings to analyze")
            return analysis
        
        # Process findings for compliance mapping
        for finding in findings:
            try:
                # Check CIS compliance
                if self.compliance_config.get('cis_enabled', True):
                    cis_result = self.compliance_mapper.check_cis_compliance(finding)
                    if cis_result:
                        analysis['cis_findings'].append({
                            **cis_result,
                            'finding_id': finding.get('Id'),
                            'title': finding.get('Title'),
                            'created_at': finding.get('CreatedAt'),
                            'updated_at': finding.get('UpdatedAt'),
                            'workflow_status': finding.get('Workflow', {}).get('Status')
                        })
                
                # Check PCI DSS compliance
                if self.compliance_config.get('pci_enabled', True):
                    pci_result = self.compliance_mapper.check_pci_compliance(finding)
                    if pci_result:
                        analysis['pci_findings'].append({
                            **pci_result,
                            'finding_id': finding.get('Id'),
                            'title': finding.get('Title'),
                            'created_at': finding.get('CreatedAt'),
                            'updated_at': finding.get('UpdatedAt'),
                            'workflow_status': finding.get('Workflow', {}).get('Status')
                        })
                        
            except Exception as e:
                logger.error(f"Error analyzing finding {finding.get('Id', 'unknown')}: {e}")
                continue
        
        # Calculate compliance scores
        analysis['compliance_scores'] = self._calculate_compliance_scores(analysis)
        
        logger.info(f"Compliance analysis complete: {len(analysis['cis_findings'])} CIS findings, "
                   f"{len(analysis['pci_findings'])} PCI findings")
        
        return analysis
    
    def _calculate_compliance_scores(self, analysis: Dict[str, Any]) -> Dict[str, float]:
        """Calculate compliance scores based on findings"""
        scores = {}
        
        # CIS score calculation (simplified)
        total_cis_controls = len(self.compliance_mapper.cis_patterns)
        cis_violations = len(set(f['control_id'] for f in analysis['cis_findings']))
        cis_score = max(0, (total_cis_controls - cis_violations) / total_cis_controls * 100)
        scores['cis_score'] = round(cis_score, 2)
        
        # PCI DSS score calculation (simplified)
        total_pci_requirements = len(self.compliance_mapper.pci_patterns)
        pci_violations = len(set(f['requirement_id'] for f in analysis['pci_findings']))
        pci_score = max(0, (total_pci_requirements - pci_violations) / total_pci_requirements * 100)
        scores['pci_score'] = round(pci_score, 2)
        
        return scores
    
    def store_compliance_report(self, analysis: Dict[str, Any]) -> Optional[str]:
        """Store compliance analysis report in S3"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_key = f'compliance-reports/{self.environment}/{timestamp}_compliance_report.json'
        
        # Prepare report data
        report_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'environment': self.environment,
                'region': self.region,
                'scanner_version': '2.0.0'
            },
            'analysis': analysis,
            'summary': {
                'total_findings': analysis['total_findings'],
                'cis_findings_count': len(analysis['cis_findings']),
                'pci_findings_count': len(analysis['pci_findings']),
                'compliance_scores': analysis['compliance_scores']
            }
        }
        
        try:
            self._retry_with_backoff(
                self.s3.put_object,
                Bucket=self.s3_bucket,
                Key=report_key,
                Body=json.dumps(report_data, indent=2),
                ContentType='application/json',
                ServerSideEncryption='AES256'
            )
            
            logger.info(f"Compliance report stored: s3://{self.s3_bucket}/{report_key}")
            return report_key
            
        except Exception as e:
            logger.error(f"Error storing compliance report: {e}")
            return None
    
    def send_compliance_notification(self, analysis: Dict[str, Any]) -> bool:
        """Send compliance notification via SNS"""
        if not self.sns_topic_arn:
            logger.warning("SNS topic ARN not configured, skipping notification")
            return False
        
        scores = analysis['compliance_scores']
        cis_score = scores.get('cis_score', 0)
        pci_score = scores.get('pci_score', 0)
        
        # Check if notification is needed based on thresholds
        thresholds = self.compliance_config.get('score_thresholds', {})
        cis_warning = thresholds.get('cis_warning', 80)
        pci_warning = thresholds.get('pci_warning', 80)
        
        if cis_score >= cis_warning and pci_score >= pci_warning:
            logger.info("Compliance scores are above warning thresholds, no notification needed")
            return True
        
        # Prepare notification message
        message = f"""
Compliance Scan Results - {self.environment.upper()}

CIS AWS Foundations Score: {cis_score}% ({len(analysis['cis_findings'])} violations)
PCI DSS Score: {pci_score}% ({len(analysis['pci_findings'])} violations)

Total Security Hub Findings: {analysis['total_findings']}

Scan completed at: {analysis['processed_at']}
Region: {self.region}

Please review the detailed compliance report in S3 for remediation guidance.
        """.strip()
        
        try:
            self._retry_with_backoff(
                self.sns.publish,
                TopicArn=self.sns_topic_arn,
                Subject=f'Compliance Scan Alert - {self.environment.upper()}',
                Message=message
            )
            logger.info("Compliance notification sent successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error sending compliance notification: {e}")
            return False
    
    def run_compliance_scan(self, days_back: int = 30, no_s3: bool = False, 
                           no_notification: bool = False) -> Dict[str, Any]:
        """Run complete compliance scan workflow"""
        logger.info(f"Starting compliance scan for environment: {self.environment}")
        
        try:
            # Get Security Hub findings
            findings = self.get_security_hub_findings(days_back, 
                                                    max_results=self.compliance_config.get('max_findings', 1000))
            
            if not findings:
                logger.warning("No findings retrieved, compliance scan aborted")
                return {'status': 'no_findings', 'findings_count': 0}
            
            # Analyze compliance
            analysis = self.analyze_compliance(findings)
            
            # Store report if requested
            report_location = None
            if not no_s3:
                report_location = self.store_compliance_report(analysis)
            
            # Send notification if requested
            notification_sent = False
            if not no_notification:
                notification_sent = self.send_compliance_notification(analysis)
            
            result = {
                'status': 'completed',
                'findings_count': analysis['total_findings'],
                'cis_findings': len(analysis['cis_findings']),
                'pci_findings': len(analysis['pci_findings']),
                'compliance_scores': analysis['compliance_scores'],
                'report_location': f"s3://{self.s3_bucket}/{report_location}" if report_location else None,
                'notification_sent': notification_sent,
                'scan_duration': None  # Could add timing if needed
            }
            
            logger.info(f"Compliance scan completed successfully: {result}")
            return result
            
        except Exception as e:
            logger.error(f"Compliance scan failed: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'findings_count': 0
            }

def lambda_handler(event, context):
    """AWS Lambda handler function"""
    try:
        # Extract parameters from event
        days_back = event.get('days_back', 30)
        region = event.get('region')
        no_s3 = event.get('no_s3', False)
        no_notification = event.get('no_notification', False)
        
        # Initialize scanner
        scanner = ComplianceScanner(region=region)
        
        # Run compliance scan
        result = scanner.run_compliance_scan(
            days_back=days_back,
            no_s3=no_s3,
            no_notification=no_notification
        )
        
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
    # CLI interface for local testing
    import argparse
    
    parser = argparse.ArgumentParser(description='AWS Compliance Scanner')
    parser.add_argument('--days-back', type=int, default=30, help='Days to look back for findings')
    parser.add_argument('--region', type=str, help='AWS region')
    parser.add_argument('--no-s3', action='store_true', help='Skip S3 upload')
    parser.add_argument('--no-notification', action='store_true', help='Skip SNS notification')
    
    args = parser.parse_args()
    
    try:
        scanner = ComplianceScanner(region=args.region)
        result = scanner.run_compliance_scan(
            days_back=args.days_back,
            no_s3=args.no_s3,
            no_notification=args.no_notification
        )
        print(json.dumps(result, indent=2))
        
    except Exception as e:
        logger.error(f"CLI execution failed: {e}")
        sys.exit(1)