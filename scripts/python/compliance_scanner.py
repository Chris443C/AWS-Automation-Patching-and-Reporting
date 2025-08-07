#!/usr/bin/env python3
"""
AWS Compliance Scanner - CIS and PCI DSS Integration
Integrates with Security Hub to provide comprehensive compliance reporting
"""

import boto3
import json
import os
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ComplianceScanner:
    """Comprehensive compliance scanner integrating Security Hub, CIS, and PCI DSS"""
    
    def __init__(self, region: str = None):
        self.region = region or os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
        self.securityhub = boto3.client('securityhub', region_name=self.region)
        self.s3 = boto3.client('s3')
        self.ssm = boto3.client('ssm')
        self.sns = boto3.client('sns')
        
        # Configuration
        self.s3_bucket = os.environ.get('S3_BUCKET', 'aws-patching-automation-reports')
        self.environment = os.environ.get('ENVIRONMENT', 'dev')
        self.sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
        
        # CIS Controls mapping
        self.cis_controls = {
            '1.1': 'Avoid the use of the "root" account',
            '1.2': 'Ensure multi-factor authentication (MFA) is enabled for all IAM users',
            '1.3': 'Ensure credentials unused for 90 days or greater are disabled',
            '1.4': 'Ensure access keys are rotated every 90 days or less',
            '1.5': 'Ensure IAM password policy requires at least one uppercase letter',
            '1.6': 'Ensure IAM password policy requires at least one lowercase letter',
            '1.7': 'Ensure IAM password policy requires at least one symbol',
            '1.8': 'Ensure IAM password policy requires at least one number',
            '1.9': 'Ensure IAM password policy requires minimum length of 14 or greater',
            '1.10': 'Ensure IAM password policy prevents password reuse',
            '1.11': 'Ensure IAM password policy expires passwords within 90 days or less',
            '1.12': 'Ensure no root account access key exists',
            '1.13': 'Ensure MFA is enabled for the "root" account',
            '1.14': 'Ensure hardware MFA is enabled for the "root" account',
            '1.15': 'Ensure security questions are registered in the AWS account',
            '1.16': 'Ensure IAM policies are attached only to groups or roles',
            '1.17': 'Maintain current contact details',
            '1.18': 'Ensure security contact information is registered',
            '1.19': 'Ensure IAM instance roles are used for AWS resource access from instances',
            '1.20': 'Ensure a support role has been created to manage incidents with AWS Support',
            '1.21': 'Do not setup access keys during initial user setup for all IAM users and roles',
            '1.22': 'Ensure IAM policies that allow full "*:*" administrative privileges are not created',
            '2.1': 'Ensure CloudTrail is enabled in all regions',
            '2.2': 'Ensure CloudTrail log file validation is enabled',
            '2.3': 'Ensure the S3 bucket CloudTrail logs to is not publicly accessible',
            '2.4': 'Ensure CloudTrail trails are integrated with CloudWatch Logs',
            '2.5': 'Ensure AWS Config is enabled in all regions',
            '2.6': 'Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket',
            '2.7': 'Ensure CloudTrail logs are encrypted at rest using KMS CMKs',
            '2.8': 'Ensure rotation for customer created CMKs is enabled',
            '2.9': 'Ensure VPC flow logging is enabled in all VPCs',
            '2.10': 'Ensure Object-level logging for read events is enabled for S3 bucket',
            '2.11': 'Ensure Object-level logging for write events is enabled for S3 bucket',
            '2.12': 'Ensure CloudTrail is enabled in all regions',
            '2.13': 'Ensure CloudTrail log file validation is enabled',
            '2.14': 'Ensure the S3 bucket CloudTrail logs to is not publicly accessible',
            '2.15': 'Ensure CloudTrail trails are integrated with CloudWatch Logs',
            '2.16': 'Ensure AWS Config is enabled in all regions',
            '2.17': 'Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket',
            '2.18': 'Ensure CloudTrail logs are encrypted at rest using KMS CMKs',
            '2.19': 'Ensure rotation for customer created CMKs is enabled',
            '2.20': 'Ensure VPC flow logging is enabled in all VPCs',
            '2.21': 'Ensure Object-level logging for read events is enabled for S3 bucket',
            '2.22': 'Ensure Object-level logging for write events is enabled for S3 bucket'
        }
        
        # PCI DSS Requirements mapping
        self.pci_requirements = {
            '1.1': 'Establish and implement firewall and router configuration standards',
            '1.2': 'Build firewall and router configurations that restrict connections',
            '1.3': 'Prohibit direct public access between the Internet and any system component',
            '1.4': 'Install personal firewall software on any mobile and/or employee-owned devices',
            '1.5': 'Ensure security policies and operational procedures are documented',
            '2.1': 'Always change vendor-supplied defaults and remove or disable unnecessary default accounts',
            '2.2': 'Develop configuration standards for all system components',
            '2.3': 'Encrypt all non-console administrative access using strong cryptography',
            '2.4': 'Maintain an inventory of system components that are in scope for PCI DSS',
            '2.5': 'Ensure that security policies and operational procedures are documented',
            '3.1': 'Keep cardholder data storage to a minimum',
            '3.2': 'Do not store sensitive authentication data after authorization',
            '3.3': 'Mask PAN when displayed',
            '3.4': 'Render PAN unreadable anywhere it is stored',
            '3.5': 'Document and implement procedures to protect keys used to secure stored cardholder data',
            '3.6': 'Fully document and implement all key-management processes and procedures',
            '3.7': 'Ensure that security policies and operational procedures are documented',
            '4.1': 'Use strong cryptography and security protocols to safeguard sensitive cardholder data',
            '4.2': 'Never send unprotected PANs by end-user messaging technologies',
            '4.3': 'Ensure that security policies and operational procedures are documented',
            '5.1': 'Deploy anti-virus software on all systems commonly affected by malicious software',
            '5.2': 'Ensure that all anti-virus mechanisms are current, actively running, and capable of generating audit logs',
            '5.3': 'Ensure that security policies and operational procedures are documented',
            '6.1': 'Establish a process to identify security vulnerabilities',
            '6.2': 'Ensure that all system components and software are protected from known vulnerabilities',
            '6.3': 'Develop software applications in accordance with PCI DSS',
            '6.4': 'Follow change control processes and procedures for all changes to system components',
            '6.5': 'Address common coding vulnerabilities in software-development processes',
            '6.6': 'For public-facing web applications, address new threats and vulnerabilities',
            '6.7': 'Ensure that security policies and operational procedures are documented',
            '7.1': 'Limit access to system components and cardholder data to only those individuals',
            '7.2': 'Establish an access control system for systems components with multiple users',
            '7.3': 'Ensure that security policies and operational procedures are documented',
            '8.1': 'Define and implement policies and procedures to ensure proper user identification',
            '8.2': 'In addition to assigning a unique ID, employ at least one of the following methods',
            '8.3': 'Secure all individual access to system components',
            '8.4': 'Document and communicate authentication procedures and policies',
            '8.5': 'Do not use group, shared, or generic IDs, passwords, or other authentication methods',
            '8.6': 'Where other authentication mechanisms are used, these must be assigned to an individual',
            '8.7': 'All access to any database containing cardholder data is restricted',
            '8.8': 'Ensure that security policies and operational procedures are documented',
            '9.1': 'Use appropriate facility entry controls to limit and monitor physical access',
            '9.2': 'Implement procedures to easily distinguish between onsite personnel and visitors',
            '9.3': 'Control physical access for onsite personnel to the sensitive areas',
            '9.4': 'Implement procedures to identify and authorize visitors',
            '9.5': 'Physically secure all media',
            '9.6': 'Maintain strict control over the internal or external distribution of any kind of media',
            '9.7': 'Maintain strict control over the storage and accessibility of media',
            '9.8': 'Destroy media when it is no longer needed for business or legal reasons',
            '9.9': 'Protect devices that capture payment card data via direct physical interaction',
            '9.10': 'Ensure that security policies and operational procedures are documented',
            '10.1': 'Implement audit trails to link all access to system components',
            '10.2': 'Automated audit trails for all system components',
            '10.3': 'Record at least the following audit trail entries for all system components',
            '10.4': 'Using time-synchronization technology, synchronize all critical system clocks and times',
            '10.5': 'Secure audit trails so they cannot be altered',
            '10.6': 'Review logs and security events for all system components',
            '10.7': 'Retain audit trail history for at least one year',
            '10.8': 'Ensure that security policies and operational procedures are documented',
            '11.1': 'Test for the presence of wireless access points',
            '11.2': 'Run internal and external network vulnerability scans',
            '11.3': 'Implement a methodology for penetration testing',
            '11.4': 'Use network intrusion detection and/or intrusion prevention techniques',
            '11.5': 'Deploy file-integrity monitoring software',
            '11.6': 'Ensure that security policies and operational procedures are documented',
            '12.1': 'Establish, publish, maintain, and disseminate a security policy',
            '12.2': 'Implement a risk-assessment process',
            '12.3': 'Develop usage policies for critical technologies',
            '12.4': 'Ensure that security policies and operational procedures clearly define responsibilities',
            '12.5': 'Assign to an individual or team the following information security management responsibilities',
            '12.6': 'Implement a formal security awareness program',
            '12.7': 'Screen potential personnel prior to hire',
            '12.8': 'Maintain and implement policies and procedures to manage service providers',
            '12.9': 'Additional requirements for service providers',
            '12.10': 'Implement an incident response plan',
            '12.11': 'Ensure that security policies and operational procedures are documented'
        }

    def scan_security_hub_findings(self, days_back: int = 30) -> Dict[str, Any]:
        """Scan Security Hub findings for compliance violations"""
        logger.info(f"Scanning Security Hub findings for the last {days_back} days")
        
        try:
            # Get findings from Security Hub
            findings = self._get_security_hub_findings(days_back)
            
            # Analyze findings for compliance impact
            compliance_analysis = self._analyze_compliance_findings(findings)
            
            # Generate compliance report
            report = self._generate_compliance_report(compliance_analysis)
            
            return report
            
        except Exception as e:
            logger.error(f"Error scanning Security Hub findings: {e}")
            raise

    def _get_security_hub_findings(self, days_back: int) -> List[Dict[str, Any]]:
        """Retrieve Security Hub findings"""
        findings = []
        
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days_back)
        
        # Get findings with filters
        paginator = self.securityhub.get_paginator('get_findings')
        
        for page in paginator.paginate(
            Filters={
                'RecordState': [
                    {
                        'Value': 'ACTIVE',
                        'Comparison': 'EQUALS'
                    }
                ],
                'SeverityLabel': [
                    {
                        'Value': 'HIGH',
                        'Comparison': 'EQUALS'
                    },
                    {
                        'Value': 'CRITICAL',
                        'Comparison': 'EQUALS'
                    }
                ],
                'UpdatedAt': [
                    {
                        'Start': start_date.isoformat(),
                        'End': end_date.isoformat()
                    }
                ]
            }
        ):
            findings.extend(page['Findings'])
        
        return findings

    def _analyze_compliance_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze findings for CIS and PCI compliance impact"""
        analysis = {
            'cis_violations': [],
            'pci_violations': [],
            'critical_findings': [],
            'high_findings': [],
            'compliance_score': {
                'cis': 100,
                'pci': 100
            }
        }
        
        for finding in findings:
            # Check CIS compliance
            cis_impact = self._check_cis_compliance(finding)
            if cis_impact:
                analysis['cis_violations'].append(cis_impact)
            
            # Check PCI compliance
            pci_impact = self._check_pci_compliance(finding)
            if pci_impact:
                analysis['pci_violations'].append(pci_impact)
            
            # Categorize by severity
            severity = finding.get('Severity', {}).get('Label', 'UNKNOWN')
            if severity == 'CRITICAL':
                analysis['critical_findings'].append(finding)
            elif severity == 'HIGH':
                analysis['high_findings'].append(finding)
        
        # Calculate compliance scores
        analysis['compliance_score']['cis'] = self._calculate_cis_score(analysis['cis_violations'])
        analysis['compliance_score']['pci'] = self._calculate_pci_score(analysis['pci_violations'])
        
        return analysis

    def _check_cis_compliance(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if finding violates CIS controls"""
        finding_text = json.dumps(finding).lower()
        
        for control_id, control_description in self.cis_controls.items():
            if any(keyword in finding_text for keyword in control_description.lower().split()):
                return {
                    'control_id': control_id,
                    'control_description': control_description,
                    'finding_id': finding.get('Id'),
                    'finding_title': finding.get('Title'),
                    'severity': finding.get('Severity', {}).get('Label'),
                    'resources': finding.get('Resources', [])
                }
        
        return None

    def _check_pci_compliance(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if finding violates PCI DSS requirements"""
        finding_text = json.dumps(finding).lower()
        
        for req_id, req_description in self.pci_requirements.items():
            if any(keyword in finding_text for keyword in req_description.lower().split()):
                return {
                    'requirement_id': req_id,
                    'requirement_description': req_description,
                    'finding_id': finding.get('Id'),
                    'finding_title': finding.get('Title'),
                    'severity': finding.get('Severity', {}).get('Label'),
                    'resources': finding.get('Resources', [])
                }
        
        return None

    def _calculate_cis_score(self, violations: List[Dict[str, Any]]) -> int:
        """Calculate CIS compliance score (0-100)"""
        if not violations:
            return 100
        
        # Each violation reduces score by 5 points
        deduction = len(violations) * 5
        return max(0, 100 - deduction)

    def _calculate_pci_score(self, violations: List[Dict[str, Any]]) -> int:
        """Calculate PCI DSS compliance score (0-100)"""
        if not violations:
            return 100
        
        # Each violation reduces score by 3 points
        deduction = len(violations) * 3
        return max(0, 100 - deduction)

    def _generate_compliance_report(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive compliance report"""
        report = {
            'scan_timestamp': datetime.now().isoformat(),
            'environment': self.environment,
            'compliance_scores': analysis['compliance_score'],
            'summary': {
                'total_critical_findings': len(analysis['critical_findings']),
                'total_high_findings': len(analysis['high_findings']),
                'cis_violations': len(analysis['cis_violations']),
                'pci_violations': len(analysis['pci_violations'])
            },
            'cis_violations': analysis['cis_violations'],
            'pci_violations': analysis['pci_violations'],
            'critical_findings': analysis['critical_findings'],
            'high_findings': analysis['high_findings'],
            'recommendations': self._generate_recommendations(analysis)
        }
        
        return report

    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations based on findings"""
        recommendations = []
        
        if analysis['compliance_score']['cis'] < 80:
            recommendations.append("CIS compliance score is below 80%. Review and remediate CIS violations immediately.")
        
        if analysis['compliance_score']['pci'] < 80:
            recommendations.append("PCI DSS compliance score is below 80%. Review and remediate PCI violations immediately.")
        
        if analysis['critical_findings']:
            recommendations.append(f"Address {len(analysis['critical_findings'])} critical security findings immediately.")
        
        if analysis['cis_violations']:
            recommendations.append(f"Remediate {len(analysis['cis_violations'])} CIS control violations.")
        
        if analysis['pci_violations']:
            recommendations.append(f"Remediate {len(analysis['pci_violations'])} PCI DSS requirement violations.")
        
        if not recommendations:
            recommendations.append("No immediate action required. Continue monitoring compliance status.")
        
        return recommendations

    def save_report_to_s3(self, report: Dict[str, Any], filename: str = None) -> str:
        """Save compliance report to S3"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"compliance_report_{self.environment}_{timestamp}.json"
        
        try:
            self.s3.put_object(
                Bucket=self.s3_bucket,
                Key=f"compliance-reports/{filename}",
                Body=json.dumps(report, indent=2),
                ContentType='application/json'
            )
            
            logger.info(f"Compliance report saved to s3://{self.s3_bucket}/compliance-reports/{filename}")
            return f"s3://{self.s3_bucket}/compliance-reports/{filename}"
            
        except Exception as e:
            logger.error(f"Error saving report to S3: {e}")
            raise

    def send_compliance_notification(self, report: Dict[str, Any]) -> None:
        """Send compliance notification via SNS"""
        if not self.sns_topic_arn:
            logger.warning("SNS topic ARN not configured. Skipping notification.")
            return
        
        try:
            subject = f"Compliance Scan Report - {self.environment.upper()}"
            
            message = f"""
Compliance Scan Report - {report['scan_timestamp']}

Environment: {report['environment']}

Compliance Scores:
- CIS: {report['compliance_scores']['cis']}%
- PCI DSS: {report['compliance_scores']['pci']}%

Summary:
- Critical Findings: {report['summary']['total_critical_findings']}
- High Findings: {report['summary']['total_high_findings']}
- CIS Violations: {report['summary']['cis_violations']}
- PCI Violations: {report['summary']['pci_violations']}

Recommendations:
{chr(10).join(f"- {rec}" for rec in report['recommendations'])}

Full report available in S3.
            """
            
            self.sns.publish(
                TopicArn=self.sns_topic_arn,
                Subject=subject,
                Message=message
            )
            
            logger.info("Compliance notification sent successfully")
            
        except Exception as e:
            logger.error(f"Error sending compliance notification: {e}")
            raise

    def run_compliance_scan(self, days_back: int = 30, save_to_s3: bool = True, send_notification: bool = True) -> Dict[str, Any]:
        """Run complete compliance scan"""
        logger.info("Starting comprehensive compliance scan")
        
        # Scan Security Hub findings
        report = self.scan_security_hub_findings(days_back)
        
        # Save to S3 if requested
        if save_to_s3:
            s3_location = self.save_report_to_s3(report)
            report['s3_location'] = s3_location
        
        # Send notification if requested
        if send_notification:
            self.send_compliance_notification(report)
        
        logger.info("Compliance scan completed successfully")
        return report


def main():
    """Main function for command-line execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='AWS Compliance Scanner')
    parser.add_argument('--days-back', type=int, default=30, help='Number of days to scan back')
    parser.add_argument('--no-s3', action='store_true', help='Skip saving to S3')
    parser.add_argument('--no-notification', action='store_true', help='Skip sending notifications')
    parser.add_argument('--region', type=str, help='AWS region')
    
    args = parser.parse_args()
    
    try:
        scanner = ComplianceScanner(region=args.region)
        report = scanner.run_compliance_scan(
            days_back=args.days_back,
            save_to_s3=not args.no_s3,
            send_notification=not args.no_notification
        )
        
        print(json.dumps(report, indent=2))
        
    except Exception as e:
        logger.error(f"Compliance scan failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main() 