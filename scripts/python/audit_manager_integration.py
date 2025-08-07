#!/usr/bin/env python3
"""
AWS Audit Manager Integration
Integrates AWS Audit Manager with the existing compliance automation solution
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

class AuditManagerIntegration:
    """Integrates AWS Audit Manager with the compliance automation solution"""
    
    def __init__(self, region: str = None):
        self.region = region or os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
        self.auditmanager = boto3.client('auditmanager', region_name=self.region)
        self.config = boto3.client('config', region_name=self.region)
        self.securityhub = boto3.client('securityhub', region_name=self.region)
        self.inspector = boto3.client('inspector2', region_name=self.region)
        self.s3 = boto3.client('s3')
        self.sns = boto3.client('sns')
        
        # Configuration
        self.s3_bucket = os.environ.get('S3_BUCKET', 'aws-patching-automation-reports')
        self.environment = os.environ.get('ENVIRONMENT', 'dev')
        self.sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
        
        # Supported compliance frameworks
        self.supported_frameworks = [
            'CIS AWS Foundations Benchmark',
            'PCI DSS',
            'SOC 2',
            'HIPAA',
            'ISO 27001'
        ]

    def get_available_frameworks(self) -> List[Dict[str, Any]]:
        """Get available compliance frameworks in Audit Manager"""
        logger.info("Retrieving available compliance frameworks")
        
        try:
            response = self.auditmanager.list_assessment_frameworks(
                frameworkType='Standard'
            )
            
            available_frameworks = []
            for framework in response.get('frameworkMetadataList', []):
                framework_name = framework.get('name', '')
                
                # Check if framework is supported
                if any(supported in framework_name for supported in self.supported_frameworks):
                    available_frameworks.append({
                        'id': framework.get('id'),
                        'name': framework_name,
                        'type': framework.get('type'),
                        'description': framework.get('description', ''),
                        'complianceType': framework.get('complianceType', '')
                    })
            
            logger.info(f"Found {len(available_frameworks)} supported frameworks")
            return available_frameworks
            
        except Exception as e:
            logger.error(f"Error getting available frameworks: {e}")
            return []

    def create_assessment(self, framework_id: str, assessment_name: str = None) -> Optional[str]:
        """Create a new compliance assessment"""
        logger.info(f"Creating assessment for framework: {framework_id}")
        
        try:
            if not assessment_name:
                assessment_name = f"Automated Compliance Assessment - {self.environment} - {datetime.now().strftime('%Y%m%d')}"
            
            # Create assessment
            response = self.auditmanager.create_assessment(
                name=assessment_name,
                assessmentReportsDestination={
                    'destination': 's3',
                    'destinationType': 'S3'
                },
                frameworkId=framework_id,
                description=f'Automated compliance assessment for {self.environment} environment',
                scope={
                    'awsAccounts': [
                        {
                            'id': self._get_account_id(),
                            'emailAddress': os.environ.get('NOTIFICATION_EMAIL', 'admin@company.com')
                        }
                    ]
                }
            )
            
            assessment_id = response.get('assessment', {}).get('id')
            logger.info(f"Created assessment with ID: {assessment_id}")
            return assessment_id
            
        except Exception as e:
            logger.error(f"Error creating assessment: {e}")
            return None

    def get_existing_assessments(self) -> List[Dict[str, Any]]:
        """Get existing assessments"""
        logger.info("Retrieving existing assessments")
        
        try:
            response = self.auditmanager.list_assessments()
            
            assessments = []
            for assessment in response.get('assessmentMetadata', []):
                assessments.append({
                    'id': assessment.get('id'),
                    'name': assessment.get('name'),
                    'status': assessment.get('status'),
                    'framework': assessment.get('framework', {}).get('name'),
                    'created_at': assessment.get('createdAt'),
                    'last_updated': assessment.get('lastUpdated')
                })
            
            return assessments
            
        except Exception as e:
            logger.error(f"Error getting existing assessments: {e}")
            return []

    def collect_evidence_from_config(self, assessment_id: str) -> Dict[str, Any]:
        """Collect evidence from AWS Config"""
        logger.info("Collecting evidence from AWS Config")
        
        try:
            evidence_collection = {
                'source': 'AWS Config',
                'timestamp': datetime.now().isoformat(),
                'evidence_items': []
            }
            
            # Get Config rules
            rules_response = self.config.describe_config_rules()
            
            for rule in rules_response.get('ConfigRules', []):
                rule_name = rule.get('ConfigRuleName')
                
                try:
                    # Get compliance details for the rule
                    compliance_response = self.config.get_compliance_details_by_config_rule(
                        ConfigRuleName=rule_name
                    )
                    
                    for evaluation in compliance_response.get('EvaluationResults', []):
                        evidence_item = {
                            'rule_name': rule_name,
                            'resource_id': evaluation.get('EvaluationResultIdentifier', {}).get('EvaluationResultQualifier', {}).get('ResourceId'),
                            'compliance_type': evaluation.get('ComplianceType'),
                            'timestamp': evaluation.get('ResultRecordedTime', '').isoformat(),
                            'annotation': evaluation.get('Annotation', ''),
                            'evidence_type': 'AWS Config Rule Evaluation'
                        }
                        
                        evidence_collection['evidence_items'].append(evidence_item)
                        
                except Exception as e:
                    logger.warning(f"Error getting compliance details for rule {rule_name}: {e}")
                    continue
            
            logger.info(f"Collected {len(evidence_collection['evidence_items'])} Config evidence items")
            return evidence_collection
            
        except Exception as e:
            logger.error(f"Error collecting Config evidence: {e}")
            return {'source': 'AWS Config', 'evidence_items': []}

    def collect_evidence_from_security_hub(self, assessment_id: str) -> Dict[str, Any]:
        """Collect evidence from Security Hub"""
        logger.info("Collecting evidence from Security Hub")
        
        try:
            evidence_collection = {
                'source': 'Security Hub',
                'timestamp': datetime.now().isoformat(),
                'evidence_items': []
            }
            
            # Get Security Hub findings
            findings_response = self.securityhub.get_findings(
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
                    'product_name': finding.get('ProductName', ''),
                    'evidence_type': 'Security Hub Finding'
                }
                
                evidence_collection['evidence_items'].append(evidence_item)
            
            logger.info(f"Collected {len(evidence_collection['evidence_items'])} Security Hub evidence items")
            return evidence_collection
            
        except Exception as e:
            logger.error(f"Error collecting Security Hub evidence: {e}")
            return {'source': 'Security Hub', 'evidence_items': []}

    def collect_evidence_from_inspector(self, assessment_id: str) -> Dict[str, Any]:
        """Collect evidence from AWS Inspector"""
        logger.info("Collecting evidence from AWS Inspector")
        
        try:
            evidence_collection = {
                'source': 'AWS Inspector',
                'timestamp': datetime.now().isoformat(),
                'evidence_items': []
            }
            
            # Get Inspector findings
            findings_response = self.inspector.list_findings(
                maxResults=100
            )
            
            for finding in findings_response.get('findings', []):
                evidence_item = {
                    'finding_arn': finding.get('findingArn'),
                    'severity': finding.get('severity'),
                    'status': finding.get('status'),
                    'timestamp': finding.get('updatedAt', '').isoformat(),
                    'title': finding.get('title', ''),
                    'description': finding.get('description', ''),
                    'package_vulnerability_id': finding.get('packageVulnerabilityDetails', {}).get('vulnerabilityId'),
                    'evidence_type': 'Inspector Finding'
                }
                
                evidence_collection['evidence_items'].append(evidence_item)
            
            logger.info(f"Collected {len(evidence_collection['evidence_items'])} Inspector evidence items")
            return evidence_collection
            
        except Exception as e:
            logger.error(f"Error collecting Inspector evidence: {e}")
            return {'source': 'AWS Inspector', 'evidence_items': []}

    def upload_evidence_to_audit_manager(self, assessment_id: str, evidence_collections: List[Dict[str, Any]]) -> bool:
        """Upload evidence to Audit Manager"""
        logger.info(f"Uploading evidence to assessment: {assessment_id}")
        
        try:
            # Get evidence folders for the assessment
            folders_response = self.auditmanager.get_evidence_folders_by_assessment(
                assessmentId=assessment_id
            )
            
            evidence_folders = folders_response.get('evidenceFolders', [])
            if not evidence_folders:
                logger.warning("No evidence folders found for assessment")
                return False
            
            # Use the first folder as the default
            default_folder_id = evidence_folders[0].get('id')
            
            uploaded_count = 0
            
            for collection in evidence_collections:
                for evidence_item in collection.get('evidence_items', []):
                    try:
                        # Create evidence in Audit Manager
                        self.auditmanager.create_evidence(
                            assessmentId=assessment_id,
                            evidenceFolderId=default_folder_id,
                            dataSource=collection.get('source', 'Unknown'),
                            evidenceByType='Manual',
                            content=json.dumps(evidence_item),
                            name=f"{collection.get('source')} - {evidence_item.get('evidence_type', 'Evidence')}",
                            description=evidence_item.get('description', 'Automated evidence collection')
                        )
                        
                        uploaded_count += 1
                        
                    except Exception as e:
                        logger.warning(f"Error uploading evidence item: {e}")
                        continue
            
            logger.info(f"Successfully uploaded {uploaded_count} evidence items")
            return uploaded_count > 0
            
        except Exception as e:
            logger.error(f"Error uploading evidence to Audit Manager: {e}")
            return False

    def generate_assessment_report(self, assessment_id: str) -> Dict[str, Any]:
        """Generate assessment report"""
        logger.info(f"Generating assessment report for: {assessment_id}")
        
        try:
            # Get assessment details
            assessment_response = self.auditmanager.get_assessment(
                assessmentId=assessment_id
            )
            
            assessment = assessment_response.get('assessment', {})
            
            # Get assessment evidence
            evidence_response = self.auditmanager.get_evidence_by_assessment_control(
                assessmentId=assessment_id
            )
            
            # Calculate compliance metrics
            compliance_metrics = self._calculate_compliance_metrics(evidence_response.get('evidenceByAssessmentControl', []))
            
            report = {
                'report_timestamp': datetime.now().isoformat(),
                'environment': self.environment,
                'assessment_id': assessment_id,
                'assessment_name': assessment.get('name'),
                'framework': assessment.get('framework', {}).get('name'),
                'assessment_status': assessment.get('status'),
                'compliance_metrics': compliance_metrics,
                'evidence_summary': {
                    'total_evidence_items': len(evidence_response.get('evidenceByAssessmentControl', [])),
                    'evidence_sources': self._get_evidence_sources(evidence_response.get('evidenceByAssessmentControl', []))
                },
                'metadata': {
                    'created_at': assessment.get('createdAt'),
                    'last_updated': assessment.get('lastUpdated'),
                    'scope': assessment.get('scope', {})
                }
            }
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating assessment report: {e}")
            return {}

    def _calculate_compliance_metrics(self, evidence_by_control: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate compliance metrics from evidence"""
        try:
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
            
        except Exception as e:
            logger.error(f"Error calculating compliance metrics: {e}")
            return {
                'total_controls': 0,
                'compliant_controls': 0,
                'non_compliant_controls': 0,
                'compliance_score': 0
            }

    def _get_evidence_sources(self, evidence_by_control: List[Dict[str, Any]]) -> List[str]:
        """Get unique evidence sources"""
        try:
            sources = set()
            for control in evidence_by_control:
                for evidence in control.get('evidence', []):
                    data_source = evidence.get('dataSource', '')
                    if data_source:
                        sources.add(data_source)
            
            return list(sources)
            
        except Exception as e:
            logger.error(f"Error getting evidence sources: {e}")
            return []

    def _get_account_id(self) -> str:
        """Get current AWS account ID"""
        try:
            sts = boto3.client('sts')
            response = sts.get_caller_identity()
            return response.get('Account', '')
        except Exception as e:
            logger.error(f"Error getting account ID: {e}")
            return ''

    def save_report_to_s3(self, report: Dict[str, Any], filename: str = None) -> str:
        """Save assessment report to S3"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"audit_manager_report_{self.environment}_{timestamp}.json"
        
        try:
            self.s3.put_object(
                Bucket=self.s3_bucket,
                Key=f"audit-reports/{filename}",
                Body=json.dumps(report, indent=2),
                ContentType='application/json'
            )
            
            logger.info(f"Audit Manager report saved to s3://{self.s3_bucket}/audit-reports/{filename}")
            return f"s3://{self.s3_bucket}/audit-reports/{filename}"
            
        except Exception as e:
            logger.error(f"Error saving report to S3: {e}")
            raise

    def send_audit_notification(self, report: Dict[str, Any], s3_location: str) -> None:
        """Send audit notification via SNS"""
        if not self.sns_topic_arn:
            logger.warning("SNS topic ARN not configured. Skipping notification.")
            return
        
        try:
            subject = f"Audit Manager Assessment Report - {self.environment.upper()}"
            
            compliance_score = report.get('compliance_metrics', {}).get('compliance_score', 0)
            
            message = f"""
Audit Manager Assessment Report

Assessment: {report.get('assessment_name', 'N/A')}
Framework: {report.get('framework', 'N/A')}
Compliance Score: {compliance_score}%
Status: {report.get('assessment_status', 'N/A')}

Evidence Summary:
- Total Evidence Items: {report.get('evidence_summary', {}).get('total_evidence_items', 0)}
- Evidence Sources: {', '.join(report.get('evidence_summary', {}).get('evidence_sources', []))}

Report Location: {s3_location}

Timestamp: {report.get('report_timestamp', 'N/A')}
            """
            
            self.sns.publish(
                TopicArn=self.sns_topic_arn,
                Subject=subject,
                Message=message
            )
            
            logger.info("Audit notification sent successfully")
            
        except Exception as e:
            logger.error(f"Error sending audit notification: {e}")
            raise

    def run_automated_assessment(self, framework_name: str = None, assessment_name: str = None) -> Dict[str, Any]:
        """Run complete automated assessment workflow"""
        logger.info("Starting automated Audit Manager assessment")
        
        try:
            # Get available frameworks
            frameworks = self.get_available_frameworks()
            
            if not frameworks:
                raise Exception("No supported frameworks found")
            
            # Select framework
            selected_framework = None
            if framework_name:
                for framework in frameworks:
                    if framework_name.lower() in framework['name'].lower():
                        selected_framework = framework
                        break
            
            if not selected_framework:
                selected_framework = frameworks[0]  # Use first available framework
            
            logger.info(f"Selected framework: {selected_framework['name']}")
            
            # Create assessment
            assessment_id = self.create_assessment(
                selected_framework['id'], 
                assessment_name
            )
            
            if not assessment_id:
                raise Exception("Failed to create assessment")
            
            # Collect evidence from multiple sources
            evidence_collections = [
                self.collect_evidence_from_config(assessment_id),
                self.collect_evidence_from_security_hub(assessment_id),
                self.collect_evidence_from_inspector(assessment_id)
            ]
            
            # Upload evidence to Audit Manager
            evidence_uploaded = self.upload_evidence_to_audit_manager(
                assessment_id, evidence_collections
            )
            
            if not evidence_uploaded:
                logger.warning("No evidence was uploaded to Audit Manager")
            
            # Generate assessment report
            report = self.generate_assessment_report(assessment_id)
            
            # Save report to S3
            s3_location = self.save_report_to_s3(report)
            report['s3_location'] = s3_location
            
            # Send notification
            self.send_audit_notification(report, s3_location)
            
            logger.info("Automated assessment completed successfully")
            return report
            
        except Exception as e:
            logger.error(f"Automated assessment failed: {e}")
            raise


def main():
    """Main function for command-line execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='AWS Audit Manager Integration')
    parser.add_argument('--framework', type=str, help='Compliance framework name')
    parser.add_argument('--assessment-name', type=str, help='Assessment name')
    parser.add_argument('--region', type=str, help='AWS region')
    parser.add_argument('--list-frameworks', action='store_true', help='List available frameworks')
    parser.add_argument('--list-assessments', action='store_true', help='List existing assessments')
    parser.add_argument('--no-s3', action='store_true', help='Skip saving to S3')
    parser.add_argument('--no-notification', action='store_true', help='Skip sending notifications')
    
    args = parser.parse_args()
    
    try:
        integration = AuditManagerIntegration(region=args.region)
        
        if args.list_frameworks:
            frameworks = integration.get_available_frameworks()
            print(json.dumps(frameworks, indent=2))
        elif args.list_assessments:
            assessments = integration.get_existing_assessments()
            print(json.dumps(assessments, indent=2))
        else:
            # Run automated assessment
            report = integration.run_automated_assessment(
                framework_name=args.framework,
                assessment_name=args.assessment_name
            )
            print(json.dumps(report, indent=2))
        
    except Exception as e:
        logger.error(f"Audit Manager integration failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main() 