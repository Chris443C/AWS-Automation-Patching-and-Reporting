#!/usr/bin/env python3
"""
AWS Config Compliance Integration
Integrates AWS Config rule-based compliance checks with Security Hub and patching automation
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

class ConfigComplianceIntegration:
    """Integrates AWS Config compliance checks with the patching automation solution"""
    
    def __init__(self, region: str = None):
        self.region = region or os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
        self.config = boto3.client('config', region_name=self.region)
        self.s3 = boto3.client('s3')
        self.sns = boto3.client('sns')
        self.ssm = boto3.client('ssm')
        
        # Configuration
        self.s3_bucket = os.environ.get('S3_BUCKET', 'aws-patching-automation-reports')
        self.environment = os.environ.get('ENVIRONMENT', 'dev')
        self.sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
        
        # Define Config rules that are relevant to patching and compliance
        self.patching_config_rules = [
            'SSMAgentInstalled',
            'PatchCompliance',
            'PatchApprovalWorkflow'
        ]
        
        self.security_config_rules = [
            'SecurityGroupRestrictedAccess',
            'S3BucketEncryption',
            'CloudTrailEnabled'
        ]
        
        # Map Config rules to CIS controls and PCI requirements
        self.config_rule_mapping = {
            'SSMAgentInstalled': {
                'cis_controls': ['1.19'],  # Ensure IAM instance roles are used
                'pci_requirements': ['7.1'],  # Limit access to system components
                'description': 'SSM Agent installation for patch management'
            },
            'PatchCompliance': {
                'cis_controls': ['6.2'],  # Ensure all system components are protected
                'pci_requirements': ['6.2'],  # Ensure all system components are protected
                'description': 'Patch compliance status'
            },
            'PatchApprovalWorkflow': {
                'cis_controls': ['6.4'],  # Follow change control processes
                'pci_requirements': ['6.4'],  # Follow change control processes
                'description': 'Patch approval workflow configuration'
            },
            'SecurityGroupRestrictedAccess': {
                'cis_controls': ['3.1', '3.2'],  # VPC and security group controls
                'pci_requirements': ['1.1', '1.2'],  # Firewall and router configuration
                'description': 'Security group access restrictions'
            },
            'S3BucketEncryption': {
                'cis_controls': ['2.7'],  # CloudTrail encryption
                'pci_requirements': ['3.4'],  # Render PAN unreadable
                'description': 'S3 bucket encryption'
            },
            'CloudTrailEnabled': {
                'cis_controls': ['2.1', '2.4'],  # CloudTrail configuration
                'pci_requirements': ['10.1', '10.2'],  # Audit trails
                'description': 'CloudTrail audit logging'
            }
        }

    def get_config_compliance_status(self, rule_names: List[str] = None) -> Dict[str, Any]:
        """Get compliance status for specified Config rules"""
        logger.info("Retrieving AWS Config compliance status")
        
        try:
            if not rule_names:
                rule_names = self.patching_config_rules + self.security_config_rules
            
            compliance_results = {}
            
            for rule_name in rule_names:
                full_rule_name = f"{rule_name}-{self.environment}"
                
                try:
                    # Get compliance details for the rule
                    response = self.config.get_compliance_details_by_config_rule(
                        ConfigRuleName=full_rule_name
                    )
                    
                    rule_compliance = {
                        'rule_name': rule_name,
                        'full_rule_name': full_rule_name,
                        'compliance_summary': {
                            'compliant': 0,
                            'non_compliant': 0,
                            'not_applicable': 0
                        },
                        'resources': [],
                        'mapping': self.config_rule_mapping.get(rule_name, {})
                    }
                    
                    # Process evaluation results
                    for evaluation in response.get('EvaluationResults', []):
                        compliance_type = evaluation.get('ComplianceType', 'NOT_APPLICABLE')
                        resource_id = evaluation.get('EvaluationResultIdentifier', {}).get('EvaluationResultQualifier', {}).get('ResourceId', 'Unknown')
                        annotation = evaluation.get('Annotation', '')
                        
                        # Update compliance summary
                        if compliance_type == 'COMPLIANT':
                            rule_compliance['compliance_summary']['compliant'] += 1
                        elif compliance_type == 'NON_COMPLIANT':
                            rule_compliance['compliance_summary']['non_compliant'] += 1
                        else:
                            rule_compliance['compliance_summary']['not_applicable'] += 1
                        
                        # Add resource details
                        rule_compliance['resources'].append({
                            'resource_id': resource_id,
                            'compliance_type': compliance_type,
                            'annotation': annotation,
                            'timestamp': evaluation.get('ResultRecordedTime', '')
                        })
                    
                    compliance_results[rule_name] = rule_compliance
                    
                except self.config.exceptions.NoSuchConfigRuleException:
                    logger.warning(f"Config rule {full_rule_name} not found")
                    compliance_results[rule_name] = {
                        'rule_name': rule_name,
                        'full_rule_name': full_rule_name,
                        'error': 'Rule not found',
                        'mapping': self.config_rule_mapping.get(rule_name, {})
                    }
                except Exception as e:
                    logger.error(f"Error getting compliance for rule {rule_name}: {e}")
                    compliance_results[rule_name] = {
                        'rule_name': rule_name,
                        'full_rule_name': full_rule_name,
                        'error': str(e),
                        'mapping': self.config_rule_mapping.get(rule_name, {})
                    }
            
            return compliance_results
            
        except Exception as e:
            logger.error(f"Error retrieving Config compliance status: {e}")
            raise

    def calculate_config_compliance_score(self, compliance_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate compliance scores based on Config rule results"""
        logger.info("Calculating Config compliance scores")
        
        try:
            total_rules = len(compliance_results)
            compliant_rules = 0
            non_compliant_rules = 0
            total_resources = 0
            compliant_resources = 0
            non_compliant_resources = 0
            
            # Calculate scores for each rule
            for rule_name, rule_data in compliance_results.items():
                if 'error' in rule_data:
                    continue
                
                summary = rule_data.get('compliance_summary', {})
                rule_compliant = summary.get('compliant', 0)
                rule_non_compliant = summary.get('non_compliant', 0)
                rule_total = rule_compliant + rule_non_compliant
                
                total_resources += rule_total
                compliant_resources += rule_compliant
                non_compliant_resources += rule_non_compliant
                
                # Rule is compliant if all resources are compliant
                if rule_total > 0 and rule_non_compliant == 0:
                    compliant_rules += 1
                elif rule_non_compliant > 0:
                    non_compliant_rules += 1
            
            # Calculate overall scores
            overall_score = 0
            if total_resources > 0:
                overall_score = (compliant_resources / total_resources) * 100
            
            rule_score = 0
            if total_rules > 0:
                rule_score = (compliant_rules / total_rules) * 100
            
            return {
                'overall_score': round(overall_score, 2),
                'rule_score': round(rule_score, 2),
                'summary': {
                    'total_rules': total_rules,
                    'compliant_rules': compliant_rules,
                    'non_compliant_rules': non_compliant_rules,
                    'total_resources': total_resources,
                    'compliant_resources': compliant_resources,
                    'non_compliant_resources': non_compliant_resources
                }
            }
            
        except Exception as e:
            logger.error(f"Error calculating compliance scores: {e}")
            raise

    def map_config_to_cis_pci(self, compliance_results: Dict[str, Any]) -> Dict[str, Any]:
        """Map Config rule violations to CIS controls and PCI requirements"""
        logger.info("Mapping Config violations to CIS and PCI requirements")
        
        try:
            cis_violations = []
            pci_violations = []
            
            for rule_name, rule_data in compliance_results.items():
                if 'error' in rule_data:
                    continue
                
                mapping = rule_data.get('mapping', {})
                cis_controls = mapping.get('cis_controls', [])
                pci_requirements = mapping.get('pci_requirements', [])
                
                # Check for non-compliant resources
                non_compliant_resources = [
                    resource for resource in rule_data.get('resources', [])
                    if resource.get('compliance_type') == 'NON_COMPLIANT'
                ]
                
                if non_compliant_resources:
                    # Map to CIS controls
                    for control_id in cis_controls:
                        for resource in non_compliant_resources:
                            cis_violations.append({
                                'control_id': control_id,
                                'config_rule': rule_name,
                                'resource_id': resource.get('resource_id'),
                                'annotation': resource.get('annotation'),
                                'description': mapping.get('description', '')
                            })
                    
                    # Map to PCI requirements
                    for req_id in pci_requirements:
                        for resource in non_compliant_resources:
                            pci_violations.append({
                                'requirement_id': req_id,
                                'config_rule': rule_name,
                                'resource_id': resource.get('resource_id'),
                                'annotation': resource.get('annotation'),
                                'description': mapping.get('description', '')
                            })
            
            return {
                'cis_violations': cis_violations,
                'pci_violations': pci_violations
            }
            
        except Exception as e:
            logger.error(f"Error mapping Config to CIS/PCI: {e}")
            raise

    def generate_config_compliance_report(self, compliance_results: Dict[str, Any], 
                                        compliance_scores: Dict[str, Any],
                                        cis_pci_mapping: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive Config compliance report"""
        logger.info("Generating Config compliance report")
        
        try:
            report = {
                'report_timestamp': datetime.now().isoformat(),
                'environment': self.environment,
                'compliance_scores': compliance_scores,
                'config_rules': compliance_results,
                'cis_violations': cis_pci_mapping.get('cis_violations', []),
                'pci_violations': cis_pci_mapping.get('pci_violations', []),
                'summary': {
                    'total_config_rules': len(compliance_results),
                    'total_cis_violations': len(cis_pci_mapping.get('cis_violations', [])),
                    'total_pci_violations': len(cis_pci_mapping.get('pci_violations', [])),
                    'patching_rules_compliant': 0,
                    'security_rules_compliant': 0
                },
                'recommendations': []
            }
            
            # Calculate rule category compliance
            for rule_name, rule_data in compliance_results.items():
                if 'error' in rule_data:
                    continue
                
                summary = rule_data.get('compliance_summary', {})
                is_compliant = summary.get('non_compliant', 0) == 0
                
                if rule_name in self.patching_config_rules and is_compliant:
                    report['summary']['patching_rules_compliant'] += 1
                elif rule_name in self.security_config_rules and is_compliant:
                    report['summary']['security_rules_compliant'] += 1
            
            # Generate recommendations
            recommendations = []
            
            if compliance_scores.get('overall_score', 0) < 80:
                recommendations.append("Config compliance score is below 80%. Review and remediate non-compliant resources.")
            
            if len(cis_pci_mapping.get('cis_violations', [])) > 0:
                recommendations.append(f"Found {len(cis_pci_mapping['cis_violations'])} CIS control violations. Review Config rule compliance.")
            
            if len(cis_pci_mapping.get('pci_violations', [])) > 0:
                recommendations.append(f"Found {len(cis_pci_mapping['pci_violations'])} PCI requirement violations. Review Config rule compliance.")
            
            # Check specific patching-related rules
            patching_rules_status = {}
            for rule_name in self.patching_config_rules:
                if rule_name in compliance_results:
                    rule_data = compliance_results[rule_name]
                    if 'error' not in rule_data:
                        summary = rule_data.get('compliance_summary', {})
                        if summary.get('non_compliant', 0) > 0:
                            patching_rules_status[rule_name] = 'NON_COMPLIANT'
                        else:
                            patching_rules_status[rule_name] = 'COMPLIANT'
            
            for rule_name, status in patching_rules_status.items():
                if status == 'NON_COMPLIANT':
                    recommendations.append(f"Config rule '{rule_name}' is non-compliant. This may affect patch automation.")
            
            if not recommendations:
                recommendations.append("All Config rules are compliant. Continue monitoring compliance status.")
            
            report['recommendations'] = recommendations
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating Config compliance report: {e}")
            raise

    def save_config_report_to_s3(self, report: Dict[str, Any], filename: str = None) -> str:
        """Save Config compliance report to S3"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"config_compliance_report_{self.environment}_{timestamp}.json"
        
        try:
            self.s3.put_object(
                Bucket=self.s3_bucket,
                Key=f"config-compliance-reports/{filename}",
                Body=json.dumps(report, indent=2),
                ContentType='application/json'
            )
            
            logger.info(f"Config compliance report saved to s3://{self.s3_bucket}/config-compliance-reports/{filename}")
            return f"s3://{self.s3_bucket}/config-compliance-reports/{filename}"
            
        except Exception as e:
            logger.error(f"Error saving Config report to S3: {e}")
            raise

    def send_config_compliance_notification(self, report: Dict[str, Any]) -> None:
        """Send Config compliance notification via SNS"""
        if not self.sns_topic_arn:
            logger.warning("SNS topic ARN not configured. Skipping notification.")
            return
        
        try:
            subject = f"AWS Config Compliance Report - {self.environment.upper()}"
            
            message = f"""
AWS Config Compliance Report - {report['report_timestamp']}

Environment: {report['environment']}

Compliance Scores:
- Overall Score: {report['compliance_scores']['overall_score']}%
- Rule Score: {report['compliance_scores']['rule_score']}%

Summary:
- Total Config Rules: {report['summary']['total_config_rules']}
- CIS Violations: {report['summary']['total_cis_violations']}
- PCI Violations: {report['summary']['total_pci_violations']}
- Patching Rules Compliant: {report['summary']['patching_rules_compliant']}/{len(self.patching_config_rules)}
- Security Rules Compliant: {report['summary']['security_rules_compliant']}/{len(self.security_config_rules)}

Recommendations:
{chr(10).join(f"- {rec}" for rec in report['recommendations'])}

Full report available in S3.
            """
            
            self.sns.publish(
                TopicArn=self.sns_topic_arn,
                Subject=subject,
                Message=message
            )
            
            logger.info("Config compliance notification sent successfully")
            
        except Exception as e:
            logger.error(f"Error sending Config compliance notification: {e}")
            raise

    def run_config_compliance_scan(self, rule_names: List[str] = None, 
                                 save_to_s3: bool = True, 
                                 send_notification: bool = True) -> Dict[str, Any]:
        """Run complete Config compliance scan"""
        logger.info("Starting AWS Config compliance scan")
        
        try:
            # Get Config compliance status
            compliance_results = self.get_config_compliance_status(rule_names)
            
            # Calculate compliance scores
            compliance_scores = self.calculate_config_compliance_score(compliance_results)
            
            # Map to CIS and PCI requirements
            cis_pci_mapping = self.map_config_to_cis_pci(compliance_results)
            
            # Generate comprehensive report
            report = self.generate_config_compliance_report(
                compliance_results, compliance_scores, cis_pci_mapping
            )
            
            # Save to S3 if requested
            if save_to_s3:
                s3_location = self.save_config_report_to_s3(report)
                report['s3_location'] = s3_location
            
            # Send notification if requested
            if send_notification:
                self.send_config_compliance_notification(report)
            
            logger.info("AWS Config compliance scan completed successfully")
            return report
            
        except Exception as e:
            logger.error(f"Config compliance scan failed: {e}")
            raise

    def get_patching_related_violations(self) -> Dict[str, Any]:
        """Get violations specifically related to patching automation"""
        logger.info("Retrieving patching-related Config violations")
        
        try:
            patching_violations = {
                'ssm_agent_issues': [],
                'patch_compliance_issues': [],
                'approval_workflow_issues': []
            }
            
            # Get compliance for patching rules
            compliance_results = self.get_config_compliance_status(self.patching_config_rules)
            
            for rule_name, rule_data in compliance_results.items():
                if 'error' in rule_data:
                    continue
                
                non_compliant_resources = [
                    resource for resource in rule_data.get('resources', [])
                    if resource.get('compliance_type') == 'NON_COMPLIANT'
                ]
                
                if rule_name == 'SSMAgentInstalled':
                    patching_violations['ssm_agent_issues'] = non_compliant_resources
                elif rule_name == 'PatchCompliance':
                    patching_violations['patch_compliance_issues'] = non_compliant_resources
                elif rule_name == 'PatchApprovalWorkflow':
                    patching_violations['approval_workflow_issues'] = non_compliant_resources
            
            return patching_violations
            
        except Exception as e:
            logger.error(f"Error getting patching-related violations: {e}")
            raise


def main():
    """Main function for command-line execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='AWS Config Compliance Integration')
    parser.add_argument('--rule-names', nargs='+', help='Specific Config rule names to check')
    parser.add_argument('--no-s3', action='store_true', help='Skip saving to S3')
    parser.add_argument('--no-notification', action='store_true', help='Skip sending notifications')
    parser.add_argument('--region', type=str, help='AWS region')
    parser.add_argument('--patching-only', action='store_true', help='Check only patching-related rules')
    
    args = parser.parse_args()
    
    try:
        integration = ConfigComplianceIntegration(region=args.region)
        
        if args.patching_only:
            # Get only patching-related violations
            violations = integration.get_patching_related_violations()
            print(json.dumps(violations, indent=2))
        else:
            # Run full compliance scan
            report = integration.run_config_compliance_scan(
                rule_names=args.rule_names,
                save_to_s3=not args.no_s3,
                send_notification=not args.no_notification
            )
            print(json.dumps(report, indent=2))
        
    except Exception as e:
        logger.error(f"Config compliance integration failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main() 