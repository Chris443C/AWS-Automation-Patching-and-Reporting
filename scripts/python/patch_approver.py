#!/usr/bin/env python3
"""
Patch Approver for AWS Automation Patching
Handles patch approval workflows and manages patch baselines
"""

import json
import boto3
import os
import logging
import re
import time
import random
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import hashlib
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PatchApprover:
    def __init__(self):
        """Initialize the patch approver with AWS clients"""
        self.ssm = boto3.client('ssm')
        self.s3 = boto3.client('s3')
        self.sns = boto3.client('sns')
        self.ec2 = boto3.client('ec2')
        
        # Environment variables with validation
        self.environment = self._validate_environment(os.environ.get('ENVIRONMENT', 'dev'))
        self.s3_bucket = self._validate_s3_bucket(os.environ.get('S3_BUCKET'))
        self.sns_topic_arn = self._validate_sns_topic(os.environ.get('SNS_TOPIC_ARN'))
        
        # Configuration
        self.config = self._load_config()
    
    def _validate_environment(self, env: str) -> str:
        """Validate environment name"""
        if not env or not re.match(r'^[a-zA-Z0-9-]{1,20}$', env):
            raise ValueError(f"Invalid environment name: {env}")
        return env
    
    def _validate_s3_bucket(self, bucket: str) -> str:
        """Validate S3 bucket name"""
        if not bucket:
            raise ValueError("S3 bucket name is required")
        if not re.match(r'^[a-z0-9.-]{3,63}$', bucket):
            raise ValueError(f"Invalid S3 bucket name: {bucket}")
        return bucket
    
    def _validate_sns_topic(self, topic_arn: str) -> Optional[str]:
        """Validate SNS topic ARN"""
        if not topic_arn:
            return None
        if not re.match(r'^arn:aws:sns:[a-z0-9-]+:[0-9]+:[a-zA-Z0-9-_]+$', topic_arn):
            raise ValueError(f"Invalid SNS topic ARN: {topic_arn}")
        return topic_arn
    
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
                        logger.warning(f"Rate limited, retrying in {wait_time:.2f}s... (attempt {attempt + 1}/{max_retries})")
                        time.sleep(wait_time)
                    else:
                        logger.error(f"Max retries exceeded for {func.__name__}")
                        raise
                else:
                    logger.error(f"AWS API error in {func.__name__}: {e}")
                    raise
            except Exception as e:
                logger.error(f"Unexpected error in {func.__name__}: {e}")
                raise
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from SSM Parameter Store with retry logic"""
        try:
            response = self._retry_with_backoff(
                self.ssm.get_parameter,
                Name=f'/patching-automation/{self.environment}/patch-config',
                WithDecryption=True
            )
            config = json.loads(response['Parameter']['Value'])
            # Validate config structure
            required_keys = ['autoApprovalThreshold', 'approvalWorkflow']
            for key in required_keys:
                if key not in config:
                    logger.warning(f"Missing config key: {key}, using default")
            return config
        except Exception as e:
            logger.warning(f"Could not load config from SSM: {e}, using defaults")
            return {
                "autoApprovalThreshold": 8.0,
                "approvalWorkflow": "manual",
                "maxConcurrency": 10,
                "maxErrors": 2,
                "severityThresholds": {
                    "critical": 10.0,
                    "important": 7.0,
                    "moderate": 5.0,
                    "low": 2.0
                }
            }
    
    def get_patch_baseline(self, operating_system: str = 'WINDOWS') -> Optional[str]:
        """Get the patch baseline ID for the specified operating system"""
        try:
            response = self.ssm.describe_patch_baselines(
                Filters=[
                    {
                        'Key': 'NAME_PREFIX',
                        'Values': [f'{operating_system}-PatchBaseline-{self.environment}']
                    }
                ]
            )
            
            if response['BaselineIdentities']:
                return response['BaselineIdentities'][0]['BaselineId']
            else:
                logger.warning(f"No patch baseline found for {operating_system}")
                return None
        except Exception as e:
            logger.error(f"Error getting patch baseline: {e}")
            return None
    
    def _validate_instance_ids(self, instance_ids: List[str]) -> List[str]:
        """Validate instance ID format"""
        if not instance_ids:
            return []
        
        validated_ids = []
        instance_id_pattern = re.compile(r'^i-[0-9a-f]{8,17}$')
        
        for instance_id in instance_ids:
            if not isinstance(instance_id, str):
                raise ValueError(f"Instance ID must be string: {instance_id}")
            if not instance_id_pattern.match(instance_id):
                raise ValueError(f"Invalid instance ID format: {instance_id}")
            validated_ids.append(instance_id)
        
        if len(validated_ids) > 100:
            raise ValueError(f"Too many instance IDs provided (max: 100, got: {len(validated_ids)})")
        
        return validated_ids
    
    def get_available_patches(self, instance_ids: List[str] = None, max_results: int = 1000) -> List[Dict[str, Any]]:
        """Get available patches for instances with input validation and pagination"""
        available_patches = []
        
        try:
            # Validate instance IDs if provided
            if instance_ids:
                instance_ids = self._validate_instance_ids(instance_ids)
            
            # Get instances if not provided
            if not instance_ids:
                response = self._retry_with_backoff(
                    self.ec2.describe_instances,
                    Filters=[
                        {
                            'Name': 'tag:PatchGroup',
                            'Values': [f'{self.environment}-servers']
                        },
                        {
                            'Name': 'instance-state-name',
                            'Values': ['running']
                        }
                    ],
                    MaxResults=100
                )
                
                instance_ids = []
                for reservation in response['Reservations']:
                    for instance in reservation['Instances']:
                        instance_ids.append(instance['InstanceId'])
            
            if not instance_ids:
                logger.warning("No instances found for patching")
                return []
            
            # Get patch compliance for instances with rate limiting
            for i, instance_id in enumerate(instance_ids):
                if len(available_patches) >= max_results:
                    logger.warning(f"Reached maximum patches limit: {max_results}")
                    break
                try:
                    response = self._retry_with_backoff(
                        self.ssm.describe_instance_patch_states,
                        InstanceIds=[instance_id]
                    )
                    
                    if response['InstancePatchStates']:
                        patch_state = response['InstancePatchStates'][0]
                        
                        # Get missing patches with pagination
                        missing_patches = self._retry_with_backoff(
                            self.ssm.describe_instance_patches,
                            InstanceId=instance_id,
                            Filters=[
                                {
                                    'Key': 'STATE',
                                    'Values': ['Missing']
                                }
                            ],
                            MaxResults=100
                        )
                        
                        for patch in missing_patches['Patches']:
                            available_patches.append({
                                'instance_id': instance_id,
                                'patch_id': patch['Id'],
                                'title': patch['Title'],
                                'description': patch.get('Description', ''),
                                'classification': patch.get('Classification', ''),
                                'severity': patch.get('Severity', ''),
                                'kb_id': patch.get('KBId', ''),
                                'product': patch.get('Product', ''),
                                'release_date': patch.get('ReleaseDate', ''),
                                'installed_time': patch.get('InstalledTime', '')
                            })
                
                except Exception as e:
                    logger.error(f"Error getting patches for instance {instance_id}: {e}")
                    continue
            
            logger.info(f"Found {len(available_patches)} available patches")
            return available_patches
            
        except Exception as e:
            logger.error(f"Error getting available patches: {e}")
            return []
    
    def categorize_patches(self, patches: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Categorize patches by severity and classification"""
        categorized = {
            'critical': [],
            'important': [],
            'moderate': [],
            'low': [],
            'security': [],
            'critical_updates': [],
            'definition_updates': [],
            'other': []
        }
        
        for patch in patches:
            severity = patch.get('severity', '').lower()
            classification = patch.get('classification', '').lower()
            
            # Categorize by severity
            if severity == 'critical':
                categorized['critical'].append(patch)
            elif severity == 'important':
                categorized['important'].append(patch)
            elif severity == 'moderate':
                categorized['moderate'].append(patch)
            elif severity == 'low':
                categorized['low'].append(patch)
            
            # Categorize by classification
            if 'security' in classification:
                categorized['security'].append(patch)
            elif 'critical' in classification:
                categorized['critical_updates'].append(patch)
            elif 'definition' in classification:
                categorized['definition_updates'].append(patch)
            else:
                categorized['other'].append(patch)
        
        return categorized
    
    def auto_approve_patches(self, patches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Automatically approve patches based on configuration"""
        auto_approval_threshold = self.config.get('autoApprovalThreshold', 8.0)
        approved_patches = []
        
        # Define severity scores for auto-approval
        severity_scores = {
            'critical': 10.0,
            'important': 7.0,
            'moderate': 5.0,
            'low': 2.0
        }
        
        for patch in patches:
            severity = patch.get('severity', '').lower()
            classification = patch.get('classification', '').lower()
            
            # Auto-approve based on severity score
            score = severity_scores.get(severity, 0)
            
            # Auto-approve security updates and critical patches
            if (score >= auto_approval_threshold or 
                'security' in classification or 
                'critical' in classification):
                
                approved_patches.append({
                    **patch,
                    'approval_reason': f'Auto-approved: {severity} severity, {classification} classification',
                    'approved_by': 'system',
                    'approved_at': datetime.now().isoformat()
                })
                logger.info(f"Auto-approved patch: {patch.get('title', 'Unknown')}")
        
        return approved_patches
    
    def manual_approval_workflow(self, patches: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create manual approval workflow for patches"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        approval_key = f'patch-approvals/{timestamp}_pending_approval.json'
        
        # Categorize patches
        categorized = self.categorize_patches(patches)
        
        # Create approval request
        approval_request = {
            'timestamp': datetime.now().isoformat(),
            'environment': self.environment,
            'total_patches': len(patches),
            'categorized_patches': categorized,
            'summary': {
                'critical': len(categorized['critical']),
                'important': len(categorized['important']),
                'moderate': len(categorized['moderate']),
                'low': len(categorized['low']),
                'security': len(categorized['security']),
                'critical_updates': len(categorized['critical_updates']),
                'definition_updates': len(categorized['definition_updates']),
                'other': len(categorized['other'])
            },
            'approval_deadline': (datetime.now() + timedelta(days=7)).isoformat(),
            'status': 'pending_approval'
        }
        
        try:
            # Store approval request in S3
            self.s3.put_object(
                Bucket=self.s3_bucket,
                Key=approval_key,
                Body=json.dumps(approval_request, indent=2),
                ContentType='application/json'
            )
            
            # Send notification
            self.send_approval_notification(approval_request, approval_key)
            
            logger.info(f"Manual approval workflow created: s3://{self.s3_bucket}/{approval_key}")
            return {
                'status': 'manual_approval_required',
                'approval_location': f"s3://{self.s3_bucket}/{approval_key}",
                'total_patches': len(patches)
            }
            
        except Exception as e:
            logger.error(f"Error creating manual approval workflow: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def send_approval_notification(self, approval_request: Dict[str, Any], approval_key: str) -> bool:
        """Send notification about pending patch approvals"""
        if not self.sns_topic_arn:
            logger.warning("SNS topic ARN not configured")
            return False
        
        summary = approval_request['summary']
        
        message = f"""
Patch Approval Required - {self.environment.upper()}

Summary:
- Critical Patches: {summary['critical']}
- Important Patches: {summary['important']}
- Security Updates: {summary['security']}
- Total Patches: {approval_request['total_patches']}

Approval Deadline: {approval_request['approval_deadline']}
Approval Location: s3://{self.s3_bucket}/{approval_key}

Please review and approve/reject patches by updating the approval file.
        """.strip()
        
        try:
            self.sns.publish(
                TopicArn=self.sns_topic_arn,
                Subject=f'Patch Approval Required - {self.environment.upper()}',
                Message=message
            )
            logger.info("Approval notification sent successfully")
            return True
        except Exception as e:
            logger.error(f"Error sending approval notification: {e}")
            return False
    
    def update_patch_baseline(self, approved_patches: List[Dict[str, Any]], operating_system: str = 'WINDOWS') -> bool:
        """Update patch baseline with approved patches"""
        try:
            baseline_id = self.get_patch_baseline(operating_system)
            if not baseline_id:
                logger.error("No patch baseline found")
                return False
            
            # Extract patch IDs
            patch_ids = [patch['patch_id'] for patch in approved_patches if patch.get('patch_id')]
            
            if not patch_ids:
                logger.warning("No patch IDs to approve")
                return False
            
            # Update baseline with approved patches
            self.ssm.update_patch_baseline(
                BaselineId=baseline_id,
                ApprovedPatches=patch_ids,
                ApprovedPatchesComplianceLevel='CRITICAL'
            )
            
            logger.info(f"Updated patch baseline {baseline_id} with {len(patch_ids)} approved patches")
            return True
            
        except Exception as e:
            logger.error(f"Error updating patch baseline: {e}")
            return False
    
    def store_approval_report(self, patches: List[Dict[str, Any]], approved_patches: List[Dict[str, Any]]) -> str:
        """Store approval report in S3"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_key = f'patch-approvals/{timestamp}_approval_report.json'
        
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'environment': self.environment,
            'total_patches': len(patches),
            'approved_patches': approved_patches,
            'rejected_patches': [p for p in patches if p not in approved_patches],
            'summary': {
                'total': len(patches),
                'approved': len(approved_patches),
                'rejected': len(patches) - len(approved_patches)
            }
        }
        
        try:
            self.s3.put_object(
                Bucket=self.s3_bucket,
                Key=report_key,
                Body=json.dumps(report_data, indent=2),
                ContentType='application/json'
            )
            logger.info(f"Stored approval report: s3://{self.s3_bucket}/{report_key}")
            return report_key
        except Exception as e:
            logger.error(f"Error storing approval report: {e}")
            return None
    
    def process_patch_approval(self, instance_ids: List[str] = None) -> Dict[str, Any]:
        """Main method to process patch approval workflow with comprehensive validation"""
        logger.info("Starting patch approval processing")
        
        try:
            # Validate inputs
            if instance_ids:
                instance_ids = self._validate_instance_ids(instance_ids)
                logger.info(f"Processing {len(instance_ids)} specific instances")
            
            # Get available patches
            patches = self.get_available_patches(instance_ids, max_results=1000)
            if not patches:
                logger.info("No patches available for approval")
                return {'status': 'no_patches_available'}
            
            logger.info(f"Found {len(patches)} patches requiring approval")
            
            # Validate workflow configuration
            workflow_type = self.config.get('approvalWorkflow', 'manual')
            if workflow_type not in ['automatic', 'manual']:
                logger.warning(f"Invalid workflow type: {workflow_type}, defaulting to manual")
                workflow_type = 'manual'
            
            if workflow_type == 'automatic':
                # Auto-approve patches
                approved_patches = self.auto_approve_patches(patches)
                logger.info(f"Auto-approved {len(approved_patches)} out of {len(patches)} patches")
                
                # Update patch baseline
                baseline_updated = False
                if approved_patches:
                    baseline_updated = self.update_patch_baseline(approved_patches)
                
                # Store report
                report_key = self.store_approval_report(patches, approved_patches)
                
                result = {
                    'status': 'auto_approved',
                    'total_patches': len(patches),
                    'approved_patches': len(approved_patches),
                    'baseline_updated': baseline_updated,
                    'report_location': f"s3://{self.s3_bucket}/{report_key}" if report_key else None
                }
                
            else:
                # Manual approval workflow
                result = self.manual_approval_workflow(patches)
            
            logger.info(f"Patch approval processing completed: {result['status']}")
            return result
            
        except ValueError as e:
            logger.error(f"Validation error in patch approval: {e}")
            return {'status': 'error', 'error': f'Validation failed: {str(e)}'}
        except Exception as e:
            logger.error(f"Unexpected error in patch approval: {e}")
            return {'status': 'error', 'error': f'Processing failed: {str(e)}'}

def lambda_handler(event, context):
    """AWS Lambda handler function"""
    try:
        approver = PatchApprover()
        
        # Extract instance IDs from event if provided
        instance_ids = event.get('instance_ids', None)
        
        result = approver.process_patch_approval(instance_ids)
        
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
    approver = PatchApprover()
    result = approver.process_patch_approval()
    print(json.dumps(result, indent=2)) 