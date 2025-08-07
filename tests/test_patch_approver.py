#!/usr/bin/env python3
"""
Unit tests for PatchApprover class
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import json
import sys
import os

# Add the scripts directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts', 'python'))

from patch_approver import PatchApprover
from botocore.exceptions import ClientError

class TestPatchApprover(unittest.TestCase):
    """Test cases for PatchApprover class"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Mock environment variables
        self.env_patcher = patch.dict(os.environ, {
            'ENVIRONMENT': 'test',
            'S3_BUCKET': 'test-bucket-123',
            'SNS_TOPIC_ARN': 'arn:aws:sns:us-east-1:123456789012:test-topic'
        })
        self.env_patcher.start()
        
        # Mock AWS clients
        self.ssm_mock = Mock()
        self.s3_mock = Mock()
        self.sns_mock = Mock()
        self.ec2_mock = Mock()
        
        with patch('patch_approver.boto3') as boto3_mock:
            boto3_mock.client.side_effect = lambda service, **kwargs: {
                'ssm': self.ssm_mock,
                's3': self.s3_mock,
                'sns': self.sns_mock,
                'ec2': self.ec2_mock
            }[service]
            
            # Mock successful SSM parameter retrieval
            self.ssm_mock.get_parameter.return_value = {
                'Parameter': {
                    'Value': json.dumps({
                        "autoApprovalThreshold": 8.0,
                        "approvalWorkflow": "manual",
                        "maxConcurrency": 10,
                        "maxErrors": 2
                    })
                }
            }
            
            self.approver = PatchApprover()
    
    def tearDown(self):
        """Clean up test fixtures"""
        self.env_patcher.stop()
    
    def test_init_validation_success(self):
        """Test successful initialization with valid inputs"""
        self.assertEqual(self.approver.environment, 'test')
        self.assertEqual(self.approver.s3_bucket, 'test-bucket-123')
        self.assertIsNotNone(self.approver.config)
    
    def test_validate_environment_invalid(self):
        """Test environment validation with invalid input"""
        with patch.dict(os.environ, {'ENVIRONMENT': ''}):
            with self.assertRaises(ValueError):
                PatchApprover()
    
    def test_validate_s3_bucket_invalid(self):
        """Test S3 bucket validation with invalid input"""
        with patch.dict(os.environ, {'S3_BUCKET': 'INVALID-BUCKET-NAME!'}):
            with self.assertRaises(ValueError):
                PatchApprover()
    
    def test_validate_instance_ids_valid(self):
        """Test instance ID validation with valid inputs"""
        valid_ids = ['i-1234567890abcdef0', 'i-abcdef1234567890']
        result = self.approver._validate_instance_ids(valid_ids)
        self.assertEqual(result, valid_ids)
    
    def test_validate_instance_ids_invalid_format(self):
        """Test instance ID validation with invalid format"""
        invalid_ids = ['invalid-id', 'i-123']
        with self.assertRaises(ValueError):
            self.approver._validate_instance_ids(invalid_ids)
    
    def test_validate_instance_ids_too_many(self):
        """Test instance ID validation with too many IDs"""
        too_many_ids = [f'i-{i:016x}' for i in range(101)]
        with self.assertRaises(ValueError):
            self.approver._validate_instance_ids(too_many_ids)
    
    def test_load_config_success(self):
        """Test successful configuration loading"""
        expected_config = {
            "autoApprovalThreshold": 8.0,
            "approvalWorkflow": "manual"
        }
        self.ssm_mock.get_parameter.return_value = {
            'Parameter': {'Value': json.dumps(expected_config)}
        }
        
        config = self.approver._load_config()
        self.assertEqual(config['autoApprovalThreshold'], 8.0)
    
    def test_load_config_failure_uses_defaults(self):
        """Test configuration loading failure falls back to defaults"""
        self.ssm_mock.get_parameter.side_effect = ClientError(
            {'Error': {'Code': 'ParameterNotFound'}}, 'GetParameter'
        )
        
        config = self.approver._load_config()
        self.assertEqual(config['autoApprovalThreshold'], 8.0)
        self.assertEqual(config['approvalWorkflow'], 'manual')
    
    def test_retry_with_backoff_success(self):
        """Test successful retry mechanism"""
        mock_func = Mock(return_value='success')
        result = self.approver._retry_with_backoff(mock_func, arg1='test')
        self.assertEqual(result, 'success')
        mock_func.assert_called_once_with(arg1='test')
    
    def test_retry_with_backoff_throttling(self):
        """Test retry mechanism with throttling"""
        mock_func = Mock()
        mock_func.side_effect = [
            ClientError({'Error': {'Code': 'Throttling'}}, 'TestOperation'),
            'success'
        ]
        
        with patch('time.sleep'):  # Mock sleep to speed up test
            result = self.approver._retry_with_backoff(mock_func, max_retries=2)
        
        self.assertEqual(result, 'success')
        self.assertEqual(mock_func.call_count, 2)
    
    def test_retry_with_backoff_max_retries_exceeded(self):
        """Test retry mechanism when max retries exceeded"""
        mock_func = Mock()
        mock_func.side_effect = ClientError({'Error': {'Code': 'Throttling'}}, 'TestOperation')
        
        with patch('time.sleep'):
            with self.assertRaises(ClientError):
                self.approver._retry_with_backoff(mock_func, max_retries=2)
    
    def test_get_available_patches_no_instances(self):
        """Test getting patches when no instances found"""
        self.ec2_mock.describe_instances.return_value = {'Reservations': []}
        
        patches = self.approver.get_available_patches()
        self.assertEqual(patches, [])
    
    def test_get_available_patches_with_instances(self):
        """Test getting patches with instances"""
        # Mock EC2 response
        self.ec2_mock.describe_instances.return_value = {
            'Reservations': [
                {
                    'Instances': [
                        {'InstanceId': 'i-1234567890abcdef0'}
                    ]
                }
            ]
        }
        
        # Mock SSM responses
        self.ssm_mock.describe_instance_patch_states.return_value = {
            'InstancePatchStates': [
                {'InstanceId': 'i-1234567890abcdef0', 'PatchGroup': 'test-servers'}
            ]
        }
        
        self.ssm_mock.describe_instance_patches.return_value = {
            'Patches': [
                {
                    'Id': 'patch-001',
                    'Title': 'Test Security Update',
                    'Classification': 'SecurityUpdates',
                    'Severity': 'Critical',
                    'KBId': 'KB123456'
                }
            ]
        }
        
        patches = self.approver.get_available_patches()
        self.assertEqual(len(patches), 1)
        self.assertEqual(patches[0]['patch_id'], 'patch-001')
        self.assertEqual(patches[0]['title'], 'Test Security Update')
    
    def test_auto_approve_patches_critical_severity(self):
        """Test auto-approval of critical patches"""
        patches = [
            {
                'patch_id': 'patch-001',
                'title': 'Critical Security Update',
                'severity': 'Critical',
                'classification': 'SecurityUpdates'
            }
        ]
        
        approved = self.approver.auto_approve_patches(patches)
        self.assertEqual(len(approved), 1)
        self.assertIn('approval_reason', approved[0])
        self.assertEqual(approved[0]['approved_by'], 'system')
    
    def test_auto_approve_patches_low_severity_rejected(self):
        """Test that low severity patches are not auto-approved"""
        patches = [
            {
                'patch_id': 'patch-001',
                'title': 'Low Priority Update',
                'severity': 'Low',
                'classification': 'Updates'
            }
        ]
        
        approved = self.approver.auto_approve_patches(patches)
        self.assertEqual(len(approved), 0)
    
    def test_categorize_patches(self):
        """Test patch categorization"""
        patches = [
            {'severity': 'Critical', 'classification': 'SecurityUpdates'},
            {'severity': 'Important', 'classification': 'CriticalUpdates'},
            {'severity': 'Low', 'classification': 'Updates'}
        ]
        
        categorized = self.approver.categorize_patches(patches)
        
        self.assertEqual(len(categorized['critical']), 1)
        self.assertEqual(len(categorized['important']), 1)
        self.assertEqual(len(categorized['low']), 1)
        self.assertEqual(len(categorized['security']), 1)
    
    def test_process_patch_approval_no_patches(self):
        """Test processing when no patches are available"""
        self.ec2_mock.describe_instances.return_value = {'Reservations': []}
        
        result = self.approver.process_patch_approval()
        self.assertEqual(result['status'], 'no_patches_available')
    
    def test_process_patch_approval_validation_error(self):
        """Test processing with validation error"""
        invalid_instance_ids = ['invalid-id']
        
        result = self.approver.process_patch_approval(invalid_instance_ids)
        self.assertEqual(result['status'], 'error')
        self.assertIn('Validation failed', result['error'])
    
    def test_store_approval_report_success(self):
        """Test successful report storage"""
        patches = [{'patch_id': 'patch-001', 'title': 'Test Patch'}]
        approved_patches = []
        
        self.s3_mock.put_object.return_value = {}
        
        report_key = self.approver.store_approval_report(patches, approved_patches)
        self.assertIsNotNone(report_key)
        self.assertTrue(report_key.startswith('patch-approvals/'))
        self.s3_mock.put_object.assert_called_once()
    
    def test_store_approval_report_s3_error(self):
        """Test report storage with S3 error"""
        self.s3_mock.put_object.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied'}}, 'PutObject'
        )
        
        patches = [{'patch_id': 'patch-001'}]
        approved_patches = []
        
        report_key = self.approver.store_approval_report(patches, approved_patches)
        self.assertIsNone(report_key)
    
    def test_send_approval_notification_success(self):
        """Test successful notification sending"""
        approval_request = {
            'total_patches': 5,
            'summary': {'critical': 2, 'important': 3, 'security': 1},
            'approval_deadline': '2024-01-01T00:00:00'
        }
        
        self.sns_mock.publish.return_value = {'MessageId': 'msg-123'}
        
        result = self.approver.send_approval_notification(approval_request, 'test-key')
        self.assertTrue(result)
        self.sns_mock.publish.assert_called_once()
    
    def test_send_approval_notification_no_topic(self):
        """Test notification when SNS topic is not configured"""
        self.approver.sns_topic_arn = None
        
        approval_request = {'total_patches': 5, 'summary': {}}
        result = self.approver.send_approval_notification(approval_request, 'test-key')
        self.assertFalse(result)

class TestPatchApproverIntegration(unittest.TestCase):
    """Integration tests for PatchApprover"""
    
    @patch('patch_approver.boto3')
    def test_full_workflow_automatic_approval(self, mock_boto3):
        """Test complete automatic approval workflow"""
        # Set up environment
        with patch.dict(os.environ, {
            'ENVIRONMENT': 'test',
            'S3_BUCKET': 'test-bucket-123',
            'SNS_TOPIC_ARN': 'arn:aws:sns:us-east-1:123456789012:test-topic'
        }):
            # Mock AWS clients
            ssm_mock = Mock()
            s3_mock = Mock()
            sns_mock = Mock()
            ec2_mock = Mock()
            
            mock_boto3.client.side_effect = lambda service, **kwargs: {
                'ssm': ssm_mock,
                's3': s3_mock,
                'sns': sns_mock,
                'ec2': ec2_mock
            }[service]
            
            # Mock configuration for automatic approval
            ssm_mock.get_parameter.return_value = {
                'Parameter': {
                    'Value': json.dumps({
                        "autoApprovalThreshold": 8.0,
                        "approvalWorkflow": "automatic",
                        "maxConcurrency": 10,
                        "maxErrors": 2
                    })
                }
            }
            
            # Mock instance discovery
            ec2_mock.describe_instances.return_value = {
                'Reservations': [
                    {'Instances': [{'InstanceId': 'i-1234567890abcdef0'}]}
                ]
            }
            
            # Mock patch state
            ssm_mock.describe_instance_patch_states.return_value = {
                'InstancePatchStates': [
                    {'InstanceId': 'i-1234567890abcdef0'}
                ]
            }
            
            # Mock available patches
            ssm_mock.describe_instance_patches.return_value = {
                'Patches': [
                    {
                        'Id': 'patch-001',
                        'Title': 'Critical Security Update',
                        'Classification': 'SecurityUpdates',
                        'Severity': 'Critical'
                    }
                ]
            }
            
            # Mock patch baseline
            ssm_mock.describe_patch_baselines.return_value = {
                'BaselineIdentities': [
                    {'BaselineId': 'pb-1234567890abcdef'}
                ]
            }
            
            # Mock S3 operations
            s3_mock.put_object.return_value = {}
            
            # Initialize and run
            approver = PatchApprover()
            result = approver.process_patch_approval()
            
            # Verify results
            self.assertEqual(result['status'], 'auto_approved')
            self.assertEqual(result['total_patches'], 1)
            self.assertEqual(result['approved_patches'], 1)
            
            # Verify AWS calls were made
            ssm_mock.update_patch_baseline.assert_called_once()
            s3_mock.put_object.assert_called()

if __name__ == '__main__':
    unittest.main()