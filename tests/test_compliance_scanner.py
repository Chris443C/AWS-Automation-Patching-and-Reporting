#!/usr/bin/env python3
"""
Unit tests for ComplianceScanner class
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import json
import sys
import os
from datetime import datetime, timedelta

# Add the scripts directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts', 'python'))

from compliance_scanner_optimized import ComplianceScanner, ComplianceMapper
from botocore.exceptions import ClientError

class TestComplianceMapper(unittest.TestCase):
    """Test cases for ComplianceMapper class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.mapper = ComplianceMapper()
    
    def test_cis_pattern_matching(self):
        """Test CIS control pattern matching"""
        # Test finding that matches CIS 1.1 (root account)
        finding = {
            'Title': 'Root account access detected',
            'Description': 'Avoid the use of the root account',
            'GeneratorId': 'aws-inspector',
            'Resources': [{'Type': 'AwsIamUser'}]
        }
        
        result = self.mapper.check_cis_compliance(finding)
        self.assertIsNotNone(result)
        self.assertEqual(result['control_id'], '1.1')
        self.assertEqual(result['framework'], 'CIS AWS Foundations Benchmark')
    
    def test_pci_pattern_matching(self):
        """Test PCI DSS pattern matching"""
        # Test finding that matches PCI 1.1 (firewall)
        finding = {
            'Title': 'Security group allows unrestricted access',
            'Description': 'Firewall configuration needs review',
            'GeneratorId': 'aws-config',
            'Resources': [{'Type': 'AwsEc2SecurityGroup'}]
        }
        
        result = self.mapper.check_pci_compliance(finding)
        self.assertIsNotNone(result)
        self.assertEqual(result['requirement_id'], '1.1')
        self.assertEqual(result['framework'], 'PCI DSS v3.2.1')
    
    def test_no_pattern_match(self):
        """Test finding that doesn't match any patterns"""
        finding = {
            'Title': 'Unrelated finding',
            'Description': 'This does not match any compliance patterns',
            'GeneratorId': 'custom-check',
            'Resources': []
        }
        
        cis_result = self.mapper.check_cis_compliance(finding)
        pci_result = self.mapper.check_pci_compliance(finding)
        
        self.assertIsNone(cis_result)
        self.assertIsNone(pci_result)
    
    def test_extract_finding_text(self):
        """Test finding text extraction"""
        finding = {
            'Title': 'Test Title',
            'Description': 'Test Description',
            'GeneratorId': 'test-generator',
            'Resources': [
                {'Type': 'AwsS3Bucket'},
                {'Type': 'AwsIamRole'}
            ]
        }
        
        text = self.mapper._extract_finding_text(finding)
        self.assertIn('test title', text)
        self.assertIn('test description', text)
        self.assertIn('awss3bucket', text)
        self.assertIn('awsiamrole', text)
    
    def test_get_finding_severity(self):
        """Test severity extraction from findings"""
        # Test with dict severity format
        finding1 = {
            'Severity': {'Label': 'CRITICAL'}
        }
        severity1 = self.mapper._get_finding_severity(finding1)
        self.assertEqual(severity1, 'CRITICAL')
        
        # Test with string severity format
        finding2 = {
            'Severity': 'HIGH'
        }
        severity2 = self.mapper._get_finding_severity(finding2)
        self.assertEqual(severity2, 'HIGH')
        
        # Test with missing severity
        finding3 = {}
        severity3 = self.mapper._get_finding_severity(finding3)
        self.assertEqual(severity3, 'UNKNOWN')

class TestComplianceScanner(unittest.TestCase):
    """Test cases for ComplianceScanner class"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Mock environment variables
        self.env_patcher = patch.dict(os.environ, {
            'ENVIRONMENT': 'test',
            'S3_BUCKET': 'test-compliance-bucket',
            'SNS_TOPIC_ARN': 'arn:aws:sns:us-east-1:123456789012:compliance-topic',
            'AWS_DEFAULT_REGION': 'us-east-1'
        })
        self.env_patcher.start()
        
        # Mock AWS clients
        self.securityhub_mock = Mock()
        self.s3_mock = Mock()
        self.ssm_mock = Mock()
        self.sns_mock = Mock()
        
        with patch('compliance_scanner_optimized.boto3') as boto3_mock:
            boto3_mock.client.side_effect = lambda service, region_name=None, config=None: {
                'securityhub': self.securityhub_mock,
                's3': self.s3_mock,
                'ssm': self.ssm_mock,
                'sns': self.sns_mock
            }[service]
            
            # Mock successful SSM parameter retrieval
            self.ssm_mock.get_parameter.return_value = {
                'Parameter': {
                    'Value': json.dumps({
                        "cis_enabled": True,
                        "pci_enabled": True,
                        "severity_filter": ["CRITICAL", "HIGH"],
                        "max_findings": 1000,
                        "score_thresholds": {
                            "cis_warning": 80,
                            "pci_warning": 80
                        }
                    })
                }
            }
            
            self.scanner = ComplianceScanner()
    
    def tearDown(self):
        """Clean up test fixtures"""
        self.env_patcher.stop()
    
    def test_init_validation_success(self):
        """Test successful initialization with valid inputs"""
        self.assertEqual(self.scanner.region, 'us-east-1')
        self.assertEqual(self.scanner.environment, 'test')
        self.assertEqual(self.scanner.s3_bucket, 'test-compliance-bucket')
    
    def test_validate_region_invalid(self):
        """Test region validation with invalid input"""
        with self.assertRaises(ValueError):
            ComplianceScanner(region='INVALID_REGION!')
    
    def test_validate_s3_bucket_invalid(self):
        """Test S3 bucket validation with invalid input"""
        with patch.dict(os.environ, {'S3_BUCKET': 'INVALID-BUCKET!'}):
            with self.assertRaises(ValueError):
                ComplianceScanner()
    
    def test_validate_environment_invalid(self):
        """Test environment validation with invalid input"""
        with patch.dict(os.environ, {'ENVIRONMENT': ''}):
            with self.assertRaises(ValueError):
                ComplianceScanner()
    
    def test_load_compliance_config_success(self):
        """Test successful configuration loading"""
        expected_config = {
            "cis_enabled": True,
            "pci_enabled": True,
            "severity_filter": ["CRITICAL", "HIGH"]
        }
        self.ssm_mock.get_parameter.return_value = {
            'Parameter': {'Value': json.dumps(expected_config)}
        }
        
        config = self.scanner._load_compliance_config()
        self.assertTrue(config['cis_enabled'])
        self.assertTrue(config['pci_enabled'])
    
    def test_load_compliance_config_failure_defaults(self):
        """Test configuration loading failure uses defaults"""
        self.ssm_mock.get_parameter.side_effect = ClientError(
            {'Error': {'Code': 'ParameterNotFound'}}, 'GetParameter'
        )
        
        config = self.scanner._load_compliance_config()
        self.assertTrue(config['cis_enabled'])
        self.assertTrue(config['pci_enabled'])
        self.assertEqual(config['max_findings'], 1000)
    
    def test_retry_with_backoff_success(self):
        """Test successful retry mechanism"""
        mock_func = Mock(return_value='success')
        result = self.scanner._retry_with_backoff(mock_func, arg1='test')
        self.assertEqual(result, 'success')
        mock_func.assert_called_once_with(arg1='test')
    
    def test_retry_with_backoff_throttling_recovery(self):
        """Test retry mechanism with throttling recovery"""
        mock_func = Mock()
        mock_func.side_effect = [
            ClientError({'Error': {'Code': 'Throttling'}}, 'GetFindings'),
            'success'
        ]
        
        with patch('time.sleep'):  # Mock sleep to speed up test
            result = self.scanner._retry_with_backoff(mock_func, max_retries=2)
        
        self.assertEqual(result, 'success')
        self.assertEqual(mock_func.call_count, 2)
    
    def test_get_security_hub_findings_success(self):
        """Test successful Security Hub findings retrieval"""
        # Mock paginator
        mock_paginator = Mock()
        mock_page_iterator = [
            {
                'Findings': [
                    {
                        'Id': 'finding-001',
                        'Title': 'Test Security Finding',
                        'Severity': {'Label': 'HIGH'},
                        'CreatedAt': '2024-01-01T00:00:00.000Z'
                    }
                ]
            }
        ]
        mock_paginator.paginate.return_value = mock_page_iterator
        self.securityhub_mock.get_paginator.return_value = mock_paginator
        
        findings = self.scanner.get_security_hub_findings(days_back=30, max_results=100)
        
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['Id'], 'finding-001')
        self.securityhub_mock.get_paginator.assert_called_once_with('get_findings')
    
    def test_get_security_hub_findings_empty(self):
        """Test Security Hub findings retrieval with no results"""
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [{'Findings': []}]
        self.securityhub_mock.get_paginator.return_value = mock_paginator
        
        findings = self.scanner.get_security_hub_findings()
        self.assertEqual(len(findings), 0)
    
    def test_get_security_hub_findings_error(self):
        """Test Security Hub findings retrieval with error"""
        self.securityhub_mock.get_paginator.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied'}}, 'GetFindings'
        )
        
        findings = self.scanner.get_security_hub_findings()
        self.assertEqual(len(findings), 0)
    
    def test_analyze_compliance_with_findings(self):
        """Test compliance analysis with findings"""
        findings = [
            {
                'Id': 'finding-001',
                'Title': 'Root account access detected',
                'Description': 'Avoid the use of the root account',
                'Severity': {'Label': 'HIGH'},
                'CreatedAt': '2024-01-01T00:00:00.000Z',
                'UpdatedAt': '2024-01-01T00:00:00.000Z',
                'Workflow': {'Status': 'NEW'},
                'Resources': [{'Type': 'AwsIamUser'}]
            },
            {
                'Id': 'finding-002',
                'Title': 'Firewall misconfiguration',
                'Description': 'Security group allows unrestricted access',
                'Severity': {'Label': 'CRITICAL'},
                'CreatedAt': '2024-01-01T00:00:00.000Z',
                'UpdatedAt': '2024-01-01T00:00:00.000Z',
                'Workflow': {'Status': 'NEW'},
                'Resources': [{'Type': 'AwsEc2SecurityGroup'}]
            }
        ]
        
        analysis = self.scanner.analyze_compliance(findings)
        
        self.assertEqual(analysis['total_findings'], 2)
        self.assertGreater(len(analysis['cis_findings']), 0)
        self.assertGreater(len(analysis['pci_findings']), 0)
        self.assertIn('compliance_scores', analysis)
        self.assertIn('cis_score', analysis['compliance_scores'])
        self.assertIn('pci_score', analysis['compliance_scores'])
    
    def test_analyze_compliance_no_findings(self):
        """Test compliance analysis with no findings"""
        analysis = self.scanner.analyze_compliance([])
        
        self.assertEqual(analysis['total_findings'], 0)
        self.assertEqual(len(analysis['cis_findings']), 0)
        self.assertEqual(len(analysis['pci_findings']), 0)
    
    def test_calculate_compliance_scores(self):
        """Test compliance score calculation"""
        analysis = {
            'cis_findings': [
                {'control_id': '1.1'},
                {'control_id': '2.1'}
            ],
            'pci_findings': [
                {'requirement_id': '1.1'}
            ]
        }
        
        scores = self.scanner._calculate_compliance_scores(analysis)
        
        self.assertIn('cis_score', scores)
        self.assertIn('pci_score', scores)
        self.assertTrue(0 <= scores['cis_score'] <= 100)
        self.assertTrue(0 <= scores['pci_score'] <= 100)
    
    def test_store_compliance_report_success(self):
        """Test successful compliance report storage"""
        analysis = {
            'total_findings': 5,
            'cis_findings': [],
            'pci_findings': [],
            'compliance_scores': {'cis_score': 85.0, 'pci_score': 90.0}
        }
        
        self.s3_mock.put_object.return_value = {}
        
        report_key = self.scanner.store_compliance_report(analysis)
        
        self.assertIsNotNone(report_key)
        self.assertTrue(report_key.startswith('compliance-reports/test/'))
        self.s3_mock.put_object.assert_called_once()
        
        # Verify S3 put_object call
        call_args = self.s3_mock.put_object.call_args
        self.assertEqual(call_args[1]['Bucket'], 'test-compliance-bucket')
        self.assertEqual(call_args[1]['ContentType'], 'application/json')
        self.assertEqual(call_args[1]['ServerSideEncryption'], 'AES256')
    
    def test_store_compliance_report_s3_error(self):
        """Test compliance report storage with S3 error"""
        self.s3_mock.put_object.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied'}}, 'PutObject'
        )
        
        analysis = {'total_findings': 0, 'cis_findings': [], 'pci_findings': []}
        report_key = self.scanner.store_compliance_report(analysis)
        
        self.assertIsNone(report_key)
    
    def test_send_compliance_notification_above_threshold(self):
        """Test notification not sent when scores are above threshold"""
        analysis = {
            'compliance_scores': {'cis_score': 85.0, 'pci_score': 90.0},
            'cis_findings': [],
            'pci_findings': [],
            'total_findings': 5,
            'processed_at': datetime.now().isoformat()
        }
        
        result = self.scanner.send_compliance_notification(analysis)
        self.assertTrue(result)  # No notification needed, returns True
        self.sns_mock.publish.assert_not_called()
    
    def test_send_compliance_notification_below_threshold(self):
        """Test notification sent when scores are below threshold"""
        analysis = {
            'compliance_scores': {'cis_score': 60.0, 'pci_score': 70.0},
            'cis_findings': [{'control_id': '1.1'}, {'control_id': '2.1'}],
            'pci_findings': [{'requirement_id': '1.1'}],
            'total_findings': 10,
            'processed_at': datetime.now().isoformat()
        }
        
        self.sns_mock.publish.return_value = {'MessageId': 'msg-123'}
        
        result = self.scanner.send_compliance_notification(analysis)
        self.assertTrue(result)
        self.sns_mock.publish.assert_called_once()
        
        # Verify SNS publish call
        call_args = self.sns_mock.publish.call_args
        self.assertEqual(call_args[1]['TopicArn'], self.scanner.sns_topic_arn)
        self.assertIn('Compliance Scan Alert', call_args[1]['Subject'])
    
    def test_send_compliance_notification_no_topic(self):
        """Test notification when SNS topic is not configured"""
        self.scanner.sns_topic_arn = None
        
        analysis = {
            'compliance_scores': {'cis_score': 60.0, 'pci_score': 70.0},
            'cis_findings': [],
            'pci_findings': [],
            'total_findings': 5,
            'processed_at': datetime.now().isoformat()
        }
        
        result = self.scanner.send_compliance_notification(analysis)
        self.assertFalse(result)
    
    def test_run_compliance_scan_success(self):
        """Test successful complete compliance scan"""
        # Mock Security Hub findings
        mock_paginator = Mock()
        mock_page_iterator = [
            {
                'Findings': [
                    {
                        'Id': 'finding-001',
                        'Title': 'Root account access detected',
                        'Description': 'Avoid the use of the root account',
                        'Severity': {'Label': 'HIGH'},
                        'CreatedAt': '2024-01-01T00:00:00.000Z',
                        'UpdatedAt': '2024-01-01T00:00:00.000Z',
                        'Workflow': {'Status': 'NEW'},
                        'Resources': [{'Type': 'AwsIamUser'}]
                    }
                ]
            }
        ]
        mock_paginator.paginate.return_value = mock_page_iterator
        self.securityhub_mock.get_paginator.return_value = mock_paginator
        
        # Mock S3 operations
        self.s3_mock.put_object.return_value = {}
        
        # Mock SNS operations
        self.sns_mock.publish.return_value = {'MessageId': 'msg-123'}
        
        result = self.scanner.run_compliance_scan(days_back=30)
        
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['findings_count'], 1)
        self.assertGreaterEqual(result['cis_findings'], 0)
        self.assertGreaterEqual(result['pci_findings'], 0)
        self.assertIn('compliance_scores', result)
        self.assertIsNotNone(result['report_location'])
    
    def test_run_compliance_scan_no_findings(self):
        """Test compliance scan with no findings"""
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [{'Findings': []}]
        self.securityhub_mock.get_paginator.return_value = mock_paginator
        
        result = self.scanner.run_compliance_scan()
        
        self.assertEqual(result['status'], 'no_findings')
        self.assertEqual(result['findings_count'], 0)
    
    def test_run_compliance_scan_skip_s3_and_notification(self):
        """Test compliance scan with S3 and notification disabled"""
        # Mock Security Hub findings
        mock_paginator = Mock()
        mock_page_iterator = [
            {
                'Findings': [
                    {
                        'Id': 'finding-001',
                        'Title': 'Test finding',
                        'Severity': {'Label': 'HIGH'},
                        'Resources': []
                    }
                ]
            }
        ]
        mock_paginator.paginate.return_value = mock_page_iterator
        self.securityhub_mock.get_paginator.return_value = mock_paginator
        
        result = self.scanner.run_compliance_scan(no_s3=True, no_notification=True)
        
        self.assertEqual(result['status'], 'completed')
        self.assertIsNone(result['report_location'])
        self.assertFalse(result['notification_sent'])
        self.s3_mock.put_object.assert_not_called()
        self.sns_mock.publish.assert_not_called()
    
    def test_run_compliance_scan_error_handling(self):
        """Test compliance scan with error"""
        self.securityhub_mock.get_paginator.side_effect = Exception('Test error')
        
        result = self.scanner.run_compliance_scan()
        
        self.assertEqual(result['status'], 'error')
        self.assertIn('error', result)
        self.assertEqual(result['findings_count'], 0)

class TestComplianceScannerIntegration(unittest.TestCase):
    """Integration tests for ComplianceScanner"""
    
    @patch('compliance_scanner_optimized.boto3')
    def test_end_to_end_compliance_scan(self, mock_boto3):
        """Test complete end-to-end compliance scan workflow"""
        # Set up environment
        with patch.dict(os.environ, {
            'ENVIRONMENT': 'test',
            'S3_BUCKET': 'test-compliance-bucket',
            'SNS_TOPIC_ARN': 'arn:aws:sns:us-east-1:123456789012:test-topic',
            'AWS_DEFAULT_REGION': 'us-east-1'
        }):
            # Mock AWS clients
            securityhub_mock = Mock()
            s3_mock = Mock()
            ssm_mock = Mock()
            sns_mock = Mock()
            
            mock_boto3.client.side_effect = lambda service, region_name=None, config=None: {
                'securityhub': securityhub_mock,
                's3': s3_mock,
                'ssm': ssm_mock,
                'sns': sns_mock
            }[service]
            
            # Mock compliance configuration
            ssm_mock.get_parameter.return_value = {
                'Parameter': {
                    'Value': json.dumps({
                        "cis_enabled": True,
                        "pci_enabled": True,
                        "severity_filter": ["CRITICAL", "HIGH"],
                        "max_findings": 100,
                        "score_thresholds": {
                            "cis_warning": 80,
                            "pci_warning": 80
                        }
                    })
                }
            }
            
            # Mock Security Hub findings that will trigger compliance violations
            mock_paginator = Mock()
            mock_page_iterator = [
                {
                    'Findings': [
                        {
                            'Id': 'finding-001',
                            'Title': 'Root account MFA not enabled',
                            'Description': 'Ensure MFA is enabled for the root account',
                            'Severity': {'Label': 'CRITICAL'},
                            'CreatedAt': '2024-01-01T00:00:00.000Z',
                            'UpdatedAt': '2024-01-01T00:00:00.000Z',
                            'Workflow': {'Status': 'NEW'},
                            'Resources': [{'Type': 'AwsAccount'}]
                        },
                        {
                            'Id': 'finding-002',
                            'Title': 'Security group allows unrestricted access',
                            'Description': 'Firewall rules need to be reviewed',
                            'Severity': {'Label': 'HIGH'},
                            'CreatedAt': '2024-01-01T00:00:00.000Z',
                            'UpdatedAt': '2024-01-01T00:00:00.000Z',
                            'Workflow': {'Status': 'NEW'},
                            'Resources': [{'Type': 'AwsEc2SecurityGroup'}]
                        }
                    ]
                }
            ]
            mock_paginator.paginate.return_value = mock_page_iterator
            securityhub_mock.get_paginator.return_value = mock_paginator
            
            # Mock S3 operations
            s3_mock.put_object.return_value = {}
            
            # Mock SNS operations
            sns_mock.publish.return_value = {'MessageId': 'msg-123'}
            
            # Initialize scanner and run scan
            scanner = ComplianceScanner()
            result = scanner.run_compliance_scan(days_back=7)
            
            # Verify results
            self.assertEqual(result['status'], 'completed')
            self.assertEqual(result['findings_count'], 2)
            self.assertGreater(result['cis_findings'], 0)  # Should find CIS violations
            self.assertGreater(result['pci_findings'], 0)  # Should find PCI violations
            
            # Verify compliance scores are calculated
            self.assertIn('compliance_scores', result)
            self.assertIn('cis_score', result['compliance_scores'])
            self.assertIn('pci_score', result['compliance_scores'])
            
            # Verify report was stored
            self.assertIsNotNone(result['report_location'])
            s3_mock.put_object.assert_called()
            
            # Verify notification was sent (scores should be below thresholds due to violations)
            self.assertTrue(result['notification_sent'])
            sns_mock.publish.assert_called()

if __name__ == '__main__':
    unittest.main()