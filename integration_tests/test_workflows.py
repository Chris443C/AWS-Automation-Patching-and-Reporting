#!/usr/bin/env python3
"""
Integration tests for Step Functions workflows using LocalStack
"""

import pytest
import json
import boto3
import time
from datetime import datetime
from unittest.mock import patch
import os

# Test configuration
LOCALSTACK_ENDPOINT = os.environ.get('LOCALSTACK_HOST', 'http://localhost:4566')
TEST_REGION = 'us-east-1'
TEST_ENVIRONMENT = 'test'


@pytest.fixture(scope="module")
def aws_credentials():
    """Mocked AWS Credentials for LocalStack."""
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_SECURITY_TOKEN'] = 'testing'
    os.environ['AWS_SESSION_TOKEN'] = 'testing'
    os.environ['AWS_DEFAULT_REGION'] = TEST_REGION


@pytest.fixture(scope="module")
def stepfunctions_client(aws_credentials):
    """Create LocalStack Step Functions client."""
    return boto3.client(
        'stepfunctions',
        endpoint_url=LOCALSTACK_ENDPOINT,
        region_name=TEST_REGION
    )


@pytest.fixture(scope="module")
def lambda_client(aws_credentials):
    """Create LocalStack Lambda client."""
    return boto3.client(
        'lambda',
        endpoint_url=LOCALSTACK_ENDPOINT,
        region_name=TEST_REGION
    )


@pytest.fixture(scope="module")
def events_client(aws_credentials):
    """Create LocalStack EventBridge client."""
    return boto3.client(
        'events',
        endpoint_url=LOCALSTACK_ENDPOINT,
        region_name=TEST_REGION
    )


@pytest.fixture(scope="module")
def iam_client(aws_credentials):
    """Create LocalStack IAM client."""
    return boto3.client(
        'iam',
        endpoint_url=LOCALSTACK_ENDPOINT,
        region_name=TEST_REGION
    )


def create_mock_lambda_function(lambda_client, function_name, handler_code):
    """Create a mock Lambda function in LocalStack."""
    import zipfile
    import io
    
    # Create a simple Python Lambda function
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
        zip_file.writestr('lambda_function.py', handler_code)
    
    zip_buffer.seek(0)
    
    try:
        lambda_client.create_function(
            FunctionName=function_name,
            Runtime='python3.11',
            Role=f'arn:aws:iam::123456789012:role/lambda-execution-role',
            Handler='lambda_function.lambda_handler',
            Code={'ZipFile': zip_buffer.read()},
            Description=f'Mock function for testing - {function_name}',
            Timeout=30,
            MemorySize=128
        )
    except lambda_client.exceptions.ResourceConflictException:
        # Function already exists
        pass


def create_execution_role(iam_client):
    """Create IAM role for Step Functions execution."""
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "states.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }
    
    try:
        iam_client.create_role(
            RoleName='lambda-execution-role',
            AssumeRolePolicyDocument=json.dumps(assume_role_policy),
            Description='Role for Lambda execution in tests'
        )
        
        # Attach basic execution policy
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "lambda:InvokeFunction",
                        "events:PutEvents",
                        "logs:*"
                    ],
                    "Resource": "*"
                }
            ]
        }
        
        iam_client.put_role_policy(
            RoleName='lambda-execution-role',
            PolicyName='lambda-execution-policy',
            PolicyDocument=json.dumps(policy)
        )
    except iam_client.exceptions.EntityAlreadyExistsException:
        # Role already exists
        pass


class TestPatchApprovalWorkflow:
    """Test cases for Patch Approval Workflow"""
    
    def setup_method(self):
        """Set up test environment for each test"""
        self.correlation_id = f"test-{int(time.time())}"
        self.test_event = {
            "correlation_id": self.correlation_id,
            "detail-type": "Vulnerability Detection",
            "detail": {
                "vulnerability_count": 5,
                "critical_count": 2,
                "high_count": 3
            }
        }
    
    def test_patch_approval_workflow_creation(
        self, 
        stepfunctions_client, 
        lambda_client, 
        events_client, 
        iam_client
    ):
        """Test creating the patch approval workflow state machine"""
        # Create execution role
        create_execution_role(iam_client)
        
        # Create mock Lambda functions
        vulnerability_scanner_code = '''
def lambda_handler(event, context):
    return {
        "vulnerabilities_count": 10,
        "patches_count": 5,
        "critical_vulnerabilities": 2,
        "high_vulnerabilities": 3,
        "scan_timestamp": "2024-01-01T00:00:00Z"
    }
        '''
        
        patch_approver_code = '''
def lambda_handler(event, context):
    approval_mode = event.get("approval_mode", "standard")
    if approval_mode == "automatic":
        return {"approved_patches": 2, "approval_status": "approved"}
    return {"approval_status": "pending", "review_required": True}
        '''
        
        notification_service_code = '''
def lambda_handler(event, context):
    return {"notification_sent": True, "message_id": "msg-123"}
        '''
        
        create_mock_lambda_function(
            lambda_client, 
            'vulnerability-scanner-microservice-test', 
            vulnerability_scanner_code
        )
        create_mock_lambda_function(
            lambda_client, 
            'patch-approver-microservice-test', 
            patch_approver_code
        )
        create_mock_lambda_function(
            lambda_client, 
            'notification-service-microservice-test', 
            notification_service_code
        )
        
        # Create EventBridge custom bus
        try:
            events_client.create_event_bus(Name='patching-automation-test')
        except events_client.exceptions.ResourceAlreadyExistsException:
            pass
        
        # Define simplified state machine
        state_machine_definition = {
            "Comment": "Simplified patch approval workflow for testing",
            "StartAt": "ValidateInput",
            "States": {
                "ValidateInput": {
                    "Type": "Pass",
                    "Parameters": {
                        "correlation_id.$": "$.correlation_id",
                        "event_type.$": "$.detail-type",
                        "vulnerability_data.$": "$.detail"
                    },
                    "Next": "ScanVulnerabilities"
                },
                "ScanVulnerabilities": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::lambda:invoke",
                    "Parameters": {
                        "FunctionName": "vulnerability-scanner-microservice-test",
                        "Payload": {
                            "scanType": "targeted",
                            "daysBack": 1,
                            "correlation_id.$": "$.correlation_id"
                        }
                    },
                    "ResultPath": "$.vulnerability_scan_result",
                    "TimeoutSeconds": 60,
                    "Retry": [
                        {
                            "ErrorEquals": ["Lambda.ServiceException"],
                            "IntervalSeconds": 2,
                            "MaxAttempts": 2,
                            "BackoffRate": 2.0
                        }
                    ],
                    "Next": "EvaluateVulnerabilities"
                },
                "EvaluateVulnerabilities": {
                    "Type": "Choice",
                    "Choices": [
                        {
                            "Variable": "$.vulnerability_scan_result.Payload.critical_vulnerabilities",
                            "NumericGreaterThan": 0,
                            "Next": "ProcessCriticalVulnerabilities"
                        }
                    ],
                    "Default": "ProcessStandardVulnerabilities"
                },
                "ProcessCriticalVulnerabilities": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::lambda:invoke",
                    "Parameters": {
                        "FunctionName": "patch-approver-microservice-test",
                        "Payload": {
                            "approval_mode": "automatic",
                            "severity_filter": ["CRITICAL"],
                            "correlation_id.$": "$.correlation_id"
                        }
                    },
                    "ResultPath": "$.patch_approval_result",
                    "Next": "PublishApprovalEvents"
                },
                "ProcessStandardVulnerabilities": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::lambda:invoke",
                    "Parameters": {
                        "FunctionName": "patch-approver-microservice-test",
                        "Payload": {
                            "approval_mode": "standard",
                            "correlation_id.$": "$.correlation_id"
                        }
                    },
                    "ResultPath": "$.patch_approval_result",
                    "Next": "PublishApprovalEvents"
                },
                "PublishApprovalEvents": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::events:putEvents",
                    "Parameters": {
                        "Entries": [
                            {
                                "Source": "patching-automation.patch-approval-workflow",
                                "DetailType": "Patch Approval Completed",
                                "Detail": {
                                    "correlation_id.$": "$.correlation_id",
                                    "status": "approved"
                                },
                                "EventBusName": "patching-automation-test"
                            }
                        ]
                    },
                    "Next": "WorkflowSuccess"
                },
                "WorkflowSuccess": {
                    "Type": "Succeed",
                    "Comment": "Patch approval workflow completed successfully"
                }
            }
        }
        
        # Create state machine
        try:
            response = stepfunctions_client.create_state_machine(
                name='patch-approval-workflow-test',
                definition=json.dumps(state_machine_definition),
                roleArn='arn:aws:iam::123456789012:role/lambda-execution-role'
            )
            
            state_machine_arn = response['stateMachineArn']
            
            # Verify state machine was created
            describe_response = stepfunctions_client.describe_state_machine(
                stateMachineArn=state_machine_arn
            )
            
            assert describe_response['name'] == 'patch-approval-workflow-test'
            assert describe_response['status'] == 'ACTIVE'
            
        except stepfunctions_client.exceptions.StateMachineAlreadyExists:
            # State machine already exists, get its ARN
            list_response = stepfunctions_client.list_state_machines()
            state_machine_arn = next(
                sm['stateMachineArn'] 
                for sm in list_response['stateMachines']
                if sm['name'] == 'patch-approval-workflow-test'
            )
    
    def test_patch_approval_workflow_execution_critical_vulnerabilities(
        self, 
        stepfunctions_client, 
        lambda_client, 
        iam_client
    ):
        """Test workflow execution with critical vulnerabilities"""
        # Setup
        create_execution_role(iam_client)
        
        # Get state machine ARN
        try:
            list_response = stepfunctions_client.list_state_machines()
            state_machine_arn = next(
                sm['stateMachineArn'] 
                for sm in list_response['stateMachines']
                if sm['name'] == 'patch-approval-workflow-test'
            )
        except (StopIteration, stepfunctions_client.exceptions.ClientError):
            pytest.skip("State machine not available for execution test")
        
        # Start execution with critical vulnerabilities
        execution_input = {
            "correlation_id": self.correlation_id,
            "detail-type": "Critical Vulnerability Detection",
            "detail": {
                "vulnerability_count": 10,
                "critical_count": 5,
                "high_count": 3
            }
        }
        
        response = stepfunctions_client.start_execution(
            stateMachineArn=state_machine_arn,
            name=f'test-execution-critical-{self.correlation_id}',
            input=json.dumps(execution_input)
        )
        
        execution_arn = response['executionArn']
        
        # Wait for execution to complete (with timeout)
        max_wait_time = 30  # seconds
        wait_time = 0
        
        while wait_time < max_wait_time:
            execution_status = stepfunctions_client.describe_execution(
                executionArn=execution_arn
            )
            
            if execution_status['status'] != 'RUNNING':
                break
                
            time.sleep(1)
            wait_time += 1
        
        # Verify execution completed successfully
        final_status = stepfunctions_client.describe_execution(
            executionArn=execution_arn
        )
        
        assert final_status['status'] == 'SUCCEEDED'
        
        # Verify execution history
        history = stepfunctions_client.get_execution_history(
            executionArn=execution_arn
        )
        
        # Check that critical vulnerability path was taken
        events = history['events']
        state_names = [
            event.get('stateEnteredEventDetails', {}).get('name')
            for event in events
            if event['type'] == 'StateEntered'
        ]
        
        assert 'ProcessCriticalVulnerabilities' in state_names
        assert 'WorkflowSuccess' in state_names
    
    def test_patch_approval_workflow_execution_standard_vulnerabilities(
        self, 
        stepfunctions_client
    ):
        """Test workflow execution with standard vulnerabilities"""
        # Get state machine ARN
        try:
            list_response = stepfunctions_client.list_state_machines()
            state_machine_arn = next(
                sm['stateMachineArn'] 
                for sm in list_response['stateMachines']
                if sm['name'] == 'patch-approval-workflow-test'
            )
        except (StopIteration, stepfunctions_client.exceptions.ClientError):
            pytest.skip("State machine not available for execution test")
        
        # Start execution with no critical vulnerabilities
        execution_input = {
            "correlation_id": self.correlation_id + "-standard",
            "detail-type": "Vulnerability Detection",
            "detail": {
                "vulnerability_count": 5,
                "critical_count": 0,
                "high_count": 2
            }
        }
        
        response = stepfunctions_client.start_execution(
            stateMachineArn=state_machine_arn,
            name=f'test-execution-standard-{self.correlation_id}',
            input=json.dumps(execution_input)
        )
        
        execution_arn = response['executionArn']
        
        # Wait for execution to complete
        max_wait_time = 30
        wait_time = 0
        
        while wait_time < max_wait_time:
            execution_status = stepfunctions_client.describe_execution(
                executionArn=execution_arn
            )
            
            if execution_status['status'] != 'RUNNING':
                break
                
            time.sleep(1)
            wait_time += 1
        
        # Verify execution completed successfully
        final_status = stepfunctions_client.describe_execution(
            executionArn=execution_arn
        )
        
        assert final_status['status'] == 'SUCCEEDED'
        
        # Verify standard vulnerability path was taken
        history = stepfunctions_client.get_execution_history(
            executionArn=execution_arn
        )
        
        events = history['events']
        state_names = [
            event.get('stateEnteredEventDetails', {}).get('name')
            for event in events
            if event['type'] == 'StateEntered'
        ]
        
        assert 'ProcessStandardVulnerabilities' in state_names
        assert 'WorkflowSuccess' in state_names


class TestWorkflowIntegration:
    """Test cross-workflow integration scenarios"""
    
    def test_event_driven_workflow_triggers(self, events_client):
        """Test that EventBridge events can trigger workflows"""
        # Create a custom event bus
        bus_name = 'patching-automation-test'
        
        try:
            events_client.create_event_bus(Name=bus_name)
        except events_client.exceptions.ResourceAlreadyExistsException:
            pass
        
        # Put a test event
        test_event = {
            'Source': 'patching-automation.vulnerability-scanner',
            'DetailType': 'Critical Vulnerabilities Detected',
            'Detail': json.dumps({
                'correlation_id': f'integration-test-{int(time.time())}',
                'environment': 'test',
                'critical_count': 3,
                'high_count': 5
            }),
            'EventBusName': bus_name
        }
        
        response = events_client.put_events(Entries=[test_event])
        
        # Verify event was accepted
        assert response['FailedEntryCount'] == 0
        assert len(response['Entries']) == 1
        assert 'EventId' in response['Entries'][0]
    
    def test_workflow_error_handling(self, stepfunctions_client, lambda_client, iam_client):
        """Test workflow behavior with Lambda function errors"""
        create_execution_role(iam_client)
        
        # Create a Lambda function that always fails
        failing_lambda_code = '''
def lambda_handler(event, context):
    raise Exception("Simulated Lambda failure for testing")
        '''
        
        create_mock_lambda_function(
            lambda_client, 
            'failing-function-test', 
            failing_lambda_code
        )
        
        # Create a simple state machine with error handling
        error_test_definition = {
            "Comment": "Error handling test workflow",
            "StartAt": "FailingTask",
            "States": {
                "FailingTask": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::lambda:invoke",
                    "Parameters": {
                        "FunctionName": "failing-function-test",
                        "Payload": {}
                    },
                    "Retry": [
                        {
                            "ErrorEquals": ["States.ALL"],
                            "IntervalSeconds": 1,
                            "MaxAttempts": 2,
                            "BackoffRate": 2.0
                        }
                    ],
                    "Catch": [
                        {
                            "ErrorEquals": ["States.ALL"],
                            "Next": "ErrorHandler",
                            "ResultPath": "$.error"
                        }
                    ],
                    "Next": "Success"
                },
                "ErrorHandler": {
                    "Type": "Pass",
                    "Parameters": {
                        "error_handled": True,
                        "error_details.$": "$.error"
                    },
                    "Next": "Failure"
                },
                "Success": {
                    "Type": "Succeed"
                },
                "Failure": {
                    "Type": "Fail",
                    "Cause": "Lambda function failed after retries"
                }
            }
        }
        
        # Create state machine
        try:
            response = stepfunctions_client.create_state_machine(
                name='error-test-workflow',
                definition=json.dumps(error_test_definition),
                roleArn='arn:aws:iam::123456789012:role/lambda-execution-role'
            )
            state_machine_arn = response['stateMachineArn']
        except stepfunctions_client.exceptions.StateMachineAlreadyExists:
            # Get existing state machine
            list_response = stepfunctions_client.list_state_machines()
            state_machine_arn = next(
                sm['stateMachineArn'] 
                for sm in list_response['stateMachines']
                if sm['name'] == 'error-test-workflow'
            )
        
        # Execute the state machine
        response = stepfunctions_client.start_execution(
            stateMachineArn=state_machine_arn,
            name=f'error-test-execution-{int(time.time())}',
            input=json.dumps({})
        )
        
        execution_arn = response['executionArn']
        
        # Wait for execution to complete
        max_wait_time = 20
        wait_time = 0
        
        while wait_time < max_wait_time:
            execution_status = stepfunctions_client.describe_execution(
                executionArn=execution_arn
            )
            
            if execution_status['status'] != 'RUNNING':
                break
                
            time.sleep(1)
            wait_time += 1
        
        # Verify execution failed as expected (after retry attempts)
        final_status = stepfunctions_client.describe_execution(
            executionArn=execution_arn
        )
        
        assert final_status['status'] == 'FAILED'
        
        # Verify error handling path was taken
        history = stepfunctions_client.get_execution_history(
            executionArn=execution_arn
        )
        
        events = history['events']
        state_names = [
            event.get('stateEnteredEventDetails', {}).get('name')
            for event in events
            if event['type'] == 'StateEntered'
        ]
        
        assert 'ErrorHandler' in state_names


if __name__ == '__main__':
    pytest.main([__file__, '-v'])