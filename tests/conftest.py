"""
Pytest fixtures go here.
"""

from uuid import uuid4
import pytest

MOCK_SECRET_ID = "arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret-name-abc123"
MOCK_CLIENT_REQUEST_TOKEN = "MyClientRequestToken-ABC123-XYZ987"


class MockContext:  # pylint: disable=too-few-public-methods
    """Creates context for the lambda function"""

    def __init__(self, function_name, aws_request_id=None):
        value = "arn:aws:lambda:us-east-1:ACCOUNT:function"
        self.function_name = function_name
        self.function_version = "v$LATEST"
        self.memory_limit_in_mb = 512
        self.invoked_function_arn = f"{value}:{self.function_name}"
        if aws_request_id is None:
            self.aws_request_id = str(uuid4())
        else:
            self.aws_request_id = aws_request_id


@pytest.fixture
def lambda_context():
    """Dummy lambda context"""
    return MockContext("dummy_function")


@pytest.fixture
def mock_secret_id():
    """Mock Secrets Manager secret ID. This is also the ARN."""
    return MOCK_SECRET_ID


@pytest.fixture
def mock_client_request_token():
    """Secrets Manager rotation client request token."""
    return MOCK_CLIENT_REQUEST_TOKEN


# =====
# Secrets Manager rotation events
# =====
@pytest.fixture
def create_secret_event():
    """Secrets Manager rotation create secret event."""
    event = {
        "Step": "createSecret",
        "SecretId": MOCK_SECRET_ID,
        "ClientRequestToken": MOCK_CLIENT_REQUEST_TOKEN,
    }
    return event


# =====
# Secrets Manager API responses
# =====
@pytest.fixture
def describe_secret_response():
    """Secrets Manager DescribeSecret response"""
    response = {
        "RotationEnabled": True,
        "VersionIdsToStages": {MOCK_CLIENT_REQUEST_TOKEN: ["AWSPENDING"]},
    }
    return response


@pytest.fixture
def get_secret_value_response_current():
    """Secrets Manager GetSecretValue response with current secret"""
    response = {
        "SecretString": "MyCurrentSecretString",
    }
    return response


@pytest.fixture
def get_secret_value_response_pending():
    """Secrets Manager GetSecretValue response with pending secret"""
    response = {
        "SecretString": "MyPendingSecretString",
    }
    return response


@pytest.fixture
def get_random_password_response():
    """Secrets Manager GetRandomPassword response"""
    response = {"RandomPassword": "MyNewSecretString"}
    return response
