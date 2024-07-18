"""
Pytest fixtures go here.
"""

import json
from uuid import uuid4
import pytest

MOCK_SECRET_ID = "arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret-name-abc123"
MOCK_CLIENT_REQUEST_TOKEN = "MyClientRequestToken-ABC123-XYZ987"
MOCK_OLD_SECRET_VERSION_ID = "MyOldClientRequestToken-ABC123-XYZ987"
MOCK_CLIENT_ID = "MyClientID"
MOCK_USERNAME = "my-username"
MOCK_PASSWORD = "MyPassword"
MOCK_NEW_PASSWORD = "MyNewPassword"
MOCK_SECRET_STRING = json.dumps(
    {"clientId": MOCK_CLIENT_ID, "username": MOCK_USERNAME, "password": MOCK_PASSWORD}
)
MOCK_NEW_SECRET_STRING = json.dumps(
    {"clientId": MOCK_CLIENT_ID, "username": MOCK_USERNAME, "password": MOCK_NEW_PASSWORD}
)


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


@pytest.fixture
def mock_old_secret_version_id():
    """Secrets Manager rotation old secret version ID."""
    return MOCK_OLD_SECRET_VERSION_ID


@pytest.fixture
def mock_client_id():
    """Cognito Identity Provider client ID."""
    return MOCK_CLIENT_ID


@pytest.fixture
def mock_secret_string():
    """Secrets Manager secret string."""
    return MOCK_SECRET_STRING


@pytest.fixture
def mock_new_secret_string():
    """Secrets Manager new secret string."""
    return MOCK_NEW_SECRET_STRING


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


@pytest.fixture
def set_secret_event():
    """Secrets Manager rotation set secret event."""
    event = {
        "Step": "setSecret",
        "SecretId": MOCK_SECRET_ID,
        "ClientRequestToken": MOCK_CLIENT_REQUEST_TOKEN,
    }
    return event


@pytest.fixture
def test_secret_event():
    """Secrets Manager rotation test secret event."""
    event = {
        "Step": "testSecret",
        "SecretId": MOCK_SECRET_ID,
        "ClientRequestToken": MOCK_CLIENT_REQUEST_TOKEN,
    }
    return event


@pytest.fixture
def finish_secret_event():
    """Secrets Manager rotation finish secret event."""
    event = {
        "Step": "finishSecret",
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
        "VersionIdsToStages": {
            MOCK_OLD_SECRET_VERSION_ID: ["AWSCURRENT"],
            MOCK_CLIENT_REQUEST_TOKEN: ["AWSPENDING"],
        },
    }
    return response


@pytest.fixture
def get_secret_value_response_current():
    """Secrets Manager GetSecretValue response with current secret"""
    response = {
        "SecretString": MOCK_SECRET_STRING,
    }
    return response


@pytest.fixture
def get_secret_value_response_pending():
    """Secrets Manager GetSecretValue response with pending secret"""
    response = {
        "SecretString": MOCK_NEW_SECRET_STRING,
    }
    return response


@pytest.fixture
def get_random_password_response():
    """Secrets Manager GetRandomPassword response"""
    response = {"RandomPassword": MOCK_NEW_PASSWORD}
    return response


# =====
# Cognito Identity Provider API responses
# =====
@pytest.fixture
def initiate_auth_response_no_challenge():
    """Cognito Identity Provider initiate auth response"""
    response = {
        "AuthenticationResult": {
            "AccessToken": "MyAccessToken",
            "ExpiresIn": 43200,
            "TokenType": "Bearer",
            "RefreshToken": "MyRefreshToken",
            "IdToken": "MyIdToken",
        }
    }
    return response


@pytest.fixture
def initiate_auth_response_force_change_password():
    """Cognito Identity Provider initiate auth response - force change password"""
    response = {
        "ChallengeName": "NEW_PASSWORD_REQUIRED",
        "Session": "MySessionToken-ABC123",
        "ChallengeParameters": {
            "USER_ID_FOR_SRP": MOCK_USERNAME,
            "requiredAttributes": "[]",
            "userAttributes": json.dumps({"email": f"{MOCK_USERNAME}@example.com"}),
        },
    }
    return response


@pytest.fixture
def respond_to_auth_challenge():
    """Cognito Identity Provider respond to auth challenge response"""
    response = {
        "ChallengeParameters": {},
        "AuthenticationResult": {
            "AccessToken": "MyAccessToken",
            "ExpiresIn": 43200,
            "TokenType": "Bearer",
            "RefreshToken": "MyRefreshToken",
            "IdToken": "MyIdToken",
        },
    }
    return response
