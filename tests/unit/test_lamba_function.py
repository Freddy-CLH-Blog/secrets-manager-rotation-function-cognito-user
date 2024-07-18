"""
Tests for the lambda handler
"""

from botocore.stub import Stubber

from src import lambda_function


class TestLambdaHandler:
    """
    Tests for the main lambda handler function `lambda_handler()`.
    """

    def test_create_secret_event_existing_pending_secret(
        self,
        create_secret_event,
        lambda_context,
        mock_secret_id,
        mock_client_request_token,
        describe_secret_response,
        get_secret_value_response_current,
        get_secret_value_response_pending,
    ):  # pylint: disable=too-many-arguments
        """
        Lambda handler with a "create secret" event where there is an existing pending secret
        should return without generating a new pending secret i.e. `get_random_password()` is not
        called.
        """
        sm_stubber = Stubber(lambda_function.sm_client)
        sm_stubber.add_response(
            "describe_secret",
            describe_secret_response,
            expected_params={"SecretId": mock_secret_id},
        )
        sm_stubber.add_response(
            "get_secret_value",
            get_secret_value_response_current,
            expected_params={
                "SecretId": mock_secret_id,
                "VersionStage": "AWSCURRENT",
            },
        )
        # Set Secrets Manager response: a pending secret exists
        sm_stubber.add_response(
            "get_secret_value",
            get_secret_value_response_pending,
            expected_params={
                "SecretId": mock_secret_id,
                "VersionId": mock_client_request_token,
                "VersionStage": "AWSPENDING",
            },
        )

        with sm_stubber:
            lambda_function.lambda_handler(create_secret_event, lambda_context)

        sm_stubber.assert_no_pending_responses()

    def test_create_secret_event_creates_new_pending_secret(
        self,
        create_secret_event,
        lambda_context,
        mock_secret_id,
        mock_client_request_token,
        describe_secret_response,
        get_secret_value_response_current,
        get_random_password_response,
    ):  # pylint: disable=too-many-arguments
        """
        Lambda handler with a "create secret" event where there is no existing pending secret
        should generate a new pending secret i.e. `get_random_password()` is called.
        """
        sm_stubber = Stubber(lambda_function.sm_client)
        sm_stubber.add_response(
            "describe_secret",
            describe_secret_response,
            expected_params={"SecretId": mock_secret_id},
        )
        sm_stubber.add_response(
            "get_secret_value",
            get_secret_value_response_current,
            expected_params={
                "SecretId": mock_secret_id,
                "VersionStage": "AWSCURRENT",
            },
        )
        # Set Secrets Manager response: no existing pending secret thus raise not found exception
        sm_stubber.add_client_error(
            "get_secret_value",
            service_error_code="ResourceNotFoundException",
            http_status_code=404,
            expected_params={
                "SecretId": mock_secret_id,
                "VersionId": mock_client_request_token,
                "VersionStage": "AWSPENDING",
            },
        )
        # Set Secrets Manager response: generate a new secret string
        sm_stubber.add_response(
            "get_random_password",
            get_random_password_response,
            expected_params={"ExcludeCharacters": "/@\"'\\"},
        )
        # Set Secrets Manager response: put the new secret string as a pending secret
        sm_stubber.add_response(
            "put_secret_value",
            {},
            expected_params={
                "SecretId": mock_secret_id,
                "ClientRequestToken": mock_client_request_token,
                "SecretString": get_random_password_response["RandomPassword"],
                "VersionStages": ["AWSPENDING"],
            },
        )

        with sm_stubber:
            lambda_function.lambda_handler(create_secret_event, lambda_context)

        sm_stubber.assert_no_pending_responses()
