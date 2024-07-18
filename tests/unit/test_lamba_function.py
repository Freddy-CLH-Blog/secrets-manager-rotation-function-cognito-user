"""
Tests for the lambda handler
"""

import json
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
        # Set Secrets Manager response: retrieve the current secret string
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
        mock_new_secret_string,
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
        # Set Secrets Manager response: retrieve the current secret string
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
                "SecretString": mock_new_secret_string,
                "VersionStages": ["AWSPENDING"],
            },
        )

        with sm_stubber:
            lambda_function.lambda_handler(create_secret_event, lambda_context)

        sm_stubber.assert_no_pending_responses()

    def test_set_secret_change_password(
        self,
        set_secret_event,
        lambda_context,
        mock_secret_id,
        mock_client_request_token,
        mock_client_id,
        mock_secret_string,
        mock_new_secret_string,
        describe_secret_response,
        get_secret_value_response_current,
        get_secret_value_response_pending,
        initiate_auth_response_no_challenge,
    ):  # pylint: disable=too-many-arguments,too-many-locals
        """
        Lambda handler with a "set secret" event should perform a Cognito User Pool InitiateAuth
        call using a password. After a successful InitiateAuth response having no challenge, the
        password should be changed by performing a Cognito User Pool ChangePassword call.
        """
        username = json.loads(mock_secret_string)["username"]
        password = json.loads(mock_secret_string)["password"]
        new_password = json.loads(mock_new_secret_string)["password"]
        access_token = initiate_auth_response_no_challenge["AuthenticationResult"]["AccessToken"]

        sm_stubber = Stubber(lambda_function.sm_client)
        cognito_stubber = Stubber(lambda_function.cognito_client)

        sm_stubber.add_response(
            "describe_secret",
            describe_secret_response,
            expected_params={"SecretId": mock_secret_id},
        )
        # Set Secrets Manager response: retrieve the current secret string
        sm_stubber.add_response(
            "get_secret_value",
            get_secret_value_response_current,
            expected_params={
                "SecretId": mock_secret_id,
                "VersionStage": "AWSCURRENT",
            },
        )
        # Set Secrets Manager response: retrieve the pending secret string
        sm_stubber.add_response(
            "get_secret_value",
            get_secret_value_response_pending,
            expected_params={
                "SecretId": mock_secret_id,
                "VersionId": mock_client_request_token,
                "VersionStage": "AWSPENDING",
            },
        )

        # Set Cognito User Pool response: initiate auth with password (no challenge)
        cognito_stubber.add_response(
            "initiate_auth",
            initiate_auth_response_no_challenge,
            expected_params={
                "AuthFlow": "USER_PASSWORD_AUTH",
                "ClientId": mock_client_id,
                "AuthParameters": {
                    "USERNAME": username,
                    "PASSWORD": password,
                },
            },
        )
        # Set Cognito User Pool response: perform change password
        cognito_stubber.add_response(
            "change_password",
            {},
            expected_params={
                "PreviousPassword": password,
                "ProposedPassword": new_password,
                "AccessToken": access_token,
            },
        )

        with sm_stubber:
            with cognito_stubber:
                lambda_function.lambda_handler(set_secret_event, lambda_context)

        sm_stubber.assert_no_pending_responses()
        cognito_stubber.assert_no_pending_responses()

    def test_set_secret_challenge_force_change_password(
        self,
        set_secret_event,
        lambda_context,
        mock_secret_id,
        mock_client_request_token,
        mock_client_id,
        mock_secret_string,
        mock_new_secret_string,
        describe_secret_response,
        get_secret_value_response_current,
        get_secret_value_response_pending,
        initiate_auth_response_force_change_password,
        respond_to_auth_challenge,
    ):  # pylint: disable=too-many-arguments,too-many-locals
        """
        Lambda handler with a "set secret" event should perform a Cognito User Pool InitiateAuth
        call using a password. After a InitiateAuth response with a challenge to force the change
        of password, the password is then changed in response to the challenge by performing a
        Cognito User Pool RespondToAuthChallenge call.
        """
        username = json.loads(mock_secret_string)["username"]
        password = json.loads(mock_secret_string)["password"]
        new_password = json.loads(mock_new_secret_string)["password"]
        session_token = initiate_auth_response_force_change_password["Session"]

        sm_stubber = Stubber(lambda_function.sm_client)
        cognito_stubber = Stubber(lambda_function.cognito_client)

        sm_stubber.add_response(
            "describe_secret",
            describe_secret_response,
            expected_params={"SecretId": mock_secret_id},
        )
        # Set Secrets Manager response: retrieve the current secret string
        sm_stubber.add_response(
            "get_secret_value",
            get_secret_value_response_current,
            expected_params={
                "SecretId": mock_secret_id,
                "VersionStage": "AWSCURRENT",
            },
        )
        # Set Secrets Manager response: retrieve the pending secret string
        sm_stubber.add_response(
            "get_secret_value",
            get_secret_value_response_pending,
            expected_params={
                "SecretId": mock_secret_id,
                "VersionId": mock_client_request_token,
                "VersionStage": "AWSPENDING",
            },
        )

        # Set Cognito User Pool response:
        # initiate auth with password, challenge force change password
        cognito_stubber.add_response(
            "initiate_auth",
            initiate_auth_response_force_change_password,
            expected_params={
                "AuthFlow": "USER_PASSWORD_AUTH",
                "ClientId": mock_client_id,
                "AuthParameters": {
                    "USERNAME": username,
                    "PASSWORD": password,
                },
            },
        )
        # Set Cognito User Pool response: respond to challenge change password
        cognito_stubber.add_response(
            "respond_to_auth_challenge",
            respond_to_auth_challenge,
            expected_params={
                "ChallengeName": "NEW_PASSWORD_REQUIRED",
                "ChallengeResponses": {
                    "USERNAME": username,
                    "NEW_PASSWORD": new_password,
                },
                "ClientId": mock_client_id,
                "Session": session_token,
            },
        )

        with sm_stubber:
            with cognito_stubber:
                lambda_function.lambda_handler(set_secret_event, lambda_context)

        sm_stubber.assert_no_pending_responses()
        cognito_stubber.assert_no_pending_responses()

    def test_test_secret_event(
        self,
        test_secret_event,
        lambda_context,
        mock_secret_id,
        mock_client_request_token,
        mock_client_id,
        mock_new_secret_string,
        describe_secret_response,
        get_secret_value_response_pending,
        initiate_auth_response_no_challenge,
    ):  # pylint: disable=too-many-arguments,too-many-locals
        """
        Lambda handler with a "test secret" event should retrieve the new password stored as
        AWSPENDING in Secrets Manager. It should then test the new password by performing a Cognito
        User Pool InitiateAuth call using the new password.
        """
        username = json.loads(mock_new_secret_string)["username"]
        new_password = json.loads(mock_new_secret_string)["password"]
        sm_stubber = Stubber(lambda_function.sm_client)
        cognito_stubber = Stubber(lambda_function.cognito_client)

        sm_stubber.add_response(
            "describe_secret",
            describe_secret_response,
            expected_params={"SecretId": mock_secret_id},
        )
        # Set Secrets Manager response: retrieve the pending secret string
        sm_stubber.add_response(
            "get_secret_value",
            get_secret_value_response_pending,
            expected_params={
                "SecretId": mock_secret_id,
                "VersionId": mock_client_request_token,
                "VersionStage": "AWSPENDING",
            },
        )

        # Set Cognito User Pool response: initiate auth with password (no challenge)
        cognito_stubber.add_response(
            "initiate_auth",
            initiate_auth_response_no_challenge,
            expected_params={
                "AuthFlow": "USER_PASSWORD_AUTH",
                "ClientId": mock_client_id,
                "AuthParameters": {
                    "USERNAME": username,
                    "PASSWORD": new_password,
                },
            },
        )

        with sm_stubber:
            with cognito_stubber:
                lambda_function.lambda_handler(test_secret_event, lambda_context)

        sm_stubber.assert_no_pending_responses()
        cognito_stubber.assert_no_pending_responses()

    def test_finish_secret_event(
        self,
        finish_secret_event,
        lambda_context,
        mock_secret_id,
        mock_client_request_token,
        mock_old_secret_version_id,
        describe_secret_response,
    ):  # pylint: disable=too-many-arguments
        """
        Lambda handler with a "finish secret" event should update the new password in
        Secrets Manager by setting the label AWSCURRENT to it's version ID. This is done by
        performing a Secrets Manager UpdateSecretVersionStage call.
        """
        sm_stubber = Stubber(lambda_function.sm_client)
        sm_stubber.add_response(
            "describe_secret",
            describe_secret_response,
            expected_params={"SecretId": mock_secret_id},
        )
        # Set Secrets Manager response: describe the secret to get the current version
        sm_stubber.add_response(
            "describe_secret",
            describe_secret_response,
            expected_params={"SecretId": mock_secret_id},
        )
        sm_stubber.add_response(
            "update_secret_version_stage",
            {},
            expected_params={
                "SecretId": mock_secret_id,
                "VersionStage": "AWSCURRENT",
                "MoveToVersionId": mock_client_request_token,
                "RemoveFromVersionId": mock_old_secret_version_id,
            },
        )

        with sm_stubber:
            lambda_function.lambda_handler(finish_secret_event, lambda_context)

        sm_stubber.assert_no_pending_responses()
