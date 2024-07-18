"""
Secrets Manager rotation lambda function to automatically change the password of a Amazon Cognito
user pool managed user.
"""

import os
import json
import boto3
from aws_lambda_powertools import Logger

logger = Logger()

AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

# Setup the client
sm_client = boto3.client("secretsmanager", region_name=AWS_REGION)
cognito_client = boto3.client("cognito-idp", region_name=AWS_REGION)


def lambda_handler(event, context):  # pylint: disable=unused-argument
    """Secrets Manager Rotation Template

    This is a template for creating an AWS Secrets Manager rotation lambda

    Args:
        event (dict): Lambda dictionary of event parameters. These keys must include the following:
            - SecretId: The secret ARN or identifier
            - ClientRequestToken: The ClientRequestToken of the secret version
            - Step: The rotation step (one of createSecret, setSecret, testSecret, or finishSecret)

        context (LambdaContext): The Lambda runtime information

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist
        ValueError: If the secret is not properly configured for rotation
        KeyError: If the event parameters do not contain the expected keys

    """
    arn = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]

    # Add additional logging keys: secret_id, version_id, rotation_step
    logger.append_keys(secret_id=arn)
    logger.append_keys(version_id=token)
    logger.append_keys(rotation_step=step)
    logger.info(
        f"Secrets Manager secret rotation event {step} for secret {arn} secret version {token}."
    )

    # Make sure the version is staged correctly
    metadata = sm_client.describe_secret(SecretId=arn)
    if not metadata["RotationEnabled"]:
        logger.error(f"Secret {arn} is not enabled for rotation")
        raise ValueError(f"Secret {arn} is not enabled for rotation")
    versions = metadata["VersionIdsToStages"]
    if token not in versions:
        logger.error(f"Secret version {token} has no stage for rotation of secret {arn}.")
        raise ValueError(f"Secret version {token} has no stage for rotation of secret {arn}.")
    if "AWSCURRENT" in versions[token]:
        logger.info(f"Secret version {token} already set as AWSCURRENT for secret {arn}.")
        return
    if "AWSPENDING" not in versions[token]:
        logger.error(f"Secret version {token} not set as AWSPENDING for rotation of secret {arn}.")
        raise ValueError(
            f"Secret version {token} not set as AWSPENDING for rotation of secret {arn}."
        )

    if step == "createSecret":
        create_secret(arn, token)

    elif step == "setSecret":
        set_secret(arn, token)

    elif step == "testSecret":
        test_secret(arn, token)

    elif step == "finishSecret":
        finish_secret(arn, token)

    else:
        raise ValueError("Invalid step parameter")


def create_secret(arn, token):
    """Create the secret

    This method first checks for the existence of a secret for the passed in token. If one does not
    exist, it will generate a new secret and put it with the passed in token.

    Args:
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

    """
    # Make sure the current secret exists
    secret = sm_client.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")
    secret_string = json.loads(secret["SecretString"])
    client_id = secret_string["clientId"]
    username = secret_string["username"]

    # Now try to get the secret version, if that fails, put a new secret
    try:
        sm_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        logger.info(f"createSecret: Successfully retrieved secret for {arn}.")
    except sm_client.exceptions.ResourceNotFoundException:
        # Get exclude characters from environment variable
        exclude_characters = os.getenv("EXCLUDE_CHARACTERS", "/@\"'\\")
        # Generate a random password
        passwd = sm_client.get_random_password(ExcludeCharacters=exclude_characters)

        # Put the secret
        new_secret_string = json.dumps(
            {"clientId": client_id, "username": username, "password": passwd["RandomPassword"]}
        )
        sm_client.put_secret_value(
            SecretId=arn,
            ClientRequestToken=token,
            SecretString=new_secret_string,
            VersionStages=["AWSPENDING"],
        )
        logger.info(f"createSecret: Successfully put secret for ARN {arn} and version {token}.")


def set_secret(arn, token):
    """Set the secret

    This method should set the AWSPENDING secret for the Cognito user.

    Args:
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version

    """
    # Retrieve the current secret
    secret = sm_client.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")
    secret_string = json.loads(secret["SecretString"])
    client_id = secret_string["clientId"]
    username = secret_string["username"]
    current_password = secret_string["password"]

    # Retrieve the pending secret
    secret = sm_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
    secret_string = json.loads(secret["SecretString"])
    assert client_id == secret_string["clientId"], "Client ID mismatch"
    assert username == secret_string["username"], "Username mismatch"
    pending_password = secret_string["password"]

    # Perform user password auth using current password on Cognito
    auth_resp = cognito_client.initiate_auth(
        AuthFlow="USER_PASSWORD_AUTH",
        ClientId=client_id,
        AuthParameters={
            "USERNAME": username,
            "PASSWORD": current_password,
        },
    )

    if "ChallengeName" in auth_resp:
        if auth_resp["ChallengeName"] == "NEW_PASSWORD_REQUIRED":
            # Handle the challenge of forcing the user to change password
            cognito_client.respond_to_auth_challenge(
                ChallengeName="NEW_PASSWORD_REQUIRED",
                ChallengeResponses={
                    "USERNAME": username,
                    "NEW_PASSWORD": pending_password,
                },
                ClientId=client_id,
                Session=auth_resp["Session"],
            )
            logger.info(
                f"setSecret: Successfully set new password for user {username} with ARN {arn}."
            )
        else:
            raise RuntimeError(f"Unexpected ChallengeName {auth_resp['ChallengeName']}")
    else:
        # At this point, the user has successfully authenticated with the current password with no
        # challenge. We then need to perform a change password.
        access_token = auth_resp["AuthenticationResult"]["AccessToken"]
        cognito_client.change_password(
            PreviousPassword=current_password,
            ProposedPassword=pending_password,
            AccessToken=access_token,
        )
        logger.info(f"setSecret: Successfully changed password for user {username} with ARN {arn}.")


def test_secret(arn, token):
    """Test the secret

    This method should validate that the Cognito user can login with the password in AWSPENDING.

    Args:
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version

    """
    # Retrieve the pending secret
    secret = sm_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
    secret_string = json.loads(secret["SecretString"])
    client_id = secret_string["clientId"]
    username = secret_string["username"]
    pending_password = secret_string["password"]

    # Perform user password auth using pending password on Cognito
    auth_resp = cognito_client.initiate_auth(
        AuthFlow="USER_PASSWORD_AUTH",
        ClientId=client_id,
        AuthParameters={
            "USERNAME": username,
            "PASSWORD": pending_password,
        },
    )
    if "AuthenticationResult" in auth_resp:
        for expected_token in ["AccessToken", "IdToken", "RefreshToken"]:
            assert (
                expected_token in auth_resp["AuthenticationResult"]
            ), f"Missing token {expected_token}"
        logger.info(f"testSecret: Successfully tested user {username} with ARN {arn}.")
    else:
        logger.error(f"testSecret: Failed to test user {username} with ARN {arn}.")
        raise RuntimeError("Unexpected response from Cognito")


def finish_secret(arn, token):
    """Finish the secret

    This method finalizes the rotation process by marking the secret version passed in as the
    AWSCURRENT secret.

    Args:
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn does not exist

    """
    # First describe the secret to get the current version
    metadata = sm_client.describe_secret(SecretId=arn)
    current_version = None
    for version in metadata["VersionIdsToStages"]:
        if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
            if version == token:
                # The correct version is already marked as current, return
                logger.info(
                    f"finishSecret: Version {version} already marked as AWSCURRENT for {arn}."
                )
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    sm_client.update_secret_version_stage(
        SecretId=arn,
        VersionStage="AWSCURRENT",
        MoveToVersionId=token,
        RemoveFromVersionId=current_version,
    )
    logger.info(
        f"finishSecret: Successfully set AWSCURRENT stage to version {token} for secret {arn}."
    )
