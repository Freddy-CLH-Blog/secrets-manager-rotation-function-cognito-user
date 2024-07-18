"""
Secrets Manager rotation lambda function to automatically change the password of a Amazon Cognito
user pool managed user.
"""

import os
import boto3
from aws_lambda_powertools import Logger

logger = Logger()

AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

# Setup the client
sm_client = boto3.client("secretsmanager", region_name=AWS_REGION)


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
        create_secret(sm_client, arn, token)

    elif step == "setSecret":
        set_secret(sm_client, arn, token)

    elif step == "testSecret":
        test_secret(sm_client, arn, token)

    elif step == "finishSecret":
        finish_secret(sm_client, arn, token)

    else:
        raise ValueError("Invalid step parameter")


def create_secret(client, arn, token):
    """Create the secret

    This method first checks for the existence of a secret for the passed in token. If one does not
    exist, it will generate a new secret and put it with the passed in token.

    Args:
        client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

    """
    # Make sure the current secret exists
    client.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")

    # Now try to get the secret version, if that fails, put a new secret
    try:
        client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        logger.info(f"createSecret: Successfully retrieved secret for {arn}.")
    except client.exceptions.ResourceNotFoundException:
        # Get exclude characters from environment variable
        exclude_characters = (
            os.environ["EXCLUDE_CHARACTERS"] if "EXCLUDE_CHARACTERS" in os.environ else "/@\"'\\"
        )
        # Generate a random password
        passwd = client.get_random_password(ExcludeCharacters=exclude_characters)

        # Put the secret
        client.put_secret_value(
            SecretId=arn,
            ClientRequestToken=token,
            SecretString=passwd["RandomPassword"],
            VersionStages=["AWSPENDING"],
        )
        logger.info(f"createSecret: Successfully put secret for ARN {arn} and version {token}.")


def set_secret(service_client, arn, token):
    """Set the secret

    This method should set the AWSPENDING secret for the Cognito user.

    Args:
        service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version

    """
    # This is where the secret should be set in the service
    raise NotImplementedError


def test_secret(service_client, arn, token):
    """Test the secret

    This method should validate that the Cognito user can login with the password in AWSPENDING.

    Args:
        service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version

    """
    # This is where the secret should be tested against the service
    raise NotImplementedError


def finish_secret(service_client, arn, token):
    """Finish the secret

    This method finalizes the rotation process by marking the secret version passed in as the
    AWSCURRENT secret.

    Args:
        service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn does not exist

    """
    # First describe the secret to get the current version
    metadata = service_client.describe_secret(SecretId=arn)
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
    service_client.update_secret_version_stage(
        SecretId=arn,
        VersionStage="AWSCURRENT",
        MoveToVersionId=token,
        RemoveFromVersionId=current_version,
    )
    logger.info(
        f"finishSecret: Successfully set AWSCURRENT stage to version {token} for secret {arn}."
    )
