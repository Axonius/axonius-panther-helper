import json
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

# AWS Secrets Manager:
AWS_REGION = "<AWS_REGION>"  # Replace <AWS_REGION> with your AWS region
AWS_ROLE_ARN = "<AWS_ROLE_ARN>"  # Replace <AWS_ROLE_ARN> with your AWS role ARN
AWS_ROLE_SESSION_NAME = "<AWS_ROLE_SESSION_NAME>"  # Replace <AWS_ROLE_SESSION_NAME> with the name you want to give to that session, e.g. PantherGetSecrets.


def get_secret(secret_name: str) -> dict:
    """
    Fetches secrets from AWS secrets manager using assume role.

    Args:
        secret_name: the required secret to fetch.

    Returns:
        Json with the content of the required secret
    """

    try:
        sts_client = boto3.client(service_name="sts", region_name=AWS_REGION)

        resp = sts_client.assume_role(
            RoleArn=AWS_ROLE_ARN,
            RoleSessionName=AWS_ROLE_SESSION_NAME,
        )
        credentials = resp.get("Credentials")

        sec_client = boto3.client(
            service_name="secretsmanager",
            region_name=AWS_REGION,
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
        )
    except NoCredentialsError:
        return {"ERROR": "No trust connection to AWS secrets manager"}

    try:
        get_secret_value_response = sec_client.get_secret_value(SecretId=secret_name)
        # Decrypts secret using the associated KMS key.
        secret = get_secret_value_response["SecretString"]
    except ClientError as error_message:
        return {"ERROR": str(error_message)}
    except NoCredentialsError:
        return {"ERROR": "No trust connection to AWS secrets manager"}

    return json.loads(secret)
