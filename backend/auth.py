import os
import boto3
import hmac
import hashlib
import base64
from dotenv import load_dotenv
from pathlib import Path
from botocore.exceptions import ClientError

import os
print("📁 Current working dir:", os.getcwd())
print("📄 .env exists:", os.path.exists(".env"))


# ✅ Always load .env from correct path
env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

# ✅ Debug prints (you should see these when you run)
print("✅ DEBUG: COGNITO_APP_CLIENT_ID =", os.getenv("COGNITO_APP_CLIENT_ID"))
print("✅ DEBUG: COGNITO_CLIENT_SECRET =", os.getenv("COGNITO_CLIENT_SECRET"))

# ✅ Load variables
COGNITO_APP_CLIENT_ID = os.getenv("COGNITO_APP_CLIENT_ID")
COGNITO_CLIENT_SECRET = os.getenv("COGNITO_CLIENT_SECRET")
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_KEY")

# ✅ Sanity check before proceeding
if not all([COGNITO_APP_CLIENT_ID, COGNITO_CLIENT_SECRET, AWS_ACCESS_KEY, AWS_SECRET_KEY]):
    raise ValueError("❌ Missing one or more required environment variables!")

# ✅ Boto3 client
client = boto3.client(
    "cognito-idp",
    region_name="eu-north-1",
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY
)

def get_secret_hash(username):
    message = username + COGNITO_APP_CLIENT_ID
    dig = hmac.new(str(COGNITO_CLIENT_SECRET).encode('utf-8'),
                   msg=message.encode('utf-8'),
                   digestmod=hashlib.sha256).digest()
    return base64.b64encode(dig).decode()



def get_cognito(username, password):
    try:
        secret_hash = get_secret_hash(username)
        response = client.initiate_auth(
            ClientId=COGNITO_APP_CLIENT_ID,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": username,
                "PASSWORD": password,
                "SECRET_HASH": secret_hash
            }
        )
        return response
    except ClientError as e:
        print("❌ Cognito login error:", e)
        raise e
