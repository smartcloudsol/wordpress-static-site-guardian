import json
import os
import datetime
import base64
import urllib.parse
import hashlib
import boto3
from botocore.exceptions import ClientError
import logging

# Configure logging
logger = logging.getLogger()
log_level = os.environ.get('LOG_LEVEL', 'INFO')
logger.setLevel(getattr(logging, log_level.upper()))

# Initialize AWS clients
kms_client = boto3.client('kms')
ssm_client = boto3.client('ssm')

def lambda_handler(event, context):
    """
    Lambda function to issue CloudFront signed cookies
    Handles both sign-in (issue cookies) and sign-out (expire cookies)
    """
    
    try:
        # Get environment variables
        domain_name = os.environ['DOMAIN_NAME']

        # Extract action from query parameters or body
        query_params = event.get('queryStringParameters') or {}
        action = query_params.get('action', 'signin')
        
        logger.info(f"Processing {action} request")
        
        if action == 'signout':
            # Expire cookies immediately
            cookies = create_expired_cookies()
        else:
            # Issue new signed cookies
            cookies = create_signed_cookies()
        
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Credentials': 'true',
                'Access-Control-Allow-Origin': f'https://{domain_name}',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'GET,OPTIONS'
            },
            'multiValueHeaders': {
                'Set-Cookie': cookies
            },
            'body': json.dumps({
                'message': f'Cookies {"expired" if action == "signout" else "issued"} successfully',
                'action': action,
                'timestamp': datetime.datetime.utcnow().isoformat(),
                'cookieCount': len(cookies)
            })
        }
    
    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}", exc_info=True)
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': json.dumps({
                'error': str(e),
                'timestamp': datetime.datetime.utcnow().isoformat()
            })
        }

def get_private_key_from_ssm():
    """Retrieve private key from SSM Parameter Store"""
    try:
        kms_key_id = os.environ['KMS_KEY_ID']
        parameter_name = f"/cloudfront/private-key/{kms_key_id}"
        
        try:
            # Get the encrypted private key from Parameter Store
            response = ssm_client.get_parameter(
                Name=parameter_name,
                WithDecryption=True
            )
            private_key_pem = response['Parameter']['Value']
            logger.info("Successfully retrieved private key from SSM")
            return private_key_pem
            
        except ssm_client.exceptions.ParameterNotFound:
            logger.warning(f"Private key parameter not found: {parameter_name}")
            return None
            
    except Exception as e:
        logger.error(f"Error retrieving private key: {str(e)}")
        return None

def create_signed_cookies():
    """Create signed cookies for protected content access"""
    
    try:
        # Get environment variables
        domain_name = os.environ['DOMAIN_NAME']
        key_pair_id = os.environ['KEY_PAIR_ID']
        expiration_days = int(os.environ['COOKIE_EXPIRATION_DAYS'])
        protected_paths = [path.strip() for path in os.environ['PROTECTED_PATHS'].split(',')]
        
        logger.info(f"Creating signed cookies for domain: {domain_name}")
        logger.debug(f"Protected paths: {protected_paths}")
        
        # Calculate expiration time
        expiration_time = datetime.datetime.utcnow() + datetime.timedelta(days=expiration_days)
        expiration_timestamp = int(expiration_time.timestamp())
        
        # Create comprehensive policy
        policy = {
            "Statement": [{
                "Resource": f"https://{domain_name}/restricted*",
                "Condition": {
                    "DateLessThan": {
                        "AWS:EpochTime": expiration_timestamp
                    }
                }
            }]
        }
        
        policy_json = json.dumps(policy, separators=(',', ':'))
        logger.debug(f"Policy: {policy_json}")
        
        # Create CloudFront-safe base64 encoding
        policy_b64 = base64.b64encode(policy_json.encode()).decode()
        policy_b64 = policy_b64.replace('+', '-').replace('=', '_').replace('/', '~')
        
        # Sign the policy
        signature = sign_policy(policy_json)
        
        # Create cookies with proper attributes
        cookie_domain = domain_name
        if not cookie_domain.startswith('.'):
            cookie_domain = f".{cookie_domain}"
        
        max_age = expiration_days * 24 * 3600
        
        cookies = [
            f"CloudFront-Policy={policy_b64}; Domain={cookie_domain}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}",
            f"CloudFront-Signature={signature}; Domain={cookie_domain}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}",
            f"CloudFront-Key-Pair-Id={key_pair_id}; Domain={cookie_domain}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}"
        ]
        
        logger.info(f"Created {len(cookies)} cookies")
        return cookies
        
    except Exception as e:
        logger.error(f"Error creating signed cookies: {str(e)}")
        raise

def sign_policy(policy_json):
    """Sign the policy using RSA-SHA1 (CloudFront requirement) with native cryptography"""
    try:
        # Get the private key from SSM
        private_key_pem = get_private_key_from_ssm()
        
        if private_key_pem is None:
            raise ValueError("Private key not found in SSM Parameter Store")
        
        # Use Lambda runtime's native cryptography library
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.backends import default_backend
        
        logger.info("Using native cryptography library for RSA-SHA1 signing")
        
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )
        
        signature = private_key.sign(
            policy_json.encode(),
            padding.PKCS1v15(),
            hashes.SHA1()
        )
        
        signature_b64 = base64.b64encode(signature).decode()
        signature_b64 = signature_b64.replace('+', '-').replace('=', '_').replace('/', '~')
        
        logger.info("Created production RSA-SHA1 signature successfully")
        return signature_b64
        
    except Exception as e:
        logger.error(f"Error signing policy: {str(e)}")
        raise


def create_expired_cookies():
    """Create expired cookies to sign out user"""
    
    try:
        domain_name = os.environ['DOMAIN_NAME']
        cookie_domain = domain_name
        if not cookie_domain.startswith('.'):
            cookie_domain = f".{cookie_domain}"
        
        cookies = [
            f"CloudFront-Policy=; Domain={cookie_domain}; Path=/; Max-Age=0; Secure; HttpOnly",
            f"CloudFront-Signature=; Domain={cookie_domain}; Path=/; Max-Age=0; Secure; HttpOnly",
            f"CloudFront-Key-Pair-Id=; Domain={cookie_domain}; Path=/; Max-Age=0; Secure; HttpOnly"
        ]
        
        logger.info(f"Created {len(cookies)} expired cookies")
        return cookies
        
    except Exception as e:
        logger.error(f"Error creating expired cookies: {str(e)}")
        raise