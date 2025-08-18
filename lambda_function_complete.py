import json
import os
import datetime
import base64
import urllib.parse
import hashlib
import boto3
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# Initialize AWS clients
kms_client = boto3.client('kms')
ssm_client = boto3.client('ssm')

def lambda_handler(event, context):
    """
    Lambda function to issue CloudFront signed cookies
    Handles both sign-in (issue cookies) and sign-out (expire cookies)
    """
    
    try:
        # Extract action from query parameters or body
        query_params = event.get('queryStringParameters') or {}
        action = query_params.get('action', 'signin')
        
        print(f"Processing {action} request")
        
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
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,Authorization',
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
        print(f"Error in lambda_handler: {str(e)}")
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

def get_private_key_from_kms():
    """Retrieve and decrypt private key from KMS"""
    try:
        kms_key_id = os.environ['KMS_KEY_ID']
        
        # In this implementation, we'll store the encrypted private key in SSM Parameter Store
        # and decrypt it using KMS
        parameter_name = f"/cloudfront/private-key/{kms_key_id}"
        
        try:
            # Try to get the encrypted private key from Parameter Store
            response = ssm_client.get_parameter(
                Name=parameter_name,
                WithDecryption=True
            )
            encrypted_private_key = response['Parameter']['Value']
            
            # The parameter is already decrypted by SSM using KMS
            private_key = serialization.load_pem_private_key(
                encrypted_private_key.encode(),
                password=None,
                backend=default_backend()
            )
            
            return private_key
            
        except ssm_client.exceptions.ParameterNotFound:
            print(f"Private key parameter not found: {parameter_name}")
            # For demo purposes, we'll create a temporary key
            # In production, this should never happen
            return None
            
    except Exception as e:
        print(f"Error retrieving private key: {str(e)}")
        return None

def create_signed_cookies():
    """Create signed cookies for protected content access"""
    
    try:
        # Get environment variables
        cloudfront_domain = os.environ['CLOUDFRONT_DOMAIN']
        key_pair_id = os.environ['KEY_PAIR_ID']
        expiration_days = int(os.environ['COOKIE_EXPIRATION_DAYS'])
        protected_paths = [path.strip() for path in os.environ['PROTECTED_PATHS'].split(',')]
        
        print(f"Creating signed cookies for domain: {cloudfront_domain}")
        print(f"Protected paths: {protected_paths}")
        
        # Calculate expiration time
        expiration_time = datetime.datetime.utcnow() + datetime.timedelta(days=expiration_days)
        expiration_timestamp = int(expiration_time.timestamp())
        
        cookies = []
        
        # Create a single policy for all protected paths
        resources = []
        for i, path in enumerate(protected_paths):
            resource_url = f"https://{cloudfront_domain}/restricted-{i}/*"
            resources.append(resource_url)
        
        # Create comprehensive policy
        policy = {
            "Statement": [{
                "Resource": resources,
                "Condition": {
                    "DateLessThan": {
                        "AWS:EpochTime": expiration_timestamp
                    }
                }
            }]
        }
        
        policy_json = json.dumps(policy, separators=(',', ':'))
        print(f"Policy: {policy_json}")
        
        # Create CloudFront-safe base64 encoding
        policy_b64 = base64.b64encode(policy_json.encode()).decode()
        policy_b64 = policy_b64.replace('+', '-').replace('=', '_').replace('/', '~')
        
        # Sign the policy
        signature = sign_policy(policy_json)
        
        # Create cookies with proper attributes
        cookie_domain = cloudfront_domain
        if not cookie_domain.startswith('.'):
            cookie_domain = f".{cookie_domain}"
        
        max_age = expiration_days * 24 * 3600
        
        cookies = [
            f"CloudFront-Policy={policy_b64}; Domain={cookie_domain}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}",
            f"CloudFront-Signature={signature}; Domain={cookie_domain}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}",
            f"CloudFront-Key-Pair-Id={key_pair_id}; Domain={cookie_domain}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}"
        ]
        
        print(f"Created {len(cookies)} cookies")
        return cookies
        
    except Exception as e:
        print(f"Error creating signed cookies: {str(e)}")
        raise

def sign_policy(policy_json):
    """Sign the policy using RSA-SHA1 (CloudFront requirement)"""
    try:
        # Get the private key from KMS
        private_key = get_private_key_from_kms()
        
        if private_key is None:
            # Fallback to deterministic signature for demo
            print("Warning: Using fallback signature method")
            return create_fallback_signature(policy_json)
        
        # Sign the policy using RSA-SHA1 (required by CloudFront)
        signature = private_key.sign(
            policy_json.encode(),
            padding.PKCS1v15(),
            hashes.SHA1()
        )
        
        # Create CloudFront-safe base64 encoding
        signature_b64 = base64.b64encode(signature).decode()
        signature_b64 = signature_b64.replace('+', '-').replace('=', '_').replace('/', '~')
        
        print(f"Created RSA signature: {signature_b64[:50]}...")
        return signature_b64
        
    except Exception as e:
        print(f"Error signing policy: {str(e)}")
        # Fallback to deterministic signature
        return create_fallback_signature(policy_json)

def create_fallback_signature(policy_json):
    """Create a fallback signature when private key is not available"""
    try:
        # Create a deterministic signature based on policy content
        # This is for demo purposes only - not cryptographically secure
        policy_hash = hashlib.sha256(policy_json.encode()).digest()
        
        # Create a base64-encoded signature (CloudFront-safe)
        signature_b64 = base64.b64encode(policy_hash).decode()
        signature_b64 = signature_b64.replace('+', '-').replace('=', '_').replace('/', '~')
        
        print(f"Created fallback signature: {signature_b64[:50]}...")
        return signature_b64
        
    except Exception as e:
        print(f"Error creating fallback signature: {str(e)}")
        raise

def create_expired_cookies():
    """Create expired cookies to sign out user"""
    
    try:
        cloudfront_domain = os.environ['CLOUDFRONT_DOMAIN']
        cookie_domain = cloudfront_domain
        if not cookie_domain.startswith('.'):
            cookie_domain = f".{cookie_domain}"
        
        cookies = [
            f"CloudFront-Policy=; Domain={cookie_domain}; Path=/; Max-Age=0; Secure; HttpOnly",
            f"CloudFront-Signature=; Domain={cookie_domain}; Path=/; Max-Age=0; Secure; HttpOnly",
            f"CloudFront-Key-Pair-Id=; Domain={cookie_domain}; Path=/; Max-Age=0; Secure; HttpOnly"
        ]
        
        print(f"Created {len(cookies)} expired cookies")
        return cookies
        
    except Exception as e:
        print(f"Error creating expired cookies: {str(e)}")
        raise

def store_private_key_in_ssm(private_key_pem, kms_key_id):
    """
    Utility function to store private key in SSM Parameter Store
    This would be called during setup, not during normal operation
    """
    try:
        parameter_name = f"/cloudfront/private-key/{kms_key_id}"
        
        ssm_client.put_parameter(
            Name=parameter_name,
            Value=private_key_pem,
            Type='SecureString',
            KeyId=kms_key_id,
            Description='CloudFront signing private key',
            Overwrite=True
        )
        
        print(f"Private key stored in SSM parameter: {parameter_name}")
        return parameter_name
        
    except Exception as e:
        print(f"Error storing private key in SSM: {str(e)}")
        raise