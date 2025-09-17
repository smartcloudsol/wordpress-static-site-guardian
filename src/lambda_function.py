import json
import datetime
import base64
import urllib.parse
import hashlib
import boto3
from botocore.exceptions import ClientError
import logging
import re
import time
import urllib.request
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
kms_client = boto3.client('kms')
ssm_client = boto3.client('ssm')

# Global cache for JWKS keys (persists across Lambda invocations)
JWKS_CACHE = {
    'keys': {},
    'last_updated': 0,
    'cache_duration': 3600  # 1 hour cache
}

# Embedded configuration (replaces environment variables for Lambda@Edge)
# TODO: These need to be populated during deployment with actual values
# For now, using placeholder values that will need to be replaced
DOMAIN_NAME = 'example.com'  # Replace with actual domain
KEY_PAIR_ID = 'ABCDEFGHIJKLMNOPQR'  # Replace with actual key pair ID
COOKIE_EXPIRATION_DAYS = 30
PROTECTED_PATHS = '/dashboard,/members,/profile'  # Replace with actual protected paths
KMS_KEY_ID = '12345678-1234-1234-1234-123456789012'  # Replace with actual KMS key ID
COGNITO_USER_POOL_ID = 'us-east-1_abcdefghi'  # Replace with actual User Pool ID
COGNITO_APP_CLIENT_IDS = 'client1,client2'  # Replace with actual App Client IDs

def lambda_handler(event, context):
    """
    Lambda@Edge function to issue CloudFront signed cookies
    Processes CloudFront viewer request events for /issue-cookie* paths
    """
    
    try:
        # Extract CloudFront request from event
        request = event['Records'][0]['cf']['request']
        uri = request['uri']
        querystring = request.get('querystring', '')
        headers = request.get('headers', {})
        
        logger.info(f"Processing Lambda@Edge request for URI: {uri}")
        
        # Validate this is an /issue-cookie request
        if not uri.startswith('/issue-cookie'):
            logger.error(f"Invalid URI for cookie issuance: {uri}")
            return create_error_response(400, 'Invalid endpoint')
        
        # Check for /issue-cookie in protected paths (defensive validation)
        # This is a backup check - the template should prevent this configuration
        protected_paths_list = [path.strip() for path in PROTECTED_PATHS.split(',') if path.strip()]
        
        for protected_path in protected_paths_list:
            if protected_path.startswith('/issue-cookie'):
                logger.error(f"Configuration error: protected path '{protected_path}' conflicts with /issue-cookie endpoint")
                return create_error_response(400, 'Configuration error: /issue-cookie paths cannot be in protected paths list')
        
        # Additional validation: check for common variations
        issue_cookie_variations = ['/issue-cookie', '/issue-cookie/', '/issue-cookie*']
        for variation in issue_cookie_variations:
            if variation in protected_paths_list:
                logger.error(f"Configuration error: '{variation}' found in protected paths")
                return create_error_response(400, f'Configuration error: {variation} cannot be in protected paths')
        
        logger.debug(f"Protected paths validation passed. Protected paths: {protected_paths_list}")
        
        # Extract JWT from Authorization header
        auth_header = headers.get('authorization', [{}])[0].get('value', '')
        if not auth_header.startswith('Bearer '):
            logger.warning("Missing or invalid Authorization header")
            return create_unauthorized_response()
        
        jwt_token = auth_header[7:]  # Remove 'Bearer ' prefix
        
        # Verify JWT token
        if not verify_jwt_token(jwt_token):
            logger.warning("JWT token verification failed")
            return create_unauthorized_response()
        
        # Parse query string for action
        query_params = parse_query_string(querystring)
        action = query_params.get('action', ['signin'])[0].lower()
        
        # Validate action parameter
        valid_actions = ['signin', 'signout']
        if action not in valid_actions:
            logger.warning(f"Invalid action parameter: {action}")
            return create_error_response(400, f'Invalid action. Must be one of: {", ".join(valid_actions)}')
        
        logger.info(f"Processing {action} request with valid JWT")
        
        if action == 'signout':
            # Return 204 No Content response that expires all cookies
            cookies = create_expired_cookies()
            return create_cookie_response(204, cookies, 'Cookies expired successfully')
        else:  # action == 'signin'
            # Return 204 No Content response with new signed host-only cookies
            cookies = create_signed_cookies()
            return create_cookie_response(204, cookies, 'Cookies issued successfully')
    
    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}", exc_info=True)
        return create_error_response(500, 'Internal server error')

def verify_jwt_token(jwt_token):
    """
    Verify JWT token against Cognito User Pool with full JWKS validation
    Supports both ID tokens (aud claim) and access tokens (client_id claim)
    """
    try:
        # Parse JWT token
        header, payload, signature = parse_jwt_token(jwt_token)
        if not header or not payload:
            logger.warning("Invalid JWT token format")
            return False
        
        # Validate basic claims
        current_time = int(time.time())
        
        # Check expiration
        if payload.get('exp', 0) < current_time:
            logger.warning("JWT token has expired")
            return False
        
        # Check not-before (if present)
        if payload.get('nbf', 0) > current_time:
            logger.warning("JWT token not yet valid (nbf claim)")
            return False
        
        # Validate issuer (extract region from User Pool ID)
        region = extract_region_from_user_pool_id(COGNITO_USER_POOL_ID)
        expected_issuer = f"https://cognito-idp.{region}.amazonaws.com/{COGNITO_USER_POOL_ID}"
        if payload.get('iss') != expected_issuer:
            logger.warning(f"Invalid issuer: {payload.get('iss')}. Expected: {expected_issuer}")
            return False
        
        # Validate audience (ID token) or client_id (access token)
        valid_client_ids = [client_id.strip() for client_id in COGNITO_APP_CLIENT_IDS.split(',')]
        
        # Check for ID token (has 'aud' claim)
        if 'aud' in payload:
            if payload.get('token_use') != 'id':
                logger.warning("Token has 'aud' claim but token_use is not 'id'")
                return False
            if payload['aud'] not in valid_client_ids:
                logger.warning(f"Invalid audience: {payload['aud']}")
                return False
        
        # Check for access token (has 'client_id' claim)
        elif 'client_id' in payload:
            if payload.get('token_use') != 'access':
                logger.warning("Token has 'client_id' claim but token_use is not 'access'")
                return False
            if payload['client_id'] not in valid_client_ids:
                logger.warning(f"Invalid client_id: {payload['client_id']}")
                return False
        
        else:
            logger.warning("JWT token missing both 'aud' and 'client_id' claims")
            return False
        
        # Verify signature
        if not verify_jwt_signature(jwt_token, header, payload):
            logger.warning("JWT signature verification failed")
            return False
        
        logger.info("JWT token verification successful")
        return True
        
    except Exception as e:
        logger.error(f"JWT verification error: {e}")
        return False

def extract_region_from_user_pool_id(user_pool_id):
    """Extract AWS region from Cognito User Pool ID format: region_poolid"""
    try:
        if '_' in user_pool_id:
            region = user_pool_id.split('_')[0]
            logger.debug(f"Extracted region '{region}' from User Pool ID '{user_pool_id}'")
            return region
        else:
            logger.warning(f"Invalid User Pool ID format: {user_pool_id}. Using default region us-east-1")
            return 'us-east-1'
    except Exception as e:
        logger.error(f"Error extracting region from User Pool ID: {e}")
        return 'us-east-1'

def parse_jwt_token(jwt_token):
    """Parse JWT token into header, payload, and signature"""
    try:
        parts = jwt_token.split('.')
        if len(parts) != 3:
            return None, None, None
        
        # Decode header and payload (add padding if needed)
        header_b64, payload_b64, signature_b64 = parts
        
        # Add padding for base64 decoding
        header_b64 += '=' * (4 - len(header_b64) % 4)
        payload_b64 += '=' * (4 - len(payload_b64) % 4)
        
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        
        return header, payload, signature_b64
        
    except Exception as e:
        logger.error(f"Error parsing JWT token: {e}")
        return None, None, None

def verify_jwt_signature(jwt_token, header, payload):
    """Verify JWT signature using cached JWKS keys"""
    try:
        # Get key ID from header
        kid = header.get('kid')
        if not kid:
            logger.warning("JWT header missing 'kid' claim")
            return False
        
        # Get public key from JWKS
        public_key = get_jwks_key(kid)
        if not public_key:
            logger.warning(f"Public key not found for kid: {kid}")
            return False
        
        # Verify signature
        parts = jwt_token.split('.')
        message = f"{parts[0]}.{parts[1]}".encode()
        signature = base64.urlsafe_b64decode(parts[2] + '=' * (4 - len(parts[2]) % 4))
        
        try:
            public_key.verify(
                signature,
                message,
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
            
    except Exception as e:
        logger.error(f"Error verifying JWT signature: {e}")
        return False

def get_jwks_key(kid):
    """Get public key from JWKS cache or fetch from Cognito"""
    try:
        current_time = time.time()
        
        # Check if cache is still valid
        if (current_time - JWKS_CACHE['last_updated']) > JWKS_CACHE['cache_duration']:
            logger.info("JWKS cache expired, fetching new keys")
            fetch_jwks_keys()
        
        # Return cached key
        return JWKS_CACHE['keys'].get(kid)
        
    except Exception as e:
        logger.error(f"Error getting JWKS key: {e}")
        return None

def fetch_jwks_keys():
    """Fetch JWKS keys from Cognito and cache them"""
    try:
        # Construct JWKS URL (extract region from User Pool ID)
        region = extract_region_from_user_pool_id(COGNITO_USER_POOL_ID)
        jwks_url = f"https://cognito-idp.{region}.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json"
        
        # Fetch JWKS
        with urllib.request.urlopen(jwks_url, timeout=10) as response:
            jwks_data = json.loads(response.read().decode())
        
        # Parse and cache keys
        new_keys = {}
        for key_data in jwks_data.get('keys', []):
            kid = key_data.get('kid')
            if not kid:
                continue
            
            # Convert JWK to RSA public key
            public_key = jwk_to_rsa_public_key(key_data)
            if public_key:
                new_keys[kid] = public_key
        
        # Update cache
        JWKS_CACHE['keys'] = new_keys
        JWKS_CACHE['last_updated'] = time.time()
        
        logger.info(f"Cached {len(new_keys)} JWKS keys")
        
    except Exception as e:
        logger.error(f"Error fetching JWKS keys: {e}")

def jwk_to_rsa_public_key(jwk_data):
    """Convert JWK to RSA public key"""
    try:
        if jwk_data.get('kty') != 'RSA':
            return None
        
        # Get modulus and exponent
        n = base64.urlsafe_b64decode(jwk_data['n'] + '=' * (4 - len(jwk_data['n']) % 4))
        e = base64.urlsafe_b64decode(jwk_data['e'] + '=' * (4 - len(jwk_data['e']) % 4))
        
        # Convert to integers
        n_int = int.from_bytes(n, byteorder='big')
        e_int = int.from_bytes(e, byteorder='big')
        
        # Create RSA public key
        public_numbers = rsa.RSAPublicNumbers(e_int, n_int)
        public_key = public_numbers.public_key(backend=default_backend())
        
        return public_key
        
    except Exception as e:
        logger.error(f"Error converting JWK to RSA public key: {e}")
        return None

def parse_query_string(querystring):
    """Parse CloudFront query string into dictionary"""
    if not querystring:
        return {}
    
    params = {}
    for param in querystring.split('&'):
        if '=' in param:
            key, value = param.split('=', 1)
            key = urllib.parse.unquote_plus(key)
            value = urllib.parse.unquote_plus(value)
            if key in params:
                if isinstance(params[key], list):
                    params[key].append(value)
                else:
                    params[key] = [params[key], value]
            else:
                params[key] = [value]
        else:
            key = urllib.parse.unquote_plus(param)
            params[key] = ['']
    
    return params

def create_error_response(status_code, message):
    """Create CloudFront error response"""
    return {
        'status': str(status_code),
        'statusDescription': get_status_description(status_code),
        'headers': {
            'content-type': [{'key': 'Content-Type', 'value': 'application/json'}],
            'cache-control': [{'key': 'Cache-Control', 'value': 'no-store'}]
        },
        'body': json.dumps({
            'error': message,
            'timestamp': datetime.datetime.utcnow().isoformat()
        })
    }

def create_unauthorized_response():
    """Create 401 Unauthorized response with WWW-Authenticate header"""
    return {
        'status': '401',
        'statusDescription': 'Unauthorized',
        'headers': {
            'www-authenticate': [{'key': 'WWW-Authenticate', 'value': 'Bearer realm="CloudFront"'}],
            'content-type': [{'key': 'Content-Type', 'value': 'application/json'}],
            'cache-control': [{'key': 'Cache-Control', 'value': 'no-store'}]
        },
        'body': json.dumps({
            'error': 'Unauthorized - valid JWT Bearer token required',
            'timestamp': datetime.datetime.utcnow().isoformat()
        })
    }

def create_cookie_response(status_code, cookies, message):
    """Create CloudFront response with Set-Cookie headers"""
    headers = {
        'cache-control': [{'key': 'Cache-Control', 'value': 'no-store'}]
    }
    
    # Add Content-Type only for responses with body
    if status_code != 204:
        headers['content-type'] = [{'key': 'Content-Type', 'value': 'application/json'}]
    
    # Add Set-Cookie headers (CloudFront Lambda@Edge format)
    # Each Set-Cookie header needs a unique key name
    for i, cookie in enumerate(cookies):
        headers[f'set-cookie-{i}'] = [{'key': 'Set-Cookie', 'value': cookie}]
    
    body = json.dumps({
        'message': message,
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'cookieCount': len(cookies)
    }) if status_code != 204 else ''
    
    response = {
        'status': str(status_code),
        'statusDescription': get_status_description(status_code),
        'headers': headers
    }
    
    if body:
        response['body'] = body
    
    return response

def get_status_description(status_code):
    """Get HTTP status description"""
    status_descriptions = {
        200: 'OK',
        204: 'No Content',
        400: 'Bad Request',
        401: 'Unauthorized',
        500: 'Internal Server Error'
    }
    return status_descriptions.get(status_code, 'Unknown')

def get_private_key_from_ssm():
    """Retrieve private key from SSM Parameter Store"""
    try:
        kms_key_id = KMS_KEY_ID
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
        # Use embedded configuration
        domain_name = DOMAIN_NAME
        key_pair_id = KEY_PAIR_ID
        expiration_days = COOKIE_EXPIRATION_DAYS
        protected_paths = [path.strip() for path in PROTECTED_PATHS.split(',')]
        
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
        
        # Create host-only cookies (no Domain attribute for Lambda@Edge)
        max_age = expiration_days * 24 * 3600
        
        cookies = [
            f"CloudFront-Policy={policy_b64}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}",
            f"CloudFront-Signature={signature}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}",
            f"CloudFront-Key-Pair-Id={key_pair_id}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}"
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
        domain_name = DOMAIN_NAME
        # For Lambda@Edge, use host-only cookies (no Domain attribute)
        # This ensures cookies are scoped to the exact domain
        
        # Host-only cookies (no Domain attribute for Lambda@Edge)
        cookies = [
            f"CloudFront-Policy=; Path=/; Max-Age=0; Secure; HttpOnly",
            f"CloudFront-Signature=; Path=/; Max-Age=0; Secure; HttpOnly", 
            f"CloudFront-Key-Pair-Id=; Path=/; Max-Age=0; Secure; HttpOnly"
        ]
        
        logger.info(f"Created {len(cookies)} expired cookies")
        return cookies
        
    except Exception as e:
        logger.error(f"Error creating expired cookies: {str(e)}")
        raise