#!/usr/bin/env python3
"""
Unit tests for JWT verification functionality in Lambda@Edge function
Tests JWT parsing, signature verification, and claim validation
"""

import json
import sys
import os
import time
import base64
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

class TestJWTVerification(unittest.TestCase):
    """Test JWT verification functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Mock configuration values
        self.test_user_pool_id = 'us-east-1_testpool123'
        self.test_client_ids = ['client1', 'client2']
        self.current_time = int(time.time())
        
        # Sample JWT header and payload
        self.valid_header = {
            'alg': 'RS256',
            'kid': 'test-key-id',
            'typ': 'JWT'
        }
        
        self.valid_id_token_payload = {
            'iss': f'https://cognito-idp.us-east-1.amazonaws.com/{self.test_user_pool_id}',
            'aud': 'client1',
            'token_use': 'id',
            'exp': self.current_time + 3600,  # 1 hour from now
            'iat': self.current_time - 60,    # 1 minute ago
            'sub': 'user-123',
            'email': 'test@example.com'
        }
        
        self.valid_access_token_payload = {
            'iss': f'https://cognito-idp.us-east-1.amazonaws.com/{self.test_user_pool_id}',
            'client_id': 'client1',
            'token_use': 'access',
            'exp': self.current_time + 3600,  # 1 hour from now
            'iat': self.current_time - 60,    # 1 minute ago
            'sub': 'user-123',
            'scope': 'openid email'
        }
    
    def create_test_jwt(self, header, payload):
        """Create a test JWT token (without signature verification)"""
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        signature_b64 = 'test-signature'
        return f"{header_b64}.{payload_b64}.{signature_b64}"
    
    @patch('src.lambda_function.COGNITO_USER_POOL_ID', 'us-east-1_testpool123')
    @patch('src.lambda_function.COGNITO_APP_CLIENT_IDS', 'client1,client2')
    def test_parse_jwt_token_valid(self):
        """Test parsing valid JWT token"""
        from src.lambda_function import parse_jwt_token
        
        jwt_token = self.create_test_jwt(self.valid_header, self.valid_id_token_payload)
        header, payload, signature = parse_jwt_token(jwt_token)
        
        self.assertIsNotNone(header)
        self.assertIsNotNone(payload)
        self.assertIsNotNone(signature)
        self.assertEqual(header['alg'], 'RS256')
        self.assertEqual(payload['aud'], 'client1')
    
    def test_parse_jwt_token_invalid_format(self):
        """Test parsing JWT token with invalid format"""
        from src.lambda_function import parse_jwt_token
        
        # Test with wrong number of parts
        header, payload, signature = parse_jwt_token('invalid.jwt')
        self.assertIsNone(header)
        self.assertIsNone(payload)
        self.assertIsNone(signature)
        
        # Test with invalid base64
        header, payload, signature = parse_jwt_token('invalid.base64.token')
        self.assertIsNone(header)
        self.assertIsNone(payload)
        self.assertIsNone(signature)
    
    @patch('src.lambda_function.COGNITO_USER_POOL_ID', 'us-east-1_testpool123')
    @patch('src.lambda_function.COGNITO_APP_CLIENT_IDS', 'client1,client2')
    @patch('src.lambda_function.verify_jwt_signature')
    @patch('time.time')
    def test_verify_jwt_token_valid_id_token(self, mock_time, mock_verify_signature):
        """Test verification of valid ID token"""
        from src.lambda_function import verify_jwt_token
        
        mock_time.return_value = self.current_time
        mock_verify_signature.return_value = True
        
        jwt_token = self.create_test_jwt(self.valid_header, self.valid_id_token_payload)
        result = verify_jwt_token(jwt_token)
        
        self.assertTrue(result)
        mock_verify_signature.assert_called_once()
    
    @patch('src.lambda_function.COGNITO_USER_POOL_ID', 'us-east-1_testpool123')
    @patch('src.lambda_function.COGNITO_APP_CLIENT_IDS', 'client1,client2')
    @patch('src.lambda_function.verify_jwt_signature')
    @patch('time.time')
    def test_verify_jwt_token_valid_access_token(self, mock_time, mock_verify_signature):
        """Test verification of valid access token"""
        from src.lambda_function import verify_jwt_token
        
        mock_time.return_value = self.current_time
        mock_verify_signature.return_value = True
        
        jwt_token = self.create_test_jwt(self.valid_header, self.valid_access_token_payload)
        result = verify_jwt_token(jwt_token)
        
        self.assertTrue(result)
        mock_verify_signature.assert_called_once()
    
    @patch('src.lambda_function.COGNITO_USER_POOL_ID', 'us-east-1_testpool123')
    @patch('src.lambda_function.COGNITO_APP_CLIENT_IDS', 'client1,client2')
    @patch('time.time')
    def test_verify_jwt_token_expired(self, mock_time):
        """Test verification of expired token"""
        from src.lambda_function import verify_jwt_token
        
        mock_time.return_value = self.current_time
        
        # Create expired token
        expired_payload = self.valid_id_token_payload.copy()
        expired_payload['exp'] = self.current_time - 3600  # 1 hour ago
        
        jwt_token = self.create_test_jwt(self.valid_header, expired_payload)
        result = verify_jwt_token(jwt_token)
        
        self.assertFalse(result)
    
    @patch('src.lambda_function.COGNITO_USER_POOL_ID', 'us-east-1_testpool123')
    @patch('src.lambda_function.COGNITO_APP_CLIENT_IDS', 'client1,client2')
    @patch('time.time')
    def test_verify_jwt_token_not_before(self, mock_time):
        """Test verification of token with future nbf claim"""
        from src.lambda_function import verify_jwt_token
        
        mock_time.return_value = self.current_time
        
        # Create token with future nbf
        future_payload = self.valid_id_token_payload.copy()
        future_payload['nbf'] = self.current_time + 3600  # 1 hour from now
        
        jwt_token = self.create_test_jwt(self.valid_header, future_payload)
        result = verify_jwt_token(jwt_token)
        
        self.assertFalse(result)
    
    @patch('src.lambda_function.COGNITO_USER_POOL_ID', 'us-east-1_testpool123')
    @patch('src.lambda_function.COGNITO_APP_CLIENT_IDS', 'client1,client2')
    def test_verify_jwt_token_invalid_issuer(self):
        """Test verification with invalid issuer"""
        from src.lambda_function import verify_jwt_token
        
        # Create token with wrong issuer
        invalid_payload = self.valid_id_token_payload.copy()
        invalid_payload['iss'] = 'https://evil.com'
        
        jwt_token = self.create_test_jwt(self.valid_header, invalid_payload)
        result = verify_jwt_token(jwt_token)
        
        self.assertFalse(result)
    
    @patch('src.lambda_function.COGNITO_USER_POOL_ID', 'us-east-1_testpool123')
    @patch('src.lambda_function.COGNITO_APP_CLIENT_IDS', 'client1,client2')
    def test_verify_jwt_token_invalid_audience(self):
        """Test verification with invalid audience"""
        from src.lambda_function import verify_jwt_token
        
        # Create ID token with wrong audience
        invalid_payload = self.valid_id_token_payload.copy()
        invalid_payload['aud'] = 'invalid-client'
        
        jwt_token = self.create_test_jwt(self.valid_header, invalid_payload)
        result = verify_jwt_token(jwt_token)
        
        self.assertFalse(result)
    
    @patch('src.lambda_function.COGNITO_USER_POOL_ID', 'us-east-1_testpool123')
    @patch('src.lambda_function.COGNITO_APP_CLIENT_IDS', 'client1,client2')
    def test_verify_jwt_token_invalid_client_id(self):
        """Test verification with invalid client_id"""
        from src.lambda_function import verify_jwt_token
        
        # Create access token with wrong client_id
        invalid_payload = self.valid_access_token_payload.copy()
        invalid_payload['client_id'] = 'invalid-client'
        
        jwt_token = self.create_test_jwt(self.valid_header, invalid_payload)
        result = verify_jwt_token(jwt_token)
        
        self.assertFalse(result)
    
    @patch('src.lambda_function.COGNITO_USER_POOL_ID', 'us-east-1_testpool123')
    @patch('src.lambda_function.COGNITO_APP_CLIENT_IDS', 'client1,client2')
    def test_verify_jwt_token_wrong_token_use(self):
        """Test verification with wrong token_use claim"""
        from src.lambda_function import verify_jwt_token
        
        # Create ID token with wrong token_use
        invalid_payload = self.valid_id_token_payload.copy()
        invalid_payload['token_use'] = 'access'  # Should be 'id' for aud claim
        
        jwt_token = self.create_test_jwt(self.valid_header, invalid_payload)
        result = verify_jwt_token(jwt_token)
        
        self.assertFalse(result)
    
    @patch('src.lambda_function.COGNITO_USER_POOL_ID', 'us-east-1_testpool123')
    @patch('src.lambda_function.COGNITO_APP_CLIENT_IDS', 'client1,client2')
    def test_verify_jwt_token_missing_claims(self):
        """Test verification with missing required claims"""
        from src.lambda_function import verify_jwt_token
        
        # Create token without aud or client_id
        invalid_payload = self.valid_id_token_payload.copy()
        del invalid_payload['aud']
        
        jwt_token = self.create_test_jwt(self.valid_header, invalid_payload)
        result = verify_jwt_token(jwt_token)
        
        self.assertFalse(result)
    
    @patch('src.lambda_function.COGNITO_USER_POOL_ID', 'us-east-1_testpool123')
    @patch('src.lambda_function.COGNITO_APP_CLIENT_IDS', 'client1,client2')
    @patch('src.lambda_function.verify_jwt_signature')
    @patch('time.time')
    def test_verify_jwt_token_signature_failure(self, mock_time, mock_verify_signature):
        """Test verification with signature failure"""
        from src.lambda_function import verify_jwt_token
        
        mock_time.return_value = self.current_time
        mock_verify_signature.return_value = False  # Signature verification fails
        
        jwt_token = self.create_test_jwt(self.valid_header, self.valid_id_token_payload)
        result = verify_jwt_token(jwt_token)
        
        self.assertFalse(result)
        mock_verify_signature.assert_called_once()

class TestJWKSHandling(unittest.TestCase):
    """Test JWKS key handling and caching"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_jwks_response = {
            'keys': [
                {
                    'kid': 'test-key-1',
                    'kty': 'RSA',
                    'use': 'sig',
                    'n': 'test-modulus-base64',
                    'e': 'AQAB'
                },
                {
                    'kid': 'test-key-2',
                    'kty': 'RSA',
                    'use': 'sig',
                    'n': 'test-modulus-2-base64',
                    'e': 'AQAB'
                }
            ]
        }
    
    @patch('src.lambda_function.JWKS_CACHE', {'keys': {}, 'last_updated': 0, 'cache_duration': 3600})
    @patch('src.lambda_function.fetch_jwks_keys')
    @patch('time.time')
    def test_get_jwks_key_cache_expired(self, mock_time, mock_fetch_jwks):
        """Test JWKS key retrieval when cache is expired"""
        from src.lambda_function import get_jwks_key, JWKS_CACHE
        
        mock_time.return_value = 7200  # 2 hours after cache was last updated
        mock_fetch_jwks.return_value = None
        
        # Cache should be refreshed
        result = get_jwks_key('test-key-1')
        
        mock_fetch_jwks.assert_called_once()
        self.assertIsNone(result)  # Key not found after refresh
    
    @patch('src.lambda_function.JWKS_CACHE', {'keys': {'test-key-1': 'mock-key'}, 'last_updated': 7000, 'cache_duration': 3600})
    @patch('src.lambda_function.fetch_jwks_keys')
    @patch('time.time')
    def test_get_jwks_key_cache_valid(self, mock_time, mock_fetch_jwks):
        """Test JWKS key retrieval when cache is still valid"""
        from src.lambda_function import get_jwks_key
        
        mock_time.return_value = 7200  # Within cache duration
        
        result = get_jwks_key('test-key-1')
        
        # Should not fetch new keys
        mock_fetch_jwks.assert_not_called()
        self.assertEqual(result, 'mock-key')
    
    @patch('urllib.request.urlopen')
    @patch('src.lambda_function.COGNITO_USER_POOL_ID', 'us-east-1_testpool')
    @patch('src.lambda_function.jwk_to_rsa_public_key')
    @patch('time.time')
    def test_fetch_jwks_keys_success(self, mock_time, mock_jwk_to_rsa, mock_urlopen):
        """Test successful JWKS key fetching"""
        from src.lambda_function import fetch_jwks_keys, JWKS_CACHE
        
        # Mock HTTP response
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(self.test_jwks_response).encode()
        mock_urlopen.return_value.__enter__.return_value = mock_response
        
        # Mock key conversion
        mock_jwk_to_rsa.return_value = 'mock-rsa-key'
        mock_time.return_value = 1000
        
        fetch_jwks_keys()
        
        # Verify cache was updated
        self.assertEqual(len(JWKS_CACHE['keys']), 2)
        self.assertEqual(JWKS_CACHE['last_updated'], 1000)
        mock_jwk_to_rsa.assert_called()
    
    def test_jwk_to_rsa_public_key_invalid_type(self):
        """Test JWK to RSA conversion with invalid key type"""
        from src.lambda_function import jwk_to_rsa_public_key
        
        invalid_jwk = {'kty': 'EC', 'n': 'test', 'e': 'AQAB'}
        result = jwk_to_rsa_public_key(invalid_jwk)
        
        self.assertIsNone(result)

def run_jwt_tests():
    """Run all JWT verification tests"""
    print("🧪 Running JWT Verification Tests...")
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestJWTVerification))
    suite.addTests(loader.loadTestsFromTestCase(TestJWKSHandling))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print(f"\n📊 JWT Test Results:")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.failures:
        print("\n❌ Failures:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback}")
    
    if result.errors:
        print("\n💥 Errors:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback}")
    
    success = len(result.failures) == 0 and len(result.errors) == 0
    if success:
        print("\n🎉 All JWT verification tests passed!")
    else:
        print("\n❌ Some JWT verification tests failed.")
    
    return success

if __name__ == '__main__':
    success = run_jwt_tests()
    sys.exit(0 if success else 1)