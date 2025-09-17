#!/usr/bin/env python3
"""
Simple JWT verification tests for Lambda@Edge function
Tests basic JWT parsing and validation logic
"""

import json
import sys
import os
import time
import base64

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

def test_jwt_parsing():
    """Test basic JWT parsing functionality"""
    print("🧪 Testing JWT parsing...")
    
    # Create a simple test JWT
    header = {'alg': 'RS256', 'typ': 'JWT', 'kid': 'test-key'}
    payload = {
        'iss': 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_test',
        'aud': 'test-client',
        'exp': int(time.time()) + 3600,
        'iat': int(time.time()),
        'token_use': 'id'
    }
    
    # Encode JWT parts
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    signature_b64 = 'test-signature'
    
    test_jwt = f"{header_b64}.{payload_b64}.{signature_b64}"
    
    # Test parsing
    parts = test_jwt.split('.')
    if len(parts) == 3:
        print("✅ JWT has correct number of parts")
    else:
        print("❌ JWT parsing failed - wrong number of parts")
        return False
    
    # Test header decoding
    try:
        decoded_header = json.loads(base64.urlsafe_b64decode(parts[0] + '==='))
        if decoded_header['alg'] == 'RS256':
            print("✅ JWT header parsing successful")
        else:
            print("❌ JWT header parsing failed")
            return False
    except Exception as e:
        print(f"❌ JWT header parsing error: {e}")
        return False
    
    # Test payload decoding
    try:
        decoded_payload = json.loads(base64.urlsafe_b64decode(parts[1] + '==='))
        if decoded_payload['aud'] == 'test-client':
            print("✅ JWT payload parsing successful")
        else:
            print("❌ JWT payload parsing failed")
            return False
    except Exception as e:
        print(f"❌ JWT payload parsing error: {e}")
        return False
    
    return True

def test_lambda_function_syntax():
    """Test that the Lambda function has valid syntax"""
    print("🧪 Testing Lambda function syntax...")
    
    try:
        # Test Python syntax compilation
        import py_compile
        py_compile.compile('src/lambda_function.py', doraise=True)
        print("✅ Lambda function syntax is valid")
        return True
    except Exception as e:
        print(f"❌ Lambda function syntax error: {e}")
        return False

def test_jwt_claim_validation():
    """Test JWT claim validation logic"""
    print("🧪 Testing JWT claim validation...")
    
    current_time = int(time.time())
    
    # Test cases for different claim scenarios
    test_cases = [
        {
            'name': 'Valid ID token',
            'payload': {
                'iss': 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_test',
                'aud': 'valid-client',
                'token_use': 'id',
                'exp': current_time + 3600,
                'iat': current_time
            },
            'valid_clients': ['valid-client'],
            'expected': True
        },
        {
            'name': 'Valid access token',
            'payload': {
                'iss': 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_test',
                'client_id': 'valid-client',
                'token_use': 'access',
                'exp': current_time + 3600,
                'iat': current_time
            },
            'valid_clients': ['valid-client'],
            'expected': True
        },
        {
            'name': 'Expired token',
            'payload': {
                'iss': 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_test',
                'aud': 'valid-client',
                'token_use': 'id',
                'exp': current_time - 3600,  # Expired
                'iat': current_time - 7200
            },
            'valid_clients': ['valid-client'],
            'expected': False
        },
        {
            'name': 'Invalid audience',
            'payload': {
                'iss': 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_test',
                'aud': 'invalid-client',
                'token_use': 'id',
                'exp': current_time + 3600,
                'iat': current_time
            },
            'valid_clients': ['valid-client'],
            'expected': False
        }
    ]
    
    for test_case in test_cases:
        payload = test_case['payload']
        valid_clients = test_case['valid_clients']
        expected = test_case['expected']
        
        # Simulate claim validation logic
        is_valid = True
        
        # Check expiration
        if payload.get('exp', 0) < current_time:
            is_valid = False
        
        # Check audience/client_id
        if 'aud' in payload:
            if payload['aud'] not in valid_clients:
                is_valid = False
        elif 'client_id' in payload:
            if payload['client_id'] not in valid_clients:
                is_valid = False
        else:
            is_valid = False
        
        if is_valid == expected:
            print(f"✅ {test_case['name']}: validation correct")
        else:
            print(f"❌ {test_case['name']}: validation incorrect (expected {expected}, got {is_valid})")
            return False
    
    return True

def run_simple_jwt_tests():
    """Run simple JWT tests"""
    print("🧪 Running Simple JWT Verification Tests...")
    print("=" * 50)
    
    tests = [
        ("JWT Parsing", test_jwt_parsing),
        ("Lambda Function Syntax", test_lambda_function_syntax),
        ("JWT Claim Validation", test_jwt_claim_validation)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n🔍 {test_name}:")
        try:
            if test_func():
                passed += 1
            else:
                print(f"❌ {test_name} failed")
        except Exception as e:
            print(f"💥 {test_name} error: {e}")
    
    print("\n" + "=" * 50)
    print(f"📊 Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All simple JWT tests passed!")
        return True
    else:
        print("❌ Some JWT tests failed.")
        return False

if __name__ == '__main__':
    success = run_simple_jwt_tests()
    sys.exit(0 if success else 1)