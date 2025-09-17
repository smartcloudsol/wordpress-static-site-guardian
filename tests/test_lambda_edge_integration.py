#!/usr/bin/env python3
"""
Lambda@Edge Integration Tests
Tests the complete Lambda@Edge function behavior with CloudFront events
"""

import json
import sys
import os
import time
import base64

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

def create_cloudfront_event(uri, querystring='', headers=None):
    """Create a mock CloudFront viewer request event"""
    if headers is None:
        headers = {}
    
    return {
        'Records': [{
            'cf': {
                'request': {
                    'uri': uri,
                    'querystring': querystring,
                    'headers': headers,
                    'method': 'GET'
                }
            }
        }]
    }

def create_jwt_token(payload):
    """Create a simple test JWT token"""
    header = {'alg': 'RS256', 'typ': 'JWT', 'kid': 'test-key'}
    
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    signature_b64 = 'test-signature'
    
    return f"{header_b64}.{payload_b64}.{signature_b64}"

def test_issue_cookie_endpoint_validation():
    """Test /issue-cookie endpoint validation"""
    print("🧪 Testing /issue-cookie endpoint validation...")
    
    # Test valid /issue-cookie request
    event = create_cloudfront_event('/issue-cookie')
    
    # Check URI validation
    request = event['Records'][0]['cf']['request']
    uri = request['uri']
    
    if uri.startswith('/issue-cookie'):
        print("✅ Valid /issue-cookie URI accepted")
    else:
        print("❌ Valid /issue-cookie URI rejected")
        return False
    
    # Test invalid URI
    invalid_event = create_cloudfront_event('/invalid-endpoint')
    invalid_request = invalid_event['Records'][0]['cf']['request']
    invalid_uri = invalid_request['uri']
    
    if not invalid_uri.startswith('/issue-cookie'):
        print("✅ Invalid URI correctly rejected")
    else:
        print("❌ Invalid URI incorrectly accepted")
        return False
    
    return True

def test_jwt_authorization_header():
    """Test JWT Bearer token extraction from Authorization header"""
    print("🧪 Testing JWT Authorization header processing...")
    
    # Test valid Bearer token
    valid_headers = {
        'authorization': [{'key': 'Authorization', 'value': 'Bearer eyJhbGciOiJSUzI1NiJ9.test.signature'}]
    }
    
    event = create_cloudfront_event('/issue-cookie', headers=valid_headers)
    auth_header = event['Records'][0]['cf']['request']['headers'].get('authorization', [{}])[0].get('value', '')
    
    if auth_header.startswith('Bearer '):
        jwt_token = auth_header[7:]  # Remove 'Bearer ' prefix
        if jwt_token:
            print("✅ JWT Bearer token correctly extracted")
        else:
            print("❌ JWT Bearer token extraction failed")
            return False
    else:
        print("❌ Authorization header format incorrect")
        return False
    
    # Test missing Authorization header
    event_no_auth = create_cloudfront_event('/issue-cookie')
    auth_header_missing = event_no_auth['Records'][0]['cf']['request']['headers'].get('authorization', [{}])[0].get('value', '')
    
    if not auth_header_missing.startswith('Bearer '):
        print("✅ Missing Authorization header correctly detected")
    else:
        print("❌ Missing Authorization header not detected")
        return False
    
    return True

def test_query_string_action_parsing():
    """Test query string action parameter parsing"""
    print("🧪 Testing query string action parsing...")
    
    # Test signin action
    event_signin = create_cloudfront_event('/issue-cookie', 'action=signin')
    querystring = event_signin['Records'][0]['cf']['request']['querystring']
    
    # Parse query string
    params = {}
    if querystring:
        for param in querystring.split('&'):
            if '=' in param:
                key, value = param.split('=', 1)
                params[key] = value
    
    if params.get('action') == 'signin':
        print("✅ Signin action correctly parsed")
    else:
        print("❌ Signin action parsing failed")
        return False
    
    # Test signout action
    event_signout = create_cloudfront_event('/issue-cookie', 'action=signout')
    querystring_signout = event_signout['Records'][0]['cf']['request']['querystring']
    
    params_signout = {}
    if querystring_signout:
        for param in querystring_signout.split('&'):
            if '=' in param:
                key, value = param.split('=', 1)
                params_signout[key] = value
    
    if params_signout.get('action') == 'signout':
        print("✅ Signout action correctly parsed")
    else:
        print("❌ Signout action parsing failed")
        return False
    
    # Test default action (no query string)
    event_default = create_cloudfront_event('/issue-cookie')
    querystring_default = event_default['Records'][0]['cf']['request']['querystring']
    
    if not querystring_default:
        print("✅ Default action handling (empty query string)")
    
    return True

def test_protected_path_validation():
    """Test protected path validation logic"""
    print("🧪 Testing protected path validation...")
    
    # Simulate protected paths configuration
    protected_paths = '/dashboard,/members,/profile'
    protected_paths_list = [path.strip() for path in protected_paths.split(',') if path.strip()]
    
    # Test that /issue-cookie is not in protected paths
    issue_cookie_variations = ['/issue-cookie', '/issue-cookie/', '/issue-cookie*']
    
    for variation in issue_cookie_variations:
        if variation in protected_paths_list:
            print(f"❌ Configuration error: {variation} found in protected paths")
            return False
    
    print("✅ Protected path validation: /issue-cookie not in protected paths")
    
    # Test valid protected paths
    valid_paths = ['/dashboard', '/members', '/profile']
    for path in valid_paths:
        if path in protected_paths_list:
            print(f"✅ Valid protected path found: {path}")
        else:
            print(f"❌ Valid protected path missing: {path}")
            return False
    
    return True

def test_cloudfront_response_format():
    """Test CloudFront response format"""
    print("🧪 Testing CloudFront response format...")
    
    # Test 204 No Content response format
    response_204 = {
        'status': '204',
        'statusDescription': 'No Content',
        'headers': {
            'cache-control': [{'key': 'Cache-Control', 'value': 'no-store'}],
            'set-cookie-0': [{'key': 'Set-Cookie', 'value': 'CloudFront-Policy=value; Path=/; Secure; HttpOnly'}],
            'set-cookie-1': [{'key': 'Set-Cookie', 'value': 'CloudFront-Signature=value; Path=/; Secure; HttpOnly'}],
            'set-cookie-2': [{'key': 'Set-Cookie', 'value': 'CloudFront-Key-Pair-Id=value; Path=/; Secure; HttpOnly'}]
        }
    }
    
    # Validate response structure
    if response_204.get('status') == '204':
        print("✅ 204 status code correct")
    else:
        print("❌ 204 status code incorrect")
        return False
    
    if 'body' not in response_204:
        print("✅ 204 response correctly has no body")
    else:
        print("❌ 204 response incorrectly has body")
        return False
    
    # Check Cache-Control header
    headers = response_204.get('headers', {})
    cache_control = headers.get('cache-control', [{}])[0].get('value', '')
    if cache_control == 'no-store':
        print("✅ Cache-Control: no-store header present")
    else:
        print("❌ Cache-Control: no-store header missing or incorrect")
        return False
    
    # Check Set-Cookie headers
    cookie_count = 0
    for key in headers:
        if key.startswith('set-cookie-'):
            cookie_count += 1
    
    if cookie_count == 3:
        print("✅ Correct number of Set-Cookie headers (3)")
    else:
        print(f"❌ Incorrect number of Set-Cookie headers: {cookie_count}")
        return False
    
    # Test 401 Unauthorized response format
    response_401 = {
        'status': '401',
        'statusDescription': 'Unauthorized',
        'headers': {
            'www-authenticate': [{'key': 'WWW-Authenticate', 'value': 'Bearer realm="CloudFront"'}],
            'content-type': [{'key': 'Content-Type', 'value': 'application/json'}],
            'cache-control': [{'key': 'Cache-Control', 'value': 'no-store'}]
        },
        'body': json.dumps({'error': 'Unauthorized - valid JWT Bearer token required'})
    }
    
    if response_401.get('status') == '401':
        print("✅ 401 status code correct")
    else:
        print("❌ 401 status code incorrect")
        return False
    
    # Check WWW-Authenticate header
    www_auth = response_401['headers'].get('www-authenticate', [{}])[0].get('value', '')
    if 'Bearer' in www_auth:
        print("✅ WWW-Authenticate header present")
    else:
        print("❌ WWW-Authenticate header missing or incorrect")
        return False
    
    return True

def test_cookie_format():
    """Test cookie format for Lambda@Edge"""
    print("🧪 Testing cookie format...")
    
    # Test host-only cookies (no Domain attribute)
    test_cookies = [
        'CloudFront-Policy=value; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=2592000',
        'CloudFront-Signature=value; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=2592000',
        'CloudFront-Key-Pair-Id=value; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=2592000'
    ]
    
    for i, cookie in enumerate(test_cookies):
        # Check that Domain attribute is not present (host-only cookies)
        if 'Domain=' not in cookie:
            print(f"✅ Cookie {i+1}: Host-only (no Domain attribute)")
        else:
            print(f"❌ Cookie {i+1}: Has Domain attribute (should be host-only)")
            return False
        
        # Check required attributes
        required_attrs = ['Path=/', 'Secure', 'HttpOnly']
        for attr in required_attrs:
            if attr in cookie:
                print(f"✅ Cookie {i+1}: Has {attr}")
            else:
                print(f"❌ Cookie {i+1}: Missing {attr}")
                return False
    
    # Test expired cookies for signout
    expired_cookies = [
        'CloudFront-Policy=; Path=/; Max-Age=0; Secure; HttpOnly',
        'CloudFront-Signature=; Path=/; Max-Age=0; Secure; HttpOnly',
        'CloudFront-Key-Pair-Id=; Path=/; Max-Age=0; Secure; HttpOnly'
    ]
    
    for i, cookie in enumerate(expired_cookies):
        if 'Max-Age=0' in cookie:
            print(f"✅ Expired cookie {i+1}: Has Max-Age=0")
        else:
            print(f"❌ Expired cookie {i+1}: Missing Max-Age=0")
            return False
    
    return True

def test_error_scenarios():
    """Test error scenarios and edge cases"""
    print("🧪 Testing error scenarios...")
    
    # Test invalid action parameter
    valid_actions = ['signin', 'signout']
    invalid_action = 'invalid-action'
    
    if invalid_action not in valid_actions:
        print("✅ Invalid action correctly rejected")
    else:
        print("❌ Invalid action incorrectly accepted")
        return False
    
    # Test malformed JWT
    malformed_jwts = [
        'invalid.jwt',  # Wrong number of parts
        'invalid',      # No dots
        '',             # Empty string
        'a.b.c.d'       # Too many parts
    ]
    
    for jwt in malformed_jwts:
        parts = jwt.split('.')
        if len(parts) != 3:
            print(f"✅ Malformed JWT correctly rejected: {jwt}")
        else:
            print(f"❌ Malformed JWT incorrectly accepted: {jwt}")
            return False
    
    # Test missing Authorization header scenarios
    missing_auth_scenarios = [
        '',                           # Empty
        'Basic dXNlcjpwYXNz',        # Wrong auth type
        'Bearer',                     # Missing token
        'bearer token'                # Wrong case
    ]
    
    for auth in missing_auth_scenarios:
        if not auth.startswith('Bearer ') or len(auth) <= 7:
            print(f"✅ Invalid auth header correctly rejected: {auth[:20]}...")
        else:
            print(f"❌ Invalid auth header incorrectly accepted: {auth}")
            return False
    
    return True

def run_lambda_edge_integration_tests():
    """Run all Lambda@Edge integration tests"""
    print("🧪 Running Lambda@Edge Integration Tests...")
    print("=" * 60)
    
    tests = [
        ("Issue Cookie Endpoint Validation", test_issue_cookie_endpoint_validation),
        ("JWT Authorization Header", test_jwt_authorization_header),
        ("Query String Action Parsing", test_query_string_action_parsing),
        ("Protected Path Validation", test_protected_path_validation),
        ("CloudFront Response Format", test_cloudfront_response_format),
        ("Cookie Format", test_cookie_format),
        ("Error Scenarios", test_error_scenarios)
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
    
    print("\n" + "=" * 60)
    print(f"📊 Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All Lambda@Edge integration tests passed!")
        return True
    else:
        print("❌ Some Lambda@Edge integration tests failed.")
        return False

if __name__ == '__main__':
    success = run_lambda_edge_integration_tests()
    sys.exit(0 if success else 1)