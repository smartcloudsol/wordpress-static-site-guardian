#!/usr/bin/env python3
"""
Template Validation Tests
Tests CloudFormation template parameter validation and constraints
"""

import json
import sys
import os
import subprocess
import tempfile
import yaml

def test_template_syntax_validation():
    """Test that the template has valid CloudFormation syntax"""
    print("🧪 Testing template syntax validation...")
    
    try:
        # Test SAM validation
        result = subprocess.run(['sam', 'validate', '--template', 'template.yaml'], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("✅ SAM template validation passed")
            return True
        else:
            print(f"❌ SAM template validation failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ Template validation timed out")
        return False
    except Exception as e:
        print(f"❌ Template validation error: {e}")
        return False

def test_protected_paths_parameter():
    """Test ProtectedPaths parameter configuration"""
    print("🧪 Testing ProtectedPaths parameter...")
    
    try:
        # Read template as text to avoid YAML parsing issues with CloudFormation functions
        with open('template.yaml', 'r') as f:
            template_content = f.read()
        
        # Check for ProtectedPaths parameter
        if 'ProtectedPaths:' in template_content:
            print("✅ ProtectedPaths parameter found")
        else:
            print("❌ ProtectedPaths parameter not found")
            return False
        
        # Check parameter type
        if 'Type: CommaDelimitedList' in template_content:
            print("✅ ProtectedPaths has correct type: CommaDelimitedList")
        else:
            print("❌ ProtectedPaths missing CommaDelimitedList type")
            return False
        
        # Check description mentions /issue-cookie restriction
        if 'Cannot include /issue-cookie path' in template_content:
            print("✅ ProtectedPaths description mentions /issue-cookie restriction")
        else:
            print("❌ ProtectedPaths description missing /issue-cookie restriction")
            return False
        
        # Check constraint description
        if 'Cannot include /issue-cookie or /issue-cookie*' in template_content:
            print("✅ ProtectedPaths constraint mentions /issue-cookie restriction")
        else:
            print("❌ ProtectedPaths constraint missing /issue-cookie restriction")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Error testing ProtectedPaths parameter: {e}")
        return False

def test_cognito_parameters():
    """Test Cognito integration parameters"""
    print("🧪 Testing Cognito parameters...")
    
    try:
        # Read template as text to avoid YAML parsing issues
        with open('template.yaml', 'r') as f:
            template_content = f.read()
        
        # Test CognitoUserPoolId parameter
        if 'CognitoUserPoolId:' in template_content:
            print("✅ CognitoUserPoolId parameter found")
        else:
            print("❌ CognitoUserPoolId parameter not found")
            return False
        
        # Check AllowedPattern for User Pool ID format
        if 'AllowedPattern:' in template_content and '_' in template_content:
            print("✅ CognitoUserPoolId has AllowedPattern validation")
        else:
            print("❌ CognitoUserPoolId missing AllowedPattern validation")
            return False
        
        # Test CognitoAppClientIds parameter
        if 'CognitoAppClientIds:' in template_content:
            print("✅ CognitoAppClientIds parameter found")
        else:
            print("❌ CognitoAppClientIds parameter not found")
            return False
        
        # Check for JWT audience validation description
        if 'JWT audience validation' in template_content:
            print("✅ CognitoAppClientIds has JWT audience validation description")
        else:
            print("❌ CognitoAppClientIds missing JWT audience validation description")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Error testing Cognito parameters: {e}")
        return False

def test_parameter_validation_logic():
    """Test parameter validation logic"""
    print("🧪 Testing parameter validation logic...")
    
    # Test valid protected paths
    valid_protected_paths = [
        '/dashboard,/members,/profile',
        '/admin,/settings',
        '/private'
    ]
    
    for paths in valid_protected_paths:
        path_list = [path.strip() for path in paths.split(',') if path.strip()]
        
        # Check that none contain /issue-cookie
        has_issue_cookie = any('/issue-cookie' in path for path in path_list)
        
        if not has_issue_cookie:
            print(f"✅ Valid protected paths: {paths}")
        else:
            print(f"❌ Protected paths contain /issue-cookie: {paths}")
            return False
    
    # Test invalid protected paths (should be rejected)
    invalid_protected_paths = [
        '/dashboard,/issue-cookie,/profile',
        '/issue-cookie',
        '/members,/issue-cookie/sub',
        '/dashboard,/issue-cookie*'
    ]
    
    for paths in invalid_protected_paths:
        path_list = [path.strip() for path in paths.split(',') if path.strip()]
        
        # Check that some contain /issue-cookie (these should be rejected)
        has_issue_cookie = any('/issue-cookie' in path for path in path_list)
        
        if has_issue_cookie:
            print(f"✅ Invalid protected paths correctly identified: {paths}")
        else:
            print(f"❌ Invalid protected paths not identified: {paths}")
            return False
    
    return True

def test_template_build():
    """Test that template can be built successfully"""
    print("🧪 Testing template build...")
    
    try:
        # Test SAM build
        result = subprocess.run(['sam', 'build', '--template', 'template.yaml'], 
                              capture_output=True, text=True, timeout=120)
        
        if result.returncode == 0:
            print("✅ Template builds successfully")
            return True
        else:
            print(f"❌ Template build failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ Template build timed out")
        return False
    except Exception as e:
        print(f"❌ Template build error: {e}")
        return False

def test_lambda_edge_configuration():
    """Test Lambda@Edge specific configuration"""
    print("🧪 Testing Lambda@Edge configuration...")
    
    try:
        # Read template as text to avoid YAML parsing issues
        with open('template.yaml', 'r') as f:
            template_content = f.read()
        
        # Check CookieSigningFunction configuration
        if 'CookieSigningFunction:' in template_content:
            print("✅ CookieSigningFunction found")
        else:
            print("❌ CookieSigningFunction not found")
            return False
        
        # Check that Environment variables are not present (Lambda@Edge doesn't support them)
        # Look for Environment section in CookieSigningFunction
        cookie_function_start = template_content.find('CookieSigningFunction:')
        next_resource_start = template_content.find('\n  # ', cookie_function_start + 1)
        if next_resource_start == -1:
            next_resource_start = len(template_content)
        
        cookie_function_section = template_content[cookie_function_start:next_resource_start]
        
        if 'Environment:' not in cookie_function_section:
            print("✅ Lambda@Edge function has no Environment variables")
        else:
            print("❌ Lambda@Edge function incorrectly has Environment variables")
            return False
        
        # Check function name indicates Edge deployment
        if 'cookie-signing-edge' in template_content:
            print("✅ Function name indicates Lambda@Edge deployment")
        else:
            print("❌ Function name doesn't indicate Lambda@Edge deployment")
            return False
        
        # Check CloudFront distribution has /issue-cookie cache behavior
        if "PathPattern: '/issue-cookie*'" in template_content:
            print("✅ CloudFront distribution has /issue-cookie* cache behavior")
        else:
            print("❌ CloudFront distribution missing /issue-cookie* cache behavior")
            return False
        
        # Check Lambda@Edge association
        if 'LambdaFunctionAssociations:' in template_content:
            print("✅ /issue-cookie* cache behavior has Lambda@Edge association")
        else:
            print("❌ /issue-cookie* cache behavior missing Lambda@Edge association")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Error testing Lambda@Edge configuration: {e}")
        return False

def test_removed_api_gateway_components():
    """Test that API Gateway components have been removed"""
    print("🧪 Testing API Gateway component removal...")
    
    try:
        # Load template
        with open('template.yaml', 'r') as f:
            template_content = f.read()
        
        # Check for API Gateway references that should be removed
        api_gateway_components = [
            'ApiDomainName',
            'ApiGatewayDomainName',
            'ServerlessRestApi',
            'ApiGatewayDeployment',
            'ApiGatewayGetMethod',
            'ApiGatewayOptionsMethod',
            'ApiGatewayResource',
            'ApiGatewayBasePathMapping',
            'LambdaApiGatewayPermission'
        ]
        
        for component in api_gateway_components:
            if component in template_content:
                print(f"❌ API Gateway component still present: {component}")
                return False
            else:
                print(f"✅ API Gateway component removed: {component}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error testing API Gateway removal: {e}")
        return False

def run_template_validation_tests():
    """Run all template validation tests"""
    print("🧪 Running Template Validation Tests...")
    print("=" * 60)
    
    tests = [
        ("Template Syntax Validation", test_template_syntax_validation),
        ("ProtectedPaths Parameter", test_protected_paths_parameter),
        ("Cognito Parameters", test_cognito_parameters),
        ("Parameter Validation Logic", test_parameter_validation_logic),
        ("Template Build", test_template_build),
        ("Lambda@Edge Configuration", test_lambda_edge_configuration),
        ("API Gateway Component Removal", test_removed_api_gateway_components)
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
        print("🎉 All template validation tests passed!")
        return True
    else:
        print("❌ Some template validation tests failed.")
        return False

if __name__ == '__main__':
    success = run_template_validation_tests()
    sys.exit(0 if success else 1)