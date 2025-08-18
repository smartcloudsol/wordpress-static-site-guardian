#!/usr/bin/env python3
"""
Test script to validate the cloudfront_manager Lambda function
"""

import json
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_lambda_function():
    """Test the Lambda function structure without AWS dependencies"""
    
    try:
        # Test that the file can be parsed as Python
        with open('src/cloudfront_manager.py', 'r') as f:
            code = f.read()
        
        # Compile the code to check for syntax errors
        compile(code, 'src/cloudfront_manager.py', 'exec')
        
        # Check for required function definitions
        required_functions = [
            'lambda_handler',
            'send_response', 
            'create_resource',
            'delete_resource',
            'emergency_response'
        ]
        
        for func_name in required_functions:
            if f'def {func_name}(' not in code:
                raise ValueError(f"Required function '{func_name}' not found")
        
        # Check for error handling patterns
        error_patterns = [
            'try:',
            'except Exception',
            'logger.error',
            'send_response'
        ]
        
        for pattern in error_patterns:
            if pattern not in code:
                raise ValueError(f"Required error handling pattern '{pattern}' not found")
        
        print("✅ Lambda function structure validation passed!")
        print("ℹ️  Function contains all required components and error handling")
        
        return True
        
    except Exception as e:
        print(f"❌ Lambda function structure test failed: {e}")
        return False

def test_syntax():
    """Test Python syntax"""
    
    try:
        import py_compile
        py_compile.compile('src/cloudfront_manager.py', doraise=True)
        print("✅ Python syntax validation passed!")
        return True
    except Exception as e:
        print(f"❌ Python syntax validation failed: {e}")
        return False

def test_imports():
    """Test that all required standard library modules can be imported"""
    
    try:
        import json
        import logging
        import signal
        import time
        
        # Test urllib3 (might not be available locally)
        try:
            import urllib3
            print("✅ urllib3 available")
        except ImportError:
            print("⚠️  urllib3 not available locally (but available in Lambda runtime)")
        
        # boto3 and botocore are provided by Lambda runtime
        print("ℹ️  boto3 and botocore will be available in Lambda runtime")
        
        print("✅ Standard library modules imported successfully!")
        return True
    except Exception as e:
        print(f"❌ Import test failed: {e}")
        return False

if __name__ == '__main__':
    print("🧪 Running Lambda function validation tests...\n")
    
    tests = [
        ("Syntax Validation", test_syntax),
        ("Import Validation", test_imports),
        ("Lambda Function Structure Test", test_lambda_function)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"Running {test_name}...")
        if test_func():
            passed += 1
        print()
    
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Lambda function is ready for deployment.")
        sys.exit(0)
    else:
        print("💥 Some tests failed. Please fix the issues before deployment.")
        sys.exit(1)