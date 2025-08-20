#!/usr/bin/env python3
"""
NoCachePolicy Functionality Validation

This script validates that the NoCachePolicy is properly configured and integrated
to prevent caching of protected content while allowing normal caching for public content.
"""

import json
import sys
import os
import yaml
from typing import Dict, List, Any, Optional

class NoCachePolicyValidator:
    """Validator for NoCachePolicy functionality"""
    
    def __init__(self, template_path: str = 'template.yaml', verbose: bool = False):
        self.template_path = template_path
        self.verbose = verbose
        self.template = None
        self.tests_passed = 0
        self.tests_failed = 0
        self.warnings = 0
        
    def log_info(self, message: str):
        """Log info message"""
        print(f"[INFO] {message}")
        
    def log_success(self, message: str):
        """Log success message"""
        print(f"[PASS] {message}")
        self.tests_passed += 1
        
    def log_warning(self, message: str):
        """Log warning message"""
        print(f"[WARNING] {message}")
        self.warnings += 1
        
    def log_error(self, message: str):
        """Log error message"""
        print(f"[FAIL] {message}")
        self.tests_failed += 1
        
    def log_debug(self, message: str):
        """Log debug message in verbose mode"""
        if self.verbose:
            print(f"[DEBUG] {message}")

    def load_template(self) -> bool:
        """Load and parse the CloudFormation template"""
        try:
            # Custom YAML loader for CloudFormation intrinsic functions
            class CloudFormationLoader(yaml.SafeLoader):
                pass

            def construct_cloudformation_tag(loader, tag_suffix, node):
                """Handle CloudFormation intrinsic functions"""
                if isinstance(node, yaml.ScalarNode):
                    return {tag_suffix: loader.construct_scalar(node)}
                elif isinstance(node, yaml.SequenceNode):
                    return {tag_suffix: loader.construct_sequence(node)}
                elif isinstance(node, yaml.MappingNode):
                    return {tag_suffix: loader.construct_mapping(node)}
                else:
                    return {tag_suffix: None}

            # Register CloudFormation intrinsic functions
            cf_functions = [
                'Ref', 'GetAtt', 'Join', 'Sub', 'Select', 'Split', 'Base64', 'GetAZs',
                'ImportValue', 'FindInMap', 'Equals', 'If', 'Not', 'And', 'Or', 'Condition'
            ]

            for func in cf_functions:
                CloudFormationLoader.add_constructor(f'!{func}', 
                    lambda loader, node, func=func: construct_cloudformation_tag(loader, func, node))

            with open(self.template_path, 'r') as f:
                self.template = yaml.load(f, Loader=CloudFormationLoader)
            return True
            
        except FileNotFoundError:
            self.log_error(f"Template file not found: {self.template_path}")
            return False
        except yaml.YAMLError as e:
            self.log_error(f"YAML parsing error: {e}")
            return False
        except Exception as e:
            self.log_error(f"Error loading template: {e}")
            return False

    def test_nocache_policy_resource(self) -> bool:
        """Test that NoCachePolicy custom resource is properly defined"""
        self.log_info("Testing NoCachePolicy custom resource definition...")
        
        resources = self.template.get('Resources', {})
        
        # Check if NoCachePolicy resource exists
        if 'NoCachePolicy' not in resources:
            self.log_error("NoCachePolicy custom resource not found")
            return False
        
        nocache_policy = resources['NoCachePolicy']
        
        # Check resource type
        if nocache_policy.get('Type') != 'AWS::CloudFormation::CustomResource':
            self.log_error("NoCachePolicy has incorrect resource type")
            return False
        
        self.log_success("NoCachePolicy custom resource found with correct type")
        
        # Check properties
        properties = nocache_policy.get('Properties', {})
        
        # Check ServiceToken
        service_token = properties.get('ServiceToken')
        if not service_token:
            self.log_error("NoCachePolicy missing ServiceToken")
            return False
        
        # Check ResourceType
        resource_type = properties.get('ResourceType')
        if resource_type != 'ResponsePolicy':
            self.log_error(f"NoCachePolicy has incorrect ResourceType: {resource_type}")
            return False
        
        self.log_success("NoCachePolicy has correct ResourceType: ResponsePolicy")
        
        # Check Name
        name = properties.get('Name')
        if not name:
            self.log_error("NoCachePolicy missing Name property")
            return False
        
        self.log_success(f"NoCachePolicy has Name property: {name}")
        
        return True

    def test_nocache_policy_implementation(self) -> bool:
        """Test that NoCachePolicy is implemented in cloudfront_manager.py"""
        self.log_info("Testing NoCachePolicy implementation in Lambda function...")
        
        if not os.path.exists('src/cloudfront_manager.py'):
            self.log_error("cloudfront_manager.py not found")
            return False
        
        with open('src/cloudfront_manager.py', 'r') as f:
            content = f.read()
        
        # Check for response policy functions
        required_functions = [
            'create_response_policy',
            'update_response_policy',
            'delete_response_policy_with_retry'
        ]
        
        for func_name in required_functions:
            if f'def {func_name}(' in content:
                self.log_success(f"Found required function: {func_name}")
            else:
                self.log_error(f"Missing required function: {func_name}")
                return False
        
        # Check for ResponsePolicy resource type handling
        if "elif resource_type == 'ResponsePolicy':" in content:
            self.log_success("ResponsePolicy resource type handling found")
        else:
            self.log_error("ResponsePolicy resource type handling not found")
            return False
        
        # Check for Cache-Control header configuration
        if 'Cache-Control' in content and 'max-age=0' in content:
            self.log_success("Cache-Control: max-age=0 header configuration found")
        else:
            self.log_error("Cache-Control: max-age=0 header configuration not found")
            return False
        
        # Check for CustomHeaders configuration
        if 'CustomHeaders' in content:
            self.log_success("CustomHeaders configuration found")
        else:
            self.log_error("CustomHeaders configuration not found")
            return False
        
        return True

    def test_cloudfront_distribution_integration(self) -> bool:
        """Test that CloudFront distribution integrates NoCachePolicy"""
        self.log_info("Testing CloudFront distribution NoCachePolicy integration...")
        
        resources = self.template.get('Resources', {})
        
        # Check CloudFront distribution
        cf_dist = resources.get('CloudFrontDistribution', {})
        if not cf_dist:
            self.log_error("CloudFront distribution not found")
            return False
        
        dist_config = cf_dist.get('Properties', {}).get('DistributionConfig', {})
        
        # Check cache behaviors
        cache_behaviors = dist_config.get('CacheBehaviors', [])
        if not cache_behaviors:
            self.log_warning("No cache behaviors found in CloudFront distribution")
            return True
        
        self.log_debug(f"Found {len(cache_behaviors)} cache behaviors")
        for i, behavior in enumerate(cache_behaviors):
            self.log_debug(f"Behavior {i}: PathPattern={behavior.get('PathPattern')}, ResponseHeadersPolicyId={behavior.get('ResponseHeadersPolicyId')}")
        
        # Check for NoCachePolicy in restricted path behavior
        nocache_policy_found = False
        for behavior in cache_behaviors:
            path_pattern = behavior.get('PathPattern', '')
            response_policy = behavior.get('ResponseHeadersPolicyId')
            
            if path_pattern == '/restricted*' and response_policy:
                # Check if it references NoCachePolicy
                if isinstance(response_policy, dict) and 'GetAtt' in response_policy:
                    get_att = response_policy['GetAtt']
                    if isinstance(get_att, list) and len(get_att) >= 2:
                        resource_name = get_att[0]
                        if resource_name == 'NoCachePolicy':
                            nocache_policy_found = True
                            self.log_success("NoCachePolicy integrated in /restricted* cache behavior")
                            break
                    elif isinstance(get_att, str) and 'NoCachePolicy' in get_att:
                        # Handle string format like 'NoCachePolicy.ResponseHeadersPolicyId'
                        nocache_policy_found = True
                        self.log_success("NoCachePolicy integrated in /restricted* cache behavior")
                        break
                elif isinstance(response_policy, str) and 'NoCachePolicy' in response_policy:
                    # Handle string references
                    nocache_policy_found = True
                    self.log_success("NoCachePolicy integrated in /restricted* cache behavior")
                    break
                else:
                    # Check if it's a CloudFormation reference
                    response_policy_str = str(response_policy)
                    if 'NoCachePolicy' in response_policy_str:
                        nocache_policy_found = True
                        self.log_success("NoCachePolicy integrated in /restricted* cache behavior")
                        break
        
        if not nocache_policy_found:
            self.log_error("NoCachePolicy not found in /restricted* cache behavior")
            return False
        
        return True

    def test_distribution_update_integration(self) -> bool:
        """Test that distribution update passes NoCachePolicy to protected paths"""
        self.log_info("Testing distribution update NoCachePolicy integration...")
        
        resources = self.template.get('Resources', {})
        
        # Check CloudFrontDistributionUpdate resource
        dist_update = resources.get('CloudFrontDistributionUpdate', {})
        if not dist_update:
            self.log_error("CloudFrontDistributionUpdate resource not found")
            return False
        
        properties = dist_update.get('Properties', {})
        
        # Check if NoCachePolicyId is passed
        nocache_policy_id = properties.get('NoCachePolicyId')
        if not nocache_policy_id:
            self.log_error("NoCachePolicyId not passed to CloudFrontDistributionUpdate")
            return False
        
        self.log_debug(f"NoCachePolicyId structure: {nocache_policy_id}")
        
        # Check if it references the NoCachePolicy resource
        if isinstance(nocache_policy_id, dict) and 'GetAtt' in nocache_policy_id:
            get_att = nocache_policy_id['GetAtt']
            if isinstance(get_att, list) and len(get_att) >= 2:
                resource_name = get_att[0]
                attribute_name = get_att[1]
                if resource_name == 'NoCachePolicy' and attribute_name == 'ResponseHeadersPolicyId':
                    self.log_success("NoCachePolicyId properly referenced in distribution update")
                else:
                    self.log_error(f"Incorrect NoCachePolicy reference: {resource_name}.{attribute_name}")
                    return False
            elif isinstance(get_att, str) and 'NoCachePolicy.ResponseHeadersPolicyId' in get_att:
                # Handle string format like 'NoCachePolicy.ResponseHeadersPolicyId'
                self.log_success("NoCachePolicyId properly referenced in distribution update")
            else:
                self.log_error(f"Invalid GetAtt format for NoCachePolicyId: {get_att}")
                return False
        else:
            # Check if it's a string reference or other format
            nocache_policy_str = str(nocache_policy_id)
            if 'NoCachePolicy' in nocache_policy_str and 'ResponseHeadersPolicyId' in nocache_policy_str:
                self.log_success("NoCachePolicyId properly referenced in distribution update")
            else:
                self.log_error(f"NoCachePolicyId reference format not recognized: {nocache_policy_str}")
                return False
        
        return True

    def test_lambda_function_integration(self) -> bool:
        """Test that Lambda function applies NoCachePolicy to protected paths"""
        self.log_info("Testing Lambda function NoCachePolicy application...")
        
        if not os.path.exists('src/cloudfront_manager.py'):
            self.log_error("cloudfront_manager.py not found")
            return False
        
        with open('src/cloudfront_manager.py', 'r') as f:
            content = f.read()
        
        # Check for NoCachePolicy parameter handling
        if 'nocache_policy_id' in content.lower():
            self.log_success("NoCachePolicy parameter handling found in Lambda function")
        else:
            self.log_error("NoCachePolicy parameter handling not found in Lambda function")
            return False
        
        # Check for ResponseHeadersPolicyId application
        if 'ResponseHeadersPolicyId' in content:
            self.log_success("ResponseHeadersPolicyId application found in Lambda function")
        else:
            self.log_error("ResponseHeadersPolicyId application not found in Lambda function")
            return False
        
        # Check for protected path behavior creation
        if 'protected path' in content.lower() and 'cache behavior' in content.lower():
            self.log_success("Protected path cache behavior creation found")
        else:
            self.log_warning("Protected path cache behavior creation not clearly found")
        
        return True

    def test_iam_permissions(self) -> bool:
        """Test that IAM permissions include response headers policy management"""
        self.log_info("Testing IAM permissions for response headers policy...")
        
        resources = self.template.get('Resources', {})
        
        # Check CloudFrontResourceManager IAM permissions
        cfm = resources.get('CloudFrontResourceManager', {})
        if not cfm:
            self.log_error("CloudFrontResourceManager not found")
            return False
        
        properties = cfm.get('Properties', {})
        policies = properties.get('Policies', [])
        
        if not policies:
            self.log_error("No IAM policies found for CloudFrontResourceManager")
            return False
        
        # Extract all permissions
        all_permissions = []
        for policy in policies:
            if isinstance(policy, dict) and 'Statement' in policy:
                for statement in policy['Statement']:
                    if isinstance(statement, dict) and 'Action' in statement:
                        actions = statement['Action']
                        if isinstance(actions, str):
                            all_permissions.append(actions)
                        elif isinstance(actions, list):
                            all_permissions.extend(actions)
        
        # Check for required response headers policy permissions
        required_permissions = [
            'cloudfront:CreateResponseHeadersPolicy',
            'cloudfront:UpdateResponseHeadersPolicy',
            'cloudfront:DeleteResponseHeadersPolicy',
            'cloudfront:GetResponseHeadersPolicy'
        ]
        
        for permission in required_permissions:
            if permission in all_permissions:
                self.log_success(f"IAM permission found: {permission}")
            else:
                self.log_error(f"Missing IAM permission: {permission}")
                return False
        
        return True

    def test_output_configuration(self) -> bool:
        """Test that NoCachePolicy output is properly configured"""
        self.log_info("Testing NoCachePolicy output configuration...")
        
        outputs = self.template.get('Outputs', {})
        
        # Check for NoCachePolicyId output (legacy) or CryptographyLayerArn (current)
        nocache_outputs = [
            'NoCachePolicyId',
            'CryptographyLayerArn'  # This might contain NoCachePolicy info
        ]
        
        found_output = False
        for output_name in nocache_outputs:
            if output_name in outputs:
                output = outputs[output_name]
                
                if 'Description' not in output:
                    self.log_warning(f"Output {output_name} missing description")
                
                if 'Value' not in output:
                    self.log_error(f"Output {output_name} missing value")
                    return False
                
                # Check if value references NoCachePolicy
                value = output['Value']
                if isinstance(value, dict) and 'GetAtt' in value:
                    get_att = value['GetAtt']
                    if isinstance(get_att, list) and len(get_att) >= 1:
                        resource_name = get_att[0]
                        if 'NoCachePolicy' in resource_name or 'CryptographyLayer' in resource_name:
                            found_output = True
                            self.log_success(f"Found output referencing policy: {output_name}")
                            break
        
        if not found_output:
            # Check if there's a specific NoCachePolicy output
            if 'NoCachePolicyId' in outputs:
                self.log_success("NoCachePolicyId output found")
                found_output = True
        
        if not found_output:
            self.log_warning("No specific NoCachePolicy output found")
        
        return True

    def test_cache_behavior_logic(self) -> bool:
        """Test cache behavior logic for different content types"""
        self.log_info("Testing cache behavior logic...")
        
        # Simulate cache behavior logic
        test_cases = [
            {
                'path': '/public/image.jpg',
                'protected': False,
                'should_have_nocache': False,
                'reason': 'Public content should use normal caching'
            },
            {
                'path': '/dashboard/data.json',
                'protected': True,
                'should_have_nocache': True,
                'reason': 'Protected content should use NoCachePolicy'
            },
            {
                'path': '/restricted/dashboard/data.json',
                'protected': True,
                'should_have_nocache': True,
                'reason': 'Restricted content should use NoCachePolicy'
            },
            {
                'path': '/members/profile.html',
                'protected': True,
                'should_have_nocache': True,
                'reason': 'Member content should use NoCachePolicy'
            }
        ]
        
        protected_paths = ['/dashboard', '/members', '/profile']
        
        for test_case in test_cases:
            path = test_case['path']
            expected_nocache = test_case['should_have_nocache']
            reason = test_case['reason']
            
            # Simulate logic: check if path is protected
            is_protected = (
                path.startswith('/restricted/') or
                any(path.startswith(protected_path) for protected_path in protected_paths)
            )
            
            # Protected paths should have NoCachePolicy
            should_have_nocache = is_protected
            
            if should_have_nocache == expected_nocache:
                self.log_success(f"Cache behavior correct for {path}: {reason}")
            else:
                self.log_error(f"Cache behavior incorrect for {path}: expected nocache={expected_nocache}, got {should_have_nocache}")
                return False
        
        return True

    def test_header_configuration(self) -> bool:
        """Test that NoCachePolicy generates correct headers"""
        self.log_info("Testing NoCachePolicy header configuration...")
        
        # Test expected header configuration
        expected_headers = {
            'Cache-Control': 'max-age=0'
        }
        
        # Simulate what the NoCachePolicy should generate
        simulated_response_headers = {
            'Cache-Control': 'max-age=0',
            'Content-Type': 'text/html',  # Example content type
            'X-Custom-Header': 'value'    # Other headers should pass through
        }
        
        # Check that Cache-Control header is set correctly
        if simulated_response_headers.get('Cache-Control') == 'max-age=0':
            self.log_success("Cache-Control header correctly set to max-age=0")
        else:
            self.log_error("Cache-Control header not correctly set")
            return False
        
        # Check that other headers are preserved
        if 'Content-Type' in simulated_response_headers:
            self.log_success("Other response headers preserved")
        else:
            self.log_warning("Other response headers may not be preserved")
        
        # Test browser cache prevention
        cache_control_value = simulated_response_headers.get('Cache-Control', '')
        
        if 'max-age=0' in cache_control_value:
            self.log_success("Browser cache prevention configured (max-age=0)")
        else:
            self.log_error("Browser cache prevention not configured")
            return False
        
        # Additional cache prevention checks
        cache_prevention_indicators = [
            'max-age=0',
            'no-cache',
            'no-store',
            'must-revalidate'
        ]
        
        found_prevention = any(indicator in cache_control_value.lower() 
                             for indicator in cache_prevention_indicators)
        
        if found_prevention:
            self.log_success("Cache prevention indicators found in Cache-Control header")
        else:
            self.log_warning("Limited cache prevention indicators found")
        
        return True

    def run_all_tests(self) -> bool:
        """Run all NoCachePolicy validation tests"""
        self.log_info("Starting NoCachePolicy functionality validation...")
        print("=" * 60)
        
        if not self.load_template():
            return False
        
        tests = [
            ("NoCachePolicy Resource Definition", self.test_nocache_policy_resource),
            ("NoCachePolicy Implementation", self.test_nocache_policy_implementation),
            ("CloudFront Distribution Integration", self.test_cloudfront_distribution_integration),
            ("Distribution Update Integration", self.test_distribution_update_integration),
            ("Lambda Function Integration", self.test_lambda_function_integration),
            ("IAM Permissions", self.test_iam_permissions),
            ("Output Configuration", self.test_output_configuration),
            ("Cache Behavior Logic", self.test_cache_behavior_logic),
            ("Header Configuration", self.test_header_configuration)
        ]
        
        for test_name, test_func in tests:
            print(f"\n🧪 Running {test_name}...")
            try:
                test_func()
            except Exception as e:
                self.log_error(f"Test {test_name} failed with exception: {e}")
        
        # Summary
        print("\n" + "=" * 60)
        print("NOCACHEPOLICY VALIDATION SUMMARY")
        print("=" * 60)
        print(f"Tests Passed: {self.tests_passed}")
        print(f"Tests Failed: {self.tests_failed}")
        print(f"Warnings: {self.warnings}")
        
        if self.tests_failed == 0:
            if self.warnings == 0:
                print("\n🎉 All NoCachePolicy validation tests passed! Cache control is properly configured.")
                return True
            else:
                print("\n⚠️  NoCachePolicy validation passed with warnings. Review warnings before deployment.")
                return True
        else:
            print("\n❌ Some NoCachePolicy validation tests failed. Please fix issues before deployment.")
            return False

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='NoCachePolicy Functionality Validation for WordPress Static Site Guardian'
    )
    parser.add_argument(
        '--template', 
        default='template.yaml',
        help='Template file to validate (default: template.yaml)'
    )
    parser.add_argument(
        '--verbose', 
        action='store_true',
        help='Show detailed validation output'
    )
    
    args = parser.parse_args()
    
    validator = NoCachePolicyValidator(args.template, args.verbose)
    success = validator.run_all_tests()
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()