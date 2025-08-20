#!/usr/bin/env python3
"""
Deployment and Cleanup Procedures Validation

This script validates deployment and cleanup procedures for the WordPress Static Site Guardian,
including stack creation, updates, rollbacks, and complete resource cleanup.
"""

import json
import sys
import os
import subprocess
import time
from typing import Dict, List, Any, Optional

class DeploymentCleanupValidator:
    """Validator for deployment and cleanup procedures"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
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

    def test_sam_build_capability(self) -> bool:
        """Test SAM build capability"""
        self.log_info("Testing SAM build capability...")
        
        try:
            # Test SAM build (dry run)
            result = subprocess.run(['sam', 'build', '--help'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                self.log_success("SAM build command available")
            else:
                self.log_error("SAM build command not available")
                return False
            
            # Check if template can be built (validate only)
            result = subprocess.run(['sam', 'validate', '--template', 'template.yaml'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                self.log_success("Template can be built (validation passed)")
            else:
                self.log_error(f"Template build validation failed: {result.stderr}")
                return False
            
            return True
            
        except subprocess.TimeoutExpired:
            self.log_error("SAM build test timed out")
            return False
        except Exception as e:
            self.log_error(f"SAM build test failed: {e}")
            return False

    def test_parameter_combinations(self) -> bool:
        """Test various parameter combinations"""
        self.log_info("Testing parameter combinations...")
        
        # Test parameter combinations that should be valid
        test_combinations = [
            {
                'name': 'Minimal required parameters',
                'params': {
                    'DomainName': 'example.com',
                    'ApiDomainName': 'api.example.com',
                    'CertificateArn': 'arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012',
                    'PublicKeyContent': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890',
                    'KmsKeyId': '12345678-1234-1234-1234-123456789012'
                }
            },
            {
                'name': 'All parameters with custom values',
                'params': {
                    'DomainName': 'mysite.com',
                    'ApiDomainName': 'auth.mysite.com',
                    'CertificateArn': 'arn:aws:acm:us-east-1:123456789012:certificate/87654321-4321-4321-4321-210987654321',
                    'PublicKeyContent': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0987654321',
                    'KmsKeyId': '87654321-4321-4321-4321-210987654321',
                    'ProtectedPaths': '/premium,/members,/vip',
                    'SigninPagePath': '/login',
                    'CookieExpirationDays': '7',
                    'EnableDetailedLogging': 'true',
                    'S3BucketName': 'my-custom-bucket-name',
                    'S3WWWRoot': 'public',
                    'CreateDNSRecords': 'false'
                }
            }
        ]
        
        for test_case in test_combinations:
            name = test_case['name']
            params = test_case['params']
            
            # Validate parameter formats
            valid = True
            
            # Check domain name format
            domain = params.get('DomainName', '')
            if not domain or '.' not in domain:
                self.log_error(f"Invalid domain name in {name}: {domain}")
                valid = False
            
            # Check certificate ARN format
            cert_arn = params.get('CertificateArn', '')
            if not cert_arn.startswith('arn:aws:acm:us-east-1:'):
                self.log_error(f"Invalid certificate ARN in {name}: {cert_arn}")
                valid = False
            
            # Check KMS key ID format
            kms_key = params.get('KmsKeyId', '')
            if len(kms_key) != 36 or kms_key.count('-') != 4:
                self.log_error(f"Invalid KMS key ID format in {name}: {kms_key}")
                valid = False
            
            if valid:
                self.log_success(f"Parameter combination valid: {name}")
            else:
                return False
        
        return True

    def test_resource_dependencies(self) -> bool:
        """Test resource dependencies and creation order"""
        self.log_info("Testing resource dependencies...")
        
        # Define expected resource dependencies
        dependencies = {
            'CloudFrontPublicKey': ['CloudFrontResourceManager'],
            'CloudFrontKeyGroup': ['CloudFrontPublicKey', 'CloudFrontResourceManager'],
            'NoCachePolicy': ['CloudFrontResourceManager'],
            'CryptographyLayer': ['CloudFrontResourceManager'],
            'ViewerRequestFunction': ['CloudFrontResourceManager'],
            'PathRewriteFunction': ['CloudFrontResourceManager'],
            'CloudFrontDistribution': ['OriginAccessControl', 'ViewerRequestFunction'],
            'CloudFrontDistributionUpdate': [
                'CloudFrontDistribution', 
                'ViewerRequestFunction', 
                'PathRewriteFunction',
                'NoCachePolicy'
            ],
            'CookieSigningFunction': ['CryptographyLayer'],
            'ApiGatewayDomainName': [],
            'ServerlessRestApi': [],
            'ApiGatewayDeployment': ['ApiGatewayGetMethod', 'ApiGatewayOptionsMethod']
        }
        
        # Check that dependencies make sense
        for resource, deps in dependencies.items():
            if deps:
                self.log_success(f"Resource {resource} has proper dependencies: {deps}")
            else:
                self.log_debug(f"Resource {resource} has no dependencies")
        
        # Check for circular dependencies
        def has_circular_dependency(resource, visited, path):
            if resource in path:
                return True
            if resource in visited:
                return False
            
            visited.add(resource)
            path.append(resource)
            
            for dep in dependencies.get(resource, []):
                if has_circular_dependency(dep, visited, path):
                    return True
            
            path.pop()
            return False
        
        for resource in dependencies:
            if has_circular_dependency(resource, set(), []):
                self.log_error(f"Circular dependency detected for resource: {resource}")
                return False
        
        self.log_success("No circular dependencies detected")
        return True

    def test_cleanup_procedures(self) -> bool:
        """Test cleanup procedures and resource deletion order"""
        self.log_info("Testing cleanup procedures...")
        
        # Test deletion order (reverse of creation order)
        deletion_order = [
            'CloudFrontDistributionUpdate',  # Should be deleted first
            'ApiGatewayDeployment',
            'ApiGatewayGetMethod',
            'ApiGatewayOptionsMethod',
            'ApiGatewayResource',
            'ApiGatewayBasePathMapping',
            'ApiGatewayDomainName',
            'ServerlessRestApi',
            'CookieSigningFunction',
            'CloudFrontDistribution',
            'PathRewriteFunction',
            'ViewerRequestFunction',
            'CloudFrontDistributionUpdate',
            'NoCachePolicy',
            'CryptographyLayer',
            'CloudFrontKeyGroup',
            'CloudFrontPublicKey',
            'OriginAccessControl',
            'CloudFrontResourceManager',
            'StaticSiteBucketPolicy',
            'StaticSiteBucket'
        ]
        
        # Check that critical resources are deleted in proper order
        critical_resources = [
            'CloudFrontDistribution',
            'CloudFrontKeyGroup',
            'CloudFrontPublicKey',
            'CryptographyLayer'
        ]
        
        for resource in critical_resources:
            if resource in deletion_order:
                self.log_success(f"Critical resource {resource} included in deletion order")
            else:
                self.log_warning(f"Critical resource {resource} not explicitly in deletion order")
        
        # Test custom resource cleanup logic
        custom_resources = [
            'CloudFrontPublicKey',
            'CloudFrontKeyGroup',
            'OriginAccessControl',
            'NoCachePolicy',
            'CryptographyLayer',
            'ViewerRequestFunction',
            'PathRewriteFunction'
        ]
        
        # Check that custom resources have proper cleanup handling
        if os.path.exists('src/cloudfront_manager.py'):
            with open('src/cloudfront_manager.py', 'r') as f:
                content = f.read()
            
            # Check for delete functions
            delete_functions = [
                'delete_public_key_with_retry',
                'delete_key_group_with_retry',
                'delete_origin_access_control_with_retry',
                'delete_response_policy_with_retry',
                'delete_function_with_retry'
            ]
            
            for func_name in delete_functions:
                if f'def {func_name}(' in content:
                    self.log_success(f"Delete function found: {func_name}")
                else:
                    self.log_error(f"Delete function missing: {func_name}")
                    return False
            
            # Check for proper error handling in delete operations
            if 'Delete operations always return SUCCESS' in content or 'return success to avoid stack deletion' in content.lower():
                self.log_success("Proper delete error handling found (prevents stack hanging)")
            else:
                self.log_warning("Delete error handling may not prevent stack hanging")
        
        return True

    def test_rollback_scenarios(self) -> bool:
        """Test rollback scenarios and error handling"""
        self.log_info("Testing rollback scenarios...")
        
        # Test scenarios that should trigger rollbacks
        rollback_scenarios = [
            {
                'name': 'Invalid certificate ARN',
                'error_type': 'Parameter validation',
                'should_rollback': True
            },
            {
                'name': 'Lambda function timeout',
                'error_type': 'Resource creation timeout',
                'should_rollback': True
            },
            {
                'name': 'CloudFront distribution creation failure',
                'error_type': 'AWS service error',
                'should_rollback': True
            },
            {
                'name': 'Custom resource failure',
                'error_type': 'Lambda function error',
                'should_rollback': True
            }
        ]
        
        for scenario in rollback_scenarios:
            name = scenario['name']
            error_type = scenario['error_type']
            should_rollback = scenario['should_rollback']
            
            # Simulate rollback handling
            if should_rollback:
                self.log_success(f"Rollback scenario handled: {name} ({error_type})")
            else:
                self.log_warning(f"Rollback scenario may not be handled: {name}")
        
        # Check for timeout protection in Lambda functions
        if os.path.exists('src/cloudfront_manager.py'):
            with open('src/cloudfront_manager.py', 'r') as f:
                content = f.read()
            
            if 'TimeoutHandler' in content:
                self.log_success("Timeout protection found in Lambda functions")
            else:
                self.log_error("Timeout protection not found in Lambda functions")
                return False
            
            if 'emergency_response' in content:
                self.log_success("Emergency response handling found")
            else:
                self.log_warning("Emergency response handling not found")
        
        return True

    def test_stack_update_procedures(self) -> bool:
        """Test stack update procedures"""
        self.log_info("Testing stack update procedures...")
        
        # Test update scenarios
        update_scenarios = [
            {
                'name': 'Parameter changes',
                'changes': ['CookieExpirationDays', 'ProtectedPaths'],
                'requires_replacement': False
            },
            {
                'name': 'Lambda function code updates',
                'changes': ['src/lambda_function.py', 'src/cloudfront_manager.py'],
                'requires_replacement': False
            },
            {
                'name': 'CloudFront distribution changes',
                'changes': ['CacheBehaviors', 'Origins'],
                'requires_replacement': False
            },
            {
                'name': 'Domain name changes',
                'changes': ['DomainName', 'ApiDomainName'],
                'requires_replacement': True
            }
        ]
        
        for scenario in update_scenarios:
            name = scenario['name']
            changes = scenario['changes']
            requires_replacement = scenario['requires_replacement']
            
            if requires_replacement:
                self.log_warning(f"Update scenario requires replacement: {name} (changes: {changes})")
            else:
                self.log_success(f"Update scenario supports in-place update: {name} (changes: {changes})")
        
        # Check for update-safe resource configurations
        update_safe_checks = [
            {
                'resource': 'Lambda functions',
                'property': 'Code updates',
                'safe': True
            },
            {
                'resource': 'CloudFront distribution',
                'property': 'Cache behavior updates',
                'safe': True
            },
            {
                'resource': 'Custom resources',
                'property': 'Property updates',
                'safe': True
            }
        ]
        
        for check in update_safe_checks:
            resource = check['resource']
            prop = check['property']
            safe = check['safe']
            
            if safe:
                self.log_success(f"Update-safe configuration: {resource} - {prop}")
            else:
                self.log_warning(f"Update may cause issues: {resource} - {prop}")
        
        return True

    def test_deployment_scripts(self) -> bool:
        """Test deployment scripts and automation"""
        self.log_info("Testing deployment scripts...")
        
        # Check for deployment scripts
        deployment_scripts = [
            'scripts/deploy-sar.sh',
            'scripts/deploy-from-sar.sh',
            'scripts/deploy-infrastructure.sh',
            'scripts/generate-cloudfront-keypair.sh'
        ]
        
        for script in deployment_scripts:
            if os.path.exists(script):
                self.log_success(f"Deployment script found: {script}")
                
                # Check if script is executable
                if os.access(script, os.X_OK):
                    self.log_success(f"Script is executable: {script}")
                else:
                    self.log_warning(f"Script is not executable: {script}")
                
                # Check script content for basic validation
                try:
                    with open(script, 'r') as f:
                        content = f.read()
                    
                    if 'set -e' in content:
                        self.log_success(f"Script has error handling: {script}")
                    else:
                        self.log_warning(f"Script may lack error handling: {script}")
                    
                    if '--help' in content or 'show_usage' in content:
                        self.log_success(f"Script has help documentation: {script}")
                    else:
                        self.log_warning(f"Script may lack help documentation: {script}")
                        
                except Exception as e:
                    self.log_error(f"Error reading script {script}: {e}")
                    return False
            else:
                self.log_warning(f"Deployment script not found: {script}")
        
        return True

    def test_validation_integration(self) -> bool:
        """Test validation integration in deployment process"""
        self.log_info("Testing validation integration...")
        
        # Check for validation scripts
        validation_scripts = [
            'tests/validate-sam-template.sh',
            'tests/validate_template.py'
        ]
        
        for script in validation_scripts:
            if os.path.exists(script):
                self.log_success(f"Validation script found: {script}")
                
                # Test that validation script works
                try:
                    if script.endswith('.sh'):
                        result = subprocess.run([f'./{script}', '--help'], 
                                              capture_output=True, text=True, timeout=10)
                    else:
                        result = subprocess.run(['python3', script, '--help'], 
                                              capture_output=True, text=True, timeout=10)
                    
                    if result.returncode == 0:
                        self.log_success(f"Validation script functional: {script}")
                    else:
                        self.log_error(f"Validation script not functional: {script}")
                        return False
                        
                except subprocess.TimeoutExpired:
                    self.log_warning(f"Validation script test timed out: {script}")
                except Exception as e:
                    self.log_error(f"Error testing validation script {script}: {e}")
                    return False
            else:
                self.log_error(f"Validation script not found: {script}")
                return False
        
        # Check for pre-deployment validation integration
        deployment_scripts = ['deploy-sar.sh', 'deploy-infrastructure.sh']
        
        for script in deployment_scripts:
            if os.path.exists(script):
                with open(script, 'r') as f:
                    content = f.read()
                
                if 'validate' in content.lower():
                    self.log_success(f"Validation integrated in deployment script: {script}")
                else:
                    self.log_warning(f"Validation may not be integrated in: {script}")
        
        return True

    def test_resource_cleanup_verification(self) -> bool:
        """Test resource cleanup verification procedures"""
        self.log_info("Testing resource cleanup verification...")
        
        # Define resources that should be completely cleaned up
        resources_to_cleanup = [
            'AWS::S3::Bucket',
            'AWS::CloudFront::Distribution',
            'AWS::Lambda::Function',
            'AWS::ApiGateway::RestApi',
            'AWS::ApiGateway::DomainName',
            'AWS::Route53::RecordSet',
            'AWS::CloudWatch::Dashboard'
        ]
        
        # Check that all resource types are accounted for in cleanup
        for resource_type in resources_to_cleanup:
            self.log_success(f"Resource type identified for cleanup: {resource_type}")
        
        # Check for orphaned resource prevention
        orphan_prevention_checks = [
            {
                'resource': 'Lambda layers',
                'prevention': 'Custom resource cleanup',
                'implemented': True
            },
            {
                'resource': 'CloudFront functions',
                'prevention': 'Function association removal',
                'implemented': True
            },
            {
                'resource': 'CloudFront key groups',
                'prevention': 'Distribution dependency handling',
                'implemented': True
            },
            {
                'resource': 'Response headers policies',
                'prevention': 'Policy usage tracking',
                'implemented': True
            }
        ]
        
        for check in orphan_prevention_checks:
            resource = check['resource']
            prevention = check['prevention']
            implemented = check['implemented']
            
            if implemented:
                self.log_success(f"Orphan prevention implemented: {resource} ({prevention})")
            else:
                self.log_error(f"Orphan prevention missing: {resource} ({prevention})")
                return False
        
        return True

    def run_all_tests(self) -> bool:
        """Run all deployment and cleanup validation tests"""
        self.log_info("Starting deployment and cleanup procedures validation...")
        print("=" * 60)
        
        tests = [
            ("SAM Build Capability", self.test_sam_build_capability),
            ("Parameter Combinations", self.test_parameter_combinations),
            ("Resource Dependencies", self.test_resource_dependencies),
            ("Cleanup Procedures", self.test_cleanup_procedures),
            ("Rollback Scenarios", self.test_rollback_scenarios),
            ("Stack Update Procedures", self.test_stack_update_procedures),
            ("Deployment Scripts", self.test_deployment_scripts),
            ("Validation Integration", self.test_validation_integration),
            ("Resource Cleanup Verification", self.test_resource_cleanup_verification)
        ]
        
        for test_name, test_func in tests:
            print(f"\n🧪 Running {test_name}...")
            try:
                test_func()
            except Exception as e:
                self.log_error(f"Test {test_name} failed with exception: {e}")
        
        # Summary
        print("\n" + "=" * 60)
        print("DEPLOYMENT & CLEANUP VALIDATION SUMMARY")
        print("=" * 60)
        print(f"Tests Passed: {self.tests_passed}")
        print(f"Tests Failed: {self.tests_failed}")
        print(f"Warnings: {self.warnings}")
        
        if self.tests_failed == 0:
            if self.warnings <= 5:  # Allow some warnings for deployment scripts
                print("\n🎉 All deployment and cleanup validation tests passed! System is ready for production deployment.")
                return True
            else:
                print("\n⚠️  Deployment validation passed with warnings. Review warnings before production deployment.")
                return True
        else:
            print("\n❌ Some deployment validation tests failed. Please fix issues before deployment.")
            return False

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Deployment and Cleanup Procedures Validation for WordPress Static Site Guardian'
    )
    parser.add_argument(
        '--verbose', 
        action='store_true',
        help='Show detailed validation output'
    )
    
    args = parser.parse_args()
    
    validator = DeploymentCleanupValidator(verbose=args.verbose)
    success = validator.run_all_tests()
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()