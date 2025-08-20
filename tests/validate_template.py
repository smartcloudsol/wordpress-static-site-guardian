#!/usr/bin/env python3
"""
Advanced CloudFormation Template Validation for WordPress Static Site Guardian

This script provides detailed validation of the SAM template including:
- YAML syntax and structure validation
- Parameter constraint validation
- Resource dependency analysis
- Custom resource validation
- Security best practices validation
"""

import yaml
import json
import sys
import os
import re
import argparse
from typing import Dict, List, Any, Tuple
from pathlib import Path

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

class TemplateValidator:
    """Advanced CloudFormation template validator"""
    
    def __init__(self, template_path: str, verbose: bool = False):
        self.template_path = template_path
        self.verbose = verbose
        self.template = None
        self.errors = []
        self.warnings = []
        self.checks_passed = 0
        self.total_checks = 0
        
    def log_info(self, message: str):
        """Log info message"""
        print(f"[INFO] {message}")
        
    def log_warning(self, message: str):
        """Log warning message"""
        print(f"[WARNING] {message}")
        self.warnings.append(message)
        
    def log_error(self, message: str):
        """Log error message"""
        print(f"[ERROR] {message}")
        self.errors.append(message)
        
    def log_success(self, message: str):
        """Log success message"""
        if self.verbose:
            print(f"[PASS] {message}")
        self.checks_passed += 1
        
    def check(self, description: str):
        """Start a new check"""
        if self.verbose:
            print(f"[CHECK] {description}")
        self.total_checks += 1
        
    def load_template(self) -> bool:
        """Load and parse the CloudFormation template"""
        try:
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
    
    def validate_template_structure(self) -> bool:
        """Validate basic template structure"""
        self.check("Template structure validation")
        
        if not isinstance(self.template, dict):
            self.log_error("Template must be a dictionary")
            return False
        
        # Check required top-level sections
        required_sections = ['AWSTemplateFormatVersion', 'Transform', 'Description']
        for section in required_sections:
            if section not in self.template:
                self.log_error(f"Missing required section: {section}")
                return False
            else:
                self.log_success(f"Found required section: {section}")
        
        # Check SAM transform
        if self.template.get('Transform') != 'AWS::Serverless-2016-10-31':
            self.log_error("Invalid SAM transform")
            return False
        else:
            self.log_success("Valid SAM transform found")
        
        return True
    
    def validate_parameters(self) -> bool:
        """Validate template parameters"""
        self.check("Parameters validation")
        
        parameters = self.template.get('Parameters', {})
        if not parameters:
            self.log_warning("No parameters defined")
            return True
        
        # Required parameters for WordPress Static Site Guardian
        required_params = {
            'DomainName': 'Main domain for CloudFront distribution',
            'ApiDomainName': 'API Gateway domain',
            'CertificateArn': 'SSL certificate ARN',
            'PublicKeyContent': 'RSA public key content',
            'KmsKeyId': 'KMS key for private key encryption'
        }
        
        for param_name, description in required_params.items():
            if param_name not in parameters:
                self.log_error(f"Missing required parameter: {param_name} ({description})")
            else:
                param = parameters[param_name]
                
                # Validate parameter structure
                if 'Type' not in param:
                    self.log_error(f"Parameter {param_name} missing Type")
                elif param['Type'] != 'String':
                    self.log_warning(f"Parameter {param_name} is not String type")
                
                if 'Description' not in param:
                    self.log_warning(f"Parameter {param_name} missing Description")
                
                # Check for validation patterns on critical parameters
                if param_name in ['DomainName', 'ApiDomainName', 'CertificateArn']:
                    if 'AllowedPattern' not in param:
                        self.log_warning(f"Parameter {param_name} missing validation pattern")
                    else:
                        self.log_success(f"Parameter {param_name} has validation pattern")
                
                self.log_success(f"Required parameter found: {param_name}")
        
        return len(self.errors) == 0
    
    def validate_resources(self) -> bool:
        """Validate template resources"""
        self.check("Resources validation")
        
        resources = self.template.get('Resources', {})
        if not resources:
            self.log_error("No resources defined")
            return False
        
        # Critical resources for WordPress Static Site Guardian
        critical_resources = {
            'StaticSiteBucket': 'AWS::S3::Bucket',
            'CloudFrontDistribution': 'AWS::CloudFront::Distribution',
            'CookieSigningFunction': 'AWS::Serverless::Function',
            'CloudFrontResourceManager': 'AWS::Serverless::Function'
        }
        
        for resource_name, expected_type in critical_resources.items():
            if resource_name not in resources:
                self.log_error(f"Missing critical resource: {resource_name}")
            else:
                resource = resources[resource_name]
                if 'Type' not in resource:
                    self.log_error(f"Resource {resource_name} missing Type")
                elif resource['Type'] != expected_type:
                    self.log_error(f"Resource {resource_name} has wrong type: {resource['Type']} (expected {expected_type})")
                else:
                    self.log_success(f"Critical resource found: {resource_name}")
        
        # Custom resources validation
        custom_resources = [
            'CloudFrontPublicKey',
            'CloudFrontKeyGroup', 
            'OriginAccessControl',
            'NoCachePolicy'
        ]
        
        for resource_name in custom_resources:
            if resource_name not in resources:
                self.log_error(f"Missing custom resource: {resource_name}")
            else:
                resource = resources[resource_name]
                if resource.get('Type') != 'AWS::CloudFormation::CustomResource':
                    self.log_error(f"Custom resource {resource_name} has wrong type")
                else:
                    # Check ServiceToken reference
                    props = resource.get('Properties', {})
                    service_token = props.get('ServiceToken')
                    if not service_token or 'CloudFrontResourceManager' not in str(service_token):
                        self.log_warning(f"Custom resource {resource_name} may not reference CloudFrontResourceManager")
                    else:
                        self.log_success(f"Custom resource found: {resource_name}")
        
        return len(self.errors) == 0
    
    def validate_lambda_functions(self) -> bool:
        """Validate Lambda function configurations"""
        self.check("Lambda functions validation")
        
        resources = self.template.get('Resources', {})
        lambda_functions = {
            name: resource for name, resource in resources.items()
            if resource.get('Type') == 'AWS::Serverless::Function'
        }
        
        for func_name, func_config in lambda_functions.items():
            props = func_config.get('Properties', {})
            
            # Check required properties
            required_props = ['CodeUri', 'Handler']
            for prop in required_props:
                if prop not in props:
                    self.log_error(f"Lambda function {func_name} missing {prop}")
                else:
                    self.log_success(f"Lambda function {func_name} has {prop}")
            
            # Check timeout for CloudFrontResourceManager
            if func_name == 'CloudFrontResourceManager':
                timeout = props.get('Timeout', 30)
                if timeout < 900:  # 15 minutes needed for layer creation
                    self.log_warning(f"CloudFrontResourceManager timeout ({timeout}s) may be too low for layer creation")
                else:
                    self.log_success("CloudFrontResourceManager has adequate timeout")
            
        return len(self.errors) == 0
    
    def validate_iam_permissions(self) -> bool:
        """Validate IAM permissions"""
        self.check("IAM permissions validation")
        
        resources = self.template.get('Resources', {})
        
        # Check CloudFrontResourceManager permissions
        cfm = resources.get('CloudFrontResourceManager', {})
        cfm_props = cfm.get('Properties', {})
        policies = cfm_props.get('Policies', [])
        
        if not policies:
            self.log_error("CloudFrontResourceManager missing IAM policies")
            return False
        
        # Extract all permissions from policies
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
        
        # Required permissions
        required_permissions = [
            'cloudfront:CreatePublicKey',
            'cloudfront:CreateKeyGroup',
            'cloudfront:CreateResponseHeadersPolicy',
            'cloudfront:CreateDistribution',
            'cloudfront:UpdateDistribution'
        ]
        
        for permission in required_permissions:
            if permission in all_permissions:
                self.log_success(f"IAM permission found: {permission}")
            else:
                self.log_warning(f"IAM permission missing: {permission}")
        
        return True
    
    def validate_cloudfront_config(self) -> bool:
        """Validate CloudFront configuration"""
        self.check("CloudFront configuration validation")
        
        resources = self.template.get('Resources', {})
        cf_dist = resources.get('CloudFrontDistribution', {})
        
        if not cf_dist:
            self.log_error("CloudFront distribution not found")
            return False
        
        dist_config = cf_dist.get('Properties', {}).get('DistributionConfig', {})
        
        # Check for cache behaviors
        cache_behaviors = dist_config.get('CacheBehaviors', [])
        if not cache_behaviors:
            self.log_warning("No cache behaviors defined")
        else:
            # Check for NoCachePolicy integration
            nocache_found = False
            for behavior in cache_behaviors:
                if 'ResponseHeadersPolicyId' in behavior:
                    policy_ref = str(behavior['ResponseHeadersPolicyId'])
                    if 'NoCachePolicy' in policy_ref:
                        nocache_found = True
                        break
            
            if nocache_found:
                self.log_success("NoCachePolicy integration found")
            else:
                self.log_warning("NoCachePolicy integration not found in cache behaviors")
        
        # Check for custom domain
        aliases = dist_config.get('Aliases', [])
        if not aliases:
            self.log_warning("No custom domain aliases configured")
        else:
            self.log_success("Custom domain aliases configured")
        
        return True
    
    def validate_outputs(self) -> bool:
        """Validate template outputs"""
        self.check("Outputs validation")
        
        outputs = self.template.get('Outputs', {})
        if not outputs:
            self.log_warning("No outputs defined")
            return True
        
        # Critical outputs
        critical_outputs = [
            'S3BucketName',
            'CloudFrontDistributionId',
            'ApiGatewayInvokeUrl'
        ]
        
        for output_name in critical_outputs:
            if output_name not in outputs:
                self.log_warning(f"Missing critical output: {output_name}")
            else:
                output = outputs[output_name]
                if 'Description' not in output:
                    self.log_warning(f"Output {output_name} missing description")
                if 'Value' not in output:
                    self.log_error(f"Output {output_name} missing value")
                else:
                    self.log_success(f"Critical output found: {output_name}")
        
        return len(self.errors) == 0
    
    def validate_security_best_practices(self) -> bool:
        """Validate security best practices"""
        self.check("Security best practices validation")
        
        resources = self.template.get('Resources', {})
        
        # Check S3 bucket security
        s3_bucket = resources.get('StaticSiteBucket', {})
        s3_props = s3_bucket.get('Properties', {})
        
        # Check public access block
        public_access_block = s3_props.get('PublicAccessBlockConfiguration', {})
        if not public_access_block:
            self.log_error("S3 bucket missing PublicAccessBlockConfiguration")
        else:
            required_blocks = ['BlockPublicAcls', 'BlockPublicPolicy', 'IgnorePublicAcls', 'RestrictPublicBuckets']
            for block in required_blocks:
                if public_access_block.get(block) != True:
                    self.log_warning(f"S3 bucket {block} not set to true")
                else:
                    self.log_success(f"S3 bucket {block} properly configured")
        
        # Check encryption
        encryption = s3_props.get('BucketEncryption', {})
        if not encryption:
            self.log_warning("S3 bucket encryption not configured")
        else:
            self.log_success("S3 bucket encryption configured")
        
        # Check Lambda function environment variables for sensitive data
        lambda_functions = {
            name: resource for name, resource in resources.items()
            if resource.get('Type') == 'AWS::Serverless::Function'
        }
        
        for func_name, func_config in lambda_functions.items():
            env_vars = func_config.get('Properties', {}).get('Environment', {}).get('Variables', {})
            for var_name, var_value in env_vars.items():
                if isinstance(var_value, str) and any(keyword in var_value.lower() for keyword in ['password', 'secret', 'key']):
                    if not var_value.startswith('!'):  # Not a CloudFormation function
                        self.log_warning(f"Lambda function {func_name} may have hardcoded sensitive data in {var_name}")
        
        return True
    
    def run_validation(self) -> bool:
        """Run all validations"""
        self.log_info("Starting comprehensive template validation...")
        
        if not self.load_template():
            return False
        
        validations = [
            self.validate_template_structure,
            self.validate_parameters,
            self.validate_resources,
            self.validate_lambda_functions,
            self.validate_iam_permissions,
            self.validate_cloudfront_config,
            self.validate_outputs,
            self.validate_security_best_practices
        ]
        
        for validation in validations:
            try:
                validation()
            except Exception as e:
                self.log_error(f"Validation error: {e}")
        
        # Summary
        print("\n" + "="*50)
        print("VALIDATION SUMMARY")
        print("="*50)
        print(f"Total Checks: {self.total_checks}")
        print(f"Passed: {self.checks_passed}")
        print(f"Warnings: {len(self.warnings)}")
        print(f"Errors: {len(self.errors)}")
        
        if len(self.errors) == 0:
            if len(self.warnings) == 0:
                print("\n🎉 All validations passed! Template is ready for deployment.")
                return True
            else:
                print("\n⚠️  Validation passed with warnings. Review warnings before deployment.")
                return True
        else:
            print("\n❌ Validation failed. Please fix errors before deployment.")
            return False

def main():
    parser = argparse.ArgumentParser(
        description='Advanced CloudFormation Template Validation for WordPress Static Site Guardian'
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
    
    validator = TemplateValidator(args.template, args.verbose)
    success = validator.run_validation()
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()