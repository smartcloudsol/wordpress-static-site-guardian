#!/usr/bin/env python3
"""
Test script for optional error pages functionality

This script tests the conditional logic for error pages in the CloudFormation template.
"""

import yaml
import sys
import os
from pathlib import Path

# Add the project root to the path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

def load_template():
    """Load the CloudFormation template"""
    template_path = project_root / "template.yaml"
    
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

    with open(template_path, 'r') as f:
        return yaml.load(f, Loader=CloudFormationLoader)

def test_parameter_defaults():
    """Test that error page parameters have empty defaults"""
    template = load_template()
    parameters = template.get('Parameters', {})
    
    # Test NotFoundPagePath has empty default
    not_found_param = parameters.get('NotFoundPagePath', {})
    assert not_found_param.get('Default') == '', f"NotFoundPagePath should have empty default, got: {not_found_param.get('Default')}"
    
    # Test ForbiddenPagePath has empty default
    forbidden_param = parameters.get('ForbiddenPagePath', {})
    assert forbidden_param.get('Default') == '', f"ForbiddenPagePath should have empty default, got: {forbidden_param.get('Default')}"
    
    # Test ProtectedPaths has no default
    protected_paths_param = parameters.get('ProtectedPaths', {})
    assert 'Default' not in protected_paths_param, f"ProtectedPaths should have no default, but found: {protected_paths_param.get('Default')}"
    
    print("✓ Parameter defaults are correct")

def test_conditions_exist():
    """Test that the required conditions exist"""
    template = load_template()
    conditions = template.get('Conditions', {})
    
    # Test HasNotFoundPage condition exists
    assert 'HasNotFoundPage' in conditions, "HasNotFoundPage condition should exist"
    
    # Test HasForbiddenPage condition exists
    assert 'HasForbiddenPage' in conditions, "HasForbiddenPage condition should exist"
    
    print("✓ Required conditions exist")

def test_parameter_descriptions():
    """Test that parameter descriptions mention optional nature and S3WWWRoot"""
    template = load_template()
    parameters = template.get('Parameters', {})
    
    # Test NotFoundPagePath description
    not_found_desc = parameters.get('NotFoundPagePath', {}).get('Description', '')
    assert 'Optional' in not_found_desc, "NotFoundPagePath description should mention it's optional"
    assert 'S3WWWRoot' in not_found_desc, "NotFoundPagePath description should mention S3WWWRoot"
    
    # Test ForbiddenPagePath description
    forbidden_desc = parameters.get('ForbiddenPagePath', {}).get('Description', '')
    assert 'Optional' in forbidden_desc, "ForbiddenPagePath description should mention it's optional"
    assert 'S3WWWRoot' in forbidden_desc, "ForbiddenPagePath description should mention S3WWWRoot"
    
    # Test ProtectedPaths description
    protected_desc = parameters.get('ProtectedPaths', {}).get('Description', '')
    assert 'e.g.' in protected_desc, "ProtectedPaths description should include examples"
    
    print("✓ Parameter descriptions are correct")

def test_allowed_patterns():
    """Test that parameter allowed patterns accept empty strings"""
    template = load_template()
    parameters = template.get('Parameters', {})
    
    # Test NotFoundPagePath allows empty string
    not_found_pattern = parameters.get('NotFoundPagePath', {}).get('AllowedPattern', '')
    assert not_found_pattern.startswith('^$|'), "NotFoundPagePath should allow empty string"
    
    # Test ForbiddenPagePath allows empty string
    forbidden_pattern = parameters.get('ForbiddenPagePath', {}).get('AllowedPattern', '')
    assert forbidden_pattern.startswith('^$|'), "ForbiddenPagePath should allow empty string"
    
    print("✓ Parameter allowed patterns are correct")

def main():
    """Run all tests"""
    print("Testing optional error pages functionality...")
    
    try:
        test_parameter_defaults()
        test_conditions_exist()
        test_parameter_descriptions()
        test_allowed_patterns()
        
        print("\n✅ All tests passed! Optional error pages are correctly configured.")
        return 0
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())