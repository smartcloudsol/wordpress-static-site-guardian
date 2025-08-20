#!/bin/bash

# Comprehensive SAM Template Validation Script
# Validates SAM template for syntax, parameters, resources, and dependencies

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters for validation results
TOTAL_CHECKS=0
PASSED_CHECKS=0
WARNING_COUNT=0
ERROR_COUNT=0

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    WARNING_COUNT=$((WARNING_COUNT + 1))
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    ERROR_COUNT=$((ERROR_COUNT + 1))
}

print_check() {
    echo -e "${BLUE}[CHECK]${NC} $1"
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
}

print_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ERROR_COUNT=$((ERROR_COUNT + 1))
}

# Function to show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Comprehensive SAM template validation for WordPress Static Site Guardian

OPTIONS:
    --template FILE         Template file to validate (default: template.yaml)
    --strict               Treat warnings as errors
    --skip-lint            Skip SAM linting (faster validation)
    --verbose              Show detailed validation output
    -h, --help             Show this help message

VALIDATION CHECKS:
    - SAM template syntax validation
    - SAM template linting
    - Parameter validation and constraints
    - Resource dependencies and references
    - Custom resource validation
    - Lambda function code validation
    - IAM permissions validation
    - CloudFront configuration validation

EXAMPLES:
    $0                                    # Basic validation
    $0 --strict                          # Strict validation (warnings as errors)
    $0 --template my-template.yaml       # Validate specific template
    $0 --verbose --skip-lint             # Verbose output without linting

EOF
}

# Default values
TEMPLATE_FILE="template.yaml"
STRICT_MODE=false
SKIP_LINT=false
VERBOSE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --template)
            TEMPLATE_FILE="$2"
            shift 2
            ;;
        --strict)
            STRICT_MODE=true
            shift
            ;;
        --skip-lint)
            SKIP_LINT=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

echo "WordPress Static Site Guardian - SAM Template Validation"
echo "========================================================"
echo "Template: $TEMPLATE_FILE"
echo "Strict Mode: $STRICT_MODE"
echo "Skip Lint: $SKIP_LINT"
echo "Verbose: $VERBOSE"
echo

# Check prerequisites
print_status "Checking prerequisites..."

print_check "SAM CLI availability"
if command -v sam &> /dev/null; then
    print_success "SAM CLI found"
else
    print_fail "SAM CLI is not installed"
    echo "  Install from: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html"
    exit 1
fi

print_check "Template file existence"
if [[ -f "$TEMPLATE_FILE" ]]; then
    print_success "Template file found: $TEMPLATE_FILE"
else
    print_fail "Template file not found: $TEMPLATE_FILE"
    exit 1
fi

print_check "Python availability for custom validation"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1)
    print_success "Python found: $PYTHON_VERSION"
else
    print_warning "Python3 not found - some validations will be skipped"
fi

echo

# Basic SAM validation
print_status "Running SAM template validation..."

print_check "SAM template syntax validation"
if sam validate --template "$TEMPLATE_FILE" >/dev/null 2>&1; then
    print_success "SAM template syntax is valid"
else
    print_fail "SAM template syntax validation failed"
    if [[ "$VERBOSE" == "true" ]]; then
        echo "SAM validation output:"
        sam validate --template "$TEMPLATE_FILE" 2>&1 | sed 's/^/  /'
    fi
    exit 1
fi

# SAM linting
if [[ "$SKIP_LINT" == "false" ]]; then
    print_check "SAM template linting"
    if sam validate --template "$TEMPLATE_FILE" --lint >/dev/null 2>&1; then
        print_success "SAM template linting passed"
    else
        if [[ "$STRICT_MODE" == "true" ]]; then
            print_fail "SAM template linting failed (strict mode)"
            if [[ "$VERBOSE" == "true" ]]; then
                echo "SAM linting output:"
                sam validate --template "$TEMPLATE_FILE" --lint 2>&1 | sed 's/^/  /'
            fi
            exit 1
        else
            print_warning "SAM template linting has warnings"
            if [[ "$VERBOSE" == "true" ]]; then
                echo "SAM linting output:"
                sam validate --template "$TEMPLATE_FILE" --lint 2>&1 | sed 's/^/  /'
            fi
        fi
    fi
fi

echo

# Parameter validation
print_status "Validating template parameters..."

print_check "Required parameters presence"
REQUIRED_PARAMS=("DomainName" "ApiDomainName" "CertificateArn" "PublicKeyContent" "KmsKeyId")
TEMPLATE_CONTENT=$(cat "$TEMPLATE_FILE")

for param in "${REQUIRED_PARAMS[@]}"; do
    if echo "$TEMPLATE_CONTENT" | grep -q "^  $param:"; then
        print_success "Required parameter found: $param"
    else
        print_fail "Required parameter missing: $param"
    fi
done

print_check "Parameter constraints validation"
# Check for AllowedPattern constraints on critical parameters
PATTERN_PARAMS=("DomainName" "ApiDomainName" "CertificateArn")
for param in "${PATTERN_PARAMS[@]}"; do
    if echo "$TEMPLATE_CONTENT" | grep -A 5 "^  $param:" | grep -q "AllowedPattern:"; then
        print_success "Parameter $param has validation pattern"
    else
        print_warning "Parameter $param missing validation pattern"
    fi
done

echo

# Resource validation
print_status "Validating template resources..."

print_check "Critical resources presence"
CRITICAL_RESOURCES=("StaticSiteBucket" "CloudFrontDistribution" "CookieSigningFunction" "CloudFrontResourceManager")
for resource in "${CRITICAL_RESOURCES[@]}"; do
    if echo "$TEMPLATE_CONTENT" | grep -q "^  $resource:"; then
        print_success "Critical resource found: $resource"
    else
        print_fail "Critical resource missing: $resource"
    fi
done

print_check "Custom resources validation"
CUSTOM_RESOURCES=("CloudFrontPublicKey" "CloudFrontKeyGroup" "OriginAccessControl" "NoCachePolicy")
for resource in "${CUSTOM_RESOURCES[@]}"; do
    if echo "$TEMPLATE_CONTENT" | grep -q "^  $resource:"; then
        print_success "Custom resource found: $resource"
    else
        print_fail "Custom resource missing: $resource"
    fi
done

print_check "Resource dependencies"
# Check that custom resources reference the CloudFrontResourceManager
if echo "$TEMPLATE_CONTENT" | grep -A 3 "Type: AWS::CloudFormation::CustomResource" | grep -q "!GetAtt CloudFrontResourceManager.Arn"; then
    print_success "Custom resources properly reference CloudFrontResourceManager"
else
    print_warning "Some custom resources may not reference CloudFrontResourceManager"
fi

echo

# Lambda function validation
print_status "Validating Lambda functions..."

print_check "Lambda function code directory"
if [[ -d "src" ]]; then
    print_success "Lambda source directory found: src/"
else
    print_fail "Lambda source directory missing: src/"
fi

print_check "Lambda function handlers"
LAMBDA_FILES=("lambda_function.py" "cloudfront_manager.py")
for file in "${LAMBDA_FILES[@]}"; do
    if [[ -f "src/$file" ]]; then
        print_success "Lambda file found: src/$file"
    else
        print_fail "Lambda file missing: src/$file"
    fi
done

print_check "Lambda dependencies"
if [[ -f "src/requirements.txt" ]]; then
    print_success "Lambda requirements file found: src/requirements.txt"
    
    # Check for critical dependencies
    REQUIRED_DEPS=("boto3")
    for dep in "${REQUIRED_DEPS[@]}"; do
        if grep -q "$dep" "src/requirements.txt"; then
            print_success "Required dependency found: $dep"
        else
            print_warning "Required dependency missing: $dep"
        fi
    done
else
    print_warning "Lambda requirements file missing: src/requirements.txt"
fi

# Python syntax validation if Python is available
if command -v python3 &> /dev/null; then
    print_check "Python syntax validation"
    SYNTAX_ERRORS=0
    
    for py_file in src/*.py; do
        if [[ -f "$py_file" ]]; then
            if python3 -m py_compile "$py_file" 2>/dev/null; then
                print_success "Syntax valid: $py_file"
            else
                print_fail "Syntax error in: $py_file"
                SYNTAX_ERRORS=$((SYNTAX_ERRORS + 1))
            fi
        fi
    done
    
    if [[ $SYNTAX_ERRORS -eq 0 ]]; then
        print_success "All Python files have valid syntax"
    fi
fi

echo

# IAM permissions validation
print_status "Validating IAM permissions..."

print_check "CloudFront permissions"
CF_PERMISSIONS=("cloudfront:CreatePublicKey" "cloudfront:CreateKeyGroup" "cloudfront:CreateResponseHeadersPolicy")
for perm in "${CF_PERMISSIONS[@]}"; do
    if echo "$TEMPLATE_CONTENT" | grep -q "$perm"; then
        print_success "IAM permission found: $perm"
    else
        print_warning "IAM permission missing: $perm"
    fi
done

print_check "Lambda permissions"
LAMBDA_PERMISSIONS=("kms:Decrypt" "ssm:GetParameter")
for perm in "${LAMBDA_PERMISSIONS[@]}"; do
    if echo "$TEMPLATE_CONTENT" | grep -q "$perm"; then
        print_success "Lambda permission found: $perm"
    else
        print_warning "Lambda permission missing: $perm"
    fi
done

echo

# CloudFront configuration validation
print_status "Validating CloudFront configuration..."

print_check "CloudFront distribution configuration"
if echo "$TEMPLATE_CONTENT" | grep -q "Type: AWS::CloudFront::Distribution"; then
    print_success "CloudFront distribution resource found"
else
    print_fail "CloudFront distribution resource missing"
fi

print_check "Cache behaviors configuration"
if echo "$TEMPLATE_CONTENT" | grep -q "CacheBehaviors:"; then
    print_success "Cache behaviors configuration found"
else
    print_warning "Cache behaviors configuration missing"
fi

print_check "NoCachePolicy integration"
if echo "$TEMPLATE_CONTENT" | grep -q "ResponseHeadersPolicyId.*NoCachePolicy"; then
    print_success "NoCachePolicy properly integrated"
else
    print_warning "NoCachePolicy integration not found"
fi

echo

# Output validation
print_status "Validating template outputs..."

print_check "Critical outputs presence"
CRITICAL_OUTPUTS=("S3BucketName" "CloudFrontDistributionId" "ApiGatewayInvokeUrl")
for output in "${CRITICAL_OUTPUTS[@]}"; do
    if echo "$TEMPLATE_CONTENT" | grep -q "^  $output:"; then
        print_success "Critical output found: $output"
    else
        print_warning "Critical output missing: $output"
    fi
done

echo

# Summary
print_status "Validation Summary"
echo "=================="
echo "Total Checks: $TOTAL_CHECKS"
echo "Passed: $PASSED_CHECKS"
echo "Warnings: $WARNING_COUNT"
echo "Errors: $ERROR_COUNT"
echo

if [[ $ERROR_COUNT -eq 0 ]]; then
    if [[ $WARNING_COUNT -eq 0 ]]; then
        print_success "🎉 All validations passed! Template is ready for deployment."
        echo
        print_status "Next steps:"
        echo "1. Run 'sam build' to build the application"
        echo "2. Run 'sam deploy --guided' to deploy with guided setup"
        echo "3. Or use 'sam deploy' with existing samconfig.toml"
        exit 0
    else
        if [[ "$STRICT_MODE" == "true" ]]; then
            print_error "❌ Validation failed in strict mode due to warnings"
            exit 1
        else
            print_warning "⚠️  Validation passed with warnings. Review warnings before deployment."
            echo
            print_status "Next steps:"
            echo "1. Review and address warnings if needed"
            echo "2. Run 'sam build' to build the application"
            echo "3. Run 'sam deploy --guided' to deploy with guided setup"
            exit 0
        fi
    fi
else
    print_error "❌ Validation failed with $ERROR_COUNT errors"
    echo
    print_status "Please fix the errors before deployment:"
    echo "1. Review and fix all reported errors"
    echo "2. Re-run this validation script"
    echo "3. Only proceed with deployment after all errors are resolved"
    exit 1
fi