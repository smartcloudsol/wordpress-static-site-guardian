#!/bin/bash

# WordPress Static Site Guardian - SAR Compatible Deployment Script
# Deploy SAR-compatible version to AWS Serverless Application Repository

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Default values
REGION="us-east-1"
S3_BUCKET=""
APPLICATION_NAME="wordpress-static-site-guardian"
SEMANTIC_VERSION="1.0.0"

# Function to show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Deploy WordPress Static Site Guardian (SAR Compatible) to AWS Serverless Application Repository

OPTIONS:
    -b, --bucket BUCKET_NAME             S3 bucket for SAR artifacts (required)
    -r, --region REGION                  AWS region (default: us-east-1)
    -v, --version VERSION                Semantic version (default: 1.0.0)
    -n, --name APPLICATION_NAME          Application name (default: wordpress-static-site-guardian)
    -h, --help                           Show this help message

EXAMPLES:
    $0 -b my-sar-artifacts-bucket
    $0 -b my-bucket -r us-west-2 -v 1.1.0

PREREQUISITES:
    1. AWS CLI configured with SAR publishing permissions
    2. SAM CLI installed for packaging
    3. S3 bucket for storing application artifacts
    4. Valid semantic version format (x.y.z)

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -b|--bucket)
            S3_BUCKET="$2"
            shift 2
            ;;
        -r|--region)
            REGION="$2"
            shift 2
            ;;
        -v|--version)
            SEMANTIC_VERSION="$2"
            shift 2
            ;;
        -n|--name)
            APPLICATION_NAME="$2"
            shift 2
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

# Validate required parameters
if [[ -z "$S3_BUCKET" ]]; then
    print_error "S3 bucket is required for SAR deployment"
    show_usage
    exit 1
fi

# Validate semantic version format
if [[ ! "$SEMANTIC_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    print_error "Invalid semantic version format. Must be x.y.z (e.g., 1.0.0)"
    exit 1
fi

print_status "Deploying WordPress Static Site Guardian (SAR Compatible) to SAR..."
echo "  Application Name: $APPLICATION_NAME"
echo "  Version: $SEMANTIC_VERSION"
echo "  Region: $REGION"
echo "  S3 Bucket: $S3_BUCKET"
echo

# Check if required tools are available
if ! command -v sam &> /dev/null; then
    print_error "SAM CLI is not installed. Please install it first:"
    echo "  https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html"
    exit 1
fi

if ! command -v aws &> /dev/null; then
    print_error "AWS CLI is not installed or not in PATH"
    exit 1
fi

# Check AWS CLI configuration
if ! aws sts get-caller-identity --region "$REGION" &>/dev/null; then
    print_error "AWS CLI not configured or no valid credentials found for region $REGION"
    exit 1
fi

# Check if S3 bucket exists
if ! aws s3 ls "s3://$S3_BUCKET" --region "$REGION" &>/dev/null; then
    print_error "S3 bucket '$S3_BUCKET' does not exist or is not accessible"
    exit 1
fi

# Update template.yaml with current version
print_status "Updating template.yaml with version $SEMANTIC_VERSION..."
sed -i.bak "s/SemanticVersion: .*/SemanticVersion: $SEMANTIC_VERSION/" template.yaml

# Detect Python version and update template if needed
print_status "Detecting Python version..."
PYTHON_VERSION=$(python3 --version 2>&1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
if [[ -n "$PYTHON_VERSION" ]]; then
    print_status "Detected Python $PYTHON_VERSION"
    # Update template to use detected Python version
    sed -i.bak2 "s/Runtime: python3\.[0-9]*/Runtime: python$PYTHON_VERSION/" template.yaml
    print_status "Updated template to use Python $PYTHON_VERSION"
fi

# Validate SAM template
print_status "Validating SAM template..."
if ! sam validate --template template.yaml --region "$REGION"; then
    print_error "SAM template validation failed"
    # Restore original template
    if [[ -f "template.yaml.bak" ]]; then
        mv template.yaml.bak template.yaml
    fi
    exit 1
fi

# Build the application
print_status "Building SAM application..."
if ! sam build --template template.yaml; then
    print_error "SAM build failed"
    # Restore original template
    if [[ -f "template.yaml.bak" ]]; then
        mv template.yaml.bak template.yaml
    fi
    exit 1
fi

# Package the application
print_status "Packaging application for SAR..."
PACKAGED_TEMPLATE="packaged-template.yaml"

if ! sam package \
    --template-file .aws-sam/build/template.yaml \
    --s3-bucket "$S3_BUCKET" \
    --s3-prefix "wordpress-static-site-guardian/$SEMANTIC_VERSION" \
    --output-template-file "$PACKAGED_TEMPLATE" \
    --region "$REGION"; then
    print_error "SAM packaging failed"
    # Restore original template
    if [[ -f "template.yaml.bak" ]]; then
        mv template.yaml.bak template.yaml
    fi
    exit 1
fi

# Publish to SAR
print_status "Publishing to AWS Serverless Application Repository..."
if ! sam publish \
    --template "$PACKAGED_TEMPLATE" \
    --region "$REGION"; then
    print_error "SAR publishing failed"
    # Restore original template
    if [[ -f "template.yaml.bak" ]]; then
        mv template.yaml.bak template.yaml
    fi
    exit 1
fi

# Clean up
rm -f template.yaml.bak template.yaml.bak2
rm -f "$PACKAGED_TEMPLATE"

print_status "Successfully published to AWS Serverless Application Repository!"
echo
echo "Application Details:"
echo "  Name: $APPLICATION_NAME"
echo "  Version: $SEMANTIC_VERSION"
echo "  Region: $REGION"
echo
echo "You can now find your application in the AWS Serverless Application Repository:"
echo "  https://$REGION.console.aws.amazon.com/serverlessrepo/home?region=$REGION#/available-applications"
echo
print_status "Next steps:"
echo "1. Verify the application appears in the SAR console"
echo "2. Test deployment from the SAR console"
echo "3. Share the application ARN with users for easy deployment"
echo "4. Consider making the application public for broader distribution"
echo
print_warning "Note: This SAR-compatible version uses custom resources for CloudFront components"
echo "that are not natively supported by SAR. The functionality remains the same."