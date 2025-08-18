#!/bin/bash

# Create Lambda Layer for Cryptography Dependencies
# This script creates a Lambda layer with the required cryptography libraries

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
LAYER_NAME="cloudfront-crypto-layer"
REGION="us-east-1"
PYTHON_VERSION="3.12"

# Function to show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Create Lambda Layer for CloudFront signing dependencies

OPTIONS:
    -n, --name NAME                      Layer name (default: cloudfront-crypto-layer)
    -r, --region REGION                  AWS region (default: us-east-1)
    -p, --python-version VERSION         Python version (default: 3.12, use 'auto' to detect)
    -h, --help                           Show this help message

EXAMPLES:
    $0
    $0 -n my-crypto-layer -r us-west-2 -p auto
    $0 -n my-crypto-layer -r us-west-2 -p 3.12

OUTPUT:
    - Lambda layer ARN for use in CloudFormation

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--name)
            LAYER_NAME="$2"
            shift 2
            ;;
        -r|--region)
            REGION="$2"
            shift 2
            ;;
        -p|--python-version)
            PYTHON_VERSION="$2"
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

# Auto-detect Python version if not specified
if [[ "$PYTHON_VERSION" == "auto" ]]; then
    DETECTED_VERSION=$(python3 --version 2>&1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
    if [[ -n "$DETECTED_VERSION" ]]; then
        PYTHON_VERSION="$DETECTED_VERSION"
        print_status "Auto-detected Python version: $PYTHON_VERSION"
    else
        print_error "Could not detect Python version"
        exit 1
    fi
fi

print_status "Creating Lambda layer for cryptography dependencies..."
echo "  Layer Name: $LAYER_NAME"
echo "  Region: $REGION"
echo "  Python Version: $PYTHON_VERSION"
echo

# Check if required tools are available
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed or not in PATH"
    exit 1
fi

if ! command -v pip3 &> /dev/null; then
    print_error "pip3 is not installed or not in PATH"
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

# Create temporary directory for layer contents
TEMP_DIR=$(mktemp -d)
LAYER_DIR="$TEMP_DIR/python"
mkdir -p "$LAYER_DIR"

print_status "Installing dependencies to temporary directory..."

# Install cryptography and boto3 to the layer directory
pip3 install \
    --target "$LAYER_DIR" \
    --platform linux_x86_64 \
    --implementation cp \
    --python-version "$PYTHON_VERSION" \
    --only-binary=:all: \
    --upgrade \
    cryptography boto3 botocore

if [[ $? -ne 0 ]]; then
    print_error "Failed to install dependencies"
    rm -rf "$TEMP_DIR"
    exit 1
fi

print_status "Creating layer zip file..."

# Create zip file
cd "$TEMP_DIR"
ZIP_FILE="$LAYER_NAME.zip"
zip -r "$ZIP_FILE" python/ > /dev/null

if [[ $? -ne 0 ]]; then
    print_error "Failed to create zip file"
    rm -rf "$TEMP_DIR"
    exit 1
fi

print_status "Publishing Lambda layer..."

# Publish the layer
LAYER_OUTPUT=$(aws lambda publish-layer-version \
    --layer-name "$LAYER_NAME" \
    --description "Cryptography dependencies for CloudFront signed cookies" \
    --zip-file "fileb://$ZIP_FILE" \
    --compatible-runtimes "python$PYTHON_VERSION" \
    --region "$REGION" \
    --output json)

if [[ $? -ne 0 ]]; then
    print_error "Failed to publish Lambda layer"
    rm -rf "$TEMP_DIR"
    exit 1
fi

LAYER_ARN=$(echo "$LAYER_OUTPUT" | jq -r '.LayerArn')
LAYER_VERSION=$(echo "$LAYER_OUTPUT" | jq -r '.Version')
LAYER_VERSION_ARN=$(echo "$LAYER_OUTPUT" | jq -r '.LayerVersionArn')

# Clean up
rm -rf "$TEMP_DIR"

print_status "Lambda layer created successfully!"
echo
echo "Layer Details:"
echo "  Layer Name: $LAYER_NAME"
echo "  Layer ARN: $LAYER_ARN"
echo "  Version: $LAYER_VERSION"
echo "  Version ARN: $LAYER_VERSION_ARN"
echo

print_status "Add this ARN to your CloudFormation template:"
echo "----------------------------------------"
echo "$LAYER_VERSION_ARN"
echo "----------------------------------------"

# Save layer info to file
cat > "lambda_layer_info.json" << EOF
{
  "LayerName": "$LAYER_NAME",
  "LayerArn": "$LAYER_ARN",
  "Version": $LAYER_VERSION,
  "LayerVersionArn": "$LAYER_VERSION_ARN",
  "Region": "$REGION",
  "PythonVersion": "$PYTHON_VERSION"
}
EOF

print_status "Layer information saved to lambda_layer_info.json"