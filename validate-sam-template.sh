#!/bin/bash

# Validate SAM Template Script
# Quick validation of the SAM template for common issues

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

print_status "Validating SAM template..."

# Check if SAM CLI is available
if ! command -v sam &> /dev/null; then
    print_error "SAM CLI is not installed. Please install it first:"
    echo "  https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html"
    exit 1
fi

# Check if template exists
if [[ ! -f "template.yaml" ]]; then
    print_error "template.yaml not found in current directory"
    exit 1
fi

# Validate the template
print_status "Running SAM validate..."
if sam validate --template template.yaml; then
    print_status "✅ SAM template validation passed!"
else
    print_error "❌ SAM template validation failed"
    exit 1
fi

# Check for common issues
print_status "Checking for common issues..."

# Check if src directory exists
if [[ ! -d "src" ]]; then
    print_warning "src/ directory not found - Lambda function code may be missing"
fi

# Check if Lambda function file exists
if [[ ! -f "src/lambda_function.py" ]]; then
    print_warning "src/lambda_function.py not found - Lambda handler may be missing"
fi

# Check if requirements.txt exists
if [[ ! -f "src/requirements.txt" ]]; then
    print_warning "src/requirements.txt not found - Lambda dependencies may be missing"
fi

print_status "Template validation complete!"
echo
print_status "Next steps:"
echo "1. Run 'sam build' to build the application"
echo "2. Run 'sam deploy --guided' to deploy with guided setup"
echo "3. Or use the deploy-sar.sh script to publish to SAR"