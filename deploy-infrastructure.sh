#!/bin/bash

# WordPress Protection Infrastructure Deployment Script
# This script helps deploy the CloudFormation template with proper configuration

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
STACK_NAME=""
DOMAIN_NAME=""
API_DOMAIN_NAME=""
CERTIFICATE_ARN=""
PROTECTED_PATHS="/dashboard,/profile,/admin"
SIGNIN_PAGE_PATH="/signin"
COGNITO_REFRESH_TOKEN_VALIDITY=30
REGION="us-east-1"
KMS_KEY_ID=""
PUBLIC_KEY_CONTENT=""

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

# Function to show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Deploy WordPress Protection Infrastructure

OPTIONS:
    -s, --stack-name STACK_NAME          CloudFormation stack name (required)
    -d, --domain DOMAIN                  Main domain for CloudFront (required)
    -a, --api-domain API_DOMAIN          API Gateway domain (required)
    -c, --certificate-arn ARN            ACM certificate ARN in us-east-1 (required)
    -k, --kms-key-id KEY_ID              KMS Key ID containing encrypted private key (required)
    -u, --public-key-content CONTENT     Base64 public key content (required)
    -p, --protected-paths PATHS          Comma-separated protected paths (default: /dashboard,/profile,/admin)
    -i, --signin-path PATH               Path for sign-in page (default: /signin)
    -t, --token-validity DAYS            Cookie expiration in days (default: 30)
    -r, --region REGION                  AWS region (default: us-east-1)
    -h, --help                           Show this help message

EXAMPLES:
    $0 -s my-wordpress-stack -d example.com -a api.example.com -c arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012 -k 12345678-1234-1234-1234-123456789012 -u "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."
    $0 -s my-stack -d site.com -a api.site.com -c arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012 -k 12345678-1234-1234-1234-123456789012 -u "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..." -p "/admin,/dashboard" -i "/login" -t 7

PREREQUISITES:
    1. AWS CLI configured with appropriate permissions
    2. Valid SSL certificate in ACM (us-east-1 for CloudFront)
    3. CloudFront key pair generated (public/private keys)
    4. Domain DNS configured to point to CloudFront

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--stack-name)
            STACK_NAME="$2"
            shift 2
            ;;
        -d|--domain)
            DOMAIN_NAME="$2"
            shift 2
            ;;
        -a|--api-domain)
            API_DOMAIN_NAME="$2"
            shift 2
            ;;
        -c|--certificate-arn)
            CERTIFICATE_ARN="$2"
            shift 2
            ;;
        -k|--kms-key-id)
            KMS_KEY_ID="$2"
            shift 2
            ;;
        -u|--public-key-content)
            PUBLIC_KEY_CONTENT="$2"
            shift 2
            ;;
        -p|--protected-paths)
            PROTECTED_PATHS="$2"
            shift 2
            ;;
        -i|--signin-path)
            SIGNIN_PAGE_PATH="$2"
            shift 2
            ;;
        -t|--token-validity)
            COGNITO_REFRESH_TOKEN_VALIDITY="$2"
            shift 2
            ;;
        -r|--region)
            REGION="$2"
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
if [[ -z "$STACK_NAME" || -z "$DOMAIN_NAME" || -z "$API_DOMAIN_NAME" || -z "$CERTIFICATE_ARN" || -z "$KMS_KEY_ID" || -z "$PUBLIC_KEY_CONTENT" ]]; then
    print_error "Missing required parameters"
    show_usage
    exit 1
fi

# Validate certificate ARN format
if [[ ! "$CERTIFICATE_ARN" =~ ^arn:aws:acm:us-east-1:[0-9]{12}:certificate/[a-f0-9-]{36}$ ]]; then
    print_error "Invalid certificate ARN format. Must be an ACM certificate ARN in us-east-1 region"
    exit 1
fi

# Validate KMS Key ID format
if [[ ! "$KMS_KEY_ID" =~ ^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$ ]]; then
    print_error "Invalid KMS Key ID format. Must be a valid UUID format"
    exit 1
fi

# Validate public key content is not empty
if [[ ${#PUBLIC_KEY_CONTENT} -lt 100 ]]; then
    print_error "Public key content appears to be too short. Please provide the full base64-encoded public key"
    exit 1
fi

# Validate API domain is subdomain of main domain
if [[ "$API_DOMAIN_NAME" != *"$DOMAIN_NAME" ]]; then
    print_warning "API domain should be a subdomain of the main domain"
fi

print_status "Starting deployment with the following configuration:"
echo "  Stack Name: $STACK_NAME"
echo "  Domain: $DOMAIN_NAME"
echo "  API Domain: $API_DOMAIN_NAME"
echo "  Certificate ARN: $CERTIFICATE_ARN"
echo "  KMS Key ID: $KMS_KEY_ID"
echo "  Public Key Length: ${#PUBLIC_KEY_CONTENT} characters"
echo "  Protected Paths: $PROTECTED_PATHS"
echo "  Signin Path: $SIGNIN_PAGE_PATH"
echo "  Token Validity: $COGNITO_REFRESH_TOKEN_VALIDITY days"
echo "  Region: $REGION"
echo

# Check if AWS CLI is configured
if ! aws sts get-caller-identity &>/dev/null; then
    print_error "AWS CLI not configured or no valid credentials found"
    exit 1
fi

print_status "AWS CLI configured successfully"

# Check if CloudFormation template exists
if [[ ! -f "wordpress-protection-infrastructure.yaml" ]]; then
    print_error "CloudFormation template not found: wordpress-protection-infrastructure.yaml"
    exit 1
fi

# Validate CloudFormation template
print_status "Validating CloudFormation template..."
if ! aws cloudformation validate-template --template-body file://wordpress-protection-infrastructure.yaml --region "$REGION" &>/dev/null; then
    print_error "CloudFormation template validation failed"
    exit 1
fi

print_status "Template validation successful"

# Deploy the stack
print_status "Deploying CloudFormation stack..."

aws cloudformation deploy \
    --template-file wordpress-protection-infrastructure.yaml \
    --stack-name "$STACK_NAME" \
    --parameter-overrides \
        ProtectedPaths="$PROTECTED_PATHS" \
        CognitoRefreshTokenValidity="$COGNITO_REFRESH_TOKEN_VALIDITY" \
        DomainName="$DOMAIN_NAME" \
        ApiDomainName="$API_DOMAIN_NAME" \
        CertificateArn="$CERTIFICATE_ARN" \
        KmsKeyId="$KMS_KEY_ID" \
        PublicKeyContent="$PUBLIC_KEY_CONTENT" \
        SigninPagePath="$SIGNIN_PAGE_PATH" \
    --capabilities CAPABILITY_NAMED_IAM \
    --region "$REGION"

if [[ $? -eq 0 ]]; then
    print_status "Stack deployment completed successfully!"
    
    # Get stack outputs
    print_status "Retrieving stack outputs..."
    
    S3_BUCKET_URL=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" --query "Stacks[0].Outputs[?OutputKey=='S3BucketUrl'].OutputValue" --output text)
    CLOUDFRONT_DOMAIN=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" --query "Stacks[0].Outputs[?OutputKey=='CloudFrontDistributionDomain'].OutputValue" --output text)
    API_GATEWAY_URL=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" --query "Stacks[0].Outputs[?OutputKey=='ApiGatewayInvokeUrl'].OutputValue" --output text)
    
    echo
    print_status "Deployment Summary:"
    echo "  S3 Bucket URL: $S3_BUCKET_URL"
    echo "  CloudFront Domain: $CLOUDFRONT_DOMAIN"
    echo "  API Gateway URL: $API_GATEWAY_URL"
    echo
    
    print_warning "IMPORTANT: Manual steps required to complete setup:"
    echo "1. Configure DNS records to point your domains to CloudFront and API Gateway"
    echo "2. Upload your static WordPress files to the S3 bucket"
    echo "3. Test the cookie issuance endpoint with proper IAM authentication"
    echo "4. Verify that protected paths are properly secured"
    
else
    print_error "Stack deployment failed"
    exit 1
fi