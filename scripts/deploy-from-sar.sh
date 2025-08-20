#!/bin/bash

# WordPress Static Site Guardian - SAR User Deployment Script
# Deploy from AWS Serverless Application Repository

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
STACK_NAME=""
DOMAIN_NAME=""
API_DOMAIN_NAME=""
CERTIFICATE_ARN=""
KMS_KEY_ID=""
PUBLIC_KEY_CONTENT=""
PROTECTED_PATHS="/dashboard,/profile,/admin"
SIGNIN_PAGE_PATH="/signin"
COOKIE_EXPIRATION_DAYS=30
S3_BUCKET_NAME=""
S3_WWWROOT_PREFIX="wwwroot"
NOT_FOUND_PAGE_PATH="/404"
FORBIDDEN_PAGE_PATH="/403"
CREATE_DNS_RECORDS="true"
REGION="us-east-1"
APPLICATION_ID="arn:aws:serverlessrepo:us-east-1:123456789012:applications/wordpress-static-site-guardian"
ENABLE_LOGGING="false"

# Function to show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Deploy WordPress Static Site Guardian from AWS Serverless Application Repository

REQUIRED OPTIONS:
    -s, --stack-name STACK_NAME          CloudFormation stack name (required)
    -d, --domain DOMAIN                  Main domain for CloudFront (required)
    -a, --api-domain API_DOMAIN          API Gateway domain (required)
    -c, --certificate-arn ARN            ACM certificate ARN in us-east-1 (required)
    -k, --kms-key-id KEY_ID              KMS Key ID containing encrypted private key (required)
    -u, --public-key-content CONTENT     Base64 public key content (required)
    -w, --s3-wwwroot-prefix PREFIX       Non-empty S3 prefix that does not start or end with '/' (required)

OPTIONAL OPTIONS:
    -p, --protected-paths PATHS          Comma-separated protected paths (default: /dashboard,/profile,/admin)
    -i, --signin-path PATH               Path for sign-in page (default: /signin)
    -e, --expiration-days DAYS           Cookie expiration in days (default: 30)
    -b, --s3-bucket-name NAME            Custom S3 bucket name (optional, auto-generated if not provided)
    --not-found-page PATH                Custom 404 error page path (default: /404)
    --forbidden-page PATH                Custom 403 error page path (default: /403)
    --no-dns-records                     Skip creating Route53 DNS records (default: create records)
    -l, --enable-logging                 Enable detailed CloudWatch logging
    -r, --region REGION                  AWS region (default: us-east-1)
    --application-id APP_ID              SAR Application ID (default: public application)
    -h, --help                           Show this help message

EXAMPLES:
    # Basic deployment
    $0 -s my-wordpress-protection \\
       -d example.com \\
       -a api.example.com \\
       -c arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012 \\
       -k 12345678-1234-1234-1234-123456789012 \\
       -u "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."

    # With custom settings
    $0 -s my-stack \\
       -d site.com \\
       -a api.site.com \\
       -c arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012 \\
       -k 12345678-1234-1234-1234-123456789012 \\
       -u "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..." \\
       -w "wwwroot" \\
       -p "/admin,/members" \\
       -i "/login" \\
       -e 7 \\
       -b "my-custom-bucket-name" \\
       --enable-logging

PREREQUISITES:
    1. AWS CLI configured with appropriate permissions
    2. SSL certificate in ACM (us-east-1 region)
    3. KMS key and public key generated (use scripts/generate-cloudfront-keypair.sh)
    4. Domain DNS ready for configuration

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
        -e|--expiration-days)
            COOKIE_EXPIRATION_DAYS="$2"
            shift 2
            ;;
        -b|--s3-bucket-name)
            S3_BUCKET_NAME="$2"
            shift 2
            ;;
        -w|--s3-wwwroot-prefix)
            S3_WWWROOT_PREFIX="$2"
            shift 2
            ;;
        --not-found-page)
            NOT_FOUND_PAGE_PATH="$2"
            shift 2
            ;;
        --forbidden-page)
            FORBIDDEN_PAGE_PATH="$2"
            shift 2
            ;;
        --no-dns-records)
            CREATE_DNS_RECORDS="false"
            shift
            ;;
        -l|--enable-logging)
            ENABLE_LOGGING="true"
            shift
            ;;
        -r|--region)
            REGION="$2"
            shift 2
            ;;
        --application-id)
            APPLICATION_ID="$2"
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

print_status "Deploying WordPress Static Site Guardian from SAR..."
echo "  Stack Name: $STACK_NAME"
echo "  Domain: $DOMAIN_NAME"
echo "  API Domain: $API_DOMAIN_NAME"
echo "  Certificate ARN: $CERTIFICATE_ARN"
echo "  KMS Key ID: $KMS_KEY_ID"
echo "  Public Key Length: ${#PUBLIC_KEY_CONTENT} characters"
echo "  S3 WWWRoot Prefix: $S3_WWWROOT_PREFIX"
echo "  Protected Paths: $PROTECTED_PATHS"
echo "  Signin Path: $SIGNIN_PAGE_PATH"
echo "  Cookie Expiration: $COOKIE_EXPIRATION_DAYS days"
echo "  Enable Logging: $ENABLE_LOGGING"
echo "  Region: $REGION"
echo

# Check if AWS CLI is configured
if ! aws sts get-caller-identity --region "$REGION" &>/dev/null; then
    print_error "AWS CLI not configured or no valid credentials found"
    exit 1
fi

print_status "AWS CLI configured successfully"

# Deploy from SAR
print_status "Deploying from AWS Serverless Application Repository..."

aws serverlessrepo create-cloud-formation-change-set \
    --application-id "$APPLICATION_ID" \
    --stack-name "$STACK_NAME" \
    --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
    --parameter-overrides \
        ParameterKey=DomainName,ParameterValue="$DOMAIN_NAME" \
        ParameterKey=ApiDomainName,ParameterValue="$API_DOMAIN_NAME" \
        ParameterKey=CertificateArn,ParameterValue="$CERTIFICATE_ARN" \
        ParameterKey=KmsKeyId,ParameterValue="$KMS_KEY_ID" \
        ParameterKey=PublicKeyContent,ParameterValue="$PUBLIC_KEY_CONTENT" \
        ParameterKey=S3WWWRoot,ParameterValue="$S3_WWWROOT_PREFIX" \
        ParameterKey=ProtectedPaths,ParameterValue="$PROTECTED_PATHS" \
        ParameterKey=SigninPagePath,ParameterValue="$SIGNIN_PAGE_PATH" \
        ParameterKey=CookieExpirationDays,ParameterValue="$COOKIE_EXPIRATION_DAYS" \
        ParameterKey=S3BucketName,ParameterValue="$S3_BUCKET_NAME" \
        ParameterKey=NotFoundPagePath,ParameterValue="$NOT_FOUND_PAGE_PATH" \
        ParameterKey=ForbiddenPagePath,ParameterValue="$FORBIDDEN_PAGE_PATH" \
        ParameterKey=CreateDNSRecords,ParameterValue="$CREATE_DNS_RECORDS" \
        ParameterKey=EnableDetailedLogging,ParameterValue="$ENABLE_LOGGING" \
    --region "$REGION"

if [[ $? -ne 0 ]]; then
    print_error "Failed to create CloudFormation change set from SAR"
    exit 1
fi

print_status "Change set created successfully. Executing deployment..."

# Execute the change set
aws cloudformation execute-change-set \
    --change-set-name "serverlessrepo-$STACK_NAME" \
    --stack-name "$STACK_NAME" \
    --region "$REGION"

if [[ $? -ne 0 ]]; then
    print_error "Failed to execute CloudFormation change set"
    exit 1
fi

print_status "Deployment initiated. Waiting for completion..."

# Wait for stack creation to complete
aws cloudformation wait stack-create-complete \
    --stack-name "$STACK_NAME" \
    --region "$REGION"

if [[ $? -eq 0 ]]; then
    print_status "Stack deployment completed successfully!"
    
    # Get stack outputs
    print_status "Retrieving stack outputs..."
    
    S3_BUCKET_NAME=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" --query "Stacks[0].Outputs[?OutputKey=='S3BucketName'].OutputValue" --output text)
    CLOUDFRONT_DOMAIN=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" --query "Stacks[0].Outputs[?OutputKey=='CloudFrontDistributionDomain'].OutputValue" --output text)
    API_GATEWAY_URL=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" --query "Stacks[0].Outputs[?OutputKey=='ApiGatewayInvokeUrl'].OutputValue" --output text)
    
    echo
    print_status "Deployment Summary:"
    echo "  S3 Bucket: $S3_BUCKET_NAME"
    echo "  CloudFront Domain: $CLOUDFRONT_DOMAIN"
    echo "  API Gateway URL: $API_GATEWAY_URL"
    echo
    
    print_warning "IMPORTANT: Complete these final steps:"
    echo "1. Configure DNS records to point $DOMAIN_NAME to $CLOUDFRONT_DOMAIN"
    echo "2. Configure DNS records to point $API_DOMAIN_NAME to the API Gateway"
    echo "3. Upload your static WordPress files to S3 bucket: $S3_BUCKET_NAME/$S3_WWWROOT_PREFIX"
    echo "4. Test the cookie issuance endpoint with proper IAM authentication"
    echo "5. Verify that protected paths are properly secured"
    
    if [[ "$ENABLE_LOGGING" == "true" ]]; then
        DASHBOARD_URL=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" --query "Stacks[0].Outputs[?OutputKey=='MonitoringDashboard'].OutputValue" --output text)
        echo "6. Monitor your application: $DASHBOARD_URL"
    fi
    
else
    print_error "Stack deployment failed"
    exit 1
fi