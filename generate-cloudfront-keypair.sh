#!/bin/bash

# CloudFront Key Pair Generation Script
# Generates RSA key pair for CloudFront signed cookies and uploads private key to KMS

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
KEY_NAME="cloudfront-keypair"
KEY_SIZE=2048
OUTPUT_DIR="./keys"
REGION="us-east-1"
KMS_KEY_DESCRIPTION="CloudFront signing private key"

# Function to show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Generate RSA key pair for CloudFront signed cookies

OPTIONS:
    -n, --name NAME                      Key pair name (default: cloudfront-keypair)
    -s, --size SIZE                      Key size in bits (default: 2048)
    -o, --output-dir DIR                 Output directory (default: ./keys)
    -r, --region REGION                  AWS region for KMS (default: us-east-1)
    -h, --help                           Show this help message

EXAMPLES:
    $0
    $0 -n my-cloudfront-key -s 4096 -o /path/to/keys -r us-west-2

OUTPUT:
    - {name}_public.pem: Public key (for CloudFormation template)
    - {name}_public_formatted.txt: Public key formatted for CloudFormation
    - KMS Key ID: Stored in AWS KMS for secure private key management
    - kms_key_info.json: KMS key details for CloudFormation

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--name)
            KEY_NAME="$2"
            shift 2
            ;;
        -s|--size)
            KEY_SIZE="$2"
            shift 2
            ;;
        -o|--output-dir)
            OUTPUT_DIR="$2"
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

# Validate key size
if [[ ! "$KEY_SIZE" =~ ^(1024|2048|4096)$ ]]; then
    print_error "Invalid key size. Must be 1024, 2048, or 4096"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

print_status "Generating CloudFront key pair..."
echo "  Key Name: $KEY_NAME"
echo "  Key Size: $KEY_SIZE bits"
echo "  Output Directory: $OUTPUT_DIR"
echo "  AWS Region: $REGION"
echo

# Check if AWS CLI is available and configured
if ! command -v aws &> /dev/null; then
    print_error "AWS CLI is not installed or not in PATH"
    exit 1
fi

if ! aws sts get-caller-identity --region "$REGION" &>/dev/null; then
    print_error "AWS CLI not configured or no valid credentials found for region $REGION"
    exit 1
fi

# Check if OpenSSL is available
if ! command -v openssl &> /dev/null; then
    print_error "OpenSSL is not installed or not in PATH"
    exit 1
fi

# Generate private key
PRIVATE_KEY_FILE="$OUTPUT_DIR/${KEY_NAME}_private.pem"
PUBLIC_KEY_FILE="$OUTPUT_DIR/${KEY_NAME}_public.pem"
PUBLIC_KEY_FORMATTED_FILE="$OUTPUT_DIR/${KEY_NAME}_public_formatted.txt"
KMS_INFO_FILE="$OUTPUT_DIR/kms_key_info.json"

print_status "Generating private key..."
openssl genrsa -out "$PRIVATE_KEY_FILE" "$KEY_SIZE"

if [[ $? -ne 0 ]]; then
    print_error "Failed to generate private key"
    exit 1
fi

print_status "Generating public key..."
openssl rsa -in "$PRIVATE_KEY_FILE" -pubout -out "$PUBLIC_KEY_FILE"

if [[ $? -ne 0 ]]; then
    print_error "Failed to generate public key"
    exit 1
fi

# Format public key for CloudFormation (remove headers and join lines)
print_status "Formatting public key for CloudFormation..."
grep -v "BEGIN PUBLIC KEY" "$PUBLIC_KEY_FILE" | grep -v "END PUBLIC KEY" | tr -d '\n' > "$PUBLIC_KEY_FORMATTED_FILE"

# Create KMS key for storing private key
print_status "Creating KMS key for private key storage..."
KMS_KEY_OUTPUT=$(aws kms create-key \
    --region "$REGION" \
    --description "$KMS_KEY_DESCRIPTION for $KEY_NAME" \
    --key-usage ENCRYPT_DECRYPT \
    --key-spec SYMMETRIC_DEFAULT \
    --output json)

if [[ $? -ne 0 ]]; then
    print_error "Failed to create KMS key"
    exit 1
fi

KMS_KEY_ID=$(echo "$KMS_KEY_OUTPUT" | jq -r '.KeyMetadata.KeyId')
KMS_KEY_ARN=$(echo "$KMS_KEY_OUTPUT" | jq -r '.KeyMetadata.Arn')

print_status "Created KMS key: $KMS_KEY_ID"

# Create alias for the KMS key
KMS_ALIAS="alias/${KEY_NAME}-private-key"
aws kms create-alias \
    --region "$REGION" \
    --alias-name "$KMS_ALIAS" \
    --target-key-id "$KMS_KEY_ID" &>/dev/null

# Store private key in SSM Parameter Store (encrypted with KMS)
print_status "Storing private key in SSM Parameter Store..."
PRIVATE_KEY_CONTENT=$(cat "$PRIVATE_KEY_FILE")
SSM_PARAMETER_NAME="/cloudfront/private-key/$KMS_KEY_ID"

aws ssm put-parameter \
    --region "$REGION" \
    --name "$SSM_PARAMETER_NAME" \
    --value "$PRIVATE_KEY_CONTENT" \
    --type "SecureString" \
    --key-id "$KMS_KEY_ID" \
    --description "CloudFront signing private key for $KEY_NAME" \
    --overwrite

if [[ $? -ne 0 ]]; then
    print_error "Failed to store private key in SSM Parameter Store"
    exit 1
fi

print_status "Private key stored in SSM Parameter Store: $SSM_PARAMETER_NAME"

# Store KMS information for CloudFormation
cat > "$KMS_INFO_FILE" << EOF
{
  "KmsKeyId": "$KMS_KEY_ID",
  "KmsKeyArn": "$KMS_KEY_ARN",
  "KmsAlias": "$KMS_ALIAS",
  "Region": "$REGION",
  "SsmParameterName": "$SSM_PARAMETER_NAME"
}
EOF

# Set appropriate permissions
chmod 600 "$PRIVATE_KEY_FILE"
chmod 644 "$PUBLIC_KEY_FILE"
chmod 644 "$PUBLIC_KEY_FORMATTED_FILE"
chmod 644 "$KMS_INFO_FILE"

print_status "Key pair generated and stored successfully!"
echo
echo "Files created:"
echo "  Private Key: $PRIVATE_KEY_FILE (local copy - securely delete after verification)"
echo "  Public Key: $PUBLIC_KEY_FILE"
echo "  Formatted Public Key: $PUBLIC_KEY_FORMATTED_FILE"
echo "  KMS Key Info: $KMS_INFO_FILE"
echo
echo "AWS Resources created:"
echo "  KMS Key ID: $KMS_KEY_ID"
echo "  KMS Key ARN: $KMS_KEY_ARN"
echo "  KMS Alias: $KMS_ALIAS"
echo "  SSM Parameter: $SSM_PARAMETER_NAME"
echo

print_warning "IMPORTANT SECURITY NOTES:"
echo "1. Private key is now securely stored in AWS SSM Parameter Store (encrypted with KMS)"
echo "2. You can safely delete the local private key file after verification"
echo "3. The KMS key ID will be used by your Lambda function for decryption"
echo "4. The public key content will be automatically used in your CloudFormation template"
echo

print_status "Next steps:"
echo "1. Copy the content of $PUBLIC_KEY_FORMATTED_FILE"
echo "2. Replace <PUBLIC_KEY_PLACEHOLDER> in wordpress-protection-infrastructure.yaml"
echo "3. Use the KMS Key ID ($KMS_KEY_ID) as the KmsKeyId parameter in CloudFormation"
echo "4. Deploy your CloudFormation stack"
echo "5. Securely delete the local private key file: rm $PRIVATE_KEY_FILE"

# Display the formatted public key content
echo
print_status "Formatted public key content (copy this):"
echo "----------------------------------------"
cat "$PUBLIC_KEY_FORMATTED_FILE"
echo
echo "----------------------------------------"

echo
print_status "KMS Key ID for CloudFormation parameter:"
echo "----------------------------------------"
echo "$KMS_KEY_ID"
echo "----------------------------------------"