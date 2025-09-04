# WordPress Static Site Guardian

**Enterprise-grade protection for static WordPress sites with CloudFront signed cookies and seamless authentication integration.**

## 🛡️ What This Application Does

WordPress Static Site Guardian provides comprehensive protection for static WordPress-generated sites using AWS CloudFront signed cookies. It creates a complete infrastructure that:

- **Protects Premium Content**: Secures specific paths (like `/dashboard`, `/members`, `/courses`) with authentication
- **Seamless User Experience**: Redirects unauthenticated users to your sign-in page with return URL preservation
- **Enterprise Security**: Uses RSA-SHA1 signed cookies with KMS-encrypted private keys
- **Global Performance**: Leverages CloudFront's global edge network for fast content delivery
- **Easy Integration**: Works with existing authentication systems like [Gatey Pro](https://wpsuite.io) and Amazon Cognito

## 🏗️ Architecture

This application creates:

- **S3 Bucket**: Secure static file hosting with public access blocked
- **CloudFront Distribution**: Global CDN with signed cookie authentication and custom error pages
- **API Gateway**: RESTful endpoint with custom domain for cookie issuance and management
- **Lambda Function**: Serverless cookie signing with RSA cryptography
- **CloudFront Functions**: Edge-based authentication and path rewriting logic
- **Route53 Records**: Automatic DNS configuration (optional)
- **KMS Integration**: Secure private key management
- **CloudWatch Monitoring**: Comprehensive logging and metrics (optional)

## 📋 Prerequisites

Before deploying this application, ensure you have:

### 1. SSL Certificate
- Valid SSL certificate in AWS Certificate Manager (ACM)
- **Must be in us-east-1 region** (required for CloudFront)
- Certificate must cover your domain and API subdomain

### 2. CloudFront Key Pair
Generate RSA key pairs using our provided script:

```bash
# Download the key generation script
curl -O https://raw.githubusercontent.com/smartcloudsol/wordpress-static-site-guardian/refs/heads/main/scripts/generate-cloudfront-keypair.sh
chmod +x generate-cloudfront-keypair.sh

# Generate keys and store in AWS
./generate-cloudfront-keypair.sh --name my-wordpress-keys --region us-east-1
```

This creates:
- **KMS Key ID**: Required for the `KmsKeyId` parameter
- **Public Key Content**: Required for the `PublicKeyContent` parameter
- **Private Key**: Securely stored in SSM Parameter Store

### 3. Domain Configuration
- Domain registered and DNS accessible
- API subdomain planned (e.g., `api.yourdomain.com`)

## 📦 Deployment Options

### Option 1: Deploy from AWS Serverless Application Repository (Recommended)
The easiest way to deploy WordPress Static Site Guardian is directly from the AWS Serverless Application Repository:

1. **Browse to SAR**: Visit the [AWS Serverless Application Repository](https://serverlessrepo.aws.amazon.com/applications)
2. **Search**: Look for "WordPress Static Site Guardian"
3. **Deploy**: Click "Deploy" and fill in the required parameters
4. **Complete Setup**: Follow the post-deployment instructions

**Note**: The SAR version uses custom Lambda resources to manage CloudFront components (Public Keys, Key Groups, Origin Access Control, and Functions) that are not natively supported by SAR. This approach maintains full functionality while ensuring compatibility with the AWS Serverless Application Repository.

### Option 2: Deploy Using Our SAR Script
Use our automated deployment script for SAR applications:

```bash
./scripts/deploy-from-sar.sh \
  --stack-name my-wordpress-protection \
  --domain example.com \
  --api-domain api.example.com \
  --certificate-arn arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012 \
  --kms-key-id 12345678-1234-1234-1234-123456789012 \
  --public-key-content "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..." \
  --enable-logging
```

## 🚀 Deployment Parameters

### Required Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| **DomainName** | Your main domain for CloudFront | `example.com` |
| **ApiDomainName** | API subdomain (must be subdomain of main domain) | `api.example.com` |
| **CertificateArn** | ACM certificate ARN in us-east-1 | `arn:aws:acm:us-east-1:123...` |
| **KmsKeyId** | KMS Key ID from key generation script | `12345678-1234-1234-1234-123456789012` |
| **PublicKeyContent** | Base64 public key from generation script | `MIIBIjANBgkqhkiG9w0BAQEF...` |
| **S3WWWRoot** | Non-empty S3 prefix that does not start or end with '/' | `wwwroot` |

### Optional Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| **ProtectedPaths** | `/dashboard,/profile,/admin` | Comma-separated paths to protect |
| **SigninPagePath** | `/signin` | Path to redirect unauthenticated users |
| **CookieExpirationDays** | `30` | Cookie lifetime (1-365 days) |
| **S3BucketName** | *(auto-generated)* | Custom S3 bucket name (optional) |
| **NotFoundPagePath** | `/404` | Custom 404 error page path |
| **ForbiddenPagePath** | `/403` | Custom 403 error page path |
| **CreateDNSRecords** | `true` | Automatically create Route53 DNS records |
| **EnableDetailedLogging** | `false` | Enable CloudWatch logging and monitoring |

## 📝 Post-Deployment Steps

After successful deployment:

### 1. DNS Configuration
- **Automatic**: If `CreateDNSRecords` is `true`, DNS records are created automatically in Route53
- **Manual**: If `CreateDNSRecords` is `false`, configure DNS manually using the provided outputs:
  - **Main Domain** → CloudFront Distribution Domain
  - **API Domain** → API Gateway Regional Domain
  - **WWW Subdomain** → CloudFront Distribution Domain

### 2. Upload Static Files

> **Important:** Upload your static WordPress site into the `<wwwroot>/` prefix of the created S3 bucket. The CloudFront and Lambda code expect all static content to be placed under `s3://<bucket-name>/<wwwroot>/`. Do not upload files directly to the bucket root.
Upload your WordPress static files to the S3 bucket, including:
- **Static Site Content**: All your WordPress-generated files
- **Error Pages**: Custom 404 and 403 pages (default: `/404`, `/403`)
- **Protected Content**: Files for protected paths in their respective directories

### 3. Test Protection
1. **Public Access**: Visit public pages to ensure they load correctly
2. **Protected Paths**: Visit protected paths - should redirect to your sign-in page
3. **Error Pages**: Test 404 and 403 error handling
4. **Cookie Issuance**: Test the API Gateway endpoint for cookie generation
5. **Authenticated Access**: Verify signed cookies grant access to protected content

### 4. Integrate with Authentication
Configure your authentication system ([Gatey Pro](https://wpsuite.io) API Settings and Sign-in/Sign-out Hooks, custom auth, etc.) to call the cookie issuance endpoint after successful login.

## 📊 Monitoring & Troubleshooting

### CloudWatch Logs (if enabled)
- **Lambda Function**: `/aws/lambda/[STACK_NAME]-cookie-signing`
- **API Gateway**: `/aws/apigateway/[STACK_NAME]-cookie-api`

### Common Issues

1. **403 Forbidden on Protected Paths**
   - Check CloudFront signed cookies are present
   - Verify cookie domain matches your domain
   - Ensure key group configuration is correct

2. **Cookies Not Being Set**
   - Verify API Gateway CORS configuration
   - Check Lambda function response headers
   - Confirm domain attributes in cookies

3. **Certificate Issues**
   - Ensure certificate is in us-east-1 region
   - Verify certificate covers all required domains

## 💰 Cost Estimation

Typical monthly costs for a medium-traffic site:

- **CloudFront**: ~$1-10 (depending on traffic)
- **Lambda**: ~$0.20-2 (depending on authentication frequency)
- **API Gateway**: ~$3.50 per million requests
- **S3**: ~$0.023 per GB storage
- **KMS**: $1 per key + $0.03 per 10K requests
- **CloudWatch**: ~$0.50-5 (if logging enabled)

**Total estimated cost**: $5-25/month for most use cases

## 🔒 Security Features

- **Zero Plaintext Storage**: Private keys encrypted with AWS KMS
- **Least Privilege IAM**: Minimal required permissions
- **Secure Cookies**: HttpOnly, Secure, SameSite attributes
- **HTTPS Enforcement**: TLS 1.2+ required
- **Edge Security**: Authentication logic runs at CloudFront edge locations
- **Audit Trail**: Comprehensive CloudWatch logging (optional)

## 📁 Project Structure

This project is organized into logical folders for better maintainability:

```
├── 📁 src/                    # Lambda function source code
├── 📁 scripts/                # Deployment and utility scripts  
├── 📁 tests/                  # Validation and testing scripts
├── 📄 template.yaml           # Main CloudFormation template
└── 📄 README.md               # This documentation
```

For detailed folder structure and usage examples, see [FOLDER_STRUCTURE.md](.kiro/fixes/FOLDER_STRUCTURE.md).

### Quick Start Commands

```bash
# Generate RSA keys
./scripts/generate-cloudfront-keypair.sh --name my-keys

# Deploy from SAR
./scripts/deploy-from-sar.sh --stack-name my-stack --domain example.com ...

# Validate template
./tests/validate-sam-template.sh --strict

# Run comprehensive tests
python3 tests/test_end_to_end.py
```
