# WordPress Static Site Guardian

**Enterprise-grade protection for static WordPress sites with CloudFront signed cookies and seamless authentication integration.**

## 🛡️ What This Application Does

WordPress Static Site Guardian provides comprehensive protection for static WordPress-generated sites using AWS CloudFront signed cookies with Lambda@Edge authentication. It creates a complete infrastructure that:

- **Protects Premium Content**: Secures specific paths (like `/dashboard`, `/members`, `/courses`) with JWT-based authentication
- **Seamless User Experience**: Redirects unauthenticated users to your sign-in page with return URL preservation
- **Enterprise Security**: Uses RSA-SHA1 signed cookies with KMS-encrypted private keys and JWT Bearer token authentication
- **Global Performance**: Leverages CloudFront's global edge network with Lambda@Edge for ultra-fast authentication
- **Easy Integration**: Works with Amazon Cognito User Pools and other JWT-compatible authentication systems

## 🏗️ Architecture

This application creates:

- **S3 Bucket**: Secure static file hosting with public access blocked
- **CloudFront Distribution**: Global CDN with signed cookie authentication, custom error pages, and `/issue-cookie*` behavior
- **Lambda@Edge Function**: Serverless cookie signing with JWT authentication and RSA cryptography at edge locations
- **CloudFront Functions**: Edge-based authentication and path rewriting logic
- **Route53 Records**: Automatic DNS configuration (optional)
- **KMS Integration**: Secure private key management
- **CloudWatch Monitoring**: Comprehensive logging and metrics with regional log groups (optional)

## 📋 Prerequisites

Before deploying this application, ensure you have:

### 1. SSL Certificate
- Valid SSL certificate in AWS Certificate Manager (ACM)
- **Must be in us-east-1 region** (required for CloudFront)
- Certificate must cover your domain

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
- Cognito User Pool configured for JWT authentication

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
  --certificate-arn arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012 \
  --kms-key-id 12345678-1234-1234-1234-123456789012 \
  --public-key-content "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..." \
  --cognito-user-pool-id us-east-1_abcdefghi \
  --cognito-app-client-ids "client1,client2" \
  --enable-logging
```

## 🚀 Deployment Parameters

### Required Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| **DomainName** | Your main domain for CloudFront | `example.com` |
| **CertificateArn** | ACM certificate ARN in us-east-1 | `arn:aws:acm:us-east-1:123...` |
| **CognitoUserPoolId** | Cognito User Pool ID for JWT issuer validation | `us-east-1_abcdefghi` |
| **CognitoAppClientIds** | Comma-separated Cognito App Client IDs for JWT audience validation | `client1,client2` |
| **KmsKeyId** | KMS Key ID from key generation script | `12345678-1234-1234-1234-123456789012` |
| **PublicKeyContent** | Base64 public key from generation script | `MIIBIjANBgkqhkiG9w0BAQEF...` |
| **S3WWWRoot** | Non-empty S3 prefix that does not start or end with '/' | `wwwroot` |

### Optional Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| **ProtectedPaths** | *(no default)* | Comma-separated paths to protect (e.g., `/dashboard,/profile`). Cannot include `/issue-cookie` |
| **SigninPagePath** | `/signin` | Path to redirect unauthenticated users |
| **CookieExpirationDays** | `30` | Cookie lifetime (1-365 days) |
| **S3BucketName** | *(auto-generated)* | Custom S3 bucket name (optional) |
| **NotFoundPagePath** | *(empty)* | Optional custom 404 error page path (see Error Pages section) |
| **ForbiddenPagePath** | *(empty)* | Optional custom 403 error page path (see Error Pages section) |
| **CreateDNSRecords** | `true` | Automatically create Route53 DNS records |
| **EnableDetailedLogging** | `false` | Enable CloudWatch logging and monitoring |

## 📝 Post-Deployment Steps

After successful deployment:

### 1. DNS Configuration
- **Automatic**: If `CreateDNSRecords` is `true`, DNS records are created automatically in Route53
- **Manual**: If `CreateDNSRecords` is `false`, configure DNS manually using the provided outputs:
  - **Main Domain** → CloudFront Distribution Domain
  - **WWW Subdomain** → CloudFront Distribution Domain

### 2. Upload Static Files

> **Important:** Upload your static WordPress site into the `<wwwroot>/` prefix of the created S3 bucket. The CloudFront and Lambda code expect all static content to be placed under `s3://<bucket-name>/<wwwroot>/`. Do not upload files directly to the bucket root.

Upload your WordPress static files to the S3 bucket, including:
- **Static Site Content**: All your WordPress-generated files
- **Protected Content**: Files for protected paths in their respective directories

### 3. Optional Error Pages Configuration

Error pages are **optional**. If you want custom 404 or 403 pages:

**Important**: Specify error page paths **relative to** the S3WWWRoot folder (do **not** include the S3WWWRoot prefix).

**Example**: If WordPress had a custom 404 page at `/404-2`, Simply Static would export it as `/404-2/index.html`. The correct parameter value is:
```
/404-2/index.html
```

This is because CloudFront error pages are fetched **from the origin (S3)**, not from a routed public URL.

**Configuration**:
- Leave `NotFoundPagePath` and `ForbiddenPagePath` empty to disable custom error pages
- If provided, ensure the files exist in your S3 bucket at the specified paths
- The system will only configure error responses for non-empty paths

### 4. Test Protection
1. **Public Access**: Visit public pages to ensure they load correctly
2. **Protected Paths**: Visit protected paths - should redirect to your sign-in page
3. **Error Pages**: Test 404 and 403 error handling
4. **Cookie Issuance**: Test the `/issue-cookie` endpoint with JWT Bearer token authentication
5. **Authenticated Access**: Verify signed cookies grant access to protected content

### 5. Integrate with Authentication
Configure your authentication system to call the cookie issuance endpoint after successful login:

#### JWT Bearer Token Authentication
The `/issue-cookie` endpoint requires a valid JWT Bearer token in the Authorization header:

```bash
# Issue cookies (signin)
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     "https://yourdomain.com/issue-cookie?action=signin"

# Expire cookies (signout)  
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     "https://yourdomain.com/issue-cookie?action=signout"
```

#### Cognito Integration
- Configure your Cognito User Pool ID and App Client IDs in the deployment parameters
- Use Cognito ID tokens or access tokens as Bearer tokens
- The system validates JWT issuer, audience, expiration, and signature automatically

## 📊 Monitoring & Troubleshooting

### CloudWatch Logs (if enabled)
- **Lambda@Edge Function**: `/aws/lambda/us-east-1.[STACK_NAME]-cookie-signing-edge` (and regional log groups)
- **CloudFront Functions**: Available in CloudFront console monitoring

### Common Issues

1. **403 Forbidden on Protected Paths**
   - Check CloudFront signed cookies are present
   - Verify cookie domain matches your domain
   - Ensure key group configuration is correct

2. **Cookies Not Being Set**
   - Verify JWT Bearer token is valid and properly formatted
   - Check Lambda@Edge function response headers in CloudWatch logs
   - Confirm host-only cookies are being set (no Domain attribute)

3. **Certificate Issues**
   - Ensure certificate is in us-east-1 region
   - Verify certificate covers all required domains

## 💰 Cost Estimation

Typical monthly costs for a medium-traffic site:

- **CloudFront**: ~$1-10 (depending on traffic)
- **Lambda@Edge**: ~$0.60 per million requests + $0.50 per GB-second
- **S3**: ~$0.023 per GB storage
- **KMS**: $1 per key + $0.03 per 10K requests
- **CloudWatch**: ~$0.50-5 (if logging enabled)

**Total estimated cost**: $3-20/month for most use cases (lower than API Gateway version)

## 🔒 Security Features

- **Zero Plaintext Storage**: Private keys encrypted with AWS KMS
- **JWT Authentication**: Industry-standard JWT Bearer token validation with JWKS
- **Least Privilege IAM**: Minimal required permissions
- **Host-Only Cookies**: Secure cookies without Domain attribute for better security
- **HTTPS Enforcement**: TLS 1.2+ required
- **Edge Security**: Authentication logic runs at CloudFront edge locations globally
- **Audit Trail**: Comprehensive CloudWatch logging with regional log groups (optional)

## 🌐 Lambda@Edge Benefits

- **Global Performance**: Authentication happens at CloudFront edge locations worldwide
- **Reduced Latency**: No API Gateway round-trip for cookie issuance
- **Cost Effective**: Lower costs compared to API Gateway architecture
- **Simplified Architecture**: Fewer moving parts and dependencies
- **Regional Logging**: Lambda@Edge logs appear in CloudWatch logs in the region where the function executed

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
