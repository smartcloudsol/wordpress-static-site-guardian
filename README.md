# WordPress Static Site Guardian

**Enterprise-grade protection for static WordPress sites with CloudFront signed cookies and seamless authentication integration.**

## 🛡️ What This Application Does

WordPress Static Site Guardian provides comprehensive protection for static WordPress-generated sites using AWS CloudFront signed cookies. It creates a complete infrastructure that:

- **Protects Premium Content**: Secures specific paths (like `/dashboard`, `/members`, `/courses`) with authentication
- **Seamless User Experience**: Redirects unauthenticated users to your sign-in page with return URL preservation
- **Enterprise Security**: Uses RSA-SHA1 signed cookies with KMS-encrypted private keys
- **Global Performance**: Leverages CloudFront's global edge network for fast content delivery
- **Easy Integration**: Works with existing authentication systems like Gatey Pro and Amazon Cognito

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
curl -O https://raw.githubusercontent.com/your-repo/wordpress-static-site-guardian/main/generate-cloudfront-keypair.sh
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

## 🚀 Deployment Parameters

### Required Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| **DomainName** | Your main domain for CloudFront | `example.com` |
| **ApiDomainName** | API subdomain (must be subdomain of main domain) | `api.example.com` |
| **CertificateArn** | ACM certificate ARN in us-east-1 | `arn:aws:acm:us-east-1:123...` |
| **KmsKeyId** | KMS Key ID from key generation script | `12345678-1234-1234-1234-123456789012` |
| **PublicKeyContent** | Base64 public key from generation script | `MIIBIjANBgkqhkiG9w0BAQEF...` |

### Optional Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| **ProtectedPaths** | `/dashboard,/profile,/admin` | Comma-separated paths to protect |
| **SigninPath** | `/signin` | Path to redirect unauthenticated users |
| **CookieExpirationDays** | `30` | Cookie lifetime (1-365 days) |
| **S3BucketName** | *(auto-generated)* | Custom S3 bucket name (optional) |
| **NotFoundPagePath** | `/404.html` | Custom 404 error page path |
| **ForbiddenPagePath** | `/403.html` | Custom 403 error page path |
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
Upload your WordPress static files to the S3 bucket, including:
- **Static Site Content**: All your WordPress-generated files
- **Error Pages**: Custom 404 and 403 pages (default: `/404.html`, `/403.html`)
- **Protected Content**: Files for protected paths in their respective directories

### 3. Test Protection
1. **Public Access**: Visit public pages to ensure they load correctly
2. **Protected Paths**: Visit protected paths - should redirect to your sign-in page
3. **Error Pages**: Test 404 and 403 error handling
4. **Cookie Issuance**: Test the API Gateway endpoint for cookie generation
5. **Authenticated Access**: Verify signed cookies grant access to protected content

### 4. Integrate with Authentication
Configure your authentication system (Gatey Pro, custom auth, etc.) to call the cookie issuance endpoint after successful login.

## 🔧 Integration Examples

### Gatey Pro Integration

```javascript
// Sign-In Hook
const response = await fetch('https://api.yourdomain.com/prod/issue-cookie', {
  method: 'GET',
  headers: {
    'Authorization': 'AWS4-HMAC-SHA256 ...' // Properly signed request
  }
});

if (response.ok) {
  // Cookies set automatically, redirect to protected content
  window.location.href = '/dashboard';
}
```

### Custom Authentication

```javascript
// After successful authentication
fetch('/api/auth/success', {
  method: 'POST',
  body: JSON.stringify({ userId: user.id })
})
.then(() => {
  // Call your cookie issuance endpoint
  return fetch('https://api.yourdomain.com/prod/issue-cookie', {
    method: 'GET',
    headers: { 'Authorization': generateAWSSignature() }
  });
})
.then(() => {
  window.location.href = '/protected-content';
});
```

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

---

# WordPress Static Site Guardian

**🚀 Now Available in AWS Serverless Application Repository!**

WordPress Static Site Guardian is a complete, enterprise-grade infrastructure solution for protecting static WordPress-generated sites using CloudFront signed cookies, API Gateway, and Lambda functions. Now available as a one-click deployable application in the AWS Serverless Application Repository (SAR).

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
./deploy-from-sar.sh \
  --stack-name my-wordpress-protection \
  --domain example.com \
  --api-domain api.example.com \
  --certificate-arn arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012 \
  --kms-key-id 12345678-1234-1234-1234-123456789012 \
  --public-key-content "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..." \
  --enable-logging
```

### Option 3: Deploy from Source (Advanced)
For developers who want to customize or contribute to the project, you can deploy from the source code using the traditional CloudFormation approach.

## Architecture Overview

- **S3 Bucket**: Hosts static site files with public access blocked
- **CloudFront Distribution**: Serves content with signed cookie protection for specific paths
- **API Gateway**: Provides `/issue-cookie` endpoint for authentication
- **Lambda Function**: Issues and manages signed cookies with RSA signing
- **CloudFront Key Group**: Manages public keys for cookie verification
- **KMS Integration**: Secure private key storage and encryption
- **SSM Parameter Store**: Encrypted private key retrieval for Lambda functions

## Prerequisites

1. **AWS CLI** configured with appropriate permissions (see IAM Requirements below)
2. **SSL Certificate** in AWS Certificate Manager (ACM) in `us-east-1` region
3. **Python 3.12+** and **pip3** for Lambda layer creation (auto-detected by scripts)
4. **OpenSSL** for key pair generation
5. **jq** for JSON processing in scripts
6. **SAM CLI** for building and deploying serverless applications
7. **Domain DNS** configured to point to CloudFront distribution
8. **Gatey Pro** configured with Amazon Cognito integration

## Required IAM Permissions

Your AWS CLI user/role needs the following permissions to run the deployment scripts:

### Core CloudFormation Permissions
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudformation:CreateStack",
        "cloudformation:UpdateStack",
        "cloudformation:DeleteStack",
        "cloudformation:DescribeStacks",
        "cloudformation:DescribeStackEvents",
        "cloudformation:DescribeStackResources",
        "cloudformation:ValidateTemplate",
        "cloudformation:GetTemplate"
      ],
      "Resource": "*"
    }
  ]
}
```

### AWS Service Permissions
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:PutBucketPolicy",
        "s3:PutBucketPublicAccessBlock",
        "s3:PutEncryptionConfiguration",
        "s3:PutVersioningConfiguration",
        "s3:GetBucketLocation"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "cloudfront:CreateDistribution",
        "cloudfront:UpdateDistribution",
        "cloudfront:DeleteDistribution",
        "cloudfront:GetDistribution",
        "cloudfront:CreatePublicKey",
        "cloudfront:UpdatePublicKey",
        "cloudfront:DeletePublicKey",
        "cloudfront:GetPublicKey",
        "cloudfront:CreateKeyGroup",
        "cloudfront:UpdateKeyGroup",
        "cloudfront:DeleteKeyGroup",
        "cloudfront:GetKeyGroup",
        "cloudfront:CreateFunction",
        "cloudfront:UpdateFunction",
        "cloudfront:DeleteFunction",
        "cloudfront:GetFunction",
        "cloudfront:PublishFunction",
        "cloudfront:CreateOriginAccessControl",
        "cloudfront:DeleteOriginAccessControl",
        "cloudfront:GetOriginAccessControl"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "lambda:CreateFunction",
        "lambda:UpdateFunctionCode",
        "lambda:UpdateFunctionConfiguration",
        "lambda:DeleteFunction",
        "lambda:GetFunction",
        "lambda:AddPermission",
        "lambda:RemovePermission",
        "lambda:PublishLayerVersion",
        "lambda:DeleteLayerVersion",
        "lambda:GetLayerVersion"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "apigateway:POST",
        "apigateway:GET",
        "apigateway:PUT",
        "apigateway:DELETE",
        "apigateway:PATCH"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:GetRole",
        "iam:PassRole",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:PutRolePolicy",
        "iam:DeleteRolePolicy",
        "iam:GetRolePolicy"
      ],
      "Resource": "*"
    }
  ]
}
```

### KMS and SSM Permissions
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:CreateKey",
        "kms:CreateAlias",
        "kms:DeleteAlias",
        "kms:DescribeKey",
        "kms:GetKeyPolicy",
        "kms:PutKeyPolicy",
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ssm:PutParameter",
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:DeleteParameter",
        "ssm:DescribeParameters"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

### Minimal Policy Example
For a complete minimal policy, you can use:
```bash
# Create a policy file
cat > wordpress-protection-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudformation:*",
        "s3:*",
        "cloudfront:*",
        "lambda:*",
        "apigateway:*",
        "iam:*",
        "kms:*",
        "ssm:*",
        "sts:GetCallerIdentity",
        "acm:ListCertificates",
        "acm:DescribeCertificate"
      ],
      "Resource": "*"
    }
  ]
}
EOF

# Attach to your user/role
aws iam put-user-policy --user-name YOUR_USERNAME --policy-name WordPressProtectionPolicy --policy-document file://wordpress-protection-policy.json
```

## 🚀 Quick Start Guide

### Step 1: Generate CloudFront Key Pair

Before deploying, generate RSA key pairs and store them securely in AWS:

```bash
# Generate key pair and store in AWS KMS + SSM
./generate-cloudfront-keypair.sh \
  --name my-wordpress-keys \
  --region us-east-1 \
  --size 2048
```

This will output:
- **KMS Key ID**: Required for deployment
- **Public Key Content**: Required for deployment  
- **SSM Parameter**: Where the private key is securely stored

### Step 2: Deploy from SAR (Recommended)

#### Option A: AWS Console
1. Go to [AWS Serverless Application Repository](https://serverlessrepo.aws.amazon.com/applications)
2. Search for "WordPress Static Site Guardian"
3. Click "Deploy" and enter your parameters
4. Wait for deployment to complete

#### Option B: Command Line
```bash
./deploy-from-sar.sh \
  --stack-name my-wordpress-protection \
  --domain example.com \
  --api-domain api.example.com \
  --certificate-arn arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012 \
  --kms-key-id 12345678-1234-1234-1234-123456789012 \
  --public-key-content "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..." \
  --protected-paths "/dashboard,/profile,/admin" \
  --signin-path "/signin" \
  --expiration-days 30 \
  --s3-bucket-name "my-custom-bucket" \
  --not-found-page "/custom-404.html" \
  --forbidden-page "/custom-403.html" \
  --enable-logging
```

### Step 3: Complete Setup

After successful deployment:

#### A. Configure DNS Records
Point your domains to the CloudFront distribution and API Gateway endpoints (provided in stack outputs).

#### B. Upload Static Files
Upload your WordPress static files to the S3 bucket created by the stack.

#### C. Test Protection
1. Visit a protected path (should redirect to signin)
2. Test cookie issuance via API Gateway
3. Verify authenticated access works

#### D. Monitor (Optional)
If logging is enabled, use the CloudWatch dashboard to monitor your application.

## 🔧 SAR Compatibility Architecture

The AWS Serverless Application Repository has limitations on supported CloudFormation resource types. To work around this, our SAR-compatible version uses:

### **Custom Lambda Resources**
- **CloudFront Public Key Management**: Custom resource Lambda function creates and manages CloudFront public keys
- **Key Group Management**: Automated key group creation and association
- **Origin Access Control**: Dynamic OAC creation for S3 bucket security
- **CloudFront Function Deployment**: Automated deployment of edge authentication logic

### **Benefits of This Approach**
- **Full Functionality**: All features work exactly the same as the direct CloudFormation deployment
- **SAR Compatibility**: Meets all AWS Serverless Application Repository requirements
- **Automated Management**: Custom resources handle the complete lifecycle (create, update, delete)
- **Error Handling**: Robust error handling and rollback capabilities

### **Technical Implementation**
The custom resource Lambda function (`cloudfront_manager.py`) handles:
- CloudFront API calls for unsupported resource types
- Proper resource lifecycle management
- CloudFormation response handling
- Error recovery and cleanup

## 🛠️ Advanced Deployment (From Source)

For developers who want to customize the solution or deploy from source:

### 1. Deploy Infrastructure from Source

```bash
./deploy-infrastructure.sh \
  --stack-name my-wordpress-protection \
  --domain example.com \
  --api-domain api.example.com \
  --certificate-arn arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012 \
  --kms-key-id 12345678-1234-1234-1234-123456789012 \
  --public-key-content "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..." \
  --protected-paths "/dashboard,/profile,/admin" \
  --signin-path "/signin" \
  --token-validity 30
```

### 2. Publish to Your Own SAR

```bash
# Build and publish to your own SAR
./deploy-sar.sh \
  --bucket my-sar-artifacts-bucket \
  --region us-east-1 \
  --version 1.0.0
```

## Key Management & Security

### Automated Key Management
The solution implements enterprise-grade key management:

- **RSA Key Generation**: Automated 2048-bit RSA key pair creation
- **KMS Encryption**: Private keys encrypted using AWS KMS
- **SSM Parameter Store**: Secure storage with automatic decryption
- **Public Key Injection**: Automatic CloudFormation template population
- **Key Rotation**: Support for key rotation without service interruption

### Security Features
- **Zero Plaintext Storage**: Private keys never stored in plaintext
- **Least Privilege IAM**: Minimal required permissions for each component
- **Secure Cookies**: HttpOnly, Secure, SameSite attributes
- **HTTPS Enforcement**: All communication over TLS
- **Path-Based Protection**: Granular access control per URL path

## CloudFront Function Implementation

The CloudFront Function is automatically implemented and dynamically configured:

### Core Functionality
1. **Dynamic Path Parsing**: Reads protected paths from CloudFormation parameters
2. **Cookie Validation**: Verifies CloudFront signed cookies on protected routes
3. **Smart Redirects**: Redirects unauthenticated users with return URL preservation
4. **Path Rewriting**: Maps user-friendly URLs to internal restricted paths
5. **Edge Case Handling**: Manages trailing slashes, exact matches, and nested paths

### Path Mapping Examples
- `/dashboard` → `/restricted-0/` (internal CloudFront path)
- `/profile/settings` → `/restricted-1/settings`
- `/admin/users` → `/restricted-2/users`

The function automatically adapts to your configuration with zero manual intervention!

## Lambda Function Features

### Cookie Signing Implementation
- **RSA-SHA1 Signing**: CloudFront-compliant digital signatures
- **Policy Generation**: Dynamic policy creation for multiple protected paths
- **Base64 Encoding**: CloudFront-safe character encoding
- **Expiration Management**: Configurable cookie lifetime
- **Fallback Mechanisms**: Graceful degradation when keys unavailable

### AWS Integration
- **KMS Decryption**: Secure private key retrieval
- **SSM Parameter Store**: Encrypted parameter access
- **CloudWatch Logging**: Comprehensive operation logging
- **Error Handling**: Robust exception management

## API Gateway Usage

### Issue Signed Cookies (Sign In)

```bash
curl -X GET "https://api.example.com/prod/issue-cookie" \
  -H "Authorization: AWS4-HMAC-SHA256 Credential=ACCESS_KEY/DATE/REGION/execute-api/aws4_request, SignedHeaders=host;x-amz-date, Signature=SIGNATURE" \
  -H "X-Amz-Date: DATE" \
  -v
```

### Expire Cookies (Sign Out)

```bash
curl -X GET "https://api.example.com/prod/issue-cookie?action=signout" \
  -H "Authorization: AWS4-HMAC-SHA256 Credential=ACCESS_KEY/DATE/REGION/execute-api/aws4_request, SignedHeaders=host;x-amz-date, Signature=SIGNATURE" \
  -H "X-Amz-Date: DATE" \
  -v
```

## Gatey Pro Integration

### Sign-In Hook Configuration

Configure Gatey Pro to call your API Gateway endpoint after successful authentication:

```javascript
// Gatey Pro Sign-In Hook
const response = await fetch('https://api.example.com/prod/issue-cookie', {
  method: 'GET',
  headers: {
    'Authorization': 'AWS4-HMAC-SHA256 ...' // Properly signed request
  }
});

if (response.ok) {
  // Cookies will be set automatically via Set-Cookie headers
  window.location.href = '/dashboard'; // Redirect to protected content
}
```

### Sign-Out Hook Configuration

```javascript
// Gatey Pro Sign-Out Hook
const response = await fetch('https://api.example.com/prod/issue-cookie?action=signout', {
  method: 'GET',
  headers: {
    'Authorization': 'AWS4-HMAC-SHA256 ...' // Properly signed request
  }
});

if (response.ok) {
  // Cookies will be expired
  window.location.href = '/'; // Redirect to home page
}
```

## Advanced Configuration

### Environment Variables
The Lambda function uses these environment variables:
- `CLOUDFRONT_DOMAIN`: Distribution domain name
- `KEY_PAIR_ID`: CloudFront public key identifier
- `COOKIE_EXPIRATION_DAYS`: Cookie lifetime in days
- `PROTECTED_PATHS`: Comma-separated list of protected paths
- `KMS_KEY_ID`: KMS key for private key decryption
- `AWS_REGION_NAME`: AWS region for service calls

### CloudFormation Parameters
Key parameters for customization:
- `ProtectedPaths`: List of paths to protect
- `SigninPath`: Custom sign-in page path
- `CognitoRefreshTokenValidity`: Cookie expiration alignment
- `KmsKeyId`: KMS key for private key storage
- `PublicKeyContent`: RSA public key content
- `LambdaLayerArn`: Optional cryptography layer

### Lambda Layer Usage
For full RSA signing capabilities:
```yaml
# In CloudFormation template
Layers: 
  - arn:aws:lambda:us-east-1:123456789012:layer:cloudfront-crypto-layer:1
```

## Security Best Practices

### Infrastructure Security
1. **KMS Key Management**: Rotate KMS keys regularly
2. **SSM Parameter Encryption**: Use customer-managed KMS keys
3. **IAM Role Boundaries**: Implement permission boundaries
4. **VPC Endpoints**: Use VPC endpoints for AWS service calls
5. **CloudTrail Logging**: Enable comprehensive audit logging

### Application Security
1. **Cookie Security**: Secure, HttpOnly, SameSite attributes enforced
2. **HTTPS Enforcement**: TLS 1.2+ required for all communications
3. **Token Validation**: Cryptographic signature verification
4. **Path Traversal Protection**: Input sanitization and validation
5. **Rate Limiting**: API Gateway throttling configured

### Operational Security
1. **Monitoring**: CloudWatch alarms for failed authentications
2. **Log Analysis**: Centralized logging with anomaly detection
3. **Key Rotation**: Automated key rotation procedures
4. **Backup Strategy**: Cross-region backup of critical parameters
5. **Incident Response**: Documented security incident procedures

## Monitoring and Troubleshooting

### CloudWatch Logs
- **Lambda Function**: `/aws/lambda/[STACK_NAME]-cookie-signing`
- **API Gateway**: Enable execution and access logging in stage settings
- **CloudFront Function**: Real-time logs in CloudWatch (if enabled)

### Monitoring Dashboards
Create CloudWatch dashboards to monitor:
- Cookie issuance success/failure rates
- Lambda function duration and errors
- API Gateway request counts and latency
- CloudFront cache hit ratios and error rates

### Common Issues and Solutions

#### Authentication Issues
1. **403 Forbidden on Protected Paths**
   - Verify CloudFront signed cookies are present
   - Check cookie domain and path attributes
   - Validate key group configuration
   - Ensure clock synchronization for expiration times

2. **Cookies Not Being Set**
   - Check Lambda function response headers
   - Verify API Gateway CORS configuration
   - Confirm domain attribute matches request domain
   - Review browser security policies

#### Infrastructure Issues
3. **Certificate Problems**
   - Ensure ACM certificate is in `us-east-1` region
   - Verify certificate covers all required domains
   - Check certificate validation status

4. **KMS/SSM Access Errors**
   - Verify Lambda execution role permissions
   - Check KMS key policy allows Lambda access
   - Confirm SSM parameter exists and is accessible
   - Review CloudWatch logs for specific error messages

#### Performance Issues
5. **High Lambda Cold Start Times**
   - Consider provisioned concurrency for high-traffic sites
   - Optimize Lambda function code and dependencies
   - Use Lambda layers for shared libraries

6. **CloudFront Cache Issues**
   - Review cache behaviors and TTL settings
   - Check if protected content is being cached
   - Verify Origin Access Control configuration

### Debugging Commands

```bash
# Check Lambda function logs
aws logs describe-log-groups --log-group-name-prefix "/aws/lambda/my-stack-cookie-signing"

# Test API Gateway endpoint
curl -X GET "https://api.example.com/prod/issue-cookie" \
  -H "Authorization: AWS4-HMAC-SHA256 ..." \
  -v

# Verify SSM parameter
aws ssm get-parameter --name "/cloudfront/private-key/YOUR-KMS-KEY-ID" --with-decryption

# Check CloudFront distribution status
aws cloudfront get-distribution --id YOUR-DISTRIBUTION-ID
```

## Cost Optimization

- Use CloudFront PriceClass_100 for cost optimization (included in template)
- Enable S3 versioning only if needed
- Monitor Lambda invocations and optimize timeout settings

## Cost Optimization

### Infrastructure Costs
- **CloudFront**: Use PriceClass_100 for cost optimization (included)
- **Lambda**: Optimize memory allocation and execution time
- **API Gateway**: Consider caching for frequently accessed endpoints
- **S3**: Use Intelligent Tiering for static assets
- **KMS**: Monitor key usage and optimize encryption calls

### Estimated Monthly Costs (US East)
- **CloudFront**: $0.085/GB + $0.0075/10K requests
- **Lambda**: $0.20/1M requests + $0.0000166667/GB-second
- **API Gateway**: $3.50/1M requests
- **S3**: $0.023/GB storage + $0.0004/1K requests
- **KMS**: $1/month/key + $0.03/10K requests
- **SSM**: No additional charges for standard parameters

## 📋 Production Deployment Checklist

### Pre-Deployment Requirements
- [ ] SSL certificate provisioned in ACM (us-east-1 region)
- [ ] Domain DNS ready for configuration
- [ ] AWS CLI configured with appropriate permissions
- [ ] Key pair generated using `generate-cloudfront-keypair.sh`
- [ ] KMS Key ID and Public Key Content available

### SAR Deployment Process
- [ ] Application found in AWS Serverless Application Repository
- [ ] All required parameters provided correctly
- [ ] Stack deployment initiated successfully
- [ ] CloudFormation stack creation completed (15-20 minutes)
- [ ] All resources created without errors

### Post-Deployment Validation
- [ ] DNS records configured and propagated
- [ ] SSL certificate validation successful
- [ ] S3 bucket accessible and files uploaded
- [ ] CloudFront distribution serving content
- [ ] Protected paths redirecting unauthenticated users
- [ ] API Gateway cookie endpoint responding
- [ ] Lambda function executing without errors
- [ ] Signed cookies granting access to protected content
- [ ] Sign-out functionality expiring cookies properly

### Security & Monitoring Validation
- [ ] Private keys secured in SSM Parameter Store
- [ ] IAM roles following least privilege principle
- [ ] All communications over HTTPS (TLS 1.2+)
- [ ] Cookie security attributes properly configured
- [ ] CloudWatch logging enabled (if selected)
- [ ] Monitoring dashboard accessible (if enabled)
- [ ] No sensitive data exposed in logs or outputs

### Performance & Cost Optimization
- [ ] CloudFront cache behaviors optimized
- [ ] Lambda function memory and timeout configured appropriately
- [ ] S3 storage class optimized for access patterns
- [ ] CloudWatch log retention periods set appropriately
- [ ] Unused resources cleaned up

## Cleanup

### Complete Infrastructure Removal
```bash
# Delete CloudFormation stack
aws cloudformation delete-stack --stack-name my-wordpress-protection --region us-east-1

# Wait for stack deletion to complete
aws cloudformation wait stack-delete-complete --stack-name my-wordpress-protection --region us-east-1

# Clean up KMS key (optional - has 7-30 day waiting period)
aws kms schedule-key-deletion --key-id YOUR-KMS-KEY-ID --pending-window-in-days 7

# Remove SSM parameters
aws ssm delete-parameter --name "/cloudfront/private-key/YOUR-KMS-KEY-ID"

# Delete Lambda layer versions (optional)
aws lambda delete-layer-version --layer-name cloudfront-crypto-layer --version-number 1
```

### Local Cleanup
```bash
# Remove generated key files
rm -rf ./keys/
rm -f kms_key_info.json lambda_layer_info.json
```

## Support and Documentation

### AWS Documentation
- **CloudFormation**: [AWS CloudFormation User Guide](https://docs.aws.amazon.com/cloudformation/)
- **CloudFront Signed Cookies**: [CloudFront Developer Guide](https://docs.aws.amazon.com/cloudfront/latest/DeveloperGuide/private-content-signed-cookies.html)
- **Lambda Functions**: [AWS Lambda Developer Guide](https://docs.aws.amazon.com/lambda/)
- **API Gateway**: [API Gateway Developer Guide](https://docs.aws.amazon.com/apigateway/)

### Third-Party Integration
- **Gatey Pro**: [Gatey Pro Documentation](https://gatey.io/docs)
- **WordPress Static Generators**: Gatsby, Next.js, Jekyll documentation

### Community Support
- **GitHub Issues**: Report bugs and feature requests
- **AWS Forums**: Community support for AWS services
- **Stack Overflow**: Technical questions and solutions

### Professional Support
For enterprise deployments and custom implementations:
- AWS Professional Services
- AWS Partner Network consultants
- Custom development and integration services