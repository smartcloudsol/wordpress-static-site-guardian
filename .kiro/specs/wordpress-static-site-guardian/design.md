# Design Document

## Overview

WordPress Static Site Guardian is a comprehensive AWS solution that enables static WordPress sites to maintain authentication-protected content areas while leveraging the performance and security benefits of CloudFront CDN. The system uses CloudFront signed cookies for edge-based authentication, ensuring optimal performance and security.

The architecture consists of multiple AWS services working together: S3 for static hosting, CloudFront for global content delivery and authentication with Lambda@Edge for cookie management, and various supporting services for security, monitoring, and DNS management.

## Architecture

### High-Level Architecture

```mermaid
graph TB
    User[User Browser] --> CF[CloudFront Distribution]
    CF --> S3[S3 Static Site Bucket]
    CF --> CFFunc[CloudFront Functions]
    CF --> LambdaEdge[Lambda@Edge Cookie Signing]
    
    Auth[Authentication System] --> CF
    LambdaEdge --> KMS[KMS Encrypted Keys]
    LambdaEdge --> SSM[SSM Parameter Store]
    LambdaEdge --> Cognito[Cognito JWKS]
    
    CF --> KeyGroup[CloudFront Key Group]
    KeyGroup --> PubKey[Public Key]
    
    Route53[Route53 DNS] --> CF
    
    CW[CloudWatch] --> LambdaEdge
```

### Component Architecture

#### 1. Static Site Hosting Layer
- **S3 Bucket**: Hosts static WordPress-generated files with public access blocked
- **Origin Access Control (OAC)**: Provides secure access from CloudFront to S3
- **CloudFront Distribution**: Global CDN with custom domain and SSL certificate support

#### 2. Authentication and Authorization Layer
- **CloudFront Signed Cookies**: Edge-based authentication using RSA-SHA1 signatures
- **CloudFront Key Group**: Contains public keys for cookie verification
- **CloudFront Functions**: Edge-based request processing for authentication and path rewriting

#### 3. Cookie Management Layer
- **Lambda@Edge Function**: Edge-deployed cookie signing with JWT verification and native cryptography
- **CloudFront Cache Behavior**: /issue-cookie* behavior with Lambda@Edge association
- **KMS**: Secure private key encryption and management
- **SSM Parameter Store**: Encrypted private key storage

#### 4. DNS and Domain Management
- **Route53**: Automatic DNS record creation for custom domains
- **ACM Certificates**: SSL/TLS certificates for HTTPS enforcement

#### 5. Monitoring and Observability
- **CloudWatch Logs**: Comprehensive logging for all components
- **CloudWatch Dashboards**: Performance and authentication metrics
- **CloudWatch Alarms**: Proactive monitoring and alerting

## Components and Interfaces

### S3 Static Site Bucket

**Purpose**: Secure hosting of static WordPress-generated files

**Configuration**:
- Public access completely blocked
- Server-side encryption enabled (AES256)
- Versioning enabled for content management
- Bucket policy allows access only from CloudFront service principal

**Interface**:
- Input: Static WordPress files uploaded to `/{S3WWWRoot}/` prefix
- Output: Serves files to CloudFront distribution via OAC

### CloudFront Distribution

**Purpose**: Global content delivery with authentication-protected behaviors

**Configuration**:
- Custom domain with SSL certificate (TLS 1.2+)
- Origin Access Control for secure S3 access
- Multiple cache behaviors for public and protected content
- Custom error pages (404, 403)
- CloudFront Functions for request processing
- NoCachePolicy response policy for protected content cache control

**Cache Behaviors**:
1. **Default Behavior**: Public content, no authentication required
2. **Cookie Issuance Behavior**: `/issue-cookie*` path pattern with Lambda@Edge association
   - GET/HEAD methods only with CachingDisabled policy
   - Lambda@Edge function on viewer request for JWT verification and cookie signing
3. **Protected Path Behaviors**: Dynamically created for each protected path
   - Requires signed cookies via trusted key groups
   - Uses viewer-request functions for authentication checks
   - Uses NoCachePolicy response policy for strict cache control
4. **Restricted Path Behaviors**: Internal routing behaviors for authenticated content
   - Uses NoCachePolicy response policy to prevent caching of sensitive content

**Interface**:
- Input: HTTP/HTTPS requests from users
- Output: Static content or authentication redirects

### CloudFront Response Policy (NoCachePolicy)

**Purpose**: Strict cache control for protected and restricted content to prevent inappropriate caching of sensitive material

**Configuration**:
- Custom response policy named "NoCachePolicy"
- Sets "Cache-Control" header with "max-age=0" value
- Disables all other caching mechanisms
- Applied to all protected and restricted path cache behaviors

**Security Benefits**:
- Ensures sensitive content is never cached by browsers or intermediate proxies
- Forces fresh authentication checks on every request to protected content
- Prevents stale permission data from being served to users
- Maintains security even if user permissions change

**Interface**:
- Input: Responses from S3 origin for protected content
- Output: Modified responses with no-cache headers

### CloudFront Functions

**Purpose**: Edge-based request processing for authentication and path rewriting

#### Viewer Request Function (Authentication)
**Functionality**:
- Checks for valid signed cookies on protected paths
- Redirects unauthenticated users to sign-in page with return URL
- Rewrites authenticated requests to restricted path format
- Handles path normalization and index.html resolution

#### Path Rewrite Function (Origin Requests)
**Functionality**:
- Maps restricted paths back to original paths for S3 origin
- Handles S3 prefix mapping (adds `/{S3WWWRoot}/` prefix)
- Ensures proper file resolution for directory requests

**Interface**:
- Input: CloudFront request events
- Output: Modified request objects or redirect responses

### Lambda@Edge Function (Cookie Signing)

**Purpose**: Edge-deployed cookie signing with JWT verification and secure key management

**Configuration**:
- Deployed to CloudFront edge locations via Lambda@Edge
- Associated with `/issue-cookie*` cache behavior on viewer request
- No environment variables (configuration embedded as constants)
- GET/HEAD methods only with no body processing

**Functionality**:
- Verifies JWT Bearer tokens from Authorization header
- Validates JWT signature using cached Cognito JWKS
- Checks issuer, expiration, not-before, and audience claims
- Retrieves encrypted private key from KMS/SSM
- Uses Lambda runtime's native cryptography libraries for RSA-SHA1 signing
- Generates CloudFront signed cookies with proper expiration
- Handles both cookie issuance (signin) and expiration (signout)
- Returns host-only cookies without Domain attribute
- Comprehensive error handling and logging

**JWT Verification**:
- Supports both ID tokens (aud claim) and access tokens (client_id claim)
- Validates token_use claim for 'id' or 'access'
- Caches JWKS keys in memory for performance
- Returns 401 with WWW-Authenticate header for invalid tokens

**Configuration Constants** (embedded in code):
- Cognito User Pool ID for issuer validation
- Allowed App Client IDs for audience validation
- CloudFront key pair identifier
- Cookie lifetime configuration
- Protected paths list for validation

**Interface**:
- Input: CloudFront viewer request events with JWT Bearer tokens
- Output: HTTP responses with Set-Cookie headers or 401/400 errors

### CloudFront Resource Manager Lambda

**Purpose**: Custom CloudFormation resource handler for unsupported CloudFront resources

**Functionality**:
- Creates and manages CloudFront Public Keys
- Creates and manages CloudFront Key Groups
- Creates and manages Origin Access Control
- Creates and manages CloudFront Functions
- Creates and manages CloudFront Response Policies (NoCachePolicy)
- Handles CloudFormation lifecycle (Create, Update, Delete)
- Comprehensive error handling to prevent stack hanging

**Interface**:
- Input: CloudFormation custom resource events
- Output: CloudFormation responses with resource identifiers

### Key Management System

**Purpose**: Secure cryptographic key management

**Components**:
- **KMS Key**: Encrypts private keys with customer-managed key
- **SSM Parameter Store**: Stores encrypted private key securely
- **CloudFront Public Key**: Stores public key for cookie verification
- **CloudFront Key Group**: Groups public keys for distribution association

**Interface**:
- Input: RSA key pairs generated by key generation script
- Output: Secure key storage and retrieval for cookie operations

## Data Models

### CloudFront Signed Cookie Structure

```json
{
  "CloudFront-Policy": "base64-encoded-policy",
  "CloudFront-Signature": "base64-encoded-signature", 
  "CloudFront-Key-Pair-Id": "key-pair-identifier"
}
```

**Policy Document**:
```json
{
  "Statement": [{
    "Resource": "https://domain.com/protected-path/*",
    "Condition": {
      "DateLessThan": {
        "AWS:EpochTime": expiration-timestamp
      }
    }
  }]
}
```

### Configuration Parameters

```yaml
ProtectedPaths:
  Type: CommaDelimitedList
  Description: "Paths requiring authentication (cannot include /issue-cookie)"
  Example: ["/dashboard", "/members", "/courses"]
  AllowedPattern: "^(?!.*(?:^|,)/issue-cookie(?:$|,)).*$"

CookieExpirationDays:
  Type: Number
  Description: "Cookie lifetime in days"
  Range: 1-365

CognitoUserPoolId:
  Type: String
  Description: "Cognito User Pool ID for JWT issuer validation"

CognitoAppClientIds:
  Type: CommaDelimitedList
  Description: "Allowed Cognito App Client IDs for JWT audience validation"

DomainConfiguration:
  MainDomain: "example.com"
  CertificateArn: "arn:aws:acm:us-east-1:..."
```

### CloudFront Distribution Configuration

```yaml
Origins:
  - S3Origin: Static content from S3 bucket
  - SelfOrigin: Self-referencing origin for protected content routing

ResponsePolicies:
  - NoCachePolicy:
      Name: "NoCachePolicy"
      CustomHeaders:
        Cache-Control: "max-age=0"
      CachingDisabled: true

CacheBehaviors:
  - DefaultBehavior: Public content, no authentication
  - ProtectedBehaviors: Generated dynamically for each protected path
    - PathPattern: "/dashboard*", "/members*", etc.
    - TrustedKeyGroups: Reference to created key group
    - ViewerRequestFunction: Authentication function
    - ResponseHeadersPolicy: NoCachePolicy
  - RestrictedBehaviors: Internal routing for authenticated content
    - PathPattern: "/restricted/*"
    - ResponseHeadersPolicy: NoCachePolicy
```

## Error Handling

### CloudFormation Custom Resource Error Handling

**Strategy**: Comprehensive error handling to prevent stack operations from hanging

**Implementation**:
- Module-level validation on Lambda import
- Multiple layers of try/catch blocks
- Emergency response system for critical failures
- Timeout protection with graceful degradation
- Proper PhysicalResourceId management
- Delete operations always return SUCCESS to prevent stack deletion blocking

### CloudFront Function Error Handling

**Authentication Failures**:
- Missing cookies: Redirect to sign-in page
- Invalid cookies: Redirect to sign-in page with error parameter
- Expired cookies: Redirect to sign-in page for re-authentication

**Path Processing Errors**:
- Invalid path patterns: Serve 404 error page (if configured)
- Missing files: Serve custom 404 error page (if configured)
- Access denied: Serve custom 403 error page (if configured)

### Conditional Error Page Handling

**Strategy**: Error pages are optional and conditionally configured based on parameter values

**Implementation**:
- **Optional Parameters**: `NotFoundPagePath` and `ForbiddenPagePath` default to empty strings
- **Conditional Logic**: CloudFormation conditions (`HasNotFoundPage`, `HasForbiddenPage`) determine error response configuration
- **S3 Origin Mapping**: Error page paths are specified **relative to S3WWWRoot**; the template automatically prefixes them at deploy time
- **Path Format**: Error pages are fetched from S3 origin, not from routed public URLs
- **Graceful Degradation**: When error pages are not configured, CloudFront uses default error handling

**Configuration Logic**:
- If both error pages are configured: Include both 404 and 403 custom error responses
- If only 404 page is configured: Include only 404 custom error response
- If only 403 page is configured: Include only 403 custom error response  
- If neither page is configured: Omit custom error responses entirely (use `AWS::NoValue`)

### Lambda Function Error Handling

**Key Management Errors**:
- KMS decryption failures: Log error and return 500
- SSM parameter retrieval failures: Retry with exponential backoff
- Invalid key format: Validate and return descriptive error

**Cookie Generation Errors**:
- Invalid expiration dates: Use default expiration
- Signature generation failures: Log error and return 500
- Domain validation errors: Return 400 with validation message

## Testing Strategy

### Unit Testing

**Lambda Functions**:
- Mock AWS SDK calls for isolated testing
- Test cookie generation with known inputs
- Validate error handling paths
- Test timeout and retry logic

**CloudFront Functions**:
- Test authentication logic with various cookie states
- Validate path rewriting for different URL patterns
- Test redirect generation with proper return URLs
- Verify S3 prefix handling

### Integration Testing

**End-to-End Authentication Flow**:
1. Deploy test stack with test parameters
2. Upload test static content to S3
3. Test public content access (should succeed)
4. Test protected content access without cookies (should redirect)
5. Call cookie issuance API with test credentials
6. Test protected content access with cookies (should succeed)
7. Test cookie expiration and cleanup

### Performance Testing

**CloudFront Performance**:
- Measure cache hit rates for public content
- Test edge location performance for authentication
- Validate cookie processing overhead
- Monitor origin request patterns
- Verify NoCachePolicy prevents caching of protected content
- Test cache behavior differences between public and protected paths

**Lambda Performance**:
- Test cold start times for cookie signing
- Measure KMS decryption performance
- Validate concurrent request handling
- Monitor memory and timeout usage

### Security Testing

**Authentication Security**:
- Test cookie tampering detection
- Validate signature verification
- Test expired cookie handling
- Verify domain scope enforcement
- Validate NoCachePolicy prevents sensitive content caching
- Test cache control headers are properly applied to protected content

**Key Management Security**:
- Test KMS key access controls
- Validate SSM parameter encryption
- Test key rotation procedures
- Verify audit logging

### Deployment Testing

**CloudFormation Testing**:
- Test stack creation with various parameter combinations
- Validate stack updates and rollbacks
- Test stack deletion and resource cleanup
- Verify custom resource error handling

**Cross-Region Testing**:
- Test certificate requirements (us-east-1)
- Validate DNS propagation
- Test global CloudFront deployment
