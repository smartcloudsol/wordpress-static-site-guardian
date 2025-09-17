# Implementation Plan

## 1. Core Infrastructure Setup
- [x] 1.1 Create S3 bucket with security configurations
  - Implement S3 bucket with public access blocked
  - Configure server-side encryption (AES256)
  - Enable versioning for content management
  - Set up bucket ownership controls
  - _Requirements: 1.1, 1.2_

- [x] 1.2 Implement CloudFormation template structure
  - Create SAM template with metadata for Serverless Application Repository
  - Define all required parameters with validation patterns
  - Set up conditions for optional features
  - Configure global settings and outputs
  - _Requirements: 11.1, 11.2_

## 2. CloudFront Distribution and Security
- [x] 2.1 Create Origin Access Control (OAC) custom resource
  - Implement Lambda function to create OAC via CloudFront API
  - Handle CloudFormation lifecycle (Create, Update, Delete)
  - Add proper error handling and resource cleanup
  - _Requirements: 1.2, 1.3_

- [x] 2.2 Implement CloudFront distribution configuration
  - Configure S3 origin with OAC integration
  - Set up custom domain with SSL certificate
  - Configure default cache behavior for public content
  - Add conditional custom error pages (404, 403) based on parameter configuration
  - _Requirements: 1.4, 1.5_

- [x] 2.3 Create NoCachePolicy response policy custom resource
  - Implement Lambda function to create CloudFront response policy via API
  - Configure policy with "Cache-Control: max-age=0" header
  - Disable all other caching mechanisms in the policy
  - Handle CloudFormation lifecycle (Create, Update, Delete)
  - _Requirements: 12.1, 12.2, 12.3_

- [x] 2.4 Create S3 bucket policy for CloudFront access
  - Allow CloudFront service principal access to S3 objects
  - Enable CloudFront logging to S3 bucket
  - Implement least privilege access controls
  - _Requirements: 1.2, 6.5_

## 3. Cryptographic Key Management
- [x] 3.1 Implement CloudFront public key custom resource
  - Create Lambda function to manage CloudFront public keys
  - Format RSA public key for CloudFront API
  - Handle key creation, updates, and deletion
  - _Requirements: 7.3, 3.1_

- [x] 3.2 Create CloudFront key group custom resource
  - Implement key group management via CloudFront API
  - Associate public keys with key groups
  - Handle CloudFormation resource dependencies
  - _Requirements: 3.1, 7.3_

- [x] 3.3 Set up KMS and SSM integration for private keys
  - Configure KMS key permissions for Lambda function
  - Set up SSM parameter access for encrypted private key retrieval
  - Implement secure key storage and retrieval patterns
  - _Requirements: 7.1, 7.2, 5.1_

## 4. CloudFront Functions for Edge Processing
- [x] 4.1 Create viewer request function for authentication
  - Implement cookie validation logic at CloudFront edge
  - Add redirect logic for unauthenticated users with return URL preservation
  - Implement path rewriting for protected content routing
  - Handle index.html resolution and path normalization
  - _Requirements: 6.1, 6.2, 2.2, 2.5_

- [x] 4.2 Create path rewrite function for origin requests
  - Implement mapping from restricted paths back to original paths
  - Add S3 prefix handling for proper file resolution
  - Handle directory requests and file extension logic
  - _Requirements: 6.4, 2.5_

- [x] 4.3 Implement CloudFront function custom resources
  - Create Lambda function to manage CloudFront functions via API
  - Generate JavaScript function code dynamically from parameters
  - Handle function publishing and CloudFormation lifecycle
  - _Requirements: 6.5, 11.3_

## 5. Lambda@Edge Cookie Management Migration
- [x] 5.1 Remove API Gateway infrastructure from template
  - Delete ApiDomainName parameter from template parameters section
  - Remove ApiGatewayDomainName, ServerlessRestApi, and related API Gateway resources
  - Remove API Gateway deployment, methods, and base path mapping resources
  - Remove Lambda permission for API Gateway invocation
  - Remove API Gateway DNS record creation (ApiDNSRecord)
  - Remove API Gateway-related outputs (ApiGatewayId, ApiGatewayInvokeUrl, etc.)
  - Remove API Gateway monitoring dashboard widgets from MonitoringDashboard
  - _Requirements: 4.1, 8.5_

- [x] 5.2 Add Cognito integration parameters to template
  - Add CognitoUserPoolId parameter for JWT issuer validation
  - Add CognitoAppClientIds parameter (CommaDelimitedList) for audience validation
  - Update ProtectedPaths AllowedPattern regex to reject /issue-cookie inclusion
  - Add parameter validation constraints and descriptions
  - _Requirements: 4.6, 5.7_

- [x] 5.3 Create /issue-cookie* CloudFront cache behavior in distribution
  - Add cache behavior with PathPattern: /issue-cookie*
  - Configure AllowedMethods: GET, HEAD only (no POST, no OPTIONS)
  - Set CachePolicyId to CachingDisabled managed policy (4135ea2d-6df8-44a3-9df3-4b5a84be39ad)
  - Associate Lambda@Edge function on viewer request event
  - Add to CloudFront distribution configuration in template
  - _Requirements: 4.1, 4.5_

## 6. Lambda@Edge Function for Cookie Signing
- [x] 6.1 Convert existing Lambda function to Lambda@Edge compatible
  - Modify src/lambda_function.py for Lambda@Edge deployment requirements
  - Remove all environment variables and embed configuration as constants in code
  - Update function handler to process CloudFront viewer request events
  - Add Lambda@Edge IAM role and permissions for us-east-1 deployment
  - Configure function for Lambda@Edge association in template
  - _Requirements: 5.1, 5.6, 5.7_

- [x] 6.2 Implement JWT Bearer token authentication in Lambda@Edge
  - Add JWT parsing from Authorization header (Bearer token format)
  - Implement JWT signature verification using cached Cognito JWKS endpoint
  - Validate JWT issuer claim against configured Cognito User Pool ID
  - Validate JWT expiration, not-before, and audience claims
  - Support both ID tokens (aud claim) and access tokens (client_id claim)
  - Return 401 with WWW-Authenticate header for invalid tokens
  - Cache JWKS keys in memory for performance optimization
  - _Requirements: 5.7, 4.2_

- [x] 6.3 Implement query string action handling in Lambda@Edge
  - Parse action parameter from query string (signin/signout actions)
  - Return 204 No Content for successful signin with host-only cookies
  - Expire all three CloudFront cookies for signout action (Max-Age=0)
  - Include Cache-Control: no-store header in all responses
  - Handle missing or invalid action parameters gracefully
  - _Requirements: 4.5, 5.5_

- [x] 6.4 Add protected path validation in Lambda@Edge
  - Check if /issue-cookie appears in embedded protected paths configuration
  - Return 400 Bad Request if /issue-cookie is found in protected paths
  - Add defensive validation in Lambda@Edge code as backup to template validation
  - Log validation errors for monitoring and debugging
  - _Requirements: 4.6_

## 7. CloudFront Distribution Updates and Protected Behaviors
- [x] 7.1 Implement distribution update custom resource
  - Create Lambda function to add self-referencing origin to CloudFront
  - Implement dynamic cache behavior creation for protected paths
  - Handle CloudFront API structure (Quantity/Items format)
  - Add comprehensive error handling for API validation
  - _Requirements: 2.1, 2.4, 12.4_

- [x] 7.2 Add protected path cache behaviors
  - Generate cache behaviors dynamically from protected paths parameter
  - Configure trusted key groups for signed cookie validation
  - Set up viewer request function associations
  - Implement proper cache policy configuration
  - _Requirements: 2.1, 2.3, 6.1_

- [x] 7.3 Apply NoCachePolicy to protected and restricted path behaviors
  - Update protected path cache behaviors to use NoCachePolicy response policy
  - Configure restricted path behaviors to use NoCachePolicy
  - Ensure no-cache headers are applied to all sensitive content
  - Test cache control headers are properly set in responses
  - _Requirements: 12.4, 12.5_

## 8. DNS and Domain Management
- [x] 8.1 Implement Route53 hosted zone lookup
  - Create custom resource to find hosted zone for domain
  - Handle domain matching logic for subdomains
  - Add error handling for missing hosted zones
  - _Requirements: 8.1, 8.4_

- [x] 8.2 Update DNS records for main domain only
  - Keep Route53 A records for main domain (apex and www)
  - Remove API Gateway domain DNS record creation (ApiDNSRecord resource)
  - Update conditional DNS creation logic to exclude API subdomain
  - Ensure only WWWDNSRecord and ApexDNSRecord are created
  - _Requirements: 8.3, 8.5_

## 9. Custom Resource Error Handling and Robustness
- [x] 9.1 Implement comprehensive Lambda error handling
  - Add module-level validation to prevent import failures
  - Implement timeout protection with graceful degradation
  - Create emergency response system for critical failures
  - _Requirements: 12.2, 12.3_

- [x] 9.2 Add proper CloudFormation resource lifecycle management
  - Ensure all custom resources return proper PhysicalResourceId
  - Implement retry logic with exponential backoff for resource operations
  - Handle resource dependencies and deletion order
  - Add graceful error handling to prevent stack hanging
  - _Requirements: 12.1, 12.3, 11.5_

- [x] 9.3 Implement CloudFront function deletion handling
  - Remove function associations from distribution before deletion
  - Add retry logic for "function in use" scenarios
  - Handle proper deletion order to prevent orphaned resources
  - _Requirements: 12.5, 11.5_

## 10. Monitoring and Observability
- [x] 10.1 Set up CloudWatch logging and monitoring
  - Configure Lambda function logging with appropriate log levels
  - Create CloudWatch dashboard for system metrics
  - Add API Gateway request/response logging
  - _Requirements: 9.1, 9.2, 9.3_

- [x] 10.2 Update monitoring dashboards for Lambda@Edge
  - Remove API Gateway metrics from CloudWatch dashboard
  - Add Lambda@Edge metrics and regional log group monitoring
  - Update dashboard configuration to exclude API Gateway widgets
  - Add Lambda@Edge execution metrics and error monitoring
  - _Requirements: 9.4, 9.5_

## 11. Testing and Validation
- [x] 11.1 Create Lambda function validation tests
  - Implement syntax validation for Python code
  - Add import validation for required modules
  - Create function structure validation tests
  - Test error handling and timeout scenarios
  - _Requirements: 12.1, 12.2_

- [x] 11.2 Add CloudFormation template validation
  - Implement SAM template validation and linting
  - Test parameter validation and constraints
  - Validate resource dependencies and references
  - _Requirements: 11.4, 12.4_

- [x] 11.3 Add tests for optional error pages and empty ProtectedPaths
  - Test deployment with no error pages configured (both parameters empty)
  - Test deployment with only 404 error page configured
  - Test deployment with only 403 error page configured
  - Test deployment with empty ProtectedPaths parameter
  - Validate conditional CloudFormation logic works correctly
  - _Requirements: 1.5, 1.6, 2.4_

- [x] 11.4 Add JWT verification unit tests
  - Test valid JWT signature verification with cached JWKS
  - Test invalid issuer, expiration, and audience validation
  - Test both ID token (aud claim) and access token (client_id claim) validation
  - Test token_use claim validation for id/access tokens
  - Create test cases for Lambda@Edge JWT processing
  - _Requirements: 5.7, 4.2_

- [x] 11.5 Add Lambda@Edge integration tests
  - Test GET /issue-cookie?action=signin with valid JWT returns 204 and sets host-only cookies
  - Test GET /issue-cookie?action=signout expires all three cookies
  - Test missing/invalid JWT returns 401 with WWW-Authenticate header
  - Test /issue-cookie in protected paths returns 400 error
  - Test Lambda@Edge regional deployment and execution
  - _Requirements: 4.5, 4.6, 5.5_

- [x] 11.6 Add template validation for protected paths
  - Test template validation fails when /issue-cookie appears in ProtectedPaths parameter
  - Test AllowedPattern regex correctly rejects /issue-cookie inclusion
  - Test valid protected paths are accepted by validation
  - Update existing validation scripts for new parameter constraints
  - _Requirements: 4.6_

## 12. Documentation and Deployment Scripts
- [x] 12.1 Update README for Lambda@Edge architecture
  - Remove API Gateway references and ApiDomainName parameter documentation
  - Document new /issue-cookie* CloudFront behavior and usage
  - Update integration examples for JWT Bearer token authentication
  - Add Lambda@Edge logging information (regional log groups)
  - Update setup instructions to reflect new architecture
  - _Requirements: 11.4_

- [x] 12.2 Update deployment scripts for new parameters
  - Remove ApiDomainName from deployment script parameter examples
  - Add CognitoUserPoolId and CognitoAppClientIds parameters to scripts
  - Update parameter validation and examples in deployment documentation
  - Update template validation script for new parameter constraints
  - _Requirements: 11.1, 7.4_

## 13. Integration and Authentication System Support
- [x] 13.1 Update Gatey Pro integration for Lambda@Edge
  - Update integration documentation to use /issue-cookie endpoint on main domain
  - Replace IAM authentication examples with JWT Bearer token authentication
  - Verify cookie domain scoping for host-only cookies
  - Update integration code examples and API calls
  - _Requirements: 10.1, 10.2_

- [x] 13.2 Add support for Cognito JWT authentication
  - Document JWT Bearer token requirements for integration
  - Provide example integration code for Cognito ID/access tokens
  - Test with Cognito user pools and app clients
  - Create integration guides for common authentication flows
  - _Requirements: 10.4, 10.5_

## 14. Production Readiness and Security Hardening
- [x] 14.1 Implement security best practices
  - Ensure all IAM roles follow least privilege principle
  - Add comprehensive input validation and sanitization
  - Implement proper secret management for cryptographic keys
  - _Requirements: 6.2, 7.5, 12.1_

- [x] 14.2 Add production monitoring and alerting
  - Set up CloudWatch alarms for error rates and performance
  - Implement comprehensive audit logging
  - Add security monitoring for authentication failures
  - _Requirements: 9.5, 7.5_

## 15. Final Template Updates and Output Configuration
- [x] 15.1 Update template outputs for Lambda@Edge architecture
  - Remove ApiGatewayId, ApiGatewayInvokeUrl, and API Gateway domain outputs
  - Remove ApiGatewayRegionalDomainName and ApiGatewayRegionalHostedZoneId outputs
  - Update SetupInstructions output to reference /issue-cookie on main domain
  - Add Lambda@Edge function ARN output for monitoring and debugging
  - _Requirements: 4.1_

- [x] 15.2 Validate template parameter constraints
  - Ensure ProtectedPaths AllowedPattern regex correctly rejects /issue-cookie
  - Test parameter validation with various input combinations
  - Validate CognitoUserPoolId and CognitoAppClientIds parameter formats
  - Test template deployment with new parameter constraints
  - _Requirements: 4.6, 5.7_

## 16. Remaining Tasks for Production Readiness
- [x] 16.1 Implement native cryptography support in Lambda runtime
  - Utilize Lambda runtime's built-in cryptography libraries for RSA-SHA1 signing
  - Update Lambda function to use native cryptography without external dependencies
  - Test proper signature generation and CloudFront validation
  - Remove Lambda layer dependencies from deployment scripts and templates
  - _Requirements: 5.2, 3.2, 7.1, 13.1, 13.2, 13.3_

- [x] 16.2 Add CloudFormation template validation script
  - Create script to validate SAM template syntax and structure
  - Add parameter validation and constraint checking
  - Validate resource dependencies and references
  - Include in deployment automation workflow
  - _Requirements: 11.4, 12.4_

- [x] 16.3 Perform comprehensive end-to-end testing
  - Test complete authentication flow from sign-in to content access
  - Validate cookie issuance and expiration workflows with real RSA signatures
  - Test error scenarios and edge cases
  - Verify cross-browser compatibility
  - _Requirements: 10.3, 12.1_

- [x] 16.4 Validate NoCachePolicy functionality
  - Test that protected content responses include "Cache-Control: max-age=0" headers
  - Verify that browsers do not cache protected content
  - Test that restricted path responses also include no-cache headers
  - Validate that public content still uses normal caching behavior
  - _Requirements: 12.1, 12.4, 12.5_

- [x] 16.5 Validate deployment and cleanup procedures
  - Test stack creation with various parameter combinations
  - Verify stack updates and rollbacks work correctly
  - Test complete stack deletion and resource cleanup
  - Validate no orphaned resources remain after deletion
  - _Requirements: 11.5, 12.5_