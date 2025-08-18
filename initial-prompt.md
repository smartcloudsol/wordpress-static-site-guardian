## CloudFormation Template Prompt for Kiro

Your task is to generate an AWS CloudFormation template that sets up the infrastructure for protecting static WordPress-generated sites hosted on S3, served via CloudFront, and secured with signed cookies issued through API Gateway and Lambda. The authentication is handled by Gatey Pro (Amazon Cognito integration).

## Requirements

1. **S3 Bucket**

   - Hosts static site files.

   - Public access blocked, access only via CloudFront.

2. **CloudFront Distribution**

   - Origin: S3 bucket.

   - Behaviors:

     - Public content (no restrictions).

     - Restricted paths (from a configurable string list of protected paths, e.g. `/dashboard`, `/profile`, ...).

   - Trusted Key Group for signed cookies.

   - Viewer request function placeholders to handle:

     - Redirect unauthenticated users to `/signin`.

     - Rewrite requests to `/restricted-0/...`, `/restricted-1/...`, … depending on the number of protected paths.

     - Map them back to original paths after cookie validation.

3. **CloudFront Key Group**

   - Contains the public key(s) for verifying signed cookies.

4. **API Gateway**

   - REST API with an endpoint `/issue-cookie`.

   - **GET** method (not POST) that triggers Lambda to issue signed cookies.

5. **Lambda Function**

   - Signs cookies using CloudFront private key.

   - Cookie expiration aligns with the Cognito AppClient refresh token expiration (configurable parameter).

   - On logout (sign-out hook), same Lambda sets cookie `Max-Age=0` to expire immediately.

6. **IAM Roles/Policies**

   - Allow Lambda to create signed cookies and integrate with API Gateway securely.

   - Ensure principle of least privilege.

## Parameters

- `ProtectedPaths`: List<String> – Paths to secure (e.g., ["/dashboard", "/profile", "/admin"]).  

- `CognitoRefreshTokenValidity`: Integer – Validity in days, to match Cognito AppClient refresh token expiration.  

- `DomainName`: String – Custom domain for CloudFront.  

- `ApiDomainName`: String – Custom domain for API Gateway (must be a subdomain of the CloudFront domain).  

## Outputs

- S3 Bucket URL

- CloudFront Distribution DomainName

- API Gateway Invoke URL (`/issue-cookie` endpoint)

- Example curl command for testing cookie issuance:  

  ```bash

  curl -X GET "https://<api-domain>/issue-cookie" -H "Authorization: <IAM-signed-request>"

  ```

---

## Notes for Implementation

- Insert `<code></code>` placeholders in CloudFront for viewer request functions; they will be pasted later manually.  

- Cookie settings must align with Gatey’s Sign-In and Sign-Out hooks.  

- Template should be YAML, CloudFormation compliant, and support deployment with a single command.  