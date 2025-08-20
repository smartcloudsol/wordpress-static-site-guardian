# CloudFront IAM Permissions Fix

## Problem
The CloudFront resource manager Lambda function was failing with an access denied error:

```
Error updating distribution: An error occurred (AccessDenied) when calling the GetDistributionConfig operation: 
User: arn:aws:sts::637423296378:assumed-role/serverlessrepo-wordpress--CloudFrontResourceManager-JWv7gNpIaXuq/serverlessrepo-wordpress-static-site-guardian-cloudfront-manager 
is not authorized to perform: cloudfront:GetDistributionConfig on resource: arn:aws:cloudfront::637423296378:distribution/E28SM5GOXS0SIM 
because no identity-based policy allows the cloudfront:GetDistributionConfig action
```

## Root Cause
The Lambda function's IAM policy was missing the `cloudfront:GetDistributionConfig` permission, which is required by the `update_distribution()` function to:
1. Get the current distribution configuration
2. Modify it to add self-origins and protected path behaviors  
3. Update the distribution with the new configuration

## Solution
Added the missing permission to the CloudFront resource manager's IAM policy:

```yaml
# Before
Action:
  - cloudfront:CreateDistribution
  - cloudfront:UpdateDistribution
  - cloudfront:GetDistribution

# After  
Action:
  - cloudfront:CreateDistribution
  - cloudfront:UpdateDistribution
  - cloudfront:GetDistribution
  - cloudfront:GetDistributionConfig  # ✅ Added missing permission
```

## Why This Permission Is Needed

### CloudFront Distribution Operations
The `update_distribution()` function performs these operations:

1. **Get Distribution Config**: `cloudfront.get_distribution_config(Id=distribution_id)`
   - Requires: `cloudfront:GetDistributionConfig` ❌ (was missing)
   - Gets the current configuration and ETag for updates

2. **Get Distribution Info**: `cloudfront.get_distribution(Id=distribution_id)`  
   - Requires: `cloudfront:GetDistribution` ✅ (already had)
   - Gets the distribution domain name

3. **Update Distribution**: `cloudfront.update_distribution(...)`
   - Requires: `cloudfront:UpdateDistribution` ✅ (already had)
   - Applies the modified configuration

### The Difference
- `GetDistribution`: Returns distribution metadata and status
- `GetDistributionConfig`: Returns the detailed configuration needed for updates

## Impact
This fix allows the `CloudFrontDistributionUpdate` custom resource to:
- ✅ Add self-referencing origins to CloudFront distributions
- ✅ Create cache behaviors for protected paths
- ✅ Complete the advanced CloudFront configuration post-deployment

## Validation
- ✅ Template validates successfully with `sam validate`
- ✅ IAM policy includes all required CloudFront permissions
- ✅ Lambda function can now perform distribution updates

This fix ensures that the sophisticated CloudFront configuration features (self-origins and protected path behaviors) work correctly during stack deployment.