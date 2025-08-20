# API Gateway Stage Reference Fix

## Problem
CloudFormation was failing with the error:
```
Resource handler returned message: "Invalid stage identifier specified"
```

This occurred when creating the `ApiGatewayBasePathMapping` resource.

## Root Cause
The `ApiGatewayBasePathMapping` was incorrectly referencing the deployment resource instead of the stage name:

```yaml
# INCORRECT
ApiGatewayBasePathMapping:
  Type: AWS::ApiGateway::BasePathMapping
  Properties:
    DomainName: !Ref ApiGatewayDomainName
    RestApiId: !Ref ServerlessRestApi
    Stage: !Ref ApiGatewayDeployment  # ❌ This references a deployment resource, not a stage name
```

## Solution
Fixed the reference to use the actual stage name and added proper dependency:

```yaml
# CORRECT
ApiGatewayBasePathMapping:
  Type: AWS::ApiGateway::BasePathMapping
  DependsOn: ApiGatewayDeployment  # ✅ Ensure deployment exists first
  Properties:
    DomainName: !Ref ApiGatewayDomainName
    RestApiId: !Ref ServerlessRestApi
    Stage: Prod  # ✅ Use the actual stage name
```

## Explanation

### API Gateway Stage vs Deployment
- **Deployment**: A snapshot of the API configuration at a point in time
- **Stage**: A named reference to a deployment that can be used for routing

### The Fix
1. **Stage Property**: Changed from `!Ref ApiGatewayDeployment` to `Prod` (the actual stage name)
2. **DependsOn**: Added explicit dependency on `ApiGatewayDeployment` to ensure proper creation order
3. **Stage Name**: Used `Prod` which matches the `StageName` defined in the `ApiGatewayDeployment`

### Why This Works
- The `ApiGatewayDeployment` creates a stage named "Prod"
- The `BasePathMapping` needs to reference this stage by name, not by the deployment resource
- The `DependsOn` ensures the deployment (and thus the stage) exists before the mapping is created

## Validation
- ✅ Template validates successfully with `sam validate`
- ✅ Stage name "Prod" matches the deployment configuration
- ✅ Proper dependency order maintained

This fix ensures that the API Gateway custom domain mapping works correctly and the stack deployment completes successfully.