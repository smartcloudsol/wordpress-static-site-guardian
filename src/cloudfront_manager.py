import json
import boto3
import logging
from botocore.exceptions import ClientError
import urllib3

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize CloudFront client
cloudfront = boto3.client('cloudfront')

def lambda_handler(event, context):
    """
    Custom resource handler for CloudFront resources not supported by SAR
    """
    
    try:
        logger.info(f"Received event: {json.dumps(event)}")
        
        request_type = event['RequestType']
        resource_type = event['ResourceProperties']['ResourceType']
        
        if request_type == 'Create':
            response = create_resource(event, resource_type)
        elif request_type == 'Update':
            response = update_resource(event, resource_type)
        elif request_type == 'Delete':
            response = delete_resource(event, resource_type)
        else:
            raise ValueError(f"Unknown request type: {request_type}")
        
        send_response(event, context, 'SUCCESS', response)
        
    except Exception as e:
        logger.error(f"Error: {str(e)}", exc_info=True)
        send_response(event, context, 'FAILED', {'Error': str(e)})

def create_resource(event, resource_type):
    """Create CloudFront resource based on type"""
    
    props = event['ResourceProperties']
    
    if resource_type == 'PublicKey':
        return create_public_key(props)
    elif resource_type == 'KeyGroup':
        return create_key_group(props)
    elif resource_type == 'OriginAccessControl':
        return create_origin_access_control(props)
    elif resource_type == 'Function':
        return create_cloudfront_function(props)
    elif resource_type == 'PathRewriteFunction':
        return create_path_rewrite_function(props)
    elif resource_type == 'HostedZoneLookup':
        return lookup_hosted_zone(props)
    else:
        raise ValueError(f"Unknown resource type: {resource_type}")

def create_public_key(props):
    """Create CloudFront Public Key"""
    
    public_key_content = props['PublicKeyContent']
    name = props['Name']
    
    # Format the public key properly
    formatted_key = f"-----BEGIN PUBLIC KEY-----\n{public_key_content}\n-----END PUBLIC KEY-----"
    
    import uuid
    caller_reference = f"{name}-{str(uuid.uuid4())}"
    
    response = cloudfront.create_public_key(
        PublicKeyConfig={
            'CallerReference': caller_reference,
            'Name': name,
            'EncodedKey': formatted_key,
            'Comment': 'Public key for signed cookie verification'
        }
    )
    
    return {
        'PublicKeyId': response['PublicKey']['Id'],
        'PublicKeyArn': response['PublicKey']['PublicKeyConfig']['CallerReference']
    }

def create_key_group(props):
    """Create CloudFront Key Group"""
    
    name = props['Name']
    public_key_id = props['PublicKeyId']
    
    response = cloudfront.create_key_group(
        KeyGroupConfig={
            'Name': name,
            'Items': [public_key_id],
            'Comment': 'Key group for signed cookie verification'
        }
    )
    
    return {
        'KeyGroupId': response['KeyGroup']['Id'],
        'KeyGroupArn': response['KeyGroup']['KeyGroupConfig']['Name']
    }

def create_origin_access_control(props):
    """Create CloudFront Origin Access Control"""
    
    name = props['Name']
    
    response = cloudfront.create_origin_access_control(
        OriginAccessControlConfig={
            'Name': name,
            'Description': 'Origin Access Control for S3 bucket access',
            'OriginAccessControlOriginType': 's3',
            'SigningBehavior': 'always',
            'SigningProtocol': 'sigv4'
        }
    )
    
    return {
        'OriginAccessControlId': response['OriginAccessControl']['Id']
    }

def create_cloudfront_function(props):
    """Create CloudFront Function"""
    
    name = props['Name']
    protected_paths = props['ProtectedPaths']
    signin_page_path = props['SigninPagePath']
    
    # Generate the function code
    function_code = generate_function_code(protected_paths, signin_page_path)
    
    response = cloudfront.create_function(
        Name=name,
        FunctionConfig={
            'Comment': 'Handle authentication and path rewriting for protected content',
            'Runtime': 'cloudfront-js-2.0'
        },
        FunctionCode=function_code.encode('utf-8')
    )
    
    # Publish the function
    cloudfront.publish_function(
        Name=name,
        IfMatch=response['ETag']
    )
    
    return {
        'FunctionARN': response['FunctionSummary']['FunctionMetadata']['FunctionARN']
    }

def create_path_rewrite_function(props):
    """Create CloudFront Function for path rewriting"""
    
    name = props['Name']
    protected_paths = props['ProtectedPaths']
    
    # Generate the path rewrite function code
    function_code = generate_path_rewrite_code(protected_paths)
    
    response = cloudfront.create_function(
        Name=name,
        FunctionConfig={
            'Comment': 'Rewrite restricted paths back to original paths',
            'Runtime': 'cloudfront-js-2.0'
        },
        FunctionCode=function_code.encode('utf-8')
    )
    
    # Publish the function
    cloudfront.publish_function(
        Name=name,
        IfMatch=response['ETag']
    )
    
    return {
        'FunctionARN': response['FunctionSummary']['FunctionMetadata']['FunctionARN']
    }

def lookup_hosted_zone(props):
    """Lookup Route53 hosted zone for domain"""
    
    import boto3
    route53 = boto3.client('route53')
    
    domain_name = props['DomainName']
    
    try:
        # List hosted zones and find the one that matches our domain
        response = route53.list_hosted_zones()
        
        for zone in response['HostedZones']:
            zone_name = zone['Name'].rstrip('.')
            if domain_name == zone_name or domain_name.endswith('.' + zone_name):
                return {
                    'HostedZoneId': zone['Id'].split('/')[-1]  # Remove /hostedzone/ prefix
                }
        
        raise ValueError(f"No hosted zone found for domain: {domain_name}")
        
    except Exception as e:
        logger.error(f"Error looking up hosted zone: {e}")
        raise

def generate_path_rewrite_code(protected_paths):
    """Generate CloudFront Function code for path rewriting"""
    
    return f"""
function handler(event) {{
    var request = event.request;
    var uri = request.uri;
    
    // Protected paths from CloudFormation parameter
    var protectedPathsStr = '{protected_paths}';
    var protectedPaths = protectedPathsStr.split(',');
    for (var i = 0; i < protectedPaths.length; i++) {{
        protectedPaths[i] = protectedPaths[i].replace(/^\\s+|\\s+$/g, '');
    }}
    
    // Check if this is a restricted path that needs rewriting
    if (uri.startsWith('/restricted-')) {{
        // Extract the index from /restricted-N/...
        var match = uri.match(/^\\/restricted-(\\d+)(\\/.*)?$/);
        if (match) {{
            var pathIndex = parseInt(match[1]);
            var remainingPath = match[2] || '/';
            
            // Rewrite to the original protected path
            if (pathIndex < protectedPaths.length) {{
                var originalPath = protectedPaths[pathIndex];
                if (remainingPath === '/') {{
                    request.uri = originalPath;
                }} else {{
                    request.uri = originalPath + remainingPath;
                }}
                if (request.uri.endsWith("/")) {
                    request.uri = "/www" + request.uri + "index.html";
                }
                else if (!request.uri.includes(".")) {
                    request.uri = "/www" + request.uri + "/index.html";
                }
                else {
                    request.uri = "/www" + request.uri;
                }        
            }}
        }}
    }}
    
    return request;
}}
"""

def generate_function_code(protected_paths, signin_page_path):
    """Generate CloudFront Function code"""
    
    return f"""
function handler(event) {{
    var request = event.request;
    var uri = request.uri;
    var headers = request.headers;
    var cookies = request.cookies;
    
    // Protected paths from CloudFormation parameter
    var protectedPathsStr = '{protected_paths}';
    var protectedPaths = protectedPathsStr.split(',');
    for (var i = 0; i < protectedPaths.length; i++) {{
        protectedPaths[i] = protectedPaths[i].replace(/^\\s+|\\s+$/g, '');
    }}
    
    var signinPath = '{signin_page_path}';
    
    // Check if the request is for a protected path
    var isProtectedPath = false;
    var pathIndex = -1;
    
    for (var i = 0; i < protectedPaths.length; i++) {{
        if (uri.startsWith(protectedPaths[i])) {{
            isProtectedPath = true;
            pathIndex = i;
            break;
        }}
    }}
    
    // If not a protected path, allow the request
    if (!isProtectedPath) {{
        if (request.uri.endsWith("/")) {
            request.uri = "/www" + request.uri + "index.html";
        }
        else if (!request.uri.includes(".")) {
            request.uri = "/www" + request.uri + "/index.html";
        }
        else {
            request.uri = "/www" + request.uri;
        }        
        return request;
    }}
    
    // Check for required signed cookies
    var hasValidCookies = checkSignedCookies(cookies, pathIndex);
    
    if (!hasValidCookies) {{
        // Redirect to sign-in page with return URL
        return {{
            statusCode: 302,
            statusDescription: 'Found',
            headers: {{
                'location': {{ 
                    value: signinPath + '?redirect_to=' + encodeURIComponent(uri) 
                }},
                'cache-control': {{ 
                    value: 'no-cache, no-store, must-revalidate' 
                }}
            }}
        }};
    }}
    
    // Rewrite the URI to the restricted path format
    var originalPath = protectedPaths[pathIndex];
    var restrictedPath = '/restricted-' + pathIndex;
    
    // Handle exact path match and subpaths
    if (uri === originalPath) {{
        request.uri = restrictedPath + '/';
    }} else if (uri.startsWith(originalPath + '/')) {{
        request.uri = uri.replace(originalPath, restrictedPath);
    }} else {{
        request.uri = restrictedPath + uri.substring(originalPath.length);
    }}
    
    // Ensure we don't have double slashes
    request.uri = request.uri.replace(/\\/+/g, '/');
    
    return request;
}}

function checkSignedCookies(cookies, pathIndex) {{
    // Check for the presence of required CloudFront signed cookies
    var requiredCookies = [
        'CloudFront-Policy',
        'CloudFront-Signature', 
        'CloudFront-Key-Pair-Id'
    ];
    
    for (var i = 0; i < requiredCookies.length; i++) {{
        var cookieName = requiredCookies[i];
        if (!cookies[cookieName] || !cookies[cookieName].value) {{
            return false;
        }}
    }}
    
    // Additional basic validation
    var policy = cookies['CloudFront-Policy'];
    var signature = cookies['CloudFront-Signature'];
    var keyPairId = cookies['CloudFront-Key-Pair-Id'];
    
    // Check if cookies have actual values (not empty strings)
    if (!policy.value.trim() || !signature.value.trim() || !keyPairId.value.trim()) {{
        return false;
    }}
    
    // CloudFront will validate the actual signature and policy
    // This function just checks for presence of required cookies
    return true;
}}
"""

def update_resource(event, resource_type):
    """Update CloudFront resource"""
    # For simplicity, we'll recreate resources on update
    # In production, you might want more sophisticated update logic
    delete_resource(event, resource_type)
    return create_resource(event, resource_type)

def delete_resource(event, resource_type):
    """Delete CloudFront resource"""
    
    try:
        physical_resource_id = event.get('PhysicalResourceId', '')
        
        if resource_type == 'PublicKey' and physical_resource_id:
            cloudfront.delete_public_key(Id=physical_resource_id)
        elif resource_type == 'KeyGroup' and physical_resource_id:
            cloudfront.delete_key_group(Id=physical_resource_id)
        elif resource_type == 'OriginAccessControl' and physical_resource_id:
            cloudfront.delete_origin_access_control(Id=physical_resource_id)
        elif resource_type in ['Function', 'PathRewriteFunction'] and physical_resource_id:
            cloudfront.delete_function(Name=physical_resource_id)
        elif resource_type == 'HostedZoneLookup':
            # No deletion needed for lookup operations
            pass
            
    except ClientError as e:
        # Resource might not exist, which is fine for delete
        logger.warning(f"Error deleting resource: {e}")
    
    return {'Status': 'Deleted'}

def send_response(event, context, response_status, response_data):
    """Send response to CloudFormation"""
    
    response_url = event['ResponseURL']
    
    response_body = {
        'Status': response_status,
        'Reason': f'See CloudWatch Log Stream: {context.log_stream_name}',
        'PhysicalResourceId': response_data.get('PhysicalResourceId', context.log_stream_name),
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'Data': response_data
    }
    
    json_response_body = json.dumps(response_body)
    
    headers = {
        'content-type': '',
        'content-length': str(len(json_response_body))
    }
    
    try:
        http = urllib3.PoolManager()
        response = http.request('PUT', response_url, body=json_response_body, headers=headers)
        logger.info(f"Status code: {response.status}")
    except Exception as e:
        logger.error(f"Failed to send response: {e}")