import json
import boto3
import logging
from botocore.exceptions import ClientError
import urllib3
import signal
import time

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize CloudFront client with error handling
try:
    cloudfront = boto3.client('cloudfront')
    logger.info("CloudFront client initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize CloudFront client: {e}")
    # Create a dummy client that will fail gracefully
    cloudfront = None

# Module-level validation
def validate_module():
    """Validate that the module loaded correctly"""
    try:
        # Test basic imports
        import json
        import boto3
        import logging
        from botocore.exceptions import ClientError
        import urllib3
        import signal
        import time
        
        # Test basic functionality
        test_dict = {'test': 'value'}
        json.dumps(test_dict)
        
        logger.info("Module validation passed")
        return True
    except Exception as e:
        logger.error(f"Module validation failed: {e}")
        return False

# Run validation on import
MODULE_VALID = validate_module()

class TimeoutHandler:
    """Handle Lambda timeout gracefully"""
    def __init__(self, timeout_seconds=270):  # 4.5 minutes for 5-minute Lambda
        self.timeout_seconds = timeout_seconds
        self.timed_out = False
    
    def __enter__(self):
        signal.signal(signal.SIGALRM, self._timeout_handler)
        signal.alarm(self.timeout_seconds)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        signal.alarm(0)
    
    def _timeout_handler(self, signum, frame):
        self.timed_out = True
        logger.error("Lambda function timed out")
        raise TimeoutError("Lambda function execution timed out")

def lambda_handler(event, context):
    """
    Custom resource handler for CloudFront resources not supported by SAR
    Includes comprehensive error handling to prevent CloudFormation from hanging
    """
    
    # Initialize response variables for emergency fallback
    response_url = None
    response_body = None
    
    try:
        # Check module validity first
        if not MODULE_VALID:
            raise RuntimeError("Module failed validation - syntax or import errors detected")
        
        # Check CloudFront client
        if cloudfront is None:
            raise RuntimeError("CloudFront client failed to initialize")
        
        # Extract response URL immediately for emergency use
        response_url = event.get('ResponseURL')
        
        # Validate basic event structure
        if not event:
            raise ValueError("Empty event received")
        
        if 'RequestType' not in event:
            raise ValueError("Missing RequestType in event")
        
        if 'ResourceProperties' not in event:
            raise ValueError("Missing ResourceProperties in event")
        
        if 'ResourceType' not in event['ResourceProperties']:
            raise ValueError("Missing ResourceType in ResourceProperties")
        
        # Log the event (with error handling for JSON serialization)
        try:
            logger.info(f"Received event: {json.dumps(event)}")
        except Exception as json_error:
            logger.info(f"Received event (JSON serialization failed): {str(event)[:1000]}...")
            logger.warning(f"JSON serialization error: {json_error}")
        
        with TimeoutHandler():
            request_type = event['RequestType']
            resource_type = event['ResourceProperties']['ResourceType']
            
            # Validate request type
            if request_type not in ['Create', 'Update', 'Delete']:
                raise ValueError(f"Invalid request type: {request_type}")
            
            # Handle test resource type for validation
            if resource_type == 'Test':
                response = {
                    'Status': 'TestSuccess', 
                    'Message': 'Lambda function is working correctly',
                    'PhysicalResourceId': f"test-resource-{int(time.time())}"
                }
            # Execute the appropriate operation
            elif request_type == 'Create':
                response = create_resource(event, resource_type)
            elif request_type == 'Update':
                response = update_resource(event, resource_type)
            elif request_type == 'Delete':
                response = delete_resource(event, resource_type)
            
            # Ensure response has required fields
            if not isinstance(response, dict):
                response = {'Status': 'Success', 'Data': response}
            
            # Ensure PhysicalResourceId is present and is a string
            if 'PhysicalResourceId' not in response:
                response['PhysicalResourceId'] = f"{resource_type}-{request_type}-{int(time.time())}"
            else:
                response['PhysicalResourceId'] = str(response['PhysicalResourceId'])
            
            send_response(event, context, 'SUCCESS', response)
        
    except TimeoutError:
        logger.error("Lambda function timed out")
        try:
            # For timeouts, especially on delete, return success to avoid blocking stack operations
            if event.get('RequestType') == 'Delete':
                send_response(event, context, 'SUCCESS', {
                    'Status': 'TimeoutOnDelete', 
                    'Message': 'Deletion timed out but continuing',
                    'PhysicalResourceId': f"timeout-delete-{int(time.time())}"
                })
            else:
                send_response(event, context, 'FAILED', {
                    'Error': 'Lambda function timed out',
                    'PhysicalResourceId': f"timeout-failed-{int(time.time())}"
                })
        except Exception as send_error:
            logger.error(f"Failed to send timeout response: {send_error}")
            emergency_response(response_url, context, 'FAILED', {'Error': 'Timeout and response send failed'})
            
    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}", exc_info=True)
        
        try:
            # For delete operations, we should still return success to avoid blocking stack deletion
            if event.get('RequestType') == 'Delete':
                logger.warning("Delete operation failed, but returning SUCCESS to allow stack deletion to continue")
                send_response(event, context, 'SUCCESS', {
                    'Status': 'DeleteFailed', 
                    'Error': str(e),
                    'PhysicalResourceId': f"delete-failed-{int(time.time())}"
                })
            else:
                send_response(event, context, 'FAILED', {
                    'Error': str(e),
                    'PhysicalResourceId': f"error-failed-{int(time.time())}"
                })
        except Exception as send_error:
            logger.error(f"Failed to send error response: {send_error}")
            # Last resort - try emergency response
            try:
                emergency_response(response_url, context, 'FAILED', {'Error': f'Handler failed: {str(e)}, Send failed: {str(send_error)}'})
            except Exception as emergency_error:
                logger.error(f"Emergency response also failed: {emergency_error}")
                # At this point, we've done everything we can

def emergency_response(response_url, context, status, data):
    """
    Emergency response function that works even if other parts fail
    """
    if not response_url:
        logger.error("No response URL available for emergency response")
        return
    
    try:
        import urllib3
        import json
        
        response_body = {
            'Status': status,
            'Reason': f'Emergency response - See CloudWatch Log Stream: {getattr(context, "log_stream_name", "unknown")}',
            'PhysicalResourceId': getattr(context, 'log_stream_name', 'emergency-response'),
            'StackId': 'unknown',
            'RequestId': 'unknown', 
            'LogicalResourceId': 'unknown',
            'Data': data or {}
        }
        
        json_response_body = json.dumps(response_body)
        
        headers = {
            'content-type': '',
            'content-length': str(len(json_response_body))
        }
        
        http = urllib3.PoolManager()
        response = http.request('PUT', response_url, body=json_response_body, headers=headers)
        logger.info(f"Emergency response sent with status code: {response.status}")
        
    except Exception as e:
        logger.error(f"Emergency response failed: {e}")
        # Nothing more we can do at this point

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
    elif resource_type == 'DistributionUpdate':
        return update_distribution(props)
    elif resource_type == 'Test':
        return {
            'Status': 'TestSuccess', 
            'Message': 'Create operation test successful',
            'PhysicalResourceId': f"test-resource-{int(time.time())}"
        }
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
        'PublicKeyArn': response['PublicKey']['PublicKeyConfig']['CallerReference'],
        'PhysicalResourceId': response['PublicKey']['Id']
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
        'KeyGroupArn': response['KeyGroup']['KeyGroupConfig']['Name'],
        'PhysicalResourceId': response['KeyGroup']['Id']
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
        'OriginAccessControlId': response['OriginAccessControl']['Id'],
        'PhysicalResourceId': response['OriginAccessControl']['Id']
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
        'FunctionARN': response['FunctionSummary']['FunctionMetadata']['FunctionARN'],
        'PhysicalResourceId': name
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
        'FunctionARN': response['FunctionSummary']['FunctionMetadata']['FunctionARN'],
        'PhysicalResourceId': name
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
                hosted_zone_id = zone['Id'].split('/')[-1]  # Remove /hostedzone/ prefix
                return {
                    'HostedZoneId': hosted_zone_id,
                    'PhysicalResourceId': f"hosted-zone-lookup-{domain_name}-{hosted_zone_id}"
                }
        
        raise ValueError(f"No hosted zone found for domain: {domain_name}")
        
    except Exception as e:
        logger.error(f"Error looking up hosted zone: {e}")
        raise

def update_distribution(props):
    """Update CloudFront distribution with self-origin and protected path behaviors"""
    
    try:
        # Validate required properties
        distribution_id = props.get('DistributionId')
        if not distribution_id:
            raise ValueError("DistributionId is required")
        
        protected_paths_str = props.get('ProtectedPaths', '')
        protected_paths = [path.strip() for path in protected_paths_str.split(',') if path.strip()]
        
        viewer_request_function_arn = props.get('ViewerRequestFunctionArn')
        if not viewer_request_function_arn:
            raise ValueError("ViewerRequestFunctionArn is required")
        
        logger.info(f"Updating distribution {distribution_id} with {len(protected_paths)} protected paths")
        
        # Get current distribution configuration
        response = cloudfront.get_distribution_config(Id=distribution_id)
        config = response['DistributionConfig']
        etag = response['ETag']
        
        logger.info(f"Retrieved distribution config, ETag: {etag}")
        
        # Log config structure for debugging
        try:
            config_keys = list(config.keys()) if isinstance(config, dict) else []
            logger.info(f"Distribution config keys: {config_keys}")
            
            # Check Origins structure specifically
            origins_raw = config.get('Origins')
            logger.info(f"Origins type: {type(origins_raw)}")
            if origins_raw:
                logger.info(f"Origins content (first 500 chars): {str(origins_raw)[:500]}")
            
            # Check CacheBehaviors structure specifically
            cache_behaviors_raw = config.get('CacheBehaviors')
            logger.info(f"CacheBehaviors type: {type(cache_behaviors_raw)}")
            if cache_behaviors_raw:
                logger.info(f"CacheBehaviors content (first 500 chars): {str(cache_behaviors_raw)[:500]}")
        except Exception as debug_error:
            logger.error(f"Error debugging config structure: {debug_error}")
        
        # Get the distribution domain name
        dist_response = cloudfront.get_distribution(Id=distribution_id)
        domain_name = dist_response['Distribution']['DomainName']
        
        logger.info(f"Distribution domain name: {domain_name}")
        
        # Log current origins for debugging
        try:
            origins_structure = config.get('Origins', {})
            if isinstance(origins_structure, dict) and 'Items' in origins_structure:
                current_origins = origins_structure['Items']
                logger.info(f"Current origins count: {origins_structure.get('Quantity', len(current_origins))}")
            else:
                logger.error(f"Origins structure unexpected: {type(origins_structure)}")
                current_origins = []
            
            for i, origin in enumerate(current_origins):
                try:
                    if isinstance(origin, dict):
                        origin_id = origin.get('Id', 'NO_ID')
                        origin_domain = origin.get('DomainName', 'NO_DOMAIN')
                        logger.info(f"Origin {i}: Id={origin_id}, Domain={origin_domain}")
                    else:
                        logger.warning(f"Origin {i}: Unexpected type {type(origin)}, value: {str(origin)[:100]}")
                except Exception as origin_error:
                    logger.error(f"Error processing origin {i}: {origin_error}")
        except Exception as origins_error:
            logger.error(f"Error processing origins: {origins_error}")
            current_origins = []
        
        # Add self-origin if it doesn't exist
        self_origin_id = 'CloudFrontSelfOrigin'
        
        # Track if we make any changes
        changes_made = False
        
        # Safely check for existing self-origin
        has_self_origin = False
        try:
            origins_structure = config.get('Origins', {})
            if isinstance(origins_structure, dict) and 'Items' in origins_structure:
                origins_items = origins_structure['Items']
                if isinstance(origins_items, list):
                    has_self_origin = any(
                        origin.get('Id') == self_origin_id 
                        for origin in origins_items
                        if isinstance(origin, dict) and 'Id' in origin
                    )
                    logger.info(f"Self-origin check completed: has_self_origin={has_self_origin}")
                else:
                    logger.error(f"Origins Items is not a list: {type(origins_items)}")
                    has_self_origin = False
            else:
                logger.error(f"Origins structure invalid: {type(origins_structure)}")
                has_self_origin = False
        except Exception as e:
            logger.error(f"Error checking existing origins: {e}", exc_info=True)
            has_self_origin = False
        
        if not has_self_origin:
            try:
                # Ensure Origins structure exists and is correct
                if 'Origins' not in config:
                    logger.warning("Origins key not found in config, creating new Origins structure")
                    config['Origins'] = {'Quantity': 0, 'Items': []}
                elif not isinstance(config['Origins'], dict):
                    logger.error(f"Origins is not a dict (type: {type(config['Origins'])}), replacing with new structure")
                    config['Origins'] = {'Quantity': 0, 'Items': []}
                elif 'Items' not in config['Origins']:
                    logger.warning("Origins missing Items, adding Items list")
                    config['Origins']['Items'] = []
                elif not isinstance(config['Origins']['Items'], list):
                    logger.error(f"Origins Items is not a list (type: {type(config['Origins']['Items'])}), replacing")
                    config['Origins']['Items'] = []
                
                logger.info(f"Adding self-origin with ID '{self_origin_id}' and domain '{domain_name}'")
                new_origin = {
                    'Id': self_origin_id,
                    'DomainName': domain_name,
                    'OriginPath': '',
                    'CustomHeaders': {'Quantity': 0},
                    'CustomOriginConfig': {
                        'HTTPPort': 443,
                        'HTTPSPort': 443,
                        'OriginProtocolPolicy': 'https-only',
                        'OriginSslProtocols': {
                            'Quantity': 1,
                            'Items': ['TLSv1.2']
                        },
                        'OriginReadTimeout': 30,
                        'OriginKeepaliveTimeout': 5
                    },
                    'ConnectionAttempts': 3,
                    'ConnectionTimeout': 10,
                    'OriginShield': {'Enabled': False}
                }
                
                config['Origins']['Items'].append(new_origin)
                config['Origins']['Quantity'] = len(config['Origins']['Items'])
                changes_made = True
                logger.info("Successfully added self-origin")
            except Exception as origin_add_error:
                logger.error(f"Error adding self-origin: {origin_add_error}", exc_info=True)
                # Continue without adding self-origin
        else:
            logger.info(f"Self-origin '{self_origin_id}' already exists")
        
        # Add cache behaviors for each protected path
        cache_behaviors_structure = config.get('CacheBehaviors', {'Quantity': 0, 'Items': []})
        
        # Handle CacheBehaviors structure (similar to Origins)
        if isinstance(cache_behaviors_structure, dict) and 'Items' in cache_behaviors_structure:
            cache_behaviors = cache_behaviors_structure['Items']
            logger.info(f"Cache behaviors count: {cache_behaviors_structure.get('Quantity', len(cache_behaviors))}")
        elif isinstance(cache_behaviors_structure, list):
            # Fallback for older format
            cache_behaviors = cache_behaviors_structure
            logger.info(f"Cache behaviors count (legacy format): {len(cache_behaviors)}")
        else:
            logger.warning(f"CacheBehaviors unexpected type: {type(cache_behaviors_structure)}, using empty list")
            cache_behaviors = []
            logger.info("Cache behaviors count: 0")
        
        # Safely extract existing patterns
        existing_patterns = set()
        try:
            for i, behavior in enumerate(cache_behaviors):
                try:
                    if isinstance(behavior, dict) and 'PathPattern' in behavior:
                        existing_patterns.add(behavior['PathPattern'])
                        logger.debug(f"Cache behavior {i}: PathPattern={behavior['PathPattern']}")
                    else:
                        logger.warning(f"Cache behavior {i}: Unexpected type {type(behavior)} or missing PathPattern")
                except Exception as behavior_error:
                    logger.error(f"Error processing cache behavior {i}: {behavior_error}")
        except Exception as e:
            logger.error(f"Error extracting existing cache behavior patterns: {e}")
            existing_patterns = set()
        
        logger.info(f"Existing cache behavior patterns: {existing_patterns}")
        
        new_behaviors = []
        for path in protected_paths:
            if not path:
                continue
                
            path_pattern = f"{path.lstrip('/')}*"
            
            # Skip if behavior already exists
            if path_pattern in existing_patterns:
                logger.info(f"Cache behavior for pattern '{path_pattern}' already exists, skipping")
                continue
            
            behavior = {
                'PathPattern': path_pattern,
                'TargetOriginId': self_origin_id,
                'ViewerProtocolPolicy': 'redirect-to-https',
                'AllowedMethods': {
                    'Quantity': 2,
                    'Items': ['GET', 'HEAD'],
                    'CachedMethods': {
                        'Quantity': 2,
                        'Items': ['GET', 'HEAD']
                    }
                },
                'SmoothStreaming': False,
                'CachePolicyId': '4cc15a8a-d715-48a4-82b8-cc0b614638fe',  # UseOriginCacheControlHeaders-QueryStrings
                'Compress': True,
                'FunctionAssociations': {
                    'Quantity': 1,
                    'Items': [{
                        'EventType': 'viewer-request',
                        'FunctionARN': viewer_request_function_arn
                    }]
                }
            }
            
            new_behaviors.append(behavior)
        
        # Update cache behaviors if we have new ones
        if new_behaviors:
            try:
                # Ensure cache_behaviors is still a list before extending
                if not isinstance(cache_behaviors, list):
                    logger.warning(f"cache_behaviors became non-list (type: {type(cache_behaviors)}), reinitializing")
                    cache_behaviors = []
                
                cache_behaviors.extend(new_behaviors)
                
                # Update the config with proper CloudFront structure
                config['CacheBehaviors'] = {
                    'Quantity': len(cache_behaviors),
                    'Items': cache_behaviors
                }
                changes_made = True
                logger.info(f"Added {len(new_behaviors)} new cache behaviors")
            except Exception as extend_error:
                logger.error(f"Error extending cache behaviors: {extend_error}")
                # Try alternative approach
                try:
                    combined_behaviors = list(cache_behaviors) + new_behaviors
                    config['CacheBehaviors'] = {
                        'Quantity': len(combined_behaviors),
                        'Items': combined_behaviors
                    }
                    changes_made = True
                    logger.info(f"Added {len(new_behaviors)} new cache behaviors (alternative method)")
                except Exception as alt_error:
                    logger.error(f"Alternative cache behavior update also failed: {alt_error}")
                    # Continue without adding cache behaviors
        
        # Only update if we made changes
        if changes_made or not has_self_origin:
            logger.info("Updating distribution with new configuration")
            try:
                cloudfront.update_distribution(
                    Id=distribution_id,
                    DistributionConfig=config,
                    IfMatch=etag
                )
                logger.info("Distribution update successful")
            except Exception as update_error:
                logger.error(f"Failed to update distribution: {update_error}")
                raise
        else:
            logger.info("No changes needed for distribution")
        
        return {
            'DistributionId': distribution_id,
            'Status': 'Updated',
            'PhysicalResourceId': f"distribution-update-{distribution_id}",
            'ChangesApplied': changes_made or not has_self_origin
        }
        
    except Exception as e:
        logger.error(f"Error updating distribution {distribution_id}: {e}", exc_info=True)
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
                if (request.uri.endsWith('/')) {{
                    request.uri = '/www' + request.uri + 'index.html';
                }}
                else if (!request.uri.includes('.')) {{
                    request.uri = '/www' + request.uri + '/index.html';
                }}
                else {{
                    request.uri = '/www' + request.uri;
                }}        
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
        if (request.uri.endsWith('/')) {{
            request.uri = '/www' + request.uri + 'index.html';
        }}
        else if (!request.uri.includes('.')) {{
            request.uri = '/www' + request.uri + '/index.html';
        }}
        else {{
            request.uri = '/www' + request.uri;
        }}        
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
    
    # For most CloudFront resources, we need to recreate them
    # Some resources like DistributionUpdate can be updated in place
    if resource_type == 'DistributionUpdate':
        return update_distribution(event['ResourceProperties'])
    elif resource_type == 'HostedZoneLookup':
        return lookup_hosted_zone(event['ResourceProperties'])
    else:
        # For other resources, recreate them
        try:
            delete_resource(event, resource_type)
        except Exception as e:
            logger.warning(f"Error during update deletion: {e}")
        
        return create_resource(event, resource_type)

def delete_resource(event, resource_type):
    """Delete CloudFront resource with proper dependency handling"""
    
    import time
    
    try:
        physical_resource_id = event.get('PhysicalResourceId', '')
        
        if not physical_resource_id:
            logger.info(f"No PhysicalResourceId found for {resource_type}, skipping deletion")
            return {
                'Status': 'Deleted',
                'PhysicalResourceId': f"no-resource-{resource_type}-{int(time.time())}"
            }
        
        if resource_type == 'PublicKey':
            delete_public_key_with_retry(physical_resource_id)
        elif resource_type == 'KeyGroup':
            delete_key_group_with_retry(physical_resource_id)
        elif resource_type == 'OriginAccessControl':
            delete_origin_access_control_with_retry(physical_resource_id)
        elif resource_type in ['Function', 'PathRewriteFunction']:
            delete_function_with_retry(physical_resource_id)
        elif resource_type == 'HostedZoneLookup':
            # No deletion needed for lookup operations
            pass
        elif resource_type == 'DistributionUpdate':
            # Remove function associations from distribution before functions are deleted
            remove_function_associations_from_distribution(event['ResourceProperties'])
        else:
            logger.warning(f"Unknown resource type for deletion: {resource_type}")
            
    except Exception as e:
        # Log the error but don't fail the deletion
        logger.error(f"Error deleting resource {resource_type} ({physical_resource_id}): {e}")
        # For CloudFormation, we should still return success to avoid stack deletion issues
        # The resources can be cleaned up manually if needed
    
    return {
        'Status': 'Deleted',
        'PhysicalResourceId': physical_resource_id or f"deleted-resource-{resource_type}-{int(time.time())}"
    }

def delete_function_with_retry(function_name, max_retries=10):
    """Delete CloudFront function with retry logic"""
    
    for attempt in range(max_retries):
        try:
            # Check if function exists first
            try:
                cloudfront.get_function(Name=function_name)
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchFunction':
                    logger.info(f"Function {function_name} does not exist, skipping deletion")
                    return
                raise
            
            # Try to delete the function
            cloudfront.delete_function(Name=function_name)
            logger.info(f"Successfully deleted function: {function_name}")
            return
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            
            if error_code == 'NoSuchFunction':
                logger.info(f"Function {function_name} already deleted")
                return
            elif error_code in ['FunctionInUse', 'InvalidIfMatchVersion']:
                if attempt < max_retries - 1:
                    # Longer wait times for function deletion since distribution updates take time
                    wait_time = min((attempt + 1) * 60, 300)  # Up to 5 minutes
                    logger.warning(f"Function {function_name} is in use, retrying in {wait_time} seconds (attempt {attempt + 1}/{max_retries})")
                    time.sleep(wait_time)
                    continue
                else:
                    logger.error(f"Failed to delete function {function_name} after {max_retries} attempts: {e}")
                    logger.error(f"Function {function_name} may still be associated with a distribution. Manual cleanup required.")
                    # Don't raise exception, let CloudFormation continue
                    return
            else:
                logger.error(f"Unexpected error deleting function {function_name}: {e}")
                return

def delete_key_group_with_retry(key_group_id, max_retries=5):
    """Delete CloudFront key group with retry logic"""
    
    for attempt in range(max_retries):
        try:
            # Get current ETag
            try:
                response = cloudfront.get_key_group(Id=key_group_id)
                etag = response['ETag']
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchResource':
                    logger.info(f"Key group {key_group_id} does not exist, skipping deletion")
                    return
                raise
            
            # Try to delete the key group
            cloudfront.delete_key_group(Id=key_group_id, IfMatch=etag)
            logger.info(f"Successfully deleted key group: {key_group_id}")
            return
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            
            if error_code == 'NoSuchResource':
                logger.info(f"Key group {key_group_id} already deleted")
                return
            elif error_code in ['ResourceInUse', 'InvalidIfMatchVersion']:
                if attempt < max_retries - 1:
                    wait_time = (attempt + 1) * 30
                    logger.warning(f"Key group {key_group_id} is in use, retrying in {wait_time} seconds (attempt {attempt + 1}/{max_retries})")
                    time.sleep(wait_time)
                    continue
                else:
                    logger.error(f"Failed to delete key group {key_group_id} after {max_retries} attempts: {e}")
                    return
            else:
                logger.error(f"Unexpected error deleting key group {key_group_id}: {e}")
                return

def delete_public_key_with_retry(public_key_id, max_retries=5):
    """Delete CloudFront public key with retry logic"""
    
    for attempt in range(max_retries):
        try:
            # Get current ETag
            try:
                response = cloudfront.get_public_key(Id=public_key_id)
                etag = response['ETag']
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicKey':
                    logger.info(f"Public key {public_key_id} does not exist, skipping deletion")
                    return
                raise
            
            # Try to delete the public key
            cloudfront.delete_public_key(Id=public_key_id, IfMatch=etag)
            logger.info(f"Successfully deleted public key: {public_key_id}")
            return
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            
            if error_code == 'NoSuchPublicKey':
                logger.info(f"Public key {public_key_id} already deleted")
                return
            elif error_code in ['PublicKeyInUse', 'InvalidIfMatchVersion']:
                if attempt < max_retries - 1:
                    wait_time = (attempt + 1) * 30
                    logger.warning(f"Public key {public_key_id} is in use, retrying in {wait_time} seconds (attempt {attempt + 1}/{max_retries})")
                    time.sleep(wait_time)
                    continue
                else:
                    logger.error(f"Failed to delete public key {public_key_id} after {max_retries} attempts: {e}")
                    return
            else:
                logger.error(f"Unexpected error deleting public key {public_key_id}: {e}")
                return

def remove_function_associations_from_distribution(props):
    """Remove function associations from CloudFront distribution to allow function deletion"""
    
    try:
        distribution_id = props.get('DistributionId')
        if not distribution_id:
            logger.info("No DistributionId found, skipping function association removal")
            return
        
        logger.info(f"Removing function associations from distribution {distribution_id}")
        
        # Get current distribution configuration
        response = cloudfront.get_distribution_config(Id=distribution_id)
        config = response['DistributionConfig']
        etag = response['ETag']
        
        # Track if we made any changes
        changes_made = False
        
        # Remove function associations from default cache behavior
        if 'FunctionAssociations' in config['DefaultCacheBehavior']:
            if config['DefaultCacheBehavior']['FunctionAssociations'].get('Quantity', 0) > 0:
                config['DefaultCacheBehavior']['FunctionAssociations'] = {
                    'Quantity': 0,
                    'Items': []
                }
                changes_made = True
                logger.info("Removed function associations from default cache behavior")
        
        # Remove function associations from cache behaviors
        if 'CacheBehaviors' in config:
            for i, behavior in enumerate(config['CacheBehaviors']):
                if 'FunctionAssociations' in behavior:
                    if behavior['FunctionAssociations'].get('Quantity', 0) > 0:
                        behavior['FunctionAssociations'] = {
                            'Quantity': 0,
                            'Items': []
                        }
                        changes_made = True
                        logger.info(f"Removed function associations from cache behavior {i}")
        
        # Only update if we made changes
        if changes_made:
            # Update the distribution
            cloudfront.update_distribution(
                Id=distribution_id,
                DistributionConfig=config,
                IfMatch=etag
            )
            
            logger.info(f"Successfully removed function associations from distribution {distribution_id}")
            
            # Wait for the distribution update to propagate
            import time
            logger.info("Waiting for distribution update to propagate...")
            time.sleep(60)  # Longer wait for distribution updates
        else:
            logger.info("No function associations found to remove")
        
    except Exception as e:
        logger.error(f"Error removing function associations from distribution: {e}")
        # Don't raise exception - we want deletion to continue even if this fails

def delete_origin_access_control_with_retry(oac_id, max_retries=5):
    """Delete CloudFront Origin Access Control with retry logic"""
    
    for attempt in range(max_retries):
        try:
            # Get current ETag
            try:
                response = cloudfront.get_origin_access_control(Id=oac_id)
                etag = response['ETag']
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchOriginAccessControl':
                    logger.info(f"Origin Access Control {oac_id} does not exist, skipping deletion")
                    return
                raise
            
            # Try to delete the OAC
            cloudfront.delete_origin_access_control(Id=oac_id, IfMatch=etag)
            logger.info(f"Successfully deleted Origin Access Control: {oac_id}")
            return
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            
            if error_code == 'NoSuchOriginAccessControl':
                logger.info(f"Origin Access Control {oac_id} already deleted")
                return
            elif error_code in ['OriginAccessControlInUse', 'InvalidIfMatchVersion']:
                if attempt < max_retries - 1:
                    wait_time = (attempt + 1) * 30
                    logger.warning(f"Origin Access Control {oac_id} is in use, retrying in {wait_time} seconds (attempt {attempt + 1}/{max_retries})")
                    time.sleep(wait_time)
                    continue
                else:
                    logger.error(f"Failed to delete Origin Access Control {oac_id} after {max_retries} attempts: {e}")
                    return
            else:
                logger.error(f"Unexpected error deleting Origin Access Control {oac_id}: {e}")
                return

def send_response(event, context, response_status, response_data):
    """Send response to CloudFormation with robust error handling"""
    
    try:
        # Validate inputs
        if not event:
            raise ValueError("Event is None or empty")
        
        if 'ResponseURL' not in event:
            raise ValueError("ResponseURL not found in event")
        
        response_url = event['ResponseURL']
        
        # Build response body with safe defaults
        response_body = {
            'Status': response_status or 'FAILED',
            'Reason': f'See CloudWatch Log Stream: {getattr(context, "log_stream_name", "unknown")}',
            'PhysicalResourceId': str(
                response_data.get('PhysicalResourceId') if isinstance(response_data, dict) and response_data.get('PhysicalResourceId')
                else getattr(context, 'log_stream_name', 'unknown-resource')
            ),
            'StackId': event.get('StackId', 'unknown-stack'),
            'RequestId': event.get('RequestId', 'unknown-request'),
            'LogicalResourceId': event.get('LogicalResourceId', 'unknown-logical-resource'),
            'Data': response_data if isinstance(response_data, dict) else {'Result': str(response_data)}
        }
        
        # Serialize with error handling
        try:
            json_response_body = json.dumps(response_body)
        except Exception as json_error:
            logger.error(f"JSON serialization failed: {json_error}")
            # Fallback with string representation
            response_body['Data'] = {'Error': 'JSON serialization failed', 'OriginalData': str(response_data)[:500]}
            json_response_body = json.dumps(response_body)
        
        headers = {
            'content-type': '',
            'content-length': str(len(json_response_body))
        }
        
        # Send the response
        http = urllib3.PoolManager()
        response = http.request('PUT', response_url, body=json_response_body, headers=headers)
        logger.info(f"CloudFormation response sent successfully with status code: {response.status}")
        
        # Validate response
        if response.status not in [200, 201, 202]:
            logger.warning(f"Unexpected response status from CloudFormation: {response.status}")
        
    except Exception as e:
        logger.error(f"Failed to send response to CloudFormation: {e}", exc_info=True)
        
        # Try one more time with minimal data
        try:
            minimal_response = {
                'Status': 'FAILED',
                'Reason': f'Response send failed: {str(e)}',
                'PhysicalResourceId': 'send-response-failed',
                'StackId': event.get('StackId', 'unknown'),
                'RequestId': event.get('RequestId', 'unknown'),
                'LogicalResourceId': event.get('LogicalResourceId', 'unknown'),
                'Data': {'Error': 'Response transmission failed'}
            }
            
            minimal_json = json.dumps(minimal_response)
            minimal_headers = {'content-type': '', 'content-length': str(len(minimal_json))}
            
            http = urllib3.PoolManager()
            response = http.request('PUT', event['ResponseURL'], body=minimal_json, headers=minimal_headers)
            logger.info(f"Minimal response sent with status: {response.status}")
            
        except Exception as final_error:
            logger.error(f"Final response attempt also failed: {final_error}")
            # At this point, CloudFormation will timeout, but we've logged everything