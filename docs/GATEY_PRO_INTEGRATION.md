# Gatey Pro Integration with Lambda@Edge Architecture

This guide explains how to integrate [Gatey Pro](https://wpsuite.io) with WordPress Static Site Guardian's new Lambda@Edge architecture.

## Overview

The Lambda@Edge architecture replaces the previous API Gateway approach with a more efficient, globally distributed cookie issuance system that uses JWT Bearer token authentication.

## Key Changes from API Gateway Version

### Before (API Gateway)
- Separate API subdomain (e.g., `api.example.com`)
- IAM-based authentication
- Regional endpoint

### After (Lambda@Edge)
- Cookie endpoint on main domain (`https://yourdomain.com/issue-cookie`)
- JWT Bearer token authentication
- Global edge locations

## Integration Steps

### 1. Update Gatey Pro Configuration

In your Gatey Pro settings, update the API configuration:

**Old Configuration:**
```
API Endpoint: https://api.yourdomain.com/issue-cookie
Authentication: IAM (AWS Access Key/Secret)
```

**New Configuration:**
```
API Endpoint: https://yourdomain.com/issue-cookie
Authentication: JWT Bearer Token
```

### 2. Configure JWT Token Source

Gatey Pro needs to provide JWT tokens for authentication. Configure your token source:

#### Option A: Cognito Integration
If using Amazon Cognito User Pools:

```php
// In your Gatey Pro custom authentication hook
function get_jwt_token_for_user($user_id) {
    // Get Cognito ID token or access token for the user
    $cognito_token = get_user_cognito_token($user_id);
    return $cognito_token;
}
```

#### Option B: Custom JWT Provider
If using a custom JWT provider:

```php
// In your Gatey Pro custom authentication hook
function get_jwt_token_for_user($user_id) {
    // Generate or retrieve JWT token for the user
    $jwt_token = generate_custom_jwt($user_id);
    return $jwt_token;
}
```

### 3. Update Sign-in Hook

Update your Gatey Pro sign-in hook to use JWT Bearer authentication:

```php
/**
 * Gatey Pro Sign-in Hook for Lambda@Edge
 */
function gatey_pro_signin_hook($user_id) {
    // Get JWT token for the user
    $jwt_token = get_jwt_token_for_user($user_id);
    
    if (!$jwt_token) {
        error_log('Failed to get JWT token for user: ' . $user_id);
        return false;
    }
    
    // Issue cookies via Lambda@Edge endpoint
    $endpoint = 'https://yourdomain.com/issue-cookie?action=signin';
    
    $response = wp_remote_get($endpoint, [
        'headers' => [
            'Authorization' => 'Bearer ' . $jwt_token,
            'Content-Type' => 'application/json'
        ],
        'timeout' => 10
    ]);
    
    if (is_wp_error($response)) {
        error_log('Cookie issuance failed: ' . $response->get_error_message());
        return false;
    }
    
    $status_code = wp_remote_retrieve_response_code($response);
    
    if ($status_code === 204) {
        // Success - cookies were set via Set-Cookie headers
        error_log('Cookies issued successfully for user: ' . $user_id);
        return true;
    } else {
        error_log('Cookie issuance failed with status: ' . $status_code);
        return false;
    }
}

// Hook into Gatey Pro sign-in event
add_action('gatey_pro_user_signin', 'gatey_pro_signin_hook');
```

### 4. Update Sign-out Hook

Update your Gatey Pro sign-out hook:

```php
/**
 * Gatey Pro Sign-out Hook for Lambda@Edge
 */
function gatey_pro_signout_hook($user_id) {
    // Get JWT token for the user (still needed for authentication)
    $jwt_token = get_jwt_token_for_user($user_id);
    
    if (!$jwt_token) {
        error_log('Failed to get JWT token for user signout: ' . $user_id);
        return false;
    }
    
    // Expire cookies via Lambda@Edge endpoint
    $endpoint = 'https://yourdomain.com/issue-cookie?action=signout';
    
    $response = wp_remote_get($endpoint, [
        'headers' => [
            'Authorization' => 'Bearer ' . $jwt_token,
            'Content-Type' => 'application/json'
        ],
        'timeout' => 10
    ]);
    
    if (is_wp_error($response)) {
        error_log('Cookie expiration failed: ' . $response->get_error_message());
        return false;
    }
    
    $status_code = wp_remote_retrieve_response_code($response);
    
    if ($status_code === 204) {
        // Success - cookies were expired
        error_log('Cookies expired successfully for user: ' . $user_id);
        return true;
    } else {
        error_log('Cookie expiration failed with status: ' . $status_code);
        return false;
    }
}

// Hook into Gatey Pro sign-out event
add_action('gatey_pro_user_signout', 'gatey_pro_signout_hook');
```

### 5. Error Handling and Logging

Implement comprehensive error handling:

```php
/**
 * Enhanced error handling for Lambda@Edge integration
 */
function handle_cookie_response($response, $action, $user_id) {
    if (is_wp_error($response)) {
        error_log("Cookie {$action} failed for user {$user_id}: " . $response->get_error_message());
        return false;
    }
    
    $status_code = wp_remote_retrieve_response_code($response);
    $response_body = wp_remote_retrieve_body($response);
    
    switch ($status_code) {
        case 204:
            error_log("Cookie {$action} successful for user {$user_id}");
            return true;
            
        case 401:
            error_log("JWT authentication failed for user {$user_id}: Invalid or expired token");
            return false;
            
        case 400:
            error_log("Bad request for user {$user_id}: " . $response_body);
            return false;
            
        case 500:
            error_log("Server error during cookie {$action} for user {$user_id}: " . $response_body);
            return false;
            
        default:
            error_log("Unexpected response code {$status_code} for user {$user_id}: " . $response_body);
            return false;
    }
}
```

## Testing Your Integration

### 1. Test JWT Token Generation

```php
// Test that JWT tokens are being generated correctly
function test_jwt_generation() {
    $user_id = get_current_user_id();
    $jwt_token = get_jwt_token_for_user($user_id);
    
    if ($jwt_token) {
        error_log('JWT token generated successfully: ' . substr($jwt_token, 0, 20) . '...');
        return true;
    } else {
        error_log('JWT token generation failed');
        return false;
    }
}
```

### 2. Test Cookie Issuance

```bash
# Test cookie issuance with curl
curl -v -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     "https://yourdomain.com/issue-cookie?action=signin"

# Expected response: 204 No Content with Set-Cookie headers
```

### 3. Test Protected Content Access

1. Sign in through Gatey Pro
2. Verify cookies are set in browser
3. Access protected content
4. Verify access is granted

## Troubleshooting

### Common Issues

1. **401 Unauthorized Responses**
   - Check JWT token validity and expiration
   - Verify Cognito User Pool ID and App Client IDs in CloudFormation parameters
   - Ensure JWT issuer matches configured User Pool

2. **Cookies Not Being Set**
   - Check browser developer tools for Set-Cookie headers
   - Verify domain matches (host-only cookies)
   - Check for HTTPS requirement

3. **Protected Content Still Blocked**
   - Verify cookies are present in browser
   - Check CloudFront signed cookie validation
   - Verify protected paths configuration

### Debug Mode

Enable debug logging in your Gatey Pro integration:

```php
// Add to wp-config.php for debugging
define('GATEY_PRO_DEBUG', true);

// Enhanced logging function
function gatey_pro_debug_log($message) {
    if (defined('GATEY_PRO_DEBUG') && GATEY_PRO_DEBUG) {
        error_log('[Gatey Pro Lambda@Edge] ' . $message);
    }
}
```

## Migration Checklist

- [ ] Update API endpoint URL (remove API subdomain)
- [ ] Configure JWT token source (Cognito or custom)
- [ ] Update sign-in hook with JWT Bearer authentication
- [ ] Update sign-out hook with JWT Bearer authentication
- [ ] Implement error handling and logging
- [ ] Test JWT token generation
- [ ] Test cookie issuance endpoint
- [ ] Test protected content access
- [ ] Verify sign-out functionality
- [ ] Monitor logs for any issues

## Benefits of Lambda@Edge Integration

- **Global Performance**: Cookie issuance happens at CloudFront edge locations worldwide
- **Reduced Latency**: No API Gateway round-trip required
- **Cost Savings**: Lower costs compared to API Gateway architecture
- **Simplified Architecture**: Fewer moving parts and dependencies
- **Better Security**: Host-only cookies provide better security isolation

## Support

For additional support with Gatey Pro integration:

1. Check the [Gatey Pro documentation](https://wpsuite.io/docs)
2. Review CloudWatch logs for Lambda@Edge function execution
3. Test JWT token validity using online JWT decoders
4. Verify CloudFormation stack outputs and configuration

## Example Complete Integration

Here's a complete example of a Gatey Pro integration file:

```php
<?php
/**
 * Gatey Pro Lambda@Edge Integration
 * Complete integration example for WordPress Static Site Guardian
 */

class GateyProLambdaEdgeIntegration {
    
    private $endpoint_base;
    private $cognito_client;
    
    public function __construct($domain) {
        $this->endpoint_base = "https://{$domain}/issue-cookie";
        $this->init_hooks();
    }
    
    private function init_hooks() {
        add_action('gatey_pro_user_signin', [$this, 'handle_signin']);
        add_action('gatey_pro_user_signout', [$this, 'handle_signout']);
    }
    
    public function handle_signin($user_id) {
        return $this->manage_cookies($user_id, 'signin');
    }
    
    public function handle_signout($user_id) {
        return $this->manage_cookies($user_id, 'signout');
    }
    
    private function manage_cookies($user_id, $action) {
        $jwt_token = $this->get_jwt_token($user_id);
        
        if (!$jwt_token) {
            $this->log("Failed to get JWT token for user {$user_id}");
            return false;
        }
        
        $endpoint = $this->endpoint_base . "?action={$action}";
        
        $response = wp_remote_get($endpoint, [
            'headers' => [
                'Authorization' => 'Bearer ' . $jwt_token,
                'Content-Type' => 'application/json'
            ],
            'timeout' => 10
        ]);
        
        return $this->handle_response($response, $action, $user_id);
    }
    
    private function get_jwt_token($user_id) {
        // Implement your JWT token retrieval logic here
        // This could be from Cognito, custom JWT provider, etc.
        return get_user_meta($user_id, 'cognito_id_token', true);
    }
    
    private function handle_response($response, $action, $user_id) {
        if (is_wp_error($response)) {
            $this->log("Cookie {$action} failed for user {$user_id}: " . $response->get_error_message());
            return false;
        }
        
        $status_code = wp_remote_retrieve_response_code($response);
        
        if ($status_code === 204) {
            $this->log("Cookie {$action} successful for user {$user_id}");
            return true;
        } else {
            $this->log("Cookie {$action} failed for user {$user_id} with status {$status_code}");
            return false;
        }
    }
    
    private function log($message) {
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('[Gatey Pro Lambda@Edge] ' . $message);
        }
    }
}

// Initialize the integration
new GateyProLambdaEdgeIntegration('yourdomain.com');
```

This integration provides a complete, production-ready solution for using Gatey Pro with the Lambda@Edge architecture.