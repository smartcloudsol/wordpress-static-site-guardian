# Amazon Cognito Integration Guide

This guide explains how to integrate Amazon Cognito User Pools with WordPress Static Site Guardian's Lambda@Edge architecture for JWT-based authentication.

## Overview

The Lambda@Edge architecture uses JWT Bearer tokens for authentication, making it perfectly compatible with Amazon Cognito User Pools. This integration provides enterprise-grade authentication with minimal setup.

## Architecture

```
User Authentication Flow:
1. User signs in via Cognito (web app, mobile app, etc.)
2. Cognito returns JWT tokens (ID token and/or access token)
3. Client calls /issue-cookie endpoint with JWT Bearer token
4. Lambda@Edge validates JWT against Cognito JWKS
5. Lambda@Edge issues signed CloudFront cookies
6. User can access protected content with cookies
```

## Prerequisites

1. **Amazon Cognito User Pool** configured and operational
2. **Cognito App Clients** configured for your applications
3. **WordPress Static Site Guardian** deployed with Lambda@Edge architecture

## Setup Steps

### 1. Configure Cognito User Pool

If you don't have a Cognito User Pool yet, create one:

```bash
# Create User Pool
aws cognito-idp create-user-pool \
    --pool-name "MyWordPressSite" \
    --policies '{
        "PasswordPolicy": {
            "MinimumLength": 8,
            "RequireUppercase": true,
            "RequireLowercase": true,
            "RequireNumbers": true,
            "RequireSymbols": false
        }
    }' \
    --auto-verified-attributes email \
    --username-attributes email \
    --region us-east-1

# Note the UserPoolId from the response
```

### 2. Create App Clients

Create app clients for your applications:

```bash
# Create App Client for web application
aws cognito-idp create-user-pool-client \
    --user-pool-id us-east-1_XXXXXXXXX \
    --client-name "WebApp" \
    --generate-secret \
    --explicit-auth-flows ADMIN_NO_SRP_AUTH ALLOW_USER_PASSWORD_AUTH ALLOW_REFRESH_TOKEN_AUTH \
    --token-validity-units '{
        "AccessToken": "hours",
        "IdToken": "hours", 
        "RefreshToken": "days"
    }' \
    --access-token-validity 1 \
    --id-token-validity 1 \
    --refresh-token-validity 30 \
    --region us-east-1

# Note the ClientId from the response
```

### 3. Deploy WordPress Static Site Guardian

Deploy with your Cognito configuration:

```bash
./scripts/deploy-from-sar.sh \
  --stack-name my-wordpress-protection \
  --domain example.com \
  --certificate-arn arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012 \
  --cognito-user-pool-id us-east-1_XXXXXXXXX \
  --cognito-app-client-ids "client1,client2" \
  --kms-key-id 12345678-1234-1234-1234-123456789012 \
  --public-key-content "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..." \
  --protected-paths "/dashboard,/members,/courses"
```

## JWT Token Types

### ID Tokens
- **Purpose**: User identity information
- **Audience Claim**: `aud` (App Client ID)
- **Token Use**: `id`
- **Best For**: User authentication and profile information

### Access Tokens  
- **Purpose**: API access authorization
- **Audience Claim**: `client_id` (App Client ID)
- **Token Use**: `access`
- **Best For**: API calls and resource access

Both token types are supported by the Lambda@Edge function.

## Client-Side Integration

### Web Application (JavaScript)

```javascript
/**
 * Cognito Authentication with WordPress Static Site Guardian
 */
class CognitoAuth {
    constructor(userPoolId, clientId, region = 'us-east-1') {
        this.userPoolId = userPoolId;
        this.clientId = clientId;
        this.region = region;
        this.cognitoUser = null;
    }
    
    /**
     * Sign in user and get JWT tokens
     */
    async signIn(username, password) {
        try {
            const authData = {
                Username: username,
                Password: password,
            };
            
            const authDetails = new AmazonCognitoIdentity.AuthenticationDetails(authData);
            
            const userData = {
                Username: username,
                Pool: this.getUserPool()
            };
            
            this.cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
            
            return new Promise((resolve, reject) => {
                this.cognitoUser.authenticateUser(authDetails, {
                    onSuccess: (result) => {
                        const idToken = result.getIdToken().getJwtToken();
                        const accessToken = result.getAccessToken().getJwtToken();
                        
                        // Issue cookies using ID token
                        this.issueCookies(idToken)
                            .then(() => resolve({ idToken, accessToken }))
                            .catch(reject);
                    },
                    onFailure: (err) => {
                        reject(err);
                    }
                });
            });
        } catch (error) {
            throw new Error(`Sign in failed: ${error.message}`);
        }
    }
    
    /**
     * Issue cookies via Lambda@Edge endpoint
     */
    async issueCookies(jwtToken) {
        try {
            const response = await fetch('/issue-cookie?action=signin', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${jwtToken}`,
                    'Content-Type': 'application/json'
                },
                credentials: 'include' // Important for cookies
            });
            
            if (response.status === 204) {
                console.log('Cookies issued successfully');
                return true;
            } else {
                const errorText = await response.text();
                throw new Error(`Cookie issuance failed: ${response.status} ${errorText}`);
            }
        } catch (error) {
            throw new Error(`Cookie issuance error: ${error.message}`);
        }
    }
    
    /**
     * Sign out user and expire cookies
     */
    async signOut() {
        try {
            if (this.cognitoUser) {
                // Get current session for token
                const session = await this.getCurrentSession();
                const idToken = session.getIdToken().getJwtToken();
                
                // Expire cookies first
                await this.expireCookies(idToken);
                
                // Then sign out from Cognito
                this.cognitoUser.signOut();
                this.cognitoUser = null;
                
                console.log('Sign out successful');
                return true;
            }
        } catch (error) {
            console.error('Sign out error:', error);
            throw error;
        }
    }
    
    /**
     * Expire cookies via Lambda@Edge endpoint
     */
    async expireCookies(jwtToken) {
        try {
            const response = await fetch('/issue-cookie?action=signout', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${jwtToken}`,
                    'Content-Type': 'application/json'
                },
                credentials: 'include'
            });
            
            if (response.status === 204) {
                console.log('Cookies expired successfully');
                return true;
            } else {
                const errorText = await response.text();
                throw new Error(`Cookie expiration failed: ${response.status} ${errorText}`);
            }
        } catch (error) {
            throw new Error(`Cookie expiration error: ${error.message}`);
        }
    }
    
    /**
     * Get current session
     */
    getCurrentSession() {
        return new Promise((resolve, reject) => {
            if (!this.cognitoUser) {
                reject(new Error('No user session'));
                return;
            }
            
            this.cognitoUser.getSession((err, session) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(session);
                }
            });
        });
    }
    
    /**
     * Get Cognito User Pool
     */
    getUserPool() {
        const poolData = {
            UserPoolId: this.userPoolId,
            ClientId: this.clientId
        };
        return new AmazonCognitoIdentity.CognitoUserPool(poolData);
    }
    
    /**
     * Check if user is authenticated
     */
    async isAuthenticated() {
        try {
            const session = await this.getCurrentSession();
            return session.isValid();
        } catch (error) {
            return false;
        }
    }
}

// Usage example
const auth = new CognitoAuth('us-east-1_XXXXXXXXX', 'your-client-id');

// Sign in
document.getElementById('signin-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    try {
        await auth.signIn(username, password);
        alert('Sign in successful! You can now access protected content.');
        window.location.href = '/dashboard'; // Redirect to protected content
    } catch (error) {
        alert('Sign in failed: ' + error.message);
    }
});

// Sign out
document.getElementById('signout-btn').addEventListener('click', async () => {
    try {
        await auth.signOut();
        alert('Signed out successfully');
        window.location.href = '/'; // Redirect to home
    } catch (error) {
        alert('Sign out failed: ' + error.message);
    }
});
```

### React Application

```jsx
/**
 * React Hook for Cognito Authentication
 */
import { useState, useEffect, createContext, useContext } from 'react';

const AuthContext = createContext();

export const useAuth = () => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
};

export const AuthProvider = ({ children, userPoolId, clientId }) => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);
    const [cognitoAuth, setCognitoAuth] = useState(null);
    
    useEffect(() => {
        const auth = new CognitoAuth(userPoolId, clientId);
        setCognitoAuth(auth);
        
        // Check if user is already authenticated
        auth.isAuthenticated()
            .then(isAuth => {
                if (isAuth) {
                    setUser({ authenticated: true });
                }
            })
            .finally(() => setLoading(false));
    }, [userPoolId, clientId]);
    
    const signIn = async (username, password) => {
        try {
            setLoading(true);
            const tokens = await cognitoAuth.signIn(username, password);
            setUser({ authenticated: true, tokens });
            return tokens;
        } finally {
            setLoading(false);
        }
    };
    
    const signOut = async () => {
        try {
            setLoading(true);
            await cognitoAuth.signOut();
            setUser(null);
        } finally {
            setLoading(false);
        }
    };
    
    const value = {
        user,
        loading,
        signIn,
        signOut,
        isAuthenticated: !!user?.authenticated
    };
    
    return (
        <AuthContext.Provider value={value}>
            {children}
        </AuthContext.Provider>
    );
};

// Usage in components
const SignInForm = () => {
    const { signIn, loading } = useAuth();
    const [credentials, setCredentials] = useState({ username: '', password: '' });
    
    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            await signIn(credentials.username, credentials.password);
            // Redirect to protected content
            window.location.href = '/dashboard';
        } catch (error) {
            alert('Sign in failed: ' + error.message);
        }
    };
    
    return (
        <form onSubmit={handleSubmit}>
            <input
                type="email"
                placeholder="Email"
                value={credentials.username}
                onChange={(e) => setCredentials({...credentials, username: e.target.value})}
                required
            />
            <input
                type="password"
                placeholder="Password"
                value={credentials.password}
                onChange={(e) => setCredentials({...credentials, password: e.target.value})}
                required
            />
            <button type="submit" disabled={loading}>
                {loading ? 'Signing in...' : 'Sign In'}
            </button>
        </form>
    );
};
```

### Mobile Application (React Native)

```javascript
/**
 * React Native Cognito Integration
 */
import { Auth } from 'aws-amplify';

// Configure Amplify
Auth.configure({
    region: 'us-east-1',
    userPoolId: 'us-east-1_XXXXXXXXX',
    userPoolWebClientId: 'your-client-id',
});

class MobileCognitoAuth {
    /**
     * Sign in and issue cookies
     */
    async signIn(username, password) {
        try {
            const user = await Auth.signIn(username, password);
            const session = await Auth.currentSession();
            const idToken = session.getIdToken().getJwtToken();
            
            // Issue cookies
            await this.issueCookies(idToken);
            
            return user;
        } catch (error) {
            throw new Error(`Sign in failed: ${error.message}`);
        }
    }
    
    /**
     * Issue cookies via Lambda@Edge endpoint
     */
    async issueCookies(jwtToken) {
        try {
            const response = await fetch('https://yourdomain.com/issue-cookie?action=signin', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${jwtToken}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (response.status !== 204) {
                const errorText = await response.text();
                throw new Error(`Cookie issuance failed: ${response.status} ${errorText}`);
            }
            
            return true;
        } catch (error) {
            throw new Error(`Cookie issuance error: ${error.message}`);
        }
    }
    
    /**
     * Sign out and expire cookies
     */
    async signOut() {
        try {
            const session = await Auth.currentSession();
            const idToken = session.getIdToken().getJwtToken();
            
            // Expire cookies first
            await this.expireCookies(idToken);
            
            // Then sign out from Cognito
            await Auth.signOut();
            
            return true;
        } catch (error) {
            throw new Error(`Sign out failed: ${error.message}`);
        }
    }
    
    /**
     * Expire cookies via Lambda@Edge endpoint
     */
    async expireCookies(jwtToken) {
        try {
            const response = await fetch('https://yourdomain.com/issue-cookie?action=signout', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${jwtToken}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (response.status !== 204) {
                const errorText = await response.text();
                throw new Error(`Cookie expiration failed: ${response.status} ${errorText}`);
            }
            
            return true;
        } catch (error) {
            throw new Error(`Cookie expiration error: ${error.message}`);
        }
    }
}
```

## Server-Side Integration

### Node.js/Express

```javascript
/**
 * Node.js server-side integration
 */
const AWS = require('aws-sdk');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

class ServerSideCognitoAuth {
    constructor(userPoolId, region = 'us-east-1') {
        this.userPoolId = userPoolId;
        this.region = region;
        this.jwksUri = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}/.well-known/jwks.json`;
        
        this.client = jwksClient({
            jwksUri: this.jwksUri,
            cache: true,
            cacheMaxAge: 3600000, // 1 hour
            rateLimit: true,
            jwksRequestsPerMinute: 5
        });
    }
    
    /**
     * Verify JWT token
     */
    async verifyToken(token) {
        try {
            const decoded = jwt.decode(token, { complete: true });
            if (!decoded) {
                throw new Error('Invalid token format');
            }
            
            const kid = decoded.header.kid;
            const key = await this.getSigningKey(kid);
            
            const verified = jwt.verify(token, key, {
                issuer: `https://cognito-idp.${this.region}.amazonaws.com/${this.userPoolId}`,
                algorithms: ['RS256']
            });
            
            return verified;
        } catch (error) {
            throw new Error(`Token verification failed: ${error.message}`);
        }
    }
    
    /**
     * Get signing key from JWKS
     */
    async getSigningKey(kid) {
        return new Promise((resolve, reject) => {
            this.client.getSigningKey(kid, (err, key) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(key.getPublicKey());
                }
            });
        });
    }
    
    /**
     * Issue cookies for authenticated user
     */
    async issueCookies(req, res, jwtToken) {
        try {
            // Verify the JWT token first
            const payload = await this.verifyToken(jwtToken);
            
            // Make request to Lambda@Edge endpoint
            const response = await fetch(`https://${req.get('host')}/issue-cookie?action=signin`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${jwtToken}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (response.status === 204) {
                // Forward Set-Cookie headers to client
                const setCookieHeaders = response.headers.get('set-cookie');
                if (setCookieHeaders) {
                    res.set('Set-Cookie', setCookieHeaders);
                }
                return true;
            } else {
                throw new Error(`Cookie issuance failed: ${response.status}`);
            }
        } catch (error) {
            throw new Error(`Server-side cookie issuance failed: ${error.message}`);
        }
    }
}

// Express middleware
const cognitoAuth = new ServerSideCognitoAuth('us-east-1_XXXXXXXXX');

app.post('/auth/signin', async (req, res) => {
    try {
        const { idToken } = req.body;
        
        if (!idToken) {
            return res.status(400).json({ error: 'ID token required' });
        }
        
        await cognitoAuth.issueCookies(req, res, idToken);
        
        res.status(200).json({ message: 'Authentication successful' });
    } catch (error) {
        res.status(401).json({ error: error.message });
    }
});
```

## Testing Your Integration

### 1. Test JWT Token Validation

```bash
# Get a JWT token from Cognito (replace with actual token)
JWT_TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

# Test token with online JWT decoder
echo $JWT_TOKEN | base64 -d

# Test cookie issuance
curl -v -H "Authorization: Bearer $JWT_TOKEN" \
     "https://yourdomain.com/issue-cookie?action=signin"
```

### 2. Test Protected Content Access

```bash
# After issuing cookies, test protected content access
curl -v -b cookies.txt "https://yourdomain.com/dashboard/"
```

### 3. Automated Testing Script

```bash
#!/bin/bash
# test-cognito-integration.sh

set -e

DOMAIN="yourdomain.com"
USERNAME="test@example.com"
PASSWORD="TestPassword123!"
USER_POOL_ID="us-east-1_XXXXXXXXX"
CLIENT_ID="your-client-id"

echo "Testing Cognito Integration..."

# 1. Authenticate with Cognito (requires AWS CLI and jq)
echo "1. Authenticating with Cognito..."
AUTH_RESPONSE=$(aws cognito-idp admin-initiate-auth \
    --user-pool-id $USER_POOL_ID \
    --client-id $CLIENT_ID \
    --auth-flow ADMIN_NO_SRP_AUTH \
    --auth-parameters USERNAME=$USERNAME,PASSWORD=$PASSWORD \
    --region us-east-1)

ID_TOKEN=$(echo $AUTH_RESPONSE | jq -r '.AuthenticationResult.IdToken')

if [ "$ID_TOKEN" = "null" ]; then
    echo "❌ Failed to get ID token from Cognito"
    exit 1
fi

echo "✅ Got ID token from Cognito"

# 2. Test cookie issuance
echo "2. Testing cookie issuance..."
COOKIE_RESPONSE=$(curl -s -w "%{http_code}" \
    -H "Authorization: Bearer $ID_TOKEN" \
    -c cookies.txt \
    "https://$DOMAIN/issue-cookie?action=signin")

if [ "$COOKIE_RESPONSE" = "204" ]; then
    echo "✅ Cookies issued successfully"
else
    echo "❌ Cookie issuance failed with status: $COOKIE_RESPONSE"
    exit 1
fi

# 3. Test protected content access
echo "3. Testing protected content access..."
PROTECTED_RESPONSE=$(curl -s -w "%{http_code}" \
    -b cookies.txt \
    "https://$DOMAIN/dashboard/")

if [ "$PROTECTED_RESPONSE" = "200" ]; then
    echo "✅ Protected content accessible with cookies"
else
    echo "❌ Protected content access failed with status: $PROTECTED_RESPONSE"
    exit 1
fi

# 4. Test cookie expiration
echo "4. Testing cookie expiration..."
SIGNOUT_RESPONSE=$(curl -s -w "%{http_code}" \
    -H "Authorization: Bearer $ID_TOKEN" \
    -c cookies.txt \
    "https://$DOMAIN/issue-cookie?action=signout")

if [ "$SIGNOUT_RESPONSE" = "204" ]; then
    echo "✅ Cookies expired successfully"
else
    echo "❌ Cookie expiration failed with status: $SIGNOUT_RESPONSE"
    exit 1
fi

echo "🎉 All tests passed! Cognito integration is working correctly."
```

## Troubleshooting

### Common Issues

1. **JWT Signature Verification Fails**
   - Check User Pool ID matches deployment parameter
   - Verify token hasn't expired
   - Ensure JWKS endpoint is accessible

2. **Invalid Audience Claim**
   - Verify App Client IDs match deployment parameters
   - Check token type (ID vs Access token)
   - Ensure token_use claim matches token type

3. **CORS Issues**
   - Ensure credentials: 'include' in fetch requests
   - Check domain matches between Cognito and CloudFront

### Debug Commands

```bash
# Decode JWT token to inspect claims
echo "JWT_TOKEN" | cut -d. -f2 | base64 -d | jq

# Test JWKS endpoint
curl https://cognito-idp.us-east-1.amazonaws.com/us-east-1_XXXXXXXXX/.well-known/jwks.json

# Check CloudWatch logs for Lambda@Edge
aws logs describe-log-groups --log-group-name-prefix "/aws/lambda/us-east-1."
```

## Best Practices

1. **Token Management**
   - Use ID tokens for authentication
   - Implement token refresh logic
   - Store tokens securely (not in localStorage for sensitive apps)

2. **Error Handling**
   - Implement comprehensive error handling
   - Log authentication failures for monitoring
   - Provide user-friendly error messages

3. **Security**
   - Use HTTPS for all communications
   - Implement proper CORS policies
   - Validate tokens on both client and server side

4. **Performance**
   - Cache JWKS keys appropriately
   - Implement token refresh before expiration
   - Use connection pooling for API calls

This integration provides a robust, scalable authentication solution that leverages AWS Cognito's enterprise features with the global performance of Lambda@Edge.