#!/usr/bin/env python3
"""
Custom HTTP Client with Mobile App User-Agent Support
Provides a reusable HTTP client for mobile pentesting tools
"""

import requests
import ssl
import socket
import time
import json
import hashlib
import hmac
from typing import Dict, Optional, Any, List, Tuple
from urllib.parse import urlparse, parse_qs
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from datetime import datetime
import base64
import random
import string


class MobileHTTPClient:
    """Custom HTTP client with mobile-specific features"""
    
    # Common iOS user agents
    IOS_USER_AGENTS = {
        'default': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15',
        'safari': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
        'chrome': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/119.0.0.0 Mobile/15E148 Safari/604.1',
        'facebook': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 [FBAN/FBIOS;FBAV/440.0.0.32.113]',
        'instagram': 'Instagram 298.0.0.19.114 (iPhone13,2; iOS 17_0; en_US; en-US; scale=3.00; 1170x2532; 495067065)',
        'tiktok': 'TikTok 31.1.0 rv:311018 (iPhone; iOS 17.0; en_US) Cronet',
        'swiftui_default': 'MyApp/1.0 (com.example.myapp; build:1; iOS 17.0.0) Alamofire/5.6.1',
        'amplify': 'aws-amplify/5.0.0 iOS/17.0'
    }
    
    def __init__(self, 
                 base_url: Optional[str] = None,
                 user_agent: Optional[str] = None,
                 custom_headers: Optional[Dict[str, str]] = None,
                 verify_ssl: bool = True,
                 timeout: int = 30,
                 retry_count: int = 3,
                 proxy: Optional[Dict[str, str]] = None):
        """
        Initialize custom HTTP client
        
        Args:
            base_url: Base URL for API requests
            user_agent: Custom user agent string or preset name
            custom_headers: Additional headers to include
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
            retry_count: Number of retries for failed requests
            proxy: Proxy configuration
        """
        self.base_url = base_url
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        
        # Setup session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=retry_count,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set user agent
        if user_agent:
            if user_agent in self.IOS_USER_AGENTS:
                self.user_agent = self.IOS_USER_AGENTS[user_agent]
            else:
                self.user_agent = user_agent
        else:
            self.user_agent = self.IOS_USER_AGENTS['swiftui_default']
        
        # Setup headers
        self.headers = {
            'User-Agent': self.user_agent,
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br'
        }
        
        # Add iOS-specific headers
        self.headers.update({
            'X-Device-Type': 'iPhone',
            'X-OS-Version': 'iOS 17.0',
            'X-App-Version': '1.0.0',
            'X-Device-ID': self._generate_device_id()
        })
        
        if custom_headers:
            self.headers.update(custom_headers)
        
        self.session.headers.update(self.headers)
    
    def _generate_device_id(self) -> str:
        """Generate a realistic device ID"""
        return ''.join(random.choices(string.hexdigits.upper(), k=32))
    
    def set_auth_token(self, token: str, auth_type: str = 'Bearer'):
        """Set authorization token"""
        self.session.headers['Authorization'] = f'{auth_type} {token}'
    
    def set_aws_credentials(self, access_key: str, secret_key: str, session_token: Optional[str] = None):
        """Store AWS credentials for SigV4 signing"""
        self.aws_credentials = {
            'access_key': access_key,
            'secret_key': secret_key,
            'session_token': session_token
        }
    
    def sign_request_aws_v4(self, method: str, url: str, headers: Dict[str, str], 
                           payload: str = '') -> Dict[str, str]:
        """Sign request with AWS Signature V4"""
        if not hasattr(self, 'aws_credentials'):
            return headers
        
        # Parse URL
        parsed = urlparse(url)
        host = parsed.netloc
        uri = parsed.path or '/'
        
        # Create canonical request
        t = datetime.utcnow()
        amz_date = t.strftime('%Y%m%dT%H%M%SZ')
        date_stamp = t.strftime('%Y%m%d')
        
        headers['Host'] = host
        headers['X-Amz-Date'] = amz_date
        if self.aws_credentials.get('session_token'):
            headers['X-Amz-Security-Token'] = self.aws_credentials['session_token']
        
        # Create string to sign
        canonical_headers = '\n'.join([f'{k.lower()}:{v}' for k, v in sorted(headers.items())])
        signed_headers = ';'.join([k.lower() for k in sorted(headers.keys())])
        
        payload_hash = hashlib.sha256(payload.encode()).hexdigest()
        canonical_request = f"{method}\n{uri}\n\n{canonical_headers}\n\n{signed_headers}\n{payload_hash}"
        
        # Calculate signature
        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = f"{date_stamp}/us-east-1/execute-api/aws4_request"
        string_to_sign = f"{algorithm}\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode()).hexdigest()}"
        
        # Sign with secret key
        def sign(key, msg):
            return hmac.new(key, msg.encode(), hashlib.sha256).digest()
        
        k_date = sign(f"AWS4{self.aws_credentials['secret_key']}".encode(), date_stamp)
        k_region = sign(k_date, 'us-east-1')
        k_service = sign(k_region, 'execute-api')
        k_signing = sign(k_service, 'aws4_request')
        signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()
        
        # Add authorization header
        headers['Authorization'] = f"{algorithm} Credential={self.aws_credentials['access_key']}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
        
        return headers
    
    def request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make HTTP request with mobile-specific features"""
        # Build full URL
        if self.base_url and not endpoint.startswith('http'):
            url = f"{self.base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        else:
            url = endpoint
        
        # Prepare request parameters
        request_params = {
            'timeout': self.timeout,
            'verify': self.verify_ssl,
            'allow_redirects': kwargs.get('allow_redirects', True)
        }
        
        if self.proxy:
            request_params['proxies'] = self.proxy
        
        # Add any additional parameters
        for key in ['json', 'data', 'params', 'files']:
            if key in kwargs:
                request_params[key] = kwargs[key]
        
        # Add custom headers for this request
        headers = self.session.headers.copy()
        if 'headers' in kwargs:
            headers.update(kwargs['headers'])
        
        # Sign request if AWS credentials are set
        if hasattr(self, 'aws_credentials'):
            payload = ''
            if 'json' in request_params:
                payload = json.dumps(request_params['json'])
            elif 'data' in request_params:
                payload = request_params['data'] if isinstance(request_params['data'], str) else ''
            
            headers = self.sign_request_aws_v4(method, url, headers, payload)
        
        request_params['headers'] = headers
        
        # Make request
        response = self.session.request(method, url, **request_params)
        
        return response
    
    def get(self, endpoint: str, **kwargs) -> requests.Response:
        """GET request"""
        return self.request('GET', endpoint, **kwargs)
    
    def post(self, endpoint: str, **kwargs) -> requests.Response:
        """POST request"""
        return self.request('POST', endpoint, **kwargs)
    
    def put(self, endpoint: str, **kwargs) -> requests.Response:
        """PUT request"""
        return self.request('PUT', endpoint, **kwargs)
    
    def delete(self, endpoint: str, **kwargs) -> requests.Response:
        """DELETE request"""
        return self.request('DELETE', endpoint, **kwargs)
    
    def patch(self, endpoint: str, **kwargs) -> requests.Response:
        """PATCH request"""
        return self.request('PATCH', endpoint, **kwargs)
    
    def graphql(self, query: str, variables: Optional[Dict] = None, 
                operation_name: Optional[str] = None) -> requests.Response:
        """Execute GraphQL query"""
        payload = {'query': query}
        if variables:
            payload['variables'] = variables
        if operation_name:
            payload['operationName'] = operation_name
        
        return self.post('/graphql', json=payload)
    
    def test_certificate_pinning(self, url: str) -> Dict[str, Any]:
        """Test if certificate pinning is implemented"""
        results = {
            'pinning_detected': False,
            'certificate_info': {},
            'errors': []
        }
        
        try:
            # Try with normal request
            response1 = self.get(url)
            results['normal_request'] = response1.status_code == 200
            
            # Get certificate info
            parsed = urlparse(url)
            context = ssl.create_default_context()
            with socket.create_connection((parsed.hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=parsed.hostname) as ssock:
                    cert = ssock.getpeercert()
                    results['certificate_info'] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'notAfter': cert['notAfter']
                    }
            
            # Try with self-signed cert (would fail if pinning is enabled)
            self.verify_ssl = False
            try:
                response2 = self.get(url)
                if response1.status_code == 200 and response2.status_code != 200:
                    results['pinning_detected'] = True
            except:
                results['pinning_detected'] = True
            
            self.verify_ssl = True
            
        except Exception as e:
            results['errors'].append(str(e))
        
        return results
    
    def detect_rate_limiting(self, endpoint: str, requests_count: int = 50) -> Dict[str, Any]:
        """Detect rate limiting on endpoint"""
        results = {
            'rate_limited': False,
            'threshold': None,
            'window': None,
            'responses': []
        }
        
        success_count = 0
        for i in range(requests_count):
            try:
                start = time.time()
                response = self.get(endpoint)
                elapsed = time.time() - start
                
                results['responses'].append({
                    'request': i + 1,
                    'status': response.status_code,
                    'time': elapsed
                })
                
                if response.status_code == 200:
                    success_count += 1
                elif response.status_code == 429:
                    results['rate_limited'] = True
                    results['threshold'] = i
                    
                    # Check for rate limit headers
                    if 'X-RateLimit-Limit' in response.headers:
                        results['limit'] = response.headers['X-RateLimit-Limit']
                    if 'X-RateLimit-Remaining' in response.headers:
                        results['remaining'] = response.headers['X-RateLimit-Remaining']
                    if 'X-RateLimit-Reset' in response.headers:
                        results['reset'] = response.headers['X-RateLimit-Reset']
                    break
                
                time.sleep(0.1)  # Small delay between requests
                
            except Exception as e:
                results['responses'].append({
                    'request': i + 1,
                    'error': str(e)
                })
        
        results['success_rate'] = success_count / requests_count
        
        return results


class GraphQLClient(MobileHTTPClient):
    """Specialized GraphQL client for mobile apps"""
    
    def __init__(self, endpoint: str, **kwargs):
        super().__init__(base_url=endpoint, **kwargs)
        self.headers['Content-Type'] = 'application/json'
    
    def introspection_query(self) -> Dict[str, Any]:
        """Execute introspection query"""
        query = """
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                    ...FullType
                }
            }
        }
        
        fragment FullType on __Type {
            kind
            name
            description
            fields(includeDeprecated: true) {
                name
                description
                args {
                    ...InputValue
                }
                type {
                    ...TypeRef
                }
                isDeprecated
                deprecationReason
            }
            inputFields {
                ...InputValue
            }
            interfaces {
                ...TypeRef
            }
            enumValues(includeDeprecated: true) {
                name
                description
                isDeprecated
                deprecationReason
            }
            possibleTypes {
                ...TypeRef
            }
        }
        
        fragment InputValue on __InputValue {
            name
            description
            type { ...TypeRef }
            defaultValue
        }
        
        fragment TypeRef on __Type {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                    ofType {
                        kind
                        name
                    }
                }
            }
        }
        """
        
        response = self.graphql(query)
        return response.json() if response.status_code == 200 else None
    
    def batch_query(self, queries: List[Dict[str, Any]]) -> requests.Response:
        """Execute batch GraphQL queries"""
        return self.post('', json=queries)


# Example usage
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Mobile HTTP Client Testing')
    parser.add_argument('--url', required=True, help='Target URL')
    parser.add_argument('--user-agent', default='swiftui_default', 
                      choices=list(MobileHTTPClient.IOS_USER_AGENTS.keys()) + ['custom'],
                      help='User agent preset or custom')
    parser.add_argument('--custom-ua', help='Custom user agent string')
    parser.add_argument('--token', help='Authorization token')
    parser.add_argument('--proxy', help='Proxy URL')
    parser.add_argument('--test-pinning', action='store_true', help='Test certificate pinning')
    parser.add_argument('--test-rate-limit', action='store_true', help='Test rate limiting')
    
    args = parser.parse_args()
    
    # Setup client
    client_args = {
        'user_agent': args.custom_ua if args.user_agent == 'custom' else args.user_agent
    }
    
    if args.proxy:
        client_args['proxy'] = {'http': args.proxy, 'https': args.proxy}
    
    client = MobileHTTPClient(**client_args)
    
    if args.token:
        client.set_auth_token(args.token)
    
    print(f"[*] Testing {args.url}")
    print(f"[*] User-Agent: {client.user_agent}\n")
    
    # Basic request
    try:
        response = client.get(args.url)
        print(f"[+] Status: {response.status_code}")
        print(f"[+] Headers: {dict(response.headers)}")
    except Exception as e:
        print(f"[-] Request failed: {e}")
    
    # Test certificate pinning
    if args.test_pinning:
        print("\n[*] Testing certificate pinning...")
        results = client.test_certificate_pinning(args.url)
        if results['pinning_detected']:
            print("[+] Certificate pinning detected")
        else:
            print("[-] No certificate pinning detected")
        if results['certificate_info']:
            print(f"[*] Certificate: {results['certificate_info']}")
    
    # Test rate limiting
    if args.test_rate_limit:
        print("\n[*] Testing rate limiting...")
        results = client.detect_rate_limiting(args.url)
        if results['rate_limited']:
            print(f"[+] Rate limiting detected at {results['threshold']} requests")
        else:
            print(f"[-] No rate limiting detected ({results['success_rate']*100:.1f}% success)")