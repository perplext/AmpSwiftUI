#!/usr/bin/env python3
"""
HMAC & Request Signing Analyzer
Comprehensive analysis of HMAC implementations, request signing, and replay attack vulnerabilities
"""

import os
import sys
import json
import hmac
import hashlib
import time
import base64
import argparse
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs
import concurrent.futures
import itertools
import string

class HMACAnalyzer:
    def __init__(self, target_url: str, custom_headers: Dict = None):
        self.target_url = target_url
        self.session = requests.Session()
        self.custom_headers = custom_headers or {}
        
        # Common HMAC header patterns
        self.signature_headers = [
            'X-Request-Signature', 'X-Signature', 'X-HMAC-Signature',
            'X-Hub-Signature', 'X-Hub-Signature-256', 'Authorization',
            'X-Api-Signature', 'X-Auth-Signature', 'X-CT-Authorization',
            'X-Amz-Signature', 'Signature', 'X-Hmac', 'X-Content-HMAC'
        ]
        
        self.timestamp_headers = [
            'X-Request-Timestamp', 'X-Timestamp', 'X-Time',
            'X-CT-Timestamp', 'X-Amz-Date', 'Date', 'X-Date',
            'X-Auth-Timestamp', 'X-Api-Timestamp'
        ]
        
        self.nonce_headers = [
            'X-Nonce', 'X-Request-Nonce', 'X-Api-Nonce',
            'X-Auth-Nonce', 'Nonce', 'X-Request-Id'
        ]
        
        # Common weak secrets for testing
        self.weak_secrets = [
            'secret', 'Secret123', 'password', 'Password123',
            'key', 'apikey', 'secret_key', 'private_key',
            'test', 'demo', 'example', 'sample',
            'admin', 'root', 'default', 'changeme',
            '12345678', 'qwerty', 'letmein'
        ]
        
        # AWS SigV4 detection patterns
        self.aws_sigv4_patterns = {
            'authorization': r'AWS4-HMAC-SHA256',
            'credential': r'Credential=([^/]+)/(\d{8})/([^/]+)/([^/]+)/aws4_request',
            'signed_headers': r'SignedHeaders=([^,]+)',
            'signature': r'Signature=([a-f0-9]{64})'
        }
        
    def detect_hmac_implementation(self, response: requests.Response) -> Dict:
        """Detect HMAC implementation from response headers"""
        print("[*] Detecting HMAC implementation...")
        
        detected = {
            'uses_hmac': False,
            'signature_header': None,
            'timestamp_header': None,
            'nonce_header': None,
            'algorithm': None,
            'aws_sigv4': False,
            'custom_scheme': False
        }
        
        headers = response.headers
        
        # Check for signature headers
        for header in self.signature_headers:
            if header in headers:
                detected['uses_hmac'] = True
                detected['signature_header'] = header
                sig_value = headers[header]
                
                # Detect algorithm from signature
                if 'sha256' in sig_value.lower() or len(sig_value) == 64:
                    detected['algorithm'] = 'SHA-256'
                elif 'sha512' in sig_value.lower() or len(sig_value) == 128:
                    detected['algorithm'] = 'SHA-512'
                elif 'sha1' in sig_value.lower() or len(sig_value) == 40:
                    detected['algorithm'] = 'SHA-1'
                
                # Check for AWS SigV4
                if 'AWS4-HMAC-SHA256' in sig_value:
                    detected['aws_sigv4'] = True
                    detected['algorithm'] = 'AWS4-HMAC-SHA256'
                
                break
        
        # Check for timestamp headers
        for header in self.timestamp_headers:
            if header in headers:
                detected['timestamp_header'] = header
                break
        
        # Check for nonce headers
        for header in self.nonce_headers:
            if header in headers:
                detected['nonce_header'] = header
                break
        
        # If HMAC detected but not AWS, it's likely custom
        if detected['uses_hmac'] and not detected['aws_sigv4']:
            detected['custom_scheme'] = True
        
        return detected
    
    def test_replay_attack(self, request_data: Dict) -> Dict:
        """Test for replay attack vulnerabilities"""
        print("[*] Testing replay attack vulnerability...")
        
        results = {
            'vulnerable': False,
            'timestamp_validation': False,
            'nonce_validation': False,
            'window_size': None,
            'details': []
        }
        
        # Capture initial request
        response1 = self.session.post(
            self.target_url,
            json=request_data,
            headers=self.custom_headers
        )
        
        if response1.status_code != 200:
            results['details'].append("Initial request failed")
            return results
        
        # Wait and replay exact same request
        time.sleep(2)
        response2 = self.session.post(
            self.target_url,
            json=request_data,
            headers=self.custom_headers
        )
        
        if response2.status_code == 200:
            results['vulnerable'] = True
            results['details'].append("Request replay successful - VULNERABLE")
        else:
            results['details'].append("Request replay blocked")
        
        # Test timestamp validation windows
        if 'X-Request-Timestamp' in self.custom_headers:
            print("[*] Testing timestamp validation windows...")
            
            for window in [30, 60, 300, 900, 3600]:  # seconds
                old_timestamp = int(time.time()) - window
                test_headers = self.custom_headers.copy()
                test_headers['X-Request-Timestamp'] = str(old_timestamp)
                
                response = self.session.post(
                    self.target_url,
                    json=request_data,
                    headers=test_headers
                )
                
                if response.status_code != 200:
                    results['timestamp_validation'] = True
                    results['window_size'] = window
                    results['details'].append(f"Timestamp window: {window} seconds")
                    break
        
        # Test nonce reuse
        if 'X-Nonce' in self.custom_headers:
            print("[*] Testing nonce reuse...")
            
            # Try same nonce again
            response = self.session.post(
                self.target_url,
                json=request_data,
                headers=self.custom_headers
            )
            
            if response.status_code != 200:
                results['nonce_validation'] = True
                results['details'].append("Nonce reuse prevented")
            else:
                results['vulnerable'] = True
                results['details'].append("Nonce reuse allowed - VULNERABLE")
        
        return results
    
    def brute_force_hmac_secret(self, request_data: Dict, signature: str, 
                               algorithm: str = 'sha256') -> Optional[str]:
        """Attempt to brute-force weak HMAC secrets"""
        print("[*] Testing for weak HMAC secrets...")
        
        # Reconstruct the message that was signed
        message = self._reconstruct_signed_message(request_data)
        
        # Test weak secrets
        for secret in self.weak_secrets:
            test_signature = self._generate_hmac(message, secret, algorithm)
            
            if test_signature == signature:
                print(f"[!] WEAK SECRET FOUND: {secret}")
                return secret
        
        # Test common patterns
        print("[*] Testing common secret patterns...")
        
        # API key patterns
        for prefix in ['sk_', 'pk_', 'api_', 'key_']:
            for suffix in ['test', 'live', 'prod', 'dev']:
                secret = f"{prefix}{suffix}"
                test_signature = self._generate_hmac(message, secret, algorithm)
                if test_signature == signature:
                    print(f"[!] WEAK SECRET FOUND: {secret}")
                    return secret
        
        return None
    
    def test_timing_attack(self, endpoint: str, valid_signature: str) -> Dict:
        """Test for timing attack vulnerabilities in HMAC validation"""
        print("[*] Testing for timing attack vulnerability...")
        
        results = {
            'vulnerable': False,
            'timing_differences': [],
            'details': []
        }
        
        # Generate signatures with increasing correctness
        test_sigs = []
        
        # Completely wrong signature
        test_sigs.append('0' * len(valid_signature))
        
        # Partially correct signatures (for timing attack)
        for i in range(0, len(valid_signature), 8):
            partial = valid_signature[:i] + '0' * (len(valid_signature) - i)
            test_sigs.append(partial)
        
        # Measure response times
        timings = []
        
        for sig in test_sigs:
            headers = self.custom_headers.copy()
            headers['X-Request-Signature'] = sig
            
            times = []
            # Multiple measurements for accuracy
            for _ in range(5):
                start = time.perf_counter()
                response = self.session.post(endpoint, headers=headers)
                end = time.perf_counter()
                times.append(end - start)
            
            avg_time = sum(times) / len(times)
            timings.append(avg_time)
            
        # Analyze timing differences
        if timings:
            min_time = min(timings)
            max_time = max(timings)
            diff = max_time - min_time
            
            results['timing_differences'] = timings
            
            # If timing increases with correctness, vulnerable
            if diff > 0.01:  # 10ms difference threshold
                results['vulnerable'] = True
                results['details'].append(f"Timing difference detected: {diff*1000:.2f}ms")
                results['details'].append("Possible timing attack vulnerability")
            else:
                results['details'].append("No significant timing differences detected")
        
        return results
    
    def analyze_aws_sigv4(self, headers: Dict) -> Dict:
        """Analyze AWS Signature Version 4 implementation"""
        print("[*] Analyzing AWS SigV4 implementation...")
        
        analysis = {
            'uses_sigv4': False,
            'access_key': None,
            'date': None,
            'region': None,
            'service': None,
            'signed_headers': [],
            'vulnerabilities': []
        }
        
        auth_header = headers.get('Authorization', '')
        
        if 'AWS4-HMAC-SHA256' in auth_header:
            analysis['uses_sigv4'] = True
            
            # Extract components
            import re
            
            # Extract credential scope
            cred_match = re.search(self.aws_sigv4_patterns['credential'], auth_header)
            if cred_match:
                analysis['access_key'] = cred_match.group(1)
                analysis['date'] = cred_match.group(2)
                analysis['region'] = cred_match.group(3)
                analysis['service'] = cred_match.group(4)
            
            # Extract signed headers
            signed_match = re.search(self.aws_sigv4_patterns['signed_headers'], auth_header)
            if signed_match:
                analysis['signed_headers'] = signed_match.group(1).split(';')
            
            # Check for vulnerabilities
            if analysis['access_key'] and analysis['access_key'].startswith('AKIA'):
                analysis['vulnerabilities'].append("Real AWS access key exposed")
            
            if 'host' not in [h.lower() for h in analysis['signed_headers']]:
                analysis['vulnerabilities'].append("Host header not signed - vulnerable to tampering")
            
            if 'x-amz-date' not in [h.lower() for h in analysis['signed_headers']]:
                analysis['vulnerabilities'].append("Date not properly signed")
        
        return analysis
    
    def test_signature_bypass(self, endpoint: str) -> Dict:
        """Test various signature bypass techniques"""
        print("[*] Testing signature bypass techniques...")
        
        results = {
            'bypasses': [],
            'vulnerable': False
        }
        
        bypass_tests = [
            # Remove signature header
            ('no_signature', lambda h: {k: v for k, v in h.items() 
                                       if 'signature' not in k.lower()}),
            
            # Empty signature
            ('empty_signature', lambda h: {**h, 'X-Request-Signature': ''}),
            
            # None algorithm (JWT-style attack)
            ('none_algorithm', lambda h: {**h, 'X-Algorithm': 'none'}),
            
            # Case variation
            ('case_variation', lambda h: {k.swapcase(): v for k, v in h.items()}),
            
            # Unicode characters
            ('unicode_bypass', lambda h: {**h, 'X-Request-Signature': 
                                         h.get('X-Request-Signature', '') + '\u0000'}),
            
            # Length extension
            ('length_extension', lambda h: {**h, 'X-Request-Signature': 
                                           h.get('X-Request-Signature', '') + 'padding'})
        ]
        
        for test_name, modifier in bypass_tests:
            test_headers = modifier(self.custom_headers.copy())
            
            try:
                response = self.session.post(
                    endpoint,
                    headers=test_headers,
                    timeout=5
                )
                
                if response.status_code == 200:
                    results['bypasses'].append(test_name)
                    results['vulnerable'] = True
                    print(f"[!] Bypass successful: {test_name}")
                    
            except Exception as e:
                pass
        
        return results
    
    def _reconstruct_signed_message(self, request_data: Dict) -> str:
        """Reconstruct the message that was signed"""
        # Common patterns for message construction
        patterns = [
            # JSON body
            json.dumps(request_data, separators=(',', ':')),
            
            # URL + body
            f"{self.target_url}{json.dumps(request_data)}",
            
            # Method + URL + body
            f"POST{self.target_url}{json.dumps(request_data)}",
            
            # Timestamp + body (if available)
            f"{self.custom_headers.get('X-Request-Timestamp', '')}{json.dumps(request_data)}"
        ]
        
        return patterns[0]  # Default to JSON body
    
    def _generate_hmac(self, message: str, secret: str, algorithm: str = 'sha256') -> str:
        """Generate HMAC signature"""
        if algorithm.lower() == 'sha256':
            h = hmac.new(secret.encode(), message.encode(), hashlib.sha256)
        elif algorithm.lower() == 'sha512':
            h = hmac.new(secret.encode(), message.encode(), hashlib.sha512)
        elif algorithm.lower() == 'sha1':
            h = hmac.new(secret.encode(), message.encode(), hashlib.sha1)
        else:
            h = hmac.new(secret.encode(), message.encode(), hashlib.sha256)
        
        return h.hexdigest()
    
    def generate_report(self, findings: Dict) -> Dict:
        """Generate comprehensive HMAC security report"""
        print("[*] Generating HMAC security report...")
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'target': self.target_url,
            'summary': {
                'uses_hmac': findings.get('detection', {}).get('uses_hmac', False),
                'algorithm': findings.get('detection', {}).get('algorithm', 'Unknown'),
                'replay_vulnerable': findings.get('replay', {}).get('vulnerable', False),
                'timing_vulnerable': findings.get('timing', {}).get('vulnerable', False),
                'weak_secret': findings.get('brute_force', {}).get('secret_found', False),
                'bypass_possible': len(findings.get('bypass', {}).get('bypasses', [])) > 0
            },
            'vulnerabilities': [],
            'recommendations': []
        }
        
        # Compile vulnerabilities
        if report['summary']['replay_vulnerable']:
            report['vulnerabilities'].append({
                'type': 'Replay Attack',
                'severity': 'HIGH',
                'description': 'Requests can be replayed without detection'
            })
        
        if report['summary']['timing_vulnerable']:
            report['vulnerabilities'].append({
                'type': 'Timing Attack',
                'severity': 'MEDIUM',
                'description': 'HMAC validation vulnerable to timing analysis'
            })
        
        if report['summary']['weak_secret']:
            report['vulnerabilities'].append({
                'type': 'Weak Secret',
                'severity': 'CRITICAL',
                'description': f"Weak HMAC secret discovered: {findings.get('brute_force', {}).get('secret', 'N/A')}"
            })
        
        if report['summary']['bypass_possible']:
            report['vulnerabilities'].append({
                'type': 'Signature Bypass',
                'severity': 'CRITICAL',
                'description': f"Signature validation can be bypassed: {findings.get('bypass', {}).get('bypasses', [])}"
            })
        
        # Generate recommendations
        if not findings.get('detection', {}).get('timestamp_header'):
            report['recommendations'].append(
                'Implement timestamp validation to prevent replay attacks'
            )
        
        if not findings.get('detection', {}).get('nonce_header'):
            report['recommendations'].append(
                'Implement nonce validation for additional replay protection'
            )
        
        if findings.get('detection', {}).get('algorithm') == 'SHA-1':
            report['recommendations'].append(
                'Upgrade from SHA-1 to SHA-256 or SHA-512 for HMAC'
            )
        
        if report['summary']['weak_secret']:
            report['recommendations'].append(
                'Use cryptographically strong random secrets (min 32 bytes)'
            )
        
        if report['summary']['timing_vulnerable']:
            report['recommendations'].append(
                'Implement constant-time comparison for HMAC validation'
            )
        
        report['recommendations'].extend([
            'Ensure all requests are made over TLS/SSL',
            'Include request method and full URL in signature',
            'Implement request expiry (60-300 seconds recommended)',
            'Sign all security-critical headers',
            'Use secure key storage (HSM, KMS, or secure enclave)'
        ])
        
        return report
    
    def run_full_analysis(self, test_endpoint: str = None) -> Dict:
        """Run complete HMAC security analysis"""
        endpoint = test_endpoint or self.target_url
        
        print(f"[*] Starting HMAC security analysis for {endpoint}")
        print("="*50)
        
        findings = {}
        
        # Initial request to detect HMAC
        try:
            response = self.session.get(endpoint, headers=self.custom_headers)
            findings['detection'] = self.detect_hmac_implementation(response)
            
            if findings['detection']['uses_hmac']:
                print(f"[+] HMAC detected using {findings['detection']['algorithm']}")
                
                # Test replay attacks
                test_data = {"test": "data", "timestamp": int(time.time())}
                findings['replay'] = self.test_replay_attack(test_data)
                
                # Test timing attacks
                if findings['detection']['signature_header']:
                    valid_sig = response.headers.get(
                        findings['detection']['signature_header'], 
                        '0'*64
                    )
                    findings['timing'] = self.test_timing_attack(endpoint, valid_sig)
                
                # Test signature bypass
                findings['bypass'] = self.test_signature_bypass(endpoint)
                
                # Try to brute force secret
                if findings['detection']['signature_header']:
                    signature = response.headers.get(
                        findings['detection']['signature_header'],
                        ''
                    )
                    secret = self.brute_force_hmac_secret(
                        test_data,
                        signature,
                        findings['detection']['algorithm'] or 'sha256'
                    )
                    findings['brute_force'] = {
                        'secret_found': secret is not None,
                        'secret': secret
                    }
                
                # AWS SigV4 analysis if detected
                if findings['detection']['aws_sigv4']:
                    findings['aws_analysis'] = self.analyze_aws_sigv4(response.headers)
            else:
                print("[-] No HMAC implementation detected")
                
        except Exception as e:
            print(f"[-] Analysis failed: {e}")
            findings['error'] = str(e)
        
        # Generate report
        report = self.generate_report(findings)
        
        # Save report
        report_file = f"hmac_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Report saved to {report_file}")
        
        # Print summary
        print("\n" + "="*50)
        print("ANALYSIS SUMMARY")
        print("="*50)
        print(f"HMAC Detected: {report['summary']['uses_hmac']}")
        print(f"Algorithm: {report['summary']['algorithm']}")
        print(f"Vulnerabilities Found: {len(report['vulnerabilities'])}")
        
        for vuln in report['vulnerabilities']:
            print(f"  - [{vuln['severity']}] {vuln['type']}")
        
        return report

def main():
    parser = argparse.ArgumentParser(description='HMAC & Request Signing Analyzer')
    parser.add_argument('target', help='Target API endpoint URL')
    parser.add_argument('--user-agent', default='iOS/17.0 MyApp/1.0',
                       help='Custom User-Agent header')
    parser.add_argument('--headers', help='Additional headers as JSON')
    parser.add_argument('--token', help='Bearer token for authentication')
    parser.add_argument('--test-replay', action='store_true',
                       help='Test replay attack vulnerability')
    parser.add_argument('--brute-force', action='store_true',
                       help='Attempt to brute force HMAC secret')
    parser.add_argument('--output', help='Output report file')
    
    args = parser.parse_args()
    
    # Prepare custom headers
    headers = {'User-Agent': args.user_agent}
    
    if args.headers:
        headers.update(json.loads(args.headers))
    
    if args.token:
        headers['Authorization'] = f'Bearer {args.token}'
    
    # Run analysis
    analyzer = HMACAnalyzer(args.target, headers)
    report = analyzer.run_full_analysis()
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)

if __name__ == "__main__":
    main()