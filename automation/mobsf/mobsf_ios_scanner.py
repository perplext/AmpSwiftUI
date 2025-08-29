#!/usr/bin/env python3
"""
MobSF iOS Scanner Automation
Comprehensive automated security analysis for iOS applications
Supports: IPA files, Swift/SwiftUI analysis, AWS Amplify detection
"""

import os
import sys
import json
import time
import hashlib
import argparse
import requests
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor

class MobSFiOSScanner:
    def __init__(self, server_url: str = "http://localhost:8000", api_key: str = None):
        self.server_url = server_url.rstrip('/')
        self.api_key = api_key or os.environ.get('MOBSF_API_KEY', '')
        self.headers = {'Authorization': self.api_key}
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        
    def upload_file(self, file_path: str) -> Dict:
        """Upload IPA file to MobSF"""
        print(f"[*] Uploading {file_path} to MobSF...")
        
        upload_url = f"{self.server_url}/api/v1/upload"
        
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f, 'application/octet-stream')}
            response = self.session.post(upload_url, files=files)
            
        if response.status_code == 200:
            result = response.json()
            print(f"[+] Upload successful. Hash: {result.get('hash', 'N/A')}")
            return result
        else:
            print(f"[-] Upload failed: {response.text}")
            return None
    
    def scan_file(self, scan_hash: str, file_name: str, scan_type: str = "ipa") -> Dict:
        """Initiate static analysis scan"""
        print(f"[*] Starting static analysis for {file_name}...")
        
        scan_url = f"{self.server_url}/api/v1/scan"
        data = {
            'hash': scan_hash,
            'file_name': file_name,
            'scan_type': scan_type
        }
        
        response = self.session.post(scan_url, data=data)
        
        if response.status_code == 200:
            print("[+] Scan initiated successfully")
            return response.json()
        else:
            print(f"[-] Scan failed: {response.text}")
            return None
    
    def get_scan_results(self, scan_hash: str) -> Dict:
        """Retrieve scan results"""
        print("[*] Retrieving scan results...")
        
        report_url = f"{self.server_url}/api/v1/report_json"
        data = {'hash': scan_hash}
        
        response = self.session.post(report_url, data=data)
        
        if response.status_code == 200:
            return response.json()
        else:
            print(f"[-] Failed to get results: {response.text}")
            return None
    
    def analyze_swift_components(self, results: Dict) -> Dict:
        """Analyze Swift and SwiftUI specific components"""
        swift_analysis = {
            'uses_swiftui': False,
            'swift_version': None,
            'swiftui_components': [],
            'combine_usage': False,
            'async_await': False,
            'property_wrappers': [],
            'security_issues': []
        }
        
        # Check binary info for Swift
        if 'binary_analysis' in results:
            binary = results['binary_analysis']
            
            # Check for SwiftUI framework
            if 'libraries' in binary:
                for lib in binary['libraries']:
                    if 'SwiftUI' in lib:
                        swift_analysis['uses_swiftui'] = True
                    if 'Combine' in lib:
                        swift_analysis['combine_usage'] = True
        
        # Analyze strings for SwiftUI patterns
        if 'strings' in results:
            strings = results['strings']
            swiftui_patterns = ['@State', '@Binding', '@Published', '@ObservedObject', 
                               '@EnvironmentObject', '@StateObject', 'NavigationView',
                               'NavigationStack', 'VStack', 'HStack', 'ZStack']
            
            for pattern in swiftui_patterns:
                if any(pattern in s for s in strings):
                    swift_analysis['swiftui_components'].append(pattern)
        
        # Check for security issues specific to Swift
        if 'code_analysis' in results:
            code = results['code_analysis']
            
            # Check for unsafe Swift patterns
            unsafe_patterns = [
                ('UnsafePointer', 'Use of unsafe pointer operations'),
                ('unsafeBitCast', 'Unsafe type casting detected'),
                ('withUnsafeBytes', 'Unsafe byte manipulation'),
                ('force unwrap', 'Force unwrapping may cause crashes')
            ]
            
            for pattern, issue in unsafe_patterns:
                if pattern in str(code):
                    swift_analysis['security_issues'].append(issue)
        
        return swift_analysis
    
    def detect_aws_amplify(self, results: Dict) -> Dict:
        """Detect AWS Amplify configurations and endpoints"""
        amplify_analysis = {
            'uses_amplify': False,
            'api_endpoints': [],
            'cognito_pools': [],
            's3_buckets': [],
            'graphql_endpoints': [],
            'dynamodb_tables': [],
            'lambda_functions': [],
            'security_concerns': []
        }
        
        # Search for Amplify configuration files
        if 'files' in results:
            for file in results['files']:
                if 'amplifyconfiguration.json' in file or 'aws-exports.js' in file:
                    amplify_analysis['uses_amplify'] = True
        
        # Search strings for AWS patterns
        if 'strings' in results:
            strings = results['strings']
            
            # API Gateway endpoints
            api_pattern = r'https://[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com'
            
            # Cognito patterns
            cognito_pattern = r'[a-z0-9-]+_[a-zA-Z0-9]+'  # Pool IDs
            
            # S3 bucket patterns
            s3_pattern = r's3://[a-z0-9][a-z0-9-\.]*[a-z0-9]'
            
            # GraphQL endpoints
            graphql_pattern = r'https://[a-z0-9]+\.appsync-api\.[a-z0-9-]+\.amazonaws\.com/graphql'
            
            for string in strings:
                if 'execute-api.amazonaws.com' in string:
                    amplify_analysis['api_endpoints'].append(string)
                elif 'cognito' in string.lower():
                    amplify_analysis['cognito_pools'].append(string)
                elif 's3' in string.lower() or 'bucket' in string.lower():
                    amplify_analysis['s3_buckets'].append(string)
                elif 'appsync' in string or 'graphql' in string.lower():
                    amplify_analysis['graphql_endpoints'].append(string)
                elif 'dynamodb' in string.lower():
                    amplify_analysis['dynamodb_tables'].append(string)
                elif 'lambda' in string.lower():
                    amplify_analysis['lambda_functions'].append(string)
        
        # Check for security concerns
        if 'api_keys' in results and results['api_keys']:
            for key in results['api_keys']:
                if key.startswith('AKIA'):  # AWS Access Key pattern
                    amplify_analysis['security_concerns'].append(f"AWS Access Key found: {key[:10]}...")
        
        return amplify_analysis
    
    def check_owasp_mobile_2024(self, results: Dict) -> Dict:
        """Check against OWASP Mobile Top 10 2024"""
        owasp_checks = {
            'M1_improper_credential_usage': [],
            'M2_inadequate_supply_chain_security': [],
            'M3_insecure_authentication': [],
            'M4_insufficient_input_validation': [],
            'M5_insecure_communication': [],
            'M6_inadequate_privacy_controls': [],
            'M7_insufficient_binary_protection': [],
            'M8_security_misconfiguration': [],
            'M9_insecure_data_storage': [],
            'M10_insufficient_cryptography': []
        }
        
        # M1: Improper Credential Usage
        if 'hardcoded_secrets' in results:
            for secret in results['hardcoded_secrets']:
                owasp_checks['M1_improper_credential_usage'].append(secret)
        
        # M3: Insecure Authentication/Authorization
        if 'insecure_connections' in results:
            for conn in results['insecure_connections']:
                owasp_checks['M3_insecure_authentication'].append(conn)
        
        # M5: Insecure Communication
        if 'network_security' in results:
            network = results['network_security']
            if not network.get('ats_enabled', False):
                owasp_checks['M5_insecure_communication'].append("ATS not properly configured")
        
        # M7: Insufficient Binary Protection
        if 'binary_analysis' in results:
            binary = results['binary_analysis']
            if not binary.get('pie', False):
                owasp_checks['M7_insufficient_binary_protection'].append("PIE not enabled")
            if not binary.get('stack_canary', False):
                owasp_checks['M7_insufficient_binary_protection'].append("Stack canary missing")
            if not binary.get('arc', False):
                owasp_checks['M7_insufficient_binary_protection'].append("ARC not enabled")
        
        # M9: Insecure Data Storage
        if 'insecure_storage' in results:
            for storage in results['insecure_storage']:
                owasp_checks['M9_insecure_data_storage'].append(storage)
        
        # M10: Insufficient Cryptography
        if 'weak_crypto' in results:
            for crypto in results['weak_crypto']:
                owasp_checks['M10_insufficient_cryptography'].append(crypto)
        
        return owasp_checks
    
    def generate_report(self, scan_hash: str, results: Dict, output_format: str = "json") -> str:
        """Generate comprehensive security report"""
        print(f"[*] Generating {output_format.upper()} report...")
        
        report = {
            'scan_info': {
                'hash': scan_hash,
                'timestamp': datetime.now().isoformat(),
                'mobsf_version': results.get('version', 'Unknown')
            },
            'app_info': {
                'name': results.get('app_name', 'Unknown'),
                'bundle_id': results.get('bundle_id', 'Unknown'),
                'version': results.get('version_name', 'Unknown'),
                'min_ios': results.get('min_ios_version', 'Unknown')
            },
            'security_score': results.get('security_score', 0),
            'swift_analysis': self.analyze_swift_components(results),
            'aws_amplify': self.detect_aws_amplify(results),
            'owasp_mobile_2024': self.check_owasp_mobile_2024(results),
            'vulnerabilities': {
                'critical': [],
                'high': [],
                'medium': [],
                'low': []
            }
        }
        
        # Categorize vulnerabilities by severity
        if 'findings' in results:
            for finding in results['findings']:
                severity = finding.get('severity', 'low').lower()
                if severity in report['vulnerabilities']:
                    report['vulnerabilities'][severity].append({
                        'title': finding.get('title'),
                        'description': finding.get('description'),
                        'file': finding.get('file', 'N/A')
                    })
        
        # Save report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if output_format == "json":
            output_file = f"mobsf_report_{scan_hash[:8]}_{timestamp}.json"
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
        
        elif output_format == "pdf":
            # Generate PDF report via MobSF API
            pdf_url = f"{self.server_url}/api/v1/download_pdf"
            response = self.session.post(pdf_url, data={'hash': scan_hash})
            
            if response.status_code == 200:
                output_file = f"mobsf_report_{scan_hash[:8]}_{timestamp}.pdf"
                with open(output_file, 'wb') as f:
                    f.write(response.content)
            else:
                print(f"[-] PDF generation failed: {response.text}")
                return None
        
        print(f"[+] Report saved to: {output_file}")
        return output_file
    
    async def batch_scan(self, ipa_files: List[str]) -> List[Dict]:
        """Perform batch scanning of multiple IPA files"""
        print(f"[*] Starting batch scan of {len(ipa_files)} files...")
        
        results = []
        async with aiohttp.ClientSession() as session:
            tasks = []
            for ipa_file in ipa_files:
                task = self.async_scan_file(session, ipa_file)
                tasks.append(task)
            
            results = await asyncio.gather(*tasks)
        
        return results
    
    async def async_scan_file(self, session: aiohttp.ClientSession, file_path: str) -> Dict:
        """Asynchronous file scanning"""
        # Upload file
        upload_result = self.upload_file(file_path)
        if not upload_result:
            return None
        
        scan_hash = upload_result['hash']
        file_name = upload_result['file_name']
        
        # Start scan
        scan_result = self.scan_file(scan_hash, file_name)
        if not scan_result:
            return None
        
        # Wait for scan to complete (poll status)
        max_attempts = 60
        for i in range(max_attempts):
            time.sleep(5)
            results = self.get_scan_results(scan_hash)
            if results:
                return {
                    'file': file_path,
                    'hash': scan_hash,
                    'results': results
                }
        
        return None
    
    def continuous_monitor(self, app_bundle_id: str, interval: int = 3600):
        """Continuously monitor app for updates"""
        print(f"[*] Starting continuous monitoring for {app_bundle_id}")
        print(f"[*] Check interval: {interval} seconds")
        
        last_hash = None
        
        while True:
            try:
                # In production, this would download latest IPA from App Store
                # For demo, we'll check a specified directory
                ipa_path = f"./monitor/{app_bundle_id}.ipa"
                
                if os.path.exists(ipa_path):
                    # Calculate file hash
                    with open(ipa_path, 'rb') as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()
                    
                    if file_hash != last_hash:
                        print(f"[!] New version detected for {app_bundle_id}")
                        
                        # Perform scan
                        upload_result = self.upload_file(ipa_path)
                        if upload_result:
                            scan_hash = upload_result['hash']
                            file_name = upload_result['file_name']
                            
                            self.scan_file(scan_hash, file_name)
                            time.sleep(30)  # Wait for scan
                            
                            results = self.get_scan_results(scan_hash)
                            if results:
                                # Generate report
                                self.generate_report(scan_hash, results)
                                
                                # Check for regressions
                                if last_hash:
                                    self.check_security_regression(last_hash, scan_hash, results)
                        
                        last_hash = file_hash
                
                print(f"[*] Next check in {interval} seconds...")
                time.sleep(interval)
                
            except KeyboardInterrupt:
                print("\n[*] Monitoring stopped")
                break
            except Exception as e:
                print(f"[-] Error during monitoring: {e}")
                time.sleep(interval)
    
    def check_security_regression(self, old_hash: str, new_hash: str, new_results: Dict):
        """Check for security regressions between versions"""
        print("[*] Checking for security regressions...")
        
        # Get old results
        old_results = self.get_scan_results(old_hash)
        if not old_results:
            return
        
        old_score = old_results.get('security_score', 0)
        new_score = new_results.get('security_score', 0)
        
        if new_score < old_score:
            print(f"[!] SECURITY REGRESSION DETECTED!")
            print(f"    Old score: {old_score}")
            print(f"    New score: {new_score}")
            
            # Find new vulnerabilities
            old_findings = set(f.get('title', '') for f in old_results.get('findings', []))
            new_findings = set(f.get('title', '') for f in new_results.get('findings', []))
            
            new_vulns = new_findings - old_findings
            if new_vulns:
                print(f"[!] New vulnerabilities introduced:")
                for vuln in new_vulns:
                    print(f"    - {vuln}")

def main():
    parser = argparse.ArgumentParser(description='MobSF iOS Scanner Automation')
    parser.add_argument('action', choices=['scan', 'batch', 'monitor'],
                       help='Action to perform')
    parser.add_argument('--file', help='IPA file path for single scan')
    parser.add_argument('--dir', help='Directory containing IPA files for batch scan')
    parser.add_argument('--bundle-id', help='Bundle ID for continuous monitoring')
    parser.add_argument('--server', default='http://localhost:8000',
                       help='MobSF server URL')
    parser.add_argument('--api-key', help='MobSF API key')
    parser.add_argument('--format', choices=['json', 'pdf'], default='json',
                       help='Report format')
    parser.add_argument('--interval', type=int, default=3600,
                       help='Monitoring interval in seconds')
    
    args = parser.parse_args()
    
    scanner = MobSFiOSScanner(args.server, args.api_key)
    
    if args.action == 'scan':
        if not args.file:
            print("[-] Please provide IPA file path with --file")
            sys.exit(1)
        
        # Single file scan
        upload_result = scanner.upload_file(args.file)
        if upload_result:
            scan_hash = upload_result['hash']
            file_name = upload_result['file_name']
            
            scanner.scan_file(scan_hash, file_name)
            time.sleep(30)  # Wait for scan to complete
            
            results = scanner.get_scan_results(scan_hash)
            if results:
                scanner.generate_report(scan_hash, results, args.format)
    
    elif args.action == 'batch':
        if not args.dir:
            print("[-] Please provide directory path with --dir")
            sys.exit(1)
        
        # Batch scan
        ipa_files = list(Path(args.dir).glob('*.ipa'))
        if not ipa_files:
            print(f"[-] No IPA files found in {args.dir}")
            sys.exit(1)
        
        asyncio.run(scanner.batch_scan([str(f) for f in ipa_files]))
    
    elif args.action == 'monitor':
        if not args.bundle_id:
            print("[-] Please provide bundle ID with --bundle-id")
            sys.exit(1)
        
        # Continuous monitoring
        scanner.continuous_monitor(args.bundle_id, args.interval)

if __name__ == "__main__":
    main()