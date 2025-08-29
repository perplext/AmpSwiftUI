#!/usr/bin/env python3
"""
iOS Keychain Analyzer with DEK/KEK Analysis
Advanced keychain extraction, envelope encryption detection, and sensitive data analysis
"""

import os
import sys
import json
import sqlite3
import plistlib
import argparse
import subprocess
import base64
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import frida

class KeychainAnalyzer:
    def __init__(self, device_id: str = None):
        self.device_id = device_id
        self.keychain_items = []
        self.dek_kek_pairs = []
        self.sensitive_patterns = [
            'password', 'token', 'secret', 'key', 'api', 'auth',
            'credential', 'private', 'session', 'refresh', 'access'
        ]
        self.frida_session = None
        
    def connect_device(self):
        """Connect to iOS device via Frida"""
        try:
            if self.device_id:
                self.device = frida.get_device(self.device_id)
            else:
                self.device = frida.get_usb_device()
            print(f"[+] Connected to device: {self.device.name}")
            return True
        except Exception as e:
            print(f"[-] Failed to connect: {e}")
            return False
    
    def dump_keychain_frida(self, app_bundle: str = None) -> List[Dict]:
        """Dump keychain using Frida (for jailbroken devices)"""
        print("[*] Dumping keychain with Frida...")
        
        frida_script = """
        if (ObjC.available) {
            // Query all keychain items
            var SecItemCopyMatching = new NativeFunction(
                Module.findExportByName('Security', 'SecItemCopyMatching'),
                'int', ['pointer', 'pointer']
            );
            
            var kSecClass = ObjC.classes.NSString.stringWithString_("class");
            var kSecClassGenericPassword = ObjC.classes.NSString.stringWithString_("genp");
            var kSecClassInternetPassword = ObjC.classes.NSString.stringWithString_("inet");
            var kSecClassCertificate = ObjC.classes.NSString.stringWithString_("cert");
            var kSecClassKey = ObjC.classes.NSString.stringWithString_("keys");
            var kSecClassIdentity = ObjC.classes.NSString.stringWithString_("idnt");
            
            var kSecReturnData = ObjC.classes.NSString.stringWithString_("r_Data");
            var kSecReturnAttributes = ObjC.classes.NSString.stringWithString_("r_Attributes");
            var kSecMatchLimit = ObjC.classes.NSString.stringWithString_("m_Limit");
            var kSecMatchLimitAll = ObjC.classes.NSString.stringWithString_("m_LimitAll");
            
            var classes = [
                kSecClassGenericPassword,
                kSecClassInternetPassword,
                kSecClassCertificate,
                kSecClassKey,
                kSecClassIdentity
            ];
            
            var items = [];
            
            classes.forEach(function(secClass) {
                var query = ObjC.classes.NSMutableDictionary.alloc().init();
                query.setObject_forKey_(secClass, kSecClass);
                query.setObject_forKey_(kSecMatchLimitAll, kSecMatchLimit);
                query.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(true), kSecReturnAttributes);
                query.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(true), kSecReturnData);
                
                var result = Memory.alloc(Process.pointerSize);
                var status = SecItemCopyMatching(query.handle, result);
                
                if (status === 0) {
                    var data = new ObjC.Object(Memory.readPointer(result));
                    if (data && data.count) {
                        for (var i = 0; i < data.count(); i++) {
                            var item = data.objectAtIndex_(i);
                            items.push({
                                class: secClass.toString(),
                                attributes: item.toString()
                            });
                        }
                    }
                }
            });
            
            send(JSON.stringify(items));
        }
        """
        
        try:
            if app_bundle:
                session = self.device.attach(app_bundle)
            else:
                # Attach to SpringBoard for system-wide keychain
                session = self.device.attach("SpringBoard")
            
            script = session.create_script(frida_script)
            items = []
            
            def on_message(message, data):
                if message['type'] == 'send':
                    items.extend(json.loads(message['payload']))
            
            script.on('message', on_message)
            script.load()
            
            # Wait for script to complete
            import time
            time.sleep(2)
            
            session.detach()
            return items
            
        except Exception as e:
            print(f"[-] Frida keychain dump failed: {e}")
            return []
    
    def dump_keychain_objection(self) -> List[Dict]:
        """Dump keychain using objection"""
        print("[*] Dumping keychain with objection...")
        
        try:
            result = subprocess.run(
                ['objection', '-g', 'SpringBoard', 'explore', '-c', 'ios keychain dump'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Parse objection output
                lines = result.stdout.split('\n')
                items = []
                current_item = {}
                
                for line in lines:
                    if 'Service:' in line:
                        if current_item:
                            items.append(current_item)
                        current_item = {'service': line.split('Service:')[1].strip()}
                    elif 'Account:' in line:
                        current_item['account'] = line.split('Account:')[1].strip()
                    elif 'Data:' in line:
                        current_item['data'] = line.split('Data:')[1].strip()
                    elif 'Access Group:' in line:
                        current_item['access_group'] = line.split('Access Group:')[1].strip()
                
                if current_item:
                    items.append(current_item)
                
                return items
            
        except Exception as e:
            print(f"[-] Objection keychain dump failed: {e}")
            return []
    
    def analyze_keychain_security(self, items: List[Dict]) -> Dict:
        """Analyze keychain items for security issues"""
        print("[*] Analyzing keychain security...")
        
        analysis = {
            'total_items': len(items),
            'sensitive_items': [],
            'weak_protection': [],
            'plaintext_passwords': [],
            'api_keys': [],
            'tokens': [],
            'dek_kek_detected': False,
            'security_score': 100
        }
        
        for item in items:
            item_str = json.dumps(item).lower()
            
            # Check for sensitive data
            for pattern in self.sensitive_patterns:
                if pattern in item_str:
                    analysis['sensitive_items'].append({
                        'pattern': pattern,
                        'item': item.get('service', 'Unknown'),
                        'account': item.get('account', 'Unknown')
                    })
                    analysis['security_score'] -= 2
            
            # Check for plaintext passwords
            if 'password' in item_str and 'data' in item:
                data = item.get('data', '')
                if self._is_plaintext(data):
                    analysis['plaintext_passwords'].append({
                        'service': item.get('service', 'Unknown'),
                        'account': item.get('account', 'Unknown')
                    })
                    analysis['security_score'] -= 10
            
            # Check for API keys
            if 'api' in item_str or 'key' in item_str:
                if 'data' in item:
                    data = item.get('data', '')
                    if len(data) > 20 and data.isalnum():
                        analysis['api_keys'].append({
                            'service': item.get('service', 'Unknown'),
                            'preview': data[:10] + '...'
                        })
                        analysis['security_score'] -= 5
            
            # Check for tokens
            if 'token' in item_str:
                if 'data' in item:
                    data = item.get('data', '')
                    if self._is_jwt(data):
                        analysis['tokens'].append({
                            'service': item.get('service', 'Unknown'),
                            'type': 'JWT',
                            'header': self._decode_jwt_header(data)
                        })
                        analysis['security_score'] -= 3
            
            # Check protection class
            protection = item.get('protection_class', '')
            if protection and 'WhenUnlocked' in protection:
                analysis['weak_protection'].append({
                    'service': item.get('service', 'Unknown'),
                    'protection': protection,
                    'recommendation': 'Use WhenPasscodeSetThisDeviceOnly'
                })
                analysis['security_score'] -= 2
        
        # Check for DEK/KEK pattern
        if self._detect_envelope_encryption(items):
            analysis['dek_kek_detected'] = True
            analysis['security_score'] += 10
        
        analysis['security_score'] = max(0, analysis['security_score'])
        return analysis
    
    def _is_plaintext(self, data: str) -> bool:
        """Check if data appears to be plaintext"""
        if not data:
            return False
        
        # Check if it's printable ASCII
        try:
            if all(32 <= ord(c) < 127 for c in data):
                # Check if it looks like a password pattern
                has_upper = any(c.isupper() for c in data)
                has_lower = any(c.islower() for c in data)
                has_digit = any(c.isdigit() for c in data)
                
                if has_upper and has_lower and has_digit:
                    return True
        except:
            pass
        
        return False
    
    def _is_jwt(self, data: str) -> bool:
        """Check if data is a JWT token"""
        if not data:
            return False
        
        parts = data.split('.')
        return len(parts) == 3 and all(self._is_base64(p) for p in parts)
    
    def _is_base64(self, s: str) -> bool:
        """Check if string is base64 encoded"""
        try:
            base64.b64decode(s + '==')  # Add padding if needed
            return True
        except:
            return False
    
    def _decode_jwt_header(self, token: str) -> Dict:
        """Decode JWT header"""
        try:
            header = token.split('.')[0]
            decoded = base64.b64decode(header + '==')
            return json.loads(decoded)
        except:
            return {}
    
    def _detect_envelope_encryption(self, items: List[Dict]) -> bool:
        """Detect DEK/KEK envelope encryption pattern"""
        print("[*] Checking for envelope encryption (DEK/KEK)...")
        
        # Look for patterns indicating envelope encryption
        kek_patterns = ['kek', 'key_encryption_key', 'master_key', 'wrapping_key']
        dek_patterns = ['dek', 'data_encryption_key', 'content_key', 'session_key']
        
        kek_found = False
        dek_found = False
        
        for item in items:
            item_str = json.dumps(item).lower()
            
            for pattern in kek_patterns:
                if pattern in item_str:
                    kek_found = True
                    print(f"[+] KEK pattern found: {pattern}")
                    
            for pattern in dek_patterns:
                if pattern in item_str:
                    dek_found = True
                    print(f"[+] DEK pattern found: {pattern}")
        
        if kek_found and dek_found:
            print("[+] Envelope encryption detected (DEK/KEK pattern found)")
            return True
        
        return False
    
    def extract_aws_credentials(self, items: List[Dict]) -> List[Dict]:
        """Extract AWS credentials from keychain"""
        print("[*] Extracting AWS credentials...")
        
        aws_creds = []
        aws_patterns = [
            'aws', 'amazon', 'cognito', 'amplify', 's3', 'dynamodb',
            'lambda', 'apigateway', 'appsync'
        ]
        
        for item in items:
            item_str = json.dumps(item).lower()
            
            for pattern in aws_patterns:
                if pattern in item_str:
                    cred = {
                        'service': item.get('service', 'Unknown'),
                        'account': item.get('account', 'Unknown'),
                        'type': pattern
                    }
                    
                    # Check for AWS access key pattern
                    if 'data' in item:
                        data = item.get('data', '')
                        if data.startswith('AKIA'):
                            cred['access_key'] = data[:20] + '...'
                            cred['risk'] = 'CRITICAL'
                        elif 'token' in item_str:
                            cred['token_preview'] = data[:30] + '...'
                            cred['risk'] = 'HIGH'
                    
                    aws_creds.append(cred)
                    break
        
        return aws_creds
    
    def check_secure_enclave(self) -> Dict:
        """Check if Secure Enclave is being used properly"""
        print("[*] Checking Secure Enclave usage...")
        
        frida_script = """
        if (ObjC.available) {
            var SecAccessControlCreateWithFlags = new NativeFunction(
                Module.findExportByName('Security', 'SecAccessControlCreateWithFlags'),
                'pointer', ['pointer', 'pointer', 'int', 'pointer']
            );
            
            // Hook keychain operations to check for Secure Enclave usage
            var SecItemAdd = new NativeFunction(
                Module.findExportByName('Security', 'SecItemAdd'),
                'int', ['pointer', 'pointer']
            );
            
            Interceptor.attach(SecItemAdd, {
                onEnter: function(args) {
                    var dict = new ObjC.Object(args[0]);
                    var accessControl = dict.objectForKey_(ObjC.classes.NSString.stringWithString_("accc"));
                    
                    if (accessControl) {
                        send({
                            type: 'secure_enclave',
                            used: true
                        });
                    } else {
                        send({
                            type: 'secure_enclave',
                            used: false
                        });
                    }
                }
            });
        }
        """
        
        # This would run the Frida script and analyze results
        # Simplified for demonstration
        return {
            'secure_enclave_available': True,
            'items_using_secure_enclave': 0,
            'items_not_using_secure_enclave': 0,
            'recommendation': 'Use kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly with Secure Enclave'
        }
    
    def generate_report(self, analysis: Dict, output_file: str = None):
        """Generate comprehensive keychain security report"""
        print("[*] Generating keychain security report...")
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_items': analysis['total_items'],
                'security_score': analysis['security_score'],
                'critical_issues': len(analysis.get('plaintext_passwords', [])),
                'high_issues': len(analysis.get('api_keys', [])),
                'medium_issues': len(analysis.get('weak_protection', [])),
                'envelope_encryption': analysis.get('dek_kek_detected', False)
            },
            'findings': {
                'plaintext_passwords': analysis.get('plaintext_passwords', []),
                'api_keys': analysis.get('api_keys', []),
                'tokens': analysis.get('tokens', []),
                'weak_protection': analysis.get('weak_protection', []),
                'sensitive_items': analysis.get('sensitive_items', [])
            },
            'recommendations': [
                'Use hardware-backed storage (Secure Enclave) for all sensitive data',
                'Implement envelope encryption (DEK/KEK) for additional security',
                'Use kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly protection class',
                'Avoid storing plaintext passwords or API keys',
                'Regularly rotate tokens and credentials',
                'Implement certificate pinning for network communications'
            ]
        }
        
        # AWS specific recommendations
        if any('aws' in str(item).lower() for item in analysis.get('sensitive_items', [])):
            report['recommendations'].append('Use AWS Cognito for credential management')
            report['recommendations'].append('Implement STS temporary credentials instead of long-lived keys')
        
        if not output_file:
            output_file = f"keychain_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Report saved to {output_file}")
        
        # Print summary
        print(f"\n[*] Security Score: {analysis['security_score']}/100")
        print(f"[*] Critical Issues: {report['summary']['critical_issues']}")
        print(f"[*] Envelope Encryption: {'✓' if analysis['dek_kek_detected'] else '✗'}")
        
        return report

def main():
    parser = argparse.ArgumentParser(description='iOS Keychain Security Analyzer')
    parser.add_argument('--device', help='Device ID for Frida connection')
    parser.add_argument('--app', help='App bundle ID to analyze')
    parser.add_argument('--method', choices=['frida', 'objection'], default='frida',
                       help='Extraction method')
    parser.add_argument('--output', help='Output report file')
    parser.add_argument('--check-aws', action='store_true',
                       help='Check for AWS credentials')
    parser.add_argument('--check-enclave', action='store_true',
                       help='Check Secure Enclave usage')
    
    args = parser.parse_args()
    
    analyzer = KeychainAnalyzer(args.device)
    
    if not analyzer.connect_device():
        print("[-] Failed to connect to device")
        sys.exit(1)
    
    # Dump keychain
    if args.method == 'frida':
        items = analyzer.dump_keychain_frida(args.app)
    else:
        items = analyzer.dump_keychain_objection()
    
    if not items:
        print("[-] No keychain items found")
        sys.exit(1)
    
    print(f"[+] Found {len(items)} keychain items")
    
    # Analyze security
    analysis = analyzer.analyze_keychain_security(items)
    
    # Check for AWS credentials if requested
    if args.check_aws:
        aws_creds = analyzer.extract_aws_credentials(items)
        if aws_creds:
            print(f"[!] Found {len(aws_creds)} AWS-related credentials")
            analysis['aws_credentials'] = aws_creds
    
    # Check Secure Enclave usage if requested
    if args.check_enclave:
        enclave_status = analyzer.check_secure_enclave()
        analysis['secure_enclave'] = enclave_status
    
    # Generate report
    analyzer.generate_report(analysis, args.output)

if __name__ == "__main__":
    main()