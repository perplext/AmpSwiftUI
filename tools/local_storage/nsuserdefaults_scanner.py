#!/usr/bin/env python3
"""
NSUserDefaults Security Scanner
Automated extraction and analysis of NSUserDefaults for sensitive data
"""

import os
import sys
import json
import plistlib
import sqlite3
import re
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import subprocess
import frida

class NSUserDefaultsScanner:
    def __init__(self, app_bundle_id: str = None):
        self.app_bundle_id = app_bundle_id
        self.sensitive_patterns = {
            'passwords': [
                r'password', r'passwd', r'pwd', r'pass[_-]?phrase'
            ],
            'tokens': [
                r'token', r'jwt', r'bearer', r'access[_-]?token', 
                r'refresh[_-]?token', r'auth[_-]?token', r'session[_-]?id'
            ],
            'api_keys': [
                r'api[_-]?key', r'apikey', r'secret[_-]?key', 
                r'private[_-]?key', r'client[_-]?secret'
            ],
            'aws': [
                r'aws[_-]?access', r'aws[_-]?secret', r'cognito',
                r'amplify', r's3[_-]?bucket', r'akia[0-9a-z]{16}'
            ],
            'personal_info': [
                r'email', r'phone', r'ssn', r'social[_-]?security',
                r'credit[_-]?card', r'cvv', r'pin'
            ],
            'crypto': [
                r'encryption[_-]?key', r'private[_-]?key', r'salt',
                r'iv', r'nonce', r'seed'
            ]
        }
        
        self.high_risk_values = []
        self.medium_risk_values = []
        self.low_risk_values = []
        
    def extract_nsuserdefaults_frida(self) -> Dict:
        """Extract NSUserDefaults using Frida"""
        print(f"[*] Extracting NSUserDefaults for {self.app_bundle_id}...")
        
        frida_script = """
        if (ObjC.available) {
            var NSUserDefaults = ObjC.classes.NSUserDefaults;
            var standardDefaults = NSUserDefaults.standardUserDefaults();
            
            // Get all keys
            var dict = standardDefaults.dictionaryRepresentation();
            var allKeys = dict.allKeys();
            
            var results = {};
            
            for (var i = 0; i < allKeys.count(); i++) {
                var key = allKeys.objectAtIndex_(i);
                var value = dict.objectForKey_(key);
                
                // Convert to string for analysis
                var keyStr = key.toString();
                var valueStr = '';
                
                try {
                    if (value.isKindOfClass_(ObjC.classes.NSString.class())) {
                        valueStr = value.toString();
                    } else if (value.isKindOfClass_(ObjC.classes.NSNumber.class())) {
                        valueStr = value.toString();
                    } else if (value.isKindOfClass_(ObjC.classes.NSData.class())) {
                        // Try to convert NSData to string
                        var str = ObjC.classes.NSString.alloc().initWithData_encoding_(value, 4); // NSUTF8StringEncoding
                        if (str) {
                            valueStr = str.toString();
                        } else {
                            valueStr = '<binary data: ' + value.length() + ' bytes>';
                        }
                    } else if (value.isKindOfClass_(ObjC.classes.NSArray.class())) {
                        valueStr = value.toString();
                    } else if (value.isKindOfClass_(ObjC.classes.NSDictionary.class())) {
                        valueStr = value.toString();
                    } else {
                        valueStr = value.toString();
                    }
                } catch(e) {
                    valueStr = '<error reading value>';
                }
                
                results[keyStr] = valueStr;
            }
            
            send(JSON.stringify(results));
        }
        """
        
        try:
            device = frida.get_usb_device()
            session = device.attach(self.app_bundle_id)
            script = session.create_script(frida_script)
            
            defaults = {}
            
            def on_message(message, data):
                if message['type'] == 'send':
                    defaults.update(json.loads(message['payload']))
            
            script.on('message', on_message)
            script.load()
            
            # Wait for script execution
            import time
            time.sleep(2)
            
            session.detach()
            return defaults
            
        except Exception as e:
            print(f"[-] Frida extraction failed: {e}")
            return {}
    
    def extract_nsuserdefaults_filesystem(self, app_path: str) -> Dict:
        """Extract NSUserDefaults from filesystem (jailbroken device)"""
        print("[*] Extracting NSUserDefaults from filesystem...")
        
        # NSUserDefaults are stored in Library/Preferences/[bundle_id].plist
        plist_path = Path(app_path) / "Library" / "Preferences" / f"{self.app_bundle_id}.plist"
        
        if not plist_path.exists():
            print(f"[-] Plist file not found: {plist_path}")
            return {}
        
        try:
            with open(plist_path, 'rb') as f:
                defaults = plistlib.load(f)
            return defaults
        except Exception as e:
            print(f"[-] Failed to read plist: {e}")
            return {}
    
    def analyze_sensitive_data(self, defaults: Dict) -> Dict:
        """Analyze NSUserDefaults for sensitive data"""
        print("[*] Analyzing NSUserDefaults for sensitive data...")
        
        findings = {
            'total_keys': len(defaults),
            'sensitive_keys': [],
            'plaintext_secrets': [],
            'potential_tokens': [],
            'aws_related': [],
            'personal_info': [],
            'crypto_material': [],
            'base64_encoded': [],
            'json_data': [],
            'risk_score': 0
        }
        
        for key, value in defaults.items():
            key_lower = key.lower()
            value_str = str(value)
            
            # Check key names for sensitive patterns
            for category, patterns in self.sensitive_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, key_lower, re.IGNORECASE):
                        finding = {
                            'key': key,
                            'category': category,
                            'pattern_matched': pattern,
                            'value_preview': self._safe_preview(value_str),
                            'risk': self._assess_risk(category, value_str)
                        }
                        findings['sensitive_keys'].append(finding)
                        findings['risk_score'] += self._get_risk_score(finding['risk'])
                        break
            
            # Check for specific data types
            if self._is_plaintext_secret(value_str):
                findings['plaintext_secrets'].append({
                    'key': key,
                    'type': self._identify_secret_type(value_str),
                    'preview': self._safe_preview(value_str, 20)
                })
                findings['risk_score'] += 10
            
            if self._is_jwt_token(value_str):
                findings['potential_tokens'].append({
                    'key': key,
                    'type': 'JWT',
                    'header': self._decode_jwt_header(value_str),
                    'expires': self._check_jwt_expiry(value_str)
                })
                findings['risk_score'] += 8
            
            if self._is_aws_related(key_lower, value_str):
                findings['aws_related'].append({
                    'key': key,
                    'type': self._identify_aws_type(value_str),
                    'preview': self._safe_preview(value_str, 15)
                })
                findings['risk_score'] += 15
            
            if self._contains_personal_info(value_str):
                findings['personal_info'].append({
                    'key': key,
                    'type': self._identify_pii_type(value_str),
                    'masked': self._mask_pii(value_str)
                })
                findings['risk_score'] += 12
            
            if self._is_base64(value_str):
                decoded = self._decode_base64(value_str)
                findings['base64_encoded'].append({
                    'key': key,
                    'decoded_preview': self._safe_preview(decoded, 30),
                    'contains_sensitive': self._check_decoded_sensitive(decoded)
                })
                if self._check_decoded_sensitive(decoded):
                    findings['risk_score'] += 5
            
            if self._is_json(value_str):
                findings['json_data'].append({
                    'key': key,
                    'structure': self._analyze_json_structure(value_str)
                })
        
        return findings
    
    def _safe_preview(self, value: str, length: int = 30) -> str:
        """Create safe preview of sensitive value"""
        if len(value) <= length:
            return value[:length//2] + '*' * (len(value) - length//2)
        return value[:length] + '...'
    
    def _assess_risk(self, category: str, value: str) -> str:
        """Assess risk level of finding"""
        if category in ['passwords', 'api_keys', 'aws']:
            if self._is_plaintext_secret(value):
                return 'CRITICAL'
            return 'HIGH'
        elif category in ['tokens', 'crypto']:
            return 'HIGH'
        elif category == 'personal_info':
            return 'MEDIUM'
        return 'LOW'
    
    def _get_risk_score(self, risk: str) -> int:
        """Convert risk level to numeric score"""
        scores = {
            'CRITICAL': 20,
            'HIGH': 10,
            'MEDIUM': 5,
            'LOW': 2
        }
        return scores.get(risk, 0)
    
    def _is_plaintext_secret(self, value: str) -> bool:
        """Check if value appears to be plaintext secret"""
        if len(value) < 6:
            return False
        
        # Check for password patterns
        has_upper = any(c.isupper() for c in value)
        has_lower = any(c.islower() for c in value)
        has_digit = any(c.isdigit() for c in value)
        has_special = any(c in '!@#$%^&*()_+-=' for c in value)
        
        # Likely a password if it has mixed case and numbers/special
        if (has_upper and has_lower) and (has_digit or has_special):
            return True
        
        # Check for API key patterns (long alphanumeric strings)
        if len(value) > 20 and value.isalnum():
            return True
        
        return False
    
    def _identify_secret_type(self, value: str) -> str:
        """Identify type of secret"""
        if value.startswith('AKIA'):
            return 'AWS Access Key'
        elif value.startswith('sk_'):
            return 'Stripe Secret Key'
        elif len(value) == 40 and value.isalnum():
            return 'GitHub Token'
        elif re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', value):
            return 'Base64 Secret'
        else:
            return 'Generic Secret'
    
    def _is_jwt_token(self, value: str) -> bool:
        """Check if value is JWT token"""
        parts = value.split('.')
        return len(parts) == 3 and all(self._is_base64(p) for p in parts)
    
    def _decode_jwt_header(self, token: str) -> Dict:
        """Decode JWT header"""
        try:
            import base64
            header = token.split('.')[0]
            decoded = base64.b64decode(header + '==')
            return json.loads(decoded)
        except:
            return {}
    
    def _check_jwt_expiry(self, token: str) -> str:
        """Check JWT token expiry"""
        try:
            import base64
            payload = token.split('.')[1]
            decoded = base64.b64decode(payload + '==')
            data = json.loads(decoded)
            
            if 'exp' in data:
                exp_time = datetime.fromtimestamp(data['exp'])
                if exp_time < datetime.now():
                    return 'EXPIRED'
                return exp_time.isoformat()
        except:
            pass
        return 'Unknown'
    
    def _is_aws_related(self, key: str, value: str) -> bool:
        """Check if data is AWS related"""
        aws_indicators = ['aws', 'cognito', 'amplify', 's3', 'dynamodb', 'lambda']
        return any(ind in key for ind in aws_indicators) or value.startswith('AKIA')
    
    def _identify_aws_type(self, value: str) -> str:
        """Identify AWS credential type"""
        if value.startswith('AKIA'):
            return 'AWS Access Key ID'
        elif 'cognito' in value.lower():
            return 'Cognito Pool ID'
        elif re.match(r'^[a-z0-9-]+\.[a-z0-9-]+\.amazonaws\.com', value):
            return 'AWS Endpoint'
        return 'AWS Related'
    
    def _contains_personal_info(self, value: str) -> bool:
        """Check if value contains PII"""
        # Email pattern
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            return True
        # Phone pattern
        if re.match(r'^[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}$', value):
            return True
        # SSN pattern
        if re.match(r'^\d{3}-\d{2}-\d{4}$', value):
            return True
        # Credit card pattern
        if re.match(r'^\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}$', value):
            return True
        return False
    
    def _identify_pii_type(self, value: str) -> str:
        """Identify PII type"""
        if '@' in value:
            return 'Email'
        elif re.match(r'^[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}$', value):
            return 'Phone'
        elif re.match(r'^\d{3}-\d{2}-\d{4}$', value):
            return 'SSN'
        elif re.match(r'^\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}$', value):
            return 'Credit Card'
        return 'PII'
    
    def _mask_pii(self, value: str) -> str:
        """Mask PII data"""
        if '@' in value:
            parts = value.split('@')
            return parts[0][:2] + '*' * (len(parts[0])-2) + '@' + parts[1]
        elif len(value) > 6:
            return value[:3] + '*' * (len(value)-6) + value[-3:]
        return '*' * len(value)
    
    def _is_base64(self, value: str) -> bool:
        """Check if value is base64 encoded"""
        try:
            import base64
            if len(value) % 4 == 0 and re.match(r'^[A-Za-z0-9+/]*={0,2}$', value):
                base64.b64decode(value)
                return True
        except:
            pass
        return False
    
    def _decode_base64(self, value: str) -> str:
        """Decode base64 value"""
        try:
            import base64
            return base64.b64decode(value).decode('utf-8', errors='ignore')
        except:
            return ''
    
    def _check_decoded_sensitive(self, decoded: str) -> bool:
        """Check if decoded base64 contains sensitive data"""
        for patterns in self.sensitive_patterns.values():
            for pattern in patterns:
                if re.search(pattern, decoded, re.IGNORECASE):
                    return True
        return False
    
    def _is_json(self, value: str) -> bool:
        """Check if value is JSON"""
        try:
            json.loads(value)
            return True
        except:
            return False
    
    def _analyze_json_structure(self, value: str) -> Dict:
        """Analyze JSON structure for sensitive data"""
        try:
            data = json.loads(value)
            structure = {
                'type': type(data).__name__,
                'keys': list(data.keys()) if isinstance(data, dict) else None,
                'sensitive_keys': []
            }
            
            if isinstance(data, dict):
                for key in data.keys():
                    for patterns in self.sensitive_patterns.values():
                        for pattern in patterns:
                            if re.search(pattern, key, re.IGNORECASE):
                                structure['sensitive_keys'].append(key)
                                break
            
            return structure
        except:
            return {}
    
    def generate_report(self, findings: Dict, output_file: str = None):
        """Generate comprehensive report"""
        print("[*] Generating NSUserDefaults security report...")
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'app_bundle_id': self.app_bundle_id,
            'summary': {
                'total_keys': findings['total_keys'],
                'sensitive_keys_found': len(findings['sensitive_keys']),
                'plaintext_secrets': len(findings['plaintext_secrets']),
                'potential_tokens': len(findings['potential_tokens']),
                'aws_credentials': len(findings['aws_related']),
                'personal_info': len(findings['personal_info']),
                'risk_score': findings['risk_score']
            },
            'critical_findings': [],
            'high_risk_findings': [],
            'medium_risk_findings': [],
            'recommendations': []
        }
        
        # Categorize findings by risk
        for finding in findings['sensitive_keys']:
            if finding['risk'] == 'CRITICAL':
                report['critical_findings'].append(finding)
            elif finding['risk'] == 'HIGH':
                report['high_risk_findings'].append(finding)
            else:
                report['medium_risk_findings'].append(finding)
        
        # Add specific findings
        if findings['plaintext_secrets']:
            report['critical_findings'].extend([
                {'type': 'Plaintext Secret', **secret} 
                for secret in findings['plaintext_secrets']
            ])
        
        if findings['aws_related']:
            report['critical_findings'].extend([
                {'type': 'AWS Credential', **aws} 
                for aws in findings['aws_related']
            ])
        
        # Generate recommendations
        if findings['plaintext_secrets']:
            report['recommendations'].append(
                'Never store plaintext passwords or API keys in NSUserDefaults'
            )
            report['recommendations'].append(
                'Use iOS Keychain for sensitive credential storage'
            )
        
        if findings['potential_tokens']:
            report['recommendations'].append(
                'Implement token refresh mechanisms and avoid storing long-lived tokens'
            )
        
        if findings['aws_related']:
            report['recommendations'].append(
                'Use AWS Cognito SDK for credential management instead of storing directly'
            )
            report['recommendations'].append(
                'Implement STS temporary credentials'
            )
        
        if findings['personal_info']:
            report['recommendations'].append(
                'Encrypt PII before storing in NSUserDefaults'
            )
            report['recommendations'].append(
                'Consider GDPR/CCPA compliance requirements'
            )
        
        report['recommendations'].extend([
            'Implement encryption for sensitive NSUserDefaults values',
            'Regular security audits of stored preferences',
            'Use configuration profiles for non-sensitive settings',
            'Implement secure coding practices for data storage'
        ])
        
        # Save report
        if not output_file:
            output_file = f"nsuserdefaults_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Report saved to {output_file}")
        
        # Print summary
        print(f"\n[*] Risk Score: {findings['risk_score']}")
        print(f"[*] Critical Findings: {len(report['critical_findings'])}")
        print(f"[*] Plaintext Secrets: {len(findings['plaintext_secrets'])}")
        print(f"[*] AWS Credentials: {len(findings['aws_related'])}")
        
        return report

def main():
    parser = argparse.ArgumentParser(description='NSUserDefaults Security Scanner')
    parser.add_argument('bundle_id', help='App bundle identifier')
    parser.add_argument('--method', choices=['frida', 'filesystem'], default='frida',
                       help='Extraction method')
    parser.add_argument('--app-path', help='App sandbox path (for filesystem method)')
    parser.add_argument('--output', help='Output report file')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    scanner = NSUserDefaultsScanner(args.bundle_id)
    
    # Extract NSUserDefaults
    if args.method == 'frida':
        defaults = scanner.extract_nsuserdefaults_frida()
    else:
        if not args.app_path:
            print("[-] App path required for filesystem method")
            sys.exit(1)
        defaults = scanner.extract_nsuserdefaults_filesystem(args.app_path)
    
    if not defaults:
        print("[-] No NSUserDefaults found")
        sys.exit(1)
    
    print(f"[+] Found {len(defaults)} NSUserDefaults entries")
    
    # Analyze for sensitive data
    findings = scanner.analyze_sensitive_data(defaults)
    
    # Generate report
    scanner.generate_report(findings, args.output)
    
    if args.verbose:
        print("\n[*] Detailed Findings:")
        for key in ['sensitive_keys', 'plaintext_secrets', 'aws_related']:
            if findings[key]:
                print(f"\n{key.upper()}:")
                for item in findings[key]:
                    print(f"  - {item}")

if __name__ == "__main__":
    main()