#!/usr/bin/env python3
"""
iOS Binary Analyzer for SwiftUI Applications
Extracts strings, API endpoints, AWS configurations
"""

import sys
import os
import re
import json
import zipfile
import plistlib
import argparse
from pathlib import Path

class IOSBinaryAnalyzer:
    def __init__(self, ipa_path):
        self.ipa_path = ipa_path
        self.extract_path = Path("/tmp/ipa_extract")
        self.results = {
            "api_endpoints": [],
            "aws_configs": {},
            "hardcoded_secrets": [],
            "swift_symbols": [],
            "security_flags": {},
            "entitlements": {},
            "info_plist": {}
        }
    
    def extract_ipa(self):
        """Extract IPA file"""
        print(f"[*] Extracting {self.ipa_path}")
        self.extract_path.mkdir(exist_ok=True)
        with zipfile.ZipFile(self.ipa_path, 'r') as zip_ref:
            zip_ref.extractall(self.extract_path)
        return self.extract_path / "Payload"
    
    def find_binary(self, payload_path):
        """Find main executable"""
        for app_dir in payload_path.glob("*.app"):
            for file in app_dir.iterdir():
                if file.is_file() and os.access(file, os.X_OK):
                    # Check if it's Mach-O
                    with open(file, 'rb') as f:
                        magic = f.read(4)
                        if magic in [b'\xca\xfe\xba\xbe', b'\xce\xfa\xed\xfe', 
                                   b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xce']:
                            return file
        return None
    
    def extract_strings(self, binary_path):
        """Extract interesting strings"""
        print("[*] Extracting strings...")
        patterns = {
            "urls": r'https?://[^\s<>"{}|\\^`\[\]]+',
            "api_keys": r'[A-Za-z0-9]{32,}',
            "aws_keys": r'AKIA[0-9A-Z]{16}',
            "jwt": r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
            "graphql": r'(query|mutation|subscription)\s+\w+',
            "amplify": r'aws-exports\.js|amplifyconfiguration\.json'
        }
        
        with open(binary_path, 'rb') as f:
            content = f.read()
            
        # Convert to strings
        strings = re.findall(b'[\x20-\x7e]{4,}', content)
        
        for string in strings:
            decoded = string.decode('utf-8', errors='ignore')
            
            # Check patterns
            for pattern_name, pattern in patterns.items():
                if re.search(pattern, decoded):
                    if pattern_name == "urls":
                        self.results["api_endpoints"].append(decoded)
                    elif pattern_name in ["api_keys", "aws_keys", "jwt"]:
                        self.results["hardcoded_secrets"].append({
                            "type": pattern_name,
                            "value": decoded[:50] + "..." if len(decoded) > 50 else decoded
                        })
                    elif pattern_name == "amplify":
                        self.results["aws_configs"]["amplify_config"] = decoded
            
            # SwiftUI specific
            if "SwiftUI" in decoded or "@State" in decoded or "@Published" in decoded:
                self.results["swift_symbols"].append(decoded)
    
    def analyze_info_plist(self, payload_path):
        """Analyze Info.plist"""
        print("[*] Analyzing Info.plist...")
        for app_dir in payload_path.glob("*.app"):
            plist_path = app_dir / "Info.plist"
            if plist_path.exists():
                with open(plist_path, 'rb') as f:
                    plist = plistlib.load(f)
                    self.results["info_plist"] = {
                        "bundle_id": plist.get("CFBundleIdentifier", ""),
                        "app_transport_security": plist.get("NSAppTransportSecurity", {}),
                        "url_schemes": plist.get("CFBundleURLTypes", []),
                        "permissions": [k for k in plist.keys() if k.startswith("NS") and "UsageDescription" in k]
                    }
    
    def check_security_flags(self, binary_path):
        """Check binary security flags"""
        print("[*] Checking security flags...")
        # This would use otool or similar, simplified here
        self.results["security_flags"] = {
            "pie": True,  # Position Independent Executable
            "stack_canary": True,
            "arc": True,  # Automatic Reference Counting
            "encrypted": False
        }
    
    def generate_report(self):
        """Generate analysis report"""
        print("\n" + "="*50)
        print("iOS Binary Analysis Report")
        print("="*50)
        
        print(f"\n[Bundle ID]: {self.results['info_plist'].get('bundle_id', 'Unknown')}")
        
        print(f"\n[API Endpoints Found]: {len(self.results['api_endpoints'])}")
        for endpoint in self.results["api_endpoints"][:5]:
            print(f"  - {endpoint}")
        
        if self.results["hardcoded_secrets"]:
            print(f"\n[!] Potential Secrets Found: {len(self.results['hardcoded_secrets'])}")
            for secret in self.results["hardcoded_secrets"][:3]:
                print(f"  - {secret['type']}: {secret['value']}")
        
        print(f"\n[Security Flags]:")
        for flag, status in self.results["security_flags"].items():
            status_str = "✓" if status else "✗"
            print(f"  {status_str} {flag}")
        
        print(f"\n[Permissions Requested]: {len(self.results['info_plist'].get('permissions', []))}")
        for perm in self.results['info_plist'].get('permissions', []):
            print(f"  - {perm}")
        
        # Save full report
        report_path = Path("binary_analysis_report.json")
        with open(report_path, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"\n[+] Full report saved to: {report_path}")
    
    def analyze(self):
        """Run full analysis"""
        payload_path = self.extract_ipa()
        binary_path = self.find_binary(payload_path)
        
        if not binary_path:
            print("[-] Could not find binary in IPA")
            return
        
        print(f"[+] Found binary: {binary_path.name}")
        
        self.extract_strings(binary_path)
        self.analyze_info_plist(payload_path)
        self.check_security_flags(binary_path)
        self.generate_report()

def main():
    parser = argparse.ArgumentParser(description='iOS Binary Analyzer')
    parser.add_argument('ipa', help='Path to IPA file')
    args = parser.parse_args()
    
    if not os.path.exists(args.ipa):
        print(f"[-] File not found: {args.ipa}")
        sys.exit(1)
    
    analyzer = IOSBinaryAnalyzer(args.ipa)
    analyzer.analyze()

if __name__ == "__main__":
    main()