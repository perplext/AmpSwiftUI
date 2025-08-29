#!/usr/bin/env python3
"""
iOS Database Encryption Scanner
Comprehensive analysis of database encryption across SQLite, Core Data, Realm, and GRDB
"""

import os
import sys
import sqlite3
import json
import struct
import hashlib
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import subprocess
import frida
import plistlib

class DatabaseEncryptionScanner:
    def __init__(self, app_path: str = None):
        self.app_path = app_path
        self.databases = []
        self.encryption_status = {}
        
        # SQLCipher detection patterns
        self.sqlcipher_magic = b'SQLite format 3\x00'
        self.sqlcipher_indicators = [
            b'cipher_',
            b'sqlcipher_',
            b'encrypted',
            b'PRAGMA cipher'
        ]
        
        # Realm encryption detection
        self.realm_header = b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Encrypted Realm has different header
        self.realm_unencrypted = b'T\x00\x00\x00\x00\x00\x00\x00'  # Unencrypted Realm header
        
        # Core Data indicators
        self.coredata_extensions = ['.sqlite', '.sqlite-shm', '.sqlite-wal']
        self.coredata_model_extension = '.momd'
        
        # GRDB patterns
        self.grdb_patterns = [
            'GRDB.swift',
            'Database.db',
            '.sqlite'
        ]
        
    def scan_for_databases(self, directory: str) -> List[Dict]:
        """Scan directory for all database files"""
        print(f"[*] Scanning for databases in {directory}")
        
        databases = []
        path = Path(directory)
        
        # Common database extensions
        extensions = [
            '.sqlite', '.sqlite3', '.db', '.s3db',  # SQLite
            '.realm',  # Realm
            '.coredata',  # Core Data (rare, usually .sqlite)
            '.fmdb'  # FMDB wrapper
        ]
        
        for ext in extensions:
            for db_file in path.rglob(f'*{ext}'):
                db_info = self.analyze_database_file(str(db_file))
                databases.append(db_info)
        
        # Also check for Core Data model files
        for momd in path.rglob('*.momd'):
            print(f"[*] Found Core Data model: {momd}")
            # Find associated SQLite files
            parent_dir = momd.parent
            for sqlite_file in parent_dir.glob('*.sqlite'):
                db_info = self.analyze_database_file(str(sqlite_file))
                db_info['coredata_model'] = str(momd)
                databases.append(db_info)
        
        self.databases = databases
        return databases
    
    def analyze_database_file(self, db_path: str) -> Dict:
        """Analyze individual database file for encryption"""
        print(f"[*] Analyzing database: {db_path}")
        
        info = {
            'path': db_path,
            'size': os.path.getsize(db_path),
            'type': 'unknown',
            'encrypted': False,
            'encryption_type': None,
            'algorithm': None,
            'key_storage': None,
            'vulnerabilities': []
        }
        
        # Determine database type
        if db_path.endswith('.realm'):
            info['type'] = 'Realm'
            info.update(self.analyze_realm_database(db_path))
        elif any(db_path.endswith(ext) for ext in ['.sqlite', '.sqlite3', '.db', '.s3db']):
            info['type'] = 'SQLite'
            info.update(self.analyze_sqlite_database(db_path))
        
        return info
    
    def analyze_sqlite_database(self, db_path: str) -> Dict:
        """Analyze SQLite/Core Data database for encryption"""
        analysis = {
            'subtype': 'SQLite',
            'tables': [],
            'sensitive_data': []
        }
        
        try:
            # Check if it's SQLCipher encrypted
            with open(db_path, 'rb') as f:
                header = f.read(100)
                
                # Check SQLite header
                if header[:16] == self.sqlcipher_magic:
                    # It's a valid SQLite file, check if encrypted
                    try:
                        conn = sqlite3.connect(db_path)
                        cursor = conn.cursor()
                        # Try to read sqlite_master
                        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                        tables = cursor.fetchall()
                        analysis['tables'] = [t[0] for t in tables]
                        analysis['encrypted'] = False
                        
                        # Check for sensitive data in tables
                        analysis['sensitive_data'] = self.scan_for_sensitive_data(conn)
                        
                        conn.close()
                    except sqlite3.DatabaseError as e:
                        # Can't read - likely encrypted
                        if 'file is not a database' in str(e) or 'encrypted' in str(e):
                            analysis['encrypted'] = True
                            analysis['encryption_type'] = 'SQLCipher'
                            analysis['algorithm'] = 'AES-256-CBC'
                            
                            # Check for SQLCipher indicators in file
                            if any(pattern in header for pattern in self.sqlcipher_indicators):
                                analysis['encryption_type'] = 'SQLCipher (confirmed)'
                else:
                    # Not a standard SQLite header - possibly encrypted
                    analysis['encrypted'] = True
                    analysis['encryption_type'] = 'Unknown/Custom'
                    
                    # Check if it might be encrypted Core Data
                    if 'PersistentStore' in db_path or 'CoreData' in db_path:
                        analysis['subtype'] = 'Core Data'
                        analysis['encryption_type'] = 'Core Data Encryption'
                        
        except Exception as e:
            analysis['error'] = str(e)
        
        # Check for key storage vulnerabilities
        if analysis.get('encrypted'):
            analysis.update(self.check_key_storage_security(db_path))
        
        return analysis
    
    def analyze_realm_database(self, db_path: str) -> Dict:
        """Analyze Realm database for encryption"""
        analysis = {
            'subtype': 'Realm',
            'schema_version': None
        }
        
        try:
            with open(db_path, 'rb') as f:
                header = f.read(64)
                
                # Check Realm file header
                if header[:8] == self.realm_unencrypted:
                    analysis['encrypted'] = False
                    
                    # Try to extract schema version
                    if len(header) >= 16:
                        version_bytes = header[8:16]
                        try:
                            version = struct.unpack('<Q', version_bytes)[0]
                            analysis['schema_version'] = version
                        except:
                            pass
                            
                elif header[:8] == b'\x00' * 8:
                    # Likely encrypted Realm
                    analysis['encrypted'] = True
                    analysis['encryption_type'] = 'Realm Encryption'
                    analysis['algorithm'] = 'AES-256 + SHA-256'
                else:
                    analysis['encrypted'] = 'Unknown'
                    
        except Exception as e:
            analysis['error'] = str(e)
        
        # Check for key storage
        if analysis.get('encrypted'):
            analysis.update(self.check_realm_key_storage(db_path))
        
        return analysis
    
    def scan_for_sensitive_data(self, conn: sqlite3.Connection) -> List[Dict]:
        """Scan SQLite database for sensitive data"""
        sensitive_findings = []
        
        sensitive_patterns = {
            'passwords': ['password', 'passwd', 'pwd', 'secret'],
            'tokens': ['token', 'jwt', 'bearer', 'access_token', 'refresh_token'],
            'keys': ['api_key', 'private_key', 'secret_key', 'encryption_key'],
            'personal': ['email', 'phone', 'ssn', 'credit_card'],
            'aws': ['aws_access', 'aws_secret', 'cognito', 'amplify']
        }
        
        try:
            cursor = conn.cursor()
            
            # Get all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            
            for table in tables:
                table_name = table[0]
                
                # Get column names
                cursor.execute(f"PRAGMA table_info({table_name})")
                columns = cursor.fetchall()
                
                for col in columns:
                    col_name = col[1].lower()
                    
                    # Check column names for sensitive patterns
                    for category, patterns in sensitive_patterns.items():
                        for pattern in patterns:
                            if pattern in col_name:
                                sensitive_findings.append({
                                    'table': table_name,
                                    'column': col[1],
                                    'type': category,
                                    'pattern': pattern
                                })
                                
                                # Sample data from this column
                                try:
                                    cursor.execute(f"SELECT {col[1]} FROM {table_name} LIMIT 1")
                                    sample = cursor.fetchone()
                                    if sample and sample[0]:
                                        # Check if data appears to be plaintext sensitive
                                        if self._is_plaintext_sensitive(str(sample[0])):
                                            sensitive_findings[-1]['plaintext'] = True
                                            sensitive_findings[-1]['risk'] = 'CRITICAL'
                                except:
                                    pass
                                    
        except Exception as e:
            print(f"[-] Error scanning for sensitive data: {e}")
        
        return sensitive_findings
    
    def check_key_storage_security(self, db_path: str) -> Dict:
        """Check how encryption keys are stored"""
        security_analysis = {
            'key_storage': 'Unknown',
            'vulnerabilities': []
        }
        
        # Check for hardcoded keys in nearby files
        parent_dir = Path(db_path).parent
        
        # Common files that might contain keys
        key_files = [
            'Config.plist', 'Info.plist', 'Settings.plist',
            'config.json', 'settings.json', 'keys.json',
            '*.swift', '*.m', '*.h'  # Source files
        ]
        
        for pattern in key_files:
            for file in parent_dir.glob(pattern):
                if self._check_file_for_keys(file):
                    security_analysis['vulnerabilities'].append(
                        f"Potential hardcoded key in {file.name}"
                    )
                    security_analysis['key_storage'] = 'Hardcoded (INSECURE)'
        
        # Check if using Keychain (good practice)
        keychain_indicators = [
            'kSecAttrAccount',
            'kSecClass',
            'SecItemAdd',
            'KeychainAccess'
        ]
        
        # This would need binary analysis in practice
        # Simplified check for demonstration
        if not security_analysis['vulnerabilities']:
            security_analysis['key_storage'] = 'Possibly Keychain (SECURE)'
        
        return security_analysis
    
    def check_realm_key_storage(self, db_path: str) -> Dict:
        """Check Realm encryption key storage"""
        security_analysis = {
            'key_storage': 'Unknown',
            'key_derivation': None,
            'vulnerabilities': []
        }
        
        # Realm typically uses 64-byte encryption keys
        # Check for common insecure patterns
        
        parent_dir = Path(db_path).parent
        
        # Look for Realm configuration files
        for config_file in parent_dir.glob('*.realmconfig'):
            security_analysis['vulnerabilities'].append(
                f"Realm config file found: {config_file.name}"
            )
        
        # Check for key derivation
        # Good: Key derived from user password via PBKDF2
        # Bad: Hardcoded key or weak derivation
        
        # This would require runtime analysis
        security_analysis['key_derivation'] = 'Unknown (requires runtime analysis)'
        
        return security_analysis
    
    def _is_plaintext_sensitive(self, data: str) -> bool:
        """Check if data appears to be plaintext sensitive information"""
        # Check for password patterns
        if len(data) > 6:
            has_upper = any(c.isupper() for c in data)
            has_lower = any(c.islower() for c in data)
            has_digit = any(c.isdigit() for c in data)
            
            if has_upper and has_lower and has_digit:
                return True
        
        # Check for token patterns (JWT, etc)
        if data.startswith('eyJ') or data.count('.') == 2:
            return True
        
        # Check for API key patterns
        if len(data) > 20 and data.isalnum():
            return True
        
        return False
    
    def _check_file_for_keys(self, file_path: Path) -> bool:
        """Check if file contains hardcoded encryption keys"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                # Patterns indicating hardcoded keys
                key_patterns = [
                    r'encryptionKey\s*=\s*["\'][\w+/=]{32,}["\']',
                    r'databaseKey\s*=\s*["\'][\w+/=]{32,}["\']',
                    r'realmKey\s*=\s*["\'][\w+/=]{64}["\']',
                    r'sqlcipherKey\s*=\s*["\'][\w+/=]{32,}["\']',
                    r'let\s+key\s*=\s*["\'][\w+/=]{32,}["\']',  # Swift
                    r'NSString\s*\*key\s*=\s*@["\'][\w+/=]{32,}["\']'  # Objective-C
                ]
                
                import re
                for pattern in key_patterns:
                    if re.search(pattern, content):
                        return True
                        
        except:
            pass
        
        return False
    
    def test_grdb_encryption(self, db_path: str) -> Dict:
        """Test GRDB database encryption"""
        analysis = {
            'type': 'GRDB',
            'encrypted': False,
            'using_sqlcipher': False
        }
        
        # GRDB can use SQLCipher for encryption
        # Check if it's a SQLCipher-encrypted GRDB database
        sqlite_analysis = self.analyze_sqlite_database(db_path)
        
        if sqlite_analysis.get('encrypted'):
            analysis['encrypted'] = True
            if 'SQLCipher' in sqlite_analysis.get('encryption_type', ''):
                analysis['using_sqlcipher'] = True
                analysis['algorithm'] = 'AES-256-CBC (SQLCipher)'
        
        return analysis
    
    def detect_cloudkit_cache(self, app_path: str) -> List[Dict]:
        """Detect and analyze CloudKit local cache databases"""
        cloudkit_dbs = []
        
        # CloudKit cache locations
        cache_paths = [
            'Library/Caches/CloudKit',
            'Documents/CloudKit',
            'Library/Application Support/CloudKit'
        ]
        
        base_path = Path(app_path)
        
        for cache_path in cache_paths:
            full_path = base_path / cache_path
            if full_path.exists():
                for db_file in full_path.rglob('*.sqlite'):
                    db_info = self.analyze_database_file(str(db_file))
                    db_info['type'] = 'CloudKit Cache'
                    
                    # CloudKit caches are typically not encrypted locally
                    if not db_info.get('encrypted'):
                        db_info['vulnerabilities'].append(
                            'CloudKit cache not encrypted locally'
                        )
                    
                    cloudkit_dbs.append(db_info)
        
        return cloudkit_dbs
    
    def generate_report(self, output_file: str = None) -> Dict:
        """Generate comprehensive database encryption report"""
        print("[*] Generating database encryption report...")
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'app_path': self.app_path,
            'summary': {
                'total_databases': len(self.databases),
                'encrypted_databases': 0,
                'unencrypted_databases': 0,
                'sensitive_data_found': 0,
                'critical_vulnerabilities': 0
            },
            'databases': [],
            'vulnerabilities': [],
            'recommendations': []
        }
        
        for db in self.databases:
            # Update summary
            if db.get('encrypted'):
                report['summary']['encrypted_databases'] += 1
            else:
                report['summary']['unencrypted_databases'] += 1
            
            if db.get('sensitive_data'):
                report['summary']['sensitive_data_found'] += len(db['sensitive_data'])
            
            # Add to report
            report['databases'].append(db)
            
            # Compile vulnerabilities
            if not db.get('encrypted') and db.get('sensitive_data'):
                report['vulnerabilities'].append({
                    'severity': 'CRITICAL',
                    'database': db['path'],
                    'issue': 'Unencrypted database contains sensitive data',
                    'data_types': [s['type'] for s in db['sensitive_data']]
                })
                report['summary']['critical_vulnerabilities'] += 1
            
            if db.get('vulnerabilities'):
                for vuln in db['vulnerabilities']:
                    report['vulnerabilities'].append({
                        'severity': 'HIGH',
                        'database': db['path'],
                        'issue': vuln
                    })
        
        # Generate recommendations
        if report['summary']['unencrypted_databases'] > 0:
            report['recommendations'].append(
                'Implement database encryption for all databases containing sensitive data'
            )
        
        if any('SQLite' in db.get('type', '') for db in self.databases):
            report['recommendations'].append(
                'Use SQLCipher for SQLite database encryption'
            )
        
        if any('Realm' in db.get('type', '') for db in self.databases):
            report['recommendations'].append(
                'Enable Realm encryption with 64-byte key stored in Keychain'
            )
        
        if any('Core Data' in db.get('subtype', '') for db in self.databases):
            report['recommendations'].append(
                'Use Core Data encryption with NSPersistentStoreFileProtectionKey'
            )
        
        if any('Hardcoded' in str(db.get('key_storage', '')) for db in self.databases):
            report['recommendations'].append(
                'Never hardcode encryption keys - use iOS Keychain for secure key storage'
            )
        
        report['recommendations'].extend([
            'Use hardware-backed key storage (Secure Enclave) when available',
            'Implement proper key derivation (PBKDF2 with salt)',
            'Enable file protection (NSFileProtectionComplete)',
            'Regular security audits of database contents',
            'Implement database access logging'
        ])
        
        # Save report
        if not output_file:
            output_file = f"db_encryption_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Report saved to {output_file}")
        
        # Print summary
        print("\n" + "="*50)
        print("DATABASE ENCRYPTION SUMMARY")
        print("="*50)
        print(f"Total Databases: {report['summary']['total_databases']}")
        print(f"Encrypted: {report['summary']['encrypted_databases']}")
        print(f"Unencrypted: {report['summary']['unencrypted_databases']}")
        print(f"Critical Issues: {report['summary']['critical_vulnerabilities']}")
        
        return report

def main():
    parser = argparse.ArgumentParser(description='iOS Database Encryption Scanner')
    parser.add_argument('app_path', help='Path to iOS app sandbox')
    parser.add_argument('--output', help='Output report file')
    parser.add_argument('--check-cloudkit', action='store_true',
                       help='Check CloudKit cache databases')
    parser.add_argument('--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    scanner = DatabaseEncryptionScanner(args.app_path)
    
    # Scan for databases
    databases = scanner.scan_for_databases(args.app_path)
    print(f"[+] Found {len(databases)} databases")
    
    # Check CloudKit if requested
    if args.check_cloudkit:
        cloudkit_dbs = scanner.detect_cloudkit_cache(args.app_path)
        databases.extend(cloudkit_dbs)
        print(f"[+] Found {len(cloudkit_dbs)} CloudKit cache databases")
    
    # Generate report
    report = scanner.generate_report(args.output)
    
    if args.verbose:
        print("\n[*] Detailed Findings:")
        for db in databases:
            print(f"\nDatabase: {db['path']}")
            print(f"  Type: {db['type']}")
            print(f"  Encrypted: {db.get('encrypted', False)}")
            if db.get('sensitive_data'):
                print(f"  Sensitive Data: {len(db['sensitive_data'])} items")

if __name__ == "__main__":
    main()