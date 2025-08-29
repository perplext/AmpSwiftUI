# iOS Penetration Testing Framework
## SwiftUI + AWS Amplify Security Assessment Toolkit

### Overview
Comprehensive penetration testing framework for iOS applications built with SwiftUI and AWS Amplify backend services. Incorporates 2024-2025 vulnerabilities, OWASP Mobile Top 10 2024, and advanced bypass techniques.

## Quick Start

### Prerequisites
- Jailbroken iOS device (iOS 15+) or Corellium instance
- macOS with Xcode 15+
- Python 3.9+ and Go 1.21+
- Burp Suite Professional or OWASP ZAP
- AWS CLI configured

### Installation
```bash
# Clone repository
git clone https://github.com/yourusername/AmpSwiftUI.git
cd AmpSwiftUI

# Install Python dependencies
pip3 install -r requirements.txt

# Install Frida tools
pip3 install frida-tools objection

# Install Go dependencies
go mod download

# Setup MobSF
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf
```

## Project Structure

```
AmpSwiftUI/
├── docs/                      # Documentation hub
│   ├── methodologies/        # Testing procedures
│   ├── vulnerabilities/      # CVE tracking
│   └── tools-reference.md    # Tool guides
├── tools/                    # Custom tools
│   ├── scripts/             # Python/Go tools
│   ├── frida-scripts/       # Frida hooks
│   └── configs/             # Tool configurations
├── defensive-bypass/         # Bypass techniques
│   ├── ssl-pinning/        # Certificate pinning
│   ├── anti-debug/         # Anti-debugging
│   └── jailbreak/          # JB detection
└── findings/                # Assessment results
```

## Core Components

### 1. Static Analysis
- Binary protection analysis (PIE, ASLR, Stack Canaries)
- SwiftUI view hierarchy extraction
- AWS Amplify configuration mining
- Third-party library vulnerability scanning

### 2. Dynamic Analysis
- Runtime manipulation with Frida/Objection
- SSL/TLS pinning bypass
- Method hooking and API monitoring
- Memory analysis and extraction

### 3. API Security Testing
- GraphQL introspection and fuzzing
- JWT token manipulation
- AWS Cognito identity pool testing
- Rate limiting and DoS assessment

### 4. Defensive Control Bypass
- Certificate pinning (TrustKit, Alamofire)
- Anti-debugging (ptrace, sysctl)
- Jailbreak detection
- Frida detection

## Recent Vulnerabilities (2024-2025)

### Critical iOS CVEs
- **CVE-2025-43300**: ImageIO zero-day RCE (CVSS 8.8)
- **CVE-2025-24085**: Kernel privilege escalation
- **CVE-2025-24200/24201**: WebKit vulnerabilities

### AWS Amplify Security Issues
- **CVE-2024-28056**: IAM role takeover vulnerability
- **CVE-2025-4318**: Amplify Studio code injection

### OWASP Mobile Top 10 2024
1. M1: Improper Credential Usage
2. M2: Inadequate Supply Chain Security
3. M3: Insecure Authentication/Authorization
4. M4: Insufficient Input/Output Validation
5. M5: Insecure Communication
6. M6: Inadequate Privacy Controls
7. M7: Insufficient Binary Protections
8. M8: Security Misconfiguration
9. M9: Insecure Data Storage
10. M10: Insufficient Cryptography

## Custom Tools

### ios-binary-analyzer.py
Automated IPA analysis focusing on SwiftUI symbols and AWS configurations.

### amplify-api-fuzzer.go
High-performance GraphQL/REST API fuzzer with AWS-specific payloads.

### ssl-pinning-universal-bypass.js
Frida script supporting TrustKit, Alamofire, and native URLSession pinning.

### anti-debug-defeater.py
Multi-technique anti-debugging bypass (ptrace, sysctl, syscall hooking).

### cognito-token-manipulator.py
JWT token forging and identity pool privilege escalation testing.

## Testing Methodology

### Phase 1: Reconnaissance
- Binary extraction and decryption
- String analysis for API endpoints
- Configuration file extraction
- Third-party library enumeration

### Phase 2: Static Analysis
- Run MobSF automated scanning
- Manual binary analysis with Hopper/IDA
- SwiftUI component security review
- AWS configuration assessment

### Phase 3: Dynamic Testing
- Setup proxy with SSL bypass
- Runtime manipulation with Frida
- API traffic interception
- Local storage analysis

### Phase 4: API Assessment
- GraphQL introspection
- Authentication flow testing
- Authorization bypass attempts
- Input validation fuzzing

### Phase 5: Defensive Bypass
- Certificate pinning defeat
- Anti-debugging circumvention
- Jailbreak detection bypass
- Runtime protection evasion

## Defensive Controls & Bypasses

### Certificate Pinning
**Common Implementations:**
- TrustKit
- Alamofire
- Native URLSession

**Bypass Techniques:**
- Binary patching (hash replacement)
- Runtime hooking (Frida/Objection)
- SSL Kill Switch 2
- Custom Frida scripts

### Anti-Debugging
**Detection Methods:**
- ptrace(PT_DENY_ATTACH)
- sysctl() checks
- Signal handlers
- Timing checks

**Bypass Methods:**
- Register manipulation
- Syscall hooking
- Binary patching
- Debugger detection defeat

### Jailbreak Detection
**Detection Techniques:**
- File system checks
- Cydia detection
- Fork() behavior
- Symbolic link verification

**Bypass Tools:**
- Liberty Lite
- HideJB
- FlyJB
- KernBypass
- Shadow

## Resources

### Essential Tools
- [Frida](https://frida.re/) - Dynamic instrumentation
- [Objection](https://github.com/sensepost/objection) - Runtime exploration
- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) - Security framework
- [r2frida](https://github.com/nowsecure/r2frida) - Radare2 + Frida
- [SSL Kill Switch 2](https://github.com/nabla-c0d3/ssl-kill-switch2) - SSL bypass
- [Cycript](http://www.cycript.org/) - Runtime manipulation

### AWS Security Tools
- [InQL](https://github.com/doyensec/inql) - GraphQL Burp extension
- [graphql-cop](https://github.com/dolevf/graphql-cop) - GraphQL scanner
- [aws-jwt-verify](https://github.com/awslabs/aws-jwt-verify) - Token verification

### Practice Applications
- [DVIA-v2](https://github.com/prateek147/DVIA-v2) - Damn Vulnerable iOS App
- [iGoat-Swift](https://github.com/OWASP/iGoat-Swift) - OWASP Swift app
- [UnCrackable iOS](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes) - RE challenges

### Documentation
- [OWASP MASTG](https://mas.owasp.org/MASTG/) - Mobile Security Testing Guide
- [iOS Security Suite](https://github.com/securing/IOSSecuritySuite) - Security library
- [Hacking with Swift](https://www.hackingwithswift.com/100/swiftui) - SwiftUI resources

## Contributing
Please ensure all custom tools include:
- Comprehensive documentation
- Error handling
- Logging capabilities
- Support for latest iOS versions
- AWS Amplify compatibility

## Legal Notice
This framework is for authorized security testing only. Users must obtain proper permission before testing any application. Misuse of these tools may violate laws and regulations.

## Contact
For questions or contributions, please open an issue on GitHub.