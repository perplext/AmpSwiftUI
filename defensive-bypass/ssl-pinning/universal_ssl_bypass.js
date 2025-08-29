/*
 * Universal SSL Pinning Bypass for iOS
 * Supports: TrustKit, Alamofire, AFNetworking, Native URLSession
 * Usage: frida -U -f com.target.app -l universal_ssl_bypass.js --no-pause
 */

// Color codes for output
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const BLUE = '\x1b[34m';
const RESET = '\x1b[0m';

console.log(BLUE + "[*] Starting Universal SSL Pinning Bypass for iOS" + RESET);

// TrustKit Bypass
try {
    Module.findExportByName(null, "TSKPinningValidator") !== null && Interceptor.attach(
        Module.findExportByName(null, "TSKPinningValidator"), {
            onEnter: function(args) {
                console.log(YELLOW + "[*] TrustKit pinning validation detected" + RESET);
            },
            onLeave: function(retval) {
                retval.replace(0x1);
                console.log(GREEN + "[+] TrustKit pinning bypassed" + RESET);
            }
        }
    );
} catch(err) {
    console.log(RED + "[-] TrustKit not found" + RESET);
}

// NSURLSession Bypass
try {
    var className = "NSURLSession";
    var funcName = "- URLSession:didReceiveChallenge:completionHandler:";
    
    var hook = ObjC.classes[className][funcName];
    Interceptor.attach(hook.implementation, {
        onEnter: function(args) {
            console.log(YELLOW + "[*] NSURLSession challenge detected" + RESET);
            var completion = new ObjC.Block(args[4]);
            completion.implementation = function(disposition, credential) {
                console.log(GREEN + "[+] Bypassing NSURLSession pinning" + RESET);
                disposition = 0;
                credential = ObjC.classes.NSURLCredential.credentialForTrust_(args[3]);
                completion.implementation(disposition, credential);
            };
        }
    });
} catch(err) {
    console.log(RED + "[-] NSURLSession hook failed: " + err + RESET);
}

// Alamofire 5.x Bypass
try {
    var AlamofireServerTrustEval = ObjC.classes.ServerTrustEvaluation;
    if (AlamofireServerTrustEval) {
        Interceptor.attach(AlamofireServerTrustEval["- evaluate:forHost:"].implementation, {
            onLeave: function(retval) {
                retval.replace(0x1);
                console.log(GREEN + "[+] Alamofire 5.x pinning bypassed" + RESET);
            }
        });
    }
} catch(err) {
    console.log(RED + "[-] Alamofire 5.x not found" + RESET);
}

// AFNetworking Bypass
try {
    var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
    if (AFSecurityPolicy) {
        Interceptor.attach(AFSecurityPolicy["- evaluateServerTrust:forDomain:"].implementation, {
            onLeave: function(retval) {
                retval.replace(0x1);
                console.log(GREEN + "[+] AFNetworking pinning bypassed" + RESET);
            }
        });
    }
} catch(err) {
    console.log(RED + "[-] AFNetworking not found" + RESET);
}

// SecTrustEvaluate Bypass (Low-level)
try {
    Interceptor.replace(Module.findExportByName(null, "SecTrustEvaluate"), 
        new NativeCallback(function(trust, result) {
            console.log(GREEN + "[+] SecTrustEvaluate bypassed" + RESET);
            Memory.writeU32(result, 0);
            return 0;
        }, 'int', ['pointer', 'pointer'])
    );
} catch(err) {
    console.log(RED + "[-] SecTrustEvaluate hook failed" + RESET);
}

// SecTrustEvaluateWithError Bypass (iOS 12+)
try {
    Interceptor.replace(Module.findExportByName(null, "SecTrustEvaluateWithError"),
        new NativeCallback(function(trust, error) {
            console.log(GREEN + "[+] SecTrustEvaluateWithError bypassed" + RESET);
            return 1;
        }, 'bool', ['pointer', 'pointer'])
    );
} catch(err) {
    console.log(RED + "[-] SecTrustEvaluateWithError hook failed" + RESET);
}

// tls_helper_create_peer_trust Bypass (iOS 14+)
try {
    var tls_helper = Module.findExportByName(null, "tls_helper_create_peer_trust");
    if (tls_helper) {
        Interceptor.replace(tls_helper,
            new NativeCallback(function() {
                console.log(GREEN + "[+] tls_helper_create_peer_trust bypassed" + RESET);
                return 0;
            }, 'int', [])
        );
    }
} catch(err) {
    console.log(RED + "[-] tls_helper not found" + RESET);
}

// Custom Certificate Validation Bypass
ObjC.classes.NSURLRequest && Interceptor.attach(
    ObjC.classes.NSURLRequest["- initWithURL:cachePolicy:timeoutInterval:"].implementation, {
        onEnter: function(args) {
            var url = ObjC.Object(args[2]);
            console.log(BLUE + "[*] Request to: " + url.toString() + RESET);
        }
    }
);

// SwiftUI/Combine Network Bypass
if (ObjC.classes.URLSession) {
    try {
        var URLSessionDelegate = ObjC.classes.NSURLSessionDelegate;
        Interceptor.attach(URLSessionDelegate["- URLSession:didReceiveChallenge:completionHandler:"].implementation, {
            onEnter: function(args) {
                console.log(YELLOW + "[*] URLSession challenge for SwiftUI detected" + RESET);
                var completionHandler = new ObjC.Block(args[4]);
                completionHandler.implementation = function(disposition, credential) {
                    console.log(GREEN + "[+] Bypassing SwiftUI URLSession pinning" + RESET);
                    disposition = 0;
                    credential = ObjC.classes.NSURLCredential.credentialForTrust_(args[3]);
                    completionHandler.implementation(disposition, credential);
                };
            }
        });
    } catch(err) {
        console.log(RED + "[-] SwiftUI URLSession bypass failed" + RESET);
    }
}

console.log(GREEN + "[+] SSL Pinning Bypass Script Loaded Successfully" + RESET);
console.log(BLUE + "[*] Monitoring network requests..." + RESET);