/*
 * SwiftUI View Hierarchy Inspector
 * Advanced runtime analysis of SwiftUI applications
 * Targets: iOS 15+ with SwiftUI 3.0+
 */

const Color = {
    RED: '\x1b[31m',
    GREEN: '\x1b[32m',
    YELLOW: '\x1b[33m',
    BLUE: '\x1b[34m',
    MAGENTA: '\x1b[35m',
    CYAN: '\x1b[36m',
    RESET: '\x1b[0m'
};

console.log(Color.CYAN + "[*] SwiftUI View Hierarchy Inspector v1.0" + Color.RESET);
console.log(Color.CYAN + "[*] Initializing hooks..." + Color.RESET);

// Global storage for view hierarchy
var viewHierarchy = {};
var stateTracking = {};
var environmentObjects = {};

// Hook AttributeGraph framework (SwiftUI's internal view graph)
if (ObjC.available) {
    try {
        // Hook SwiftUI View protocol conformance
        const ViewProtocol = ObjC.protocols.View;
        
        // Monitor view body calls
        Interceptor.attach(ObjC.classes.NSObject["- body"].implementation, {
            onEnter: function(args) {
                const view = ObjC.Object(args[0]);
                const className = view.$className;
                
                if (className && className.includes("SwiftUI")) {
                    console.log(Color.GREEN + "[+] View body accessed: " + className + Color.RESET);
                    
                    // Try to extract view properties
                    const properties = extractViewProperties(view);
                    if (properties) {
                        viewHierarchy[className] = properties;
                    }
                }
            }
        });
    } catch(e) {
        console.log(Color.RED + "[-] Failed to hook View protocol: " + e + Color.RESET);
    }
    
    // Hook @State property wrapper
    try {
        const State = ObjC.classes["SwiftUI.State"];
        if (State) {
            Interceptor.attach(State["- wrappedValue"].implementation, {
                onEnter: function(args) {
                    this.stateObj = ObjC.Object(args[0]);
                },
                onLeave: function(retval) {
                    const value = ObjC.Object(retval);
                    console.log(Color.YELLOW + "[*] @State accessed: " + value.toString() + Color.RESET);
                    
                    // Track state changes
                    const key = this.stateObj.toString();
                    if (!stateTracking[key]) {
                        stateTracking[key] = [];
                    }
                    stateTracking[key].push({
                        timestamp: Date.now(),
                        value: value.toString()
                    });
                }
            });
        }
    } catch(e) {
        console.log(Color.RED + "[-] Failed to hook @State: " + e + Color.RESET);
    }
    
    // Hook @Published property wrapper
    try {
        const Published = ObjC.classes["Combine.Published"];
        if (Published) {
            Interceptor.attach(Published["- wrappedValue"].implementation, {
                onLeave: function(retval) {
                    const value = ObjC.Object(retval);
                    console.log(Color.YELLOW + "[*] @Published value: " + value.toString() + Color.RESET);
                }
            });
        }
    } catch(e) {
        console.log(Color.RED + "[-] Failed to hook @Published: " + e + Color.RESET);
    }
    
    // Hook NavigationView/NavigationStack
    try {
        const NavigationView = ObjC.classes["SwiftUI.NavigationView"];
        if (NavigationView) {
            Interceptor.attach(NavigationView["- init"].implementation, {
                onEnter: function(args) {
                    console.log(Color.BLUE + "[+] NavigationView initialized" + Color.RESET);
                }
            });
        }
        
        // iOS 16+ NavigationStack
        const NavigationStack = ObjC.classes["SwiftUI.NavigationStack"];
        if (NavigationStack) {
            Interceptor.attach(NavigationStack["- init"].implementation, {
                onEnter: function(args) {
                    console.log(Color.BLUE + "[+] NavigationStack initialized" + Color.RESET);
                }
            });
        }
    } catch(e) {
        console.log(Color.RED + "[-] Failed to hook Navigation: " + e + Color.RESET);
    }
    
    // Hook Sheet presentations
    try {
        const Sheet = ObjC.classes["SwiftUI.Sheet"];
        if (Sheet) {
            Interceptor.attach(Sheet["- present"].implementation, {
                onEnter: function(args) {
                    console.log(Color.MAGENTA + "[!] Sheet presented" + Color.RESET);
                    const content = ObjC.Object(args[2]);
                    if (content) {
                        console.log(Color.MAGENTA + "    Content: " + content.$className + Color.RESET);
                    }
                }
            });
        }
    } catch(e) {
        console.log(Color.RED + "[-] Failed to hook Sheet: " + e + Color.RESET);
    }
    
    // Hook Alert presentations
    try {
        const Alert = ObjC.classes["SwiftUI.Alert"];
        if (Alert) {
            Interceptor.attach(Alert["- init"].implementation, {
                onEnter: function(args) {
                    console.log(Color.MAGENTA + "[!] Alert created" + Color.RESET);
                    
                    // Try to extract alert title and message
                    if (args[2]) {
                        const title = ObjC.Object(args[2]);
                        console.log(Color.MAGENTA + "    Title: " + title.toString() + Color.RESET);
                    }
                    if (args[3]) {
                        const message = ObjC.Object(args[3]);
                        console.log(Color.MAGENTA + "    Message: " + message.toString() + Color.RESET);
                    }
                }
            });
        }
    } catch(e) {
        console.log(Color.RED + "[-] Failed to hook Alert: " + e + Color.RESET);
    }
    
    // Hook TextField/SecureField for input monitoring
    try {
        const TextField = ObjC.classes["SwiftUI.TextField"];
        if (TextField) {
            Interceptor.attach(TextField["- text"].implementation, {
                onLeave: function(retval) {
                    const text = ObjC.Object(retval);
                    console.log(Color.YELLOW + "[*] TextField value: " + text.toString() + Color.RESET);
                }
            });
        }
        
        const SecureField = ObjC.classes["SwiftUI.SecureField"];
        if (SecureField) {
            Interceptor.attach(SecureField["- text"].implementation, {
                onLeave: function(retval) {
                    const text = ObjC.Object(retval);
                    console.log(Color.RED + "[!] SecureField value captured: " + text.toString() + Color.RESET);
                }
            });
        }
    } catch(e) {
        console.log(Color.RED + "[-] Failed to hook Text fields: " + e + Color.RESET);
    }
    
    // Hook EnvironmentObject
    try {
        const EnvironmentObject = ObjC.classes["SwiftUI.EnvironmentObject"];
        if (EnvironmentObject) {
            Interceptor.attach(EnvironmentObject["- wrappedValue"].implementation, {
                onLeave: function(retval) {
                    const obj = ObjC.Object(retval);
                    const className = obj.$className;
                    
                    console.log(Color.CYAN + "[*] EnvironmentObject accessed: " + className + Color.RESET);
                    
                    // Store environment object for analysis
                    environmentObjects[className] = {
                        instance: obj,
                        properties: extractObjectProperties(obj)
                    };
                }
            });
        }
    } catch(e) {
        console.log(Color.RED + "[-] Failed to hook EnvironmentObject: " + e + Color.RESET);
    }
}

// Helper function to extract view properties
function extractViewProperties(view) {
    const properties = {};
    
    try {
        // Get all instance variables
        const ivars = view.$ivars;
        for (let key in ivars) {
            if (ivars.hasOwnProperty(key)) {
                properties[key] = ivars[key].toString();
            }
        }
        
        // Try to get common SwiftUI properties
        const commonProps = ['frame', 'opacity', 'foregroundColor', 'backgroundColor', 'padding'];
        commonProps.forEach(prop => {
            try {
                const selector = NSSelectorFromString(prop);
                if (view.respondsToSelector_(selector)) {
                    const value = view.performSelector_(selector);
                    if (value) {
                        properties[prop] = value.toString();
                    }
                }
            } catch(e) {}
        });
    } catch(e) {
        console.log(Color.RED + "[-] Error extracting properties: " + e + Color.RESET);
    }
    
    return properties;
}

// Helper function to extract object properties
function extractObjectProperties(obj) {
    const properties = {};
    
    try {
        // Get class methods
        const methods = obj.$methods;
        
        // Filter for getters (properties)
        methods.forEach(method => {
            if (!method.includes(':') && !method.startsWith('set')) {
                try {
                    const selector = NSSelectorFromString(method.substring(2));
                    if (obj.respondsToSelector_(selector)) {
                        const value = obj.performSelector_(selector);
                        if (value) {
                            properties[method] = value.toString();
                        }
                    }
                } catch(e) {}
            }
        });
    } catch(e) {}
    
    return properties;
}

// API to dump current view hierarchy
function dumpViewHierarchy() {
    console.log(Color.CYAN + "\n========== VIEW HIERARCHY ==========" + Color.RESET);
    for (let viewName in viewHierarchy) {
        console.log(Color.GREEN + viewName + ":" + Color.RESET);
        const props = viewHierarchy[viewName];
        for (let prop in props) {
            console.log("  " + prop + ": " + props[prop]);
        }
    }
    console.log(Color.CYAN + "===================================\n" + Color.RESET);
}

// API to dump state tracking
function dumpStateChanges() {
    console.log(Color.YELLOW + "\n========== STATE CHANGES ==========" + Color.RESET);
    for (let state in stateTracking) {
        console.log(Color.YELLOW + state + ":" + Color.RESET);
        stateTracking[state].forEach(change => {
            const date = new Date(change.timestamp);
            console.log("  [" + date.toISOString() + "] " + change.value);
        });
    }
    console.log(Color.YELLOW + "===================================\n" + Color.RESET);
}

// API to dump environment objects
function dumpEnvironmentObjects() {
    console.log(Color.CYAN + "\n======= ENVIRONMENT OBJECTS =======" + Color.RESET);
    for (let className in environmentObjects) {
        console.log(Color.CYAN + className + ":" + Color.RESET);
        const props = environmentObjects[className].properties;
        for (let prop in props) {
            console.log("  " + prop + ": " + props[prop]);
        }
    }
    console.log(Color.CYAN + "===================================\n" + Color.RESET);
}

// Monitor memory for sensitive data in views
function scanViewMemory() {
    console.log(Color.MAGENTA + "\n[*] Scanning view memory for sensitive data..." + Color.RESET);
    
    const patterns = [
        /password["\s]*[:=]\s*["']([^"']+)["']/gi,
        /api[_\s]*key["\s]*[:=]\s*["']([^"']+)["']/gi,
        /token["\s]*[:=]\s*["']([^"']+)["']/gi,
        /secret["\s]*[:=]\s*["']([^"']+)["']/gi
    ];
    
    Process.enumerateRanges('r--', {
        onMatch: function(range) {
            try {
                const data = Memory.readUtf8String(range.base, Math.min(range.size, 0x1000));
                patterns.forEach(pattern => {
                    const matches = data.match(pattern);
                    if (matches) {
                        console.log(Color.RED + "[!] Sensitive data found at " + range.base + ": " + matches[0] + Color.RESET);
                    }
                });
            } catch(e) {}
        },
        onComplete: function() {
            console.log(Color.MAGENTA + "[*] Memory scan complete" + Color.RESET);
        }
    });
}

// Export functions for interactive use
global.dumpViewHierarchy = dumpViewHierarchy;
global.dumpStateChanges = dumpStateChanges;
global.dumpEnvironmentObjects = dumpEnvironmentObjects;
global.scanViewMemory = scanViewMemory;

console.log(Color.GREEN + "[+] SwiftUI Inspector loaded successfully!" + Color.RESET);
console.log(Color.GREEN + "[+] Available commands:" + Color.RESET);
console.log("    dumpViewHierarchy()    - Show current view hierarchy");
console.log("    dumpStateChanges()     - Show @State change history");
console.log("    dumpEnvironmentObjects() - Show environment objects");
console.log("    scanViewMemory()       - Scan for sensitive data");