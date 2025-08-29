/*
 * Swift Runtime Analyzer
 * Deep inspection of Swift runtime, ARC, and protocol conformance
 * Targets: Swift 5.x on iOS 14+
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

console.log(Color.CYAN + "[*] Swift Runtime Analyzer v1.0" + Color.RESET);
console.log(Color.CYAN + "[*] Checking Swift availability..." + Color.RESET);

// Check Swift runtime
if (Swift.available) {
    console.log(Color.GREEN + "[+] Swift runtime detected" + Color.RESET);
} else {
    console.log(Color.RED + "[-] Swift runtime not available" + Color.RESET);
}

// Storage for discovered Swift types
var swiftClasses = {};
var swiftProtocols = {};
var swiftFunctions = [];
var arcOperations = [];

// Enumerate Swift classes and functions
function enumerateSwiftTypes() {
    console.log(Color.BLUE + "[*] Enumerating Swift types..." + Color.RESET);
    
    try {
        // Use ApiResolver to find Swift functions
        const resolver = new ApiResolver('swift');
        
        // Find all Swift functions
        const functions = resolver.enumerateMatches('functions:*!*');
        console.log(Color.GREEN + `[+] Found ${functions.length} Swift functions` + Color.RESET);
        
        functions.forEach(func => {
            swiftFunctions.push({
                name: func.name,
                address: func.address
            });
            
            // Extract class name if present
            const parts = func.name.split('.');
            if (parts.length > 1) {
                const className = parts[0];
                if (!swiftClasses[className]) {
                    swiftClasses[className] = {
                        methods: [],
                        properties: []
                    };
                }
                swiftClasses[className].methods.push(func.name);
            }
        });
        
        // Try to find SwiftUI specific functions
        const swiftuiFuncs = resolver.enumerateMatches('functions:*SwiftUI!*');
        console.log(Color.GREEN + `[+] Found ${swiftuiFuncs.length} SwiftUI functions` + Color.RESET);
        
        // Try to find Combine framework functions
        const combineFuncs = resolver.enumerateMatches('functions:*Combine!*');
        console.log(Color.GREEN + `[+] Found ${combineFuncs.length} Combine functions` + Color.RESET);
        
    } catch(e) {
        console.log(Color.RED + "[-] Error enumerating Swift types: " + e + Color.RESET);
    }
}

// Hook Swift init methods
function hookSwiftInitializers() {
    console.log(Color.BLUE + "[*] Hooking Swift initializers..." + Color.RESET);
    
    swiftFunctions.forEach(func => {
        if (func.name.includes('.init(') || func.name.includes('.init ')) {
            try {
                Interceptor.attach(func.address, {
                    onEnter: function(args) {
                        console.log(Color.YELLOW + `[Swift Init] ${func.name}` + Color.RESET);
                        
                        // Try to dump arguments
                        for (let i = 0; i < 4; i++) {
                            try {
                                const arg = args[i];
                                if (arg && !arg.isNull()) {
                                    console.log(`  arg[${i}]: 0x${arg.toString(16)}`);
                                }
                            } catch(e) {}
                        }
                    }
                });
            } catch(e) {
                // Silently skip functions that can't be hooked
            }
        }
    });
}

// Hook Swift deinit methods
function hookSwiftDeinitializers() {
    console.log(Color.BLUE + "[*] Hooking Swift deinitializers..." + Color.RESET);
    
    swiftFunctions.forEach(func => {
        if (func.name.includes('.deinit')) {
            try {
                Interceptor.attach(func.address, {
                    onEnter: function(args) {
                        console.log(Color.RED + `[Swift Deinit] ${func.name}` + Color.RESET);
                    }
                });
            } catch(e) {}
        }
    });
}

// Hook ARC operations
function hookARCOperations() {
    console.log(Color.BLUE + "[*] Hooking ARC operations..." + Color.RESET);
    
    // swift_retain
    const swift_retain = Module.findExportByName(null, "swift_retain");
    if (swift_retain) {
        Interceptor.attach(swift_retain, {
            onEnter: function(args) {
                const obj = args[0];
                arcOperations.push({
                    type: 'retain',
                    address: obj.toString(),
                    timestamp: Date.now()
                });
                
                if (arcOperations.length % 100 === 0) {
                    console.log(Color.YELLOW + `[ARC] ${arcOperations.length} operations tracked` + Color.RESET);
                }
            }
        });
    }
    
    // swift_release
    const swift_release = Module.findExportByName(null, "swift_release");
    if (swift_release) {
        Interceptor.attach(swift_release, {
            onEnter: function(args) {
                const obj = args[0];
                arcOperations.push({
                    type: 'release',
                    address: obj.toString(),
                    timestamp: Date.now()
                });
            }
        });
    }
    
    // swift_weakRetain
    const swift_weakRetain = Module.findExportByName(null, "swift_weakRetain");
    if (swift_weakRetain) {
        Interceptor.attach(swift_weakRetain, {
            onEnter: function(args) {
                console.log(Color.CYAN + "[ARC] Weak retain" + Color.RESET);
            }
        });
    }
}

// Hook protocol witness tables
function hookProtocolWitness() {
    console.log(Color.BLUE + "[*] Analyzing protocol conformance..." + Color.RESET);
    
    // swift_conformsToProtocol
    const conformsToProtocol = Module.findExportByName(null, "swift_conformsToProtocol");
    if (conformsToProtocol) {
        Interceptor.attach(conformsToProtocol, {
            onEnter: function(args) {
                const type = args[0];
                const protocol = args[1];
                console.log(Color.MAGENTA + "[Protocol] Conformance check" + Color.RESET);
            },
            onLeave: function(retval) {
                if (!retval.isNull()) {
                    console.log(Color.GREEN + "  ✓ Conforms to protocol" + Color.RESET);
                }
            }
        });
    }
}

// Hook Swift error handling
function hookSwiftErrors() {
    console.log(Color.BLUE + "[*] Hooking Swift error handling..." + Color.RESET);
    
    // swift_errorRetain
    const errorRetain = Module.findExportByName(null, "swift_errorRetain");
    if (errorRetain) {
        Interceptor.attach(errorRetain, {
            onEnter: function(args) {
                console.log(Color.RED + "[Error] Swift error retained" + Color.RESET);
                const error = args[0];
                
                // Try to extract error information
                try {
                    const errorStr = Memory.readUtf8String(error.add(16), 100);
                    if (errorStr && errorStr.length > 0) {
                        console.log(Color.RED + "  Error: " + errorStr + Color.RESET);
                    }
                } catch(e) {}
            }
        });
    }
    
    // swift_willThrow
    const willThrow = Module.findExportByName(null, "swift_willThrow");
    if (willThrow) {
        Interceptor.attach(willThrow, {
            onEnter: function(args) {
                console.log(Color.RED + "[Error] Exception will be thrown" + Color.RESET);
            }
        });
    }
}

// Hook Swift string operations
function hookSwiftStrings() {
    console.log(Color.BLUE + "[*] Hooking Swift string operations..." + Color.RESET);
    
    // Swift.String.init
    swiftFunctions.forEach(func => {
        if (func.name.includes('Swift.String.init')) {
            try {
                Interceptor.attach(func.address, {
                    onEnter: function(args) {
                        console.log(Color.YELLOW + "[String] Creating Swift string" + Color.RESET);
                        
                        // Try to read string content
                        try {
                            const strPtr = args[0];
                            if (strPtr && !strPtr.isNull()) {
                                const str = Memory.readUtf8String(strPtr, 100);
                                if (str && str.length > 0) {
                                    console.log("  Content: " + str);
                                }
                            }
                        } catch(e) {}
                    }
                });
            } catch(e) {}
        }
    });
}

// Analyze Swift metadata
function analyzeSwiftMetadata() {
    console.log(Color.CYAN + "\n[*] Analyzing Swift metadata..." + Color.RESET);
    
    // Find Swift metadata sections
    Process.enumerateModules().forEach(module => {
        if (module.name.includes('.app') || module.name.includes('Swift')) {
            console.log(Color.BLUE + `[*] Checking module: ${module.name}` + Color.RESET);
            
            // Look for Swift type metadata
            Module.enumerateExports(module.name).forEach(exp => {
                if (exp.name.includes('$s') || exp.name.includes('_$s')) {
                    // Swift mangled symbol
                    try {
                        // Attempt to demangle
                        const demangled = swift_demangle(exp.name);
                        if (demangled) {
                            console.log(Color.GREEN + `  ${exp.name} -> ${demangled}` + Color.RESET);
                        }
                    } catch(e) {}
                }
            });
        }
    });
}

// Swift demangling (simplified)
function swift_demangle(mangledName) {
    // This would normally use swift_demangle from libswiftCore
    // Simplified pattern matching for common cases
    
    if (mangledName.includes('$s')) {
        // Try to extract meaningful parts
        const parts = mangledName.split('$s')[1];
        if (parts) {
            // Basic demangling patterns
            return parts.replace(/(\d+)([A-Za-z]+)/g, (match, len, name) => {
                return name.substring(0, parseInt(len));
            });
        }
    }
    return null;
}

// API Functions
function dumpSwiftClasses() {
    console.log(Color.CYAN + "\n========== SWIFT CLASSES ==========" + Color.RESET);
    for (let className in swiftClasses) {
        console.log(Color.GREEN + className + ":" + Color.RESET);
        const cls = swiftClasses[className];
        console.log("  Methods: " + cls.methods.length);
        cls.methods.slice(0, 5).forEach(method => {
            console.log("    - " + method);
        });
        if (cls.methods.length > 5) {
            console.log("    ... and " + (cls.methods.length - 5) + " more");
        }
    }
    console.log(Color.CYAN + "===================================\n" + Color.RESET);
}

function dumpARCStats() {
    console.log(Color.YELLOW + "\n========== ARC STATISTICS ==========" + Color.RESET);
    
    const retainCount = arcOperations.filter(op => op.type === 'retain').length;
    const releaseCount = arcOperations.filter(op => op.type === 'release').length;
    
    console.log(`Total operations: ${arcOperations.length}`);
    console.log(`Retains: ${retainCount}`);
    console.log(`Releases: ${releaseCount}`);
    console.log(`Balance: ${retainCount - releaseCount}`);
    
    // Find potential leaks (objects with more retains than releases)
    const objectCounts = {};
    arcOperations.forEach(op => {
        if (!objectCounts[op.address]) {
            objectCounts[op.address] = { retain: 0, release: 0 };
        }
        objectCounts[op.address][op.type]++;
    });
    
    console.log("\nPotential memory leaks:");
    for (let addr in objectCounts) {
        const counts = objectCounts[addr];
        if (counts.retain > counts.release + 1) {
            console.log(`  ${addr}: +${counts.retain - counts.release}`);
        }
    }
    
    console.log(Color.YELLOW + "===================================\n" + Color.RESET);
}

function findSwiftFunction(pattern) {
    console.log(Color.BLUE + `\n[*] Searching for Swift functions matching: ${pattern}` + Color.RESET);
    
    const matches = swiftFunctions.filter(func => 
        func.name.toLowerCase().includes(pattern.toLowerCase())
    );
    
    matches.forEach(func => {
        console.log(`  ${func.name} @ ${func.address}`);
    });
    
    console.log(Color.GREEN + `[+] Found ${matches.length} matches` + Color.RESET);
    return matches;
}

function hookSwiftFunction(pattern) {
    const matches = findSwiftFunction(pattern);
    
    if (matches.length === 0) {
        console.log(Color.RED + "[-] No functions found" + Color.RESET);
        return;
    }
    
    matches.forEach(func => {
        try {
            Interceptor.attach(func.address, {
                onEnter: function(args) {
                    console.log(Color.MAGENTA + `[Hook] ${func.name} called` + Color.RESET);
                    
                    // Dump first 4 arguments
                    for (let i = 0; i < 4; i++) {
                        try {
                            const arg = args[i];
                            if (arg && !arg.isNull()) {
                                console.log(`  arg[${i}]: 0x${arg.toString(16)}`);
                                
                                // Try to read as string
                                try {
                                    const str = Memory.readUtf8String(arg, 50);
                                    if (str && str.length > 0 && str.isPrintable()) {
                                        console.log(`    String: "${str}"`);
                                    }
                                } catch(e) {}
                            }
                        } catch(e) {}
                    }
                },
                onLeave: function(retval) {
                    if (retval && !retval.isNull()) {
                        console.log(`  Return: 0x${retval.toString(16)}`);
                    }
                }
            });
            
            console.log(Color.GREEN + `[+] Hooked: ${func.name}` + Color.RESET);
        } catch(e) {
            console.log(Color.RED + `[-] Failed to hook: ${func.name}` + Color.RESET);
        }
    });
}

// Initialize
enumerateSwiftTypes();
hookARCOperations();
hookProtocolWitness();
hookSwiftErrors();

// Export functions
global.dumpSwiftClasses = dumpSwiftClasses;
global.dumpARCStats = dumpARCStats;
global.findSwiftFunction = findSwiftFunction;
global.hookSwiftFunction = hookSwiftFunction;
global.hookSwiftInitializers = hookSwiftInitializers;
global.hookSwiftDeinitializers = hookSwiftDeinitializers;
global.hookSwiftStrings = hookSwiftStrings;
global.analyzeSwiftMetadata = analyzeSwiftMetadata;

console.log(Color.GREEN + "[+] Swift Runtime Analyzer loaded successfully!" + Color.RESET);
console.log(Color.GREEN + "[+] Available commands:" + Color.RESET);
console.log("    dumpSwiftClasses()       - Show discovered Swift classes");
console.log("    dumpARCStats()           - Show ARC statistics and leaks");
console.log("    findSwiftFunction(name)  - Search for Swift functions");
console.log("    hookSwiftFunction(name)  - Hook Swift functions by pattern");
console.log("    hookSwiftInitializers()  - Hook all init methods");
console.log("    hookSwiftDeinitializers() - Hook all deinit methods");
console.log("    hookSwiftStrings()       - Hook string operations");
console.log("    analyzeSwiftMetadata()   - Analyze Swift type metadata");