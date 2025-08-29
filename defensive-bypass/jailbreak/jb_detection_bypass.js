/*
 * iOS Jailbreak Detection Bypass
 * Defeats common jailbreak detection methods
 */

// File system checks
var fopen = Module.findExportByName(null, "fopen");
var access = Module.findExportByName(null, "access");
var stat = Module.findExportByName(null, "stat");
var lstat = Module.findExportByName(null, "lstat");

var jbPaths = [
    "/Applications/Cydia.app",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/bin/bash",
    "/usr/sbin/sshd",
    "/etc/apt",
    "/private/var/lib/apt/",
    "/usr/bin/ssh",
    "/private/var/stash",
    "/private/var/lib/cydia",
    "/var/cache/apt",
    "/var/lib/cydia",
    "/usr/libexec/sftp-server",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/.bootstrapped_electra",
    "/usr/lib/libjailbreak.dylib"
];

// Hook fopen
Interceptor.attach(fopen, {
    onEnter: function(args) {
        var path = Memory.readUtf8String(args[0]);
        for (var i = 0; i < jbPaths.length; i++) {
            if (path.indexOf(jbPaths[i]) > -1) {
                args[0] = Memory.allocUtf8String("/invalid");
                console.log("[+] Blocked fopen: " + path);
            }
        }
    }
});

// Hook access
Interceptor.attach(access, {
    onEnter: function(args) {
        var path = Memory.readUtf8String(args[0]);
        for (var i = 0; i < jbPaths.length; i++) {
            if (path.indexOf(jbPaths[i]) > -1) {
                console.log("[+] Blocked access: " + path);
                this.block = true;
            }
        }
    },
    onLeave: function(retval) {
        if (this.block) {
            retval.replace(-1);
        }
    }
});

// Hook stat/lstat
[stat, lstat].forEach(function(func) {
    Interceptor.attach(func, {
        onEnter: function(args) {
            var path = Memory.readUtf8String(args[0]);
            for (var i = 0; i < jbPaths.length; i++) {
                if (path.indexOf(jbPaths[i]) > -1) {
                    console.log("[+] Blocked stat: " + path);
                    this.block = true;
                }
            }
        },
        onLeave: function(retval) {
            if (this.block) {
                retval.replace(-1);
            }
        }
    });
});

// Hook dyld image checks
Interceptor.attach(Module.findExportByName(null, "_dyld_image_count"), {
    onLeave: function(retval) {
        console.log("[*] Dyld image count check");
    }
});

// Hook fork() check
Interceptor.attach(Module.findExportByName(null, "fork"), {
    onLeave: function(retval) {
        if (retval.toInt32() == -1) {
            retval.replace(20000);
            console.log("[+] Fork check bypassed");
        }
    }
});

// Hook NSFileManager
if (ObjC.available) {
    var NSFileManager = ObjC.classes.NSFileManager;
    Interceptor.attach(NSFileManager["- fileExistsAtPath:"].implementation, {
        onEnter: function(args) {
            var path = ObjC.Object(args[2]).toString();
            for (var i = 0; i < jbPaths.length; i++) {
                if (path.indexOf(jbPaths[i]) > -1) {
                    this.block = true;
                    console.log("[+] Blocked NSFileManager check: " + path);
                }
            }
        },
        onLeave: function(retval) {
            if (this.block) {
                retval.replace(0);
            }
        }
    });
}

console.log("[+] Jailbreak detection bypass loaded");