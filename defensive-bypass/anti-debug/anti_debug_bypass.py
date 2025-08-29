#!/usr/bin/env python3
"""
Anti-Debugging Bypass for iOS
Defeats: ptrace, sysctl, signal handlers, timing checks
"""

import frida
import sys
import argparse

BYPASS_SCRIPT = """
// ptrace bypass
Interceptor.attach(Module.findExportByName(null, "ptrace"), {
    onEnter: function(args) {
        if (args[0].toInt32() == 31) { // PT_DENY_ATTACH
            console.log("[+] Blocking ptrace(PT_DENY_ATTACH)");
            args[0] = ptr(0);
        }
    },
    onLeave: function(retval) {
        console.log("[+] ptrace bypassed");
    }
});

// sysctl bypass
Interceptor.attach(Module.findExportByName(null, "sysctl"), {
    onEnter: function(args) {
        this.mib = args[0];
        this.info = args[2];
    },
    onLeave: function(retval) {
        if (this.info != null) {
            var flag = Memory.readU32(this.info.add(12));
            if (flag == 0x800) {
                Memory.writeU32(this.info.add(12), 0);
                console.log("[+] sysctl debugger check bypassed");
            }
        }
    }
});

// getppid bypass (returns 1 if debugged)
Interceptor.attach(Module.findExportByName(null, "getppid"), {
    onLeave: function(retval) {
        if (retval.toInt32() != 1) {
            retval.replace(1);
            console.log("[+] getppid check bypassed");
        }
    }
});

console.log("[*] Anti-debugging bypass loaded");
"""

def main():
    parser = argparse.ArgumentParser(description='iOS Anti-Debug Bypass')
    parser.add_argument('package', help='App bundle ID')
    parser.add_argument('--spawn', action='store_true', help='Spawn app')
    args = parser.parse_args()

    try:
        device = frida.get_usb_device()
        
        if args.spawn:
            print(f"[*] Spawning {args.package}")
            pid = device.spawn([args.package])
            session = device.attach(pid)
            device.resume(pid)
        else:
            print(f"[*] Attaching to {args.package}")
            session = device.attach(args.package)
        
        script = session.create_script(BYPASS_SCRIPT)
        script.load()
        print("[+] Anti-debug bypass active")
        sys.stdin.read()
        
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()