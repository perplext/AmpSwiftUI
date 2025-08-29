/*
 * Database Operations Monitor for iOS Apps
 * Monitors SQLite, Core Data, Realm, and GRDB database operations
 */

console.log("[*] Database Monitor loaded");

// SQLite3 Monitoring
if (ObjC.available) {
    
    // Hook SQLite3 operations
    const sqlite3_open = Module.findExportByName('libsqlite3.dylib', 'sqlite3_open');
    const sqlite3_exec = Module.findExportByName('libsqlite3.dylib', 'sqlite3_exec');
    const sqlite3_prepare_v2 = Module.findExportByName('libsqlite3.dylib', 'sqlite3_prepare_v2');
    const sqlite3_bind_text = Module.findExportByName('libsqlite3.dylib', 'sqlite3_bind_text');
    const sqlite3_key = Module.findExportByName('libsqlite3.dylib', 'sqlite3_key');
    
    if (sqlite3_open) {
        Interceptor.attach(sqlite3_open, {
            onEnter: function(args) {
                const dbPath = Memory.readUtf8String(args[0]);
                console.log(`[SQLite] Opening database: ${dbPath}`);
                this.dbPath = dbPath;
            },
            onLeave: function(retval) {
                if (retval.toInt32() === 0) {
                    console.log(`[SQLite] Database opened successfully: ${this.dbPath}`);
                    
                    // Check for encryption
                    if (this.dbPath && this.dbPath.includes('.encrypted') || 
                        this.dbPath.includes('sqlcipher')) {
                        console.log("[!] Potentially encrypted database detected");
                    }
                }
            }
        });
    }
    
    if (sqlite3_exec) {
        Interceptor.attach(sqlite3_exec, {
            onEnter: function(args) {
                const sql = Memory.readUtf8String(args[1]);
                console.log(`[SQLite] Executing: ${sql}`);
                
                // Detect sensitive operations
                const sensitivePatterns = [
                    /password/i,
                    /token/i,
                    /secret/i,
                    /key/i,
                    /credit_card/i,
                    /ssn/i
                ];
                
                for (const pattern of sensitivePatterns) {
                    if (pattern.test(sql)) {
                        console.log("[!] SENSITIVE DATA: Query contains potentially sensitive information");
                        break;
                    }
                }
            }
        });
    }
    
    if (sqlite3_prepare_v2) {
        Interceptor.attach(sqlite3_prepare_v2, {
            onEnter: function(args) {
                const sql = Memory.readUtf8String(args[1]);
                console.log(`[SQLite] Preparing statement: ${sql}`);
                this.sql = sql;
            }
        });
    }
    
    if (sqlite3_bind_text) {
        Interceptor.attach(sqlite3_bind_text, {
            onEnter: function(args) {
                const value = Memory.readUtf8String(args[2]);
                console.log(`[SQLite] Binding text value: ${value}`);
                
                // Check for potential injection
                const injectionPatterns = [
                    /'\s*OR\s+'1'\s*=\s*'1/i,
                    /;\s*DROP\s+TABLE/i,
                    /UNION\s+SELECT/i
                ];
                
                for (const pattern of injectionPatterns) {
                    if (pattern.test(value)) {
                        console.log("[!] POTENTIAL INJECTION: Suspicious value being bound");
                        break;
                    }
                }
            }
        });
    }
    
    if (sqlite3_key) {
        Interceptor.attach(sqlite3_key, {
            onEnter: function(args) {
                const keyLength = args[2].toInt32();
                console.log(`[SQLCipher] Setting encryption key (length: ${keyLength})`);
                
                // Try to read the key (be careful with this in production)
                if (keyLength > 0 && keyLength < 256) {
                    const key = Memory.readByteArray(args[1], keyLength);
                    const keyHex = Array.from(new Uint8Array(key))
                        .map(b => ('0' + b.toString(16)).slice(-2))
                        .join('');
                    console.log(`[SQLCipher] Key (hex): ${keyHex.substring(0, 32)}...`);
                }
            }
        });
    }
    
    // Core Data Monitoring
    const NSManagedObjectContext = ObjC.classes.NSManagedObjectContext;
    if (NSManagedObjectContext) {
        Interceptor.attach(NSManagedObjectContext['- save:'].implementation, {
            onEnter: function(args) {
                const context = ObjC.Object(args[0]);
                console.log('[CoreData] Saving context');
                
                // Get inserted objects
                const insertedObjects = context.insertedObjects();
                if (insertedObjects && insertedObjects.count() > 0) {
                    console.log(`[CoreData] Inserting ${insertedObjects.count()} objects`);
                    
                    const enumerator = insertedObjects.objectEnumerator();
                    let obj;
                    while ((obj = enumerator.nextObject()) !== null) {
                        console.log(`[CoreData] Inserted: ${obj.entity().name()}`);
                    }
                }
                
                // Get updated objects
                const updatedObjects = context.updatedObjects();
                if (updatedObjects && updatedObjects.count() > 0) {
                    console.log(`[CoreData] Updating ${updatedObjects.count()} objects`);
                }
                
                // Get deleted objects
                const deletedObjects = context.deletedObjects();
                if (deletedObjects && deletedObjects.count() > 0) {
                    console.log(`[CoreData] Deleting ${deletedObjects.count()} objects`);
                }
            },
            onLeave: function(retval) {
                const success = retval.toInt32();
                if (success) {
                    console.log('[CoreData] Save successful');
                } else {
                    console.log('[CoreData] Save failed');
                }
            }
        });
        
        Interceptor.attach(NSManagedObjectContext['- executeFetchRequest:error:'].implementation, {
            onEnter: function(args) {
                const request = ObjC.Object(args[2]);
                if (request && request.entityName) {
                    console.log(`[CoreData] Fetching entity: ${request.entityName()}`);
                    
                    const predicate = request.predicate();
                    if (predicate) {
                        console.log(`[CoreData] Predicate: ${predicate.predicateFormat()}`);
                    }
                }
            }
        });
    }
    
    // Check for Realm Database
    const RLMRealm = ObjC.classes.RLMRealm;
    if (RLMRealm) {
        console.log("[*] Realm database detected");
        
        Interceptor.attach(RLMRealm['+ realmWithConfiguration:error:'].implementation, {
            onEnter: function(args) {
                const config = ObjC.Object(args[2]);
                if (config) {
                    console.log(`[Realm] Opening realm with config`);
                    
                    const fileURL = config.fileURL();
                    if (fileURL) {
                        console.log(`[Realm] Database path: ${fileURL.path()}`);
                    }
                    
                    // Check for encryption
                    const encryptionKey = config.encryptionKey();
                    if (encryptionKey) {
                        console.log("[Realm] Database is encrypted");
                        // Don't log the actual key in production
                        console.log(`[Realm] Encryption key length: ${encryptionKey.length()}`);
                    } else {
                        console.log("[!] Realm database is NOT encrypted");
                    }
                }
            }
        });
        
        const RLMObject = ObjC.classes.RLMObject;
        if (RLMObject) {
            const addMethod = RLMRealm['- addObject:'];
            if (addMethod) {
                Interceptor.attach(addMethod.implementation, {
                    onEnter: function(args) {
                        const obj = ObjC.Object(args[2]);
                        console.log(`[Realm] Adding object: ${obj.className()}`);
                        
                        // Try to get object properties
                        try {
                            const desc = obj.description();
                            if (desc) {
                                console.log(`[Realm] Object data: ${desc}`);
                            }
                        } catch (e) {}
                    }
                });
            }
        }
    }
    
    // Check for GRDB
    const checkGRDB = () => {
        const Database = ObjC.classes.Database;
        if (Database) {
            console.log("[*] GRDB database detected");
            
            // Hook database initialization
            const initMethod = Database['- initWithPath:configuration:'];
            if (initMethod) {
                Interceptor.attach(initMethod.implementation, {
                    onEnter: function(args) {
                        const path = ObjC.Object(args[2]);
                        console.log(`[GRDB] Opening database: ${path}`);
                    }
                });
            }
        }
    };
    
    // Keychain operations related to databases
    const SecItemAdd = Module.findExportByName('Security', 'SecItemAdd');
    const SecItemCopyMatching = Module.findExportByName('Security', 'SecItemCopyMatching');
    
    if (SecItemAdd) {
        Interceptor.attach(SecItemAdd, {
            onEnter: function(args) {
                const dict = ObjC.Object(args[0]);
                const account = dict.objectForKey_('kSecAttrAccount');
                const service = dict.objectForKey_('kSecAttrService');
                
                if (account && service) {
                    const accountStr = account.toString();
                    const serviceStr = service.toString();
                    
                    // Check for database-related keychain items
                    if (accountStr.includes('database') || accountStr.includes('encryption') ||
                        serviceStr.includes('sqlcipher') || serviceStr.includes('realm')) {
                        console.log(`[Keychain] Storing database credentials`);
                        console.log(`[Keychain] Account: ${accountStr}`);
                        console.log(`[Keychain] Service: ${serviceStr}`);
                    }
                }
            }
        });
    }
    
    // Monitor file operations for database files
    const NSFileManager = ObjC.classes.NSFileManager;
    if (NSFileManager) {
        const createFile = NSFileManager['- createFileAtPath:contents:attributes:'];
        if (createFile) {
            Interceptor.attach(createFile.implementation, {
                onEnter: function(args) {
                    const path = ObjC.Object(args[2]).toString();
                    
                    if (path.includes('.sqlite') || path.includes('.db') || 
                        path.includes('.realm') || path.includes('.coredata')) {
                        console.log(`[FileManager] Creating database file: ${path}`);
                        
                        const contents = ObjC.Object(args[3]);
                        if (contents) {
                            const length = contents.length();
                            console.log(`[FileManager] Database size: ${length} bytes`);
                        }
                    }
                }
            });
        }
    }
    
    // Periodic check for GRDB (it might be loaded later)
    setTimeout(checkGRDB, 1000);
    
    // Log database statistics every 10 seconds
    setInterval(() => {
        console.log("[*] === Database Activity Summary ===");
        console.log("[*] Check console output above for database operations");
    }, 10000);
    
} else {
    console.log("[-] Objective-C runtime not available");
}