/*
 * AWS Amplify API Interceptor
 * Comprehensive hooking for GraphQL, REST, and Cognito operations
 * Targets: AWS Amplify iOS SDK v2.x
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

console.log(Color.CYAN + "[*] AWS Amplify API Interceptor v1.0" + Color.RESET);
console.log(Color.CYAN + "[*] Initializing AWS SDK hooks..." + Color.RESET);

// Storage for captured data
var graphqlQueries = [];
var restApiCalls = [];
var cognitoTokens = {};
var s3Operations = [];
var dynamoOperations = [];

// Hook GraphQL operations
if (ObjC.available) {
    // AWSAppSync GraphQL Client
    try {
        const AWSAppSyncClient = ObjC.classes.AWSAppSyncClient;
        if (AWSAppSyncClient) {
            // Hook GraphQL query execution
            Interceptor.attach(AWSAppSyncClient["- performQuery:"].implementation, {
                onEnter: function(args) {
                    const query = ObjC.Object(args[2]);
                    console.log(Color.BLUE + "[GraphQL] Query executed:" + Color.RESET);
                    console.log(Color.YELLOW + query.toString() + Color.RESET);
                    
                    graphqlQueries.push({
                        type: 'query',
                        timestamp: Date.now(),
                        content: query.toString()
                    });
                }
            });
            
            // Hook GraphQL mutation execution
            Interceptor.attach(AWSAppSyncClient["- performMutation:"].implementation, {
                onEnter: function(args) {
                    const mutation = ObjC.Object(args[2]);
                    console.log(Color.MAGENTA + "[GraphQL] Mutation executed:" + Color.RESET);
                    console.log(Color.YELLOW + mutation.toString() + Color.RESET);
                    
                    graphqlQueries.push({
                        type: 'mutation',
                        timestamp: Date.now(),
                        content: mutation.toString()
                    });
                }
            });
            
            // Hook GraphQL subscription
            Interceptor.attach(AWSAppSyncClient["- subscribe:"].implementation, {
                onEnter: function(args) {
                    const subscription = ObjC.Object(args[2]);
                    console.log(Color.GREEN + "[GraphQL] Subscription created:" + Color.RESET);
                    console.log(Color.YELLOW + subscription.toString() + Color.RESET);
                    
                    graphqlQueries.push({
                        type: 'subscription',
                        timestamp: Date.now(),
                        content: subscription.toString()
                    });
                }
            });
        }
    } catch(e) {
        console.log(Color.RED + "[-] Failed to hook AWSAppSync: " + e + Color.RESET);
    }
    
    // Amplify API Category
    try {
        const AmplifyAPI = ObjC.classes["Amplify.API"];
        if (AmplifyAPI) {
            // Hook REST API calls
            Interceptor.attach(AmplifyAPI["- get:"].implementation, {
                onEnter: function(args) {
                    const path = ObjC.Object(args[2]);
                    console.log(Color.BLUE + "[REST] GET: " + path.toString() + Color.RESET);
                    
                    restApiCalls.push({
                        method: 'GET',
                        path: path.toString(),
                        timestamp: Date.now()
                    });
                }
            });
            
            Interceptor.attach(AmplifyAPI["- post:body:"].implementation, {
                onEnter: function(args) {
                    const path = ObjC.Object(args[2]);
                    const body = ObjC.Object(args[3]);
                    console.log(Color.MAGENTA + "[REST] POST: " + path.toString() + Color.RESET);
                    console.log(Color.YELLOW + "Body: " + body.toString() + Color.RESET);
                    
                    restApiCalls.push({
                        method: 'POST',
                        path: path.toString(),
                        body: body.toString(),
                        timestamp: Date.now()
                    });
                }
            });
        }
    } catch(e) {
        console.log(Color.RED + "[-] Failed to hook Amplify API: " + e + Color.RESET);
    }
    
    // AWS Cognito Hooks
    try {
        // AWSCognitoIdentityProvider
        const CognitoProvider = ObjC.classes.AWSCognitoIdentityProvider;
        if (CognitoProvider) {
            // Hook authentication
            Interceptor.attach(CognitoProvider["- initiateAuth:"].implementation, {
                onEnter: function(args) {
                    const authParams = ObjC.Object(args[2]);
                    console.log(Color.GREEN + "[Cognito] Authentication initiated" + Color.RESET);
                    console.log(Color.YELLOW + "Auth flow: " + authParams.authFlow + Color.RESET);
                    
                    // Extract username if available
                    if (authParams.authParameters) {
                        const params = authParams.authParameters;
                        if (params.USERNAME) {
                            console.log(Color.YELLOW + "Username: " + params.USERNAME + Color.RESET);
                        }
                    }
                }
            });
            
            // Hook token refresh
            Interceptor.attach(CognitoProvider["- initiateAuth:"].implementation, {
                onLeave: function(retval) {
                    const result = ObjC.Object(retval);
                    if (result && result.authenticationResult) {
                        const tokens = result.authenticationResult;
                        
                        if (tokens.idToken) {
                            console.log(Color.RED + "[!] ID Token captured:" + Color.RESET);
                            console.log(Color.YELLOW + tokens.idToken.substring(0, 50) + "..." + Color.RESET);
                            cognitoTokens.idToken = tokens.idToken;
                        }
                        
                        if (tokens.accessToken) {
                            console.log(Color.RED + "[!] Access Token captured:" + Color.RESET);
                            console.log(Color.YELLOW + tokens.accessToken.substring(0, 50) + "..." + Color.RESET);
                            cognitoTokens.accessToken = tokens.accessToken;
                        }
                        
                        if (tokens.refreshToken) {
                            console.log(Color.RED + "[!] Refresh Token captured:" + Color.RESET);
                            console.log(Color.YELLOW + tokens.refreshToken.substring(0, 50) + "..." + Color.RESET);
                            cognitoTokens.refreshToken = tokens.refreshToken;
                        }
                    }
                }
            });
        }
        
        // AWSCognitoIdentityUser
        const CognitoUser = ObjC.classes.AWSCognitoIdentityUser;
        if (CognitoUser) {
            // Hook user attributes
            Interceptor.attach(CognitoUser["- getDetails:"].implementation, {
                onLeave: function(retval) {
                    const details = ObjC.Object(retval);
                    if (details && details.userAttributes) {
                        console.log(Color.CYAN + "[Cognito] User attributes:" + Color.RESET);
                        const attrs = details.userAttributes;
                        for (let i = 0; i < attrs.count(); i++) {
                            const attr = attrs.objectAtIndex_(i);
                            console.log("  " + attr.name + ": " + attr.value);
                        }
                    }
                }
            });
        }
    } catch(e) {
        console.log(Color.RED + "[-] Failed to hook Cognito: " + e + Color.RESET);
    }
    
    // AWS S3 Hooks
    try {
        const AWSS3 = ObjC.classes.AWSS3;
        if (AWSS3) {
            // Hook S3 uploads
            Interceptor.attach(AWSS3["- putObject:"].implementation, {
                onEnter: function(args) {
                    const request = ObjC.Object(args[2]);
                    console.log(Color.BLUE + "[S3] Upload initiated" + Color.RESET);
                    console.log("  Bucket: " + request.bucket);
                    console.log("  Key: " + request.key);
                    
                    s3Operations.push({
                        operation: 'PUT',
                        bucket: request.bucket.toString(),
                        key: request.key.toString(),
                        timestamp: Date.now()
                    });
                }
            });
            
            // Hook S3 downloads
            Interceptor.attach(AWSS3["- getObject:"].implementation, {
                onEnter: function(args) {
                    const request = ObjC.Object(args[2]);
                    console.log(Color.BLUE + "[S3] Download initiated" + Color.RESET);
                    console.log("  Bucket: " + request.bucket);
                    console.log("  Key: " + request.key);
                    
                    s3Operations.push({
                        operation: 'GET',
                        bucket: request.bucket.toString(),
                        key: request.key.toString(),
                        timestamp: Date.now()
                    });
                }
            });
            
            // Hook presigned URL generation
            Interceptor.attach(AWSS3["- presignedURLForGetObject:"].implementation, {
                onLeave: function(retval) {
                    const url = ObjC.Object(retval);
                    console.log(Color.MAGENTA + "[S3] Presigned URL generated:" + Color.RESET);
                    console.log(Color.YELLOW + url.toString() + Color.RESET);
                }
            });
        }
    } catch(e) {
        console.log(Color.RED + "[-] Failed to hook S3: " + e + Color.RESET);
    }
    
    // AWS DynamoDB Hooks
    try {
        const AWSDynamoDB = ObjC.classes.AWSDynamoDB;
        if (AWSDynamoDB) {
            // Hook DynamoDB queries
            Interceptor.attach(AWSDynamoDB["- query:"].implementation, {
                onEnter: function(args) {
                    const request = ObjC.Object(args[2]);
                    console.log(Color.CYAN + "[DynamoDB] Query executed" + Color.RESET);
                    console.log("  Table: " + request.tableName);
                    
                    dynamoOperations.push({
                        operation: 'QUERY',
                        table: request.tableName.toString(),
                        timestamp: Date.now()
                    });
                }
            });
            
            // Hook DynamoDB scan
            Interceptor.attach(AWSDynamoDB["- scan:"].implementation, {
                onEnter: function(args) {
                    const request = ObjC.Object(args[2]);
                    console.log(Color.CYAN + "[DynamoDB] Scan executed" + Color.RESET);
                    console.log("  Table: " + request.tableName);
                    
                    dynamoOperations.push({
                        operation: 'SCAN',
                        table: request.tableName.toString(),
                        timestamp: Date.now()
                    });
                }
            });
        }
    } catch(e) {
        console.log(Color.RED + "[-] Failed to hook DynamoDB: " + e + Color.RESET);
    }
    
    // Hook AWS Signature V4 for API authentication
    try {
        const AWSSignature = ObjC.classes.AWSSignatureV4Signer;
        if (AWSSignature) {
            Interceptor.attach(AWSSignature["- signRequest:"].implementation, {
                onEnter: function(args) {
                    const request = ObjC.Object(args[2]);
                    console.log(Color.MAGENTA + "[AWS] Request signed with SigV4" + Color.RESET);
                    console.log("  URL: " + request.URL.absoluteString);
                    
                    // Extract Authorization header after signing
                    const headers = request.allHTTPHeaderFields;
                    if (headers && headers.Authorization) {
                        console.log(Color.YELLOW + "  Authorization: " + headers.Authorization + Color.RESET);
                    }
                }
            });
        }
    } catch(e) {
        console.log(Color.RED + "[-] Failed to hook AWS Signature: " + e + Color.RESET);
    }
}

// JWT Token Decoder
function decodeJWT(token) {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return null;
        
        // Decode header and payload
        const header = JSON.parse(atob(parts[0]));
        const payload = JSON.parse(atob(parts[1]));
        
        return {
            header: header,
            payload: payload,
            signature: parts[2]
        };
    } catch(e) {
        return null;
    }
}

// API Functions
function dumpGraphQLQueries() {
    console.log(Color.BLUE + "\n========== GRAPHQL QUERIES ==========" + Color.RESET);
    graphqlQueries.forEach(q => {
        const date = new Date(q.timestamp);
        console.log(`[${date.toISOString()}] ${q.type.toUpperCase()}`);
        console.log(q.content);
        console.log("");
    });
    console.log(Color.BLUE + "===================================\n" + Color.RESET);
}

function dumpRESTCalls() {
    console.log(Color.MAGENTA + "\n========== REST API CALLS ==========" + Color.RESET);
    restApiCalls.forEach(call => {
        const date = new Date(call.timestamp);
        console.log(`[${date.toISOString()}] ${call.method} ${call.path}`);
        if (call.body) {
            console.log("Body: " + call.body);
        }
        console.log("");
    });
    console.log(Color.MAGENTA + "===================================\n" + Color.RESET);
}

function dumpCognitoTokens() {
    console.log(Color.RED + "\n========== COGNITO TOKENS ==========" + Color.RESET);
    
    if (cognitoTokens.idToken) {
        console.log(Color.YELLOW + "ID Token:" + Color.RESET);
        const decoded = decodeJWT(cognitoTokens.idToken);
        if (decoded) {
            console.log("  Header: " + JSON.stringify(decoded.header, null, 2));
            console.log("  Payload: " + JSON.stringify(decoded.payload, null, 2));
        } else {
            console.log("  " + cognitoTokens.idToken);
        }
    }
    
    if (cognitoTokens.accessToken) {
        console.log(Color.YELLOW + "\nAccess Token:" + Color.RESET);
        const decoded = decodeJWT(cognitoTokens.accessToken);
        if (decoded) {
            console.log("  Payload: " + JSON.stringify(decoded.payload, null, 2));
        } else {
            console.log("  " + cognitoTokens.accessToken);
        }
    }
    
    if (cognitoTokens.refreshToken) {
        console.log(Color.YELLOW + "\nRefresh Token:" + Color.RESET);
        console.log("  " + cognitoTokens.refreshToken);
    }
    
    console.log(Color.RED + "===================================\n" + Color.RESET);
}

function dumpS3Operations() {
    console.log(Color.CYAN + "\n========== S3 OPERATIONS ==========" + Color.RESET);
    s3Operations.forEach(op => {
        const date = new Date(op.timestamp);
        console.log(`[${date.toISOString()}] ${op.operation} s3://${op.bucket}/${op.key}`);
    });
    console.log(Color.CYAN + "===================================\n" + Color.RESET);
}

function modifyNextGraphQLQuery(newQuery) {
    console.log(Color.MAGENTA + "[*] Next GraphQL query will be modified to:" + Color.RESET);
    console.log(Color.YELLOW + newQuery + Color.RESET);
    
    // Hook next query execution to modify it
    const AWSAppSyncClient = ObjC.classes.AWSAppSyncClient;
    if (AWSAppSyncClient) {
        Interceptor.attach(AWSAppSyncClient["- performQuery:"].implementation, {
            onEnter: function(args) {
                // Replace the query
                const newQueryObj = ObjC.classes.NSString.stringWithString_(newQuery);
                args[2] = newQueryObj;
                console.log(Color.GREEN + "[+] Query modified successfully!" + Color.RESET);
                
                // Remove this hook after one use
                Interceptor.detachAll();
            }
        });
    }
}

// Export functions
global.dumpGraphQLQueries = dumpGraphQLQueries;
global.dumpRESTCalls = dumpRESTCalls;
global.dumpCognitoTokens = dumpCognitoTokens;
global.dumpS3Operations = dumpS3Operations;
global.modifyNextGraphQLQuery = modifyNextGraphQLQuery;

console.log(Color.GREEN + "[+] AWS Amplify Interceptor loaded successfully!" + Color.RESET);
console.log(Color.GREEN + "[+] Available commands:" + Color.RESET);
console.log("    dumpGraphQLQueries()     - Show all GraphQL operations");
console.log("    dumpRESTCalls()          - Show all REST API calls");
console.log("    dumpCognitoTokens()      - Show captured Cognito tokens");
console.log("    dumpS3Operations()       - Show S3 operations");
console.log("    modifyNextGraphQLQuery(query) - Modify next GraphQL query");