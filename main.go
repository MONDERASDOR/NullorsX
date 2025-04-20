package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
	"github.com/spf13/cobra"
	"github.com/fatih/color"
)

var configStore = make(map[string]string)

func printBanner() {
	banner := `\n\n  _   _       _ _                 _____  \n | \ | |     | | |               / ____| \n |  \| | ___ | | | ___ _ __ ___ | (___   \n | . ` + "|/ _ \\| | |/ _ \\ '_ ` _ \\ \\___ \\  " + `\n | |\\  | (_) | | |  __/ | | | | |____) | \n |_| \\_|\\___/|_|_|\\___|_| |_| |_|_____/  \n\n The Ultimate Pentesting & Cybersecurity Toolkit\n For Red Teamers, Blue Teamers, and Security Enthusiasts.\n Ethical use only!\n By using this tool, you agree to use it for authorized testing only.\n Created by MONDERASDOR\n\n`
	fmt.Println(color.HiMagentaString(banner))
}

var rootCmd = &cobra.Command{
	Use:   "nullorsX",
	Short: "nullorsX - The Ultimate Pentesting & Cybersecurity Toolkit",
	Long: "nullorsX - The Ultimate Pentesting & Cybersecurity Toolkit\n\nFor Red Teamers, Blue Teamers, and Security Enthusiasts. Ethical use only!\nBy using this tool, you agree to use it for authorized testing only.\nCreated by MONDERASDOR\n",
	Run: func(cmd *cobra.Command, args []string) {
		printBanner()
		fmt.Println(color.HiYellowString("Welcome to nullorsX! Use --help to see available modules."))
	},
}

// Persistent config helpers
func loadConfig() {
	file, err := os.Open("config.json")
	if err != nil {
		return // No config yet
	}
	defer file.Close()
	json.NewDecoder(file).Decode(&configStore)
}

func saveConfig() {
	file, err := os.Create("config.json")
	if err != nil {
		fmt.Println(color.HiRedString("[Config] Error saving config: %v", err))
		return
	}
	defer file.Close()
	json.NewEncoder(file).Encode(configStore)
}

// --- RECON MODULE ---
var reconCmd = &cobra.Command{
	Use:   "recon",
	Short: "Information Gathering & Reconnaissance",
}
var whoisCmd = &cobra.Command{
	Use:   "whois [domain]",
	Short: "Perform a whois lookup on a domain",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		domain := args[0]
		fmt.Printf("[Recon] Whois lookup for: %s\n", domain)
		_, err := exec.LookPath("whois")
		if err != nil {
			fmt.Println(color.HiRedString("[Dependency] 'whois' command not found. Please install it for your OS."))
			return
		}
		out, err := exec.Command("whois", domain).CombinedOutput()
		if err != nil {
			fmt.Printf("Error running whois: %v\nOutput: %s\n", err, string(out))
			return
		}
		fmt.Println(string(out))
	},
}
var dnsCmd = &cobra.Command{
	Use:   "dns [domain]",
	Short: "DNS lookup for a domain",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ips, err := net.LookupHost(args[0])
		if err != nil {
			fmt.Printf("DNS lookup error: %v\n", err)
			return
		}
		fmt.Printf("A records for %s:\n", args[0])
		for _, ip := range ips {
			fmt.Println("-", ip)
		}
	},
}
var bannerCmd = &cobra.Command{
	Use:   "banner [host] [port]",
	Short: "Grab banner from host:port",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		host, port := args[0], args[1]
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 2*time.Second)
		if err != nil {
			fmt.Printf("Banner grab error: %v\n", err)
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		fmt.Printf("Banner: %s\n", string(buf[:n]))
	},
}
var geoipCmd = &cobra.Command{
	Use:   "geoip [ip]",
	Short: "Get geolocation for an IP address",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		resp, err := http.Get("http://ip-api.com/json/" + args[0])
		if err != nil {
			fmt.Printf("GeoIP error: %v\n", err)
			return
		}
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		var result map[string]interface{}
		json.Unmarshal(body, &result)
		fmt.Printf("GeoIP for %s: %v\n", args[0], result)
	},
}

// --- SCAN MODULE ---
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scanning & Enumeration",
}
var portscanCmd = &cobra.Command{
	Use:   "portscan [host] [startPort] [endPort]",
	Short: "Scan TCP ports on a host",
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		host := args[0]
		start, end := args[1], args[2]
		startPort, endPort := 0, 0
		fmt.Sscanf(start, "%d", &startPort)
		fmt.Sscanf(end, "%d", &endPort)
		fmt.Printf("[Scan] Scanning %s ports %d-%d...\n", host, startPort, endPort)
		for port := startPort; port <= endPort; port++ {
			address := fmt.Sprintf("%s:%d", host, port)
			conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
			if err == nil {
				fmt.Printf("Port %d: OPEN\n", port)
				conn.Close()
			}
		}
	},
}
var udpscanCmd = &cobra.Command{
	Use:   "udpscan [host] [startPort] [endPort]",
	Short: "Scan UDP ports on a host (basic check)",
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		host := args[0]
		start, end := args[1], args[2]
		startPort, endPort := 0, 0
		fmt.Sscanf(start, "%d", &startPort)
		fmt.Sscanf(end, "%d", &endPort)
		fmt.Printf("[Scan] Scanning UDP %s ports %d-%d...\n", host, startPort, endPort)
		for port := startPort; port <= endPort; port++ {
			addr := net.UDPAddr{IP: net.ParseIP(host), Port: port}
			conn, err := net.DialUDP("udp", nil, &addr)
			if err == nil {
				conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
				conn.Write([]byte("ping"))
				buf := make([]byte, 1024)
				_, err := conn.Read(buf)
				if err == nil {
					fmt.Printf("UDP Port %d: OPEN (received response)\n", port)
				}
				conn.Close()
			}
		}
	},
}

// --- WEB MODULE ---
var webCmd = &cobra.Command{
	Use:   "web",
	Short: "Web Attacks & Scanning",
}
var headersCmd = &cobra.Command{
	Use:   "headers [url]",
	Short: "Fetch HTTP headers for a URL",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		resp, err := http.Head(args[0])
		if err != nil {
			fmt.Println(color.HiRedString("HTTP error: %v", err))
			return
		}
		defer resp.Body.Close()
		fmt.Println(color.HiCyanString("Headers for %s:", args[0]))
		for k, v := range resp.Header {
			fmt.Printf("%s: %s\n", color.HiYellowString(k), color.WhiteString(strings.Join(v, ", ")))
		}
	},
}
var crawlerCmd = &cobra.Command{
	Use:   "crawler [url]",
	Short: "Crawl and list all links on a page",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		resp, err := http.Get(args[0])
		if err != nil {
			fmt.Println(color.HiRedString("Crawl error: %v", err))
			return
		}
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		links := extractLinks(string(body))
		fmt.Println(color.HiCyanString("Links found:"))
		for _, l := range links {
			fmt.Println(color.HiGreenString(l))
		}
	},
}
func extractLinks(html string) []string {
	var links []string
	re := regexp.MustCompile(`href=["']([^"']+)["']`)
	matches := re.FindAllStringSubmatch(html, -1)
	for _, m := range matches {
		if len(m) > 1 {
			links = append(links, m[1])
		}
	}
	return links
}
var robotsCmd = &cobra.Command{
	Use:   "robots [url]",
	Short: "Fetch robots.txt from a website",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		url := args[0]
		if !strings.HasSuffix(url, "/") {
			url += "/"
		}
		resp, err := http.Get(url + "robots.txt")
		if err != nil {
			fmt.Println(color.HiRedString("robots.txt error: %v", err))
			return
		}
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Printf("%s\n", color.HiCyanString("robots.txt for %s:", url))
		fmt.Println(color.WhiteString(string(body)))
	},
}

// --- PASSWORD MODULE ---
var passwordCmd = &cobra.Command{
	Use:   "password",
	Short: "Password Attacks & Hash Cracking",
}
var crackCmd = &cobra.Command{
	Use:   "crack [hash] [wordlist]",
	Short: "Crack a hash using a wordlist",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		hash, wordlist := args[0], args[1]
		file, err := os.Open(wordlist)
		if err != nil {
			fmt.Printf("Wordlist error: %v\n", err)
			return
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			word := scanner.Text()
			if md5Hash(word) == hash || sha1Hash(word) == hash || sha256Hash(word) == hash {
				fmt.Printf("Found: %s\n", word)
				return
			}
		}
		fmt.Println("Not found in wordlist.")
	},
}
func md5Hash(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}
func sha1Hash(s string) string {
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}
func sha256Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// --- UTILS MODULE ---
var utilsCmd = &cobra.Command{
	Use:   "utils",
	Short: "Utilities: Encoder, Decoder, Hashing, Wordlists",
}
var hashCmd = &cobra.Command{
	Use:   "hash [type] [input]",
	Short: "Generate hash (md5, sha1, sha256) of input",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		typeStr, input := args[0], args[1]
		var hash string
		switch typeStr {
		case "md5":
			h := md5.Sum([]byte(input))
			hash = hex.EncodeToString(h[:])
		case "sha1":
			h := sha1.Sum([]byte(input))
			hash = hex.EncodeToString(h[:])
		case "sha256":
			h := sha256.Sum256([]byte(input))
			hash = hex.EncodeToString(h[:])
		default:
			fmt.Println("Supported types: md5, sha1, sha256")
			return
		}
		fmt.Printf("%s(%s) = %s\n", typeStr, input, hash)
	},
}
var encodeCmd = &cobra.Command{
	Use:   "encode [input]",
	Short: "Base64 encode a string",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		encoded := base64.StdEncoding.EncodeToString([]byte(args[0]))
		fmt.Printf("Base64: %s\n", encoded)
	},
}
var decodeCmd = &cobra.Command{
	Use:   "decode [base64]",
	Short: "Base64 decode a string",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		decoded, err := base64.StdEncoding.DecodeString(args[0])
		if err != nil {
			fmt.Printf("Decode error: %v\n", err)
			return
		}
		fmt.Printf("Decoded: %s\n", decoded)
	},
}

// --- CONFIG MODULE ---
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration (API keys, output, etc.)",
}
var configSetCmd = &cobra.Command{
	Use:   "set [key] [value]",
	Short: "Set a configuration value",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		key, value := args[0], args[1]
		configStore[key] = value
		saveConfig()
		fmt.Printf("Config %s set to %s\n", key, value)
	},
}
var configGetCmd = &cobra.Command{
	Use:   "get [key]",
	Short: "Get a configuration value",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		key := args[0]
		if val, ok := configStore[key]; ok {
			fmt.Printf("%s: %s\n", key, val)
		} else {
			fmt.Printf("Config %s not set\n", key)
		}
	},
}

// --- PLUGIN MODULE ---
var pluginCmd = &cobra.Command{
	Use:   "plugin",
	Short: "Plugin System for User Scripts",
}
var pluginListCmd = &cobra.Command{
	Use:   "list [directory]",
	Short: "List available plugins in a directory",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		dir := args[0]
		files, err := os.ReadDir(dir)
		if err != nil {
			fmt.Printf("Error reading directory: %v\n", err)
			return
		}
		fmt.Println("Available plugins:")
		for _, f := range files {
			if !f.IsDir() {
				fmt.Println("-", f.Name())
			}
		}
	},
}

// --- OFFENSIVE MODULE ---
var offensiveCmd = &cobra.Command{
	Use:   "offensive",
	Short: "Offensive Attacks & Exploitation",
}
var dirbruteCmd = &cobra.Command{
	Use:   "dirbrute [url] [wordlist]",
	Short: "Directory brute-force scanner",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		url, wordlist := args[0], args[1]
		file, err := os.Open(wordlist)
		if err != nil {
			fmt.Println(color.HiRedString("Wordlist error: %v", err))
			return
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		client := &http.Client{Timeout: 2 * time.Second}
		for scanner.Scan() {
			path := scanner.Text()
			full := strings.TrimRight(url, "/") + "/" + path
			resp, err := client.Get(full)
			if err == nil && resp.StatusCode < 400 {
				fmt.Println(color.HiGreenString("Found: %s [%d]", full, resp.StatusCode))
			}
			if resp != nil {
				resp.Body.Close()
			}
		}
	},
}
var xssTestCmd = &cobra.Command{
	Use:   "xss-test [url] [param]",
	Short: "Test for reflected XSS (basic)",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		url, param := args[0], args[1]
		xssPayload := "<script>alert('xss')</script>"
		testUrl := url + "?" + param + "=" + xssPayload
		resp, err := http.Get(testUrl)
		if err != nil {
			fmt.Println(color.HiRedString("Request error: %v", err))
			return
		}
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		if strings.Contains(string(body), xssPayload) {
			fmt.Println(color.HiRedString("Possible reflected XSS! Payload found in response."))
		} else {
			fmt.Println(color.HiGreenString("No reflected XSS detected."))
		}
	},
}
var sqliTestCmd = &cobra.Command{
	Use:   "sqli-test [url] [param]",
	Short: "Test for SQLi (error-based)",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		url, param := args[0], args[1]
		testUrl := url + "?" + param + "='"
		resp, err := http.Get(testUrl)
		if err != nil {
			fmt.Println(color.HiRedString("Request error: %v", err))
			return
		}
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		errors := []string{"SQL syntax", "mysql_fetch", "ORA-", "syntax error", "ODBC", "SQLException"}
		found := false
		for _, e := range errors {
			if strings.Contains(string(body), e) {
				fmt.Println(color.HiRedString("Possible SQLi! Error '%s' found in response.", e))
				found = true
			}
		}
		if !found {
			fmt.Println(color.HiGreenString("No SQLi error detected."))
		}
	},
}

// --- DEFENSIVE MODULE ---
var defensiveCmd = &cobra.Command{
	Use:   "defensive",
	Short: "Defensive Monitoring & Analysis",
}
var portmonCmd = &cobra.Command{
	Use:   "portmon [host] [interval]",
	Short: "Monitor open TCP ports in real time",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		host := args[0]
		interval, _ := time.ParseDuration(args[1])
		fmt.Println(color.HiCyanString("Monitoring open TCP ports on %s every %s... (Ctrl+C to stop)", host, interval))
		for {
			for port := 1; port <= 1024; port++ {
				address := fmt.Sprintf("%s:%d", host, port)
				conn, err := net.DialTimeout("tcp", address, 300*time.Millisecond)
				if err == nil {
					fmt.Printf("Port %d: %s\n", port, color.HiGreenString("OPEN"))
					conn.Close()
				}
			}
			time.Sleep(interval)
		}
	},
}
var logwatchCmd = &cobra.Command{
	Use:   "logwatch [file]",
	Short: "Tail a log file and highlight suspicious entries",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		file, err := os.Open(args[0])
		if err != nil {
			fmt.Println(color.HiRedString("Log file error: %v", err))
			return
		}
		defer file.Close()
		fmt.Println(color.HiCyanString("Tailing log file: %s", args[0]))
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(strings.ToLower(line), "fail") || strings.Contains(strings.ToLower(line), "error") {
				fmt.Println(color.HiRedString(line))
			} else {
				fmt.Println(line)
			}
		}
	},
}

// --- EXPLOIT MODULE ---
var exploitCmd = &cobra.Command{
	Use:   "exploit",
	Short: "Exploit & CVE Tools",
}
var cveSearchCmd = &cobra.Command{
	Use:   "cve-search [cve-id]",
	Short: "Get CVE details from cve.circl.lu",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cve := args[0]
		resp, err := http.Get("https://cve.circl.lu/api/cve/" + cve)
		if err != nil {
			fmt.Println(color.HiRedString("CVE search error: %v", err))
			return
		}
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Println(color.HiCyanString("CVE %s details:", cve))
		fmt.Println(string(body))
	},
}

// --- WIRELESS MODULE ---
var wirelessCmd = &cobra.Command{
	Use:   "wireless",
	Short: "Wireless & Bluetooth Tools",
}
var wifiListCmd = &cobra.Command{
	Use:   "wifi-list",
	Short: "List available WiFi networks",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if runtime.GOOS == "windows" {
			_, err := exec.LookPath("netsh")
			if err != nil {
				fmt.Println(color.HiRedString("[Dependency] 'netsh' command not found. This command is required on Windows for WiFi scanning."))
				return
			}
			cmd := exec.Command("netsh", "wlan", "show", "networks")
			out, err := cmd.CombinedOutput()
			if err != nil {
				fmt.Println(color.HiRedString("WiFi scan error: %v\nOutput: %s", err, string(out)))
				return
			}
			fmt.Println(color.HiCyanString("Available WiFi networks:"))
			fmt.Println(string(out))
		} else {
			_, err := exec.LookPath("nmcli")
			if err != nil {
				fmt.Println(color.HiRedString("[Dependency] 'nmcli' command not found. This command is required on Linux for WiFi scanning."))
				return
			}
			cmd := exec.Command("nmcli", "dev", "wifi")
			out, err := cmd.CombinedOutput()
			if err != nil {
				fmt.Println(color.HiRedString("WiFi scan error: %v\nOutput: %s", err, string(out)))
				return
			}
			fmt.Println(color.HiCyanString("Available WiFi networks:"))
			fmt.Println(string(out))
		}
	},
}

// --- REVERSE MODULE ---
var reverseCmd = &cobra.Command{
	Use:   "reverse",
	Short: "Reverse Engineering & File Analysis",
}
var filetypeCmd = &cobra.Command{
	Use:   "filetype [file]",
	Short: "Identify file type by magic number",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		file, err := os.Open(args[0])
		if err != nil {
			fmt.Println(color.HiRedString("File error: %v", err))
			return
		}
		defer file.Close()
		buf := make([]byte, 512)
		file.Read(buf)
		fmt.Println(color.HiCyanString("File type: %s", http.DetectContentType(buf)))
	},
}

// --- POST MODULE ---
var postCmd = &cobra.Command{
	Use:   "post",
	Short: "Post-Exploitation Utilities",
}
var execCmd = &cobra.Command{
	Use:   "exec [command]",
	Short: "Execute a shell command and show output",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			fmt.Println(color.HiRedString("Command error: %v\nOutput: %s", err, string(out)))
		}
		fmt.Println(string(out))
	},
}

// --- REPORT MODULE ---
var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Reporting & Output",
}
var saveCmd = &cobra.Command{
	Use:   "save [file] [content]",
	Short: "Save content to a file",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		err := ioutil.WriteFile(args[0], []byte(args[1]), 0644)
		if err != nil {
			fmt.Println(color.HiRedString("Save error: %v", err))
			return
		}
		fmt.Println(color.HiGreenString("Saved to %s", args[0]))
	},
}

func init() {
	reconCmd.AddCommand(whoisCmd)
	reconCmd.AddCommand(dnsCmd)
	reconCmd.AddCommand(bannerCmd)
	reconCmd.AddCommand(geoipCmd)
	scanCmd.AddCommand(portscanCmd)
	scanCmd.AddCommand(udpscanCmd)
	webCmd.AddCommand(headersCmd)
	webCmd.AddCommand(crawlerCmd)
	webCmd.AddCommand(robotsCmd)
	passwordCmd.AddCommand(crackCmd)
	utilsCmd.AddCommand(hashCmd)
	utilsCmd.AddCommand(encodeCmd)
	utilsCmd.AddCommand(decodeCmd)
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configGetCmd)
	pluginCmd.AddCommand(pluginListCmd)
	offensiveCmd.AddCommand(dirbruteCmd)
	offensiveCmd.AddCommand(xssTestCmd)
	offensiveCmd.AddCommand(sqliTestCmd)
	defensiveCmd.AddCommand(portmonCmd)
	defensiveCmd.AddCommand(logwatchCmd)
	exploitCmd.AddCommand(cveSearchCmd)
	wirelessCmd.AddCommand(wifiListCmd)
	reverseCmd.AddCommand(filetypeCmd)
	postCmd.AddCommand(execCmd)
	reportCmd.AddCommand(saveCmd)
}

func main() {
	loadConfig()
	rootCmd.AddCommand(reconCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(webCmd)
	rootCmd.AddCommand(passwordCmd)
	rootCmd.AddCommand(utilsCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(pluginCmd)
	rootCmd.AddCommand(offensiveCmd)
	rootCmd.AddCommand(defensiveCmd)
	rootCmd.AddCommand(exploitCmd)
	rootCmd.AddCommand(wirelessCmd)
	rootCmd.AddCommand(reverseCmd)
	rootCmd.AddCommand(postCmd)
	rootCmd.AddCommand(reportCmd)
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(color.HiRedString("Error: %v", err))
		os.Exit(1)
	}
}
