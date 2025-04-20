# nullorsX

The Ultimate Pentesting & Cybersecurity Toolkit (Go CLI)   

## Install Instructions

---

### 1. Clone the Repository
```
git clone https://github.com/MONDERASDOR/nullorsX.git
cd nullorsX
```

### 2. Build the Binary (Requires Go 1.21+)
```
go build -o nullorsX.exe main.go
```

### 3. Run the Tool
```
./nullorsX.exe
```

### 4. Show Help
```
./nullorsX.exe --help
```

---

## Features

### Reconnaissance
- `whois [domain]`: Whois lookup (**Requires `whois` external tool**)
- `dns [domain]`: DNS A record lookup
- `banner [host] [port]`: Banner grabbing
- `geoip [ip]`: Geolocation lookup

### Scanning
- `portscan [host] [startPort] [endPort]`: TCP port scan
- `udpscan [host] [startPort] [endPort]`: UDP port scan
- `portmon [host] [interval]`: Port monitoring

### Web Attacks & Scanning
- `headers [url]`: HTTP headers
- `crawler [url]`: Crawl links
- `robots [url]`: Fetch robots.txt
- `dirbrute [url] [wordlist]`: Directory brute-force
- `xss-test [url] [param]`: Reflected XSS test
- `sqli-test [url] [param]`: SQL injection test

### Passwords
- `crack [hash] [wordlist]`: Crack hashes via wordlist

### Utilities
- `hash [type] [input]`: Hashing (md5, sha1, sha256)
- `encode [input]`: Base64 encode
- `decode [base64]`: Base64 decode

### Configuration
- `config set [key] [value]`: Set config (persistent)
- `config get [key]`: Get config

### Plugins
- `plugin list [directory]`: List plugins in a directory

### Exploitation
- `cve-search [cve-id]`: Fetch CVE details from cve.circl.lu

### Wireless
- `wifi-list`: List WiFi networks (**Requires `netsh` on Windows, `nmcli` on Linux**)

### Reverse Engineering & File Analysis
- `filetype [file]`: Detect file type by magic number

### Post-Exploitation
- `exec [command]`: Execute shell command

### Reporting
- `save [file] [content]`: Save content to file

---

## OS-Specific Requirements
- **Windows**: `whois` (install via [Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/whois)), `netsh` (built-in)
- **Linux**: `whois`, `nmcli` (part of NetworkManager)

If a required external tool is missing, nullorsX will print a user-friendly error message for you (:

---

## Ethical Usage
By using this tool, you agree to use it for authorized testing only. For Red Teamers, Blue Teamers, and Security Enthusiasts.

---

## Troubleshooting
- If you see a dependency error, install the missing tool for your OS.
- Config is now persistent between runs (stored in `config.json`).
- For any issues, check the output for detailed error messages.
