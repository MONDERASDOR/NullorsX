# nullorsX

The Ultimate Pentesting & Cybersecurity Toolkit (Go CLI)

## Install & Build Instructions

### 1. Clone the Repository
```
git clone https://github.com/yourusername/nullorsX.git
cd nullorsX
```

### 2. Build the Binary (Go Modules, Multi-File Project)

#### For Windows (.exe output)
To build a Windows executable, use:
```
go build -o nullorsX.exe ./
```
This will create a file named `nullorsX.exe` in your project directory, which you can run directly on Windows by double-clicking or from the command prompt:
```
nullorsX.exe
```

#### For Linux/Mac
To build for Linux/Mac, use:
```
go build -o nullorsX ./
```
This will create an executable named `nullorsX` for your platform.

### 3. Run the Tool
```
nullorsX.exe   # On Windows
./nullorsX     # On Linux/Mac
```

### 4. Show Help
```
nullorsX.exe --help   # On Windows
./nullorsX --help     # On Linux/Mac
```

---

## Features

### Reconnaissance
- `recon whois [domain]`: Whois lookup (**Requires `whois` external tool**)
- `recon dns [domain]`: DNS A record lookup
- `recon banner [host] [port]`: Banner grabbing
- `recon geoip [ip]`: Geolocation lookup

### Scanning
- `scan portscan [host] [startPort] [endPort]`: TCP port scan

### Web Attacks & Scanning
- `web headers [url]`: HTTP headers
- `web crawler [url]`: Crawl links

### Passwords
- `password crack [hash] [wordlist]`: Crack hashes via wordlist

### Utilities
- `utils hash [type] [input]`: Hashing (md5, sha1, sha256)
- `utils encode [input]`: Base64 encode
- `utils decode [base64]`: Base64 decode

### Configuration
- `config set [key] [value]`: Set config (persistent)
- `config get [key]`: Get config

### Plugins
- `plugin list [directory]`: List plugins in a directory

### Offensive
- `offensive dirbrute [url] [wordlist]`: Directory brute-force

### Defensive
- `defensive portmon [host] [interval]`: Port monitoring
- `defensive logwatch [file]`: Tail log file and highlight errors

### Exploitation
- `exploit cve-search [cve-id]`: Fetch CVE details from cve.circl.lu

### Wireless
- `wireless wifi-list`: List WiFi networks (**Requires `netsh` on Windows, `nmcli` on Linux**)

### Reverse Engineering & File Analysis
- `reverse filetype [file]`: Detect file type by magic number

### Post-Exploitation
- `post exec [command]`: Execute shell command

### Reporting
- `report save [file] [content]`: Save content to file

---

## OS-Specific Requirements
- **Windows**: `whois` (install via [Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/whois)), `netsh` (built-in)
- **Linux**: `whois`, `nmcli` (part of NetworkManager)

If a required external tool is missing, nullorsX will print a user-friendly error message.

---

## Configuration File (`config.json`)

nullorsX supports persistent configuration using a `config.json` file. Here is an example:

```json
{
  "default_output_dir": "./output",
  "scan_timeout": "2s",
  "wordlist_path": "./wordlists/top1000.txt",
  "api_keys": {
    "shodan": "YOUR_SHODAN_API_KEY",
    "virustotal": "YOUR_VIRUSTOTAL_API_KEY"
  },
  "user_profile": {
    "name": "Your Name",
    "organization": "Your Org",
    "role": "pentester"
  },
  "custom_banner": "Welcome to nullorsX!"
}
```

You can edit this file to customize output directories, timeouts, wordlists, API keys, and user info. The tool will display your custom banner if set.

---

## Ethical Usage
By using this tool, you agree to use it for authorized testing only. For Red Teamers, Blue Teamers, and Security Enthusiasts.

---

## Troubleshooting
- If you see a dependency error, install the missing tool for your OS.
- Config is now persistent between runs (stored in `config.json`).
- For any issues, check the output for detailed error messages.
- **Windows Defender/Antivirus:** Because nullorsX is a cybersecurity and pentesting toolkit, it may trigger Windows Defender or other antivirus software. This is normal for tools that perform network scanning, password cracking, or other security-related actions. If you built the tool yourself and trust the source, you can safely allow it in your antivirus. If distributing, inform users that false positives are expected for security tools.

## Credits
This tool was created by **MONDERASDOR**. If you use or share this toolkit, please give credit to the original author.
