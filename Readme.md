# Domain Scanner - A Comprehensive Recon Tool

Domain Scanner is a powerful reconnaissance tool designed to scan domains and subdomains, discover vulnerabilities, and provide detailed reports on web infrastructure.

## Features

- **Subdomain Enumeration**: Discover subdomains using multiple techniques
- **DNS Analysis**: Check various DNS record types (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, SRV)
- **Port Scanning**: Detect open ports and service information using nmap
- **Vulnerability Scanning**: Integrated nuclei scanner for vulnerability detection
- **WAF Detection**: Identify Web Application Firewalls
- **Certificate Analysis**: Extract and validate SSL certificate information
- **Technology Detection**: Identify web technologies and frameworks
- **DNS Zone Transfer Testing**: Attempt zone transfers from nameservers
- **Certificate Transparency Monitoring**: Discover subdomains from CT logs
- **Reporting**: Generate JSON, CSV, and HTML reports

## Installation

### Dependencies

```bash
pip install requests dnspython tqdm colorama urllib3 pyyaml jinja2
```

### External Tools

The following external tools should be installed and available in your PATH:

- **subfinder**: For advanced subdomain enumeration
- **nuclei**: For vulnerability scanning
- **nmap**: For port scanning
- **wafw00f**: For WAF detection

## Usage

```bash
python domain_scanner.py -d example.com
```

### Command Line Arguments

| Argument | Description |
|----------|-------------|
| -d, --domain | Target domain to scan |
| -o, --output | Output directory for scan results |
| -v, --verbose | Increase output verbosity |
| -t, --threads | Number of concurrent threads (default: 10) |
| --timeout | Request timeout in seconds (default: 5) |
| --scan-ports | Enable port scanning |
| --ports | Comma-separated list of ports to scan (e.g. 80,443,8080) |
| --wordlist | Path to subdomain wordlist file |
| --delay | Delay between requests in seconds |
| --no-dns | Skip DNS record checks |
| --proxy | Use proxy for requests (e.g., http://127.0.0.1:8080) |
| --retries | Maximum number of retries for failed requests |
| --config | Path to YAML configuration file |
| --nuclei-templates | Path to directory containing custom nuclei templates |

## Configuration File

You can use a YAML configuration file instead of command-line arguments:

```yaml
domain: example.com
output_dir: ./scan_results
threads: 15
timeout: 10
scan_ports: true
ports: [21, 22, 25, 80, 443, 8080, 8443]
wordlist: /path/to/wordlist.txt
delay: 0.5
retries: 3
verbose: true
```

## Example

Basic scan:
```bash
python domain_scanner.py -d example.com
```

Advanced scan:
```bash
python domain_scanner.py -d example.com --scan-ports --ports 80,443,8080,8443 -t 20 --wordlist subdomains.txt --nuclei-templates /path/to/templates
```

## Output

Results are saved in the specified output directory (or "scan_results" by default):
- JSON report with detailed findings
- CSV file for easy data import
- HTML report for better visualization
- Detailed log file

## License

This tool is for educational purposes only. Use responsibly and only on systems you have permission to scan.