# SICX - Advanced Web Vulnerability Scanner & Payload Generator

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()
[![Status](https://img.shields.io/badge/status-Production-success.svg)]()

SICX (SQL Injection, Command Injection, XSS) is a powerful, modular, and extensible command-line tool for automated detection and exploitation of common web vulnerabilities. Built with security researchers, bug bounty hunters, and penetration testers in mind.

## 🚀 Features

### Core Vulnerability Scanning
- ✅ **Cross-Site Scripting (XSS)**: Reflected, Stored, DOM-based variants
- ✅ **SQL Injection**: Union-based, Boolean-based, Error-based, Time-based, Blind
- ✅ **Command Injection**: Linux/Windows platform-specific payloads

### Advanced Capabilities
- 🔧 **Payload Encoding**: Base64, URL, Hex, Unicode, HTML entities
- 🎭 **Payload Obfuscation**: Comment insertion, case variation, whitespace manipulation
- 🛡️ **WAF Evasion**: Advanced bypass techniques for security filters
- 🎯 **Context-Aware Payloads**: HTML, Attribute, Script, CSS contexts
- 🗃️ **Database-Specific**: MySQL, PostgreSQL, MSSQL, Oracle variants
- 📊 **Multiple Output Formats**: CLI, JSON, CSV, XML, Plain text

### Integration & Automation
- 🔗 **Web Crawler**: Automatic parameter discovery
- 📋 **Clipboard Support**: Direct payload copying
- 💾 **Batch Processing**: Generate and save multiple payloads
- 🎨 **Colored Output**: Enhanced CLI experience with syntax highlighting

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- Windows 10/11, Linux, or macOS

### Quick Install
```bash
git clone https://github.com/Faridi-m/sicx.git
cd sicx
pip install -r requirements.txt
```

### Development Install
```bash
git clone https://github.com/Faridi-m/sicx.git
cd sicx
pip install -e .
```

### Dependencies
- `requests>=2.28.0` - HTTP requests
- `beautifulsoup4>=4.11.0` - HTML parsing
- `colorama>=0.4.0` - Colored terminal output
- `pyperclip>=1.8.0` - Clipboard operations
- `click>=8.0.0` - CLI framework

## 🛠️ Usage

### Master Command Syntax
```bash
python sicx.py <target> --type <xss|sqli|cmdi> [--xss] [--sql] [--cmd]
                   [--platform linux|windows|all] [--encode url|base64|hex]
                   [--obfuscate] [-v | --verbose]
                   [--count <N>] [--save <file>] [--output <cli|json|csv|xml|txt>]
                   [--context <html|attribute|script|css>] [--database <mysql|postgres|mssql|oracle>]
                   [--blind] [--filter-bypass] [--waf-evasion]
```

### Core Options
- `target`: Target URL or domain
- `--type`: Vulnerability type to test (xss|sqli|cmdi)
- `--xss`: Enable XSS scanning
- `--sql`: Enable SQL injection scanning  
- `--cmd`: Enable command injection scanning
- `--platform`: Target platform (linux|windows|all)
- `--encode`: Encoding method (url|base64|hex|unicode|html)
- `--obfuscate`: Apply obfuscation techniques
- `--verbose`: Detailed output

### Advanced Options
- `--count N`: Number of payloads to generate
- `--save FILE`: Save payloads to file
- `--output FORMAT`: Output format (cli|json|csv|xml|txt)
- `--context TYPE`: XSS context (html|attribute|script|css)
- `--database TYPE`: Database type (mysql|postgres|mssql|oracle)
- `--blind`: Include blind injection techniques
- `--filter-bypass`: Apply filter bypass methods
- `--waf-evasion`: WAF evasion techniques

## 📝 Examples

### Basic XSS Testing
```bash
# Basic XSS scan
python sicx.py testphp.vulnweb.com --type xss --xss -v

# XSS with encoding and obfuscation
python sicx.py example.com --type xss --xss --encode url --obfuscate -v

# Context-aware XSS testing
python sicx.py example.com --type xss --xss --context attribute --encode base64
```

### SQL Injection Testing
```bash
# Basic SQL injection scan
python sicx.py testphp.vulnweb.com --type sqli --sql -v

# MySQL-specific blind injection
python sicx.py example.com --type sqli --sql --database mysql --blind --encode hex

# Advanced WAF bypass
python sicx.py example.com --type sqli --sql --waf-evasion --filter-bypass
```

### Command Injection Testing
```bash
# Linux command injection
python sicx.py example.com --type cmdi --cmd --platform linux -v

# Windows-specific with encoding
python sicx.py example.com --type cmdi --cmd --platform windows --encode base64

# Multi-platform with obfuscation
python sicx.py example.com --type cmdi --cmd --platform all --obfuscate --encode url

```

### Payload Generation & Export
```bash
# Generate 50 XSS payloads and save as JSON
python sicx.py example.com --type xss --count 50 --save xss_payloads.json --output json

# Generate SQL payloads for PostgreSQL
python sicx.py example.com --type sqli --database postgres --count 25 --save sqli.csv --output csv

# Generate obfuscated command injection payloads
python sicx.py example.com --type cmdi --obfuscate --count 30 --save cmdi.xml --output xml

```

### Module Overview
```bash
#### Core Modules
- **`sicx.py`**: Main CLI interface and orchestration
- **`crawler.py`**: Discovers URLs with parameters for testing
- **`payload_gen.py`**: Centralized payload database and generation

#### Vulnerability Scanners
- **`xss.py`**: Cross-Site Scripting detection with context awareness
- **`sql.py`**: SQL Injection testing with database-specific payloads
- **`command_injection.py`**: Command injection with platform detection

#### Enhancement Modules
- **`encoders.py`**: Multiple encoding methods for payload transformation
- **`obfuscators.py`**: Advanced obfuscation techniques for filter bypass

## 🔧 Advanced Features

### Payload Encoding Methods
- **Base64**: Standard Base64 encoding
- **URL**: Percent-encoding for web applications
- **Hex**: Hexadecimal representation with \\x prefix
- **Unicode**: Unicode escape sequences for JavaScript
- **HTML**: HTML entity encoding for web contexts

### Obfuscation Techniques
- **Case Variation**: Mixed case keywords
- **Comment Insertion**: Strategic comment placement
- **Whitespace Manipulation**: Tab and space variations
- **Character Substitution**: Alternative character representations
- **Function Wrapping**: Database function-based bypasses

### WAF Evasion Methods
- **SQL Comment Insertion**: `/**/`, `--`, `#`
- **Keyword Fragmentation**: Breaking up detected keywords
- **Encoding Chains**: Multiple encoding layers
- **Alternative Syntax**: Database-specific syntax variations
- **Time-based Delays**: Avoiding rate limiting

## 📊 Output Formats

### CLI Output (Default)
Colored, real-time output with vulnerability detection indicators:
```
[+] XSS Vulnerability Detected: <script>alert(1)</script>
[*] Testing payload: <img src=x onerror=alert(1)>
[-] No reflection detected
```

### JSON Export
```json
{
  "payloads": [
    {
      "payload": "<script>alert(1)</script>",
      "type": "xss",
      "encoding": "none",
      "obfuscated": false,
      "timestamp": "2025-06-27T12:00:00"
    }
  ]
}
```

### CSV Export
```csv
Payload,Type,Encoding,Timestamp
"<script>alert(1)</script>",xss,none,2025-06-27T12:00:00
"' UNION SELECT 1,2,3--",sqli,url,2025-06-27T12:00:00
```

## 🔍 Vulnerability Coverage

### XSS Payload Types
- **Basic**: `<script>alert(1)</script>`
- **Event Handlers**: `<img src=x onerror=alert(1)>`
- **SVG-based**: `<svg onload=alert(1)>`
- **DOM-based**: `javascript:alert(1)`
- **Template Injection**: `{{7*7}}`, `${7*7}`
- **CSS-based**: `<style>@import'javascript:alert(1)'</style>`

### SQL Injection Types
- **Union-based**: Data extraction through UNION queries
- **Boolean-based**: True/false response analysis
- **Error-based**: Database error message exploitation
- **Time-based**: Response time analysis for blind injection
- **Stacked Queries**: Multiple query execution

### Command Injection Variants
- **Linux**: `;`, `&&`, `||`, `` ` ``, `$()`
- **Windows**: `&`, `&&`, `||`, `cmd /c`
- **PowerShell**: `powershell -c`, `-enc`
- **Environment Variables**: `$USER`, `%USERNAME%`

## 🛡️ Security Considerations

### Responsible Use
- Only test applications you own or have explicit permission to test
- Follow responsible disclosure practices
- Comply with applicable laws and regulations
- Use in authorized penetration testing scenarios only

### Input Validation
- All user inputs are sanitized and validated
- Path traversal prevention implemented
- Safe file operations with proper permissions
- Memory-safe operations throughout

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
git clone https://github.com/yourusername/sicx.git
cd sicx
pip install -e ".[dev]"
pytest tests/
```

### Code Standards
- Follow PEP 8 guidelines
- Comprehensive docstrings for all functions
- Type hints where applicable
- Minimum 80% test coverage

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support & Documentation

- **Issues**: [GitHub Issues](https://github.com/yourusername/sicx/issues)
- **Documentation**: [Wiki](https://github.com/yourusername/sicx/wiki)
- **Examples**: [Examples Directory](examples/)

## ⚠️ Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for complying with applicable laws and regulations. The authors are not responsible for any misuse or damage caused by this tool.

---

**Developed by Offensive Team Zeta** | **Version 1.0.0**
