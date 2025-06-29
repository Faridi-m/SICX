import argparse
import sys
import os
import json
import csv
import xml.etree.ElementTree as ET
from datetime import datetime
sys.path.append(os.path.dirname(__file__))  # ensure modules available
from crawler import crawl_urls
from sql import run_sql_tests
from xss import run_xss_tests
from command_injection import test_command_injection
from encoders import PayloadEncoder
from obfuscators import PayloadObfuscator
from payload_gen import get_xss_payloads, get_sqli_payloads, get_cmdi_payloads
from colorama import Fore, Style, init

init(autoreset=True)

VERSION = "1.0.0"

BANNER = f"""{Fore.LIGHTBLUE_EX}
 ____  __  ___  _  _ 
/ ___)(  )/ __)( \\/ )
\\___ \\ )(( (__  )  ( 
(____/(__)\\___)(_\\/\\_)
{Style.RESET_ALL}
{Fore.CYAN}      SicX - SQL, Injection, Command, XSS
{Fore.YELLOW}       Modular Web Vulnerability Scanner - Developed By Offensive Team Zeta
{Fore.GREEN}       Version: {VERSION}
{Style.RESET_ALL}"""

def save_payloads_to_file(payloads, filename, output_format="txt"):
    """Save payloads to file in specified format"""
    try:
        if output_format.lower() == "json":
            with open(filename, 'w') as f:
                json.dump(payloads, f, indent=2)
        elif output_format.lower() == "csv":
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Payload", "Type", "Encoding", "Timestamp"])
                for payload in payloads:
                    writer.writerow([payload.get("payload", ""), 
                                   payload.get("type", ""), 
                                   payload.get("encoding", "none"),
                                   datetime.now().isoformat()])
        elif output_format.lower() == "xml":
            root = ET.Element("payloads")
            for payload in payloads:
                payload_elem = ET.SubElement(root, "payload")
                ET.SubElement(payload_elem, "content").text = payload.get("payload", "")
                ET.SubElement(payload_elem, "type").text = payload.get("type", "")
                ET.SubElement(payload_elem, "encoding").text = payload.get("encoding", "none")
                ET.SubElement(payload_elem, "timestamp").text = datetime.now().isoformat()
            tree = ET.ElementTree(root)
            tree.write(filename)
        else:  # txt format
            with open(filename, 'w') as f:
                for payload in payloads:
                    f.write(f"{payload.get('payload', '')}\n")
        print(f"{Fore.GREEN}[+] Payloads saved to {filename}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error saving payloads: {e}{Style.RESET_ALL}")

def generate_payloads(payload_type, count=10, encoding=None, obfuscate=False, context=None, database=None, platform="all"):
    """Generate payloads based on type and parameters"""
    encoder = PayloadEncoder()
    obfuscator = PayloadObfuscator()
    
    if payload_type == "xss":
        raw_payloads = get_xss_payloads()
        all_payloads = []
        for category, payloads in raw_payloads.items():
            all_payloads.extend(payloads)
    elif payload_type == "sqli":
        raw_payloads = get_sqli_payloads()
        all_payloads = []
        for category, payloads in raw_payloads.items():
            all_payloads.extend(payloads)
    elif payload_type == "cmdi":
        raw_payloads = get_cmdi_payloads()
        all_payloads = []
        for category, payloads in raw_payloads.items():
            all_payloads.extend(payloads)
    else:
        return []
    
    # Limit to requested count
    selected_payloads = all_payloads[:count] if count else all_payloads
    
    processed_payloads = []
    for payload in selected_payloads:
        processed = payload
        
        # Apply obfuscation
        if obfuscate:
            if payload_type == "xss":
                processed = obfuscator.obfuscate_xss(processed)
            elif payload_type == "sqli":
                processed = obfuscator.obfuscate_sqli(processed)
            elif payload_type == "cmdi":
                processed = obfuscator.obfuscate_cmdi(processed)
        
        # Apply encoding
        if encoding:
            processed = encoder.encode(processed, encoding)
        
        processed_payloads.append({
            "payload": processed,
            "type": payload_type,
            "encoding": encoding or "none",
            "obfuscated": obfuscate
        })
    
    return processed_payloads

def main():
    print(BANNER)
    p = argparse.ArgumentParser(
        description="SICX - Advanced Web Vulnerability Scanner and Payload Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sicx.py example.com --type xss --xss -v
  python sicx.py example.com --type sqli --sql --encode base64 --count 5
  python sicx.py example.com --type cmdi --cmd --platform linux --save payloads.json --output json
        """
    )
    
    # Required arguments
    p.add_argument("target", help="Target URL or domain")
    p.add_argument("--type", required=True, choices=['xss','sqli','cmdi'], 
                   help="Type of vulnerability to test")
    
    # Vulnerability type flags
    p.add_argument("--xss", action="store_true", help="Generate XSS payloads")
    p.add_argument("--sql", action="store_true", help="Generate SQL injection payloads") 
    p.add_argument("--cmd", action="store_true", help="Generate command injection payloads")
    
    # Payload modification options
    p.add_argument("--encode", choices=['url','base64','hex','unicode','html'], 
                   help="Encoding type for payloads")
    p.add_argument("--obfuscate", action="store_true", 
                   help="Apply obfuscation techniques")
    p.add_argument("--platform", choices=['linux','windows','all'], default='all',
                   help="Target platform for command injection")
    
    # Advanced options
    p.add_argument("--count", type=int, 
                   help="Number of payloads to generate")
    p.add_argument("--context", choices=['html','attribute','script','css'], 
                   help="XSS context type")
    p.add_argument("--database", choices=['mysql','postgres','mssql','oracle'], 
                   help="Database type for SQL injection")
    p.add_argument("--blind", action="store_true", 
                   help="Generate blind injection payloads")
    p.add_argument("--filter-bypass", action="store_true", 
                   help="Include filter bypass techniques")
    p.add_argument("--waf-evasion", action="store_true", 
                   help="Apply WAF evasion methods")
    
    # Output options
    p.add_argument("--output", choices=['cli','json','csv','xml','txt'], default='cli',
                   help="Output format")
    p.add_argument("--save", help="Save payloads to file")
    p.add_argument("--clipboard", action="store_true", 
                   help="Copy first payload to clipboard")
    
    # General options
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    p.add_argument("--version", action="version", version=f"SICX {VERSION}")
    
    args = p.parse_args()

    # Normalize target
    if not args.target.startswith(("http://","https://")):
        target = "http://" + args.target
    else:
        target = args.target

    # Generate payloads if count is specified or non-CLI output requested
    if args.count or args.output != 'cli' or args.save:
        if args.verbose: 
            print(f"{Fore.CYAN}[*] Generating {args.count or 10} {args.type} payloads...{Style.RESET_ALL}")
        
        payloads = generate_payloads(
            args.type, 
            count=args.count or 10,
            encoding=args.encode,
            obfuscate=args.obfuscate,
            context=args.context,
            database=args.database,
            platform=args.platform
        )
        
        if args.save:
            output_format = args.output if args.output != 'cli' else 'txt'
            save_payloads_to_file(payloads, args.save, output_format)
                
        if args.output == 'json':
            print(json.dumps(payloads, indent=2))
            return
        elif args.output == 'csv':
            print("Payload,Type,Encoding,Obfuscated")
            for p in payloads:
                print(f"\"{p['payload']}\",{p['type']},{p['encoding']},{p['obfuscated']}")
            return
        elif args.count and args.output == 'cli':
            # Display payloads in CLI format when count is specified
            for i, payload_data in enumerate(payloads, 1):
                payload = payload_data['payload']
                print(f"{Fore.GREEN}[{i:2d}] {payload}{Style.RESET_ALL}")
            return

    # If no specific flags are set, proceed with web scanning
    # Only proceed to scanning if vulnerability type flags are set
    if not (args.xss or args.sql or args.cmd):
        print(f"{Fore.YELLOW}[!] Please specify vulnerability type flags: --xss, --sql, or --cmd{Style.RESET_ALL}")
        return

    # Crawl
    if args.verbose: 
        print(f"{Fore.CYAN}[*] Crawling {target}...{Style.RESET_ALL}")
    urls = crawl_urls(target)
    if not urls:
        print(f"{Fore.YELLOW}[-] No URLs with parameters found.{Style.RESET_ALL}")
        return

    if args.verbose:
        print(f"{Fore.CYAN}[+] Found {len(urls)} URLs; starting scans{Style.RESET_ALL}")

    # Scan loops
    for url in urls:
        if args.sql and args.type == 'sqli':
            if args.verbose: 
                print(f"\n{Fore.MAGENTA}[*] SQLi test on {url}{Style.RESET_ALL}")
            run_sql_tests(url, database=args.database, blind=args.blind)
        if args.xss and args.type == 'xss':
            if args.verbose: 
                print(f"\n{Fore.MAGENTA}[*] XSS test on {url}{Style.RESET_ALL}")
            run_xss_tests(url, context=args.context)
        if args.cmd and args.type == 'cmdi':
            if args.verbose: 
                print(f"\n{Fore.MAGENTA}[*] CMDi test on {url}{Style.RESET_ALL}")
            test_command_injection(url,
                platform=args.platform,
                encode=args.encode,
                obfuscate=args.obfuscate,
                verbose=args.verbose
            )

    # Display sample payloads
    if args.verbose:
        encoder = PayloadEncoder()
        obf = PayloadObfuscator()
        if args.type == 'xss':
            samples = obf.obfuscate_xss("<script>alert(1)</script>") if args.obfuscate else "<script>alert(1)</script>"
            processed = encoder.encode(samples, args.encode) if args.encode else samples
            print(f"\n{Fore.GREEN}[+] Sample XSS payload: {processed}{Style.RESET_ALL}")
        elif args.type == 'sqli':
            sample = obf.obfuscate_sqli("' OR '1'='1") if args.obfuscate else "' OR '1'='1"
            processed = encoder.encode(sample, args.encode) if args.encode else sample
            print(f"\n{Fore.GREEN}[+] Sample SQLi payload: {processed}{Style.RESET_ALL}")
        elif args.type == 'cmdi':
            sample = obf.obfuscate_cmdi("; ls -la") if args.obfuscate else "; ls -la"
            processed = encoder.encode(sample, args.encode) if args.encode else sample
            print(f"\n{Fore.GREEN}[+] Sample CMDi payload: {processed}{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Interrupted, exiting...{Style.RESET_ALL}")
